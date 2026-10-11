package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStatusRestartAndTransitions(t *testing.T) {
	dir := t.TempDir()
	reachable := filepath.Join(dir, "reachable")
	unreachable := filepath.Join(dir, "unreachable")
	if err := os.WriteFile(unreachable, []byte("old.example\r\nold.example\r\nother.example\r\n"), 0644); err != nil {
		t.Fatal(err)
	}
	recordStatus(reachable, unreachable, "old.example")
	for path, want := range map[string]string{reachable: "old.example\n", unreachable: "other.example\n"} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != want {
			t.Fatalf("%s = %q, %v; want %q", path, data, err, want)
		}
	}
	// A restart must hydrate membership from disk, including the destination.
	delete(statusFiles, reachable)
	delete(statusFiles, unreachable)
	recordStatus(reachable, unreachable, "old.example")
	recordStatus(unreachable, reachable, "old.example")
	data, err := os.ReadFile(unreachable)
	if err != nil || string(data) != "other.example\nold.example\n" {
		t.Fatalf("transition after restart = %q, %v", data, err)
	}
}

func TestStatusRetentionBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status")
	var legacy strings.Builder
	for i := 0; i < maxStatusEntries+5; i++ {
		fmt.Fprintf(&legacy, "domain-%d.example\n", i)
	}
	if err := os.WriteFile(path, []byte(legacy.String()), 0644); err != nil {
		t.Fatal(err)
	}
	// Loading must bound an oversized existing file even for an absent removal.
	if err := setStatusLineLocked(path, "absent.example", false); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		recordStatus(path, "", fmt.Sprintf("new-%d.example", i))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(string(data))
	if len(lines) != maxStatusEntries || lines[0] != "domain-3.example" || lines[len(lines)-1] != "new-2.example" {
		t.Fatalf("retained %d entries; first=%q last=%q", len(lines), lines[0], lines[len(lines)-1])
	}
	state := statusFiles[path]
	if len(state.seen) != maxStatusEntries || len(state.lines) != maxStatusEntries || state.seen["domain-0.example"] {
		t.Fatal("index did not evict old entries")
	}
	// An evicted result can be recorded again and becomes the newest entry.
	recordStatus(path, "", "domain-0.example")
	if !state.seen["domain-0.example"] || state.seen["domain-3.example"] {
		t.Fatal("evicted entry could not be recorded again")
	}
}

func TestCachedResolutionDoesNotReadStatusFiles(t *testing.T) {
	previous := currentConfig
	t.Cleanup(func() { currentConfig = previous })
	dir := t.TempDir()
	currentConfig = Config{
		CacheTTL: time.Hour, TLSProbe: true,
		ReachableDomainsFile:   filepath.Join(dir, "reachable.domains"),
		UnreachableDomainsFile: filepath.Join(dir, "unreachable.domains"),
		ReachableIPsFile:       filepath.Join(dir, "reachable.ips"),
		UnreachableIPsFile:     filepath.Join(dir, "unreachable.ips"),
	}
	const domain = "status-cache.example"
	updateCache(domain, "8.8.8.1", "TLS")
	t.Cleanup(func() { deleteCache(domain) })
	recordReachableHost(domain, "8.8.8.1")
	// Replace indexed files with directories: any attempted read/write fails.
	// Outputs are process-owned; this is an I/O tripwire, not a supported edit.
	for _, path := range currentConfig.outputFiles() {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	previousLog := logger.Writer()
	var logs selectionLogBuffer
	logger.SetOutput(&logs)
	t.Cleanup(func() { logger.SetOutput(previousLog) })
	for i := 0; i < 3; i++ {
		ip, ok, cached := resolveAndSelectWithProbes(context.Background(), domain, currentConfig, nil, nil, nil, nil)
		if ip != "8.8.8.1" || !ok || !cached {
			t.Fatalf("cached resolution = %q, %t, %t", ip, ok, cached)
		}
	}
	if strings.Contains(logs.String(), "failed to update status") {
		t.Fatalf("cache hit accessed status files: %s", logs.String())
	}
}

func TestStatusWriteFailureRetries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status")
	recordStatus(path, "", "old.example")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}
	if err := setStatusLineLocked(path, "new.example", true); err == nil {
		t.Fatal("replacement of a directory succeeded")
	}
	if statusFiles[path].seen["new.example"] {
		t.Fatal("failed write changed membership")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	recordStatus(path, "", "new.example")
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "old.example\nnew.example\n" {
		t.Fatalf("retry = %q, %v", data, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary files leaked: %v, %v", entries, err)
	}
}

func TestStatusConcurrentTransitions(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	var workers sync.WaitGroup
	for i := 0; i < 20; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			value := fmt.Sprintf("domain-%d.example", i)
			recordStatus(a, b, value)
			recordStatus(b, a, value)
		}(i)
	}
	workers.Wait()
	first, err := os.ReadFile(a)
	if err != nil || len(first) != 0 {
		t.Fatalf("old status = %q, %v", first, err)
	}
	second, err := os.ReadFile(b)
	if err != nil || len(strings.Fields(string(second))) != 20 {
		t.Fatalf("new status = %q, %v", second, err)
	}
}
