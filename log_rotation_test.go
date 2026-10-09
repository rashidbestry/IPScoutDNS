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

func TestLogRotationConfig(t *testing.T) {
	for _, mode := range []string{"active", "passive"} {
		for _, test := range []struct {
			settings string
			size     int64
			keep     int
			bad      bool
		}{
			{"", defaultLogMaxSize, 7, false},
			{"log_max_size=10MB\nlog_keep_files=3\n", 10000000, 3, false},
			{"log_max_size=2MiB\nlog_keep_files=1\n", 2 << 20, 1, false},
			{"log_max_size = 500 kb\n", 500000, 7, false},
			{"log_max_size=42\n", 42, 7, false},
			{"log_max_size=0MB\n", 0, 0, true},
			{"log_max_size=-1MB\n", 0, 0, true},
			{"log_max_size=1.5MB\n", 0, 0, true},
			{"log_max_size=9223372036854775807GB\n", 0, 0, true},
			{"log_max_size=bad\n", 0, 0, true},
			{"log_keep_files=0\n", 0, 0, true},
			{"log_keep_files=-1\n", 0, 0, true},
			{"log_keep_files=bad\n", 0, 0, true},
		} {
			cfg, err := loadConfig(writeModeTestFile(t, "mode="+mode+"\nactive_domains_file=active.txt\npassive_domains_file=passive.txt\ndirect_dns=1.1.1.1\nsave_logs=true\n"+test.settings))
			if test.bad {
				if err == nil {
					t.Fatalf("%s accepted %q", mode, test.settings)
				}
				continue
			}
			if err != nil || cfg.LogMaxSize != test.size || cfg.LogKeepFiles != test.keep {
				t.Fatalf("%s %q: size=%d keep=%d error=%v", mode, test.settings, cfg.LogMaxSize, cfg.LogKeepFiles, err)
			}
		}
	}
}

func rotationLog(t *testing.T, shared bool, size int64, keep int) Config {
	t.Helper()
	cfg := Config{SaveLogs: true, LogMaxSize: size, LogKeepFiles: keep, outputDirectory: t.TempDir(), outputDirectoryShared: shared, runtimeCopiesEnabled: !shared}
	now := time.Date(2026, 10, 7, 15, 30, 0, 0, time.UTC)
	var err error
	cfg.savedLog, err = openSavedLog(cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	cfg.savedLog.now = func() time.Time { return now }
	t.Cleanup(func() { cfg.savedLog.Close() })
	return cfg
}

func writeLogRecord(t *testing.T, file *savedLog, message string) {
	t.Helper()
	n, err := file.Write([]byte(message))
	if err != nil || n != len(message) {
		t.Fatalf("write=%d/%d error=%v", n, len(message), err)
	}
}

func TestLogRotationPreservesWholeRecords(t *testing.T) {
	cfg := rotationLog(t, false, 12, 7)
	first := cfg.savedLog.path
	writeLogRecord(t, cfg.savedLog, "first\n")
	writeLogRecord(t, cfg.savedLog, "other\n")
	if cfg.savedLog.path != first {
		t.Fatal("rotated before reaching the limit")
	}
	writeLogRecord(t, cfg.savedLog, "third\n")
	data, err := os.ReadFile(first)
	if err != nil || string(data) != "first\nother\n" {
		t.Fatalf("first log=%q error=%v", data, err)
	}
	third := cfg.savedLog.path
	oversized := "a single message longer than the limit\n"
	writeLogRecord(t, cfg.savedLog, oversized)
	data, err = os.ReadFile(cfg.savedLog.path)
	if err != nil || string(data) != oversized {
		t.Fatalf("oversized record was split: %q %v", data, err)
	}
	data, err = os.ReadFile(third)
	if err != nil || string(data) != "third\n" {
		t.Fatalf("third record=%q %v", data, err)
	}
}

func TestWindowsLogRetentionAndNumericSuffixes(t *testing.T) {
	cfg := rotationLog(t, true, 3, 7)
	for _, name := range []string{"readme.txt", "ipscoutdns_log_notes.txt", "ipscoutdns_log_2026-99-99_99-99-99.txt"} {
		if err := os.WriteFile(filepath.Join(cfg.savedLog.dir, name), []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	unrelatedDir := filepath.Join(cfg.savedLog.dir, "ipscoutdns_log_2020-01-01_00-00-00.txt")
	if err := os.Mkdir(unrelatedDir, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 15; i++ {
		writeLogRecord(t, cfg.savedLog, fmt.Sprintf("%02d\n", i))
	}
	logs, err := listSavedLogs(cfg.savedLog.dir)
	if err != nil || len(logs) != 7 {
		t.Fatalf("logs=%v error=%v", logs, err)
	}
	for i, entry := range logs {
		data, err := os.ReadFile(filepath.Join(cfg.savedLog.dir, entry.name))
		if err != nil || string(data) != fmt.Sprintf("%02d\n", 14-i) {
			t.Fatalf("retained log=%q error=%v", data, err)
		}
	}
	for _, name := range []string{"readme.txt", "ipscoutdns_log_notes.txt", "ipscoutdns_log_2026-99-99_99-99-99.txt"} {
		data, err := os.ReadFile(filepath.Join(cfg.savedLog.dir, name))
		if err != nil || string(data) != "keep" {
			t.Fatalf("unrelated file removed: %s", name)
		}
	}
	if _, err := os.Stat(unrelatedDir); err != nil {
		t.Fatal("retention removed a directory")
	}
}

func TestUncopiedRotatedLogsSurviveFailedCopy(t *testing.T) {
	cfg := rotationLog(t, false, 3, 7)
	for i := 0; i < 15; i++ {
		writeLogRecord(t, cfg.savedLog, fmt.Sprintf("%02d\n", i))
	}
	blocked := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blocked, []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := copyRuntimeLog(context.Background(), cfg, blocked); err == nil {
		t.Fatal("copy error ignored")
	}
	logs, err := listSavedLogs(cfg.savedLog.dir)
	if err != nil || len(logs) != 15 {
		t.Fatalf("uncopied logs pruned: %v %v", logs, err)
	}
	destination := filepath.Join(t.TempDir(), "logs")
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destination, "readme.txt"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := copyRuntimeLog(context.Background(), cfg, destination); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{cfg.savedLog.dir, destination} {
		logs, err := listSavedLogs(dir)
		if err != nil || len(logs) != 7 {
			t.Fatalf("retention in %s: %v %v", dir, logs, err)
		}
		for i, entry := range logs {
			data, err := os.ReadFile(filepath.Join(dir, entry.name))
			if err != nil || string(data) != fmt.Sprintf("%02d\n", 14-i) {
				t.Fatalf("retained copy=%q error=%v", data, err)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(destination, "readme.txt")); err != nil {
		t.Fatal("archive retention removed unrelated file")
	}
	if len(cfg.savedLog.copiedSizes) != 7 {
		t.Fatal("copy tracking retained removed files")
	}
}

func TestCopiedLogTailIsProtectedAfterRotation(t *testing.T) {
	cfg := rotationLog(t, false, 4, 1)
	old := cfg.savedLog.path
	writeLogRecord(t, cfg.savedLog, "a\n")
	destination := t.TempDir()
	if err := copyRuntimeLog(context.Background(), cfg, destination); err != nil {
		t.Fatal(err)
	}
	writeLogRecord(t, cfg.savedLog, "b\n")
	writeLogRecord(t, cfg.savedLog, "c\n")
	cfg.savedLog.mu.Lock()
	err := cfg.savedLog.pruneSourceLocked()
	cfg.savedLog.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(old)
	if err != nil || string(data) != "a\nb\n" {
		t.Fatal("uncopied tail was removed after rotation")
	}
	if err := copyRuntimeLog(context.Background(), cfg, destination); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("fully copied old log was not pruned")
	}
}

func TestConcurrentLogRotationAndCopy(t *testing.T) {
	cfg := rotationLog(t, false, 8, 7)
	destination := t.TempDir()
	var wg sync.WaitGroup
	wg.Add(1)
	writeErrors := make(chan error, 1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if _, err := cfg.savedLog.Write([]byte(fmt.Sprintf("%03d\n", i))); err != nil {
				writeErrors <- err
				return
			}
		}
	}()
	for i := 0; i < 5; i++ {
		if _, err := cfg.savedLog.copyTo(context.Background(), destination); err != nil {
			wg.Wait()
			t.Fatal(err)
		}
	}
	wg.Wait()
	select {
	case err := <-writeErrors:
		t.Fatal(err)
	default:
	}
	if _, err := cfg.savedLog.copyTo(context.Background(), destination); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{cfg.savedLog.dir, destination} {
		logs, err := listSavedLogs(dir)
		if err != nil || len(logs) != 7 {
			t.Fatalf("concurrent retention: %v %v", logs, err)
		}
		for _, entry := range logs {
			data, err := os.ReadFile(filepath.Join(dir, entry.name))
			if err != nil || !strings.HasSuffix(string(data), "\n") || len(data) > 8 {
				t.Fatalf("partial message: %q %v", data, err)
			}
		}
	}
}

func TestLogRetentionInactiveWhenSavingDisabled(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "ipscoutdns_log_2020-01-01_00-00-00.txt")
	if err := os.WriteFile(name, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := openSavedLog(Config{outputDirectory: dir, LogKeepFiles: 1}, time.Now())
	if err != nil || file != nil {
		t.Fatalf("disabled logging=%v %v", file, err)
	}
	if data, err := os.ReadFile(name); err != nil || string(data) != "keep" {
		t.Fatal("disabled retention modified old log")
	}
}
