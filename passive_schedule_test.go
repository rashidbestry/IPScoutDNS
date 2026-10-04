package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPassiveClockConfig(t *testing.T) {
	for _, clock := range []string{"03:00", "00:00", "23:59", "", "24:00", "3:00", "bad"} {
		cfg, err := loadConfig(writeModeTestFile(t, "mode=passive\npassive_domains_file=list\ndirect_dns=1.1.1.1\npassive_resolve_time="+clock+"\n"))
		valid := clock == "03:00" || clock == "00:00" || clock == "23:59" || clock == ""
		if valid && (err != nil || cfg.PassiveResolveTime != clock) {
			t.Fatalf("%q: %v", clock, err)
		}
		if !valid && err == nil {
			t.Fatalf("accepted %q", clock)
		}
	}
}
func TestPassiveNextClock(t *testing.T) {
	for _, hour := range []int{2, 3, 4} {
		now := time.Date(2026, 10, 4, hour, 0, 0, 0, time.FixedZone("local", 3*3600))
		next := nextPassiveResolveTime(now, "03:00")
		day := 4
		if hour >= 3 {
			day = 5
		}
		if next.Day() != day || next.Hour() != 3 || next.Location() != now.Location() {
			t.Fatal(next)
		}
	}
}
func TestPassiveCleanupAndRewrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reachable.ips")
	appendUniqueLine(path, "1.1.1.1", writtenReachableIPs)
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := clearPassiveOutputDirectory(dir); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("cleanup: %v %v", entries, err)
	}
	appendUniqueLine(path, "1.1.1.1", writtenReachableIPs)
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "1.1.1.1\n" {
		t.Fatalf("rewrite: %q %v", data, err)
	}
}
func TestPassiveClockWaitAndCleanupOrder(t *testing.T) {
	cfg := Config{PassiveResolveTime: "03:00", PassiveResolveParallel: 1, PassiveResolveInterval: time.Hour}
	waits, cleaned, resolved := 0, false, false
	err := runPassiveWithCleanup(context.Background(), cfg, func(string) ([]string, error) { return []string{"example.com"}, nil }, func(context.Context, string, Config) {
		if !cleaned || waits != 1 {
			t.Fatal("resolved before wait or cleanup")
		}
		resolved = true
	}, func(context.Context, time.Duration) bool { waits++; return waits == 1 }, func() error { cleaned = true; return nil })
	if err != nil || !resolved || waits != 2 {
		t.Fatalf("%v %v %d", err, resolved, waits)
	}
}
