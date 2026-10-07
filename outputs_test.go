package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestActiveCopyIntervalConfig(t *testing.T) {
	for _, test := range []struct {
		setting string
		want    time.Duration
	}{
		{"", time.Hour},
		{"active_copy_interval=6h\n", 6 * time.Hour},
		{"active_copy_interval=30m\n", 30 * time.Minute},
	} {
		cfg, err := loadConfig(writeModeTestFile(t, "mode=active\nactive_domains_file=list\ndirect_dns=1.1.1.1\n"+test.setting))
		if err != nil || cfg.ActiveCopyInterval != test.want {
			t.Fatalf("%q: interval = %s, error = %v", test.setting, cfg.ActiveCopyInterval, err)
		}
	}
	for _, value := range []string{"", "0h", "-1h", "3:00", "bad"} {
		_, err := loadConfig(writeModeTestFile(t, "mode=active\nactive_domains_file=list\ndirect_dns=1.1.1.1\nactive_copy_interval="+value+"\n"))
		if err == nil || !strings.Contains(err.Error(), "invalid active_copy_interval") {
			t.Fatalf("%q: error = %v", value, err)
		}
	}
}

func TestCopyOutputFiles(t *testing.T) {
	source, destination := t.TempDir(), t.TempDir()
	outputs := map[string]string{
		"reachable.hosts":     "1.1.1.1 example.com\n",
		"reachable.domains":   "example.com\n",
		"reachable.ips":       "1.1.1.1\n",
		"unreachable.domains": "",
		"unreachable.ips":     "192.0.2.1\n",
	}
	for name, data := range outputs {
		if err := os.WriteFile(filepath.Join(source, name), []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(destination, name), []byte("old\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	input := filepath.Join(destination, "passive-domains.txt")
	if err := os.WriteFile(input, []byte("input.example\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(source, "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	count, err := copyOutputFiles(context.Background(), source, destination)
	if err != nil || count != len(outputs) {
		t.Fatalf("copied = %d, error = %v", count, err)
	}
	for name, want := range outputs {
		for _, dir := range []string{source, destination} {
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil || string(data) != want {
				t.Fatalf("%s/%s: %q, error = %v", dir, name, data, err)
			}
		}
	}
	data, err := os.ReadFile(input)
	if err != nil || string(data) != "input.example\n" {
		t.Fatalf("input changed: %q, error = %v", data, err)
	}
	entries, err := os.ReadDir(destination)
	if err != nil || len(entries) != len(outputs)+1 {
		t.Fatalf("unexpected destination entries: %v, error = %v", entries, err)
	}
}

func TestCopyOutputFilesCreatesDestination(t *testing.T) {
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "reachable.ips"), []byte("1.1.1.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "etc", "ipscoutdns")
	if count, err := copyOutputFiles(context.Background(), source, destination); err != nil || count != 1 {
		t.Fatalf("copied = %d, error = %v", count, err)
	}
}

func TestCopyOutputFilesNoOutputsOrCanceled(t *testing.T) {
	source, destination := t.TempDir(), t.TempDir()
	path := filepath.Join(destination, "reachable.ips")
	if err := os.WriteFile(path, []byte("previous\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{source, filepath.Join(source, "missing")} {
		if count, err := copyOutputFiles(context.Background(), dir, destination); err != nil || count != 0 {
			t.Fatalf("copied = %d, error = %v", count, err)
		}
	}
	if err := os.WriteFile(filepath.Join(source, "reachable.ips"), []byte("new\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if count, err := copyOutputFiles(ctx, source, destination); !errors.Is(err, context.Canceled) || count != 0 {
		t.Fatalf("copied = %d, error = %v", count, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "previous\n" {
		t.Fatalf("previous copy changed: %q, error = %v", data, err)
	}
}

func TestCopyOutputFilesDestinationFailure(t *testing.T) {
	source, destination := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "reachable.ips"), []byte("new\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// A directory at the target name forces replacement to fail on every OS.
	if err := os.Mkdir(filepath.Join(destination, "reachable.ips"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := copyOutputFiles(context.Background(), source, destination); err == nil {
		t.Fatal("replacement error ignored")
	}
	entries, err := os.ReadDir(destination)
	if err != nil || len(entries) != 1 || entries[0].Name() != "reachable.ips" {
		t.Fatalf("temporary files left behind: %v, error = %v", entries, err)
	}
}

func TestPassiveCopiesAfterBatchBeforeWait(t *testing.T) {
	cfg := Config{PassiveResolveParallel: 2, PassiveResolveInterval: time.Hour}
	var resolved atomic.Int32
	copies := 0
	err := runPassiveWithOutputs(context.Background(), cfg,
		func(string) ([]string, error) { return []string{"one.example", "two.example"}, nil },
		func(context.Context, string, Config) { resolved.Add(1) },
		func(context.Context, time.Duration) bool {
			if copies != 1 {
				t.Error("wait started before copying")
			}
			return false
		}, func() error { return nil }, func(context.Context) error {
			if resolved.Load() != 2 {
				t.Error("copy started before all workers finished")
			}
			copies++
			return nil
		})
	if err != nil || copies != 1 {
		t.Fatalf("copies = %d, error = %v", copies, err)
	}
}

func TestPassiveCanceledBatchDoesNotCopy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := runPassiveWithOutputs(ctx, Config{PassiveResolveParallel: 1},
		func(string) ([]string, error) { return []string{"one.example", "two.example"}, nil },
		func(context.Context, string, Config) { cancel() },
		func(context.Context, time.Duration) bool { t.Error("wait after canceled batch"); return false },
		func() error { return nil },
		func(context.Context) error { t.Error("copied canceled batch"); return nil })
	if err != nil {
		t.Fatal(err)
	}
}

func TestOutputCopySchedulesContinueAfterFailure(t *testing.T) {
	for _, mode := range []string{"active", "passive"} {
		t.Run(mode, func(t *testing.T) {
			waits, copies := 0, 0
			copyOutputs := func(context.Context) error { copies++; return errors.New("disk unavailable") }
			wait := func(_ context.Context, delay time.Duration) bool {
				waits++
				if delay != time.Hour {
					t.Errorf("delay = %s", delay)
				}
				if mode == "active" && copies != waits-1 {
					t.Error("active copy must wait before each attempt")
				}
				if mode == "passive" && copies != waits {
					t.Error("passive copy must precede each wait")
				}
				return waits < 3
			}
			if mode == "active" {
				runActiveOutputCopies(context.Background(), time.Hour, copyOutputs, wait)
				if copies != 2 {
					t.Fatalf("copies = %d", copies)
				}
			} else {
				err := runPassiveWithOutputs(context.Background(), Config{PassiveResolveParallel: 1, PassiveResolveInterval: time.Hour},
					func(string) ([]string, error) { return []string{"one.example"}, nil },
					func(context.Context, string, Config) {}, wait, func() error { return nil }, copyOutputs)
				if err != nil || copies != 3 {
					t.Fatalf("copies = %d, error = %v", copies, err)
				}
			}
		})
	}
}

func TestActiveCanceledWaitDoesNotCopy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runActiveOutputCopies(ctx, time.Hour,
		func(context.Context) error { t.Error("copied after cancellation"); return nil },
		func(context.Context, time.Duration) bool { cancel(); return true })
}
