package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSaveLogsConfig(t *testing.T) {
	for _, mode := range []string{"active", "passive"} {
		for _, test := range []struct {
			settings string
			wantSave bool
			interval time.Duration
			wantErr  bool
		}{
			{"", false, time.Hour, false},
			{"save_logs = true\nactive_log_copy_interval=30m\n", true, 30 * time.Minute, false},
			{"save_logs=false\n", false, time.Hour, false},
			{"save_logs=maybe\n", false, 0, true},
			{"save_logs=\n", false, 0, true},
			{"active_log_copy_interval=0h\n", false, 0, true},
			{"active_log_copy_interval=-1h\n", false, 0, true},
			{"active_log_copy_interval=bad\n", false, 0, true},
		} {
			cfg, err := loadConfig(writeModeTestFile(t, "mode="+mode+"\nactive_domains_file=active.txt\npassive_domains_file=passive.txt\ndirect_dns=1.1.1.1\n"+test.settings))
			if test.wantErr {
				if err == nil {
					t.Fatalf("%s accepted %q", mode, test.settings)
				}
				continue
			}
			if err != nil || cfg.SaveLogs != test.wantSave || cfg.ActiveLogCopyInterval != test.interval {
				t.Fatalf("%s %q: save=%t, interval=%s, error=%v", mode, test.settings, cfg.SaveLogs, cfg.ActiveLogCopyInterval, err)
			}
		}
	}
}

func testSavedLog(t *testing.T, shared bool) Config {
	t.Helper()
	cfg := Config{SaveLogs: true, LogMaxSize: defaultLogMaxSize, LogKeepFiles: defaultLogKeepFiles, outputDirectory: t.TempDir(), outputDirectoryShared: shared}
	var err error
	cfg.savedLog, err = openSavedLog(cfg, time.Date(2026, 10, 7, 15, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cfg.savedLog.Close() })
	return cfg
}

func TestSavedLogLocationsAndMirroring(t *testing.T) {
	for _, shared := range []bool{false, true} {
		cfg := testSavedLog(t, shared)
		wantDir := cfg.outputDirectory
		if shared {
			wantDir = filepath.Join(wantDir, "logs")
		}
		if cfg.savedLog.path != filepath.Join(wantDir, "ipscoutdns_log_2026-10-07_15-30-00.txt") {
			t.Fatal(cfg.savedLog.path)
		}
		var console bytes.Buffer
		l := log.New(loggingOutput(&console, true, cfg.savedLog), "[ipscoutdns] ", log.LstdFlags)
		l.Printf("starting IPScoutDNS")
		l.Printf("- config")
		l.Printf("\t- save_logs=true")
		l.Printf("- output")
		l.SetOutput(indentedLogWriter{output: l.Writer(), messageOffset: len(l.Prefix()) + len("2006/01/02 15:04:05 ")})
		l.Printf("example.com: WORKING IP = 1.1.1.1 [TLS]")
		data, err := cfg.savedLog.snapshot(context.Background())
		if err != nil || string(data) != console.String() {
			t.Fatalf("file differs from console: %q, error=%v", data, err)
		}
		console.Reset()
		l.SetOutput(loggingOutput(&console, false, cfg.savedLog))
		l.Printf("file only")
		data, err = cfg.savedLog.snapshot(context.Background())
		if err != nil || console.Len() != 0 || !bytes.Contains(data, []byte("file only")) {
			t.Fatalf("saving with console off: %q, error=%v", data, err)
		}
		second, err := openSavedLog(cfg, time.Date(2026, 10, 7, 15, 30, 0, 0, time.UTC))
		if err != nil {
			t.Fatal(err)
		}
		second.Close()
		if second.path == cfg.savedLog.path {
			t.Fatal("same-second restart reused the original log")
		}
	}
	root := t.TempDir()
	file, err := openSavedLog(Config{outputDirectory: root, outputDirectoryShared: true}, time.Now())
	if err != nil || file != nil {
		t.Fatalf("saving disabled: %v %v", file, err)
	}
	if _, err := os.Stat(filepath.Join(root, "logs")); !os.IsNotExist(err) {
		t.Fatal("disabled saving created a log folder")
	}
}

func TestSavedLogCopyAndPassiveCleanup(t *testing.T) {
	cfg := testSavedLog(t, false)
	if _, err := cfg.savedLog.Write([]byte("startup\n")); err != nil {
		t.Fatal(err)
	}
	oldLog := filepath.Join(cfg.outputDirectory, "ipscoutdns_log_2026-10-06_12-00-00.txt")
	if err := os.WriteFile(oldLog, []byte("old log"), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(cfg.outputDirectory, "reachable.ips")
	if err := os.WriteFile(output, []byte("1.1.1.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	if err := copyRuntimeOutputs(context.Background(), cfg, destination); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(destination)
	if err != nil || len(entries) != 1 || entries[0].Name() != "reachable.ips" {
		t.Fatalf("host copy included log files: %v %v", entries, err)
	}
	if err := clearPassiveOutputDirectory(cfg.outputDirectory); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(oldLog); err != nil || string(data) != "old log" {
		t.Fatal("cleanup removed the previous log")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("cleanup retained host output")
	}
	logDestination := filepath.Join(destination, "logs")
	for _, line := range []string{"first pass\n", "second pass\n"} {
		cfg.savedLog.Write([]byte(line))
		if err := copyRuntimeLog(context.Background(), cfg, logDestination); err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(cfg.savedLog.path)
		got, copyErr := os.ReadFile(filepath.Join(logDestination, filepath.Base(cfg.savedLog.path)))
		if err != nil || copyErr != nil || !bytes.Equal(got, want) {
			// Copy confirmation is logged through the global logger, not this test file.
			t.Fatalf("copied log=%q, source=%q, errors=%v/%v", got, want, copyErr, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := copyRuntimeLog(ctx, cfg, filepath.Join(destination, "canceled")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled copy: %v", err)
	}
	for _, disabled := range []Config{{SaveLogs: false}, {SaveLogs: true, outputDirectoryShared: true, savedLog: cfg.savedLog}} {
		unused := filepath.Join(destination, "unused")
		if err := copyRuntimeLog(context.Background(), disabled, unused); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(unused); !os.IsNotExist(err) {
			t.Fatal("disabled or Windows log copy created a directory")
		}
	}
}

func TestPassiveLogCopiesAfterCompletionAndSkipsCancellation(t *testing.T) {
	oldWriter := logger.Writer()
	var console bytes.Buffer
	logger.SetOutput(&console)
	t.Cleanup(func() { logger.SetOutput(oldWriter) })
	for _, canceled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		resolved, hostCopied, logCopied := false, false, false
		err := runPassiveWithLogs(ctx, Config{PassiveResolveParallel: 1, PassiveResolveInterval: time.Hour},
			func(string) ([]string, error) { return []string{"example.com"}, nil },
			func(context.Context, string, Config) {
				resolved = true
				if canceled {
					cancel()
				}
			},
			func(context.Context, time.Duration) bool {
				if !logCopied {
					t.Error("wait before log copy")
				}
				return false
			}, func() error { return nil },
			func(context.Context) error { hostCopied = true; return nil },
			func(context.Context) error {
				if !resolved || !hostCopied || !strings.Contains(console.String(), "passive pass complete") {
					t.Error("log copy preceded completion")
				}
				logCopied = true
				return nil
			})
		cancel()
		if err != nil || logCopied == canceled || (canceled && hostCopied) {
			t.Fatalf("canceled=%t, hostCopied=%t, logCopied=%t, error=%v", canceled, hostCopied, logCopied, err)
		}
	}
}

func TestActiveLogCopyIntervalAndRetry(t *testing.T) {
	waits, copies := 0, 0
	runActiveLogCopies(context.Background(), 30*time.Minute,
		func(context.Context) error { copies++; return errors.New("disk unavailable") },
		func(_ context.Context, interval time.Duration) bool {
			waits++
			if interval != 30*time.Minute || copies != waits-1 {
				t.Error("wrong log interval or copy before wait")
			}
			return waits < 3
		})
	if copies != 2 {
		t.Fatalf("copies=%d", copies)
	}
}
