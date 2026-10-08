package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Whole-file reads are convenient for assertions, but never used by log copies.
func (l *savedLog) snapshot(ctx context.Context) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := l.file.Sync(); err != nil {
		return nil, err
	}
	return os.ReadFile(l.path)
}

type logSnapshotReaderFunc func([]byte) (int, error)

func (f logSnapshotReaderFunc) Read(p []byte) (int, error) { return f(p) }

func TestLogSnapshotStreamsBoundedChunks(t *testing.T) {
	const size = int64(8*1024*1024 + 17)
	remaining, reads := size, 0
	wantHash := sha256.New()
	source := logSnapshotReaderFunc(func(p []byte) (int, error) {
		reads++
		if len(p) > logCopyBufferSize {
			t.Fatalf("unbounded read: %d bytes", len(p))
		}
		if remaining == 0 {
			t.Fatal("read beyond the snapshot boundary")
		}
		n := len(p)
		if int64(n) > remaining {
			n = int(remaining)
		}
		for i := 0; i < n; i++ {
			p[i] = byte((size - remaining + int64(i)) % 251)
		}
		wantHash.Write(p[:n])
		remaining -= int64(n)
		return n, nil
	})
	destination := t.TempDir()
	if err := writeLogSnapshot(context.Background(), source, size, "log.txt", destination, make([]byte, logCopyBufferSize)); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 || reads != int((size+logCopyBufferSize-1)/logCopyBufferSize) {
		t.Fatalf("remaining=%d, reads=%d", remaining, reads)
	}
	file, err := os.Open(filepath.Join(destination, "log.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gotHash := sha256.New()
	n, err := io.Copy(gotHash, file)
	if err != nil || n != size || !bytes.Equal(gotHash.Sum(nil), wantHash.Sum(nil)) {
		t.Fatalf("streamed snapshot corrupted: size=%d error=%v", n, err)
	}
}

func TestLogSnapshotExcludesConcurrentAppendAndSurvivesRotation(t *testing.T) {
	prefix := strings.Repeat("complete record\n", 10000)
	cfg := rotationLog(t, false, int64(len(prefix)+100), 7)
	writeLogRecord(t, cfg.savedLog, prefix)
	path := cfg.savedLog.path
	source, size, err := cfg.savedLog.openSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	// These writes must be able to take the logging lock during streaming.
	firstRead := true
	reader := logSnapshotReaderFunc(func(p []byte) (int, error) {
		if firstRead {
			firstRead = false
			writeLogRecord(t, cfg.savedLog, "appended after snapshot\n")
			writeLogRecord(t, cfg.savedLog, strings.Repeat("next file\n", 20))
			if cfg.savedLog.path == path {
				t.Fatal("writer did not rotate")
			}
		}
		return source.Read(p)
	})
	destination := t.TempDir()
	name := filepath.Base(path)
	if err := writeLogSnapshot(context.Background(), reader, size, name, destination, make([]byte, logCopyBufferSize)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(destination, name))
	if err != nil || string(data) != prefix {
		t.Fatalf("snapshot included later bytes or lost its prefix: %v", err)
	}
	if _, err := cfg.savedLog.copyTo(context.Background(), destination); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(filepath.Join(destination, name))
	if err != nil || string(data) != prefix+"appended after snapshot\n" {
		t.Fatalf("next copy lost the pending tail: %v", err)
	}
}

func TestLogSnapshotFailurePreservesArchiveAndCleansTemporaryFile(t *testing.T) {
	for _, failure := range []string{"canceled before copy", "canceled mid-copy", "short source", "read failure"} {
		t.Run(failure, func(t *testing.T) {
			destination := t.TempDir()
			path := filepath.Join(destination, "log.txt")
			if err := os.WriteFile(path, []byte("previous complete archive"), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var source io.Reader = strings.NewReader(strings.Repeat("x", 2*logCopyBufferSize))
			wantErr := context.Canceled
			switch failure {
			case "canceled before copy":
				cancel()
			case "canceled mid-copy":
				reads := 0
				original := source
				source = logSnapshotReaderFunc(func(p []byte) (int, error) {
					reads++
					if reads == 2 {
						cancel()
					}
					return original.Read(p)
				})
			case "short source":
				source = strings.NewReader("short")
				wantErr = io.ErrUnexpectedEOF
			case "read failure":
				wantErr = errors.New("source read failed")
				source = logSnapshotReaderFunc(func([]byte) (int, error) { return 0, wantErr })
			}
			err := writeLogSnapshot(ctx, source, int64(2*logCopyBufferSize), "log.txt", destination, make([]byte, logCopyBufferSize))
			if !errors.Is(err, wantErr) {
				t.Fatalf("error=%v, want %v", err, wantErr)
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != "previous complete archive" {
				t.Fatal("failed copy replaced the previous archive")
			}
			entries, err := os.ReadDir(destination)
			if err != nil || len(entries) != 1 || entries[0].Name() != "log.txt" {
				t.Fatalf("temporary file leaked: %v %v", entries, err)
			}
		})
	}
}

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

func setTestOutputLogger(t *testing.T, cfg Config, console *bytes.Buffer) {
	t.Helper()
	oldWriter := logger.Writer()
	logger.SetOutput(indentedLogWriter{
		output:        loggingOutput(console, cfg.LogsEnabled, cfg.savedLog),
		messageOffset: len(logger.Prefix()) + len("2006/01/02 15:04:05 "),
	})
	t.Cleanup(func() { logger.SetOutput(oldWriter) })
}

func TestFinalActiveLogCopyIncludesShutdownAndPendingLogs(t *testing.T) {
	cfg := rotationLog(t, false, 128, 7)
	cfg.Mode, cfg.LogsEnabled = "active", true
	var console bytes.Buffer
	setTestOutputLogger(t, cfg, &console)
	logger.Printf("%s", strings.Repeat("earlier message ", 10))
	logger.Printf("shutdown signal received, stopping DNS servers")
	destination := t.TempDir()
	finishLoggingWithCopy(cfg, &console, finalActiveLogCopyTimeout, func(ctx context.Context) error {
		if ctx.Err() != nil {
			t.Fatal("final copy started with a canceled context")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("final copy has no deadline")
		}
		return copyRuntimeLog(ctx, cfg, destination)
	})
	records, err := listSavedLogs(cfg.savedLog.dir)
	if err != nil || len(records) < 2 {
		t.Fatalf("pending rotated logs: %v, %v", records, err)
	}
	var archived bytes.Buffer
	for _, record := range records {
		source, err := os.ReadFile(filepath.Join(cfg.savedLog.dir, record.name))
		if err != nil {
			t.Fatal(err)
		}
		copy, err := os.ReadFile(filepath.Join(destination, record.name))
		if err != nil || !bytes.Equal(source, copy) {
			t.Fatalf("final archive differs from source %s: %v", record.name, err)
		}
		archived.Write(copy)
	}
	for _, message := range []string{"earlier message", "\tshutdown signal received", "\tIPScoutDNS stopped cleanly"} {
		if !strings.Contains(archived.String(), message) {
			t.Fatalf("archive missing %q: %s", message, archived.String())
		}
	}
	if !strings.Contains(console.String(), "\tcopied ") || strings.Contains(archived.String(), "copied ") {
		t.Fatal("final copy confirmation must appear only in the console")
	}
}

func TestFinalActiveLogCopyTimeoutPreservesFailure(t *testing.T) {
	cfg := testSavedLog(t, false)
	cfg.Mode = "active"
	var console bytes.Buffer
	setTestOutputLogger(t, cfg, &console)
	finishLoggingWithCopy(cfg, &console, 10*time.Millisecond, func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	data, err := cfg.savedLog.snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("IPScoutDNS stopped cleanly")) || !bytes.Contains(data, []byte("failed to copy final active log: context deadline exceeded")) {
		t.Fatalf("shutdown or copy failure was not saved: %s", data)
	}
	if console.Len() != 0 {
		t.Fatal("logs_enabled=false printed shutdown output")
	}
}

func TestFinalLogCopySkippedWhenNotNeeded(t *testing.T) {
	for _, name := range []string{"passive", "windows", "saving disabled", "no saved log"} {
		t.Run(name, func(t *testing.T) {
			cfg := testSavedLog(t, false)
			cfg.Mode, cfg.LogsEnabled = "active", true
			switch name {
			case "passive":
				cfg.Mode = "passive"
			case "windows":
				cfg.outputDirectoryShared = true
			case "saving disabled":
				cfg.SaveLogs = false
			case "no saved log":
				cfg.savedLog = nil
			}
			var console bytes.Buffer
			setTestOutputLogger(t, cfg, &console)
			finishLoggingWithCopy(cfg, &console, finalActiveLogCopyTimeout, func(context.Context) error {
				t.Fatal("unexpected final log copy")
				return nil
			})
			if !strings.Contains(console.String(), "\tIPScoutDNS stopped cleanly") {
				t.Fatal("shutdown message missing")
			}
		})
	}
}
