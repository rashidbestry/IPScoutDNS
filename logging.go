package main

import (
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const savedLogPrefix = "ipscoutdns_log_"

type savedLog struct {
	mu              sync.Mutex
	copyMu          sync.Mutex
	file            *os.File
	path            string
	dir             string
	size            int64
	maxSize         int64
	keepFiles       int
	shared          bool
	now             func() time.Time
	copiedSizes     map[string]int64
	copyDestination string
}

func isSavedLogName(name string) bool {
	_, _, ok := savedLogDate(name)
	return ok
}

func savedLogDate(name string) (time.Time, uint64, bool) {
	if !strings.HasPrefix(name, savedLogPrefix) || !strings.HasSuffix(name, ".txt") {
		return time.Time{}, 0, false
	}
	stamp := strings.TrimSuffix(strings.TrimPrefix(name, savedLogPrefix), ".txt")
	if len(stamp) < 19 {
		return time.Time{}, 0, false
	}
	date, err := time.Parse("2006-01-02_15-04-05", stamp[:19])
	if err != nil {
		return time.Time{}, 0, false
	}
	var sequence uint64
	if len(stamp) > 19 {
		if stamp[19] != '_' {
			return time.Time{}, 0, false
		}
		for _, digit := range stamp[20:] {
			if digit < '0' || digit > '9' {
				return time.Time{}, 0, false
			}
		}
		sequence, err = strconv.ParseUint(stamp[20:], 10, 64)
		if err != nil || sequence == 0 {
			return time.Time{}, 0, false
		}
	}
	return date, sequence, true
}

func parseLogMaxSize(value string) (int64, error) {
	number := strings.ToUpper(strings.TrimSpace(value))
	multiplier := int64(1)
	for _, unit := range []struct {
		suffix string
		bytes  int64
	}{
		{"GIB", 1 << 30}, {"MIB", 1 << 20}, {"KIB", 1 << 10},
		{"GB", 1000 * 1000 * 1000}, {"MB", 1000 * 1000}, {"KB", 1000}, {"B", 1},
	} {
		if strings.HasSuffix(number, unit.suffix) {
			number = strings.TrimSpace(strings.TrimSuffix(number, unit.suffix))
			multiplier = unit.bytes
			break
		}
	}
	n, err := strconv.ParseInt(number, 10, 64)
	if err != nil || n <= 0 || n > math.MaxInt64/multiplier {
		return 0, fmt.Errorf("expected a positive whole size in bytes, KB, MB, GB, KiB, MiB or GiB")
	}
	return n * multiplier, nil
}

func openSavedLog(cfg Config, now time.Time) (*savedLog, error) {
	if !cfg.SaveLogs {
		return nil, nil
	}
	if cfg.LogMaxSize <= 0 || cfg.LogKeepFiles <= 0 {
		return nil, fmt.Errorf("log_max_size and log_keep_files must be greater than zero")
	}
	dir := cfg.outputDirectory
	if cfg.outputDirectoryShared {
		dir = filepath.Join(dir, "logs")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s must be a real log directory", dir)
	}
	l := &savedLog{dir: dir, maxSize: cfg.LogMaxSize, keepFiles: cfg.LogKeepFiles,
		shared: cfg.outputDirectoryShared, now: time.Now, copiedSizes: make(map[string]int64)}
	file, path, err := createSavedLog(dir, now)
	if err != nil {
		return nil, err
	}
	l.file, l.path = file, path
	if l.shared {
		if err := l.pruneSourceLocked(); err != nil {
			file.Close()
			os.Remove(path)
			return nil, err
		}
	}
	return l, nil
}

func createSavedLog(dir string, now time.Time) (*os.File, string, error) {
	base := savedLogPrefix + now.Format("2006-01-02_15-04-05")
	logs, err := listSavedLogs(dir)
	if err != nil {
		return nil, "", err
	}
	var start uint64
	for _, entry := range logs {
		if strings.HasPrefix(entry.name, base) && entry.sequence >= start {
			if entry.sequence == math.MaxUint64 {
				return nil, "", fmt.Errorf("log filename sequence exhausted")
			}
			start = entry.sequence + 1
		}
	}
	for suffix := start; ; suffix++ {
		name := base
		if suffix > 0 {
			name += fmt.Sprintf("_%d", suffix)
		}
		path := filepath.Join(dir, name+".txt")
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if os.IsExist(err) {
			if suffix == math.MaxUint64 {
				return nil, "", fmt.Errorf("log filename sequence exhausted")
			}
			continue
		}
		if err != nil {
			return nil, "", err
		}
		return file, path, nil
	}
}

func (l *savedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	rotated := l.size > 0 && (l.size >= l.maxSize || int64(len(p)) > l.maxSize-l.size)
	if rotated {
		file, path, err := createSavedLog(l.dir, l.now())
		if err != nil {
			return 0, err
		}
		if err := l.file.Sync(); err != nil {
			file.Close()
			os.Remove(path)
			return 0, err
		}
		old := l.file
		l.file, l.path, l.size = file, path, 0
		if err := old.Close(); err != nil {
			return 0, err
		}
	}
	n, err := l.file.Write(p)
	l.size += int64(n)
	if err == nil && rotated && l.shared {
		err = l.pruneSourceLocked()
	}
	return n, err
}

func (l *savedLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

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

type savedLogEntry struct {
	name     string
	size     int64
	date     time.Time
	sequence uint64
}

func listSavedLogs(dir string) ([]savedLogEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var logs []savedLogEntry
	for _, entry := range entries {
		date, sequence, ok := savedLogDate(entry.Name())
		if !ok || !entry.Type().IsRegular() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if info.Mode().IsRegular() {
			logs = append(logs, savedLogEntry{entry.Name(), info.Size(), date, sequence})
		}
	}
	sort.Slice(logs, func(i, j int) bool {
		if logs[i].date.Equal(logs[j].date) {
			return logs[i].sequence > logs[j].sequence
		}
		return logs[i].date.After(logs[j].date)
	})
	return logs, nil
}

// The active file counts toward retention and is protected even if the clock
// moves backward. Linux/OpenWrt additionally protects any uncopied contents.
func (l *savedLog) pruneSourceLocked() error {
	err := pruneSavedLogs(l.dir, l.keepFiles, filepath.Base(l.path), func(entry savedLogEntry) bool {
		size, ok := l.copiedSizes[entry.name]
		return l.shared || ok && size == entry.size
	})
	if err != nil {
		return err
	}
	for name := range l.copiedSizes {
		if _, err := os.Lstat(filepath.Join(l.dir, name)); os.IsNotExist(err) {
			delete(l.copiedSizes, name)
		}
	}
	return nil
}

func hasCopiedSize(sizes map[string]int64, name string) bool {
	_, ok := sizes[name]
	return ok
}

func pruneSavedLogs(dir string, keep int, current string, removable func(savedLogEntry) bool) error {
	logs, err := listSavedLogs(dir)
	if err != nil {
		return err
	}
	kept := 0
	for _, entry := range logs {
		if entry.name == current {
			kept = 1
			break
		}
	}
	for _, entry := range logs {
		if entry.name == current {
			continue
		}
		if kept < keep {
			kept++
			continue
		}
		if removable != nil && !removable(entry) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (l *savedLog) copyTo(ctx context.Context, destination string) (int, error) {
	l.copyMu.Lock()
	defer l.copyMu.Unlock()
	l.mu.Lock()
	if l.copyDestination != destination {
		l.copyDestination = destination
		l.copiedSizes = make(map[string]int64)
	}
	logs, err := listSavedLogs(l.dir)
	l.mu.Unlock()
	if err != nil {
		return 0, err
	}
	copied := 0
	for _, entry := range logs {
		if err := ctx.Err(); err != nil {
			return copied, err
		}
		path := filepath.Join(l.dir, entry.name)
		l.mu.Lock()
		alreadyCopied := path != l.path && hasCopiedSize(l.copiedSizes, entry.name) && l.copiedSizes[entry.name] == entry.size
		if alreadyCopied {
			info, statErr := os.Lstat(filepath.Join(destination, entry.name))
			alreadyCopied = statErr == nil && info.Mode().IsRegular() && info.Size() == entry.size
		}
		if alreadyCopied {
			l.mu.Unlock()
			continue
		}
		if path == l.path {
			err = l.file.Sync()
		}
		var data []byte
		if err == nil {
			data, err = os.ReadFile(path)
		}
		l.mu.Unlock()
		if err != nil {
			return copied, err
		}
		if _, err := writeOutputSnapshot(ctx, map[string][]byte{entry.name: data}, destination); err != nil {
			return copied, err
		}
		l.mu.Lock()
		l.copiedSizes[entry.name] = int64(len(data))
		l.mu.Unlock()
		copied++
	}
	if err := ctx.Err(); err != nil {
		return copied, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := pruneSavedLogs(destination, l.keepFiles, filepath.Base(l.path), nil); err != nil {
		return copied, err
	}
	return copied, l.pruneSourceLocked()
}

// Saving is independent of console suppression. Writes are unbuffered, so
// startup failures and runtime messages are available to each copy snapshot.
func loggingOutput(console io.Writer, enabled bool, file *savedLog) io.Writer {
	if !enabled {
		console = io.Discard
	}
	if file == nil {
		return console
	}
	return io.MultiWriter(console, file)
}

func copyRuntimeLog(ctx context.Context, cfg Config, destination string) error {
	if !cfg.SaveLogs || cfg.outputDirectoryShared || cfg.savedLog == nil {
		return nil
	}
	count, err := cfg.savedLog.copyTo(ctx, destination)
	if err == nil && count > 0 {
		logger.Printf("copied %d log files from %s to %s", count, cfg.savedLog.dir, destination)
	}
	return err
}

func runActiveLogCopies(ctx context.Context, interval time.Duration, copyLog func(context.Context) error, wait func(context.Context, time.Duration) bool) {
	runActiveOutputCopies(ctx, interval, func(ctx context.Context) error {
		if err := copyLog(ctx); err != nil && ctx.Err() == nil {
			logger.Printf("failed to copy active log: %v", err)
		}
		return nil
	}, wait)
}
