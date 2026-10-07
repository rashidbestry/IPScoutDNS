package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	outputSourceDirectory      = "/tmp/ipscoutdns"
	outputDestinationDirectory = "/etc/ipscoutdns"
)

func copyRuntimeOutputs(ctx context.Context) error {
	count, err := copyOutputFiles(ctx, outputSourceDirectory, outputDestinationDirectory)
	if err == nil && count > 0 {
		logger.Printf("copied %d output files from %s to %s", count, outputSourceDirectory, outputDestinationDirectory)
	}
	return err
}

// Take one snapshot under the output lock, then release it before writing to disk.
// Only regular files directly in the source directory are output files.
func readOutputSnapshot(ctx context.Context, dir string) (map[string][]byte, error) {
	hostsMu.Lock()
	defer hostsMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s must be a real directory", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	files := make(map[string][]byte)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		files[entry.Name()] = data
	}
	return files, nil
}

func copyOutputFiles(ctx context.Context, source, destination string) (int, error) {
	files, err := readOutputSnapshot(ctx, source)
	if err != nil || len(files) == 0 {
		return 0, err
	}
	if err := os.MkdirAll(destination, 0755); err != nil {
		return 0, err
	}
	// Stage every file before replacing any previous copies. Renaming each file
	// keeps readers from seeing partial contents; unrelated destination files stay.
	staged := make(map[string]string)
	defer func() {
		for _, path := range staged {
			_ = os.Remove(path)
		}
	}()
	for name, data := range files {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		f, err := os.CreateTemp(destination, ".ipscoutdns-output-*")
		if err != nil {
			return 0, err
		}
		staged[name] = f.Name()
		if err = f.Chmod(0644); err == nil {
			_, err = f.Write(data)
		}
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return 0, err
		}
		if closeErr != nil {
			return 0, closeErr
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	count := 0
	for name, path := range staged {
		if err := os.Rename(path, filepath.Join(destination, name)); err != nil {
			return count, fmt.Errorf("copy %s: %w", name, err)
		}
		count++
	}
	return count, nil
}

// Active mode keeps serving DNS while copying on a separate, non-overlapping
// schedule. The first copy waits a full interval, and failures retry next time.
func runActiveOutputCopies(ctx context.Context, interval time.Duration, copyOutputs func(context.Context) error, wait func(context.Context, time.Duration) bool) {
	for ctx.Err() == nil && wait(ctx, interval) {
		if ctx.Err() != nil {
			return
		}
		if err := copyOutputs(ctx); err != nil && ctx.Err() == nil {
			logger.Printf("failed to copy active outputs: %v", err)
		}
	}
}
