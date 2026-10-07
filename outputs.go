package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	openWrtOutputDirectory     = "/tmp/ipscoutdns"
	linuxOutputDirectory       = "/temp/ipscoutdns"
	outputDestinationDirectory = "/etc/ipscoutdns"
)

func runtimeOutputDirectoryWith(goos string, readFile func(string) ([]byte, error), executable func() (string, error)) (string, error) {
	if goos == "windows" {
		path, err := executable()
		if err != nil {
			return "", fmt.Errorf("locate executable: %w", err)
		}
		return filepath.Dir(path), nil
	}
	if goos == "linux" {
		if _, err := readFile("/etc/openwrt_release"); err == nil {
			return openWrtOutputDirectory, nil
		}
		if data, err := readFile("/etc/os-release"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
				if !ok || (key != "ID" && key != "ID_LIKE") {
					continue
				}
				for _, id := range strings.Fields(strings.Trim(value, "\"'")) {
					if id == "openwrt" {
						return openWrtOutputDirectory, nil
					}
				}
			}
		}
	}
	return linuxOutputDirectory, nil
}

func prepareRuntimeOutputs(cfg *Config, configPath string) error {
	dir, err := runtimeOutputDirectoryWith(runtime.GOOS, os.ReadFile, os.Executable)
	if err != nil {
		return err
	}
	if err := configureOutputPaths(cfg, dir, runtime.GOOS == "windows"); err != nil {
		return err
	}
	// The Windows output directory also contains the tool and may contain inputs.
	// Reject output filenames that would overwrite any of those files.
	protected := []string{configPath, cfg.ActiveDomainsFile, cfg.PassiveDomainsFile}
	if executable, err := os.Executable(); err == nil {
		protected = append(protected, executable)
	}
	for _, output := range cfg.outputFiles() {
		for _, input := range protected {
			if input == "" {
				continue
			}
			absolute, err := filepath.Abs(input)
			if err != nil {
				return err
			}
			if output == absolute || (runtime.GOOS == "windows" && strings.EqualFold(output, absolute)) {
				return fmt.Errorf("output file %s conflicts with an input file or executable", output)
			}
		}
	}
	return nil
}

// Config keys still choose filenames; the OS chooses their parent directory.
// Empty optional paths remain disabled, including on Windows.
func configureOutputPaths(cfg *Config, dir string, shared bool) error {
	paths := []*string{&cfg.ReachableHostsFile, &cfg.ReachableDomainsFile, &cfg.ReachableIPsFile, &cfg.UnreachableDomainsFile, &cfg.UnreachableIPsFile}
	seen := make(map[string]bool)
	for _, path := range paths {
		if *path == "" {
			continue
		}
		name := filepath.Base(*path)
		if name == "." || name == ".." || name == string(os.PathSeparator) {
			return fmt.Errorf("invalid output filename %q", *path)
		}
		key := name
		if shared {
			key = strings.ToLower(key)
		}
		if seen[key] {
			return fmt.Errorf("duplicate output filename %q", name)
		}
		seen[key] = true
		*path = filepath.Join(dir, name)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s must be a real directory", dir)
	}
	cfg.outputDirectory = dir
	cfg.outputDirectoryShared = shared
	return nil
}

func (cfg Config) outputFiles() []string {
	files := make([]string, 0, 5)
	for _, path := range []string{cfg.ReachableHostsFile, cfg.ReachableDomainsFile, cfg.ReachableIPsFile, cfg.UnreachableDomainsFile, cfg.UnreachableIPsFile} {
		if path != "" {
			files = append(files, path)
		}
	}
	return files
}

func copyRuntimeOutputs(ctx context.Context, cfg Config, destination string) error {
	if cfg.outputDirectoryShared {
		// Windows outputs are already usable beside the executable.
		return nil
	}
	count, err := copyOutputFiles(ctx, cfg.outputDirectory, destination)
	if err == nil && count > 0 {
		logger.Printf("copied %d output files from %s to %s", count, cfg.outputDirectory, destination)
	}
	return err
}

// Take one snapshot under the output lock, then release it before writing to disk.
// Only regular files directly in the source directory are output files.
func readOutputSnapshot(ctx context.Context, dir string, names map[string]bool) (map[string][]byte, error) {
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
		if names != nil && !names[entry.Name()] {
			continue
		}
		if names == nil && isSavedLogName(entry.Name()) {
			continue
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
	return copyOutputFilesWithNames(ctx, source, destination, nil)
}

func copyOutputFilesWithNames(ctx context.Context, source, destination string, names map[string]bool) (int, error) {
	files, err := readOutputSnapshot(ctx, source, names)
	if err != nil || len(files) == 0 {
		return 0, err
	}
	return writeOutputSnapshot(ctx, files, destination)
}

func writeOutputSnapshot(ctx context.Context, files map[string][]byte, destination string) (int, error) {
	if err := ctx.Err(); err != nil {
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
