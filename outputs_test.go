package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRuntimeOutputDirectory(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "tool", "ipscoutdns.exe")
	for _, test := range []struct {
		name, goos, release, osRelease, want string
	}{
		{"OpenWrt release", "linux", "DISTRIB_ID='OpenWrt'", "", openWrtOutputDirectory},
		{"OpenWrt OS ID", "linux", "", "ID=\"openwrt\"\n", openWrtOutputDirectory},
		{"OpenWrt derivative", "linux", "", "ID=router\nID_LIKE='linux openwrt'\n", openWrtOutputDirectory},
		{"Linux", "linux", "", "ID=ubuntu\nID_LIKE=debian\n", linuxOutputDirectory},
		{"Linux without release files", "linux", "", "", linuxOutputDirectory},
		{"unrelated release name", "linux", "", "NAME=OpenWrt\nID=debian\n", linuxOutputDirectory},
		{"Windows executable directory", "windows", "", "", filepath.Dir(executable)},
	} {
		t.Run(test.name, func(t *testing.T) {
			readFile := func(path string) ([]byte, error) {
				if path == "/etc/openwrt_release" && test.release != "" {
					return []byte(test.release), nil
				}
				if path == "/etc/os-release" && test.osRelease != "" {
					return []byte(test.osRelease), nil
				}
				return nil, os.ErrNotExist
			}
			got, err := runtimeOutputDirectoryWith(test.goos, readFile, func() (string, error) { return executable, nil })
			if err != nil || got != test.want {
				t.Fatalf("directory = %q, error = %v, want %q", got, err, test.want)
			}
		})
	}
	_, err := runtimeOutputDirectoryWith("windows", nil, func() (string, error) { return "", errors.New("unavailable") })
	if err == nil {
		t.Fatal("executable lookup failure was ignored")
	}
}

func TestRuntimeOutputFilesBothModes(t *testing.T) {
	previousConfig := currentConfig
	t.Cleanup(func() { currentConfig = previousConfig })
	for _, mode := range []string{"active", "passive"} {
		for _, platform := range []string{"OpenWrt", "Linux", "Windows"} {
			t.Run(mode+"/"+platform, func(t *testing.T) {
				cfg, err := loadConfig(writeModeTestFile(t, "mode="+mode+"\nactive_domains_file=active.txt\npassive_domains_file=passive.txt\ndirect_dns=1.1.1.1\nreachable_hosts=old/custom.hosts\nreachable_domains=reachable.domains\nreachable_ips=reachable.ips\nunreachable_domains=unreachable.domains\nunreachable_ips=unreachable.ips\n"))
				if err != nil {
					t.Fatal(err)
				}
				dir := filepath.Join(t.TempDir(), "outputs")
				if err := configureOutputPaths(&cfg, dir, platform == "Windows"); err != nil {
					t.Fatal(err)
				}
				currentConfig = cfg
				recordReachableHost("example.com", "1.1.1.1")
				recordDomainUnreachable("failed.example")
				recordUnreachableIP("192.0.2.1")
				files, err := readOutputSnapshot(context.Background(), cfg.outputDirectory, nil)
				if err != nil || len(files) != 5 || string(files["custom.hosts"]) != "1.1.1.1 example.com\n" {
					t.Fatalf("outputs = %q, error = %v", files, err)
				}
				for _, path := range cfg.outputFiles() {
					if filepath.Dir(path) != dir {
						t.Fatalf("output %q is outside %q", path, dir)
					}
				}
				destination := filepath.Join(t.TempDir(), "etc", "ipscoutdns", "outputs")
				if err := copyRuntimeOutputs(context.Background(), cfg, destination); err != nil {
					t.Fatal(err)
				}
				copies, err := readOutputSnapshot(context.Background(), destination, nil)
				if platform == "Windows" {
					if err != nil || len(copies) != 0 {
						t.Fatalf("Windows outputs were copied: %q, error = %v", copies, err)
					}
					return
				}
				if err != nil || len(copies) != len(files) || string(copies["custom.hosts"]) != string(files["custom.hosts"]) {
					t.Fatalf("copies = %q, error = %v", copies, err)
				}
			})
		}
	}
}

func TestOutputPathsDisabledAndInvalid(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{ReachableIPsFile: filepath.Join("old", "reachable.ips")}
	if err := configureOutputPaths(&cfg, dir, true); err != nil || cfg.ReachableIPsFile != filepath.Join(dir, "reachable.ips") || len(cfg.outputFiles()) != 1 {
		t.Fatalf("configured outputs = %v, error = %v", cfg.outputFiles(), err)
	}
	for _, cfg := range []Config{
		{ReachableIPsFile: "."},
		{ReachableIPsFile: ".."},
		{ReachableIPsFile: "old/same.ips", UnreachableIPsFile: "other/SAME.ips"},
	} {
		if err := configureOutputPaths(&cfg, dir, true); err == nil {
			t.Fatal("invalid or duplicate filename accepted")
		}
	}
	blocked := filepath.Join(dir, "blocked")
	if err := os.WriteFile(blocked, []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := configureOutputPaths(&cfg, filepath.Join(blocked, "outputs"), false); err == nil {
		t.Fatal("output directory creation failure was ignored")
	}
}

func TestWindowsOutputsPreserveToolFiles(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(t.TempDir(), "must-not-create")
	cfg := Config{ReachableIPsFile: "reachable.ips"}
	if err := configureOutputPaths(&cfg, dir, true); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ipscoutdns.exe", "ipscoutdns.conf", "passive-domains.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	appendUniqueLine(cfg.ReachableIPsFile, "1.1.1.1", writtenReachableIPs)
	if err := clearPassiveOutputFiles(cfg.outputFiles()); err != nil {
		t.Fatal(err)
	}
	appendUniqueLine(cfg.ReachableIPsFile, "1.1.1.1", writtenReachableIPs)
	if err := copyRuntimeOutputs(context.Background(), cfg, destination); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ipscoutdns.exe", "ipscoutdns.conf", "passive-domains.txt"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(data) != "keep" {
			t.Fatalf("tool file %s changed: %q, error = %v", name, data, err)
		}
		if _, err := os.Stat(filepath.Join(destination, name)); !os.IsNotExist(err) {
			t.Fatalf("tool file %s was copied", name)
		}
	}
	data, err := os.ReadFile(cfg.ReachableIPsFile)
	if err != nil || string(data) != "1.1.1.1\n" {
		t.Fatalf("output after cleanup = %q, error = %v", data, err)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("Windows copy created a destination: %v", err)
	}
	if err := clearPassiveOutputFiles([]string{dir}); err == nil {
		t.Fatal("cleanup accepted a directory as an output file")
	}
}

func TestRuntimeOutputRejectsExecutableOverwrite(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows outputs share the executable directory")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{ReachableHostsFile: filepath.Base(executable)}
	if err := prepareRuntimeOutputs(&cfg, ""); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("executable overwrite protection: %v", err)
	}
}

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
	destination := filepath.Join(t.TempDir(), "etc", "ipscoutdns", "outputs")
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
