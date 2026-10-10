package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestDomainStatusChangesImmediately(t *testing.T) {
	previousConfig := currentConfig
	t.Cleanup(func() { currentConfig = previousConfig })
	dir := t.TempDir()
	currentConfig = Config{
		ReachableDomainsFile:   filepath.Join(dir, "reachable.domains"),
		UnreachableDomainsFile: filepath.Join(dir, "unreachable.domains"),
	}
	const domain = "example.com"
	for _, reachable := range []bool{false, true, false, true} {
		if reachable {
			recordReachableDomain(domain)
		} else {
			recordDomainUnreachable(domain)
		}
		for path, present := range map[string]bool{
			currentConfig.ReachableDomainsFile:   reachable,
			currentConfig.UnreachableDomainsFile: !reachable,
		} {
			contents, err := os.ReadFile(path)
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			want := ""
			if present {
				want = domain + "\n"
			}
			if string(contents) != want {
				t.Fatalf("%s = %q, want %q", path, contents, want)
			}
		}
	}
}

func TestPingRetriesAndStopsAfterSuccess(t *testing.T) {
	calls := 0
	got := pingIPWithRunner(context.Background(), "192.0.2.1", func(context.Context, string) ([]byte, error) {
		calls++
		if calls < 3 {
			return []byte("Request timed out."), errors.New("exit status 1")
		}
		return nil, nil
	})
	if !got || calls != 3 {
		t.Fatalf("reachable = %v, calls = %d; want true, 3", got, calls)
	}
	calls = 0
	got = pingIPWithRunner(context.Background(), "192.0.2.1", func(context.Context, string) ([]byte, error) {
		calls++
		return nil, nil
	})
	if !got || calls != 1 {
		t.Fatalf("reachable = %v, calls = %d; want true, 1", got, calls)
	}
}

func TestPingFailureAndCancellation(t *testing.T) {
	calls := 0
	run := func(context.Context, string) ([]byte, error) {
		calls++
		return nil, errors.New("ping failed")
	}
	if pingIPWithRunner(context.Background(), "192.0.2.1", run) || calls != 3 {
		t.Fatalf("persistent failure calls = %d, want 3", calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	got := pingIPWithRunner(ctx, "192.0.2.1", func(context.Context, string) ([]byte, error) {
		calls++
		cancel()
		return nil, context.Canceled
	})
	if got || calls != 1 {
		t.Fatalf("canceled ping reachable = %v, calls = %d", got, calls)
	}
}

func TestReachableIPRemovesPreviousFailure(t *testing.T) {
	previousConfig := currentConfig
	t.Cleanup(func() { currentConfig = previousConfig })
	dir := t.TempDir()
	currentConfig = Config{
		ReachableIPsFile:   filepath.Join(dir, "reachable.ips"),
		UnreachableIPsFile: filepath.Join(dir, "unreachable.ips"),
	}
	const ip = "192.0.2.1"
	recordUnreachableIP(ip)
	recordReachableIP(ip)
	unreachable, err := os.ReadFile(currentConfig.UnreachableIPsFile)
	if err != nil || len(unreachable) != 0 {
		t.Fatalf("unreachable = %q, error = %v", unreachable, err)
	}
	reachable, err := os.ReadFile(currentConfig.ReachableIPsFile)
	if err != nil || string(reachable) != ip+"\n" {
		t.Fatalf("reachable = %q, error = %v", reachable, err)
	}
}

func TestRecordHostRetriesFailedWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs", "reachable.hosts")
	recordHost(path, "example.com", "192.0.2.1")
	if err := os.Mkdir(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	recordHost(path, "example.com", "192.0.2.1")
	recordHost(path, "example.com", "192.0.2.1")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "192.0.2.1 example.com\n" {
		t.Fatalf("hosts = %q", contents)
	}
	otherPath := filepath.Join(dir, "other.hosts")
	recordHost(otherPath, "example.com", "192.0.2.1")
	other, err := os.ReadFile(otherPath)
	if err != nil || string(other) != string(contents) {
		t.Fatalf("other hosts = %q, error = %v", other, err)
	}
}

func TestPingArgs(t *testing.T) {
	var want []string
	switch runtime.GOOS {
	case "linux":
		want = []string{"-c", "1", "-W", "1", "192.0.2.1"}
	case "windows":
		want = []string{"-n", "1", "-w", "1000", "192.0.2.1"}
	default:
		t.Skip("ping arguments are defined for Linux and Windows")
	}

	for _, selector := range []string{"", "default", " DEFAULT "} {
		got, err := pingArgs("192.0.2.1", selector)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("pingArgs(%q) = %v, %v; want %v, nil", selector, got, err, want)
		}
	}
}

func TestPingProbeUsesConfigAndContext(t *testing.T) {
	previous := pingIPFn
	t.Cleanup(func() { pingIPFn = previous })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	pingIPFn = func(gotCtx context.Context, ip string, selector string) bool {
		calls++
		if gotCtx != ctx || ip != "192.0.2.1" || selector != "eth0" {
			t.Fatalf("ping received context=%v, ip=%q, interface=%q", gotCtx, ip, selector)
		}
		return true
	}
	probe := pingProbe(ctx, Config{DirectTCPInterface: "eth0"})
	if !probe("192.0.2.1") || calls != 1 {
		t.Fatalf("configured ping calls = %d, want one successful call", calls)
	}
}
