package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func writeModeTestFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.txt")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestModeConfig(t *testing.T) {
	tests := []struct {
		name, contents, wantError string
	}{
		{"active", "mode=active\nactive_domains_file=active-domains.txt\n", ""},
		{"passive defaults", "mode=passive\npassive_domains_file=passive-domains.txt\n", ""},
		{"passive ignores listener and fallback", "mode=passive\npassive_domains_file=list.txt\nserver=\nfallback_dns=invalid\nfallback_dns_interface=no-such-device\n", ""},
		{"missing mode", "active_domains_file=list.txt\n", "mode is required"},
		{"both unsupported", "mode=both\n", "mode must be active or passive"},
		{"duplicate mode", "mode=active\nmode=passive\n", "specified only once"},
		{"missing active list", "mode=active\n", "active_domains_file is required"},
		{"missing passive list", "mode=passive\n", "passive_domains_file is required"},
		{"removed key", "mode=active\ndomains_file=list.txt\n", "domains_file was removed"},
		{"unprefixed interval rejected", "mode=passive\npassive_domains_file=list.txt\nresolve_interval=24h\n", "unsupported setting"},
		{"unprefixed parallel rejected", "mode=passive\npassive_domains_file=list.txt\nresolve_parallel=16\n", "unsupported setting"},
		{"zero interval", "mode=passive\npassive_domains_file=list.txt\npassive_resolve_interval=0s\n", "invalid passive_resolve_interval"},
		{"bad interval", "mode=passive\npassive_domains_file=list.txt\npassive_resolve_interval=tomorrow\n", "invalid passive_resolve_interval"},
		{"zero parallel", "mode=passive\npassive_domains_file=list.txt\npassive_resolve_parallel=0\n", "invalid passive_resolve_parallel"},
		{"negative parallel", "mode=passive\npassive_domains_file=list.txt\npassive_resolve_parallel=-1\n", "invalid passive_resolve_parallel"},
		{"bad parallel", "mode=passive\npassive_domains_file=list.txt\npassive_resolve_parallel=lots\n", "invalid passive_resolve_parallel"},
		{"active needs listener", "mode=active\nactive_domains_file=list.txt\nserver=\n", "cannot be empty"},
		{"active needs fallback", "mode=active\nactive_domains_file=list.txt\nfallback_dns=\n", "cannot be empty"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := loadConfig(writeModeTestFile(t, "direct_dns=1.1.1.1\n"+test.contents))
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.PassiveResolveInterval != 24*time.Hour || cfg.PassiveResolveParallel != 16 {
				t.Fatalf("passive defaults = %s / %d, want 24h / 16", cfg.PassiveResolveInterval, cfg.PassiveResolveParallel)
			}
		})
	}
	t.Run("custom schedule", func(t *testing.T) {
		cfg, err := loadConfig(writeModeTestFile(t, "mode=passive\npassive_domains_file=list.txt\nproxy_dns=9.9.9.9\npassive_resolve_interval=30m\npassive_resolve_parallel=4\n"))
		if err != nil || cfg.PassiveResolveInterval != 30*time.Minute || cfg.PassiveResolveParallel != 4 {
			t.Fatalf("config = %+v, error = %v", cfg, err)
		}
	})
	t.Run("upstreams required in both modes", func(t *testing.T) {
		for _, mode := range []string{"active", "passive"} {
			_, err := loadConfig(writeModeTestFile(t, "mode="+mode+"\n"))
			if err == nil || !strings.Contains(err.Error(), "upstream resolver") {
				t.Fatalf("%s error = %v", mode, err)
			}
		}
	})
}

func TestSharedSampleConfigSupportsPassiveMode(t *testing.T) {
	contents, err := os.ReadFile("ipscoutdns.conf")
	if err != nil {
		t.Fatal(err)
	}
	active, err := loadConfig("ipscoutdns.conf")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(writeModeTestFile(t, strings.Replace(string(contents), "mode=active", "mode=passive", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "passive" || cfg.PassiveDomainsFile != "passive-domains.txt" || cfg.PassiveResolveParallel != 16 || cfg.PassiveResolveInterval != 24*time.Hour {
		t.Fatalf("unexpected passive config: %+v", cfg)
	}
	active.Mode = "passive"
	if !reflect.DeepEqual(cfg, active) {
		t.Fatal("switching mode changed shared configuration")
	}
	if _, err := loadPassiveDomainsFile(cfg.PassiveDomainsFile); err != nil {
		t.Fatal(err)
	}
}

func TestPassiveDomainList(t *testing.T) {
	path := writeModeTestFile(t, "# list\n; comment\n\nExample.COM. # inline\nexample.com\napi.example.com\nxn--bcher-kva.example\n")
	got, err := loadPassiveDomainsFile(path)
	want := []string{"example.com", "api.example.com", "xn--bcher-kva.example"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("domains = %v, error = %v, want %v", got, err, want)
	}
	for _, invalid := range []string{".*", "^example\\.com$", "https://example.com", "*.example.com", "example..com", "-bad.example", "bad-.example", "192.0.2.1", ".", "two domains.com", "bücher.example", strings.Repeat("a", 64) + ".com"} {
		t.Run(invalid, func(t *testing.T) {
			if _, err := loadPassiveDomainsFile(writeModeTestFile(t, invalid)); err == nil {
				t.Fatalf("accepted %q", invalid)
			}
		})
	}
	if _, err := loadPassiveDomainsFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("accepted missing passive list")
	}
}

func TestActiveRegexFiltering(t *testing.T) {
	savedConfig, savedPatterns := currentConfig, domainRegexes
	t.Cleanup(func() { currentConfig, domainRegexes = savedConfig, savedPatterns })
	if err := loadActiveDomainsFile(writeModeTestFile(t, "# patterns\n^([a-z]+\\.)?example\\.com$ # inline\n")); err != nil {
		t.Fatal(err)
	}
	for domain, want := range map[string]bool{"example.com": true, "api.example.com": true, "other.com": false, "notexample.com": false} {
		if got := isDomainAllowed(domain); got != want {
			t.Errorf("isDomainAllowed(%q) = %v, want %v", domain, got, want)
		}
	}
	if err := loadActiveDomainsFile(writeModeTestFile(t, "[invalid")); err == nil {
		t.Fatal("accepted invalid regex")
	}
	if err := loadActiveDomainsFile(writeModeTestFile(t, "# empty")); err != nil || isDomainAllowed("example.com") {
		t.Fatal("empty allowlist must match no domains")
	}
}

func TestPassiveBatchParallelLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var domains []string
	for i := 0; i < 40; i++ {
		domains = append(domains, fmt.Sprintf("d%d.example", i))
	}
	started := make(chan struct{}, 40)
	release := make(chan struct{})
	var completed, running, peak atomic.Int32
	done := make(chan struct{})
	go func() {
		runPassiveBatch(ctx, domains, Config{PassiveResolveParallel: 16}, func(ctx context.Context, _ string, _ Config) {
			n := running.Add(1)
			defer running.Add(-1)
			for old := peak.Load(); n > old; old = peak.Load() {
				if peak.CompareAndSwap(old, n) {
					break
				}
			}
			started <- struct{}{}
			select {
			case <-release:
				completed.Add(1)
			case <-ctx.Done():
			}
		})
		close(done)
	}()
	for i := 0; i < 16; i++ {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("16 workers did not start")
		}
	}
	select {
	case <-started:
		t.Fatal("more than 16 jobs started before releasing workers")
	default:
	}
	close(release)
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("batch did not complete")
	}
	if completed.Load() != 40 || peak.Load() != 16 {
		t.Fatalf("completed = %d, peak = %d, want 40 and 16", completed.Load(), peak.Load())
	}
}

func TestPassiveScheduleReloadsAfterCompletedPass(t *testing.T) {
	ctx := context.Background()
	cfg := Config{TCPProbe: true, TLSProbe: true, ICMPProbe: true, PassiveDomainsFile: "list", PassiveResolveParallel: 1, PassiveResolveInterval: 24 * time.Hour}
	loads, waits := 0, 0
	var resolved []string
	err := runPassiveWith(ctx, cfg, func(string) ([]string, error) {
		loads++
		if loads == 1 {
			return []string{"first.example"}, nil
		}
		return []string{"second.example"}, nil
	}, func(_ context.Context, domain string, _ Config) {
		resolved = append(resolved, domain)
	}, func(_ context.Context, interval time.Duration) bool {
		waits++
		if interval != 24*time.Hour || len(resolved) != waits {
			t.Errorf("wait started before pass completed or with incorrect interval")
		}
		return waits < 2
	})
	if err != nil || loads != 2 || !reflect.DeepEqual(resolved, []string{"first.example", "second.example"}) {
		t.Fatalf("loads = %d, resolved = %v, error = %v", loads, resolved, err)
	}
}

func TestPassiveListReadFailures(t *testing.T) {
	cfg := Config{TCPProbe: true, TLSProbe: true, ICMPProbe: true, PassiveDomainsFile: "list", PassiveResolveParallel: 1, PassiveResolveInterval: time.Hour}
	loadError := fmt.Errorf("invalid list")
	if err := runPassiveWith(context.Background(), cfg, func(string) ([]string, error) {
		return nil, loadError
	}, func(context.Context, string, Config) {
		t.Fatal("resolved despite invalid startup list")
	}, func(context.Context, time.Duration) bool {
		t.Fatal("waited despite invalid startup list")
		return false
	}); err == nil {
		t.Fatal("startup list error was ignored")
	}
	loads, waits, resolved := 0, 0, 0
	err := runPassiveWith(context.Background(), cfg, func(string) ([]string, error) {
		loads++
		if loads == 2 {
			return nil, loadError
		}
		return []string{"example.com"}, nil
	}, func(context.Context, string, Config) {
		resolved++
	}, func(context.Context, time.Duration) bool {
		waits++
		return waits < 3
	})
	if err != nil || loads != 3 || resolved != 2 {
		t.Fatalf("loads = %d, resolved = %d, error = %v; want recovery after bad reload", loads, resolved, err)
	}
}

func TestPassiveCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	done := make(chan struct{})
	var count atomic.Int32
	go func() {
		runPassiveBatch(ctx, []string{"first.example", "second.example"}, Config{PassiveResolveParallel: 1}, func(ctx context.Context, _ string, _ Config) {
			count.Add(1)
			close(started)
			<-ctx.Done()
		})
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("first job did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("workers did not stop on cancellation")
	}
	if count.Load() != 1 || waitPassiveInterval(ctx, 24*time.Hour) {
		t.Fatal("cancellation started another job or failed to stop interval wait")
	}
}

func TestPassiveResolvesFreshAndPreservesStatusOnLookupFailure(t *testing.T) {
	savedConfig := currentConfig
	t.Cleanup(func() { currentConfig = savedConfig })
	dir := t.TempDir()
	currentConfig = Config{
		ReachableDomainsFile:   filepath.Join(dir, "reachable.domains"),
		UnreachableDomainsFile: filepath.Join(dir, "unreachable.domains"),
		ReachableHostsFile:     filepath.Join(dir, "reachable.hosts"),
		ReachableIPsFile:       filepath.Join(dir, "reachable.ips"),
		UnreachableIPsFile:     filepath.Join(dir, "unreachable.ips"),
	}
	domain := "fresh-pass.example"
	t.Cleanup(func() {
		hostsMu.Lock()
		defer hostsMu.Unlock()
		delete(writtenReachable, "8.8.8.8 "+domain)
	})
	updateCache(domain, "1.1.1.1")
	t.Cleanup(func() { deleteCache(domain) })
	cfg := Config{TCPProbe: true, TLSProbe: true, ICMPProbe: true, Mode: "passive", CacheTTL: 24 * time.Hour, DirectDNS: []string{"1.1.1.1"}, DNSTimeout: time.Second, MaxParallelTests: 1}
	queries := 0
	query := func(context.Context, string, string, bool, Config) []string {
		queries++
		if queries > 1 {
			return nil
		}
		return []string{"8.8.8.8"}
	}
	tlsCheck := func(context.Context, string, string, Config) tlsProbeResult {
		return tlsProbeResult{tcpReachable: true, tlsReady: true}
	}
	resolvePassiveDomainWith(context.Background(), domain, cfg, query, tlsCheck, func(string) bool { return false })
	hosts, err := os.ReadFile(currentConfig.ReachableHostsFile)
	if err != nil || !strings.Contains(string(hosts), "8.8.8.8 "+domain) {
		t.Fatalf("hosts = %q, error = %v", hosts, err)
	}
	resolvePassiveDomainWith(context.Background(), domain, cfg, query, tlsCheck, func(string) bool { return false })
	unreachable, err := os.ReadFile(currentConfig.UnreachableDomainsFile)
	if queries != 2 || !os.IsNotExist(err) || len(unreachable) != 0 {
		t.Fatalf("queries = %d, unreachable = %q, error = %v", queries, unreachable, err)
	}
	reachable, err := os.ReadFile(currentConfig.ReachableDomainsFile)
	if err != nil || strings.TrimSpace(string(reachable)) != domain {
		t.Fatalf("lookup failure changed previous reachable status: %q, error = %v", reachable, err)
	}
}

func TestDirectDNSCancellation(t *testing.T) {
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	received := make(chan struct{})
	go func() {
		buf := make([]byte, 512)
		if _, _, err := upstream.ReadFrom(buf); err == nil {
			close(received)
		}
	}()
	done := make(chan struct{})
	go func() {
		queryDNS(ctx, "cancel.example", upstream.LocalAddr().String(), Config{DNSTimeout: time.Minute})
		close(done)
	}()
	select {
	case <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("DNS query did not reach test upstream")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("DNS cancellation waited for the one-minute timeout")
	}
}

func TestSOCKSHandshakeCancellation(t *testing.T) {
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	greeted := make(chan struct{})
	go func() {
		conn, err := proxy.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		greeting := make([]byte, 3)
		if _, err := io.ReadFull(conn, greeting); err == nil {
			close(greeted)
			<-ctx.Done()
		}
	}()
	done := make(chan struct{})
	go func() {
		conn, _ := dialSOCKS5(ctx, proxy.Addr().String(), "1.1.1.1:53")
		if conn != nil {
			_ = conn.Close()
		}
		close(done)
	}()
	select {
	case <-greeted:
	case <-time.After(5 * time.Second):
		t.Fatal("SOCKS greeting was not received")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SOCKS cancellation waited for the one-minute timeout")
	}
}
