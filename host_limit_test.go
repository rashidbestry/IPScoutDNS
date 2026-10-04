package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestHostsMaxIPsConfig(t *testing.T) {
	for _, value := range []string{"", "8", "2", "0", "-1", "invalid", "999999999999999999999999"} {
		t.Run("value="+value, func(t *testing.T) {
			content := "mode=active\nactive_domains_file=domains.txt\ndirect_dns=1.1.1.1\n"
			if value != "" {
				content += "hosts_max_ips_per_domain=" + value + "\n"
			}
			cfg, err := loadConfig(writeModeTestFile(t, content))
			want := defaultHostsMaxIPsPerDomain
			if value != "" {
				parsed, parseErr := strconv.Atoi(value)
				if parseErr != nil || parsed < 0 {
					if err == nil {
						t.Fatal("invalid limit accepted")
					}
					return
				}
				want = parsed
			}
			if err != nil || cfg.HostsMaxIPsPerDomain != want {
				t.Fatalf("limit = %d, error = %v; want %d", cfg.HostsMaxIPsPerDomain, err, want)
			}
			cfg.HostsMaxIPsPerDomain = -1
			if err := cfg.validate(); err == nil {
				t.Fatal("validation accepted negative limit")
			}
		})
	}
}

func TestDomainProbeLimit(t *testing.T) {
	previous := currentConfig
	t.Cleanup(func() { currentConfig = previous })
	for _, mode := range []string{"active", "passive"} {
		for _, protocol := range []string{"TLS", "HTTP", "ICMP"} {
			for _, limit := range []int{0, 2, 8} {
				t.Run(fmt.Sprintf("%s/%s/limit=%d", mode, protocol, limit), func(t *testing.T) {
					dir := t.TempDir()
					cfg := Config{Mode: mode, DirectDNS: []string{"test"}, MaxParallelTests: 16,
						HostsMaxIPsPerDomain: limit, TLSProbe: protocol != "ICMP", HTTPProbe: true,
						ICMPProbe: true, TLSRoute: "direct",
						ReachableHostsFile: filepath.Join(dir, "reachable.hosts"),
						ReachableIPsFile:   filepath.Join(dir, "reachable.ips"),
						UnreachableIPsFile: filepath.Join(dir, "unreachable.ips")}
					if protocol == "ICMP" {
						cfg.HTTPProbe = false
					}
					currentConfig = cfg
					const domain = "limit.example"
					var ips []string
					for i := 1; i <= 20; i++ {
						ips = append(ips, fmt.Sprintf("192.0.2.%d", i))
					}
					query := func(context.Context, string, string, bool, Config) []string { return ips }
					var tlsCalls, httpCalls, icmpCalls atomic.Int32
					tlsCheck := func(context.Context, string, string, Config) tlsProbeResult {
						tlsCalls.Add(1)
						return tlsProbeResult{tcpReachable: true, tlsReady: protocol == "TLS"}
					}
					httpCheck := func(context.Context, string, string, Config) httpProbeResult {
						httpCalls.Add(1)
						return httpProbeResult{tcpReachable: true, httpReady: true}
					}
					ping := func(string) bool { icmpCalls.Add(1); return true }
					if mode == "passive" {
						resolvePassiveDomainWithProbes(context.Background(), domain, cfg, query, tlsCheck, httpCheck, ping)
					} else {
						ip, ok, _ := resolveAndSelectWithProbes(context.Background(), domain, cfg, query, tlsCheck, httpCheck, ping)
						if !ok || ip == "" {
							t.Fatal("no successful IP selected")
						}
					}
					want := 20
					if limit > 0 {
						want = limit
					}
					wantTLS, wantHTTP, wantICMP := want, 0, 0
					if protocol == "HTTP" {
						wantTLS, wantHTTP = 20, want
					} else if protocol == "ICMP" {
						wantTLS, wantICMP = 0, want
					}
					if int(tlsCalls.Load()) != wantTLS || int(httpCalls.Load()) != wantHTTP || int(icmpCalls.Load()) != wantICMP {
						t.Fatalf("calls TLS/HTTP/ICMP = %d/%d/%d, want %d/%d/%d", tlsCalls.Load(), httpCalls.Load(), icmpCalls.Load(), wantTLS, wantHTTP, wantICMP)
					}
					contents, err := os.ReadFile(cfg.ReachableHostsFile)
					if err != nil {
						t.Fatal(err)
					}
					if lines := strings.Fields(string(contents)); len(lines) != 2*want {
						t.Fatalf("hosts output = %q, want %d mappings", contents, want)
					}
					if contents, _ := os.ReadFile(cfg.UnreachableIPsFile); len(contents) != 0 {
						t.Fatalf("skipped IPs classified as unreachable: %s", contents)
					}
					// A new pass must still probe, and replace this domain's old mappings.
					ips = []string{"198.51.100.1"}
					resolveAndSelectWithProbes(context.Background(), domain, cfg, query, tlsCheck, httpCheck, ping)
					contents, err = os.ReadFile(cfg.ReachableHostsFile)
					if err != nil {
						t.Fatal(err)
					}
					if limit > 0 && string(contents) != "198.51.100.1 "+domain+"\n" {
						t.Fatalf("stale mappings retained: %q", contents)
					}
				})
			}
		}
	}
}

func TestLimitedChecksFailuresAndCancellation(t *testing.T) {
	ips := []string{"bad1", "good1", "bad2", "good2", "skipped"}
	var calls atomic.Int32
	results, reached := runIPChecksLimited(context.Background(), ips, 16, 2, func(ip string) bool {
		calls.Add(1)
		return strings.HasPrefix(ip, "good")
	}, func(result bool) bool { return result })
	if !reached || calls.Load() != 4 || len(results) != 4 {
		t.Fatalf("reached = %v, calls = %d, results = %v", reached, calls.Load(), results)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls.Store(0)
	results, reached = runIPChecksLimited(ctx, ips, 1, 2, func(string) bool {
		calls.Add(1)
		cancel()
		return false
	}, func(result bool) bool { return result })
	if reached || calls.Load() != 1 || len(results) != 1 {
		t.Fatalf("cancellation: reached = %v, calls = %d, results = %v", reached, calls.Load(), results)
	}
}

func TestHostLimitReplacesExistingMappings(t *testing.T) {
	previous := currentConfig
	t.Cleanup(func() { currentConfig = previous })
	path := filepath.Join(t.TempDir(), "reachable.hosts")
	currentConfig = Config{ReachableHostsFile: path}
	if err := os.WriteFile(path, []byte("192.0.2.1 other.example\n192.0.2.2 limit.example\n192.0.2.2 limit.example\n"), 0644); err != nil {
		t.Fatal(err)
	}
	updateReachableHosts("limit.example", []string{"198.51.100.1", "198.51.100.1", "198.51.100.2", "198.51.100.3"}, 2, false)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "192.0.2.1 other.example\n198.51.100.1 limit.example\n198.51.100.2 limit.example\n"
	if string(contents) != want {
		t.Fatalf("hosts = %q, want %q", contents, want)
	}
	updateReachableHosts("limit.example", []string{"198.51.100.1"}, 2, true)
	contents, err = os.ReadFile(path)
	if err != nil || string(contents) != want {
		t.Fatalf("cache hit lost mappings: hosts = %q, error = %v", contents, err)
	}
	updateReachableHosts("limit.example", []string{"203.0.113.1"}, 2, true)
	contents, err = os.ReadFile(path)
	want = "192.0.2.1 other.example\n203.0.113.1 limit.example\n198.51.100.1 limit.example\n"
	if err != nil || string(contents) != want {
		t.Fatalf("cache hit exceeded limit: hosts = %q, error = %v", contents, err)
	}
}
