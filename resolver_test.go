package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestTLSProbeWritesRuntimeOutputs(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	ip, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := Config{TCPProbe: true, TLSProbe: true, ICMPProbe: true,
		Mode: "passive", DirectDNS: []string{"test"}, TLSRoute: "direct", TLSPort: port,
		ReachableHostsFile:     filepath.Join(dir, "reachable.hosts"),
		ReachableDomainsFile:   filepath.Join(dir, "reachable.domains"),
		UnreachableDomainsFile: filepath.Join(dir, "unreachable.domains"),
	}
	previousConfig := currentConfig
	currentConfig = cfg
	t.Cleanup(func() { currentConfig = previousConfig })
	const domain = "example.com"
	if err := os.WriteFile(cfg.UnreachableDomainsFile, []byte(domain+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	query := func(context.Context, string, string, bool, Config) []string { return []string{"192.0.2.1"} }
	// Use a local TLS endpoint to exercise real TCP and TLS without external network access.
	probe := func(ctx context.Context, domain, candidate string, cfg Config) tlsProbeResult {
		return testTLS(ctx, domain, ip, cfg)
	}
	resolvePassiveDomainWith(context.Background(), domain, cfg, query, probe, func(string) bool {
		t.Error("ICMP should not be needed after TCP success")
		return false
	})
	for path, want := range map[string]string{
		cfg.ReachableHostsFile:     "192.0.2.1 " + domain + "\n",
		cfg.ReachableDomainsFile:   domain + "\n",
		cfg.UnreachableDomainsFile: "",
	} {
		contents, err := os.ReadFile(path)
		if err != nil || string(contents) != want {
			t.Fatalf("%s = %q, error = %v; want %q", path, contents, err, want)
		}
	}
}

func TestDomainOutputReachability(t *testing.T) {
	previousConfig := currentConfig
	previousLog := logger.Writer()
	t.Cleanup(func() { currentConfig = previousConfig; logger.SetOutput(previousLog) })
	for _, passive := range []bool{false, true} {
		name := "active"
		if passive {
			name = "passive"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := Config{TCPProbe: true, TLSProbe: true, ICMPProbe: true,
				DirectDNS:              []string{"resolver"},
				HTTPProbe:              true,
				ReachableHostsFile:     filepath.Join(dir, "reachable.hosts"),
				ReachableDomainsFile:   filepath.Join(dir, "reachable.domains"),
				UnreachableDomainsFile: filepath.Join(dir, "unreachable.domains"),
			}
			if passive {
				cfg.Mode = "passive"
			}
			currentConfig = cfg
			query := func(context.Context, string, string, bool, Config) []string {
				return []string{"192.0.2.1"}
			}
			const domain = "example.com"
			hostRecorded := false
			for _, step := range []struct {
				name        string
				probe       tlsProbeResult
				http        httpProbeResult
				ping        bool
				selected    bool
				reachable   bool
				unreachable bool
			}{
				{"service failure is immediately unreachable", tlsProbeResult{tcpError: errors.New("connection refused")}, httpProbeResult{}, false, false, false, true},
				{"TCP alone is insufficient", tlsProbeResult{tcpReachable: true}, httpProbeResult{}, false, false, false, true},
				{"only ICMP success does not validate domain", tlsProbeResult{}, httpProbeResult{}, true, false, false, true},
				{"HTTP succeeds without TLS", tlsProbeResult{}, httpProbeResult{tcpReachable: true, httpReady: true}, false, true, true, false},
				{"TLS succeeds", tlsProbeResult{tcpReachable: true, tlsReady: true}, httpProbeResult{}, false, true, true, false},
				{"failure immediately replaces reachable status", tlsProbeResult{}, httpProbeResult{}, false, false, false, true},
			} {
				t.Run(step.name, func(t *testing.T) {
					var logs selectionLogBuffer
					logger.SetOutput(&logs)
					probe := func(context.Context, string, string, Config) tlsProbeResult { return step.probe }
					httpCalls := 0
					httpProbe := func(context.Context, string, string, Config) httpProbeResult { httpCalls++; return step.http }
					ping := func(string) bool { return step.ping }
					if passive {
						resolvePassiveDomainWithProbes(context.Background(), domain, cfg, query, probe, httpProbe, ping)
					} else {
						_, ok, _ := resolveAndSelectWithProbes(context.Background(), domain, cfg, query, probe, httpProbe, ping)
						if ok != step.selected {
							t.Fatalf("selected = %v, want %v", ok, step.selected)
						}
					}
					wantHTTPCalls := 1
					if step.probe.tcpError != nil && (strings.Count(logs.String(), "NO WORKING IP") != 1 || !strings.Contains(logs.String(), "collected[1] reached[0] TCP[X] TLS[] HTTP[] ICMP[X]")) {
						t.Fatalf("expected one failed-domain summary: %s", logs.String())
					}
					if step.probe.tcpReachable && step.probe.tlsReady {
						wantHTTPCalls = 0
					}
					if httpCalls != wantHTTPCalls {
						t.Fatalf("HTTP checks = %d, want %d", httpCalls, wantHTTPCalls)
					}
					hostRecorded = hostRecorded || step.selected || (step.http.tcpReachable && step.http.httpReady)
					hosts, err := os.ReadFile(cfg.ReachableHostsFile)
					if err != nil && !os.IsNotExist(err) {
						t.Fatal(err)
					}
					wantHosts := ""
					if hostRecorded {
						wantHosts = "192.0.2.1 " + domain + "\n"
					}
					if string(hosts) != wantHosts {
						t.Fatalf("hosts = %q, want %q", hosts, wantHosts)
					}
					for path, wantDomain := range map[string]bool{
						cfg.ReachableDomainsFile:   step.reachable,
						cfg.UnreachableDomainsFile: step.unreachable,
					} {
						contents, err := os.ReadFile(path)
						if err != nil && !os.IsNotExist(err) {
							t.Fatal(err)
						}
						want := ""
						if wantDomain {
							want = domain + "\n"
						}
						if string(contents) != want {
							t.Fatalf("%s = %q, want %q", path, contents, want)
						}
					}
				})
			}
		})
	}
}

func TestDomainReachabilityRetriesTransientTCPFailure(t *testing.T) {
	previousConfig := currentConfig
	t.Cleanup(func() { currentConfig = previousConfig })
	dir := t.TempDir()
	cfg := Config{TCPProbe: true, TLSProbe: true, ICMPProbe: true,
		DirectDNS:              []string{"test"},
		ReachableHostsFile:     filepath.Join(dir, "reachable.hosts"),
		ReachableDomainsFile:   filepath.Join(dir, "reachable.domains"),
		UnreachableDomainsFile: filepath.Join(dir, "unreachable.domains"),
	}
	currentConfig = cfg
	query := func(context.Context, string, string, bool, Config) []string { return []string{"192.0.2.1"} }
	calls := 0
	probe := func(context.Context, string, string, Config) tlsProbeResult {
		calls++
		if calls == 1 {
			return tlsProbeResult{}
		}
		return tlsProbeResult{tcpReachable: true, tlsReady: true}
	}
	selected, ok := resolveAndSelectWith("example.com", cfg, query, probe, func(string) bool {
		t.Error("ICMP should not be needed after retry succeeds")
		return false
	})
	if !ok || selected != "192.0.2.1" || calls != 2 {
		t.Fatalf("selected = %q, ok = %v, probes = %d", selected, ok, calls)
	}
	if _, err := os.Stat(cfg.UnreachableDomainsFile); !os.IsNotExist(err) {
		t.Fatalf("unexpected unreachable output: %v", err)
	}
	contents, err := os.ReadFile(cfg.ReachableHostsFile)
	if err != nil || string(contents) != "192.0.2.1 example.com\n" {
		t.Fatalf("hosts = %q, error = %v", contents, err)
	}
}

func TestNoCandidatesPreservesDomainStatus(t *testing.T) {
	previousConfig := currentConfig
	previousWriter := logger.Writer()
	t.Cleanup(func() { currentConfig = previousConfig; logger.SetOutput(previousWriter) })
	for _, status := range []string{"unknown", "reachable", "unreachable"} {
		t.Run(status, func(t *testing.T) {
			var logs selectionLogBuffer
			logger.SetOutput(&logs)
			dir := t.TempDir()
			cfg := Config{TCPProbe: true, TLSProbe: true, ICMPProbe: true,
				DirectDNS:              []string{"test"},
				ReachableDomainsFile:   filepath.Join(dir, "reachable.domains"),
				UnreachableDomainsFile: filepath.Join(dir, "unreachable.domains"),
			}
			currentConfig = cfg
			if status == "reachable" {
				recordReachableDomain("example.com")
			}
			if status == "unreachable" {
				recordDomainUnreachable("example.com")
			}
			query := func(context.Context, string, string, bool, Config) []string { return nil }
			_, ok := resolveAndSelectWith("example.com", cfg, query, func(context.Context, string, string, Config) tlsProbeResult {
				t.Error("no candidate should be probed")
				return tlsProbeResult{}
			}, func(string) bool { t.Error("no candidate should be pinged"); return false })
			if ok {
				t.Fatal("unexpected selected IP")
			}
			if output := logs.String(); output != "" {
				t.Fatalf("no candidates should produce no result log, got %q", output)
			}
			for path, hasDomain := range map[string]bool{
				cfg.ReachableDomainsFile:   status == "reachable",
				cfg.UnreachableDomainsFile: status == "unreachable",
			} {
				contents, err := os.ReadFile(path)
				if err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
				want := ""
				if hasDomain {
					want = "example.com\n"
				}
				if string(contents) != want {
					t.Fatalf("%s = %q, want %q", path, contents, want)
				}
			}
		})
	}
}

func TestInconclusiveChecksDoNotChangeDomainStatus(t *testing.T) {
	previousConfig := currentConfig
	t.Cleanup(func() { currentConfig = previousConfig })
	dir := t.TempDir()
	cfg := Config{TCPProbe: true, TLSProbe: true, ICMPProbe: true,
		DirectDNS:              []string{"test"},
		HTTPProbe:              true,
		ReachableDomainsFile:   filepath.Join(dir, "reachable.domains"),
		UnreachableDomainsFile: filepath.Join(dir, "unreachable.domains"),
	}
	currentConfig = cfg
	const domain = "example.com"
	recordReachableDomain(domain)
	query := func(context.Context, string, string, bool, Config) []string { return nil }
	tlsProbe := func(context.Context, string, string, Config) tlsProbeResult {
		return tlsProbeResult{tcpReachable: true}
	}
	httpProbe := func(context.Context, string, string, Config) httpProbeResult { return httpProbeResult{} }
	ping := func(string) bool { t.Error("unexpected ICMP check"); return false }
	resolveAndSelectWithProbes(context.Background(), domain, cfg, query, tlsProbe, httpProbe, ping)
	if _, err := os.Stat(cfg.UnreachableDomainsFile); !os.IsNotExist(err) {
		t.Fatalf("DNS failure changed status: %v", err)
	}
	query = func(context.Context, string, string, bool, Config) []string { return []string{"192.0.2.1"} }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resolveAndSelectWithProbes(ctx, domain, cfg, query, tlsProbe, func(context.Context, string, string, Config) httpProbeResult {
		cancel()
		return httpProbeResult{}
	}, ping)
	if _, err := os.Stat(cfg.UnreachableDomainsFile); !os.IsNotExist(err) {
		t.Fatalf("canceled check changed status: %v", err)
	}
	resolveAndSelectWithProbes(context.Background(), domain, cfg, query, tlsProbe, httpProbe, ping)
	contents, err := os.ReadFile(cfg.UnreachableDomainsFile)
	if err != nil || string(contents) != domain+"\n" {
		t.Fatalf("completed failure = %q, error=%v", contents, err)
	}
}

func TestICMPRespectsTCPRoute(t *testing.T) {
	previousConfig := currentConfig
	t.Cleanup(func() { currentConfig = previousConfig })
	for _, mode := range []string{"active", "passive"} {
		for _, route := range []string{"direct", "proxy"} {
			t.Run(mode+"/"+route, func(t *testing.T) {
				dir := t.TempDir()
				cfg := Config{TCPProbe: true, TLSProbe: true, ICMPProbe: true,
					Mode: mode, TLSRoute: route, DirectDNS: []string{"test"},
					HTTPProbe: true, MaxParallelTests: 1,
					ReachableIPsFile:       filepath.Join(dir, "reachable.ips"),
					UnreachableIPsFile:     filepath.Join(dir, "unreachable.ips"),
					UnreachableDomainsFile: filepath.Join(dir, "unreachable.domains"),
				}
				currentConfig = cfg
				const domain = "icmp-route.example"
				const ip = "192.0.2.1"
				deleteCache(domain)
				t.Cleanup(func() { deleteCache(domain) })
				query := func(context.Context, string, string, bool, Config) []string { return []string{ip} }
				tlsCheck := func(context.Context, string, string, Config) tlsProbeResult { return tlsProbeResult{} }
				httpCheck := func(context.Context, string, string, Config) httpProbeResult { return httpProbeResult{} }
				pingCalls := 0
				pingCheck := func(string) bool { pingCalls++; return true }
				if mode == "passive" {
					resolvePassiveDomainWithProbes(context.Background(), domain, cfg, query, tlsCheck, httpCheck, pingCheck)
				} else {
					_, ok, _ := resolveAndSelectWithProbes(context.Background(), domain, cfg, query, tlsCheck, httpCheck, pingCheck)
					if ok {
						t.Error("failed TCP checks selected an IP")
					}
				}
				wantCalls := 0
				if route == "direct" {
					wantCalls = 1
				}
				if pingCalls != wantCalls {
					t.Fatalf("ICMP calls = %d, want %d", pingCalls, wantCalls)
				}
				for path, present := range map[string]bool{cfg.ReachableIPsFile: route == "direct", cfg.UnreachableIPsFile: route == "proxy"} {
					contents, err := os.ReadFile(path)
					if err != nil && !os.IsNotExist(err) {
						t.Fatal(err)
					}
					want := ""
					if present {
						want = ip + "\n"
					}
					if string(contents) != want {
						t.Fatalf("%s = %q, want %q", path, contents, want)
					}
				}
				contents, err := os.ReadFile(cfg.UnreachableDomainsFile)
				if err != nil || string(contents) != domain+"\n" {
					t.Fatalf("domain status = %q, error = %v", contents, err)
				}
			})
		}
	}
}

func TestHTTPProbeToggle(t *testing.T) {
	previousConfig := currentConfig
	t.Cleanup(func() { currentConfig = previousConfig })
	for _, mode := range []string{"active", "passive"} {
		for _, enabled := range []bool{true, false} {
			t.Run(mode+"/http="+strconv.FormatBool(enabled), func(t *testing.T) {
				dir := t.TempDir()
				cfg := Config{TCPProbe: true, TLSProbe: true, ICMPProbe: true,
					Mode: mode, DirectDNS: []string{"test"}, HTTPProbe: enabled,
					ReachableDomainsFile:   filepath.Join(dir, "reachable.domains"),
					UnreachableDomainsFile: filepath.Join(dir, "unreachable.domains"),
					ReachableHostsFile:     filepath.Join(dir, "reachable.hosts"),
				}
				currentConfig = cfg
				query := func(context.Context, string, string, bool, Config) []string { return []string{"192.0.2.1"} }
				tlsCheck := func(context.Context, string, string, Config) tlsProbeResult {
					return tlsProbeResult{tcpReachable: true}
				}
				httpCalls := 0
				httpCheck := func(context.Context, string, string, Config) httpProbeResult {
					httpCalls++
					return httpProbeResult{tcpReachable: true, httpReady: true}
				}
				pingCheck := func(string) bool { t.Error("unexpected ICMP check after TCP success"); return false }
				if mode == "passive" {
					resolvePassiveDomainWithProbes(context.Background(), "example.com", cfg, query, tlsCheck, httpCheck, pingCheck)
				} else {
					ip, ok, _ := resolveAndSelectWithProbes(context.Background(), "example.com", cfg, query, tlsCheck, httpCheck, pingCheck)
					if ok != enabled || (ok && ip != "192.0.2.1") {
						t.Errorf("selected = %q, ok = %v, HTTP enabled = %v", ip, ok, enabled)
					}
				}
				wantCalls := 0
				if enabled {
					wantCalls = 1
				}
				if httpCalls != wantCalls {
					t.Fatalf("HTTP calls = %d, want %d", httpCalls, wantCalls)
				}
				for path, present := range map[string]bool{cfg.ReachableDomainsFile: enabled, cfg.UnreachableDomainsFile: !enabled} {
					contents, err := os.ReadFile(path)
					if err != nil && !os.IsNotExist(err) {
						t.Fatal(err)
					}
					want := ""
					if present {
						want = "example.com\n"
					}
					if string(contents) != want {
						t.Fatalf("%s = %q, want %q", path, contents, want)
					}
				}
				hosts, err := os.ReadFile(cfg.ReachableHostsFile)
				if err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
				wantHosts := ""
				if enabled {
					wantHosts = "192.0.2.1 example.com\n"
				}
				if string(hosts) != wantHosts {
					t.Fatalf("hosts = %q, want %q", hosts, wantHosts)
				}
			})
		}
	}
}
