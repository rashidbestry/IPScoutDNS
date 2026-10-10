package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestCompactDomainResults(t *testing.T) {
	previous, writer := currentConfig, logger.Writer()
	t.Cleanup(func() { currentConfig = previous; logger.SetOutput(writer) })
	for _, mode := range []string{"active", "passive"} {
		for _, outcome := range []string{"TLS", "HTTP", "TCP failure", "service failure"} {
			t.Run(mode+"/"+outcome, func(t *testing.T) {
				var logs selectionLogBuffer
				logger.SetOutput(&logs)
				cfg := Config{Mode: mode, TCPProbe: true, TLSProbe: true, HTTPProbe: true, ICMPProbe: true,
					TLSRoute: "direct", DirectDNS: []string{"one", "two"}, HostsMaxIPsPerDomain: 8, MaxParallelTests: 8}
				currentConfig = cfg
				var candidates []string
				for i := 1; i <= 12; i++ {
					candidates = append(candidates, fmt.Sprintf("192.0.2.%d", i))
				}
				query := func(ctx context.Context, domain, server string, proxy bool, cfg Config) []string {
					// Identical lists from both resolvers must count only once.
					logUnlessCanceled(ctx, "per-resolver detail")
					return candidates
				}
				tlsCheck := func(ctx context.Context, domain, ip string, cfg Config) tlsProbeResult {
					logUnlessCanceled(ctx, "per-TLS detail")
					if outcome == "TCP failure" {
						logTCPProbeFailure(domain, ip, 443, cfg, "TCP", errors.New("connection refused"), 1)
						return tlsProbeResult{tcpError: errors.New("connection refused")}
					}
					return tlsProbeResult{tcpReachable: true, tlsReady: outcome == "TLS"}
				}
				httpCheck := func(ctx context.Context, domain, ip string, cfg Config) httpProbeResult {
					logUnlessCanceled(ctx, "per-HTTP detail")
					return httpProbeResult{tcpReachable: outcome != "TCP failure", httpReady: outcome == "HTTP"}
				}
				ping := func(string) bool { return false }
				if mode == "passive" {
					resolvePassiveDomainWithProbes(context.Background(), "compact.example", cfg, query, tlsCheck, httpCheck, ping)
				} else {
					resolveAndSelectWithProbes(context.Background(), "compact.example", cfg, query, tlsCheck, httpCheck, ping)
				}
				want := "- compact.example: collected[12] reached[8] WORKING IP = 192.0.2.1 [" + outcome + "]"
				if outcome == "TCP failure" {
					want = "- compact.example: collected[12] reached[0] TCP[X] TLS[] HTTP[] ICMP[X] NO WORKING IP"
				}
				if outcome == "service failure" {
					want = "- compact.example: collected[12] reached[0] TCP[] TLS[X] HTTP[X] ICMP[] NO WORKING IP"
				}
				output := logs.String()
				if strings.Count(output, "\n") != 1 || !strings.Contains(output, want) {
					t.Fatalf("want one summary %q; got %s", want, output)
				}
			})
		}
	}
}

func TestCompactCacheHitDoesNotRepeatWorkingIP(t *testing.T) {
	previous, writer := currentConfig, logger.Writer()
	t.Cleanup(func() { currentConfig = previous; logger.SetOutput(writer); deleteCache("compact.cache.example") })
	var logs selectionLogBuffer
	logger.SetOutput(&logs)
	cfg := Config{Mode: "active", TCPProbe: true, TLSProbe: true, CacheTTL: time.Hour, DirectDNS: []string{"one"}, MaxParallelTests: 1}
	currentConfig = cfg
	queries, checks := 0, 0
	query := func(context.Context, string, string, bool, Config) []string { queries++; return []string{"192.0.2.1"} }
	probe := func(context.Context, string, string, Config) tlsProbeResult {
		checks++
		return tlsProbeResult{tcpReachable: true, tlsReady: true}
	}
	for i := 0; i < 2; i++ {
		ip, ok, cached := resolveAndSelectWithProbes(context.Background(), "compact.cache.example", cfg, query, probe, nil, nil)
		if ip != "192.0.2.1" || !ok || cached != (i == 1) {
			t.Fatalf("ip=%s ok=%t cached=%t", ip, ok, cached)
		}
	}
	if queries != 1 || checks != 1 || strings.Count(logs.String(), "WORKING IP") != 1 || strings.Count(logs.String(), "CACHE HIT") != 1 || strings.Count(logs.String(), "\n") != 2 {
		t.Fatalf("queries=%d checks=%d logs=%s", queries, checks, logs.String())
	}
}

func TestOtherConfigsIncludesTimezone(t *testing.T) {
	writer, previousLocation := logger.Writer(), time.Local
	t.Cleanup(func() { logger.SetOutput(writer); time.Local = previousLocation })
	time.Local = time.FixedZone("router", 5*3600)
	for _, mode := range []string{"active", "passive"} {
		var logs bytes.Buffer
		logger.SetOutput(&logs)
		cfg := Config{Mode: mode, LogsEnabled: false, SaveLogs: true, LogMaxSize: 10000000, LogKeepFiles: 7,
			CacheTTL: time.Hour, AnswerTTL: 300, PassiveResolveInterval: 168 * time.Hour, PassiveResolveParallel: 8,
			MaxParallelTests: 8, HostsMaxIPsPerDomain: 8, ReachableHostsFile: "/tmp/ipscoutdns/reachable.hosts", runtimeCopiesEnabled: true, ActiveCopyInterval: time.Hour, ActiveLogCopyInterval: time.Minute}
		logOtherConfigs(cfg, "/etc/TZ")
		output := logs.String()
		for _, want := range []string{"Other configs:\n", "logs_enabled=false", "save_logs=true", "log_max_size=10000000B", "log_keep_files=7", "timezone=+05:00", "timezone_source=\"/etc/TZ\"", "parallel_tests=8", "hosts_max_ips_per_domain=8", "reachable_hosts=\"/tmp/ipscoutdns/reachable.hosts\""} {
			if strings.Count(output, want) != 1 {
				t.Fatalf("%s: missing/duplicated %q in %s", mode, want, output)
			}
		}
		if strings.Index(output, "timezone=") < strings.Index(output, "Other configs:") {
			t.Fatal("timezone outside Other configs")
		}
		if mode == "passive" {
			if !strings.Contains(output, "passive_resolve_interval=168h0m0s") || strings.Contains(output, "active_copy_interval=") {
				t.Fatal(output)
			}
		} else if !strings.Contains(output, "ttl=1h0m0s") || !strings.Contains(output, "answer_ttl=300") || !strings.Contains(output, "active_copy_interval=1h0m0s") || strings.Contains(output, "passive_resolve_interval=") {
			t.Fatal(output)
		}
	}
}

func TestCompactICMPFailureAndDNSResponse(t *testing.T) {
	writer := logger.Writer()
	t.Cleanup(func() { logger.SetOutput(writer) })
	var logs bytes.Buffer
	logger.SetOutput(&logs)
	ctx := compactProbeContext(context.Background())
	if pingIPWithRunner(ctx, "192.0.2.1", func(context.Context, string) ([]byte, error) {
		return []byte("0 packets received"), errors.New("exit status 1")
	}) {
		t.Fatal("accepted failed ping")
	}
	resolverIPv4ResponseWithContext(ctx, "compact.example", "resolver", nil)
	if logs.Len() != 0 {
		t.Fatalf("unexpected probe detail: %s", logs.String())
	}
}
