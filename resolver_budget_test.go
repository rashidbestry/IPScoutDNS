package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestResolutionCandidateBudget(t *testing.T) {
	for _, mode := range []string{"active", "passive"} {
		for _, quota := range []int{0, 8} {
			for _, alerts := range []int{0, 2} {
				t.Run(fmt.Sprintf("%s/quota=%d/alerts=%d", mode, quota, alerts), func(t *testing.T) {
					cfg := Config{Mode: mode, DirectDNS: []string{"test"}, TLSRoute: "direct",
						TLSProbe: true, HTTPProbe: true, ICMPProbe: true, MaxParallelTests: 16,
						HostsMaxIPsPerDomain: quota, HTTPFallbackTLSAlerts: alerts}
					// Invalid addresses and duplicates must not consume the budget.
					ips := []string{"127.0.0.1", "8.8.0.0", "::ffff:8.8.0.0"}
					for i := 0; i < 1024; i++ {
						ips = append(ips, fmt.Sprintf("8.8.%d.%d", i/256, i%256))
					}
					query := func(context.Context, string, string, bool, Config) []string { return ips }
					var tlsCalls, httpCalls, pingCalls atomic.Int32
					tls := func(context.Context, string, string, Config) tlsProbeResult {
						tlsCalls.Add(1)
						if alerts > 0 {
							return tlsProbeResult{tcpReachable: true, internalError: true}
						}
						return tlsProbeResult{}
					}
					http := func(context.Context, string, string, Config) httpProbeResult {
						httpCalls.Add(1)
						return httpProbeResult{}
					}
					ping := func(string) bool { pingCalls.Add(1); return false }
					if mode == "passive" {
						resolvePassiveDomainWithProbes(context.Background(), "budget.example", cfg, query, tls, http, ping)
					} else {
						resolveAndSelectWithProbes(context.Background(), "budget.example", cfg, query, tls, http, ping)
					}
					wantTLS, wantPing := int32(64), int32(32)
					if alerts > 0 {
						wantTLS, wantPing = 32, 0
					}
					if tlsCalls.Load() != wantTLS || httpCalls.Load() != 32 || pingCalls.Load() != wantPing {
						t.Fatalf("TLS/HTTP/ICMP calls = %d/%d/%d, want %d/32/%d", tlsCalls.Load(), httpCalls.Load(), pingCalls.Load(), wantTLS, wantPing)
					}
				})
			}
		}
	}
}

func TestResolutionDeadlineSharedByAllPhases(t *testing.T) {
	previous := pingIPFn
	t.Cleanup(func() { pingIPFn = previous })
	cfg := Config{DirectDNS: []string{"test"}, TLSRoute: "direct", TLSProbe: true, HTTPProbe: true, ICMPProbe: true,
		DNSTimeout: time.Minute, TLSTimeout: time.Minute, MaxParallelTests: 1}
	var contexts []context.Context
	query := func(ctx context.Context, _, _ string, _ bool, _ Config) []string {
		contexts = append(contexts, ctx)
		return []string{"8.8.8.8"}
	}
	tls := func(ctx context.Context, _, _ string, _ Config) tlsProbeResult {
		contexts = append(contexts, ctx)
		return tlsProbeResult{}
	}
	http := func(ctx context.Context, _, _ string, _ Config) httpProbeResult {
		contexts = append(contexts, ctx)
		return httpProbeResult{}
	}
	pingIPFn = func(ctx context.Context, _, _ string) bool { contexts = append(contexts, ctx); return false }
	started := time.Now()
	resolveAndSelectWithProbes(context.Background(), "deadline.example", cfg, query, tls, http, nil)
	if len(contexts) != 5 {
		t.Fatalf("phase contexts = %d, want DNS, TLS, retry, HTTP, ICMP", len(contexts))
	}
	deadline, ok := contexts[0].Deadline()
	if !ok || deadline.After(started.Add(31*time.Second)) {
		t.Fatalf("resolution deadline = %v, present = %v; want at most 30s", deadline, ok)
	}
	for i, ctx := range contexts {
		if got, ok := ctx.Deadline(); !ok || !got.Equal(deadline) {
			t.Errorf("phase %d deadline = %v, present = %v; want %v", i, got, ok, deadline)
		}
		if ctx.Err() == nil {
			t.Errorf("phase %d context not canceled after resolution", i)
		}
	}
}

func TestProbeConcurrencySharedAcrossDomains(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entered := make(chan struct{}, 32)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			runIPChecks(ctx, []string{"8.8.8.8"}, 1, func(string) bool {
				entered <- struct{}{}
				select {
				case <-release:
				case <-ctx.Done():
				}
				return false
			})
		}()
	}
	for i := 0; i < 32; i++ {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("probe workers did not start")
		}
	}
	queuedCtx, stop := context.WithTimeout(ctx, 30*time.Millisecond)
	defer stop()
	var calls atomic.Int32
	results := runIPChecks(queuedCtx, []string{"1.1.1.1"}, 1, func(string) bool { calls.Add(1); return true })
	if calls.Load() != 0 || len(results) != 0 {
		t.Error("queued probe bypassed the shared concurrency limit")
	}
	unblock()
	workers.Wait()
	results = runIPChecks(ctx, []string{"1.1.1.1"}, 1, func(string) bool { return true })
	if !results["1.1.1.1"] {
		t.Error("probe slots were not released")
	}
}

func TestResolutionDeadlineStopsProbePhases(t *testing.T) {
	previousConfig, previousPing := currentConfig, pingIPFn
	t.Cleanup(func() { currentConfig, pingIPFn = previousConfig, previousPing })
	for _, phase := range []string{"DNS", "TLS", "HTTP", "ICMP"} {
		t.Run(phase, func(t *testing.T) {
			cfg := Config{DirectDNS: []string{"test"}, TLSRoute: "direct", TLSProbe: true, HTTPProbe: true, ICMPProbe: true,
				MaxParallelTests: 1, ReachableDomainsFile: filepath.Join(t.TempDir(), "reachable.domains"),
				UnreachableDomainsFile: filepath.Join(t.TempDir(), "unreachable.domains")}
			currentConfig = cfg
			const domain = "expire.example"
			recordReachableDomain(domain)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			var timedOut atomic.Bool
			wait := func(gotCtx context.Context, name string) {
				if timedOut.Load() {
					t.Errorf("%s started after resolution expired", name)
				}
				if name == phase {
					<-gotCtx.Done()
					timedOut.Store(true)
				}
			}
			query := func(ctx context.Context, _, _ string, _ bool, _ Config) []string {
				wait(ctx, "DNS")
				return []string{"8.8.8.8"}
			}
			tls := func(ctx context.Context, _, _ string, _ Config) tlsProbeResult {
				wait(ctx, "TLS")
				return tlsProbeResult{}
			}
			http := func(ctx context.Context, _, _ string, _ Config) httpProbeResult {
				wait(ctx, "HTTP")
				return httpProbeResult{}
			}
			pingIPFn = func(ctx context.Context, _, _ string) bool { wait(ctx, "ICMP"); return false }
			ip, ok, cached := resolveAndSelectWithProbes(ctx, domain, cfg, query, tls, http, nil)
			if ip != "" || ok || cached || ctx.Err() != context.DeadlineExceeded {
				t.Fatalf("expired resolution returned %q, %v, %v; context error = %v", ip, ok, cached, ctx.Err())
			}
			contents, err := os.ReadFile(cfg.ReachableDomainsFile)
			if err != nil || string(contents) != domain+"\n" {
				t.Fatalf("previous domain status changed: %q, %v", contents, err)
			}
			if _, err := os.Stat(cfg.UnreachableDomainsFile); !os.IsNotExist(err) {
				t.Fatalf("expired resolution wrote failed status: %v", err)
			}
		})
	}
}
