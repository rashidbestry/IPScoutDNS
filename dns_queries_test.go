package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSQueryParallelConfig(t *testing.T) {
	for _, value := range []string{"", "1", "4", "12", "0", "-1", "invalid"} {
		t.Run("value="+value, func(t *testing.T) {
			content := "mode=active\nactive_domains_file=domains.txt\ndirect_dns=1.1.1.1\n"
			if value != "" {
				content += "dns_query_parallel=" + value + "\n"
			}
			cfg, err := loadConfig(writeModeTestFile(t, content))
			if value == "-1" || value == "invalid" {
				if err == nil || !strings.Contains(err.Error(), "invalid dns_query_parallel") {
					t.Fatalf("error = %v, want invalid dns_query_parallel", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := defaultDNSQueryParallel
			if value != "" {
				fmt.Sscan(value, &want)
			}
			if cfg.DNSQueryParallel != want {
				t.Fatalf("parallel = %d, want %d", cfg.DNSQueryParallel, want)
			}
			cfg.DNSQueryParallel = 0
			if err := cfg.validate(); err != nil {
				t.Fatalf("validation rejected unlimited parallelism: %v", err)
			}
			cfg.DNSQueryParallel = -1
			if err := cfg.validate(); err == nil {
				t.Fatal("validation accepted negative parallelism")
			}
		})
	}
}

func TestDNSQueryLimitSharedAcrossModesAndRoutes(t *testing.T) {
	for _, limit := range []int{2, 0} {
		t.Run(fmt.Sprintf("limit=%d", limit), func(t *testing.T) {
			testDNSQueryLimitSharedAcrossModesAndRoutes(t, limit)
		})
	}
}

func testDNSQueryLimitSharedAcrossModesAndRoutes(t *testing.T, limit int) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cfg := Config{DirectDNS: []string{"direct1", "direct2"}, ProxyDNS: []string{"proxy1", "proxy2"},
		DNSSOCKS5Addr: "127.0.0.1:1080", DNSQueryParallel: limit, DNSTimeout: 2 * time.Second,
		TLSProbe: true, MaxParallelTests: 1, runtimeContext: ctx}
	var active, peak, calls, proxyCalls atomic.Int32
	started := make(chan string, 8)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	query := func(ctx context.Context, domain, server string, proxy bool, _ Config) []string {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		calls.Add(1)
		if proxy {
			proxyCalls.Add(1)
		}
		started <- domain + "/" + server
		select {
		case <-release:
			return []string{"192.0.2.1"}
		case <-ctx.Done():
			return nil
		}
	}
	tlsCheck := func(context.Context, string, string, Config) tlsProbeResult {
		return tlsProbeResult{tcpReachable: true, tlsReady: true}
	}
	done := make(chan struct{}, 2)
	for _, mode := range []string{"active", "passive"} {
		go func(mode string) {
			localCfg := cfg
			localCfg.Mode = mode
			if mode == "active" {
				resolveAndSelectWithStatus(mode+".limit.example", localCfg, query, tlsCheck, func(string) bool { return false })
			} else {
				resolvePassiveDomainWithProbes(ctx, mode+".limit.example", localCfg, query, tlsCheck, nil, func(string) bool { return false })
			}
			done <- struct{}{}
		}(mode)
	}
	wantPeak := limit
	if limit == 0 {
		wantPeak = 8
	}
	for i := 0; i < wantPeak; i++ {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatalf("%d concurrent queries did not start", wantPeak)
		}
	}
	select {
	case extra := <-started:
		t.Errorf("extra query started beyond expected concurrency %d: %s", wantPeak, extra)
	case <-time.After(40 * time.Millisecond):
	}
	unblock()
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-ctx.Done():
			t.Fatal("domain queries did not complete")
		}
	}
	if peak.Load() != int32(wantPeak) || calls.Load() != 8 || proxyCalls.Load() != 4 {
		t.Fatalf("peak=%d calls=%d proxy calls=%d, want %d/8/4", peak.Load(), calls.Load(), proxyCalls.Load(), wantPeak)
	}
}

func TestQueuedDNSQueryGetsFreshTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := upstreamDNSQueries.acquire(ctx, 1); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release := func() { once.Do(upstreamDNSQueries.release) }
	defer release()
	cfg := Config{DirectDNS: []string{"test"}, DNSQueryParallel: 1, DNSTimeout: 100 * time.Millisecond}
	remaining := make(chan time.Duration, 1)
	done := make(chan []string, 1)
	go func() {
		done <- collectResolverIPsWithContext(ctx, "queue.example", cfg, func(queryCtx context.Context, _, _ string, _ bool, _ Config) []string {
			deadline, _ := queryCtx.Deadline()
			remaining <- time.Until(deadline)
			return []string{"192.0.2.1"}
		})
	}()
	// Queue for longer than dns_timeout. The network budget must not expire.
	select {
	case <-done:
		t.Fatal("queued query completed before a slot was available")
	case <-time.After(220 * time.Millisecond):
	}
	release()
	select {
	case ips := <-done:
		if len(ips) != 1 || ips[0] != "192.0.2.1" {
			t.Fatalf("IPs = %v", ips)
		}
	case <-ctx.Done():
		t.Fatal("queued query did not complete")
	}
	if budget := <-remaining; budget < cfg.DNSTimeout/2 {
		t.Fatalf("network timeout already consumed by queue: %s", budget)
	}
}

func TestQueuedActiveDNSQueryCanceledOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := upstreamDNSQueries.acquire(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	defer upstreamDNSQueries.release()
	cfg := Config{DirectDNS: []string{"test"}, DNSQueryParallel: 1, DNSTimeout: time.Second,
		TLSProbe: true, runtimeContext: ctx}
	var calls atomic.Int32
	done := make(chan bool, 1)
	go func() {
		_, ok, _ := resolveAndSelectWithStatus("shutdown.limit.example", cfg,
			func(context.Context, string, string, bool, Config) []string { calls.Add(1); return nil }, nil, nil)
		done <- ok
	}()
	cancel()
	select {
	case ok := <-done:
		if ok || calls.Load() != 0 {
			t.Fatalf("canceled query ran: ok=%t calls=%d", ok, calls.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel queued query")
	}
}

func TestFallbackSharesDNSQueryLimit(t *testing.T) {
	previousCfg, previousDomains := currentConfig, domainRegexes
	t.Cleanup(func() { currentConfig, domainRegexes = previousCfg, previousDomains })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	requests := make(chan struct{}, 1)
	fallback := startSelectionDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		requests <- struct{}{}
		replyIP(w, req, "198.51.100.99")
	}))
	currentConfig = Config{FallbackDNS: fallback, DNSQueryParallel: 1, DNSTimeout: 100 * time.Millisecond, runtimeContext: ctx}
	domainRegexes = nil
	server := startSelectionDNSServer(t, dns.HandlerFunc(handleDNS))
	if err := upstreamDNSQueries.acquire(ctx, 1); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release := func() { once.Do(upstreamDNSQueries.release) }
	defer release()
	done := make(chan error, 1)
	go func() {
		req := new(dns.Msg)
		req.SetQuestion("fallback.limit.example.", dns.TypeA)
		resp, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(req, server)
		if err == nil && (resp.Rcode != dns.RcodeSuccess || len(extractIPv4(resp)) != 1) {
			err = fmt.Errorf("unexpected fallback response: %v", resp)
		}
		done <- err
	}()
	select {
	case <-requests:
		t.Error("fallback bypassed the global query limit")
	case <-time.After(220 * time.Millisecond):
	}
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("fallback did not complete after acquiring a slot")
	}
}

func TestResolverResponseDiagnostics(t *testing.T) {
	previous := logger.Writer()
	t.Cleanup(func() { logger.SetOutput(previous) })
	for _, rcode := range []int{dns.RcodeSuccess, dns.RcodeNameError, dns.RcodeServerFailure, dns.RcodeRefused} {
		t.Run(dns.RcodeToString[rcode], func(t *testing.T) {
			var logs selectionLogBuffer
			logger.SetOutput(&logs)
			resp := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: rcode}}
			if got := resolverIPv4Response("empty.example", "resolver", resp); len(got) != 0 {
				t.Fatalf("IPs = %v", got)
			}
			want := "returned DNS " + dns.RcodeToString[rcode]
			if rcode == dns.RcodeSuccess {
				want = "returned no IPv4 addresses"
			}
			if !strings.Contains(logs.String(), want) {
				t.Fatalf("missing DNS response diagnostic: %s", logs.String())
			}
		})
	}
	var logs selectionLogBuffer
	logger.SetOutput(&logs)
	ips := collectResolverIPs("filtered.example", Config{DirectDNS: []string{"resolver"}},
		func(context.Context, string, string, bool, Config) []string {
			return []string{"0.0.0.0", "::1", "not-an-IP", "192.0.2.1"}
		})
	if len(ips) != 1 || ips[0] != "192.0.2.1" {
		t.Fatalf("usable candidates = %v", ips)
	}
	for _, ip := range []string{"0.0.0.0", "::1", "not-an-IP"} {
		if !strings.Contains(logs.String(), fmt.Sprintf("unsuitable IPv4 candidate %q; discarded", ip)) {
			t.Errorf("missing diagnostic for %s: %s", ip, logs.String())
		}
	}
}

func TestDoHResponseDiagnostics(t *testing.T) {
	previous := logger.Writer()
	t.Cleanup(func() { logger.SetOutput(previous) })
	emptyDNS, err := (&dns.Msg{MsgHdr: dns.MsgHdr{Response: true}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	answer, err := dns.NewRR("test.example. 60 IN A 192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	validDNS, err := (&dns.Msg{MsgHdr: dns.MsgHdr{Response: true}, Answer: []dns.RR{answer}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		name   string
		status int
		body   string
		want   string
		wantIP string
	}{
		{"rate limited", 429, "", "HTTP 429 Too Many Requests", ""},
		{"forbidden", 403, "", "HTTP 403 Forbidden", ""},
		{"HTTP 200 without A records", 200, string(emptyDNS), "returned no IPv4 addresses", ""},
		{"HTTP 200 with invalid DNS body", 200, "invalid", "invalid DNS response", ""},
		{"HTTP 200 with usable A record", 200, string(validDNS), "", "192.0.2.1"},
	} {
		t.Run(step.name, func(t *testing.T) {
			var logs selectionLogBuffer
			logger.SetOutput(&logs)
			resp := &http.Response{StatusCode: step.status, Status: fmt.Sprintf("%d %s", step.status, http.StatusText(step.status)),
				Header: http.Header{"Content-Type": []string{"application/dns-message"}},
				Body:   io.NopCloser(strings.NewReader(step.body))}
			got := readDoHResponse("test.example", "https://resolver/dns-query", resp)
			if (step.wantIP == "" && len(got) != 0) || (step.wantIP != "" && (len(got) != 1 || got[0] != step.wantIP)) {
				t.Fatalf("IPs = %v, want %q", got, step.wantIP)
			}
			if step.want == "" && logs.String() != "" {
				t.Fatalf("successful resolver response should be quiet: %s", logs.String())
			}
			if step.want != "" && !strings.Contains(logs.String(), step.want) {
				t.Fatalf("logs = %s, want %s", logs.String(), step.want)
			}
		})
	}
}
