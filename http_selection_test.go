package main

import (
	"bytes"
	"context"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type selectionLogBuffer struct {
	sync.Mutex
	bytes.Buffer
}

func (b *selectionLogBuffer) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	return b.Buffer.Write(p)
}

func (b *selectionLogBuffer) String() string {
	b.Lock()
	defer b.Unlock()
	return b.Buffer.String()
}

func startSelectionDNSServer(t *testing.T, handler dns.Handler) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	done := make(chan error, 1)
	server := &dns.Server{PacketConn: conn, Handler: handler, NotifyStartedFunc: func() { close(ready) }}
	go func() { done <- server.ActivateAndServe() }()
	t.Cleanup(func() {
		if err := server.Shutdown(); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("DNS server did not start")
	}
	return conn.LocalAddr().String()
}

func TestActiveDNSServiceSelection(t *testing.T) {
	for _, step := range []struct {
		name, protocol, wantIP           string
		tlsReady, httpEnabled, httpReady bool
	}{
		{"TLS preferred over an earlier candidate", "TLS", "192.0.2.2", true, true, true},
		{"HTTP selected when TLS fails", "HTTP", "192.0.2.1", false, true, true},
		{"HTTP disabled uses DNS fallback", "", "198.51.100.99", false, false, true},
		{"both service probes fail", "", "198.51.100.99", false, true, false},
	} {
		t.Run(step.name, func(t *testing.T) {
			previousConfig, previousDomains, previousLog := currentConfig, domainRegexes, logger.Writer()
			const domain = "http-selection.example"
			deleteCache(domain)
			t.Cleanup(func() {
				currentConfig, domainRegexes = previousConfig, previousDomains
				logger.SetOutput(previousLog)
				deleteCache(domain)
			})
			var logs selectionLogBuffer
			logger.SetOutput(&logs)
			var fallbackCalls, queryCalls, tlsCalls, httpCalls atomic.Int32
			fallback := startSelectionDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
				fallbackCalls.Add(1)
				replyIP(w, req, "198.51.100.99")
			}))
			cfg := Config{Mode: "active", DirectDNS: []string{"test"}, FallbackDNS: fallback,
				TCPProbe: true, TLSProbe: true, HTTPProbe: step.httpEnabled, TLSRoute: "direct",
				CacheTTL: time.Minute, DNSTimeout: time.Second, MaxParallelTests: 1}
			currentConfig = cfg
			domainRegexes = []*regexp.Regexp{regexp.MustCompile(`^http-selection\.example$`)}
			query := func(context.Context, string, string, bool, Config) []string {
				queryCalls.Add(1)
				return []string{"192.0.2.1", "192.0.2.2"}
			}
			tlsCheck := func(_ context.Context, _, ip string, _ Config) tlsProbeResult {
				tlsCalls.Add(1)
				return tlsProbeResult{tcpReachable: true, tlsReady: step.tlsReady && ip == "192.0.2.2"}
			}
			httpCheck := func(_ context.Context, _, ip string, _ Config) httpProbeResult {
				httpCalls.Add(1)
				return httpProbeResult{tcpReachable: true, httpReady: step.httpReady && ip == "192.0.2.1"}
			}
			address := startSelectionDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
				handleDNSWith(w, req, func(domain string, cfg Config) (string, bool, bool) {
					return resolveAndSelectWithProbes(context.Background(), domain, cfg, query, tlsCheck, httpCheck, func(string) bool {
						t.Error("unexpected ICMP check after TCP success")
						return false
					})
				})
			}))
			requests := 1
			if step.protocol != "" {
				requests = 2 // The second request must reuse the selected IP and protocol.
			}
			for i := 0; i < requests; i++ {
				req := new(dns.Msg)
				req.SetQuestion(dns.Fqdn(domain), dns.TypeA)
				resp, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(req, address)
				if err != nil {
					t.Fatal(err)
				}
				ips := extractIPv4(resp)
				if resp.Rcode != dns.RcodeSuccess || len(ips) != 1 || ips[0] != step.wantIP {
					t.Fatalf("DNS response = %v, want %s", resp, step.wantIP)
				}
			}
			wantHTTPCalls := int32(0)
			if step.httpEnabled && !step.tlsReady {
				wantHTTPCalls = 2
			}
			if queryCalls.Load() != 1 || tlsCalls.Load() != 2 || httpCalls.Load() != wantHTTPCalls {
				t.Fatalf("query/TLS/HTTP calls = %d/%d/%d, want 1/2/%d", queryCalls.Load(), tlsCalls.Load(), httpCalls.Load(), wantHTTPCalls)
			}
			entry, cached := getCache(domain)
			if step.protocol == "" {
				if fallbackCalls.Load() != 1 || cached {
					t.Fatalf("fallback calls = %d, cached = %v", fallbackCalls.Load(), cached)
				}
				return
			}
			if fallbackCalls.Load() != 0 || !cached || entry.IP != step.wantIP || entry.Protocol != step.protocol {
				t.Fatalf("fallback calls = %d, cache = %+v, cached = %v", fallbackCalls.Load(), entry, cached)
			}
			output := logs.String()
			if strings.Count(output, "WORKING IP =") != 1 ||
				!strings.Contains(output, "WORKING IP = "+step.wantIP+" ["+step.protocol+"]") ||
				!strings.Contains(output, "CACHE HIT = "+step.wantIP+" ["+step.protocol+"]") {
				t.Fatalf("unexpected selection logs: %s", output)
			}
		})
	}
}
