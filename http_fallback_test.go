package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPFallbackTLSAlertsConfig(t *testing.T) {
	for _, value := range []string{"", "0", "2", "5", "-1", "bad", "999999999999999999999"} {
		t.Run(value, func(t *testing.T) {
			content := "mode=active\nactive_domains_file=domains.txt\ndirect_dns=1.1.1.1\n"
			want := defaultHTTPFallbackTLSAlerts
			if value != "" {
				content += "http_fallback_tls_alerts=" + value + "\n"
				var err error
				want, err = strconv.Atoi(value)
				if err != nil || want < 0 {
					if _, err := loadConfig(writeModeTestFile(t, content)); err == nil {
						t.Fatal("invalid threshold accepted")
					}
					return
				}
			}
			cfg, err := loadConfig(writeModeTestFile(t, content))
			if err != nil || cfg.HTTPFallbackTLSAlerts != want {
				t.Fatalf("threshold = %d, error = %v; want %d", cfg.HTTPFallbackTLSAlerts, err, want)
			}
			cfg.HTTPFallbackTLSAlerts = -1
			if err := cfg.validate(); err == nil {
				t.Fatal("validation accepted negative threshold")
			}
		})
	}
}

func TestRemoteTLSInternalErrorClassification(t *testing.T) {
	remote := &net.OpError{Op: "remote error", Err: errors.New("tls: internal error")}
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{remote, true},
		{fmt.Errorf("wrapped: %w", remote), true},
		{nil, false},
		{io.EOF, false},
		{context.DeadlineExceeded, false},
		{errors.New("remote error: tls: internal error"), false},
		{&net.OpError{Op: "read", Err: errors.New("tls: internal error")}, false},
		{&net.OpError{Op: "remote error", Err: errors.New("tls: handshake failure")}, false},
	} {
		if got := isRemoteTLSInternalError(tc.err); got != tc.want {
			t.Errorf("error %v classified = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestTLSProbeRecordsRemoteInternalError(t *testing.T) {
	for _, alert := range []byte{80, 40} {
		t.Run(strconv.Itoa(int(alert)), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				// Consume ClientHello before replying with a fatal TLS alert.
				header := make([]byte, 5)
				if _, err := io.ReadFull(conn, header); err != nil {
					done <- err
					return
				}
				if _, err := io.CopyN(io.Discard, conn, int64(header[3])<<8|int64(header[4])); err != nil {
					done <- err
					return
				}
				_, err = conn.Write([]byte{21, 3, 3, 0, 2, 2, alert})
				done <- err
			}()
			port := listener.Addr().(*net.TCPAddr).Port
			result := testTLS(context.Background(), "alias.example", "127.0.0.1", Config{TLSProbe: true, TLSRoute: "direct", TLSPort: port, TLSTimeout: time.Second})
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if !result.tcpReachable || result.tlsReady || result.internalError != (alert == 80) {
				t.Fatalf("probe = %+v for alert %d", result, alert)
			}
		})
	}
}

func TestEarlyHTTPFallbackSelection(t *testing.T) {
	previous, previousLog := currentConfig, logger.Writer()
	t.Cleanup(func() { currentConfig = previous; logger.SetOutput(previousLog) })
	for _, mode := range []string{"active", "passive"} {
		for _, limit := range []int{0, 8} {
			t.Run(fmt.Sprintf("%s/limit=%d", mode, limit), func(t *testing.T) {
				var logs selectionLogBuffer
				logger.SetOutput(&logs)
				dir := t.TempDir()
				cfg := Config{Mode: mode, DirectDNS: []string{"test"}, TLSProbe: true, HTTPProbe: true,
					HTTPFallbackTLSAlerts: 2, MaxParallelTests: 16, HostsMaxIPsPerDomain: limit,
					ReachableHostsFile:     filepath.Join(dir, "reachable.hosts"),
					UnreachableIPsFile:     filepath.Join(dir, "unreachable.ips"),
					UnreachableDomainsFile: filepath.Join(dir, "unreachable.domains")}
				currentConfig = cfg
				var ips []string
				for i := 1; i <= 20; i++ {
					ips = append(ips, fmt.Sprintf("192.0.2.%d", i))
				}
				query := func(context.Context, string, string, bool, Config) []string { return ips }
				var tlsCalls, httpCalls atomic.Int32
				tlsCheck := func(context.Context, string, string, Config) tlsProbeResult {
					tlsCalls.Add(1)
					return tlsProbeResult{tcpReachable: true, internalError: true}
				}
				httpCheck := func(_ context.Context, _, ip string, _ Config) httpProbeResult {
					httpCalls.Add(1)
					// A TLS-skipped candidate also fails HTTP. Its overall status
					// must stay unknown even with the success quota disabled.
					return httpProbeResult{tcpReachable: ip != ips[2], httpReady: ip != ips[2]}
				}
				ping := func(string) bool { t.Error("unexpected ICMP"); return false }
				const domain = "early-http.example"
				if mode == "passive" {
					resolvePassiveDomainWithProbes(context.Background(), domain, cfg, query, tlsCheck, httpCheck, ping)
				} else {
					ip, ok, _ := resolveAndSelectWithProbes(context.Background(), domain, cfg, query, tlsCheck, httpCheck, ping)
					if !ok || ip != ips[0] {
						t.Fatalf("selected %q, success=%v", ip, ok)
					}
				}
				wantHTTP, wantHosts := 20, 19
				if limit > 0 {
					wantHTTP, wantHosts = 9, 8
				}
				if tlsCalls.Load() != 2 || int(httpCalls.Load()) != wantHTTP {
					t.Fatalf("TLS/HTTP calls = %d/%d, want 2/%d", tlsCalls.Load(), httpCalls.Load(), wantHTTP)
				}
				hosts, err := os.ReadFile(cfg.ReachableHostsFile)
				if err != nil || len(strings.Fields(string(hosts))) != wantHosts*2 {
					t.Fatalf("hosts=%q, error=%v", hosts, err)
				}
				for _, path := range []string{cfg.UnreachableIPsFile, cfg.UnreachableDomainsFile} {
					if data, _ := os.ReadFile(path); len(data) != 0 {
						t.Fatalf("unknown IP classified unreachable: %s", data)
					}
				}
				if strings.Count(logs.String(), "\n") != 1 || !strings.Contains(logs.String(), fmt.Sprintf("collected[20] reached[%d]", wantHosts)) || !strings.Contains(logs.String(), "[HTTP]") {
					t.Fatalf("logs = %s", logs.String())
				}
			})
		}
	}
}

func TestEarlyHTTPFallbackResumeAndGating(t *testing.T) {
	previous, previousLog := currentConfig, logger.Writer()
	t.Cleanup(func() { currentConfig = previous; logger.SetOutput(previousLog) })
	for _, tc := range []struct {
		name                                                      string
		threshold                                                 int
		httpEnabled, internalAlert, earlyTLS, lateTLS, cancelHTTP bool
		wantTLS, wantHTTP                                         int
		wantSuccess                                               bool
	}{
		{"HTTP fails and later TLS succeeds", 2, true, true, false, true, false, 3, 5, true},
		{"HTTP and all TLS fail", 2, true, true, false, false, false, 5, 5, false},
		{"feature disabled", 0, true, true, false, true, false, 3, 0, true},
		{"HTTP disabled", 2, false, true, false, true, false, 3, 0, true},
		{"ordinary TLS errors do not trigger", 2, true, false, false, true, false, 3, 0, true},
		{"early TLS success blocks fallback", 2, true, true, true, false, false, 1, 0, true},
		{"single alert below threshold", 6, true, true, false, true, false, 3, 0, true},
		{"shutdown during HTTP does not resume TLS", 2, true, true, false, true, true, 2, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs selectionLogBuffer
			logger.SetOutput(&logs)
			cfg := Config{DirectDNS: []string{"test"}, TLSProbe: true, HTTPProbe: tc.httpEnabled,
				HTTPFallbackTLSAlerts: tc.threshold, MaxParallelTests: 1, HostsMaxIPsPerDomain: 1}
			currentConfig = cfg
			ips := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"}
			query := func(context.Context, string, string, bool, Config) []string { return ips }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var tlsCalls, httpCalls atomic.Int32
			seen := make(map[string]bool) // MaxParallelTests=1 in this test.
			tlsCheck := func(_ context.Context, _, ip string, _ Config) tlsProbeResult {
				tlsCalls.Add(1)
				if seen[ip] {
					t.Errorf("TLS probe repeated for %s", ip)
				}
				seen[ip] = true
				ready := tc.earlyTLS && ip == ips[0] || tc.lateTLS && ip == ips[2]
				return tlsProbeResult{tcpReachable: true, tlsReady: ready, internalError: tc.internalAlert && !ready}
			}
			httpCheck := func(context.Context, string, string, Config) httpProbeResult {
				httpCalls.Add(1)
				if tc.cancelHTTP {
					cancel()
				}
				return httpProbeResult{}
			}
			ip, ok, _ := resolveAndSelectWithProbes(ctx, "resume.example", cfg, query, tlsCheck, httpCheck, func(string) bool { return false })
			if ok != tc.wantSuccess || int(tlsCalls.Load()) != tc.wantTLS || int(httpCalls.Load()) != tc.wantHTTP {
				t.Fatalf("selected=%q success=%v TLS/HTTP=%d/%d; want success=%v TLS/HTTP=%d/%d", ip, ok, tlsCalls.Load(), httpCalls.Load(), tc.wantSuccess, tc.wantTLS, tc.wantHTTP)
			}
			if tc.wantSuccess && !strings.Contains(logs.String(), "[TLS]") {
				t.Fatalf("logs=%s", logs.String())
			}
		})
	}
}

func TestEarlyHTTPFallbackCountsDistinctIPs(t *testing.T) {
	cfg := Config{TLSProbe: true, HTTPProbe: true, HTTPFallbackTLSAlerts: 2, MaxParallelTests: 1}
	results, _, early := runTLSChecksWithHTTPFallback(context.Background(), []string{"same", "same", "other", "untested"}, cfg,
		func(string) tlsProbeResult { return tlsProbeResult{tcpReachable: true, internalError: true} },
		func(r tlsProbeResult) bool { return r.tlsReady })
	if !early || len(results) != 2 {
		t.Fatalf("early=%v results=%v", early, results)
	}
}
