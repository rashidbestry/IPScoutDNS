package main

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestActiveDNSLiteralHostnames(t *testing.T) {
	for _, tc := range []struct {
		name  string
		valid bool
	}{
		{`injected\032alias.example.`, false},
		{`injected\009alias.example.`, false},
		{`injected\010alias.example.`, false},
		{`injected#alias.example.`, false},
		{`injected\.alias.example.`, false},
		{`_service.example.`, false},
		{`MiXeD-1.Example.`, true},
		{`xn--bcher-kva.example.`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previousConfig, previousDomains := currentConfig, domainRegexes
			req := new(dns.Msg)
			req.SetQuestion(tc.name, dns.TypeA)
			wire, err := req.Pack()
			if err != nil {
				t.Fatal(err)
			}
			decoded := new(dns.Msg)
			if err := decoded.Unpack(wire); err != nil {
				t.Fatal(err)
			}
			domain := strings.TrimSuffix(strings.ToLower(decoded.Question[0].Name), ".")
			if tc.name == `injected\032alias.example.` && domain != `injected\ alias.example` {
				t.Fatalf("unexpected wire space presentation: %q", domain)
			}
			deleteCache(domain)
			t.Cleanup(func() {
				currentConfig, domainRegexes = previousConfig, previousDomains
				deleteCache(domain)
			})
			var fallbackCalls, resolveCalls, queryCalls atomic.Int32
			fallback := startSelectionDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
				fallbackCalls.Add(1)
				replyIP(w, req, "198.51.100.99")
			}))
			dir := t.TempDir()
			cfg := Config{Mode: "active", DirectDNS: []string{"test"}, FallbackDNS: fallback,
				TLSProbe: true, CacheTTL: 24 * time.Hour, DNSTimeout: time.Second,
				MaxParallelTests: 1, HostsMaxIPsPerDomain: 1,
				ReachableHostsFile:   filepath.Join(dir, "reachable.hosts"),
				ReachableDomainsFile: filepath.Join(dir, "reachable.domains"),
			}
			const existing = "192.0.2.2 other.example\n"
			if err := os.WriteFile(cfg.ReachableHostsFile, []byte(existing), 0600); err != nil {
				t.Fatal(err)
			}
			currentConfig = cfg
			domainRegexes = []*regexp.Regexp{regexp.MustCompile(`.*`)}
			query := func(context.Context, string, string, bool, Config) []string {
				queryCalls.Add(1)
				return []string{"8.8.8.1"}
			}
			probe := func(context.Context, string, string, Config) tlsProbeResult {
				return tlsProbeResult{tcpReachable: true, tlsReady: true}
			}
			address := startSelectionDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
				handleDNSWith(w, req, func(domain string, cfg Config) (string, bool, bool) {
					resolveCalls.Add(1)
					return resolveAndSelectWithProbes(context.Background(), domain, cfg, query, probe, nil, nil)
				})
			}))
			for i := 0; i < 3; i++ {
				resp, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(req, address)
				if err != nil {
					t.Fatal(err)
				}
				if resp.Rcode != dns.RcodeSuccess {
					t.Fatalf("response: %v", resp)
				}
			}
			hosts, err := os.ReadFile(cfg.ReachableHostsFile)
			if err != nil {
				t.Fatal(err)
			}
			_, cached := getCache(domain)
			if !tc.valid {
				if fallbackCalls.Load() != 3 || resolveCalls.Load() != 0 || cached || string(hosts) != existing {
					t.Fatalf("unsafe domain processed: fallback=%d resolve=%d cached=%v hosts=%q", fallbackCalls.Load(), resolveCalls.Load(), cached, hosts)
				}
				if _, err := os.Stat(cfg.ReachableDomainsFile); !os.IsNotExist(err) {
					t.Fatalf("unexpected domain output: %v", err)
				}
			} else {
				if fallbackCalls.Load() != 0 || queryCalls.Load() != 1 || !cached || string(hosts) != existing+"8.8.8.1 "+domain+"\n" {
					t.Fatalf("valid domain mishandled: fallback=%d queries=%d cached=%v hosts=%q", fallbackCalls.Load(), queryCalls.Load(), cached, hosts)
				}
			}
		})
	}
}

func TestHostsWritersRejectNonliteralDomains(t *testing.T) {
	previous := currentConfig
	t.Cleanup(func() { currentConfig = previous })
	for _, domain := range []string{"two names.example", `two\ names.example`, "bad\nname.example", "bad\tname.example", "bad#name.example", `bad\.name.example`} {
		t.Run(domain, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "reachable.hosts")
			currentConfig = Config{ReachableHostsFile: path}
			const existing = "192.0.2.2 other.example\n"
			if err := os.WriteFile(path, []byte(existing), 0600); err != nil {
				t.Fatal(err)
			}
			recordHost(path, domain, "192.0.2.1")
			updateReachableHosts(domain, []string{"192.0.2.1"}, 1, false)
			for i := 0; i < 3; i++ {
				updateReachableHosts(domain, []string{"192.0.2.1"}, 1, true)
			}
			contents, err := os.ReadFile(path)
			if err != nil || string(contents) != existing {
				t.Fatalf("hosts = %q, error = %v", contents, err)
			}
		})
	}
}
