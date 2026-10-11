package main

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNormalizeIPv4CandidateDestinationPolicy(t *testing.T) {
	blocked := []string{
		"", "invalid", "localhost", "2130706433", "0177.0.0.1", "127.1",
		"::1", "fc00::1", "fe80::1", "2001:4860:4860::8888",
		"0.0.0.0", "0.255.255.255",
		"10.0.0.0", "10.255.255.255",
		"100.64.0.0", "100.127.255.255",
		"127.0.0.1", "127.255.255.255",
		"169.254.0.0", "169.254.169.254", "169.254.255.255",
		"172.16.0.0", "172.31.255.255",
		"192.0.0.0", "192.0.0.8", "192.0.0.11", "192.0.0.170", "192.0.0.171", "192.0.0.255",
		"192.0.2.0", "192.0.2.255",
		"192.88.99.0", "192.88.99.255",
		"192.168.0.0", "192.168.255.255",
		"198.18.0.0", "198.19.255.255",
		"198.51.100.0", "198.51.100.255",
		"203.0.113.0", "203.0.113.255",
		"224.0.0.0", "239.255.255.255", "240.0.0.0", "255.255.255.255",
	}
	for _, input := range blocked {
		t.Run(input, func(t *testing.T) {
			values := []string{input}
			if ip := net.ParseIP(input); ip != nil && ip.To4() != nil {
				values = append(values, " ::ffff:"+input+" ")
			}
			for _, value := range values {
				if got, ok := normalizeIPv4Candidate(value); ok || got != "" {
					t.Errorf("normalizeIPv4Candidate(%q) = %q, %v; want rejection", value, got, ok)
				}
			}
		})
	}
	for _, ip := range []string{
		"1.1.1.1", "8.8.8.8", "9.255.255.255", "11.0.0.0",
		"100.63.255.255", "100.128.0.0", "172.15.255.255", "172.32.0.0",
		"192.0.0.9", "192.0.0.10", "192.0.1.1", "192.31.196.1", "192.52.193.1", "192.175.48.1",
		"198.17.255.255", "198.20.0.0", "223.255.255.255",
	} {
		for _, value := range []string{ip, " " + ip + " ", "::ffff:" + ip} {
			if got, ok := normalizeIPv4Candidate(value); !ok || got != ip {
				t.Errorf("normalizeIPv4Candidate(%q) = %q, %v; want %q, true", value, got, ok, ip)
			}
		}
	}
}

func TestResolverAnswersCannotSelectPrivateProbeDestinations(t *testing.T) {
	for _, mode := range []string{"active", "passive"} {
		for _, route := range []string{"direct", "proxy"} {
			for mask := 1; mask < 16; mask++ {
				t.Run(fmt.Sprintf("%s/%s/probes=%d", mode, route, mask), func(t *testing.T) {
					cfg := Config{
						Mode: mode, TLSRoute: route, DirectDNS: []string{"direct-resolver"},
						ProxyDNS: []string{"proxy-resolver"}, DNSSOCKS5Addr: "configured-proxy",
						TCPProbe: mask&1 != 0, TLSProbe: mask&2 != 0,
						HTTPProbe: mask&4 != 0, ICMPProbe: mask&8 != 0,
					}
					query := func(_ context.Context, domain, server string, _ bool, _ Config) []string {
						resp := new(dns.Msg)
						for _, ip := range []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "100.64.0.1", "169.254.169.254", "127.0.0.1", "198.18.0.1", "0.0.0.1", "240.0.0.1"} {
							resp.Answer = append(resp.Answer, &dns.A{A: net.ParseIP(ip)})
						}
						return resolverIPv4Response(domain, server, resp)
					}
					tlsCheck := func(context.Context, string, string, Config) tlsProbeResult {
						t.Error("prohibited destination reached TLS probe")
						return tlsProbeResult{}
					}
					httpCheck := func(context.Context, string, string, Config) httpProbeResult {
						t.Error("prohibited destination reached HTTP probe")
						return httpProbeResult{}
					}
					pingCheck := func(string) bool { t.Error("prohibited destination reached ICMP probe"); return false }
					// Empty collection also prevents the TCP-only path, which dials directly.
					if ips := collectResolverIPs("attacker.example", cfg, query); len(ips) != 0 {
						t.Fatalf("prohibited candidates available to probes: %v", ips)
					}
					if mode == "passive" {
						resolvePassiveDomainWithProbes(context.Background(), "attacker.example", cfg, query, tlsCheck, httpCheck, pingCheck)
					} else if ip, ok, cached := resolveAndSelectWithProbes(context.Background(), "attacker.example", cfg, query, tlsCheck, httpCheck, pingCheck); ip != "" || ok || cached {
						t.Fatalf("prohibited answer selected: %q, %v, %v", ip, ok, cached)
					}
				})
			}
		}
	}
}

func TestResolverCandidatesFilterBeforeDeduplication(t *testing.T) {
	cfg := Config{DirectDNS: []string{"direct"}, ProxyDNS: []string{"proxy"}, DNSSOCKS5Addr: "configured-proxy"}
	query := func(context.Context, string, string, bool, Config) []string {
		return []string{"10.1.2.3", " ::ffff:192.168.1.1 ", "::ffff:8.8.8.8", " 8.8.8.8 ", "100.64.0.1"}
	}
	if got := collectResolverIPs("mixed.example", cfg, query); !reflect.DeepEqual(got, []string{"8.8.8.8"}) {
		t.Fatalf("candidates = %v, want only canonical public address", got)
	}
}

func TestPrivateCachedCandidateIsDiscarded(t *testing.T) {
	const domain = "private-cache.example"
	defer deleteCache(domain)
	for _, ip := range []string{"10.1.2.3", "172.16.0.1", "::ffff:192.168.1.1", "100.64.0.1"} {
		updateCache(domain, ip, "TLS")
		cfg := Config{TLSProbe: true, CacheTTL: time.Hour, DirectDNS: []string{"resolver"}}
		queried := make(chan struct{}, 1)
		query := func(context.Context, string, string, bool, Config) []string { queried <- struct{}{}; return nil }
		got, ok, cached := resolveAndSelectWithProbes(context.Background(), domain, cfg, query, nil, nil, nil)
		if got != "" || ok || cached || len(queried) != 1 {
			t.Fatalf("cached %q: got %q, %v, %v; DNS queries = %d", ip, got, ok, cached, len(queried))
		}
		if _, exists := getCache(domain); exists {
			t.Fatal("prohibited cached candidate was retained")
		}
	}
}
