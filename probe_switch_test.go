package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestProbeSwitchConfig(t *testing.T) {
	for _, key := range []string{"tcp_probe", "tls_probe", "http_probe", "icmp_probe"} {
		for _, value := range []string{"", "true", "false", "maybe"} {
			t.Run(key+"/"+value, func(t *testing.T) {
				content := "mode=active\nactive_domains_file=domains.txt\ndirect_dns=1.1.1.1\n"
				if value != "" {
					content += key + " = " + value + "\n"
				}
				cfg, err := loadConfig(writeModeTestFile(t, content))
				if value == "maybe" {
					if err == nil || !strings.Contains(err.Error(), "invalid "+key) {
						t.Fatalf("error = %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				got := map[string]bool{"tcp_probe": cfg.TCPProbe, "tls_probe": cfg.TLSProbe, "http_probe": cfg.HTTPProbe, "icmp_probe": cfg.ICMPProbe}[key]
				if got != (value != "false") {
					t.Fatalf("enabled = %v", got)
				}
			})
		}
	}
}

func TestProbeSwitchCombinations(t *testing.T) {
	previous := currentConfig
	currentConfig = Config{}
	t.Cleanup(func() { currentConfig = previous })
	for mask := 0; mask < 16; mask++ {
		t.Run(fmt.Sprint(mask), func(t *testing.T) {
			cfg := Config{DirectDNS: []string{"test"}, MaxParallelTests: 1, TLSRoute: "direct", TCPProbe: mask&1 != 0, TLSProbe: mask&2 != 0, HTTPProbe: mask&4 != 0, ICMPProbe: mask&8 != 0}
			tlsCalls, httpCalls, pingCalls := 0, 0, 0
			query := func(context.Context, string, string, bool, Config) []string { return []string{"192.0.2.1"} }
			tlsCheck := func(context.Context, string, string, Config) tlsProbeResult {
				tlsCalls++
				return tlsProbeResult{tcpReachable: true, tlsReady: true}
			}
			httpCheck := func(context.Context, string, string, Config) httpProbeResult {
				httpCalls++
				return httpProbeResult{tcpReachable: true, httpReady: true}
			}
			pingCheck := func(string) bool { pingCalls++; return true }
			if cfg.TCPProbe && !cfg.TLSProbe {
				if !candidateProbePassed(cfg, tlsProbeResult{tcpReachable: true}, httpProbeResult{tcpReachable: true, httpReady: true}, true) {
					t.Fatal("reachable candidate rejected")
				}
				return
			}
			_, ok, _ := resolveAndSelectWithProbes(context.Background(), "switch.example", cfg, query, tlsCheck, httpCheck, pingCheck)
			if ok != (mask != 0) {
				t.Fatalf("selected = %v", ok)
			}
			if (tlsCalls > 0) != cfg.TLSProbe {
				t.Fatalf("TLS calls = %d", tlsCalls)
			}
			if (httpCalls > 0) != (cfg.HTTPProbe && !cfg.TLSProbe) {
				t.Fatalf("HTTP calls = %d", httpCalls)
			}
			if (pingCalls > 0) != (cfg.ICMPProbe && !cfg.TLSProbe && !cfg.HTTPProbe) {
				t.Fatalf("ICMP calls = %d", pingCalls)
			}
		})
	}
}

func TestTCPProbeSkipsTLSHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan int, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			received <- -1
			return
		}
		defer conn.Close()
		buf := make([]byte, 1)
		n, _ := conn.Read(buf)
		received <- n
	}()
	ip, port, _ := net.SplitHostPort(listener.Addr().String())
	portNum, _ := strconv.Atoi(port)
	cfg := Config{TCPProbe: true, TLSProbe: false, TLSRoute: "direct", TLSPort: portNum}
	result := testTLS(context.Background(), "example.com", ip, cfg)
	if !result.tcpReachable || result.tlsReady {
		t.Fatalf("result = %+v", result)
	}
	if n := <-received; n != 0 {
		t.Fatalf("sent %d bytes with TLS disabled", n)
	}
}
