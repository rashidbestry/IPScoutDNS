package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type alpnTestHello struct {
	name      string
	protocols []string
}

// Send the actual insufficient_security alert when ALPN is missing, then
// perform a real TLS handshake on the fresh connection. Proxy scenarios serve
// the same TLS endpoint through a SOCKS5 tunnel to an otherwise unreachable IP.
func startALPNProbeServer(t *testing.T, proxy bool, firstAlert, retryAlert byte, beforeAlert func(), stallRetry bool) (Config, <-chan alpnTestHello, *atomic.Int32) {
	t.Helper()
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificates := certServer.TLS.Certificates
	certServer.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hellos := make(chan alpnTestHello, 8)
	var attempts atomic.Int32
	var workers sync.WaitGroup
	var connMu sync.Mutex
	var connections []net.Conn
	release := make(chan struct{})
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			attempt := attempts.Add(1)
			connMu.Lock()
			connections = append(connections, conn)
			connMu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				if proxy {
					greeting := make([]byte, 3)
					if _, err := io.ReadFull(conn, greeting); err != nil {
						t.Error(err)
						return
					}
					if !reflect.DeepEqual(greeting, []byte{5, 1, 0}) {
						t.Errorf("SOCKS greeting=%v", greeting)
						return
					}
					if _, err := conn.Write([]byte{5, 0}); err != nil {
						t.Error(err)
						return
					}
					connect := make([]byte, 10)
					if _, err := io.ReadFull(conn, connect); err != nil {
						t.Error(err)
						return
					}
					if !reflect.DeepEqual(connect, []byte{5, 1, 0, 1, 192, 0, 2, 1, 32, 251}) { // port 8443
						t.Errorf("SOCKS target changed on attempt %d: %v", attempt, connect)
						return
					}
					if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
						t.Error(err)
						return
					}
				}
				serverConfig := &tls.Config{Certificates: certificates, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
				serverConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					hellos <- alpnTestHello{hello.ServerName, append([]string(nil), hello.SupportedProtos...)}
					alert := retryAlert
					if attempt == 1 {
						alert = firstAlert
					}
					if attempt > 1 && stallRetry {
						<-release
					}
					if alert != 0 {
						if attempt == 1 && beforeAlert != nil {
							beforeAlert()
						}
						// Go's server callback normally emits internal_error on
						// failure. Explicitly send the alert under test instead.
						_, _ = conn.Write([]byte{21, 3, 3, 0, 2, 2, alert})
						_ = conn.Close()
						return nil, errors.New("test TLS alert sent")
					}
					return nil, nil
				}
				_ = tls.Server(conn, serverConfig).Handshake()
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-acceptDone
		close(release)
		connMu.Lock()
		for _, conn := range connections {
			_ = conn.Close()
		}
		connMu.Unlock()
		workers.Wait()
		close(hellos)
	})
	cfg := Config{TLSProbe: true, TLSRoute: "direct", DirectTCPInterface: "127.0.0.1", TLSPort: listener.Addr().(*net.TCPAddr).Port, TLSTimeout: time.Second}
	if proxy {
		cfg.TLSRoute, cfg.TLSSOCKS5Addr, cfg.TLSPort = "proxy", listener.Addr().String(), 8443
	}
	return cfg, hellos, &attempts
}

func TestTLSALPNRetrySelection(t *testing.T) {
	previous, previousLog := currentConfig, logger.Writer()
	t.Cleanup(func() { currentConfig = previous; logger.SetOutput(previousLog) })
	for _, mode := range []string{"active", "passive"} {
		for _, proxy := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/proxy=%v", mode, proxy), func(t *testing.T) {
				cfg, hellos, attempts := startALPNProbeServer(t, proxy, 71, 0, nil, false)
				cfg.Mode, cfg.DirectDNS, cfg.HTTPProbe, cfg.MaxParallelTests = mode, []string{"test"}, true, 1
				currentConfig = cfg
				var logs selectionLogBuffer
				logger.SetOutput(&logs)
				const domain = "relays.net.anydesk.com"
				query := func(context.Context, string, string, bool, Config) []string { return []string{"192.0.2.1"} }
				probe := func(ctx context.Context, domain, ip string, cfg Config) tlsProbeResult {
					if !proxy {
						ip = "127.0.0.1"
					}
					return testTLS(ctx, domain, ip, cfg)
				}
				httpCheck := func(context.Context, string, string, Config) httpProbeResult {
					t.Error("HTTP probed after TLS ALPN success")
					return httpProbeResult{}
				}
				ping := func(string) bool { t.Error("ICMP probed after TLS ALPN success"); return false }
				if mode == "passive" {
					resolvePassiveDomainWithProbes(context.Background(), domain, cfg, query, probe, httpCheck, ping)
				} else {
					ip, ok, _ := resolveAndSelectWithProbes(context.Background(), domain, cfg, query, probe, httpCheck, ping)
					if !ok || ip != "192.0.2.1" {
						t.Fatalf("selected %q success=%v", ip, ok)
					}
				}
				if attempts.Load() != 2 {
					t.Fatalf("connections=%d, want 2", attempts.Load())
				}
				first, second := <-hellos, <-hellos
				if first.name != domain || second.name != domain || len(first.protocols) != 0 || !reflect.DeepEqual(second.protocols, []string{"h2", "http/1.1"}) {
					t.Fatalf("ClientHello first=%+v second=%+v", first, second)
				}
				if strings.Count(logs.String(), "passed after ALPN retry") != 1 || !strings.Contains(logs.String(), "WORKING IP = 192.0.2.1 [TLS]") {
					t.Fatalf("logs=%s", logs.String())
				}
				if strings.Contains(logs.String(), "failed after TCP success") || strings.Contains(logs.String(), "testing ") {
					t.Fatalf("unexpected probe progress or recovered failure: %s", logs.String())
				}
			})
		}
	}
}

func TestTLSALPNRetryGating(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		first, second           byte
		wantConnections         int32
		wantReady, wantInternal bool
	}{
		{"normal TLS", 0, 0, 1, true, false},
		{"other alert", 40, 0, 1, false, false},
		{"internal error keeps HTTP classification", 80, 0, 1, false, true},
		{"retry is only once", 71, 71, 2, false, false},
		{"retry internal error remains classified", 71, 80, 2, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, attempts := startALPNProbeServer(t, false, tc.first, tc.second, nil, false)
			result := testTLS(context.Background(), "relay.example", "127.0.0.1", cfg)
			if attempts.Load() != tc.wantConnections || !result.tcpReachable || result.tlsReady != tc.wantReady || result.internalError != tc.wantInternal {
				t.Fatalf("connections=%d result=%+v", attempts.Load(), result)
			}
		})
	}
}

func TestTLSALPNRetryCancellationAndTimeout(t *testing.T) {
	t.Run("canceled before retry", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cfg, _, attempts := startALPNProbeServer(t, false, 71, 0, cancel, false)
		result := testTLS(ctx, "relay.example", "127.0.0.1", cfg)
		if result.tlsReady || attempts.Load() != 1 {
			t.Fatalf("connections=%d result=%+v", attempts.Load(), result)
		}
	})
	t.Run("retry shares candidate timeout", func(t *testing.T) {
		cfg, _, attempts := startALPNProbeServer(t, false, 71, 0, func() { time.Sleep(200 * time.Millisecond) }, true)
		cfg.TLSTimeout = 400 * time.Millisecond
		start := time.Now()
		result := testTLS(context.Background(), "relay.example", "127.0.0.1", cfg)
		elapsed := time.Since(start)
		if result.tlsReady || !result.tcpReachable || attempts.Load() != 2 || elapsed >= 550*time.Millisecond {
			t.Fatalf("connections=%d result=%+v elapsed=%s; retry must share 400ms budget", attempts.Load(), result, elapsed)
		}
	})
}
