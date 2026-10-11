package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDoHSOCKS5RedirectPolicy(t *testing.T) {
	// Isolate the process-wide test certificate roots from the rest of the suite.
	if os.Getenv("IPSCOUTDNS_DOH_TEST_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestDoHSOCKS5RedirectPolicy$", "-test.v")
		cmd.Env = append(os.Environ(), "IPSCOUTDNS_DOH_TEST_CHILD=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("DoH integration test failed: %v\n%s", err, output)
		}
		return
	}

	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/dns-query" {
			wire, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			var query dns.Msg
			if err := query.Unpack(wire); err != nil || len(query.Question) != 1 || query.Question[0].Name != "test.example." {
				t.Errorf("invalid DNS query: %v (%v)", &query, err)
			}
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" || r.Header.Get("Accept") != "application/dns-message" {
				t.Errorf("unexpected DoH request: %s %v", r.Method, r.Header)
			}
			if location := r.URL.Query().Get("location"); location != "" {
				status, _ := strconv.Atoi(r.URL.Query().Get("status"))
				w.Header().Set("Location", location)
				w.WriteHeader(status)
				return
			}
		}
		answer := &dns.A{Hdr: dns.RR_Header{Name: "test.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("8.8.8.8")}
		wire, err := (&dns.Msg{MsgHdr: dns.MsgHdr{Response: true}, Answer: []dns.RR{answer}}).Pack()
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	t.Setenv("GODEBUG", "x509usefallbackroots=1")
	x509.SetFallbackRoots(roots)

	check := func(t *testing.T, endpoint string, wantRequests int32, wantAnswer bool) {
		t.Helper()
		requests.Store(0)
		proxy, connections := startDoHTestProxy(t, server.Listener.Addr().String())
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		got := queryResolver(ctx, "test.example", endpoint, true, Config{DNSSOCKS5Addr: proxy})
		if wantAnswer {
			if len(got) != 1 || got[0] != "8.8.8.8" {
				t.Errorf("IPs = %v, want [8.8.8.8]", got)
			}
		} else if len(got) != 0 {
			t.Errorf("IPs = %v, want none", got)
		}
		if got := requests.Load(); got != wantRequests {
			t.Errorf("HTTPS requests = %d, want %d", got, wantRequests)
		}
		if got := connections.Load(); got != wantRequests {
			t.Errorf("SOCKS connections = %d, want %d; redirect must not open a connection", got, wantRequests)
		}
	}
	t.Run("success", func(t *testing.T) { check(t, server.URL+"/dns-query", 1, true) })
	t.Run("initial HTTP rejected", func(t *testing.T) { check(t, "http://127.0.0.1/dns-query", 0, false) })
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, target := range []struct{ name, location string }{
			{"HTTP downgrade", "http://127.0.0.1:8080/answer"},
			{"other HTTPS origin", "https://other.example/answer"},
			{"same origin", server.URL + "/answer"},
			{"relative", "/answer"},
		} {
			t.Run(fmt.Sprintf("%d/%s", status, target.name), func(t *testing.T) {
				endpoint := fmt.Sprintf("%s/dns-query?status=%d&location=%s", server.URL, status, url.QueryEscape(target.location))
				check(t, endpoint, 1, false)
			})
		}
	}
}

// Only the initial SOCKS connection is tunneled to the local TLS resolver.
// Later connections are counted and rejected, so regressions cannot contact
// any redirect destination outside the test fixture.
func startDoHTestProxy(t *testing.T, target string) (string, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var connections atomic.Int32
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if connections.Add(1) > 1 {
				conn.Close()
				continue
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				var greeting [3]byte
				if _, err := io.ReadFull(conn, greeting[:]); err != nil {
					t.Error(err)
					return
				}
				if greeting != [3]byte{5, 1, 0} {
					t.Errorf("unexpected SOCKS greeting: %v", greeting)
					return
				}
				_, _ = conn.Write([]byte{5, 0})
				var connect [10]byte // The initial resolver is an IPv4 httptest server.
				if _, err := io.ReadFull(conn, connect[:]); err != nil {
					t.Error(err)
					return
				}
				gotTarget := net.JoinHostPort(net.IP(connect[4:8]).String(), strconv.Itoa(int(connect[8])<<8|int(connect[9])))
				if connect[0] != 5 || connect[1] != 1 || connect[3] != 1 || gotTarget != target {
					t.Errorf("unexpected SOCKS CONNECT: %v (target %s)", connect, gotTarget)
					return
				}
				upstream, err := net.DialTimeout("tcp", target, time.Second)
				if err != nil {
					t.Error(err)
					return
				}
				defer upstream.Close()
				_ = upstream.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				done := make(chan struct{})
				go func() {
					_, _ = io.Copy(upstream, conn)
					upstream.Close()
					close(done)
				}()
				_, _ = io.Copy(conn, upstream)
				conn.Close()
				<-done
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		workers.Wait()
	})
	return listener.Addr().String(), &connections
}
