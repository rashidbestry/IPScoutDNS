package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestHTTPProbeAcceptsResponsesWithoutFollowingRedirects(t *testing.T) {
	for _, status := range []int{200, 301, 403, 404, 405, 503} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			requests := make(chan *http.Request, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- r
				w.Header().Set("Location", "http://other.example:9999/")
				w.WriteHeader(status)
			}))
			defer server.Close()
			ip, portText, err := net.SplitHostPort(server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.Atoi(portText)
			if err != nil {
				t.Fatal(err)
			}
			result := testHTTPPort(context.Background(), "example.com", ip, Config{TLSRoute: "direct", TLSTimeout: time.Second}, port)
			if !result.tcpReachable || !result.httpReady {
				t.Fatalf("probe = %+v", result)
			}
			request := <-requests
			if request.Host != "example.com" || request.Method != http.MethodHead {
				t.Fatalf("request = %s Host=%s", request.Method, request.Host)
			}
		})
	}
}

func TestHTTPProbeUsesSOCKS5AndPort80(t *testing.T) {
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	errors := make(chan error, 1)
	go func() {
		conn, err := proxy.Accept()
		if err != nil {
			errors <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		greeting := make([]byte, 3)
		if _, err := io.ReadFull(conn, greeting); err != nil {
			errors <- err
			return
		}
		if _, err := conn.Write([]byte{5, 0}); err != nil {
			errors <- err
			return
		}
		connect := make([]byte, 10)
		if _, err := io.ReadFull(conn, connect); err != nil {
			errors <- err
			return
		}
		if connect[3] != 1 || net.IP(connect[4:8]).String() != "192.0.2.1" || connect[8] != 0 || connect[9] != 80 {
			errors <- fmt.Errorf("unexpected SOCKS target: %v", connect)
			return
		}
		if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
			errors <- err
			return
		}
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			errors <- err
			return
		}
		if req.Host != "example.com" {
			errors <- fmt.Errorf("Host = %s", req.Host)
			return
		}
		_, err = io.WriteString(conn, "HTTP/1.1 302 Found\r\nLocation: https://example.com/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		errors <- err
	}()
	result := testHTTP(context.Background(), "example.com", "192.0.2.1", Config{TLSRoute: "proxy", DirectTCPMark: 255, TLSSOCKS5Addr: proxy.Addr().String(), TLSTimeout: time.Second})
	if !result.tcpReachable || !result.httpReady {
		t.Fatalf("probe = %+v", result)
	}
	if err := <-errors; err != nil {
		t.Fatal(err)
	}
}

func TestHTTPProbeRequiresHTTPResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = http.ReadRequest(bufio.NewReader(conn))
		_, _ = io.WriteString(conn, "not an HTTP response\r\n\r\n")
	}()
	ip, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	result := testHTTPPort(context.Background(), "example.com", ip, Config{TLSRoute: "direct", TLSTimeout: time.Second}, port)
	if !result.tcpReachable || result.httpReady {
		t.Fatalf("probe = %+v", result)
	}
}

func TestHTTPProbeCancellation(t *testing.T) {
	previousLog := logger.Writer()
	t.Cleanup(func() { logger.SetOutput(previousLog) })
	var logs selectionLogBuffer
	logger.SetOutput(&logs)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		<-r.Context().Done()
	}))
	defer server.Close()
	ip, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	result := testHTTPPort(ctx, "example.com", ip, Config{TLSRoute: "direct", TLSTimeout: time.Second}, port)
	if !result.tcpReachable || result.httpReady {
		t.Fatalf("probe = %+v", result)
	}
	if logs.String() != "" {
		t.Fatalf("expected cancellation should be quiet: %s", logs.String())
	}
}
