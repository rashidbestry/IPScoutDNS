package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
)

type tlsProbeResult struct {
	tcpReachable  bool
	tlsReady      bool
	internalError bool // Remote TLS internal_error alert after TCP success.
}

type httpProbeResult struct {
	tcpReachable bool
	httpReady    bool
}

func testHTTP(parent context.Context, domain string, ip string, cfg Config) httpProbeResult {
	return testHTTPPort(parent, domain, ip, cfg, 80)
}

func testHTTPPort(parent context.Context, domain string, ip string, cfg Config, port int) httpProbeResult {
	ctx, cancel := reachabilityContext(parent, cfg)
	defer cancel()
	conn, err := dialReachabilityPort(ctx, domain, ip, cfg, port)
	if err != nil {
		logger.Printf("%s: HTTP TCP probe %s:%d failed (route=%s): %v", domain, ip, port, cfg.TLSRoute, err)
		return httpProbeResult{}
	}
	defer conn.Close()
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	result := httpProbeResult{tcpReachable: true}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "http://"+domain+"/", nil)
	if err == nil {
		req.Close = true
		err = req.Write(conn)
	}
	if err != nil {
		logger.Printf("%s: HTTP request to %s failed: %v", domain, ip, err)
		return result
	}
	// Read headers only, with a size limit. Redirect responses count as
	// reachability; do not follow them to a different IP, host, or port.
	reader := bufio.NewReader(io.LimitReader(conn, 64*1024))
	for {
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			logger.Printf("%s: HTTP response from %s failed: %v", domain, ip, err)
			return result
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 100 && resp.StatusCode < 200 && resp.StatusCode != http.StatusSwitchingProtocols {
			continue
		}
		result.httpReady = resp.StatusCode >= 200 && resp.StatusCode <= 599 || resp.StatusCode == http.StatusSwitchingProtocols
		if ctx.Err() != nil {
			result.httpReady = false
		}
		return result
	}
}

func testTLS(parent context.Context, domain string, ip string, cfg Config) tlsProbeResult {
	ctx, cancel := reachabilityContext(parent, cfg)
	defer cancel()
	conn, err := dialReachability(ctx, domain, ip, cfg)
	if err != nil {
		logger.Printf("%s: TCP probe %s failed (route=%s, proxy=%s): %v", domain, ip, cfg.TLSRoute, cfg.TLSSOCKS5Addr, err)
		return tlsProbeResult{}
	}
	defer conn.Close()

	if !cfg.TLSProbe {
		return tlsProbeResult{tcpReachable: true}
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         domain,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	})
	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		logger.Printf("%s: TLS handshake %s failed after TCP success: %v", domain, ip, err)
	}
	return tlsProbeResult{
		tcpReachable:  true,
		tlsReady:      err == nil,
		internalError: isRemoteTLSInternalError(err),
	}
}

func isRemoteTLSInternalError(err error) bool {
	// crypto/tls represents received TCP alerts as net.OpError wrapping an
	// unexported alert type. Check its operation and exact alert text, rather
	// than matching arbitrary transport errors or the complete log message.
	var remote *net.OpError
	return errors.As(err, &remote) && remote.Op == "remote error" &&
		remote.Err != nil && remote.Err.Error() == "tls: internal error"
}

func reachabilityContext(parent context.Context, cfg Config) (context.Context, context.CancelFunc) {
	timeout := cfg.TLSTimeout
	if timeout <= 0 {
		timeout = defaultTLSTimeout
	}
	return context.WithTimeout(parent, timeout)
}

func dialReachability(ctx context.Context, domain string, ip string, cfg Config) (net.Conn, error) {
	port := cfg.TLSPort
	if cfg.TLSPort == 0 {
		port = 443
	}
	return dialReachabilityPort(ctx, domain, ip, cfg, port)
}

func dialReachabilityPort(ctx context.Context, domain string, ip string, cfg Config, port int) (net.Conn, error) {
	targetAddr := net.JoinHostPort(ip, strconv.Itoa(port))

	switch cfg.TLSRoute {
	case "proxy":
		return dialSOCKS5(ctx, cfg.TLSSOCKS5Addr, targetAddr)
	case "direct":
		localAddr, err := localAddrForInterface(cfg.DirectTCPInterface, "tcp", targetAddr)
		if err != nil {
			logger.Printf("%s: invalid direct TCP interface selection: %v", domain, err)
			return nil, err
		}
		return (&net.Dialer{LocalAddr: localAddr}).DialContext(ctx, "tcp", targetAddr)
	default:
		return nil, fmt.Errorf("unsupported TCP route %q", cfg.TLSRoute)
	}
}
