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
	"os"
	"strconv"
)

type tlsProbeResult struct {
	tcpReachable  bool
	tlsReady      bool
	internalError bool // Remote TLS internal_error alert after TCP success.
	tcpError      error
}

func logUnlessCanceled(ctx context.Context, format string, args ...any) {
	if !compactProbeLogs(ctx) && !errors.Is(ctx.Err(), context.Canceled) {
		logger.Printf(format, args...)
	}
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
		if !errors.Is(parent.Err(), context.Canceled) {
			logTCPProbeFailure(domain, ip, port, cfg, "HTTP TCP", err, 1)
		}
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
		logUnlessCanceled(parent, "%s: HTTP request to %s failed: %v", domain, ip, err)
		return result
	}
	// Read headers only, with a size limit. Redirect responses count as
	// reachability; do not follow them to a different IP, host, or port.
	reader := bufio.NewReader(io.LimitReader(conn, 64*1024))
	for {
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			logUnlessCanceled(parent, "%s: HTTP response from %s failed: %v", domain, ip, err)
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
	port := cfg.TLSPort
	if port == 0 {
		port = 443
	}
	conn, err := dialReachability(ctx, domain, ip, cfg)
	if err != nil {
		if !compactProbeLogs(parent) && !errors.Is(parent.Err(), context.Canceled) {
			logTCPProbeFailure(domain, ip, port, cfg, "TCP", err, 1)
		}
		return tlsProbeResult{tcpError: err}
	}
	defer conn.Close()

	if !cfg.TLSProbe {
		return tlsProbeResult{tcpReachable: true}
	}
	tlsConfig := &tls.Config{
		ServerName:         domain,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}
	tlsConn := tls.Client(conn, tlsConfig)
	err = tlsConn.HandshakeContext(ctx)
	if isRemoteTLSAlert(err, "tls: insufficient security level") && ctx.Err() == nil {
		// A fatal alert ends the first TLS connection. Reconnect through the
		// same route, retaining this candidate's original timeout budget.
		_ = conn.Close()
		retryConn, retryErr := dialReachability(ctx, domain, ip, cfg)
		if retryErr != nil {
			err = retryErr
			if !errors.Is(parent.Err(), context.Canceled) {
				logTCPProbeFailure(domain, ip, port, cfg, "TLS ALPN retry TCP", err, 1)
			}
		} else {
			defer retryConn.Close()
			retryConfig := tlsConfig.Clone()
			retryConfig.NextProtos = []string{"h2", "http/1.1"}
			err = tls.Client(retryConn, retryConfig).HandshakeContext(ctx)
			if err != nil {
				logUnlessCanceled(parent, "%s: TLS %s failed after ALPN retry: %v", domain, ip, err)
			} else {
				logUnlessCanceled(parent, "%s: TLS %s passed after ALPN retry", domain, ip)
			}
		}
	} else if err != nil {
		logUnlessCanceled(parent, "%s: TLS handshake %s failed after TCP success: %v", domain, ip, err)
	}
	return tlsProbeResult{
		tcpReachable:  true,
		tlsReady:      err == nil,
		internalError: isRemoteTLSInternalError(err),
	}
}

func compactTCPError(err error) error {
	// Strip socket address and syscall wrappers, retaining contextual errors
	// such as SO_MARK failures and SOCKS5 handshake diagnostics.
	for {
		switch wrapped := err.(type) {
		case *net.OpError:
			err = wrapped.Err
		case *os.SyscallError:
			err = wrapped.Err
		default:
			return err
		}
	}
}

func logTCPProbeFailure(domain, ip string, port int, cfg Config, probe string, err error, attempts int) {
	if compactProbeLogs(cfg.runtimeContext) {
		return
	}
	details := ""
	if cfg.TLSRoute == "proxy" {
		details = " via SOCKS5 " + cfg.TLSSOCKS5Addr
	}
	if attempts > 1 {
		details += fmt.Sprintf(" after %d attempts", attempts)
	}
	logger.Printf("%s: %s %s failed%s: %v", domain, probe, net.JoinHostPort(ip, strconv.Itoa(port)), details, compactTCPError(err))
}

func isRemoteTLSInternalError(err error) bool {
	return isRemoteTLSAlert(err, "tls: internal error")
}

func isRemoteTLSAlert(err error, alertText string) bool {
	// crypto/tls represents received TCP alerts as net.OpError wrapping an
	// unexported alert type. Check its operation and exact alert text, rather
	// than matching arbitrary transport errors or the complete log message.
	var remote *net.OpError
	return errors.As(err, &remote) && remote.Op == "remote error" &&
		remote.Err != nil && remote.Err.Error() == alertText
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
			logUnlessCanceled(ctx, "%s: invalid direct TCP interface selection: %v", domain, err)
			return nil, err
		}
		dialer := &net.Dialer{LocalAddr: localAddr}
		if err := configureDirectTCPMark(dialer, cfg.DirectTCPMark); err != nil {
			return nil, err
		}
		return dialer.DialContext(ctx, "tcp", targetAddr)
	default:
		return nil, fmt.Errorf("unsupported TCP route %q", cfg.TLSRoute)
	}
}
