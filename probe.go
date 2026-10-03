package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
)

type tlsProbeResult struct {
	tcpReachable bool
	tlsReady     bool
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
		tcpReachable: true,
		tlsReady:     err == nil,
	}
}

func reachabilityContext(parent context.Context, cfg Config) (context.Context, context.CancelFunc) {
	timeout := cfg.TLSTimeout
	if timeout <= 0 {
		timeout = defaultTLSTimeout
	}
	return context.WithTimeout(parent, timeout)
}

func dialReachability(ctx context.Context, domain string, ip string, cfg Config) (net.Conn, error) {
	port := strconv.Itoa(cfg.TLSPort)
	if cfg.TLSPort == 0 {
		port = "443"
	}
	targetAddr := net.JoinHostPort(ip, port)

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
