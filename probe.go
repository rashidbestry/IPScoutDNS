package main

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
)

func testTCP(parent context.Context, domain string, ip string, cfg Config) bool {
	ctx, cancel := reachabilityContext(parent, cfg)
	defer cancel()
	conn, err := dialReachability(ctx, domain, ip, cfg)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func testTLS(parent context.Context, domain string, ip string, cfg Config) bool {
	ctx, cancel := reachabilityContext(parent, cfg)
	defer cancel()
	conn, err := dialReachability(ctx, domain, ip, cfg)
	if err != nil {
		return false
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         domain,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	})
	return tlsConn.HandshakeContext(ctx) == nil
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
	case "interface":
		localAddr, err := localAddrForInterface(cfg.TLSInterface, "tcp", targetAddr)
		if err != nil {
			logger.Printf("%s: invalid TLS interface selection: %v", domain, err)
			return nil, err
		}
		return (&net.Dialer{LocalAddr: localAddr}).DialContext(ctx, "tcp", targetAddr)
	default:
		return (&net.Dialer{}).DialContext(ctx, "tcp", targetAddr)
	}
}
