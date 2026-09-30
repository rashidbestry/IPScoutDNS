package main

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
)

func testIP(parent context.Context, domain string, ip string) bool {
	timeout := currentConfig.TLSTimeout
	if timeout <= 0 {
		timeout = defaultTLSTimeout
	}

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	port := strconv.Itoa(currentConfig.TLSPort)
	if currentConfig.TLSPort == 0 {
		port = "443"
	}

	tlsConfig := &tls.Config{
		ServerName:         domain,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}

	var conn net.Conn
	var err error
	
	targetAddr := net.JoinHostPort(ip, port)

	if currentConfig.TLSRoute == "proxy" {
		conn, err = dialSOCKS5(ctx, currentConfig.TLSSOCKS5Addr, targetAddr)
		if err == nil {
			tlsConn := tls.Client(conn, tlsConfig)
			err = tlsConn.HandshakeContext(ctx)
			if err != nil {
				conn.Close()
			} else {
				conn = tlsConn
			}
		}
	} else {
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{},
			Config:    tlsConfig,
		}
		conn, err = dialer.DialContext(ctx, "tcp", targetAddr)
	}

	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

func testCachedIP(domain string, ip string) bool {
	logger.Printf("%s: validating cached IP %s", domain, ip)

	timeout := currentConfig.TLSTimeout
	if timeout <= 0 {
		timeout = defaultTLSTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return testIP(ctx, domain, ip)
}
