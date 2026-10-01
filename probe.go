package main

import (
	"context"
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

	var conn net.Conn
	var err error
	targetAddr := net.JoinHostPort(ip, port)

	if currentConfig.TLSRoute == "proxy" {
		conn, err = dialSOCKS5(ctx, currentConfig.TLSSOCKS5Addr, targetAddr)
	} else {
		dialer := &net.Dialer{}
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
