package main

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

const (
	tlsTimeout = 3 * time.Second
)

func testIP(parent context.Context, domain string, ip string) bool {
	ctx, cancel := context.WithTimeout(parent, tlsTimeout)
	defer cancel()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			ServerName:         domain,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

func testCachedIP(domain string, ip string) bool {
	logger.Printf("%s: validating cached IP %s", domain, ip)

	ctx, cancel := context.WithTimeout(context.Background(), tlsTimeout)
	defer cancel()

	return testIP(ctx, domain, ip)
}
