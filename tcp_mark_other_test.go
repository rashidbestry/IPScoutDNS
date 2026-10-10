//go:build !linux

package main

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestDirectTCPMarkUnsupported(t *testing.T) {
	dialer := &net.Dialer{}
	if err := configureDirectTCPMark(dialer, 0); err != nil || dialer.Control != nil {
		t.Fatalf("disabled marking error = %v", err)
	}
	_, err := dialReachabilityPort(context.Background(), "example.com", "192.0.2.1", Config{TLSRoute: "direct", DirectTCPMark: 255}, 443)
	if err == nil || !strings.Contains(err.Error(), "direct_tcp_mark is only supported") {
		t.Fatalf("direct dial error = %v; want unsupported socket mark error", err)
	}
}
