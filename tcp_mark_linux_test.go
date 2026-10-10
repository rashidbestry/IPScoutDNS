package main

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDirectTCPMarkBeforeConnect(t *testing.T) {
	for _, mark := range []uint32{255, ^uint32(0)} {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		file := os.NewFile(uintptr(fd), "unconnected TCP socket")
		t.Cleanup(func() { _ = file.Close() })
		raw, err := file.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		dialer := &net.Dialer{}
		if err := configureDirectTCPMark(dialer, mark); err != nil {
			t.Fatal(err)
		}
		if err := dialer.Control("tcp4", "192.0.2.1:443", raw); err != nil {
			if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
				t.Skip("SO_MARK requires a network capability; run this test as root")
			}
			t.Fatal(err)
		}
		got, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK)
		if err != nil || uint32(got) != mark {
			t.Fatalf("SO_MARK = %#x, error = %v; want %#x, nil", uint32(got), err, mark)
		}
	}
}

func TestDirectProbeSocketMark(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cfg := Config{TLSRoute: "direct", DirectTCPInterface: "127.0.0.1", DirectTCPMark: 255}
	conn, err := dialReachabilityPort(ctx, "example.com", "127.0.0.1", cfg, listener.Addr().(*net.TCPAddr).Port)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skip("SO_MARK requires a network capability; run this test as root")
		}
		t.Fatal(err)
	}
	defer conn.Close()
	assertTCPMark(t, conn, 255)
	if got := conn.LocalAddr().(*net.TCPAddr).IP.String(); got != "127.0.0.1" {
		t.Fatalf("source IP = %s, want 127.0.0.1", got)
	}
}

func TestProxyProbeSocketIsUnmarked(t *testing.T) {
	cfg, _, _ := startALPNProbeServer(t, true, 0, 0, nil, false)
	cfg.DirectTCPMark = 255
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := dialReachabilityPort(ctx, "example.com", "192.0.2.1", cfg, 8443)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	assertTCPMark(t, conn, 0)
}

func assertTCPMark(t *testing.T, conn net.Conn, want uint32) {
	t.Helper()
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got int
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		got, optionErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK)
	}); err != nil {
		t.Fatal(err)
	}
	if optionErr != nil || uint32(got) != want {
		t.Fatalf("SO_MARK = %#x, error = %v; want %#x, nil", uint32(got), optionErr, want)
	}
}

type markTestRawConn struct {
	controlErr error
}

func (raw markTestRawConn) Control(fn func(uintptr)) error {
	if raw.controlErr != nil {
		return raw.controlErr
	}
	fn(^uintptr(0)) // Invalid descriptor makes setsockopt fail without touching a socket.
	return nil
}

func (markTestRawConn) Read(func(uintptr) bool) error  { return syscall.EBADF }
func (markTestRawConn) Write(func(uintptr) bool) error { return syscall.EBADF }

func TestDirectTCPMarkFailure(t *testing.T) {
	for _, controlErr := range []error{nil, errors.New("socket control failed")} {
		dialer := &net.Dialer{}
		if err := configureDirectTCPMark(dialer, 255); err != nil {
			t.Fatal(err)
		}
		err := dialer.Control("tcp4", "192.0.2.1:443", markTestRawConn{controlErr: controlErr})
		wantErr := controlErr
		if wantErr == nil {
			wantErr = syscall.EBADF
		}
		if !errors.Is(err, wantErr) || !strings.Contains(err.Error(), "direct_tcp_mark=255") {
			t.Fatalf("Control() error = %v; want wrapped %v with the configured mark", err, wantErr)
		}
	}
}

func TestDirectTCPMarkDisabled(t *testing.T) {
	dialer := &net.Dialer{}
	if err := configureDirectTCPMark(dialer, 0); err != nil || dialer.Control != nil {
		t.Fatalf("disabled mark changed socket control; error = %v", err)
	}
}
