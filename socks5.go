package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
)

func dialSOCKS5(ctx context.Context, proxyAddr, targetAddr string) (net.Conn, error) {
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	// Interrupt a stalled proxy handshake when the passive service shuts down.
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()

	fail := func(e error) (net.Conn, error) { _ = conn.Close(); return nil, e }
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fail(err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return fail(err)
	}
	if greeting[0] != 0x05 || greeting[1] != 0x00 {
		return fail(fmt.Errorf("SOCKS5 authentication method not supported: version=%d method=%d", greeting[0], greeting[1]))
	}

	host, portText, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fail(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fail(fmt.Errorf("invalid target port: %s", portText))
	}

	request := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			request = append(request, 0x01)
			request = append(request, ip4...)
		} else {
			request = append(request, 0x04)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return fail(fmt.Errorf("target hostname too long"))
		}
		request = append(request, 0x03, byte(len(host)))
		request = append(request, []byte(host)...)
	}
	request = append(request, byte(port>>8), byte(port))

	if _, err := conn.Write(request); err != nil {
		return fail(err)
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return fail(err)
	}
	if header[0] != 0x05 || header[1] != 0x00 {
		return fail(fmt.Errorf("SOCKS5 CONNECT failed: reply=%d", header[1]))
	}

	var addrLen int
	switch header[3] {
	case 0x01:
		addrLen = 4
	case 0x03:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return fail(err)
		}
		addrLen = int(n[0])
	case 0x04:
		addrLen = 16
	default:
		return fail(fmt.Errorf("unknown SOCKS5 address type: %d", header[3]))
	}
	bound := make([]byte, addrLen+2)
	if _, err := io.ReadFull(conn, bound); err != nil {
		return fail(err)
	}
	return conn, nil
}
