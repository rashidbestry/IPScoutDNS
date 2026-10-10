package main

import (
	"fmt"
	"net"
	"syscall"
)

func validateDirectTCPMark(mark uint32) error {
	return nil
}

func configureDirectTCPMark(dialer *net.Dialer, mark uint32) error {
	if mark == 0 {
		return nil
	}
	// Control runs on each new socket before connect, including TLS retries.
	// Returning an error prevents dialing without the requested bypass mark.
	dialer.Control = func(network, address string, raw syscall.RawConn) error {
		var markErr error
		err := raw.Control(func(fd uintptr) {
			markErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
		})
		if err != nil {
			return fmt.Errorf("set direct_tcp_mark=%d (%#x): %w", mark, mark, err)
		}
		if markErr != nil {
			return fmt.Errorf("set direct_tcp_mark=%d (%#x): %w", mark, mark, markErr)
		}
		return nil
	}
	return nil
}
