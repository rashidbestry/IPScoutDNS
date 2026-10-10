//go:build !linux

package main

import (
	"fmt"
	"net"
)

func validateDirectTCPMark(mark uint32) error {
	if mark != 0 {
		return fmt.Errorf("direct_tcp_mark is only supported on Linux/OpenWrt; use 0 to disable")
	}
	return nil
}

func configureDirectTCPMark(dialer *net.Dialer, mark uint32) error {
	return validateDirectTCPMark(mark)
}
