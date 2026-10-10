package main

import "net"

func pingArgs(ip string, interfaceSelector string) ([]string, error) {
	args := []string{"-n", "1", "-w", "1000"}
	// Windows ping accepts a source address, so resolve interface names using
	// the same address selection as direct TCP/TLS/HTTP checks.
	localAddr, err := localAddrForInterface(interfaceSelector, "udp", net.JoinHostPort(ip, "0"))
	if err != nil {
		return nil, err
	}
	if localAddr != nil {
		args = append(args, "-S", localAddr.(*net.UDPAddr).IP.String())
	}
	return append(args, ip), nil
}
