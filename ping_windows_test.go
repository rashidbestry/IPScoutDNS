package main

import (
	"net"
	"reflect"
	"testing"
)

func TestPingExplicitSourceIP(t *testing.T) {
	want := []string{"-n", "1", "-w", "1000", "-S", "127.0.0.1", "192.0.2.1"}
	got, err := pingArgs("192.0.2.1", " 127.0.0.1 ")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("pingArgs() = %v, %v; want %v, nil", got, err, want)
	}
}

func TestPingExplicitInterface(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		localAddr, err := localAddrForInterface(iface.Name, "udp", "192.0.2.1:0")
		if err != nil {
			continue // This interface has no IPv4 address.
		}
		want := []string{"-n", "1", "-w", "1000", "-S", localAddr.(*net.UDPAddr).IP.String(), "192.0.2.1"}
		got, err := pingArgs("192.0.2.1", iface.Name)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("pingArgs(%q) = %v, %v; want %v, nil", iface.Name, got, err, want)
		}
		return
	}
	t.Skip("no local interface with an IPv4 address")
}

func TestPingInvalidInterfaceDoesNotUseDefault(t *testing.T) {
	for _, selector := range []string{"ipscoutdns-nonexistent-interface", "::1"} {
		args, err := pingArgs("192.0.2.1", selector)
		if err == nil || args != nil {
			t.Fatalf("pingArgs(%q) = %v, %v; want no arguments and an error", selector, args, err)
		}
	}
}
