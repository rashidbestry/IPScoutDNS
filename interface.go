package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func validateInterfaceSelector(selector string) error {
	selector = strings.TrimSpace(selector)
	if selector == "" || net.ParseIP(selector) != nil {
		return nil
	}
	if _, err := net.InterfaceByName(selector); err != nil {
		return err
	}
	return nil
}

func localAddrForInterface(selector string, network string, remoteAddr string) (net.Addr, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return nil, nil
	}

	remoteHost, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid remote address %q: %w", remoteAddr, err)
	}
	remoteIP := net.ParseIP(remoteHost)

	var localIP net.IP
	if selectedIP := net.ParseIP(selector); selectedIP != nil {
		localIP = selectedIP
	} else {
		iface, err := net.InterfaceByName(selector)
		if err != nil {
			return nil, fmt.Errorf("interface %q: %w", selector, err)
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("read addresses for interface %q: %w", selector, err)
		}

		var ipv4, ipv6 net.IP
		for _, address := range addresses {
			var ip net.IP
			switch address := address.(type) {
			case *net.IPNet:
				ip = address.IP
			case *net.IPAddr:
				ip = address.IP
			}
			if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			if ip.To4() != nil {
				ipv4 = ip
			} else {
				ipv6 = ip
			}
		}

		if remoteIP != nil {
			if remoteIP.To4() != nil {
				localIP = ipv4
			} else {
				localIP = ipv6
			}
		} else if ipv4 != nil {
			localIP = ipv4
		} else {
			localIP = ipv6
		}
		if localIP == nil {
			return nil, fmt.Errorf("interface %q has no address compatible with %q", selector, remoteAddr)
		}
	}

	if remoteIP != nil && (remoteIP.To4() != nil) != (localIP.To4() != nil) {
		return nil, fmt.Errorf("source address %s and destination %s use different IP versions", localIP, remoteIP)
	}

	switch {
	case strings.HasPrefix(network, "udp"):
		return &net.UDPAddr{IP: localIP}, nil
	case strings.HasPrefix(network, "tcp"):
		return &net.TCPAddr{IP: localIP}, nil
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	}
}

func newDNSClient(timeout time.Duration, interfaceSelector string, server string) (*dns.Client, error) {
	client := &dns.Client{Timeout: timeout}
	if strings.TrimSpace(interfaceSelector) == "" {
		return client, nil
	}
	localAddr, err := localAddrForInterface(interfaceSelector, "udp", server)
	if err != nil {
		return nil, err
	}
	client.Dialer = &net.Dialer{LocalAddr: localAddr}
	return client, nil
}
