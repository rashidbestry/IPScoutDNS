package main

import (
	"fmt"
	"os"

	"github.com/miekg/dns"
)

func main() {
	target := "127.0.0.1:5354"
	domain := "youtube.com"
	if len(os.Args) > 1 {
		domain = os.Args[1]
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msg.RecursionDesired = true

	fmt.Printf("Sending A query for %s to %s (UDP)...\n", domain, target)
	client := &dns.Client{Net: "udp", Timeout: 5e9}
	resp, rtt, err := client.Exchange(msg, target)
	if err != nil {
		fmt.Printf("UDP failed: %v\n", err)
	} else {
		fmt.Printf("UDP response in %s: %s\n", rtt, resp)
	}

	fmt.Printf("\nSending A query for %s to %s (TCP)...\n", domain, target)
	client2 := &dns.Client{Net: "tcp", Timeout: 5e9}
	resp2, rtt2, err2 := client2.Exchange(msg, target)
	if err2 != nil {
		fmt.Printf("TCP failed: %v\n", err2)
	} else {
		fmt.Printf("TCP response in %s: %s\n", rtt2, resp2)
	}
}
