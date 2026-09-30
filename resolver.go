package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		dns.HandleFailed(w, req)
		return
	}

	q := req.Question[0]
	domain := strings.TrimSuffix(strings.ToLower(q.Name), ".")

	if q.Qtype != dns.TypeA {
		forwardDNS(w, req, currentConfig.AdguardDNS)
		return
	}

	logger.Printf("request: %s from %s", domain, w.RemoteAddr())

	if entry, ok := getCache(domain); ok {
		age := time.Since(entry.Checked)
		if age < currentConfig.CacheTTL {
			logger.Printf("%s: CACHE HIT %s (age %s)", domain, entry.IP, age.Round(time.Second))
			replyIP(w, req, entry.IP)
			return
		}

		logger.Printf("%s: cached IP expired: %s", domain, entry.IP)
		if testCachedIP(domain, entry.IP) {
			logger.Printf("%s: cached IP still reachable: %s", domain, entry.IP)
			updateCache(domain, entry.IP)
			replyIP(w, req, entry.IP)
			return
		}

		logger.Printf("%s: cached IP FAILED: %s", domain, entry.IP)
		deleteCache(domain)
	}

	f, leader := getFlight(domain)
	if !leader {
		<-f.done
		if f.ok {
			replyIP(w, req, f.ip)
			return
		}
		forwardDNS(w, req, currentConfig.AdguardDNS)
		return
	}

	ip, ok := resolveAndSelect(domain, currentConfig)
	f.ip = ip
	f.ok = ok
	close(f.done)
	removeFlight(domain, f)

	if ok {
		updateCache(domain, ip)
		logger.Printf("%s: WORKING IP = %s", domain, ip)
		replyIP(w, req, ip)
		return
	}

	logger.Printf("%s: NO WORKING IP FOUND - AdGuard fallback", domain)
	forwardDNS(w, req, currentConfig.AdguardDNS)
}

func resolveAndSelect(domain string, cfg Config) (string, bool) {
	if len(cfg.DirectDNS) > 0 {
		if ip, ok := resolvePhase(domain, cfg.DirectDNS, false, cfg); ok {
			return ip, true
		}
		logger.Printf("%s: direct DNS phase produced no working IP", domain)
	}

	if len(cfg.ProxyDNS) > 0 {
		if strings.TrimSpace(cfg.SOCKS5Addr) == "" {
			logger.Printf("%s: proxy DNS configured but SOCKS5 address is empty", domain)
		} else if ip, ok := resolvePhase(domain, cfg.ProxyDNS, true, cfg); ok {
			return ip, true
		}
		logger.Printf("%s: proxy DNS phase produced no working IP", domain)
	}

	return "", false
}

func resolvePhase(domain string, servers []string, throughSOCKS bool, cfg Config) (string, bool) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	candidates := make(chan string, 64)
	var resolverWG sync.WaitGroup
	var dedupMu sync.Mutex
	seen := make(map[string]bool)

	for _, server := range servers {
		server := strings.TrimSpace(server)
		if server == "" {
			continue
		}

		resolverWG.Add(1)
		go func() {
			defer resolverWG.Done()

			var ips []string
			if strings.HasPrefix(strings.ToLower(server), "https://") || strings.HasPrefix(strings.ToLower(server), "http://") {
				if throughSOCKS {
					ips = queryDoHSOCKS5(ctx, domain, server, cfg.SOCKS5Addr)
				} else {
					logger.Printf("%s: ignoring DoH resolver in direct DNS section: %s", domain, server)
				}
			} else if throughSOCKS {
				ips = queryDNSSOCKS5(ctx, domain, cfg.SOCKS5Addr, server)
			} else {
				ips = queryDNS(ctx, domain, server)
			}

			if len(ips) == 0 {
				logger.Printf("%s: %s returned no IPv4 addresses", domain, server)
				return
			}

			logger.Printf("%s: %s returned %d IPv4 addresses", domain, server, len(ips))

			for _, ip := range ips {
				dedupMu.Lock()
				if seen[ip] {
					dedupMu.Unlock()
					continue
				}
				seen[ip] = true
				dedupMu.Unlock()

				select {
				case candidates <- ip:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		resolverWG.Wait()
		close(candidates)
	}()

	type result struct {
		ip string
		ok bool
	}
	parallel := currentConfig.MaxParallelTests
	if parallel <= 0 {
		parallel = defaultMaxParallel
	}

	results := make(chan result, parallel)
	var workerWG sync.WaitGroup

	for i := 0; i < parallel; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ip, ok := <-candidates:
					if !ok {
						return
					}
					logger.Printf("%s: testing %s", domain, ip)
					if testIP(ctx, domain, ip) {
						select {
						case results <- result{ip: ip, ok: true}:
						case <-ctx.Done():
						}
						return
					}
					logger.Printf("%s: %s FAILED", domain, ip)
				}
			}
		}()
	}

	go func() {
		workerWG.Wait()
		close(results)
	}()

	for r := range results {
		if r.ok {
			logger.Printf("%s: FIRST WORKING IP = %s", domain, r.ip)
			cancel()
			return r.ip, true
		}
	}

	cancel()
	return "", false
}

func queryDNS(ctx context.Context, domain string, server string) []string {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msg.RecursionDesired = true

	timeout := currentConfig.DNSTimeout
	if timeout <= 0 {
		timeout = defaultDNSTimeout
	}

	client := &dns.Client{Timeout: timeout}
	resp, _, err := client.ExchangeContext(ctx, msg, server)
	if err != nil {
		return nil
	}

	var ips []string
	for _, answer := range resp.Answer {
		switch rr := answer.(type) {
		case *dns.A:
			ips = append(ips, rr.A.String())
		}
	}
	return ips
}

func queryDNSSOCKS5(ctx context.Context, domain, socksAddr, dnsAddr string) []string {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msg.RecursionDesired = true

	wire, err := msg.Pack()
	if err != nil {
		return nil
	}

	conn, err := dialSOCKS5(ctx, socksAddr, dnsAddr)
	if err != nil {
		logger.Printf("%s: SOCKS5 DNS %s failed: %v", domain, dnsAddr, err)
		return nil
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(wire)))
	if _, err := conn.Write(length[:]); err != nil {
		return nil
	}
	if _, err := conn.Write(wire); err != nil {
		return nil
	}
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return nil
	}

	n := int(binary.BigEndian.Uint16(length[:]))
	if n <= 0 || n > 65535 {
		return nil
	}
	respWire := make([]byte, n)
	if _, err := io.ReadFull(conn, respWire); err != nil {
		return nil
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(respWire); err != nil {
		return nil
	}
	return extractIPv4(resp)
}

func queryDoHSOCKS5(ctx context.Context, domain, endpoint, socksAddr string) []string {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msg.RecursionDesired = true
	wire, err := msg.Pack()
	if err != nil {
		return nil
	}

	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		logger.Printf("%s: invalid DoH endpoint: %s", domain, endpoint)
		return nil
	}

	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialSOCKS5(ctx, socksAddr, addr)
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()},
	}
	defer transport.CloseIdleConnections()

	timeout := currentConfig.DNSTimeout
	if timeout <= 0 {
		timeout = defaultDNSTimeout
	}

	client := &http.Client{Transport: transport, Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(wire))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		logger.Printf("%s: SOCKS5 DoH %s failed: %v", domain, endpoint, err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	respWire, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil
	}
	msgResp := new(dns.Msg)
	if err := msgResp.Unpack(respWire); err != nil {
		return nil
	}
	return extractIPv4(msgResp)
}

func extractIPv4(resp *dns.Msg) []string {
	var ips []string
	for _, answer := range resp.Answer {
		if rr, ok := answer.(*dns.A); ok {
			ips = append(ips, rr.A.String())
		}
	}
	return ips
}

func replyIP(w dns.ResponseWriter, req *dns.Msg, ip string) {
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative = true

	q := req.Question[0]
	parsed := net.ParseIP(ip)
	if parsed == nil {
		dns.HandleFailed(w, req)
		return
	}

	answerTTL := currentConfig.AnswerTTL
	if answerTTL == 0 {
		answerTTL = defaultAnswerTTL
	}

	rr := &dns.A{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: answerTTL},
		A:   parsed,
	}
	msg.Answer = append(msg.Answer, rr)

	if err := w.WriteMsg(msg); err != nil {
		logger.Printf("DNS reply error: %v", err)
	}
}

func forwardDNS(w dns.ResponseWriter, req *dns.Msg, server string) {
	timeout := currentConfig.DNSTimeout
	if timeout <= 0 {
		timeout = defaultDNSTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client := &dns.Client{Timeout: timeout}
	resp, _, err := client.ExchangeContext(ctx, req, server)
	if err != nil {
		dns.HandleFailed(w, req)
		return
	}

	if err := w.WriteMsg(resp); err != nil {
		logger.Printf("forward DNS reply error: %v", err)
	}
}
