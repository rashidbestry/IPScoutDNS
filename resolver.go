package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func isDomainAllowed(domain string) bool {
	if currentConfig.DomainsFile == "" && len(domainRegexes) == 0 {
		return true
	}
	for _, re := range domainRegexes {
		if re.MatchString(domain) {
			return true
		}
	}
	return false
}

func handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		dns.HandleFailed(w, req)
		return
	}

	q := req.Question[0]
	domain := strings.TrimSuffix(strings.ToLower(q.Name), ".")

	if q.Qtype != dns.TypeA {
		forwardDNS(w, req, currentConfig.FallbackDNS)
		return
	}

	logger.Printf("request: %s [A] from %s", domain, w.RemoteAddr())

	if !isDomainAllowed(domain) {
		logger.Printf("%s: domain not in allowed list, forwarding to fallback", domain)
		forwardDNS(w, req, currentConfig.FallbackDNS)
		return
	}

	f, leader := getFlight(domain)
	if !leader {
		<-f.done
		if f.ok {
			replyIP(w, req, f.ip)
			return
		}
		forwardDNS(w, req, currentConfig.FallbackDNS)
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

	logger.Printf("%s: NO WORKING IP FOUND - DNS fallback", domain)
	recordDomainUnreachable(domain)
	forwardDNS(w, req, currentConfig.FallbackDNS)
}

func resolveAndSelect(domain string, cfg Config) (string, bool) {
	return resolveAndSelectWith(domain, cfg, queryResolver, testTLS, pingIPFn)
}

type resolverQueryFunc func(context.Context, string, string, bool, Config) []string
type tlsProbeFunc func(context.Context, string, string, Config) tlsProbeResult
type icmpProbeFunc func(string) bool

type resolverTarget struct {
	server       string
	throughSOCKS bool
}

func normalizeIPv4Candidate(value string) (string, bool) {
	parsed := net.ParseIP(strings.TrimSpace(value))
	if parsed == nil {
		return "", false
	}
	ipv4 := parsed.To4()
	if ipv4 == nil || !ipv4.IsGlobalUnicast() {
		return "", false
	}
	return ipv4.String(), true
}

func resolveAndSelectWith(domain string, cfg Config, query resolverQueryFunc, tlsCheck tlsProbeFunc, pingCheck icmpProbeFunc) (string, bool) {
	ips := collectResolverIPs(domain, cfg, query)
	if cfg.CacheTTL > 0 {
		if entry, ok := getCache(domain); ok {
			if time.Since(entry.Checked) < cfg.CacheTTL {
				if cachedIP, valid := normalizeIPv4Candidate(entry.IP); valid {
					found := false
					for _, ip := range ips {
						if ip == cachedIP {
							found = true
							break
						}
					}
					if !found {
						ips = append(ips, cachedIP)
					}
				}
			} else {
				deleteCache(domain)
			}
		}
	}
	if len(ips) == 0 {
		logger.Printf("%s: no resolver returned IPv4 addresses", domain)
		return "", false
	}
	logger.Printf("%s: collected %d unique IPv4 candidates", domain, len(ips))

	ctx := context.Background()
	tlsResults := runIPChecks(ctx, ips, cfg.MaxParallelTests, func(ip string) tlsProbeResult {
		logger.Printf("%s: TLS testing %s", domain, ip)
		return tlsCheck(ctx, domain, ip, cfg)
	})

	var tcpFailed []string
	for _, ip := range ips {
		result := tlsResults[ip]
		if result.tcpReachable {
			recordReachableIP(ip)
		} else {
			tcpFailed = append(tcpFailed, ip)
		}
	}

	icmpResults := runIPChecks(ctx, tcpFailed, cfg.MaxParallelTests, func(ip string) bool {
		logger.Printf("%s: ICMP testing %s after TCP failure", domain, ip)
		return pingCheck(ip)
	})
	for _, ip := range tcpFailed {
		if icmpResults[ip] {
			recordReachableIP(ip)
		} else {
			recordUnreachableIP(ip)
		}
	}

	selectedIP := ""
	for _, ip := range ips {
		if tlsResults[ip].tlsReady {
			recordReachableHost(domain, ip)
			if selectedIP == "" {
				selectedIP = ip
			}
		}
	}
	if selectedIP == "" {
		deleteCache(domain)
	}
	return selectedIP, selectedIP != ""
}

func collectResolverIPs(domain string, cfg Config, query resolverQueryFunc) []string {
	targets := make([]resolverTarget, 0, len(cfg.DirectDNS)+len(cfg.ProxyDNS))
	for _, server := range cfg.DirectDNS {
		targets = append(targets, resolverTarget{server: server})
	}
	for _, server := range cfg.ProxyDNS {
		targets = append(targets, resolverTarget{server: server, throughSOCKS: true})
	}
	if len(targets) == 0 {
		return nil
	}
	if strings.TrimSpace(cfg.DNSSOCKS5Addr) == "" {
		filtered := targets[:0]
		for _, target := range targets {
			if !target.throughSOCKS {
				filtered = append(filtered, target)
			}
		}
		targets = filtered
	}
	if len(targets) == 0 {
		logger.Printf("%s: proxy DNS configured but SOCKS5 address is empty", domain)
		return nil
	}

	timeout := cfg.DNSTimeout
	if timeout <= 0 {
		timeout = defaultDNSTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	results := make(chan []string, len(targets))
	for _, target := range targets {
		target := target
		go func() {
			results <- query(ctx, domain, target.server, target.throughSOCKS, cfg)
		}()
	}

	seen := make(map[string]bool)
	var ips []string
	for range targets {
		for _, value := range <-results {
			ip, valid := normalizeIPv4Candidate(value)
			if !valid {
				continue
			}
			if seen[ip] {
				continue
			}
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	return ips
}

func queryResolver(ctx context.Context, domain string, server string, throughSOCKS bool, cfg Config) []string {
	server = strings.TrimSpace(server)
	if server == "" {
		return nil
	}
	if strings.HasPrefix(strings.ToLower(server), "https://") || strings.HasPrefix(strings.ToLower(server), "http://") {
		if throughSOCKS {
			return queryDoHSOCKS5(ctx, domain, server, cfg.DNSSOCKS5Addr)
		}
		logger.Printf("%s: ignoring DoH resolver in direct DNS section: %s", domain, server)
		return nil
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	if throughSOCKS {
		return queryDNSSOCKS5(ctx, domain, cfg.DNSSOCKS5Addr, server)
	}
	return queryDNS(ctx, domain, server, cfg)
}

func runIPChecks[T any](ctx context.Context, ips []string, parallel int, check func(string) T) map[string]T {
	results := make(map[string]T, len(ips))
	if len(ips) == 0 {
		return results
	}
	if parallel <= 0 {
		parallel = defaultMaxParallel
	}
	if parallel > len(ips) {
		parallel = len(ips)
	}
	type result struct {
		ip    string
		value T
	}
	jobs := make(chan string)
	completed := make(chan result, len(ips))
	var workers sync.WaitGroup
	for i := 0; i < parallel; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for ip := range jobs {
				completed <- result{ip: ip, value: check(ip)}
			}
		}()
	}
	go func() {
		for _, ip := range ips {
			jobs <- ip
		}
		close(jobs)
		workers.Wait()
		close(completed)
	}()
	for result := range completed {
		results[result.ip] = result.value
	}
	return results
}

func queryDNS(ctx context.Context, domain string, server string, cfg Config) []string {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msg.RecursionDesired = true

	timeout := cfg.DNSTimeout
	if timeout <= 0 {
		timeout = defaultDNSTimeout
	}

	client, err := newDNSClient(timeout, cfg.DNSInterface, server)
	if err != nil {
		logger.Printf("%s: invalid DNS interface selection: %v", domain, err)
		return nil
	}
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

const forwardFailureLogInterval = 30 * time.Second

var (
	forwardFailureLogMu sync.Mutex
	forwardFailureLogs  = make(map[string]time.Time)
)

func logForwardFailure(server string, err error) {
	var networkErr net.Error
	if !errors.As(err, &networkErr) || !networkErr.Timeout() {
		logger.Printf("forward DNS to %s failed: %v", server, err)
		return
	}

	now := time.Now()
	forwardFailureLogMu.Lock()
	lastLogged := forwardFailureLogs[server]
	if !lastLogged.IsZero() && now.Sub(lastLogged) < forwardFailureLogInterval {
		forwardFailureLogMu.Unlock()
		return
	}
	forwardFailureLogs[server] = now
	forwardFailureLogMu.Unlock()

	logger.Printf("forward DNS to %s failed: %v", server, err)
}

func forwardDNS(w dns.ResponseWriter, req *dns.Msg, server string) {
	timeout := currentConfig.DNSTimeout
	if timeout <= 0 {
		timeout = defaultDNSTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := newDNSClient(timeout, currentConfig.DNSInterface, server)
	if err != nil {
		logger.Printf("invalid DNS interface selection: %v", err)
		dns.HandleFailed(w, req)
		return
	}
	resp, _, err := client.ExchangeContext(ctx, req, server)
	if err != nil {
		logForwardFailure(server, err)
		dns.HandleFailed(w, req)
		return
	}

	if err := w.WriteMsg(resp); err != nil {
		logger.Printf("forward DNS reply error: %v", err)
	}
}
