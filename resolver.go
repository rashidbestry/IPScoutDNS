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
	for _, re := range domainRegexes {
		if re.MatchString(domain) {
			return true
		}
	}
	return false
}

func handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	handleDNSWith(w, req, resolveAndSelectStatus)
}

func handleDNSWith(w dns.ResponseWriter, req *dns.Msg, resolve func(string, Config) (string, bool, bool)) {
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
		select {
		case <-f.done:
		case <-dnsServiceContext(currentConfig).Done():
			dns.HandleFailed(w, req)
			return
		}
		if f.ok {
			replyIP(w, req, f.ip)
			return
		}
		forwardDNS(w, req, currentConfig.FallbackDNS)
		return
	}

	ip, ok, _ := resolve(domain, currentConfig)
	f.ip = ip
	f.ok = ok
	close(f.done)
	removeFlight(domain, f)

	if ok {
		replyIP(w, req, ip)
		return
	}

	logger.Printf("%s: NO WORKING IP FOUND - DNS fallback", domain)
	forwardDNS(w, req, currentConfig.FallbackDNS)
}

func resolveAndSelect(domain string, cfg Config) (string, bool) {
	return resolveAndSelectWith(domain, cfg, queryResolver, testTLS, pingProbe(dnsServiceContext(cfg), cfg))
}

func resolveAndSelectStatus(domain string, cfg Config) (string, bool, bool) {
	return resolveAndSelectWithStatus(domain, cfg, queryResolver, testTLS, pingProbe(dnsServiceContext(cfg), cfg))
}

type resolverQueryFunc func(context.Context, string, string, bool, Config) []string
type tlsProbeFunc func(context.Context, string, string, Config) tlsProbeResult
type httpProbeFunc func(context.Context, string, string, Config) httpProbeResult
type icmpProbeFunc func(string) bool

type resolverTarget struct {
	server       string
	throughSOCKS bool
}

// One gate is shared by all domains, modes, and fallback requests. Its zero
// value is ready for use; a zero limit allows unlimited concurrent queries.
type dnsQueryLimiter struct {
	mu      sync.Mutex
	active  int
	changed chan struct{}
}

var upstreamDNSQueries dnsQueryLimiter

func (l *dnsQueryLimiter) acquire(ctx context.Context, limit int) error {
	if limit < 0 {
		limit = defaultDNSQueryParallel
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if limit == 0 || l.active < limit {
			l.active++
			return nil
		}
		if l.changed == nil {
			l.changed = make(chan struct{})
		}
		changed := l.changed
		l.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
		}
		l.mu.Lock()
	}
}

func (l *dnsQueryLimiter) release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.active--
	if l.changed != nil {
		close(l.changed)
		l.changed = nil
	}
}

func dnsServiceContext(cfg Config) context.Context {
	if cfg.runtimeContext != nil {
		return cfg.runtimeContext
	}
	return context.Background()
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
	ip, ok, _ := resolveAndSelectWithStatus(domain, cfg, query, tlsCheck, pingCheck)
	return ip, ok
}

func resolveAndSelectWithStatus(domain string, cfg Config, query resolverQueryFunc, tlsCheck tlsProbeFunc, pingCheck icmpProbeFunc) (string, bool, bool) {
	return resolveAndSelectWithContext(dnsServiceContext(cfg), domain, cfg, query, tlsCheck, pingCheck)
}

func resolveAndSelectWithContext(ctx context.Context, domain string, cfg Config, query resolverQueryFunc, tlsCheck tlsProbeFunc, pingCheck icmpProbeFunc) (string, bool, bool) {
	return resolveAndSelectWithProbes(ctx, domain, cfg, query, tlsCheck, testHTTP, pingCheck)
}

func resolveAndSelectWithProbes(ctx context.Context, domain string, cfg Config, query resolverQueryFunc, tlsCheck tlsProbeFunc, httpCheck httpProbeFunc, pingCheck icmpProbeFunc) (string, bool, bool) {
	if !cfg.TCPProbe && !cfg.TLSProbe && !cfg.HTTPProbe && !cfg.ICMPProbe {
		logger.Printf("%s: all reachability probes disabled; keeping previous status", domain)
		return "", false, false
	}
	if cfg.CacheTTL > 0 {
		if entry, ok := getCache(domain); ok {
			if time.Since(entry.Checked) < cfg.CacheTTL {
				if cachedIP, valid := normalizeIPv4Candidate(entry.IP); valid {
					logger.Printf("%s: CACHE HIT = %s [%s]", domain, cachedIP, entry.Protocol)
					if cfg.HostsMaxIPsPerDomain > 0 {
						updateReachableHosts(domain, []string{cachedIP}, cfg.HostsMaxIPsPerDomain, true)
						recordReachableDomain(domain)
						recordReachableIP(cachedIP)
					} else {
						recordReachableHost(domain, cachedIP)
					}
					return cachedIP, true, true
				}
			}
			deleteCache(domain)
		}
	}

	ips := collectResolverIPsWithContext(ctx, domain, cfg, query)
	if len(ips) == 0 {
		// Without a candidate IP, no reachability probe was possible. Preserve
		// the previous status rather than treating a DNS failure as a TCP failure.
		logger.Printf("%s: no resolver returned IPv4 addresses; domain reachability unknown, keeping previous status", domain)
		return "", false, false
	}
	logger.Printf("%s: collected %d unique IPv4 candidates", domain, len(ips))

	checkTCPOrTLS := func(ip string) tlsProbeResult {
		if cfg.TLSProbe {
			return tlsCheck(ctx, domain, ip, cfg)
		}
		if !cfg.TCPProbe {
			return tlsProbeResult{}
		}
		probeCtx, cancel := reachabilityContext(ctx, cfg)
		defer cancel()
		conn, err := dialReachability(probeCtx, domain, ip, cfg)
		if err != nil {
			return tlsProbeResult{}
		}
		_ = conn.Close()
		return tlsProbeResult{tcpReachable: true}
	}
	tlsPassed := func(result tlsProbeResult) bool {
		return candidateProbePassed(cfg, result, httpProbeResult{}, false)
	}
	tlsResults, limitReached, earlyHTTP := runTLSChecksWithHTTPFallback(ctx, ips, cfg, func(ip string) tlsProbeResult {
		if cfg.TCPProbe || cfg.TLSProbe {
			logger.Printf("%s: TCP/TLS testing %s", domain, ip)
		}
		return checkTCPOrTLS(ip)
	}, tlsPassed)
	if ctx.Err() != nil {
		return "", false, false
	}
	anyTCPReachable := false
	for _, result := range tlsResults {
		if result.tcpReachable {
			anyTCPReachable = true
			break
		}
	}
	if !anyTCPReachable && (cfg.TCPProbe || cfg.TLSProbe) {
		// Confirm a completely failed probe round before changing domain status.
		// Retry only on total TCP failure, using the same timeout and worker limit.
		logger.Printf("%s: all TCP probes failed; retrying once before classifying domain", domain)
		tlsResults, limitReached = runIPChecksLimited(ctx, ips, cfg.MaxParallelTests, cfg.HostsMaxIPsPerDomain, func(ip string) tlsProbeResult {
			return checkTCPOrTLS(ip)
		}, tlsPassed)
		if ctx.Err() != nil {
			return "", false, false
		}
	}

	domainReachable := false
	for _, result := range tlsResults {
		if result.tcpReachable && result.tlsReady {
			domainReachable = true
			break
		}
	}
	var httpResults map[string]httpProbeResult
	if !domainReachable && cfg.HTTPProbe {
		if earlyHTTP {
			logger.Printf("%s: remote TLS internal_error alert threshold reached (%d) with no TLS success; pausing remaining TLS checks and checking HTTP on port 80", domain, cfg.HTTPFallbackTLSAlerts)
		} else {
			logger.Printf("%s: no TLS-ready IP; checking HTTP on port 80", domain)
		}
		httpResults, limitReached = runIPChecksLimited(ctx, ips, cfg.MaxParallelTests, cfg.HostsMaxIPsPerDomain, func(ip string) httpProbeResult {
			return httpCheck(ctx, domain, ip, cfg)
		}, func(result httpProbeResult) bool { return result.tcpReachable && result.httpReady })
		if ctx.Err() != nil {
			return "", false, false
		}
		for ip, result := range httpResults {
			if result.tcpReachable && result.httpReady {
				logger.Printf("%s: HTTP reachable at %s:80", domain, ip)
				domainReachable = true
				break
			}
		}
	}
	if earlyHTTP && !domainReachable {
		var remaining []string
		for _, ip := range ips {
			if _, checked := tlsResults[ip]; !checked {
				remaining = append(remaining, ip)
			}
		}
		logger.Printf("%s: early HTTP fallback failed; resuming TLS checks for %d candidates", domain, len(remaining))
		resumed, reached := runIPChecksLimited(ctx, remaining, cfg.MaxParallelTests, cfg.HostsMaxIPsPerDomain, checkTCPOrTLS, tlsPassed)
		if ctx.Err() != nil {
			return "", false, false
		}
		limitReached = reached
		for ip, result := range resumed {
			tlsResults[ip] = result
			if result.tcpReachable && result.tlsReady {
				domainReachable = true
			}
		}
	}
	var tcpFailed []string
	for _, ip := range ips {
		result, tlsChecked := tlsResults[ip]
		_, httpChecked := httpResults[ip]
		// Candidates skipped at the quota have unknown status, not failed status.
		if !tlsChecked && !httpChecked {
			continue
		}
		if result.tcpReachable || httpResults[ip].tcpReachable {
			recordReachableIP(ip)
		} else if tlsChecked || !(cfg.TCPProbe || cfg.TLSProbe) {
			tcpFailed = append(tcpFailed, ip)
		}
	}

	var icmpResults map[string]bool
	// ICMP cannot use the SOCKS5 route. Never use a direct ping to validate
	// reachability after a failed proxy connection.
	if !limitReached && cfg.ICMPProbe && cfg.TLSRoute != "proxy" {
		icmpResults, limitReached = runIPChecksLimited(ctx, tcpFailed, cfg.MaxParallelTests, cfg.HostsMaxIPsPerDomain, func(ip string) bool {
			logger.Printf("%s: ICMP testing %s after TCP failure", domain, ip)
			return pingCheck(ip)
		}, func(result bool) bool { return candidateProbePassed(cfg, tlsProbeResult{}, httpProbeResult{}, result) })
	}
	if ctx.Err() != nil {
		return "", false, false
	}
	for _, ip := range tcpFailed {
		if limitReached {
			if _, checked := icmpResults[ip]; !checked {
				continue
			}
		}
		if icmpResults[ip] {
			recordReachableIP(ip)
		} else {
			recordUnreachableIP(ip)
		}
	}
	if !cfg.TLSProbe && !cfg.HTTPProbe {
		for _, ip := range ips {
			if candidateProbePassed(cfg, tlsResults[ip], httpResults[ip], icmpResults[ip]) {
				domainReachable = true
			}
		}
	}
	// TCP/ICMP-only selection is permitted when both service probes are disabled.
	if domainReachable {
		recordReachableDomain(domain)
	} else {
		recordDomainUnreachable(domain)
	}

	if limitReached {
		logger.Printf("%s: reached %d successful IPs; skipping remaining probes", domain, cfg.HostsMaxIPsPerDomain)
	}
	selectedIP, selectedProtocol := "", ""
	var hostIPs []string
	for _, ip := range ips {
		protocol := candidateProbeProtocol(cfg, tlsResults[ip], httpResults[ip], icmpResults[ip])
		if protocol != "" {
			hostIPs = append(hostIPs, ip)
		}
		// Early HTTP success leaves the untested TLS candidates unknown.
		if protocol != "" && selectedIP == "" {
			selectedIP = ip
			selectedProtocol = protocol
		}
	}
	if cfg.HostsMaxIPsPerDomain > 0 {
		// Refresh the domain's mappings rather than accumulating new IPs across
		// Active resolutions, restarts, or scheduled Passive passes.
		updateReachableHosts(domain, hostIPs, cfg.HostsMaxIPsPerDomain, false)
	}
	for _, ip := range hostIPs {
		if cfg.HostsMaxIPsPerDomain > 0 {
			recordReachableIP(ip)
		} else {
			recordReachableHost(domain, ip)
		}
	}
	if selectedIP == "" {
		deleteCache(domain)
	} else {
		if cfg.Mode != "passive" {
			updateCache(domain, selectedIP, selectedProtocol)
		}
		logger.Printf("%s: WORKING IP = %s [%s]", domain, selectedIP, selectedProtocol)
	}
	return selectedIP, selectedIP != "", false
}

func candidateProbePassed(cfg Config, tls tlsProbeResult, http httpProbeResult, icmp bool) bool {
	return candidateProbeProtocol(cfg, tls, http, icmp) != ""
}

func candidateProbeProtocol(cfg Config, tls tlsProbeResult, http httpProbeResult, icmp bool) string {
	if cfg.TLSProbe && tls.tcpReachable && tls.tlsReady {
		return "TLS"
	}
	if cfg.HTTPProbe && http.tcpReachable && http.httpReady {
		return "HTTP"
	}
	if cfg.TLSProbe || cfg.HTTPProbe {
		return ""
	}
	if cfg.TCPProbe {
		if tls.tcpReachable {
			return "TCP"
		}
		return ""
	}
	if cfg.ICMPProbe && cfg.TLSRoute != "proxy" && icmp {
		return "ICMP"
	}
	return ""
}

func collectResolverIPs(domain string, cfg Config, query resolverQueryFunc) []string {
	return collectResolverIPsWithContext(context.Background(), domain, cfg, query)
}

func collectResolverIPsWithContext(parent context.Context, domain string, cfg Config, query resolverQueryFunc) []string {
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
	// Waiting for a global slot does not consume this query's network timeout.
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	type resolverResult struct {
		target resolverTarget
		values []string
	}
	results := make(chan resolverResult, len(targets))
	for _, target := range targets {
		target := target
		go func() {
			values := func() []string {
				if err := upstreamDNSQueries.acquire(ctx, cfg.DNSQueryParallel); err != nil {
					return nil
				}
				defer upstreamDNSQueries.release()
				queryCtx, cancelQuery := context.WithTimeout(ctx, timeout)
				defer cancelQuery()
				return query(queryCtx, domain, target.server, target.throughSOCKS, cfg)
			}()
			results <- resolverResult{target: target, values: values}
		}()
	}

	seen := make(map[string]bool)
	var ips []string
	for range targets {
		var result resolverResult
		select {
		case result = <-results:
		case <-ctx.Done():
			return ips
		}
		for _, value := range result.values {
			ip, valid := normalizeIPv4Candidate(value)
			if !valid {
				logger.Printf("%s: resolver %s returned unsuitable IPv4 candidate %q; discarded (proxy=%t)", domain, result.target.server, value, result.target.throughSOCKS)
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

// Pause TLS only after matching alerts from distinct candidates and no TLS
// successes. Smaller initial batches avoid launching a full worker pool before
// the alert threshold can be evaluated. Once TLS succeeds, use the usual quota.
func runTLSChecksWithHTTPFallback(ctx context.Context, ips []string, cfg Config, check func(string) tlsProbeResult, passed func(tlsProbeResult) bool) (map[string]tlsProbeResult, bool, bool) {
	threshold := cfg.HTTPFallbackTLSAlerts
	if !cfg.TLSProbe || !cfg.HTTPProbe || threshold <= 0 {
		results, reached := runIPChecksLimited(ctx, ips, cfg.MaxParallelTests, cfg.HostsMaxIPsPerDomain, check, passed)
		return results, reached, false
	}
	parallel := cfg.MaxParallelTests
	if parallel <= 0 {
		parallel = defaultMaxParallel
	}
	results := make(map[string]tlsProbeResult)
	successes, alerts := 0, 0
	for start := 0; start < len(ips) && ctx.Err() == nil; {
		size := min(parallel, len(ips)-start)
		if cfg.HostsMaxIPsPerDomain > 0 {
			size = min(size, cfg.HostsMaxIPsPerDomain-successes)
		}
		if start == 0 {
			size = min(size, threshold)
		}
		batch := runIPChecks(ctx, ips[start:start+size], size, check)
		for ip, result := range batch {
			if _, seen := results[ip]; seen {
				continue
			}
			results[ip] = result
			if passed(result) {
				successes++
			}
			if result.tcpReachable && result.internalError {
				alerts++
			}
		}
		start += size
		if cfg.HostsMaxIPsPerDomain > 0 && successes >= cfg.HostsMaxIPsPerDomain {
			return results, true, false
		}
		if successes == 0 && alerts >= threshold && start < len(ips) {
			return results, false, true
		}
	}
	return results, false, false
}

// Limit each batch to the remaining success quota. Even with a large worker
// count, no extra candidate is launched after enough successful results exist.
func runIPChecksLimited[T any](ctx context.Context, ips []string, parallel, limit int, check func(string) T, passed func(T) bool) (map[string]T, bool) {
	if limit <= 0 {
		return runIPChecks(ctx, ips, parallel, check), false
	}
	if parallel <= 0 {
		parallel = defaultMaxParallel
	}
	results := make(map[string]T)
	successes := 0
	for start := 0; start < len(ips) && ctx.Err() == nil; {
		size := min(parallel, limit-successes, len(ips)-start)
		batch := runIPChecks(ctx, ips[start:start+size], size, check)
		for ip, result := range batch {
			results[ip] = result
			if passed(result) {
				successes++
			}
		}
		if successes >= limit {
			return results, true
		}
		start += size
	}
	return results, false
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
				if ctx.Err() != nil {
					return
				}
				completed <- result{ip: ip, value: check(ip)}
			}
		}()
	}
	go func() {
		for _, ip := range ips {
			select {
			case jobs <- ip:
			case <-ctx.Done():
				close(jobs)
				workers.Wait()
				close(completed)
				return
			}
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

	client, err := newDNSClient(timeout, cfg.DirectDNSInterface, server)
	if err != nil {
		logger.Printf("%s: DNS %s invalid interface selection: %v", domain, server, err)
		return nil
	}
	conn, err := client.DialContext(ctx, server)
	if err != nil {
		logger.Printf("%s: DNS %s connection failed: %v", domain, server, err)
		return nil
	}
	defer conn.Close()
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()
	resp, _, err := client.ExchangeWithConnContext(ctx, msg, conn)
	if err != nil {
		logger.Printf("%s: DNS %s query failed: %v", domain, server, err)
		return nil
	}

	return resolverIPv4Response(domain, server, resp)
}

func queryDNSSOCKS5(ctx context.Context, domain, socksAddr, dnsAddr string) []string {
	fail := func(stage string, err error) []string {
		logger.Printf("%s: SOCKS5 DNS %s %s failed: %v", domain, dnsAddr, stage, err)
		return nil
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msg.RecursionDesired = true

	wire, err := msg.Pack()
	if err != nil {
		return fail("request encoding", err)
	}

	conn, err := dialSOCKS5(ctx, socksAddr, dnsAddr)
	if err != nil {
		logger.Printf("%s: SOCKS5 DNS %s failed: %v", domain, dnsAddr, err)
		return nil
	}
	defer conn.Close()
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(wire)))
	if _, err := conn.Write(length[:]); err != nil {
		return fail("request length write", err)
	}
	if _, err := conn.Write(wire); err != nil {
		return fail("request write", err)
	}
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return fail("response length read", err)
	}

	n := int(binary.BigEndian.Uint16(length[:]))
	if n <= 0 || n > 65535 {
		logger.Printf("%s: SOCKS5 DNS %s returned invalid message length %d", domain, dnsAddr, n)
		return nil
	}
	respWire := make([]byte, n)
	if _, err := io.ReadFull(conn, respWire); err != nil {
		return fail("response read", err)
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(respWire); err != nil {
		return fail("response decoding", err)
	}
	return resolverIPv4Response(domain, dnsAddr, resp)
}

func queryDoHSOCKS5(ctx context.Context, domain, endpoint, socksAddr string) []string {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msg.RecursionDesired = true
	wire, err := msg.Pack()
	if err != nil {
		logger.Printf("%s: SOCKS5 DoH %s request encoding failed: %v", domain, endpoint, err)
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
		logger.Printf("%s: SOCKS5 DoH %s request creation failed: %v", domain, endpoint, err)
		return nil
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		logger.Printf("%s: SOCKS5 DoH %s failed: %v", domain, endpoint, err)
		return nil
	}
	return readDoHResponse(domain, endpoint, resp)
}

func readDoHResponse(domain, endpoint string, resp *http.Response) []string {
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logger.Printf("%s: SOCKS5 DoH %s returned HTTP %s", domain, endpoint, resp.Status)
		return nil
	}

	respWire, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		logger.Printf("%s: SOCKS5 DoH %s response read failed: %v", domain, endpoint, err)
		return nil
	}
	msgResp := new(dns.Msg)
	if err := msgResp.Unpack(respWire); err != nil {
		logger.Printf("%s: SOCKS5 DoH %s invalid DNS response (Content-Type=%q): %v", domain, endpoint, resp.Header.Get("Content-Type"), err)
		return nil
	}
	return resolverIPv4Response(domain, endpoint, msgResp)
}

func resolverIPv4Response(domain, server string, resp *dns.Msg) []string {
	if resp == nil {
		logger.Printf("%s: resolver %s returned no DNS message", domain, server)
		return nil
	}
	ips := extractIPv4(resp)
	// Include successful empty responses: HTTP 200 alone does not establish
	// that the resolver supplied any A records for the requested domain.
	logger.Printf("%s: resolver %s returned DNS %s with %d A records", domain, server, dns.RcodeToString[resp.Rcode], len(ips))
	if resp.Rcode != dns.RcodeSuccess {
		return nil
	}
	return ips
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

	parent := dnsServiceContext(currentConfig)
	if err := upstreamDNSQueries.acquire(parent, currentConfig.DNSQueryParallel); err != nil {
		dns.HandleFailed(w, req)
		return
	}
	defer upstreamDNSQueries.release()
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	client, err := newDNSClient(timeout, currentConfig.FallbackDNSInterface, server)
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
