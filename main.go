package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	configPath = "/etc/ipselector.conf"

	defaultListenAddr = "127.0.0.1:5354"
	defaultAdguardDNS = "127.0.0.1:53053"
	defaultSOCKS5Addr = "127.0.0.1:1080"
	defaultCacheTTL   = 24 * time.Hour

	dnsTimeout = 3 * time.Second
	tlsTimeout = 3 * time.Second

	maxParallelTests = 16

	answerTTL uint32 = 300
)

type Config struct {
	DirectDNS  []string
	ProxyDNS   []string
	ListenAddr string
	AdguardDNS string
	SOCKS5Addr string
	CacheTTL   time.Duration
}

type CacheEntry struct {
	IP      string
	Checked time.Time
}

type flight struct {
	done chan struct{}
	ip   string
	ok   bool
}

var (
	cacheMu sync.RWMutex
	cache   = make(map[string]CacheEntry)

	flightMu sync.Mutex
	flights  = make(map[string]*flight)
)

var logger = log.New(
	os.Stdout,
	"[ipselector] ",
	log.LstdFlags,
)

var currentConfig Config

func loadConfig(path string) (Config, error) {
	cfg := Config{
		ListenAddr: defaultListenAddr,
		AdguardDNS: defaultAdguardDNS,
		SOCKS5Addr: defaultSOCKS5Addr,
		CacheTTL:   defaultCacheTTL,
	}

	f, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	section := ""
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}

		switch section {
		case "direct_dns":
			cfg.DirectDNS = append(cfg.DirectDNS, line)
		case "proxy_dns":
			cfg.ProxyDNS = append(cfg.ProxyDNS, line)
		case "socks5", "adguard", "cache", "server":
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				return cfg, fmt.Errorf("%s:%d: expected key=value", path, lineNo)
			}
			key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
			switch section {
			case "socks5":
				if key == "address" {
					cfg.SOCKS5Addr = value
				}
			case "adguard":
				if key == "address" {
					cfg.AdguardDNS = value
				}
			case "cache":
				if key == "ttl" {
					d, err := time.ParseDuration(value)
					if err != nil || d <= 0 {
						return cfg, fmt.Errorf("%s:%d: invalid cache ttl %q", path, lineNo, value)
					}
					cfg.CacheTTL = d
				}
			case "server":
				if key == "address" {
					cfg.ListenAddr = value
				}
			}
		default:
			return cfg, fmt.Errorf("%s:%d: setting outside a known section", path, lineNo)
		}
	}
	if err := scanner.Err(); err != nil {
		return cfg, err
	}

	cfg.DirectDNS = cleanList(cfg.DirectDNS)
	cfg.ProxyDNS = cleanList(cfg.ProxyDNS)
	return cfg, nil
}

func cleanList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool)
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func main() {
	cfg, err := loadConfig(configPath)
	if err != nil {
		logger.Fatalf("configuration error: %v", err)
	}

	currentConfig = cfg

	logger.Printf("starting IPSelector v3")
	logger.Printf("UDP/TCP listen: %s", cfg.ListenAddr)
	logger.Printf("AdGuard DNS fallback: %s", cfg.AdguardDNS)
	logger.Printf("direct DNS resolvers: %d", len(cfg.DirectDNS))
	logger.Printf("proxy DNS resolvers: %d", len(cfg.ProxyDNS))
	logger.Printf("SOCKS5 proxy: %s", cfg.SOCKS5Addr)
	logger.Printf("cache TTL: %s", cfg.CacheTTL)
	logger.Printf("parallel TLS tests: %d", maxParallelTests)

	handler := dns.HandlerFunc(handleDNS)

	udpServer := &dns.Server{
		Addr:    cfg.ListenAddr,
		Net:     "udp",
		Handler: handler,
	}

	tcpServer := &dns.Server{
		Addr:    cfg.ListenAddr,
		Net:     "tcp",
		Handler: handler,
	}

	go func() {
		logger.Printf("UDP DNS listening on %s", cfg.ListenAddr)

		if err := udpServer.ListenAndServe(); err != nil {
			logger.Fatalf("UDP server failed: %v", err)
		}
	}()

	go func() {
		logger.Printf("TCP DNS listening on %s", cfg.ListenAddr)

		if err := tcpServer.ListenAndServe(); err != nil {
			logger.Fatalf("TCP server failed: %v", err)
		}
	}()

	select {}
}

func handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		dns.HandleFailed(w, req)
		return
	}

	q := req.Question[0]

	domain := strings.TrimSuffix(
		strings.ToLower(q.Name),
		".",
	)

	/*
	 * Only A records go through IP selection.
	 *
	 * AAAA, MX, CNAME, TXT, etc. are forwarded normally.
	 */
	if q.Qtype != dns.TypeA {
		forwardDNS(w, req, currentConfig.AdguardDNS)
		return
	}

	logger.Printf(
		"request: %s from %s",
		domain,
		w.RemoteAddr(),
	)

	/*
	 * 1. Check 24-hour cache.
	 */
	if entry, ok := getCache(domain); ok {
		age := time.Since(entry.Checked)

		if age < currentConfig.CacheTTL {
			logger.Printf(
				"%s: CACHE HIT %s (age %s)",
				domain,
				entry.IP,
				age.Round(time.Second),
			)

			replyIP(w, req, entry.IP)
			return
		}

		/*
		 * Cache expired.
		 *
		 * Only ONE request should validate the cached IP.
		 * Other simultaneous requests wait for it.
		 */
		logger.Printf(
			"%s: cached IP expired: %s",
			domain,
			entry.IP,
		)

		if testCachedIP(domain, entry.IP) {
			logger.Printf(
				"%s: cached IP still reachable: %s",
				domain,
				entry.IP,
			)

			updateCache(domain, entry.IP)
			replyIP(w, req, entry.IP)
			return
		}

		logger.Printf(
			"%s: cached IP FAILED: %s",
			domain,
			entry.IP,
		)

		deleteCache(domain)
	}

	/*
	 * 2. Request coalescing.
	 *
	 * If another client is already resolving this domain,
	 * wait for that lookup instead of starting another one.
	 */
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

	/*
	 * 3. We are the lookup leader.
	 */
	ip, ok := resolveAndSelect(domain, currentConfig)

	f.ip = ip
	f.ok = ok

	close(f.done)

	removeFlight(domain, f)

	if ok {
		updateCache(domain, ip)

		logger.Printf(
			"%s: WORKING IP = %s",
			domain,
			ip,
		)

		replyIP(w, req, ip)
		return
	}

	/*
	 * 4. No usable IP.
	 *
	 * Preserve normal DNS behavior.
	 */
	logger.Printf(
		"%s: NO WORKING IP FOUND - AdGuard fallback",
		domain,
	)

	forwardDNS(w, req, currentConfig.AdguardDNS)
}

/*
 * resolveAndSelect:
 *
 * DNS resolvers run concurrently.
 *
 * As soon as an IP is received, it is put into the
 * testing queue.
 *
 * TLS workers test candidates concurrently.
 *
 * The first successful candidate cancels everything.
 */
func resolveAndSelect(domain string, cfg Config) (string, bool) {
	// Direct DNS has priority. We completely finish the direct phase before
	// touching any Proxy DNS resolver. This keeps the SOCKS5 tunnel out of
	// the path whenever a direct resolver can provide a working IP.
	if len(cfg.DirectDNS) > 0 {
		if ip, ok := resolvePhase(domain, cfg.DirectDNS, false, cfg); ok {
			return ip, true
		}
		logger.Printf("%s: direct DNS phase produced no working IP", domain)
	}

	// Proxy DNS is optional. An empty [proxy_dns] section means disabled.
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
	results := make(chan result, maxParallelTests)
	var workerWG sync.WaitGroup

	for i := 0; i < maxParallelTests; i++ {
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

/*
 * queryDNS performs one direct DNS query.
 */
func queryDNS(
	ctx context.Context,
	domain string,
	server string,
) []string {
	msg := new(dns.Msg)

	msg.SetQuestion(
		dns.Fqdn(domain),
		dns.TypeA,
	)

	msg.RecursionDesired = true

	client := &dns.Client{
		Timeout: dnsTimeout,
	}

	resp, _, err := client.ExchangeContext(
		ctx,
		msg,
		server,
	)

	if err != nil {
		return nil
	}

	var ips []string

	for _, answer := range resp.Answer {
		switch rr := answer.(type) {
		case *dns.A:
			ips = append(
				ips,
				rr.A.String(),
			)
		}
	}

	return ips
}

// queryDNSSOCKS5 sends DNS-over-TCP through the configured SOCKS5 proxy.
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

	client := &http.Client{Transport: transport, Timeout: dnsTimeout}
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

func dialSOCKS5(ctx context.Context, proxyAddr, targetAddr string) (net.Conn, error) {
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}

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

/*
 * testIP performs the actual reachability test.
 *
 * We deliberately use:
 *
 * TCP :443
 * TLS handshake
 * requested domain as SNI
 *
 * This is much more meaningful than traceroute
 * for determining whether HTTPS access to the IP works.
 */
func testIP(
	parent context.Context,
	domain string,
	ip string,
) bool {
	ctx, cancel := context.WithTimeout(
		parent,
		tlsTimeout,
	)
	defer cancel()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			ServerName:         domain,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		},
	}

	conn, err := dialer.DialContext(
		ctx,
		"tcp",
		net.JoinHostPort(ip, "443"),
	)

	if err != nil {
		return false
	}

	defer conn.Close()

	return true
}

/*
 * Cached IP validation.
 */
func testCachedIP(
	domain string,
	ip string,
) bool {
	logger.Printf(
		"%s: validating cached IP %s",
		domain,
		ip,
	)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		tlsTimeout,
	)
	defer cancel()

	return testIP(ctx, domain, ip)
}

/*
 * DNS response containing one selected IPv4.
 */
func replyIP(
	w dns.ResponseWriter,
	req *dns.Msg,
	ip string,
) {
	msg := new(dns.Msg)

	msg.SetReply(req)

	msg.Authoritative = true

	q := req.Question[0]

	parsed := net.ParseIP(ip)

	if parsed == nil {
		dns.HandleFailed(w, req)
		return
	}

	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    answerTTL,
		},
		A: parsed,
	}

	msg.Answer = append(
		msg.Answer,
		rr,
	)

	if err := w.WriteMsg(msg); err != nil {
		logger.Printf(
			"DNS reply error: %v",
			err,
		)
	}
}

/*
 * Normal DNS fallback.
 */
func forwardDNS(
	w dns.ResponseWriter,
	req *dns.Msg,
	server string,
) {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		dnsTimeout,
	)
	defer cancel()

	client := &dns.Client{
		Timeout: dnsTimeout,
	}

	resp, _, err := client.ExchangeContext(
		ctx,
		req,
		server,
	)

	if err != nil {
		dns.HandleFailed(w, req)
		return
	}

	if err := w.WriteMsg(resp); err != nil {
		logger.Printf(
			"forward DNS reply error: %v",
			err,
		)
	}
}

/*
 * Cache functions.
 */
func getCache(
	domain string,
) (CacheEntry, bool) {
	cacheMu.RLock()
	defer cacheMu.RUnlock()

	entry, ok := cache[domain]

	return entry, ok
}

func updateCache(
	domain string,
	ip string,
) {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	cache[domain] = CacheEntry{
		IP:      ip,
		Checked: time.Now(),
	}
}

func deleteCache(
	domain string,
) {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	delete(cache, domain)
}

/*
 * Request coalescing.
 */
func getFlight(
	domain string,
) (*flight, bool) {
	flightMu.Lock()
	defer flightMu.Unlock()

	if f, ok := flights[domain]; ok {
		return f, false
	}

	f := &flight{
		done: make(chan struct{}),
	}

	flights[domain] = f

	return f, true
}

func removeFlight(
	domain string,
	f *flight,
) {
	flightMu.Lock()
	defer flightMu.Unlock()

	if current, ok := flights[domain]; ok {
		if current == f {
			delete(
				flights,
				domain,
			)
		}
	}
}
