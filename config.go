package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultConfigPath  = "/etc/ipscoutdns.conf"
	priorityConfigPath = "ipscoutdns.conf"

	defaultListenAddr    = "127.0.0.1:5354"
	defaultFallbackDNS   = "127.0.0.1:53053"
	defaultSOCKS5Addr    = "127.0.0.1:1080"
	defaultTLSSOCKS5Addr = "127.0.0.1:1080"
	defaultCacheTTL      = 24 * time.Hour
	defaultDNSTimeout    = 3 * time.Second
	defaultTLSTimeout    = 3 * time.Second
	defaultTLSPort       = 443
	defaultTLSRoute      = "direct"
	defaultMaxParallel   = 16
	defaultAnswerTTL     = uint32(300)
	defaultShutdownTime  = 5 * time.Second
)

type Config struct {
	DirectDNS              []string
	ProxyDNS               []string
	ListenAddr             string
	FallbackDNS            string
	SOCKS5Addr             string // legacy alias for DNSSOCKS5Addr
	DNSSOCKS5Addr          string // SOCKS5 proxy used for DNS resolvers
	TLSSOCKS5Addr          string // SOCKS5 proxy used for TLS reachability checks
	TLSProxyPort           int
	CacheTTL               time.Duration
	DNSTimeout             time.Duration
	TLSTimeout             time.Duration
	TLSPort                int
	TLSRoute               string
	MaxParallelTests       int
	AnswerTTL              uint32
	ShutdownTimeout        time.Duration
	ReachableHostsFile     string
	UnreachableHostsFile   string
	UnreachableDomainsFile string
	UnreachableIPsFile     string
	DomainsFile            string
}

func (c Config) validate() error {
	if len(c.DirectDNS) == 0 && len(c.ProxyDNS) == 0 {
		return fmt.Errorf("at least one upstream resolver is required: direct_dns or proxy_dns")
	}
	if strings.TrimSpace(c.ListenAddr) == "" {
		return fmt.Errorf("server.address cannot be empty")
	}
	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		return fmt.Errorf("server.address must be host:port: %w", err)
	}
	if strings.TrimSpace(c.FallbackDNS) == "" {
		return fmt.Errorf("fallback.address cannot be empty")
	}
	if _, _, err := net.SplitHostPort(c.FallbackDNS); err != nil {
		return fmt.Errorf("fallback.address must be host:port: %w", err)
	}
	if strings.TrimSpace(c.DNSSOCKS5Addr) != "" {
		if _, _, err := net.SplitHostPort(c.DNSSOCKS5Addr); err != nil {
			return fmt.Errorf("socks5 address must be host:port: %w", err)
		}
	}
	if strings.TrimSpace(c.TLSSOCKS5Addr) != "" {
		if _, _, err := net.SplitHostPort(c.TLSSOCKS5Addr); err != nil {
			return fmt.Errorf("tls socks5 address must be host:port: %w", err)
		}
	}
	if c.CacheTTL <= 0 {
		return fmt.Errorf("cache.ttl must be greater than zero")
	}
	if c.DNSTimeout <= 0 {
		return fmt.Errorf("server.dns_timeout must be greater than zero")
	}
	if c.TLSTimeout <= 0 {
		return fmt.Errorf("server.tls_timeout must be greater than zero")
	}
	if c.TLSPort <= 0 || c.TLSPort > 65535 {
		return fmt.Errorf("server.tls_port must be a valid port number")
	}
	if c.TLSRoute != "direct" && c.TLSRoute != "proxy" {
		return fmt.Errorf("server.tls_route must be either direct or proxy")
	}
	if c.TLSRoute == "proxy" && strings.TrimSpace(c.TLSSOCKS5Addr) == "" {
		return fmt.Errorf("server.tls_route is proxy but tls socks5 address is empty")
	}
	if c.MaxParallelTests <= 0 {
		return fmt.Errorf("server.parallel_tests must be greater than zero")
	}
	if c.AnswerTTL <= 0 {
		return fmt.Errorf("server.answer_ttl must be greater than zero")
	}
	if c.ShutdownTimeout <= 0 {
		return fmt.Errorf("server.shutdown_timeout must be greater than zero")
	}
	for _, v := range c.DirectDNS {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("direct_dns contains an empty resolver entry")
		}
	}
	for _, v := range c.ProxyDNS {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("proxy_dns contains an empty resolver entry")
		}
	}
	return nil
}

func resolveConfigPath() string {
	if value := strings.TrimSpace(os.Getenv("IPSCOUTDNS_CONFIG")); value != "" {
		return value
	}
	if value := strings.TrimSpace(os.Getenv("IPSELECTOR_CONFIG")); value != "" {
		return value
	}
	if _, err := os.Stat(priorityConfigPath); err == nil {
		return priorityConfigPath
	}
	if _, err := os.Stat(defaultConfigPath); err == nil {
		return defaultConfigPath
	}
	return defaultConfigPath
}

func loadConfig(path string) (Config, error) {
	cfg := Config{
		ListenAddr:       defaultListenAddr,
		FallbackDNS:      defaultFallbackDNS,
		SOCKS5Addr:       defaultSOCKS5Addr,
		DNSSOCKS5Addr:    defaultSOCKS5Addr,
		TLSSOCKS5Addr:    defaultTLSSOCKS5Addr,
		CacheTTL:         defaultCacheTTL,
		DNSTimeout:       defaultDNSTimeout,
		TLSTimeout:       defaultTLSTimeout,
		TLSPort:          defaultTLSPort,
		TLSRoute:         defaultTLSRoute,
		MaxParallelTests: defaultMaxParallel,
		AnswerTTL:        defaultAnswerTTL,
		ShutdownTimeout:  defaultShutdownTime,
	}

	f, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var (
		rawDNSProxyAddr string
		rawDNSProxyPort string
		rawTLSProxyAddr string
		rawTLSProxyPort string
		rawSOCKS5Addr   string
	)

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
		case "socks5", "dns_proxy", "dns_resolve_proxy", "dns_socks5", "tls_proxy", "tls_socks5", "fallback", "fallback_dns", "cache", "server":
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				return cfg, fmt.Errorf("%s:%d: expected key=value", path, lineNo)
			}
			key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
			switch section {
			case "socks5":
				switch key {
				case "address":
					rawSOCKS5Addr = value
				case "port":
					v, err := strconv.Atoi(value)
					if err != nil || v <= 0 || v > 65535 {
						return cfg, fmt.Errorf("%s:%d: invalid socks5 port %q", path, lineNo, value)
					}
					rawDNSProxyPort = value
				case "dns_address", "dns_proxy":
					rawDNSProxyAddr = value
				case "dns_port", "dns_proxy_port":
					v, err := strconv.Atoi(value)
					if err != nil || v <= 0 || v > 65535 {
						return cfg, fmt.Errorf("%s:%d: invalid dns proxy port %q", path, lineNo, value)
					}
					rawDNSProxyPort = value
				case "tls_address", "tls_proxy":
					rawTLSProxyAddr = value
				case "tls_port", "tls_proxy_port":
					v, err := strconv.Atoi(value)
					if err != nil || v <= 0 || v > 65535 {
						return cfg, fmt.Errorf("%s:%d: invalid tls proxy port %q", path, lineNo, value)
					}
					rawTLSProxyPort = value
				}
			case "dns_proxy", "dns_resolve_proxy", "dns_socks5":
				switch key {
				case "address":
					rawDNSProxyAddr = value
				case "port":
					v, err := strconv.Atoi(value)
					if err != nil || v <= 0 || v > 65535 {
						return cfg, fmt.Errorf("%s:%d: invalid dns proxy port %q", path, lineNo, value)
					}
					rawDNSProxyPort = value
				}
			case "tls_proxy", "tls_socks5":
				switch key {
				case "address":
					rawTLSProxyAddr = value
				case "port":
					v, err := strconv.Atoi(value)
					if err != nil || v <= 0 || v > 65535 {
						return cfg, fmt.Errorf("%s:%d: invalid tls proxy port %q", path, lineNo, value)
					}
					rawTLSProxyPort = value
				}
			case "fallback", "fallback_dns":
				if key == "address" {
					cfg.FallbackDNS = value
				}
			case "cache":
				switch key {
				case "ttl":
					d, err := time.ParseDuration(value)
					if err != nil || d <= 0 {
						return cfg, fmt.Errorf("%s:%d: invalid cache ttl %q", path, lineNo, value)
					}
					cfg.CacheTTL = d
				}
			case "server":
				switch key {
				case "address":
					cfg.ListenAddr = value
				case "dns_timeout":
					d, err := time.ParseDuration(value)
					if err != nil || d <= 0 {
						return cfg, fmt.Errorf("%s:%d: invalid dns timeout %q", path, lineNo, value)
					}
					cfg.DNSTimeout = d
				case "tls_timeout":
					d, err := time.ParseDuration(value)
					if err != nil || d <= 0 {
						return cfg, fmt.Errorf("%s:%d: invalid tls timeout %q", path, lineNo, value)
					}
					cfg.TLSTimeout = d
				case "tls_port":
					v, err := strconv.Atoi(value)
					if err != nil || v <= 0 || v > 65535 {
						return cfg, fmt.Errorf("%s:%d: invalid tls port %q", path, lineNo, value)
					}
					cfg.TLSPort = v
				case "tls_route":
					if value != "direct" && value != "proxy" {
						return cfg, fmt.Errorf("%s:%d: invalid tls route %q", path, lineNo, value)
					}
					cfg.TLSRoute = value
				case "tls_proxy_port":
					v, err := strconv.Atoi(value)
					if err != nil || v <= 0 || v > 65535 {
						return cfg, fmt.Errorf("%s:%d: invalid tls proxy port %q", path, lineNo, value)
					}
					rawTLSProxyPort = value
				case "tls_proxy", "tls_proxy_address":
					rawTLSProxyAddr = value
				case "dns_proxy_port":
					v, err := strconv.Atoi(value)
					if err != nil || v <= 0 || v > 65535 {
						return cfg, fmt.Errorf("%s:%d: invalid dns proxy port %q", path, lineNo, value)
					}
					rawDNSProxyPort = value
				case "dns_proxy", "dns_proxy_address":
					rawDNSProxyAddr = value
				case "parallel_tests", "max_parallel_tests":
					v, err := strconv.Atoi(value)
					if err != nil || v <= 0 {
						return cfg, fmt.Errorf("%s:%d: invalid parallel_tests %q", path, lineNo, value)
					}
					cfg.MaxParallelTests = v
				case "answer_ttl":
					v, err := strconv.ParseUint(value, 10, 32)
					if err != nil || v <= 0 {
						return cfg, fmt.Errorf("%s:%d: invalid answer_ttl %q", path, lineNo, value)
					}
					cfg.AnswerTTL = uint32(v)
				case "shutdown_timeout":
					d, err := time.ParseDuration(value)
					if err != nil || d <= 0 {
						return cfg, fmt.Errorf("%s:%d: invalid shutdown timeout %q", path, lineNo, value)
					}
					cfg.ShutdownTimeout = d
				case "reachable_hosts":
					cfg.ReachableHostsFile = value
				case "unreachable_hosts":
					cfg.UnreachableHostsFile = value
				case "unreachable_domains_file", "unreachable_domains":
					cfg.UnreachableDomainsFile = value
				case "unreachable_ips_file", "unreachable_ips":
					cfg.UnreachableIPsFile = value
				case "domains_file":
					cfg.DomainsFile = value
				}
			}
		default:
			return cfg, fmt.Errorf("%s:%d: setting outside a known section", path, lineNo)
		}
	}
	if err := scanner.Err(); err != nil {
		return cfg, err
	}

	// If a proxy address was given as just a port (e.g. "1081" or ":1081"), treat it as port
	if p, err := strconv.Atoi(strings.TrimPrefix(rawDNSProxyAddr, ":")); err == nil && p > 0 && p <= 65535 {
		if rawDNSProxyPort == "" {
			rawDNSProxyPort = strconv.Itoa(p)
		}
		rawDNSProxyAddr = ""
	}
	if p, err := strconv.Atoi(strings.TrimPrefix(rawTLSProxyAddr, ":")); err == nil && p > 0 && p <= 65535 {
		if rawTLSProxyPort == "" {
			rawTLSProxyPort = strconv.Itoa(p)
		}
		rawTLSProxyAddr = ""
	}

	// Resolve DNS SOCKS5 address
	dnsBase := defaultSOCKS5Addr
	if rawDNSProxyAddr != "" {
		dnsBase = rawDNSProxyAddr
	} else if rawSOCKS5Addr != "" {
		dnsBase = rawSOCKS5Addr
	}

	if rawDNSProxyPort != "" {
		host, _, err := net.SplitHostPort(dnsBase)
		if err != nil || host == "" {
			host = dnsBase
		}
		if host == "" {
			host = "127.0.0.1"
		}
		cfg.DNSSOCKS5Addr = net.JoinHostPort(host, rawDNSProxyPort)
	} else {
		cfg.DNSSOCKS5Addr = dnsBase
	}
	cfg.SOCKS5Addr = cfg.DNSSOCKS5Addr

	// Resolve TLS SOCKS5 address
	tlsBase := ""
	if rawTLSProxyAddr != "" {
		tlsBase = rawTLSProxyAddr
	} else {
		tlsBase = cfg.DNSSOCKS5Addr
	}

	if rawTLSProxyPort != "" {
		host, _, err := net.SplitHostPort(tlsBase)
		if err != nil || host == "" {
			host = tlsBase
		}
		if host == "" {
			host = "127.0.0.1"
		}
		cfg.TLSSOCKS5Addr = net.JoinHostPort(host, rawTLSProxyPort)
	} else {
		cfg.TLSSOCKS5Addr = tlsBase
	}

	if _, p, err := net.SplitHostPort(cfg.TLSSOCKS5Addr); err == nil {
		if portNum, err := strconv.Atoi(p); err == nil {
			cfg.TLSProxyPort = portNum
		}
	}

	cfg.DirectDNS = cleanList(cfg.DirectDNS)
	cfg.ProxyDNS = cleanList(cfg.ProxyDNS)
	if err := cfg.validate(); err != nil {
		return cfg, err
	}
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
