package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	defaultConfigPath  = "/etc/ipscoutdns.conf"
	priorityConfigPath = "ipscoutdns.conf"

	defaultListenAddr      = "127.0.0.1:5354"
	defaultFallbackDNS     = "127.0.0.1:53053"
	defaultSOCKS5Addr      = "127.0.0.1:1080"
	defaultTLSSOCKS5Addr   = "127.0.0.1:1080"
	defaultCacheTTL        = 24 * time.Hour
	defaultDNSTimeout      = 3 * time.Second
	defaultTLSTimeout      = 3 * time.Second
	defaultTLSPort         = 443
	defaultTLSRoute        = "direct"
	defaultMaxParallel     = 16
	defaultAnswerTTL       = uint32(300)
	defaultResolveInterval = 24 * time.Hour
	defaultResolveParallel = 16
)

type Config struct {
	Mode                   string
	ActiveDomainsFile      string
	PassiveDomainsFile     string
	ResolveInterval        time.Duration
	ResolveParallel        int
	DirectDNS              []string
	ProxyDNS               []string
	ListenAddr             string
	FallbackDNS            string
	SOCKS5Addr             string // legacy alias for DNSSOCKS5Addr
	DNSSOCKS5Addr          string // SOCKS5 proxy used for DNS resolvers
	DirectDNSInterface     string // local interface name or source IP for direct DNS
	FallbackDNSInterface   string // local interface name or source IP for fallback DNS
	DirectTCPInterface     string // local interface name or source IP for direct reachability checks
	TLSSOCKS5Addr          string // SOCKS5 proxy used for reachability checks
	TLSProxyPort           int
	CacheTTL               time.Duration
	DNSTimeout             time.Duration
	TLSTimeout             time.Duration
	TLSPort                int
	TLSRoute               string
	MaxParallelTests       int
	LogsEnabled            bool
	AnswerTTL              uint32
	ReachableHostsFile     string
	ReachableDomainsFile   string
	ReachableIPsFile       string
	UnreachableDomainsFile string
	UnreachableIPsFile     string
}

func (c Config) validate() error {
	return c.validateWithInterfaceValidator(validateInterfaceSelector)
}

func (c Config) validateWithInterfaceValidator(validateInterface func(string) error) error {
	if c.Mode != "active" && c.Mode != "passive" {
		return fmt.Errorf("mode is required and must be active or passive")
	}
	if len(c.DirectDNS) == 0 && len(c.ProxyDNS) == 0 {
		return fmt.Errorf("at least one upstream resolver is required: direct_dns or proxy_dns")
	}
	if c.Mode == "active" {
		if strings.TrimSpace(c.ActiveDomainsFile) == "" {
			return fmt.Errorf("active_domains_file is required in active mode")
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
	} else {
		if strings.TrimSpace(c.PassiveDomainsFile) == "" {
			return fmt.Errorf("passive_domains_file is required in passive mode")
		}
		if c.ResolveInterval <= 0 {
			return fmt.Errorf("resolve_interval must be greater than zero")
		}
		if c.ResolveParallel <= 0 {
			return fmt.Errorf("resolve_parallel must be greater than zero")
		}
	}
	if strings.TrimSpace(c.DNSSOCKS5Addr) != "" {
		if _, _, err := net.SplitHostPort(c.DNSSOCKS5Addr); err != nil {
			return fmt.Errorf("socks5 address must be host:port: %w", err)
		}
	}
	if strings.TrimSpace(c.TLSSOCKS5Addr) != "" {
		if _, _, err := net.SplitHostPort(c.TLSSOCKS5Addr); err != nil {
			return fmt.Errorf("tcp socks5 address must be host:port: %w", err)
		}
	}
	if err := validateInterface(c.DirectDNSInterface); err != nil {
		return fmt.Errorf("direct_dns_interface: %w", err)
	}
	if c.Mode == "active" {
		if err := validateInterface(c.FallbackDNSInterface); err != nil {
			return fmt.Errorf("fallback_dns_interface: %w", err)
		}
	}
	if err := validateInterfaceSelector(c.DirectTCPInterface); err != nil {
		return fmt.Errorf("server.direct_tcp_interface: %w", err)
	}
	if c.CacheTTL <= 0 {
		return fmt.Errorf("cache.ttl must be greater than zero")
	}
	if c.DNSTimeout <= 0 {
		return fmt.Errorf("server.dns_timeout must be greater than zero")
	}
	if c.TLSTimeout <= 0 {
		return fmt.Errorf("server.tcp_timeout must be greater than zero")
	}
	if c.TLSPort <= 0 || c.TLSPort > 65535 {
		return fmt.Errorf("server.tcp_port must be a valid port number")
	}
	if c.TLSRoute != "direct" && c.TLSRoute != "proxy" {
		return fmt.Errorf("server.tcp_route must be direct or proxy")
	}
	if c.TLSRoute == "proxy" && strings.TrimSpace(c.TLSSOCKS5Addr) == "" {
		return fmt.Errorf("server.tcp_route is proxy but tcp socks5 address is empty")
	}
	if c.MaxParallelTests <= 0 {
		return fmt.Errorf("server.parallel_tests must be greater than zero")
	}
	if c.AnswerTTL <= 0 {
		return fmt.Errorf("server.answer_ttl must be greater than zero")
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
	userConfigDir, _ := os.UserConfigDir()
	return resolveConfigPathWith(
		strings.TrimSpace(os.Getenv("IPSCOUTDNS_CONFIG")),
		strings.TrimSpace(os.Getenv("IPSELECTOR_CONFIG")),
		priorityConfigPath,
		defaultConfigPath,
		runtime.GOOS,
		userConfigDir,
		func(path string) bool {
			_, err := os.Stat(path)
			return err == nil
		},
	)
}

func resolveConfigPathWith(configOverride string, legacyOverride string, localPath string, systemPath string, goos string, userConfigDir string, exists func(string) bool) string {
	if configOverride != "" {
		return configOverride
	}
	if legacyOverride != "" {
		return legacyOverride
	}
	if exists(localPath) {
		return localPath
	}
	if goos != "windows" && exists(systemPath) {
		return systemPath
	}
	if goos == "windows" {
		if userConfigDir == "" {
			return localPath
		}
		userConfigPath := filepath.Join(userConfigDir, "IPScoutDNS", "ipscoutdns.conf")
		return userConfigPath
	}
	return systemPath
}

func parseFlatList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	raw = strings.Trim(raw, "{}")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		item = strings.Trim(item, "\"'")
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	return out
}

func loadConfig(path string) (Config, error) {
	return loadConfigWithInterfaceValidator(path, validateInterfaceSelector)
}

func loadConfigWithInterfaceValidator(path string, validateInterface func(string) error) (Config, error) {
	cfg := Config{
		ResolveInterval:  defaultResolveInterval,
		ResolveParallel:  defaultResolveParallel,
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
		LogsEnabled:      true,
		AnswerTTL:        defaultAnswerTTL,
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
		currentListKey  string
	)

	addListValue := func(key, value string) {
		for _, item := range parseFlatList(value) {
			switch key {
			case "direct_dns":
				cfg.DirectDNS = append(cfg.DirectDNS, item)
			case "proxy_dns":
				cfg.ProxyDNS = append(cfg.ProxyDNS, item)
			}
		}
	}

	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if !strings.Contains(line, "=") && !strings.Contains(line, "{") && !strings.Contains(line, "}") {
			hasOnlyDecorText := true
			for _, r := range line {
				if unicode.IsLetter(r) || unicode.IsSpace(r) || r == '-' || r == '_' || r == '/' || r == '.' {
					continue
				}
				hasOnlyDecorText = false
				break
			}
			if hasOnlyDecorText {
				continue
			}
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			return cfg, fmt.Errorf("%s:%d: flat config only; section headers are not supported", path, lineNo)
		}
		if currentListKey != "" {
			if line == "}" {
				currentListKey = ""
				continue
			}
			addListValue(currentListKey, line)
			continue
		}
		if key, value, ok := strings.Cut(line, "="); ok {
			key = strings.ToLower(strings.TrimSpace(key))
			value = strings.TrimSpace(value)
			switch key {
			case "mode":
				if cfg.Mode != "" {
					return cfg, fmt.Errorf("%s:%d: mode must be specified only once", path, lineNo)
				}
				if value != "active" && value != "passive" {
					return cfg, fmt.Errorf("%s:%d: mode must be active or passive", path, lineNo)
				}
				cfg.Mode = value
			case "active_domains_file":
				cfg.ActiveDomainsFile = value
			case "passive_domains_file":
				cfg.PassiveDomainsFile = value
			case "resolve_interval":
				d, err := time.ParseDuration(value)
				if err != nil || d <= 0 {
					return cfg, fmt.Errorf("%s:%d: invalid resolve_interval %q", path, lineNo, value)
				}
				cfg.ResolveInterval = d
			case "resolve_parallel":
				v, err := strconv.Atoi(value)
				if err != nil || v <= 0 {
					return cfg, fmt.Errorf("%s:%d: invalid resolve_parallel %q", path, lineNo, value)
				}
				cfg.ResolveParallel = v
			case "server", "address", "listen":
				cfg.ListenAddr = value
			case "logs_enabled":
				enabled, err := strconv.ParseBool(value)
				if err != nil {
					return cfg, fmt.Errorf("%s:%d: invalid logs_enabled value %q", path, lineNo, value)
				}
				cfg.LogsEnabled = enabled
			case "ttl":
				d, err := time.ParseDuration(value)
				if err != nil || d <= 0 {
					return cfg, fmt.Errorf("%s:%d: invalid cache ttl %q", path, lineNo, value)
				}
				cfg.CacheTTL = d
			case "direct_dns":
				if value == "{" {
					currentListKey = "direct_dns"
					continue
				}
				inner := strings.TrimSpace(value)
				if strings.HasPrefix(inner, "{") {
					inner = strings.TrimPrefix(inner, "{")
					if strings.HasSuffix(inner, "}") {
						inner = strings.TrimSuffix(inner, "}")
					}
					if inner == "" {
						currentListKey = "direct_dns"
						continue
					}
					addListValue(key, inner)
					if strings.HasSuffix(value, "}") {
						continue
					}
					currentListKey = "direct_dns"
					continue
				}
				addListValue(key, value)
			case "proxy_dns":
				if value == "{" {
					currentListKey = "proxy_dns"
					continue
				}
				inner := strings.TrimSpace(value)
				if strings.HasPrefix(inner, "{") {
					inner = strings.TrimPrefix(inner, "{")
					if strings.HasSuffix(inner, "}") {
						inner = strings.TrimSuffix(inner, "}")
					}
					if inner == "" {
						currentListKey = "proxy_dns"
						continue
					}
					addListValue(key, inner)
					if strings.HasSuffix(value, "}") {
						continue
					}
					currentListKey = "proxy_dns"
					continue
				}
				addListValue(key, value)
			case "direct_dns_interface", "dns_interface":
				cfg.DirectDNSInterface = value
			case "direct_tcp_interface":
				cfg.DirectTCPInterface = value
			case "fallback_dns_interface", "fallback_interface":
				cfg.FallbackDNSInterface = value
			case "fallback_dns":
				cfg.FallbackDNS = value
			case "dns_timeout":
				d, err := time.ParseDuration(value)
				if err != nil || d <= 0 {
					return cfg, fmt.Errorf("%s:%d: invalid dns timeout %q", path, lineNo, value)
				}
				cfg.DNSTimeout = d
			case "tcp_timeout", "tls_timeout":
				d, err := time.ParseDuration(value)
				if err != nil || d <= 0 {
					return cfg, fmt.Errorf("%s:%d: invalid tcp timeout %q", path, lineNo, value)
				}
				cfg.TLSTimeout = d
			case "tcp_port", "tls_port":
				v, err := strconv.Atoi(value)
				if err != nil || v <= 0 || v > 65535 {
					return cfg, fmt.Errorf("%s:%d: invalid tcp port %q", path, lineNo, value)
				}
				cfg.TLSPort = v
			case "tcp_route", "tls_route":
				if value != "direct" && value != "proxy" {
					return cfg, fmt.Errorf("%s:%d: invalid tcp route %q", path, lineNo, value)
				}
				cfg.TLSRoute = value
			case "tcp_proxy", "tcp_proxy_address", "tls_proxy", "tls_proxy_address":
				rawTLSProxyAddr = value
			case "tcp_proxy_port", "tls_proxy_port":
				v, err := strconv.Atoi(value)
				if err != nil || v <= 0 || v > 65535 {
					return cfg, fmt.Errorf("%s:%d: invalid tcp proxy port %q", path, lineNo, value)
				}
				rawTLSProxyPort = value
			case "proxy_dns_address", "dns_proxy_address", "dns_proxy", "dns_socks5":
				rawDNSProxyAddr = value
			case "proxy_dns_port", "dns_proxy_port":
				v, err := strconv.Atoi(value)
				if err != nil || v <= 0 || v > 65535 {
					return cfg, fmt.Errorf("%s:%d: invalid dns proxy port %q", path, lineNo, value)
				}
				rawDNSProxyPort = value
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
			case "domains_file":
				return cfg, fmt.Errorf("%s:%d: domains_file was removed; use active_domains_file or passive_domains_file", path, lineNo)
			case "reachable_hosts":
				cfg.ReachableHostsFile = value
			case "reachable_domains_file", "reachable_domains":
				cfg.ReachableDomainsFile = value
			case "reachable_ips_file", "reachable_ips":
				cfg.ReachableIPsFile = value
			case "unreachable_domains_file", "unreachable_domains":
				cfg.UnreachableDomainsFile = value
			case "unreachable_ips_file", "unreachable_ips":
				cfg.UnreachableIPsFile = value
			default:
				return cfg, fmt.Errorf("%s:%d: unsupported setting %q", path, lineNo, key)
			}
			continue
		}
		return cfg, fmt.Errorf("%s:%d: invalid flat config line: %q", path, lineNo, line)
	}
	if err := scanner.Err(); err != nil {
		return cfg, err
	}

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
	if err := cfg.validateWithInterfaceValidator(validateInterface); err != nil {
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
