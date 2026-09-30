package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const (
	defaultConfigPath = "/etc/ipscoutdns.conf"
	legacyConfigPath  = "/etc/ipselector.conf"

	defaultListenAddr = "127.0.0.1:5354"
	defaultAdguardDNS = "127.0.0.1:53053"
	defaultSOCKS5Addr = "127.0.0.1:1080"
	defaultCacheTTL   = 24 * time.Hour
)

type Config struct {
	DirectDNS  []string
	ProxyDNS   []string
	ListenAddr string
	AdguardDNS string
	SOCKS5Addr string
	CacheTTL   time.Duration
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
	if strings.TrimSpace(c.AdguardDNS) == "" {
		return fmt.Errorf("adguard.address cannot be empty")
	}
	if _, _, err := net.SplitHostPort(c.AdguardDNS); err != nil {
		return fmt.Errorf("adguard.address must be host:port: %w", err)
	}
	if strings.TrimSpace(c.SOCKS5Addr) != "" {
		if _, _, err := net.SplitHostPort(c.SOCKS5Addr); err != nil {
			return fmt.Errorf("socks5 address must be host:port: %w", err)
		}
	}
	if c.CacheTTL <= 0 {
		return fmt.Errorf("cache.ttl must be greater than zero")
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
	if _, err := os.Stat(defaultConfigPath); err == nil {
		return defaultConfigPath
	}
	if _, err := os.Stat(legacyConfigPath); err == nil {
		return legacyConfigPath
	}
	return defaultConfigPath
}

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
