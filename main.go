package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"github.com/miekg/dns"
)

var logger = log.New(os.Stdout, "[ipscoutdns] ", log.LstdFlags)
var currentConfig Config
var domainRegexes []*regexp.Regexp

func loadActiveDomainsFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var patterns []*regexp.Regexp
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		re, err := regexp.Compile(line)
		if err != nil {
			return fmt.Errorf("invalid regex in domains file %q: %v", line, err)
		}
		patterns = append(patterns, re)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	domainRegexes = patterns
	return nil
}

func main() {
	cfgPath := resolveConfigPath()
	flag.StringVar(&cfgPath, "config", cfgPath, "path to config file")
	flag.Parse()

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		logger.Fatalf("configuration error: %v", err)
	}

	currentConfig = cfg
	if cfg.Mode == "active" {
		if err := loadActiveDomainsFile(cfg.ActiveDomainsFile); err != nil {
			logger.Fatalf("failed to load domains file: %v", err)
		}
	}

	logger.Printf("starting IPScoutDNS v3")
	logger.Printf("mode: %s", cfg.Mode)
	if cfg.Mode == "active" {
		logger.Printf("UDP/TCP listen: %s", cfg.ListenAddr)
		logger.Printf("DNS fallback: %s", cfg.FallbackDNS)
		logger.Printf("fallback DNS interface: %s", configuredOrDefault(cfg.FallbackDNSInterface))
		logger.Printf("loaded %d domain filters from %s", len(domainRegexes), cfg.ActiveDomainsFile)
	} else {
		logger.Printf("passive domains: %s", cfg.PassiveDomainsFile)
		logger.Printf("resolve interval: %s; parallel domains: %d", cfg.PassiveResolveInterval, cfg.PassiveResolveParallel)
	}
	logger.Printf("direct DNS resolvers: %d", len(cfg.DirectDNS))
	logger.Printf("proxy DNS resolvers: %d", len(cfg.ProxyDNS))
	logger.Printf("DNS SOCKS5 proxy: %s", cfg.DNSSOCKS5Addr)
	logger.Printf("direct DNS interface: %s", configuredOrDefault(cfg.DirectDNSInterface))
	if cfg.Mode == "active" {
		logger.Printf("cache TTL: %s", cfg.CacheTTL)
		logger.Printf("answer TTL: %d", cfg.AnswerTTL)
	}
	logger.Printf("DNS timeout: %s", cfg.DNSTimeout)
	logger.Printf("TLS timeout: %s", cfg.TLSTimeout)
	logger.Printf("TLS port: %d", cfg.TLSPort)
	logger.Printf("TLS route: %s", cfg.TLSRoute)
	if cfg.TLSRoute == "direct" {
		logger.Printf("direct TCP interface: %s", configuredOrDefault(cfg.DirectTCPInterface))
	}
	logger.Printf("TLS SOCKS5 proxy: %s", cfg.TLSSOCKS5Addr)
	logger.Printf("parallel TLS tests: %d", cfg.MaxParallelTests)
	if !cfg.LogsEnabled {
		logger.SetOutput(io.Discard)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cfg.Mode == "passive" {
		if err := runPassive(ctx, cfg); err != nil {
			logger.Fatalf("passive mode: %v", err)
		}
	} else {
		runActive(ctx, cfg)
	}
	logger.Printf("IPScoutDNS stopped cleanly")
}

func runActive(ctx context.Context, cfg Config) {
	handler := dns.HandlerFunc(handleDNS)
	udpServer := &dns.Server{Addr: cfg.ListenAddr, Net: "udp", Handler: handler}
	tcpServer := &dns.Server{Addr: cfg.ListenAddr, Net: "tcp", Handler: handler}

	go func() {
		if err := udpServer.ListenAndServe(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			logger.Printf("UDP server failed: %v", err)
		}
	}()
	go func() {
		if err := tcpServer.ListenAndServe(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			logger.Printf("TCP server failed: %v", err)
		}
	}()

	logger.Printf("UDP DNS listening on %s", cfg.ListenAddr)
	logger.Printf("TCP DNS listening on %s", cfg.ListenAddr)

	<-ctx.Done()
	logger.Printf("shutdown signal received, stopping DNS servers")

	if err := udpServer.Shutdown(); err != nil {
		logger.Printf("UDP shutdown error: %v", err)
	}
	if err := tcpServer.Shutdown(); err != nil {
		logger.Printf("TCP shutdown error: %v", err)
	}
}

func configuredOrDefault(value string) string {
	if strings.TrimSpace(value) == "" {
		return "system default"
	}
	return value
}
