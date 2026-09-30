package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
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

func loadDomainsFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		re, err := regexp.Compile(line)
		if err != nil {
			return fmt.Errorf("invalid regex in domains file %q: %v", line, err)
		}
		domainRegexes = append(domainRegexes, re)
	}
	return scanner.Err()
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
	if cfg.DomainsFile != "" {
		if err := loadDomainsFile(cfg.DomainsFile); err != nil {
			logger.Fatalf("failed to load domains file: %v", err)
		}
		logger.Printf("loaded %d domain filters from %s", len(domainRegexes), cfg.DomainsFile)
	}

	logger.Printf("starting IPScoutDNS v3")
	logger.Printf("UDP/TCP listen: %s", cfg.ListenAddr)
	logger.Printf("DNS fallback: %s", cfg.FallbackDNS)
	logger.Printf("direct DNS resolvers: %d", len(cfg.DirectDNS))
	logger.Printf("proxy DNS resolvers: %d", len(cfg.ProxyDNS))
	logger.Printf("SOCKS5 proxy: %s", cfg.SOCKS5Addr)
	logger.Printf("cache TTL: %s", cfg.CacheTTL)
	logger.Printf("DNS timeout: %s", cfg.DNSTimeout)
	logger.Printf("TLS timeout: %s", cfg.TLSTimeout)
	logger.Printf("TLS port: %d", cfg.TLSPort)
	logger.Printf("TLS route: %s", cfg.TLSRoute)
	logger.Printf("parallel TLS tests: %d", cfg.MaxParallelTests)
	logger.Printf("answer TTL: %d", cfg.AnswerTTL)
	logger.Printf("shutdown timeout: %s", cfg.ShutdownTimeout)

	handler := dns.HandlerFunc(handleDNS)
	udpServer := &dns.Server{Addr: cfg.ListenAddr, Net: "udp", Handler: handler}
	tcpServer := &dns.Server{Addr: cfg.ListenAddr, Net: "tcp", Handler: handler}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer shutdownCancel()
	_ = shutdownCtx

	if err := udpServer.Shutdown(); err != nil {
		logger.Printf("UDP shutdown error: %v", err)
	}
	if err := tcpServer.Shutdown(); err != nil {
		logger.Printf("TCP shutdown error: %v", err)
	}

	logger.Printf("IPScoutDNS stopped cleanly")
}
