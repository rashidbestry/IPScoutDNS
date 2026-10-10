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
	"time"

	"github.com/miekg/dns"
)

var logger = log.New(os.Stdout, "[ipscoutdns] ", log.LstdFlags)
var currentConfig Config
var domainRegexes []*regexp.Regexp

// Keep the standard log prefix and timestamp, indenting only the message.
// log.Logger serializes writes, including concurrent passive domain workers.
type indentedLogWriter struct {
	output        io.Writer
	messageOffset int
}

func (w indentedLogWriter) Write(p []byte) (int, error) {
	if len(p) < w.messageOffset {
		return w.output.Write(p)
	}
	indented := make([]byte, len(p)+1)
	copy(indented, p[:w.messageOffset])
	indented[w.messageOffset] = '\t'
	copy(indented[w.messageOffset+1:], p[w.messageOffset:])
	n, err := w.output.Write(indented)
	if n > w.messageOffset {
		n-- // The inserted tab is not part of the caller's bytes.
	}
	return n, err
}

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
	if err := prepareRuntimeOutputs(&cfg, cfgPath); err != nil {
		logger.Fatalf("output configuration error: %v", err)
	}
	cfg.savedLog, err = openSavedLog(cfg, time.Now())
	if err != nil {
		logger.Fatalf("log file error: %v", err)
	}
	if cfg.savedLog != nil {
		defer cfg.savedLog.Close()
	}
	logger.SetOutput(loggingOutput(os.Stdout, true, cfg.savedLog))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg.runtimeContext = ctx
	currentConfig = cfg
	if cfg.Mode == "active" {
		if err := loadActiveDomainsFile(cfg.ActiveDomainsFile); err != nil {
			logger.Fatalf("failed to load domains file: %v", err)
		}
	}

	icmpEnabled := cfg.ICMPProbe && cfg.TLSRoute != "proxy"
	logger.Printf("starting IPScoutDNS")
	logger.Printf("- config")
	logger.Printf("\t- mode: %s", cfg.Mode)
	if cfg.Mode == "active" {
		logger.Printf("\t- UDP/TCP listen: %s", cfg.ListenAddr)
		logger.Printf("\t- loaded %d domain filters from %s", len(domainRegexes), cfg.ActiveDomainsFile)
		logger.Printf("\t- Probes enabled: TCP=%t TLS=%t HTTP=%t ICMP=%t", cfg.TCPProbe, cfg.TLSProbe, cfg.HTTPProbe, icmpEnabled)
		logOtherConfigs(cfg)

	} else {
		logger.Printf("\t- passive domains: %s", cfg.PassiveDomainsFile)
		logger.Printf("\t- Probes enabled: TCP=%t TLS=%t HTTP=%t ICMP=%t", cfg.TCPProbe, cfg.TLSProbe, cfg.HTTPProbe, icmpEnabled)
		logOtherConfigs(cfg)
	}
	logger.Printf("")
	logger.Printf("\t- DNS direct resolvers: %d", len(cfg.DirectDNS))
	if len(cfg.DirectDNS) > 0 {
		logger.Printf("\t- DNS direct interface: %s", configuredOrDefault(cfg.DirectDNSInterface))
	}
	if cfg.Mode == "active" {
		logger.Printf("\t- DNS fallback: %s", cfg.FallbackDNS)
		logger.Printf("\t- DNS fallback interface: %s", configuredOrDefault(cfg.FallbackDNSInterface))
	}
	logger.Printf("\t- DNS proxy resolvers: %d", len(cfg.ProxyDNS))
	if len(cfg.ProxyDNS) > 0 {
		logger.Printf("\t- DNS SOCKS5 proxy: %s", cfg.DNSSOCKS5Addr)
	}
	logger.Printf("\t- DNS timeout: %s", cfg.DNSTimeout)
	if cfg.DNSQueryParallel == 0 {
		logger.Printf("\t- DNS query parallel: unlimited (global)")
	} else {
		logger.Printf("\t- DNS query parallel: %d (global)", cfg.DNSQueryParallel)
	}
	logger.Printf("")
	logger.Printf("\t- TCP/TLS/HTTP port: %d/80", cfg.TLSPort)
	logger.Printf("\t- TCP/TLS/HTTP/ICMP route: %s", cfg.TLSRoute)
	if cfg.TLSRoute == "direct" {
		logger.Printf("\t- TCP/TLS/HTTP/ICMP direct interface: %s", configuredOrDefault(cfg.DirectTCPInterface))
		logger.Printf("\t- Direct TCP/TLS/HTTP socket mark: %d (%#x)", cfg.DirectTCPMark, cfg.DirectTCPMark)
	} else if cfg.TLSRoute == "proxy" {
		logger.Printf("\t- TCP/TLS/HTTP SOCKS5 proxy: %s", cfg.TLSSOCKS5Addr)
	}
	logger.Printf("\t- TCP/TLS/HTTP timeout: %s", cfg.TLSTimeout)
	logger.Printf("\t- HTTP early fallback TLS alerts: %d (0 disables)", cfg.HTTPFallbackTLSAlerts)

	// Startup/config logs always appear; only runtime console logs are optional.
	logger.SetOutput(loggingOutput(os.Stdout, cfg.LogsEnabled, cfg.savedLog))

	logger.Printf("- output")
	logger.SetOutput(indentedLogWriter{
		output:        logger.Writer(),
		messageOffset: len(logger.Prefix()) + len("2006/01/02 15:04:05 "),
	})
	if cfg.Mode == "passive" {
		if err := runPassive(ctx, cfg); err != nil {
			logger.Fatalf("passive mode: %v", err)
		}
	} else {
		runActive(ctx, cfg)
	}
	finishLogging(cfg)
}

func logOtherConfigs(cfg Config) {
	var modeSettings string
	if cfg.Mode == "active" {
		modeSettings = fmt.Sprintf("ttl=%s answer_ttl=%d", cfg.CacheTTL, cfg.AnswerTTL)
		if cfg.runtimeCopiesEnabled {
			modeSettings += fmt.Sprintf(" active_copy_interval=%s active_log_copy_interval=%s", cfg.ActiveCopyInterval, cfg.ActiveLogCopyInterval)
		}
	} else {
		modeSettings = fmt.Sprintf("passive_resolve_time=%q passive_resolve_interval=%s passive_resolve_parallel=%d", cfg.PassiveResolveTime, cfg.PassiveResolveInterval, cfg.PassiveResolveParallel)
	}
	logger.Printf("\t- Other configs: %s logs_enabled=%t save_logs=%t log_max_size=%dB log_keep_files=%d parallel_tests=%d hosts_max_ips_per_domain=%d reachable_hosts=%q reachable_domains_file=%q reachable_ips_file=%q unreachable_domains_file=%q unreachable_ips_file=%q",
		modeSettings, cfg.LogsEnabled, cfg.SaveLogs, cfg.LogMaxSize, cfg.LogKeepFiles, cfg.MaxParallelTests, cfg.HostsMaxIPsPerDomain,
		cfg.ReachableHostsFile, cfg.ReachableDomainsFile, cfg.ReachableIPsFile, cfg.UnreachableDomainsFile, cfg.UnreachableIPsFile)
}

func runActive(ctx context.Context, cfg Config) {
	logCopiesDone := make(chan struct{})
	if !cfg.SaveLogs || !cfg.runtimeCopiesEnabled || cfg.savedLog == nil {
		close(logCopiesDone)
	} else {
		go func() {
			defer close(logCopiesDone)
			runActiveLogCopies(ctx, cfg.ActiveLogCopyInterval, func(ctx context.Context) error {
				return copyRuntimeLog(ctx, cfg, logDestinationDirectory)
			}, waitPassiveInterval)
		}()
	}
	copiesDone := make(chan struct{})
	if !cfg.runtimeCopiesEnabled {
		close(copiesDone)
	} else {
		go func() {
			defer close(copiesDone)
			runActiveOutputCopies(ctx, cfg.ActiveCopyInterval, func(ctx context.Context) error {
				return copyRuntimeOutputs(ctx, cfg, outputDestinationDirectory)
			}, waitPassiveInterval)
		}()
	}
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
	<-copiesDone
	<-logCopiesDone
}

func configuredOrDefault(value string) string {
	if strings.TrimSpace(value) == "" {
		return "system default"
	}
	return value
}
