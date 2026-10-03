package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Passive inputs are literal ASCII hostnames (use punycode for international names).
// Reject regex syntax, URLs and IP addresses rather than sending them to DNS.
func loadPassiveDomainsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var domains []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		domain := strings.TrimSuffix(strings.ToLower(line), ".")
		if !isLiteralDomain(domain) {
			return nil, fmt.Errorf("%s:%d: invalid literal domain %q; regexes and URLs are not supported in passive mode", path, lineNo, line)
		}
		if !seen[domain] {
			seen[domain] = true
			domains = append(domains, domain)
		}
	}
	return domains, scanner.Err()
}

func isLiteralDomain(domain string) bool {
	if len(domain) > 253 || net.ParseIP(domain) != nil {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

type passiveResolveFunc func(context.Context, string, Config)

func resolvePassiveDomain(ctx context.Context, domain string, cfg Config) {
	resolvePassiveDomainWith(ctx, domain, cfg, queryResolver, testTLS, func(ip string) bool {
		return pingIPContext(ctx, ip)
	})
}

func resolvePassiveDomainWith(ctx context.Context, domain string, cfg Config, query resolverQueryFunc, tlsCheck tlsProbeFunc, pingCheck icmpProbeFunc) {
	// Each scheduled pass performs fresh discovery and probing, regardless of TTL.
	cfg.CacheTTL = 0
	ip, ok, _ := resolveAndSelectWithContext(ctx, domain, cfg, query, tlsCheck, pingCheck)
	if ctx.Err() != nil {
		return
	}
	if ok {
		logger.Printf("%s: WORKING IP = %s", domain, ip)
	} else {
		logger.Printf("%s: NO WORKING IP FOUND", domain)
		recordDomainUnreachable(domain)
	}
}

func runPassive(ctx context.Context, cfg Config) error {
	return runPassiveWith(ctx, cfg, loadPassiveDomainsFile, resolvePassiveDomain, waitPassiveInterval)
}

// Passes never overlap. The interval starts when a complete pass finishes.
// Reloading the file each pass allows list updates without restarting the daemon.
func runPassiveWith(ctx context.Context, cfg Config, load func(string) ([]string, error), resolve passiveResolveFunc, wait func(context.Context, time.Duration) bool) error {
	firstPass := true
	for ctx.Err() == nil {
		domains, err := load(cfg.PassiveDomainsFile)
		if err != nil {
			if firstPass {
				return fmt.Errorf("load passive domains: %w", err)
			}
			logger.Printf("skipping passive pass: %v", err)
		} else {
			logger.Printf("passive pass: %d domains, up to %d parallel resolves", len(domains), cfg.PassiveResolveParallel)
			runPassiveBatch(ctx, domains, cfg, resolve)
			if ctx.Err() == nil {
				logger.Printf("passive pass complete; next pass in %s", cfg.PassiveResolveInterval)
			}
		}
		firstPass = false
		if !wait(ctx, cfg.PassiveResolveInterval) {
			break
		}
	}
	return nil
}

func runPassiveBatch(ctx context.Context, domains []string, cfg Config, resolve passiveResolveFunc) {
	parallel := cfg.PassiveResolveParallel
	if parallel > len(domains) {
		parallel = len(domains)
	}
	jobs := make(chan string)
	var workers sync.WaitGroup
	for i := 0; i < parallel; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for domain := range jobs {
				if ctx.Err() != nil {
					return
				}
				resolve(ctx, domain, cfg)
			}
		}()
	}
dispatch:
	for _, domain := range domains {
		select {
		case jobs <- domain:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobs)
	workers.Wait()
}

func waitPassiveInterval(ctx context.Context, interval time.Duration) bool {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return ctx.Err() == nil
	}
}
