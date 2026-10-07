package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
	resolvePassiveDomainWithProbes(ctx, domain, cfg, query, tlsCheck, testHTTP, pingCheck)
}

func resolvePassiveDomainWithProbes(ctx context.Context, domain string, cfg Config, query resolverQueryFunc, tlsCheck tlsProbeFunc, httpCheck httpProbeFunc, pingCheck icmpProbeFunc) {
	// Each scheduled pass performs fresh discovery and probing, regardless of TTL.
	cfg.CacheTTL = 0
	_, ok, _ := resolveAndSelectWithProbes(ctx, domain, cfg, query, tlsCheck, httpCheck, pingCheck)
	if ctx.Err() != nil {
		return
	}
	if !ok {
		logger.Printf("%s: NO WORKING IP FOUND", domain)
	}
}

func runPassive(ctx context.Context, cfg Config) error {
	return runPassiveWithLogs(ctx, cfg, loadPassiveDomainsFile, resolvePassiveDomain, waitPassiveInterval, func() error {
		if cfg.outputDirectoryShared {
			return clearPassiveOutputFiles(cfg.outputFiles())
		}
		return clearPassiveOutputDirectory(cfg.outputDirectory)
	}, func(ctx context.Context) error { return copyRuntimeOutputs(ctx, cfg, outputDestinationDirectory) },
		func(ctx context.Context) error {
			return copyRuntimeLog(ctx, cfg, filepath.Join(outputDestinationDirectory, "logs"))
		})
}

// Passes never overlap. The interval starts when a complete pass finishes.
// Reloading the file each pass allows list updates without restarting the daemon.
func runPassiveWith(ctx context.Context, cfg Config, load func(string) ([]string, error), resolve passiveResolveFunc, wait func(context.Context, time.Duration) bool) error {
	return runPassiveWithCleanup(ctx, cfg, load, resolve, wait, func() error { return nil })
}

func runPassiveWithCleanup(ctx context.Context, cfg Config, load func(string) ([]string, error), resolve passiveResolveFunc, wait func(context.Context, time.Duration) bool, cleanup func() error) error {
	return runPassiveWithOutputs(ctx, cfg, load, resolve, wait, cleanup, func(context.Context) error { return nil })
}

func runPassiveWithOutputs(ctx context.Context, cfg Config, load func(string) ([]string, error), resolve passiveResolveFunc, wait func(context.Context, time.Duration) bool, cleanup func() error, copyOutputs func(context.Context) error) error {
	return runPassiveWithLogs(ctx, cfg, load, resolve, wait, cleanup, copyOutputs, func(context.Context) error { return nil })
}

func runPassiveWithLogs(ctx context.Context, cfg Config, load func(string) ([]string, error), resolve passiveResolveFunc, wait func(context.Context, time.Duration) bool, cleanup func() error, copyOutputs func(context.Context) error, copyLog func(context.Context) error) error {
	firstPass := true
	if cfg.PassiveResolveTime != "" {
		next := nextPassiveResolveTime(time.Now(), cfg.PassiveResolveTime)
		logger.Printf("next passive pass at %s", next.Format(time.RFC3339))
		if !wait(ctx, time.Until(next)) {
			return nil
		}
	}
	for ctx.Err() == nil {
		completedPass := false
		domains, err := load(cfg.PassiveDomainsFile)
		if err != nil {
			if firstPass {
				return fmt.Errorf("load passive domains: %w", err)
			}
			logger.Printf("skipping passive pass: %v", err)
		} else {
			if ctx.Err() != nil {
				return nil
			}
			if err := cleanup(); err != nil {
				return fmt.Errorf("clear passive output directory: %w", err)
			}
			logger.Printf("passive pass: %d domains, up to %d parallel resolves", len(domains), cfg.PassiveResolveParallel)
			runPassiveBatch(ctx, domains, cfg, resolve)
			if ctx.Err() != nil {
				return nil
			}
			if err := copyOutputs(ctx); err != nil && ctx.Err() == nil {
				logger.Printf("failed to copy passive outputs: %v", err)
			}
			if ctx.Err() == nil && cfg.PassiveResolveTime == "" {
				logger.Printf("passive pass complete; next pass in %s", cfg.PassiveResolveInterval)
			}
			completedPass = ctx.Err() == nil
		}
		firstPass = false
		delay := cfg.PassiveResolveInterval
		if cfg.PassiveResolveTime != "" {
			next := nextPassiveResolveTime(time.Now(), cfg.PassiveResolveTime)
			logger.Printf("next passive pass at %s", next.Format(time.RFC3339))
			delay = time.Until(next)
		}
		if completedPass {
			if err := copyLog(ctx); err != nil && ctx.Err() == nil {
				logger.Printf("failed to copy passive log: %v", err)
			}
		}
		if !wait(ctx, delay) {
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

func nextPassiveResolveTime(now time.Time, clock string) time.Time {
	t, _ := time.Parse("15:04", clock)
	next := time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), 0, 0, now.Location())
	if !next.After(now) {
		next = time.Date(now.Year(), now.Month(), now.Day()+1, t.Hour(), t.Minute(), 0, 0, now.Location())
	}
	return next
}

// A shared executable directory must only lose configured output files.
func clearPassiveOutputFiles(paths []string) error {
	hostsMu.Lock()
	defer hostsMu.Unlock()
	for _, path := range paths {
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("output %s must be a regular file", path)
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	for _, seen := range []map[string]bool{writtenReachable, writtenReachableDomains, writtenReachableIPs, writtenUnreachableDomains, writtenUnreachableIPs} {
		for key := range seen {
			path, _, _ := strings.Cut(key, "\x00")
			for _, output := range paths {
				if path == output {
					delete(seen, key)
					break
				}
			}
		}
	}
	return nil
}

func clearPassiveOutputDirectory(dir string) error {
	hostsMu.Lock()
	defer hostsMu.Unlock()
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s must be a real directory", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Type().IsRegular() && isSavedLogName(entry.Name()) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	for _, seen := range []map[string]bool{writtenReachable, writtenReachableDomains, writtenReachableIPs, writtenUnreachableDomains, writtenUnreachableIPs} {
		for key := range seen {
			path, _, _ := strings.Cut(key, "\x00")
			rel, err := filepath.Rel(dir, path)
			if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				delete(seen, key)
			}
		}
	}
	return nil
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
