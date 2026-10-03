package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var (
	hostsMu                   sync.Mutex
	writtenReachable          = make(map[string]bool)
	writtenReachableDomains   = make(map[string]bool)
	writtenReachableIPs       = make(map[string]bool)
	writtenUnreachableDomains = make(map[string]bool)
	writtenUnreachableIPs     = make(map[string]bool)
	pingIPFn                  = pingIP
)

func pingIP(ip string) bool {
	return pingIPContext(context.Background(), ip)
}

func pingIPContext(parent context.Context, ip string) bool {
	return pingIPWithRunner(parent, ip, func(ctx context.Context, ip string) ([]byte, error) {
		return exec.CommandContext(ctx, "ping", pingArgs(ip)...).CombinedOutput()
	})
}

func pingIPWithRunner(parent context.Context, ip string, run func(context.Context, string) ([]byte, error)) bool {
	if ip == "" {
		return false
	}
	for attempt := 1; attempt <= 3; attempt++ {
		if parent.Err() != nil {
			return false
		}
		ctx, cancel := context.WithTimeout(parent, 2*time.Second)
		output, err := run(ctx, ip)
		ctxErr := ctx.Err()
		cancel()
		if err == nil && ctxErr == nil {
			return true
		}
		if parent.Err() != nil {
			return false
		}
		logger.Printf("%s: ICMP attempt %d/3 failed: %v (context=%v); %s", ip, attempt, err, ctxErr, strings.TrimSpace(string(output)))
	}
	return false
}

func appendUniqueLine(path string, value string, seen map[string]bool) {
	if path == "" {
		return
	}

	hostsMu.Lock()
	defer hostsMu.Unlock()
	appendUniqueLineLocked(path, value, seen)
}

func appendUniqueLineLocked(path string, value string, seen map[string]bool) {
	if path == "" {
		return
	}
	key := path + "\x00" + value
	if seen[key] {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.Printf("failed to open hosts file %s: %v", path, err)
		return
	}
	defer f.Close()
	if _, err := fmt.Fprintln(f, value); err != nil {
		logger.Printf("failed to write hosts file %s: %v", path, err)
		return
	}
	seen[key] = true
}

func removeLineLocked(path string, value string, seen map[string]bool) {
	if path == "" {
		return
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Printf("failed to read domains file %s: %v", path, err)
		}
		return
	}

	lines := strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n")
	filtered := lines[:0]
	removed := false
	for _, line := range lines {
		if strings.TrimSuffix(line, "\r") == value {
			removed = true
			continue
		}
		filtered = append(filtered, line)
	}
	if !removed {
		return
	}

	updated := strings.Join(filtered, "\n")
	if updated != "" {
		updated += "\n"
	}
	if err := os.WriteFile(path, []byte(updated), 0644); err != nil {
		logger.Printf("failed to update domains file %s: %v", path, err)
		return
	}
	delete(seen, path+"\x00"+value)
}

func recordHost(path string, domain string, ip string) {
	if path == "" {
		return
	}

	appendUniqueLine(path, ip+" "+domain, writtenReachable)
}

func recordReachableIP(ip string) {
	hostsMu.Lock()
	defer hostsMu.Unlock()
	removeLineLocked(currentConfig.UnreachableIPsFile, ip, writtenUnreachableIPs)
	appendUniqueLineLocked(currentConfig.ReachableIPsFile, ip, writtenReachableIPs)
}

func recordUnreachableIP(ip string) {
	hostsMu.Lock()
	defer hostsMu.Unlock()
	removeLineLocked(currentConfig.ReachableIPsFile, ip, writtenReachableIPs)
	appendUniqueLineLocked(currentConfig.UnreachableIPsFile, ip, writtenUnreachableIPs)
}

func recordReachableDomain(domain string) {
	if domain == "" {
		return
	}
	hostsMu.Lock()
	defer hostsMu.Unlock()
	removeLineLocked(currentConfig.UnreachableDomainsFile, domain, writtenUnreachableDomains)
	appendUniqueLineLocked(currentConfig.ReachableDomainsFile, domain, writtenReachableDomains)
}

func recordReachableHost(domain string, ip string) {
	recordHost(currentConfig.ReachableHostsFile, domain, ip)
	recordReachableDomain(domain)
	recordReachableIP(ip)
}

func recordDomainUnreachable(domain string) {
	if domain == "" {
		return
	}
	hostsMu.Lock()
	defer hostsMu.Unlock()
	removeLineLocked(currentConfig.ReachableDomainsFile, domain, writtenReachableDomains)
	appendUniqueLineLocked(currentConfig.UnreachableDomainsFile, domain, writtenUnreachableDomains)
}
