package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
)

var (
	hostsMu                   sync.Mutex
	writtenReachable          = make(map[string]bool)
	writtenReachableDomains   = make(map[string]bool)
	writtenReachableIPs       = make(map[string]bool)
	writtenUnreachable        = make(map[string]bool)
	writtenUnreachableDomains = make(map[string]bool)
	writtenUnreachableIPs     = make(map[string]bool)
	resolvedDomains           = make(map[string]bool)
)

func appendUniqueLine(path string, value string, seen map[string]bool) {
	if path == "" {
		return
	}

	hostsMu.Lock()
	defer hostsMu.Unlock()
	appendUniqueLineLocked(path, value, seen)
}

func appendUniqueLineLocked(path string, value string, seen map[string]bool) {
	key := path + "\x00" + value
	if seen[key] {
		return
	}
	seen[key] = true

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.Printf("failed to open hosts file %s: %v", path, err)
		return
	}
	defer f.Close()
	fmt.Fprintln(f, value)
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

func recordHost(path string, domain string, ip string, isReachable bool) {
	if path == "" {
		return
	}

	key := ip + " " + domain
	hostsMu.Lock()
	defer hostsMu.Unlock()

	if isReachable {
		if writtenReachable[key] {
			return
		}
		writtenReachable[key] = true
	} else {
		if writtenUnreachable[key] {
			return
		}
		writtenUnreachable[key] = true
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.Printf("failed to open hosts file %s: %v", path, err)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", ip, domain)
}

func recordReachableHost(domain string, ip string) {
	hostsMu.Lock()
	resolvedDomains[domain] = true
	removeLineLocked(currentConfig.UnreachableDomainsFile, domain, writtenUnreachableDomains)
	hostsMu.Unlock()

	recordHost(currentConfig.ReachableHostsFile, domain, ip, true)
	if currentConfig.ReachableDomainsFile != "" {
		appendUniqueLine(currentConfig.ReachableDomainsFile, domain, writtenReachableDomains)
	}
	if currentConfig.ReachableIPsFile != "" {
		appendUniqueLine(currentConfig.ReachableIPsFile, ip, writtenReachableIPs)
	}
}

func recordDomainUnreachable(domain string) {
	if domain == "" {
		return
	}
	hostsMu.Lock()
	defer hostsMu.Unlock()
	if resolvedDomains[domain] {
		return
	}
	appendUniqueLineLocked(currentConfig.UnreachableDomainsFile, domain, writtenUnreachableDomains)
}

func recordUnreachableHost(ctx context.Context, domain string, ip string) {
	if ctx.Err() != nil {
		return
	}
	if currentConfig.UnreachableHostsFile != "" {
		recordHost(currentConfig.UnreachableHostsFile, domain, ip, false)
	}
	if currentConfig.UnreachableIPsFile != "" {
		appendUniqueLine(currentConfig.UnreachableIPsFile, ip, writtenUnreachableIPs)
	}
}
