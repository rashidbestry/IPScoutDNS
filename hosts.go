package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

var (
	hostsMu                   sync.Mutex
	writtenReachable          = make(map[string]bool)
	writtenUnreachable        = make(map[string]bool)
	writtenUnreachableDomains = make(map[string]bool)
	writtenUnreachableIPs     = make(map[string]bool)
	resolvedDomains           = make(map[string]bool)
	pingIPFn                  = pingIP
)

func pingIP(ip string) bool {
	if ip == "" {
		return false
	}

	cmdArgs := []string{"-c", "1", "-W", "1", ip}
	if runtime.GOOS == "windows" {
		cmdArgs = []string{"-n", "1", "-w", "1000", ip}
	}

	cmd := exec.Command("ping", cmdArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Printf("ping %s failed: %v (%s)", ip, err, strings.TrimSpace(string(output)))
		return false
	}

	result := strings.ToLower(string(output))
	return strings.Contains(result, "reply from") || strings.Contains(result, "bytes from")
}

func appendUniqueLine(path string, value string, seen map[string]bool) {
	if path == "" {
		return
	}

	key := path + "\x00" + value
	hostsMu.Lock()
	defer hostsMu.Unlock()

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

func markDomainResolved(domain string) {
	if domain == "" {
		return
	}
	hostsMu.Lock()
	defer hostsMu.Unlock()
	resolvedDomains[domain] = true
}

func isDomainResolved(domain string) bool {
	if domain == "" {
		return false
	}
	hostsMu.Lock()
	defer hostsMu.Unlock()
	return resolvedDomains[domain]
}

func recordDomainUnreachable(domain string) {
	if domain == "" || isDomainResolved(domain) {
		return
	}
	if currentConfig.UnreachableDomainsFile != "" {
		appendUniqueLine(currentConfig.UnreachableDomainsFile, domain, writtenUnreachableDomains)
	}
}

func recordUnreachableHost(domain string, ip string) {
	if isDomainResolved(domain) {
		return
	}
	if ip == "" {
		recordDomainUnreachable(domain)
		return
	}
	if pingIPFn(ip) {
		return
	}
	if currentConfig.UnreachableHostsFile != "" {
		recordHost(currentConfig.UnreachableHostsFile, domain, ip, false)
	}
	if currentConfig.UnreachableDomainsFile != "" {
		appendUniqueLine(currentConfig.UnreachableDomainsFile, domain, writtenUnreachableDomains)
	}
	if currentConfig.UnreachableIPsFile != "" {
		appendUniqueLine(currentConfig.UnreachableIPsFile, ip, writtenUnreachableIPs)
	}
}
