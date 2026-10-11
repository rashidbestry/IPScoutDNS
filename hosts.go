package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var (
	hostsMu          sync.Mutex
	writtenReachable = make(map[string]bool)
	pingIPFn         = pingIPContext
)

func pingProbe(parent context.Context, cfg Config) icmpProbeFunc {
	return func(ip string) bool {
		return pingIPFn(parent, ip, cfg.DirectTCPInterface)
	}
}

func pingIPContext(parent context.Context, ip string, interfaceSelector string) bool {
	return pingIPWithRunner(parent, ip, func(ctx context.Context, ip string) ([]byte, error) {
		args, err := pingArgs(ip, interfaceSelector)
		if err != nil {
			return nil, err
		}
		return exec.CommandContext(ctx, "ping", args...).CombinedOutput()
	})
}

func pingIPWithRunner(parent context.Context, ip string, run func(context.Context, string) ([]byte, error)) bool {
	if ip == "" || parent.Err() != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	output, err := run(ctx, ip)
	ctxErr := ctx.Err()
	cancel()
	if err == nil && ctxErr == nil {
		return true
	}
	if parent.Err() == nil && !compactProbeLogs(parent) {
		reason := fmt.Sprint(err)
		text := strings.TrimSpace(string(output))
		if ctxErr != nil {
			reason = ctxErr.Error()
		} else {
			// Retain command diagnostics without the ping banner or statistics.
			diagnostic := ""
			for _, line := range strings.Split(text, "\n") {
				line = strings.TrimSpace(line)
				lower := strings.ToLower(line)
				if line == "" || strings.HasPrefix(lower, "ping ") || strings.HasPrefix(lower, "pinging ") || strings.HasPrefix(line, "---") || strings.Contains(lower, "packets transmitted") || strings.HasPrefix(lower, "packets:") || lower == "request timed out." {
					continue
				}
				diagnostic = line
				break
			}
			if diagnostic != "" {
				reason += "; " + diagnostic
			} else if strings.Contains(text, "0 packets received") || strings.Contains(text, "Received = 0") || text == "Request timed out." {
				reason = "no reply"
			}
		}
		logger.Printf("%s: ICMP probe failed: %s", ip, strings.Join(strings.Fields(reason), " "))
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
	f, err := openHostsFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY)
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

func recordHost(path string, domain string, ip string) {
	if path == "" || !isLiteralDomain(domain) {
		return
	}

	appendUniqueLine(path, ip+" "+domain, writtenReachable)
}

func recordReachableIP(ip string) {
	recordStatus(currentConfig.ReachableIPsFile, currentConfig.UnreachableIPsFile, ip)
}

func recordUnreachableIP(ip string) {
	recordStatus(currentConfig.UnreachableIPsFile, currentConfig.ReachableIPsFile, ip)
}

func recordReachableDomain(domain string) {
	recordStatus(currentConfig.ReachableDomainsFile, currentConfig.UnreachableDomainsFile, domain)
}

func recordReachableHost(domain string, ip string) {
	recordHost(currentConfig.ReachableHostsFile, domain, ip)
	recordReachableDomain(domain)
	recordReachableIP(ip)
}

// Refresh only this domain's mappings while preserving other domain outputs.
// Cache hits retain existing candidates within the limit; fresh checks replace them.
// The mutex also protects concurrent Active requests and Passive domain jobs.
func updateReachableHosts(domain string, ips []string, limit int, keepExisting bool) {
	path := currentConfig.ReachableHostsFile
	if path == "" || !isLiteralDomain(domain) {
		return
	}
	hostsMu.Lock()
	defer hostsMu.Unlock()
	f, err := openHostsFile(path, os.O_RDWR|os.O_CREATE)
	if err != nil {
		logger.Printf("failed to open hosts file %s: %v", path, err)
		return
	}
	defer f.Close()
	contents, err := io.ReadAll(f)
	if err != nil {
		logger.Printf("failed to read hosts file %s: %v", path, err)
		return
	}
	var lines []string
	// Do not mutate the caller's slice when retaining existing cache-hit mappings.
	candidates := append([]string(nil), ips...)
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == domain {
			if keepExisting {
				candidates = append(candidates, fields[0])
			}
			continue
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	seen := make(map[string]bool)
	for _, ip := range candidates {
		if seen[ip] {
			continue
		}
		if limit > 0 && len(seen) >= limit {
			break
		}
		seen[ip] = true
		lines = append(lines, ip+" "+domain)
	}
	output := strings.Join(lines, "\n")
	if output != "" {
		output += "\n"
	}
	if output != string(contents) {
		// Keep using the checked inode for the entire read/update operation.
		_, err := f.WriteAt([]byte(output), 0)
		if err == nil {
			err = f.Truncate(int64(len(output)))
		}
		if err != nil {
			logger.Printf("failed to update hosts file %s: %v", path, err)
			return
		}
	}
	for key := range writtenReachable {
		if strings.HasPrefix(key, path+"\x00") && strings.HasSuffix(key, " "+domain) {
			delete(writtenReachable, key)
		}
	}
	for ip := range seen {
		writtenReachable[path+"\x00"+ip+" "+domain] = true
	}
}

func recordDomainUnreachable(domain string) {
	recordStatus(currentConfig.UnreachableDomainsFile, currentConfig.ReachableDomainsFile, domain)
}
