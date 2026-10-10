package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Release workflows set this with -X main.releaseVersion=<tag>.
var releaseVersion = "dev"

type compactProbeLogsKey struct{}

func compactProbeContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, compactProbeLogsKey{}, true)
}

func compactProbeLogs(ctx context.Context) bool {
	return ctx != nil && ctx.Value(compactProbeLogsKey{}) == true
}

func logOtherConfigs(cfg Config, timezoneSource string) {
	left := []string{
		fmt.Sprintf("logs_enabled=%t", cfg.LogsEnabled),
		fmt.Sprintf("save_logs=%t", cfg.SaveLogs),
		fmt.Sprintf("log_max_size=%dB", cfg.LogMaxSize),
		fmt.Sprintf("log_keep_files=%d", cfg.LogKeepFiles),
	}
	var right []string
	if cfg.Mode == "passive" {
		left = append(left, fmt.Sprintf("passive_resolve_time=%q", cfg.PassiveResolveTime))
		right = append(right, fmt.Sprintf("passive_resolve_interval=%s", cfg.PassiveResolveInterval), fmt.Sprintf("passive_resolve_parallel=%d", cfg.PassiveResolveParallel))
	} else {
		left = append(left, fmt.Sprintf("ttl=%s", cfg.CacheTTL), fmt.Sprintf("answer_ttl=%d", cfg.AnswerTTL))
		if cfg.runtimeCopiesEnabled {
			right = append(right, fmt.Sprintf("active_copy_interval=%s", cfg.ActiveCopyInterval), fmt.Sprintf("active_log_copy_interval=%s", cfg.ActiveLogCopyInterval))
		}
	}
	left = append(left, "timezone="+time.Now().Format("-07:00"), fmt.Sprintf("timezone_source=%q", timezoneSource))
	right = append(right,
		fmt.Sprintf("parallel_tests=%d", cfg.MaxParallelTests),
		fmt.Sprintf("hosts_max_ips_per_domain=%d", cfg.HostsMaxIPsPerDomain),
		fmt.Sprintf("reachable_hosts=%q", cfg.ReachableHostsFile),
		fmt.Sprintf("reachable_domains_file=%q", cfg.ReachableDomainsFile),
		fmt.Sprintf("reachable_ips_file=%q", cfg.ReachableIPsFile),
		fmt.Sprintf("unreachable_domains_file=%q", cfg.UnreachableDomainsFile),
		fmt.Sprintf("unreachable_ips_file=%q", cfg.UnreachableIPsFile))
	// One logger write keeps the continuation rows together and rotates saved
	// logs only between complete records. Spaces give both columns stable widths.
	indent := strings.Repeat(" ", len(logger.Prefix())+len("2006/01/02 15:04:05 ")+8)
	logger.Printf("\t- Other configs:\n%s", configColumns(left, right, indent))
}

func configColumns(left, right []string, indent string) string {
	width, rows := 0, len(left)
	if len(right) > rows {
		rows = len(right)
	}
	for _, value := range left {
		if len(value)+2 > width {
			width = len(value) + 2
		}
	}
	var output strings.Builder
	for i := 0; i < rows; i++ {
		if i > 0 {
			output.WriteByte('\n')
		}
		output.WriteString(indent)
		cell := ""
		if i < len(left) {
			cell = "- " + left[i]
		}
		if i < len(right) {
			fmt.Fprintf(&output, "%-*s    - %s", width, cell, right[i])
		} else {
			output.WriteString(cell)
		}
	}
	return output.String()
}

// Empty brackets mean no final failure (success, disabled or not attempted).
// X means the protocol was attempted but no candidate succeeded at that stage.
func logDomainResult(domain string, collected, reached int, ip, protocol string, cfg Config, tlsResults map[string]tlsProbeResult, httpResults map[string]httpProbeResult, icmpResults map[string]bool, reason string) {
	if ip != "" {
		logger.Printf("- %s: collected[%d] reached[%d] WORKING IP = %s [%s]", domain, collected, reached, ip, protocol)
		return
	}
	var tcpAttempted, tcpOK, tlsAttempted, tlsOK, httpAttempted, httpOK, icmpAttempted, icmpOK bool
	for _, result := range tlsResults {
		if cfg.TCPProbe || cfg.TLSProbe {
			tcpAttempted = true
			tcpOK = tcpOK || result.tcpReachable
		}
		if cfg.TLSProbe && result.tcpReachable {
			tlsAttempted = true
			tlsOK = tlsOK || result.tlsReady
		}
	}
	for _, result := range httpResults {
		if cfg.HTTPProbe {
			tcpAttempted = true
			tcpOK = tcpOK || result.tcpReachable
			if result.tcpReachable {
				httpAttempted = true
				httpOK = httpOK || result.httpReady
			}
		}
	}
	for _, ok := range icmpResults {
		icmpAttempted, icmpOK = true, icmpOK || ok
	}
	failure := func(attempted, ok bool) string {
		if attempted && !ok {
			return "X"
		}
		return ""
	}
	if reason != "" {
		reason = " (" + reason + ")"
	}
	logger.Printf("- %s: collected[%d] reached[%d] TCP[%s] TLS[%s] HTTP[%s] ICMP[%s] NO WORKING IP%s",
		domain, collected, reached, failure(tcpAttempted, tcpOK), failure(tlsAttempted, tlsOK), failure(httpAttempted, httpOK), failure(icmpAttempted, icmpOK), reason)
}
