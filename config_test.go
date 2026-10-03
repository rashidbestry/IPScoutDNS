package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveConfigPathWith(t *testing.T) {
	userConfigPath := filepath.Join("user-config", "IPScoutDNS", "ipscoutdns.conf")
	tests := []struct {
		name           string
		configOverride string
		legacyOverride string
		goos           string
		userConfigDir  string
		existing       map[string]bool
		want           string
	}{
		{
			name:           "current override wins",
			configOverride: "explicit.conf",
			legacyOverride: "legacy.conf",
			goos:           "windows",
			want:           "explicit.conf",
		},
		{
			name:           "legacy override is supported",
			legacyOverride: "legacy.conf",
			goos:           "windows",
			want:           "legacy.conf",
		},
		{
			name:     "local config precedes system config",
			goos:     "linux",
			existing: map[string]bool{"local.conf": true, "system.conf": true},
			want:     "local.conf",
		},
		{
			name:     "unix system config remains supported",
			goos:     "linux",
			existing: map[string]bool{"system.conf": true},
			want:     "system.conf",
		},
		{
			name:          "windows uses per-user config location",
			goos:          "windows",
			userConfigDir: "user-config",
			want:          userConfigPath,
		},
		{
			name: "windows falls back to local path if config directory is unavailable",
			goos: "windows",
			want: "local.conf",
		},
		{
			name: "unix default remains system config path",
			goos: "linux",
			want: "system.conf",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := resolveConfigPathWith(test.configOverride, test.legacyOverride, "local.conf", "system.conf", test.goos, test.userConfigDir, func(path string) bool {
				return test.existing[path]
			})
			if got != test.want {
				t.Fatalf("resolveConfigPathWith() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSampleConfigUsesTCPReachabilitySettings(t *testing.T) {
	cfg, err := loadConfig("ipscoutdns.conf")
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.TLSTimeout.String() != "3s" {
		t.Errorf("TLSTimeout = %s, want 3s", cfg.TLSTimeout)
	}
	if cfg.TLSPort != 443 {
		t.Errorf("TLSPort = %d, want 443", cfg.TLSPort)
	}
	if cfg.TLSRoute != "proxy" {
		t.Errorf("TLSRoute = %q, want proxy", cfg.TLSRoute)
	}
	if cfg.TLSSOCKS5Addr != "127.0.0.1:1080" {
		t.Errorf("TLSSOCKS5Addr = %q, want 127.0.0.1:1080", cfg.TLSSOCKS5Addr)
	}
	if cfg.DirectTCPInterface != "default" {
		t.Errorf("DirectTCPInterface = %q, want default", cfg.DirectTCPInterface)
	}
}

func TestDirectTCPInterfaceConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ipscoutdns.conf")
	contents := `direct_dns=1.1.1.1
tcp_route=direct
direct_tcp_interface=127.0.0.1
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.DirectTCPInterface != "127.0.0.1" {
		t.Fatalf("DirectTCPInterface = %q, want 127.0.0.1", cfg.DirectTCPInterface)
	}
}

func TestDNSInterfaceConfig(t *testing.T) {
	tests := []struct {
		name        string
		directKey   string
		fallbackKey string
	}{
		{
			name:        "canonical keys",
			directKey:   "direct_dns_interface",
			fallbackKey: "fallback_dns_interface",
		},
		{
			name:        "legacy aliases",
			directKey:   "dns_interface",
			fallbackKey: "fallback_interface",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ipscoutdns.conf")
			contents := "direct_dns=1.1.1.1\n" +
				test.directKey + "=eth1\n" +
				test.fallbackKey + "=eth0\n"
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}

			cfg, err := loadConfigWithInterfaceValidator(path, func(string) error { return nil })
			if err != nil {
				t.Fatalf("loadConfigWithInterfaceValidator() error = %v", err)
			}
			if cfg.DirectDNSInterface != "eth1" {
				t.Errorf("DirectDNSInterface = %q, want eth1", cfg.DirectDNSInterface)
			}
			if cfg.FallbackDNSInterface != "eth0" {
				t.Errorf("FallbackDNSInterface = %q, want eth0", cfg.FallbackDNSInterface)
			}
		})
	}
}

func TestFlatFormatConfigLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ipscoutdns.conf")
	contents := `server=127.0.0.1:53
logs_enabled=true
ttl=24h

direct_dns={
    8.8.8.8,
    1.1.1.1,
}
proxy_dns={
    9.9.9.9,
    208.67.222.222,
}
proxy_dns_address=127.0.0.1:1080
fallback_dns=8.8.8.8:53
dns_timeout=3s
answer_ttl=300

tcp_port=443
tcp_route=proxy
tcp_proxy=127.0.0.1:1080
parallel_tests=16
tcp_timeout=3s

domains_file=domains.txt
reachable_hosts=reachable.hosts
reachable_domains_file=reachable.domains
reachable_ips_file=reachable.ips
unreachable_domains_file=unreachable.domains
unreachable_ips_file=unreachable.ips
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:53" {
		t.Fatalf("ListenAddr = %q, want 127.0.0.1:53", cfg.ListenAddr)
	}
	if cfg.FallbackDNS != "8.8.8.8:53" {
		t.Fatalf("FallbackDNS = %q, want 8.8.8.8:53", cfg.FallbackDNS)
	}
	if cfg.TLSRoute != "proxy" {
		t.Fatalf("TLSRoute = %q, want proxy", cfg.TLSRoute)
	}
	if cfg.DNSSOCKS5Addr != "127.0.0.1:1080" {
		t.Fatalf("DNSSOCKS5Addr = %q, want 127.0.0.1:1080", cfg.DNSSOCKS5Addr)
	}
	if len(cfg.DirectDNS) != 2 || cfg.DirectDNS[0] != "8.8.8.8" || cfg.DirectDNS[1] != "1.1.1.1" {
		t.Fatalf("DirectDNS = %#v, want [8.8.8.8 1.1.1.1]", cfg.DirectDNS)
	}
}

func TestFlatFormatRejectsInterfaceTCPRoute(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ipscoutdns.conf")
	contents := `direct_dns=1.1.1.1
tcp_route=interface
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if _, err := loadConfig(path); err == nil {
		t.Fatal("loadConfig() accepted unsupported tcp_route=interface")
	}
}

func TestOpenWrtPackageConfig(t *testing.T) {
	configPath := os.Getenv("IPSCOUTDNS_OPENWRT_CONFIG")
	if configPath == "" {
		t.Skip("OpenWrt config is generated by the package workflow")
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:5354" {
		t.Fatalf("ListenAddr = %q, want 127.0.0.1:5354", cfg.ListenAddr)
	}
	if cfg.DomainsFile != "/etc/ipscoutdns/domains.txt" {
		t.Fatalf("DomainsFile = %q, want /etc/ipscoutdns/domains.txt", cfg.DomainsFile)
	}
	if cfg.TLSRoute != "direct" {
		t.Fatalf("TLSRoute = %q, want direct", cfg.TLSRoute)
	}
	if len(cfg.ProxyDNS) != 0 {
		t.Fatalf("ProxyDNS = %#v, want no proxy resolvers", cfg.ProxyDNS)
	}

	outputs := []struct {
		name string
		path string
	}{
		{name: "reachable hosts", path: cfg.ReachableHostsFile},
		{name: "reachable domains", path: cfg.ReachableDomainsFile},
		{name: "reachable IPs", path: cfg.ReachableIPsFile},
		{name: "unreachable domains", path: cfg.UnreachableDomainsFile},
		{name: "unreachable IPs", path: cfg.UnreachableIPsFile},
	}
	for _, output := range outputs {
		if !strings.HasPrefix(output.path, "/tmp/ipscoutdns/") {
			t.Errorf("%s output path = %q, want path under /tmp/ipscoutdns/", output.name, output.path)
		}
	}
}
