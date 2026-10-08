package main

import (
	"os"
	"path/filepath"
	"reflect"
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
			existing: map[string]bool{priorityConfigPath: true, "system.conf": true},
			want:     priorityConfigPath,
		},
		{
			name:     "config folder precedes legacy root config",
			goos:     "linux",
			existing: map[string]bool{priorityConfigPath: true, legacyLocalConfigPath: true},
			want:     priorityConfigPath,
		},
		{
			name:     "legacy root config precedes unix system config",
			goos:     "linux",
			existing: map[string]bool{legacyLocalConfigPath: true, "system.conf": true},
			want:     legacyLocalConfigPath,
		},
		{
			name:          "windows config folder precedes user config",
			goos:          "windows",
			userConfigDir: "user-config",
			existing:      map[string]bool{priorityConfigPath: true, legacyLocalConfigPath: true, userConfigPath: true},
			want:          priorityConfigPath,
		},
		{
			name:          "windows legacy root config remains supported",
			goos:          "windows",
			userConfigDir: "user-config",
			existing:      map[string]bool{legacyLocalConfigPath: true, userConfigPath: true},
			want:          legacyLocalConfigPath,
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
			want: priorityConfigPath,
		},
		{
			name: "unix default remains system config path",
			goos: "linux",
			want: "system.conf",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := resolveConfigPathWith(test.configOverride, test.legacyOverride, priorityConfigPath, "system.conf", test.goos, test.userConfigDir, func(path string) bool {
				return test.existing[path]
			})
			if got != test.want {
				t.Fatalf("resolveConfigPathWith() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSampleConfigUsesTCPReachabilitySettings(t *testing.T) {
	cfg, err := loadConfig(priorityConfigPath)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.TLSTimeout.String() != "3s" {
		t.Errorf("TLSTimeout = %s, want 3s", cfg.TLSTimeout)
	}
	if cfg.TLSPort != 443 {
		t.Errorf("TLSPort = %d, want 443", cfg.TLSPort)
	}
	if cfg.TLSSOCKS5Addr != "127.0.0.1:1080" {
		t.Errorf("TLSSOCKS5Addr = %q, want 127.0.0.1:1080", cfg.TLSSOCKS5Addr)
	}
	if cfg.DirectTCPInterface != "default" {
		t.Errorf("DirectTCPInterface = %q, want default", cfg.DirectTCPInterface)
	}
}

func TestDomainInputsResolvedBesideConfig(t *testing.T) {
	for _, mode := range []string{"active", "passive"} {
		t.Run(mode, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "config")
			if err := os.MkdirAll(filepath.Join(dir, "lists"), 0700); err != nil {
				t.Fatal(err)
			}
			activePath := filepath.Join(dir, "lists", "active.txt")
			passivePath := filepath.Join(dir, "passive.txt")
			if err := os.WriteFile(activePath, []byte("^example\\.com$\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(passivePath, []byte("example.com\n"), 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "ipscoutdns.conf")
			contents := "mode=" + mode + "\ndirect_dns=1.1.1.1\nactive_domains_file=lists/active.txt\npassive_domains_file=passive.txt\n"
			if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := loadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.ActiveDomainsFile != activePath || cfg.PassiveDomainsFile != passivePath {
				t.Fatalf("domain inputs resolved outside config directory: %q / %q", cfg.ActiveDomainsFile, cfg.PassiveDomainsFile)
			}
			if _, err := os.ReadFile(cfg.ActiveDomainsFile); err != nil {
				t.Fatal(err)
			}
			domains, err := loadPassiveDomainsFile(cfg.PassiveDomainsFile)
			if err != nil || len(domains) != 1 || domains[0] != "example.com" {
				t.Fatalf("passive input could not be loaded: %v %v", domains, err)
			}
		})
	}
}

func TestAbsoluteDomainInputsAndEmptyOptionalInputPreserved(t *testing.T) {
	for _, input := range []string{filepath.Join(t.TempDir(), "domains.txt"), "/etc/ipscoutdns/active-domains.txt"} {
		cfg, err := loadConfig(writeModeTestFile(t, "mode=active\ndirect_dns=1.1.1.1\nactive_domains_file="+input+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ActiveDomainsFile != input || cfg.PassiveDomainsFile != "" {
			t.Fatalf("absolute or omitted input changed: %q / %q", cfg.ActiveDomainsFile, cfg.PassiveDomainsFile)
		}
	}
}

func TestHTTPProbeConfig(t *testing.T) {
	for _, mode := range []string{"active", "passive"} {
		t.Run(mode, func(t *testing.T) {
			for _, test := range []struct {
				name, setting string
				want          bool
				invalid       bool
			}{
				{"omitted defaults to enabled", "", true, false},
				{"enabled", "http_probe=true\n", true, false},
				{"disabled with spaces", "http_probe = false\n", false, false},
				{"invalid boolean", "http_probe=maybe\n", false, true},
				{"empty value", "http_probe=\n", false, true},
			} {
				t.Run(test.name, func(t *testing.T) {
					contents := "mode=" + mode + "\nactive_domains_file=active-domains.txt\npassive_domains_file=passive-domains.txt\ndirect_dns=1.1.1.1\n" + test.setting
					cfg, err := loadConfig(writeModeTestFile(t, contents))
					if test.invalid {
						if err == nil || !strings.Contains(err.Error(), "invalid http_probe") {
							t.Fatalf("error = %v, want invalid http_probe", err)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if cfg.HTTPProbe != test.want {
						t.Fatalf("HTTPProbe = %v, want %v", cfg.HTTPProbe, test.want)
					}
				})
			}
		})
	}
}

func TestDirectTCPInterfaceConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ipscoutdns.conf")
	contents := `mode=active
active_domains_file=active-domains.txt
direct_dns=1.1.1.1
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
			contents := "mode=active\nactive_domains_file=active-domains.txt\ndirect_dns=1.1.1.1\n" +
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
	contents := `mode=active
server=127.0.0.1:53
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

active_domains_file=active-domains.txt
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
	contents := `mode=active
active_domains_file=active-domains.txt
direct_dns=1.1.1.1
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
	expected, err := loadConfig(priorityConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	// Packaging only relocates inputs. All other source settings must survive,
	// including proxy resolvers, listener/route, probes, logging and scheduling.
	if expected.ActiveDomainsFile != "" {
		expected.ActiveDomainsFile = "/etc/ipscoutdns/active-domains.txt"
	}
	if expected.PassiveDomainsFile != "" {
		expected.PassiveDomainsFile = "/etc/ipscoutdns/passive-domains.txt"
	}
	if !reflect.DeepEqual(cfg, expected) {
		t.Fatalf("generated config lost or changed source settings:\ngot:  %+v\nwant: %+v", cfg, expected)
	}
	runtimeDir, err := runtimeOutputDirectoryWith("linux", func(string) ([]byte, error) {
		return []byte("ID=openwrt\n"), nil
	}, os.Executable)
	if err != nil || runtimeDir != openWrtOutputDirectory {
		t.Fatalf("OpenWrt runtime directory = %q, error = %v", runtimeDir, err)
	}
	testOutputDir := t.TempDir()
	if err := configureOutputPaths(&cfg, testOutputDir, false); err != nil {
		t.Fatal(err)
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
		if output.path != "" && filepath.Dir(output.path) != testOutputDir {
			t.Errorf("%s output path = %q, want path under selected output directory", output.name, output.path)
		}
	}
}
