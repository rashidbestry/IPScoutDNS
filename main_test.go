package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfigRejectsMissingUpstreamResolvers(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "ipselector.conf")
	content := `
[server]
address=127.0.0.1:5354

[cache]
ttl=1h
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := loadConfig(cfgPath)
	if err == nil {
		t.Fatal("expected validation error for missing upstream resolvers")
	}
	if !strings.Contains(err.Error(), "at least one upstream resolver") {
		t.Fatalf("expected missing upstream resolver error, got: %v", err)
	}
}

func TestLoadConfigRejectsInvalidSOCKS5Address(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "ipselector.conf")
	content := `
[direct_dns]
8.8.8.8

[socks5]
address=not-a-valid-socks-address
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := loadConfig(cfgPath)
	if err == nil {
		t.Fatal("expected validation error for invalid SOCKS5 address")
	}
	if !strings.Contains(err.Error(), "socks5 address") {
		t.Fatalf("expected socks5 validation error, got: %v", err)
	}
}

func TestLoadConfigParsesRuntimeSettings(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "ipscoutdns.conf")
	content := `
[direct_dns]
8.8.8.8

[server]
address=127.0.0.1:5354
dns_timeout=5s
tls_timeout=7s
parallel_tests=9
answer_ttl=600
shutdown_timeout=12s

[cache]
ttl=2h
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.DNSTimeout != 5*time.Second {
		t.Fatalf("expected dns timeout 5s, got %s", cfg.DNSTimeout)
	}
	if cfg.TLSTimeout != 7*time.Second {
		t.Fatalf("expected tls timeout 7s, got %s", cfg.TLSTimeout)
	}
	if cfg.MaxParallelTests != 9 {
		t.Fatalf("expected max parallel tests 9, got %d", cfg.MaxParallelTests)
	}
	if cfg.AnswerTTL != 600 {
		t.Fatalf("expected answer ttl 600, got %d", cfg.AnswerTTL)
	}
	if cfg.ShutdownTimeout != 12*time.Second {
		t.Fatalf("expected shutdown timeout 12s, got %s", cfg.ShutdownTimeout)
	}
}
