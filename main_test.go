package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
