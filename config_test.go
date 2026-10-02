package main

import (
	"path/filepath"
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
