package main

import (
	"bytes"
	"log"
	"regexp"
	"strings"
	"testing"
)

func TestPassiveOutputLogIndentation(t *testing.T) {
	var output bytes.Buffer
	l := log.New(&output, "[ipscoutdns] ", log.LstdFlags)
	l.Printf("- config")
	l.Printf("\t- mode: passive")
	l.Printf("- output")
	l.SetOutput(indentedLogWriter{
		output:        l.Writer(),
		messageOffset: len(l.Prefix()) + len("2006/01/02 15:04:05 "),
	})
	l.Printf("passive pass: %d domains, up to %d parallel resolves", 1, 16)
	l.Printf("example.com: WORKING IP = %s [%s]", "1.1.1.1", "TLS")
	l.Printf("copied %d output files from %s to %s", 3, outputSourceDirectory, outputDestinationDirectory)
	l.Printf("passive pass complete; next pass in 24h0m0s")
	header := regexp.MustCompile(`^\[ipscoutdns\] \d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} `)
	want := []string{
		"- config", "\t- mode: passive", "- output",
		"\tpassive pass: 1 domains, up to 16 parallel resolves",
		"\texample.com: WORKING IP = 1.1.1.1 [TLS]",
		"\tcopied 3 output files from /tmp/ipscoutdns to /etc/ipscoutdns",
		"\tpassive pass complete; next pass in 24h0m0s",
	}
	lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
	if len(lines) != len(want) {
		t.Fatalf("log lines = %d, want %d: %q", len(lines), len(want), output.String())
	}
	for i, line := range lines {
		if !header.MatchString(line) || header.ReplaceAllString(line, "") != want[i] {
			t.Errorf("line %d = %q, want standard header followed by %q", i, line, want[i])
		}
	}
}
