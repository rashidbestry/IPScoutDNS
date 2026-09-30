package main

import (
	"fmt"
	"os"
	"sync"
)

var (
	hostsMu            sync.Mutex
	writtenReachable   = make(map[string]bool)
	writtenUnreachable = make(map[string]bool)
)

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
