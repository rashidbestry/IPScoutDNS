package main

import (
	"sync"
	"time"
)

type CacheEntry struct {
	IP       string
	Protocol string
	Checked  time.Time
}

type flight struct {
	done chan struct{}
	ip   string
	ok   bool
}

var (
	cacheMu sync.RWMutex
	cache   = make(map[string]CacheEntry)

	flightMu sync.Mutex
	flights  = make(map[string]*flight)
)

func getCache(domain string) (CacheEntry, bool) {
	cacheMu.RLock()
	defer cacheMu.RUnlock()

	entry, ok := cache[domain]
	return entry, ok
}

func updateCache(domain string, ip string, protocol string) {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	cache[domain] = CacheEntry{IP: ip, Protocol: protocol, Checked: time.Now()}
}

func deleteCache(domain string) {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	delete(cache, domain)
}

func getFlight(domain string) (*flight, bool) {
	flightMu.Lock()
	defer flightMu.Unlock()

	if f, ok := flights[domain]; ok {
		return f, false
	}

	f := &flight{done: make(chan struct{})}
	flights[domain] = f
	return f, true
}

func removeFlight(domain string, f *flight) {
	flightMu.Lock()
	defer flightMu.Unlock()

	if current, ok := flights[domain]; ok {
		if current == f {
			delete(flights, domain)
		}
	}
}
