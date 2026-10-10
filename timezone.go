package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

// Set time.Local before logging and worker goroutines start. Go's Unix timezone
// discovery does not read OpenWrt's POSIX /etc/TZ file. Explicit TZ wins over it.
func configureLocalTimezone() (string, error) {
	location, source, err := localTimezoneWith(runtime.GOOS, os.LookupEnv, os.ReadFile)
	if err == nil && location != nil {
		time.Local = location
	}
	return source, err
}

func localTimezoneWith(goos string, lookup func(string) (string, bool), read func(string) ([]byte, error)) (*time.Location, string, error) {
	if goos != "linux" {
		return nil, "OS default", nil
	}
	value, explicit := lookup("TZ")
	source := "TZ"
	if !explicit {
		data, err := read("/etc/TZ")
		if os.IsNotExist(err) {
			return nil, "OS default", nil
		}
		if err != nil {
			return nil, "/etc/TZ", err
		}
		value, source = strings.TrimSpace(string(data)), "/etc/TZ"
	}
	if value == "" {
		if explicit {
			return time.UTC, source, nil
		}
		return nil, source, fmt.Errorf("empty timezone setting")
	}
	value = strings.TrimPrefix(value, ":")
	if strings.HasPrefix(value, "/") {
		data, err := read(value)
		if err != nil {
			return nil, source, err
		}
		location, err := time.LoadLocationFromTZData(value, data)
		return location, source, err
	}
	if location, err := time.LoadLocation(value); err == nil {
		return location, source, nil
	}
	location, err := loadPOSIXTimezone(value)
	return location, source, err
}

// TZif v2 stores POSIX rules in its footer. Use the standard library's parser
// and DST calculations rather than duplicating them or depending on libc/tzdata.
// A sentinel base zone exposes invalid footers, which LoadLocationFromTZData
// otherwise accepts and silently ignores.
func loadPOSIXTimezone(value string) (*time.Location, error) {
	invalid := fmt.Errorf("invalid POSIX timezone %q", value)
	if value == "" || len(value) > 1024 {
		return nil, invalid
	}
	for _, ch := range value {
		if ch < 32 || ch == 127 {
			return nil, invalid
		}
	}
	const sentinel = "\x01"
	block := make([]byte, 44+6+len(sentinel)+1)
	copy(block, "TZif2")
	binary.BigEndian.PutUint32(block[36:40], 1) // one local time type
	binary.BigEndian.PutUint32(block[40:44], uint32(len(sentinel)+1))
	copy(block[50:], sentinel)
	data := append(append([]byte(nil), block...), block...)
	data = append(data, []byte("\n"+value+"\n")...)
	location, err := time.LoadLocationFromTZData(value, data)
	if err != nil {
		return nil, err
	}
	name, _ := time.Unix(0, 0).In(location).Zone()
	if name == sentinel {
		return nil, invalid
	}
	return location, nil
}
