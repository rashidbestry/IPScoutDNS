package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Status outputs are bounded snapshots, not an unlimited history. Keep insertion
// order so a new result evicts the oldest retained result once a file is full.
const maxStatusEntries = 10000

type statusFile struct {
	lines []string
	seen  map[string]bool
}

// Protected by hostsMu. These process-owned outputs are loaded once, including
// on restart; passive cleanup invalidates their indexes before deleting files.
var statusFiles = make(map[string]*statusFile)

func loadStatusFileLocked(path string) (*statusFile, error) {
	if state := statusFiles[path]; state != nil {
		return state, nil
	}
	state := &statusFile{seen: make(map[string]bool)}
	f, err := os.Open(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil {
		scanner := bufio.NewScanner(f)
		// Bound both line size and lines read when importing an old output.
		// Retain its first 10,000 lines; subsequent updates evict oldest first.
		scanner.Buffer(make([]byte, 1025), 1025)
		for n := 0; n < maxStatusEntries && scanner.Scan(); n++ {
			line := scanner.Text()
			if line != "" && !state.seen[line] {
				state.lines = append(state.lines, line)
				state.seen[line] = true
			}
		}
		scanErr := scanner.Err()
		closeErr := f.Close()
		if scanErr != nil {
			return nil, scanErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		// Normalize duplicates/CRLF and bound legacy files before publishing
		// the index. Closing the reader first also permits replacement on Windows.
		if err := writeStatusFile(path, state.lines); err != nil {
			return nil, err
		}
	}
	statusFiles[path] = state
	return state, nil
}

// Commit the file before changing its index. A failed write can be retried and
// cannot truncate the previous snapshot or leave a false membership result.
func writeStatusFile(path string, lines []string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".ipscoutdns-status-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0644); err == nil {
		output := strings.Join(lines, "\n")
		if len(lines) > 0 {
			output += "\n"
		}
		_, err = f.WriteString(output)
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}

func setStatusLineLocked(path, value string, present bool) error {
	if path == "" {
		return nil
	}
	state, err := loadStatusFileLocked(path)
	if err != nil {
		return err
	}
	if state.seen[value] == present {
		return nil
	}
	lines := make([]string, 0, len(state.lines)+1)
	for i, line := range state.lines {
		if line == value || (present && len(state.lines) == maxStatusEntries && i == 0) {
			continue
		}
		lines = append(lines, line)
	}
	if present {
		lines = append(lines, value)
	}
	if err := writeStatusFile(path, lines); err != nil {
		return err
	}
	if present && len(state.lines) == maxStatusEntries {
		delete(state.seen, state.lines[0])
	}
	state.lines = lines
	if present {
		state.seen[value] = true
	} else {
		delete(state.seen, value)
	}
	return nil
}

func recordStatus(path, opposite, value string) {
	if value == "" || len(value) > 1024 || strings.ContainsAny(value, "\r\n") {
		return
	}
	hostsMu.Lock()
	defer hostsMu.Unlock()
	if err := setStatusLineLocked(opposite, value, false); err != nil {
		logger.Printf("failed to update status file %s: %v", opposite, err)
		return
	}
	if err := setStatusLineLocked(path, value, true); err != nil {
		logger.Printf("failed to update status file %s: %v", path, err)
	}
}
