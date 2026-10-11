//go:build !linux

package main

import (
	"fmt"
	"os"
)

func prepareOpenWrtOutputDirectory(dir string) error {
	return fmt.Errorf("OpenWrt output directories require Linux")
}

func openHostsFile(path string, flags int) (*os.File, error) {
	f, err := os.OpenFile(path, flags, 0644)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("hosts output %s must be a regular file", path)
	}
	return f, nil
}
