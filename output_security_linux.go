package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// OpenWrt's fixed directory is directly under root-owned, sticky /tmp. Reject
// untrusted existing directories instead of taking ownership of their contents.
func prepareOpenWrtOutputDirectory(dir string) error {
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	f, err := openTrustedOutputDirectory(dir)
	if err != nil {
		return err
	}
	return f.Close()
}

func openTrustedOutputDirectory(dir string) (*os.File, error) {
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), dir)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, err
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 {
		f.Close()
		return nil, fmt.Errorf("output directory %s must be owned by uid %d and not writable by group or others", dir, os.Geteuid())
	}
	return f, nil
}

// Resolve only a basename relative to the checked directory. Neither the
// directory nor the output may be a symlink. Do not truncate before checking
// the opened inode; reject hard links and special files as well.
func openHostsFile(path string, flags int) (*os.File, error) {
	dir, err := openTrustedOutputDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	fd, err := syscall.Openat(int(dir.Fd()), filepath.Base(path), flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0644)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Nlink != 1 {
		f.Close()
		return nil, fmt.Errorf("hosts output %s must be a regular file with one link", path)
	}
	return f, nil
}
