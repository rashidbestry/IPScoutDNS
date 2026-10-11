package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestHostsRejectSymlink(t *testing.T) {
	previous := currentConfig
	t.Cleanup(func() { currentConfig = previous })
	for _, update := range []bool{false, true} {
		name := "append"
		if update {
			name = "update"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(t.TempDir(), "ipscoutdns.conf")
			const original = "mode=active\n"
			if err := os.WriteFile(target, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "reachable.hosts")
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			currentConfig = Config{ReachableHostsFile: path}
			if update {
				updateReachableHosts("example.com", []string{"192.0.2.1"}, 8, false)
			} else {
				recordHost(path, "example.com", "192.0.2.1")
			}
			data, err := os.ReadFile(target)
			if err != nil || string(data) != original {
				t.Fatalf("protected config changed: %q, error = %v", data, err)
			}
		})
	}
}

func TestHostsRejectUnsafeFiles(t *testing.T) {
	previous := currentConfig
	t.Cleanup(func() { currentConfig = previous })
	for _, kind := range []string{"hardlink", "fifo", "directory", "symlink-directory", "writable-directory"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(t.TempDir(), "protected")
			const original = "protected contents\n"
			if err := os.WriteFile(target, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "reachable.hosts")
			var err error
			switch kind {
			case "hardlink":
				err = os.Link(target, path)
			case "fifo":
				err = syscall.Mkfifo(path, 0600)
			case "directory":
				err = os.Mkdir(path, 0700)
			case "symlink-directory":
				link := filepath.Join(t.TempDir(), "link")
				err = os.Symlink(dir, link)
				path = filepath.Join(link, "reachable.hosts")
			case "writable-directory":
				err = os.Chmod(dir, 0777)
			}
			if err != nil {
				t.Fatal(err)
			}
			currentConfig = Config{ReachableHostsFile: path}
			recordHost(path, "example.com", "192.0.2.1")
			updateReachableHosts("example.com", []string{"192.0.2.1"}, 8, false)
			data, err := os.ReadFile(target)
			if err != nil || string(data) != original {
				t.Fatalf("protected file changed: %q, %v", data, err)
			}
			if writtenReachable[path+"\x00192.0.2.1 example.com"] {
				t.Fatal("failed write recorded as successful")
			}
			if kind == "symlink-directory" || kind == "writable-directory" {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("created output in unsafe directory: %v", err)
				}
			}
		})
	}
}

func TestOpenWrtOutputDirectorySecurity(t *testing.T) {
	for _, kind := range []string{"new", "existing", "group-writable", "world-writable", "symlink", "file"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "outputs")
			var err error
			switch kind {
			case "existing", "group-writable", "world-writable":
				err = os.Mkdir(dir, 0755)
				if err == nil && kind == "group-writable" {
					err = os.Chmod(dir, 0770)
				}
				if err == nil && kind == "world-writable" {
					err = os.Chmod(dir, 0777)
				}
			case "symlink":
				err = os.Symlink(t.TempDir(), dir)
			case "file":
				err = os.WriteFile(dir, []byte("keep"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			err = prepareOpenWrtOutputDirectory(dir)
			if kind != "new" && kind != "existing" {
				if err == nil {
					t.Fatal("unsafe directory accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if kind == "new" {
				info, err := os.Stat(dir)
				if err != nil || info.Mode().Perm() != 0700 {
					t.Fatalf("directory not private: %v, %v", info, err)
				}
			}
			// A restart can reuse a service-owned directory and existing outputs.
			path := filepath.Join(dir, "reachable.hosts")
			if err := os.WriteFile(path, []byte("keep"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := prepareOpenWrtOutputDirectory(dir); err != nil {
				t.Fatal(err)
			}
			if data, err := os.ReadFile(path); err != nil || string(data) != "keep" {
				t.Fatalf("restart changed output: %q, %v", data, err)
			}
		})
	}
}

func TestOutputDirectoryRejectsForeignOwner(t *testing.T) {
	// Non-root tests can use / as an existing directory owned by another user.
	dir := "/"
	if os.Geteuid() == 0 {
		dir = t.TempDir()
		if err := os.Chown(dir, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	f, err := openTrustedOutputDirectory(dir)
	if err == nil {
		f.Close()
		t.Fatal("foreign-owned directory accepted")
	}
}
