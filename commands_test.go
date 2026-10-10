package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCommandConfig(t *testing.T) {
	for _, mode := range []string{"active", "passive"} {
		t.Run(mode, func(t *testing.T) {
			contents := "mode=" + mode + "\ndirect_dns=1.1.1.1\nactive_domains_file=list\npassive_domains_file=list\n" + `
pre_launch_commands={
    # ignored comment
    ; ignored comment
    prepare-network
    echo "a,b # c; d" > "file with spaces"
    NAME=value; echo "$NAME"
    [ -f /tmp/ready ]
    echo {literal}
    prepare-network
}
pre_launch_commands=echo another=command
passive_post_commands={
    /etc/init.d/dnsmasq reload
    echo "done" && echo "next"
}
server=127.0.0.1:5354
`
			cfg, err := loadConfig(writeModeTestFile(t, contents))
			if err != nil {
				t.Fatal(err)
			}
			wantPre := []string{"prepare-network", `echo "a,b # c; d" > "file with spaces"`, `NAME=value; echo "$NAME"`, "[ -f /tmp/ready ]", "echo {literal}", "prepare-network", "echo another=command"}
			wantPost := []string{"/etc/init.d/dnsmasq reload", `echo "done" && echo "next"`}
			if !reflect.DeepEqual(cfg.PreLaunchCommands, wantPre) || !reflect.DeepEqual(cfg.PassivePostCommands, wantPost) {
				t.Fatalf("command lists = %q / %q, want %q / %q", cfg.PreLaunchCommands, cfg.PassivePostCommands, wantPre, wantPost)
			}
			if cfg.ListenAddr != "127.0.0.1:5354" {
				t.Fatal("command block swallowed the following config setting")
			}
		})
	}
	for _, hook := range []string{"pre_launch_commands", "passive_post_commands"} {
		t.Run(hook+" empty", func(t *testing.T) {
			cfg, err := loadConfig(writeModeTestFile(t, "mode=passive\npassive_domains_file=list\ndirect_dns=1.1.1.1\n"+hook+"=\n"+hook+"={}\n"+hook+"={\n}\n"))
			if err != nil || len(cfg.PreLaunchCommands) != 0 || len(cfg.PassivePostCommands) != 0 {
				t.Fatalf("empty hooks = %q / %q, error = %v", cfg.PreLaunchCommands, cfg.PassivePostCommands, err)
			}
		})
		t.Run(hook+" unclosed", func(t *testing.T) {
			_, err := loadConfig(writeModeTestFile(t, "mode=passive\npassive_domains_file=list\ndirect_dns=1.1.1.1\n"+hook+"={\nprepare-network\n"))
			if err == nil || !strings.Contains(err.Error(), "unclosed "+hook) {
				t.Fatalf("error = %v, want unclosed block", err)
			}
		})
	}
}

// Test commands use an environment variable to cover paths containing spaces
// without interpolating filesystem paths into shell syntax.
func hookAppendCommand(value string) string {
	if runtime.GOOS == "windows" {
		return `echo ` + value + `>>"%IPSCOUTDNS_HOOK_FILE%"`
	}
	return `printf '%s\n' '` + value + `' >> "$IPSCOUTDNS_HOOK_FILE"`
}

func hookFailCommand() string {
	if runtime.GOOS == "windows" {
		return "exit /b 7"
	}
	return "exit 7"
}

func hookEvents(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(data))
}

func TestRunCommandsOrderAndFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commands with spaces.txt")
	t.Setenv("IPSCOUTDNS_HOOK_FILE", path)
	err := runCommands(context.Background(), []string{hookAppendCommand("first"), hookFailCommand(), hookAppendCommand("second")})
	if err == nil || !strings.Contains(err.Error(), "command 2 failed") {
		t.Fatalf("error = %v, want command 2 failure", err)
	}
	if got := hookEvents(t, path); !reflect.DeepEqual(got, []string{"first", "second"}) {
		t.Fatalf("events = %q, want ordered commands before and after failure", got)
	}
}

func TestRunCommandsQuotedScriptAndWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("IPSCOUTDNS_HOOK_FILE", "relative output.txt")
	name := "script with spaces.sh"
	script := hookAppendCommand("script") + "\n"
	command := `/bin/sh "$IPSCOUTDNS_HOOK_SCRIPT" && ` + hookAppendCommand("after")
	if runtime.GOOS == "windows" {
		name = "script with spaces.cmd"
		script = "@echo off\r\n" + hookAppendCommand("script") + "\r\n"
		command = `"%IPSCOUTDNS_HOOK_SCRIPT%" && ` + hookAppendCommand("after")
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IPSCOUTDNS_HOOK_SCRIPT", path)
	if err := runCommands(context.Background(), []string{command}); err != nil {
		t.Fatal(err)
	}
	if got := hookEvents(t, filepath.Join(dir, "relative output.txt")); !reflect.DeepEqual(got, []string{"script", "after"}) {
		t.Fatalf("script/order/relative output = %q", got)
	}
}

func TestPreCommandsBeforeDailySchedule(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.txt")
	t.Setenv("IPSCOUTDNS_HOOK_FILE", path)
	cfg := Config{Mode: "passive", PassiveResolveTime: "03:00", PreLaunchCommands: []string{hookAppendCommand("pre")}}
	waited := false
	err := runMode(context.Background(), cfg,
		func(context.Context, Config) { t.Fatal("started Active mode") },
		func(ctx context.Context, cfg Config) error {
			noop := func(context.Context) error { return nil }
			return runPassiveWithClock(ctx, cfg,
				func(string) ([]string, error) { t.Fatal("resolved before schedule"); return nil, nil },
				func(context.Context, string, Config) {},
				func(context.Context, time.Duration) bool {
					waited = true
					if got := hookEvents(t, path); !reflect.DeepEqual(got, []string{"pre"}) {
						t.Fatalf("PRE not completed before daily wait: %q", got)
					}
					return false
				}, func() error { return nil }, noop, noop,
				func() time.Time { return time.Date(2026, 10, 10, 1, 0, 0, 0, time.UTC) }, nil)
		})
	if err != nil || !waited {
		t.Fatalf("error = %v, waited = %t", err, waited)
	}
}

func TestCommandOutputHelper(t *testing.T) {
	if os.Getenv("IPSCOUTDNS_COMMAND_OUTPUT_HELPER") != "1" {
		return
	}
	command := "echo STDOUT_SECRET; echo STDERR_SECRET >&2; exit 7"
	if runtime.GOOS == "windows" {
		command = "echo STDOUT_SECRET & echo STDERR_SECRET >&2 & exit /b 7"
	}
	err := runCommands(context.Background(), []string{command})
	if err == nil {
		t.Fatal("expected a failure status")
	}
	fmt.Println(err)
}

func TestRunCommandsDiscardsOutput(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestCommandOutputHelper$")
	cmd.Env = append(os.Environ(), "IPSCOUTDNS_COMMAND_OUTPUT_HELPER=1")
	output, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("command 1 failed")) {
		t.Fatalf("helper output = %s, error = %v", output, err)
	}
	for _, secret := range []string{"STDOUT_SECRET", "STDERR_SECRET"} {
		if bytes.Contains(output, []byte(secret)) {
			t.Fatalf("command text/output leaked: %s", output)
		}
	}
}

func TestRunCommandsCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "should not exist.txt")
	t.Setenv("IPSCOUTDNS_HOOK_FILE", path)
	command := "while :; do :; done"
	if runtime.GOOS == "windows" {
		command = "for /L %i in (1,0,2) do @rem waiting"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := runCommands(ctx, []string{command, hookAppendCommand("unexpected")})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 5*time.Second {
		t.Fatalf("cancelled command error = %v, elapsed = %s", err, time.Since(started))
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("command after cancellation ran: %v", err)
	}
}

func TestRunModeCommandLifecycle(t *testing.T) {
	for _, mode := range []string{"active", "passive"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hook events.txt")
			t.Setenv("IPSCOUTDNS_HOOK_FILE", path)
			var logs bytes.Buffer
			oldOutput := logger.Writer()
			logger.SetOutput(&logs)
			defer logger.SetOutput(oldOutput)
			record := func(event string) {
				file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				if _, err := fmt.Fprintln(file, event); err != nil {
					t.Fatal(err)
				}
			}
			cfg := Config{
				Mode: mode, PassiveResolveParallel: 1, PassiveResolveInterval: time.Hour,
				PreLaunchCommands:   []string{hookAppendCommand("pre1"), hookAppendCommand("pre2")},
				PassivePostCommands: []string{hookAppendCommand("post1"), hookFailCommand(), hookAppendCommand("post2")},
			}
			waits := 0
			err := runMode(context.Background(), cfg, func(context.Context, Config) { record("active") }, func(ctx context.Context, cfg Config) error {
				return runPassiveWithLogs(ctx, cfg,
					func(string) ([]string, error) { return []string{"example.com"}, nil },
					func(context.Context, string, Config) { record("resolve") },
					func(context.Context, time.Duration) bool { record("wait"); waits++; return waits < 2 },
					func() error { record("cleanup"); return nil },
					func(context.Context) error { record("copy"); return nil },
					func(context.Context) error { record("log"); return nil })
			})
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"pre1", "pre2", "active"}
			if mode == "passive" {
				want = []string{"pre1", "pre2", "cleanup", "resolve", "copy", "post1", "post2", "log", "wait", "cleanup", "resolve", "copy", "post1", "post2", "log", "wait"}
				if strings.Count(logs.String(), "command 2 failed") != 2 {
					t.Fatalf("POST failures not reported on both passes: %s", logs.String())
				}
			}
			if got := hookEvents(t, path); !reflect.DeepEqual(got, want) {
				t.Fatalf("events = %q, want %q", got, want)
			}
		})
	}
}

func TestRunModePreFailureOrCancellationStopsLaunch(t *testing.T) {
	for _, mode := range []string{"active", "passive"} {
		for _, cancelled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cancelled=%t", mode, cancelled), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if cancelled {
					cancel()
				}
				launched := false
				err := runMode(ctx, Config{Mode: mode, PreLaunchCommands: []string{hookFailCommand()}},
					func(context.Context, Config) { launched = true },
					func(context.Context, Config) error { launched = true; return nil })
				if launched || cancelled && err != nil || !cancelled && (err == nil || !strings.Contains(err.Error(), "PRE launch commands")) {
					t.Fatalf("launched = %t, error = %v", launched, err)
				}
			})
		}
	}
}

func TestPassivePostSkipped(t *testing.T) {
	for _, reason := range []string{"load failure", "cancelled resolve", "copy failure", "cancelled copy"} {
		t.Run(reason, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "should not exist.txt")
			t.Setenv("IPSCOUTDNS_HOOK_FILE", path)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cfg := Config{PassiveResolveParallel: 1, PassivePostCommands: []string{hookAppendCommand("unexpected")}}
			err := runPassiveWithOutputs(ctx, cfg,
				func(string) ([]string, error) {
					if reason == "load failure" {
						return nil, errors.New("missing file")
					}
					return []string{"example.com"}, nil
				}, func(context.Context, string, Config) {
					if reason == "cancelled resolve" {
						cancel()
					}
				}, func(context.Context, time.Duration) bool { return false }, func() error { return nil },
				func(context.Context) error {
					if reason == "copy failure" {
						return errors.New("copy failed")
					}
					if reason == "cancelled copy" {
						cancel()
					}
					return nil
				})
			if reason == "load failure" && err == nil || reason != "load failure" && err != nil {
				t.Fatalf("passive error = %v", err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("POST ran after %s: %v", reason, err)
			}
		})
	}
}
