package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

func commandShell(goos, command string) (string, []string) {
	if goos == "windows" {
		return "cmd.exe", []string{"/D", "/S", "/C", command}
	}
	return "/bin/sh", []string{"-c", command}
}

// Each command gets its own shell and inherits the service's working directory
// and environment. Nil streams discard stdout/stderr and provide no stdin.
// Attempt every command in order unless shutdown cancels the hook.
func runCommands(ctx context.Context, commands []string) error {
	var failures []error
	for i, command := range commands {
		if err := ctx.Err(); err != nil {
			return err
		}
		if strings.TrimSpace(command) == "" {
			continue
		}
		shell, args := commandShell(runtime.GOOS, command)
		cmd := exec.CommandContext(ctx, shell, args...)
		configureHookCommand(cmd, command)
		if err := cmd.Run(); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Report status by position without exposing command text or output.
			failures = append(failures, fmt.Errorf("command %d failed: %w", i+1, err))
		}
	}
	return errors.Join(failures...)
}

func runMode(ctx context.Context, cfg Config, active func(context.Context, Config), passive func(context.Context, Config) error) error {
	if err := runCommands(ctx, cfg.PreLaunchCommands); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("PRE launch commands: %w", err)
	}
	if ctx.Err() != nil {
		return nil
	}
	if cfg.Mode == "passive" {
		if err := passive(ctx, cfg); err != nil {
			return fmt.Errorf("passive mode: %w", err)
		}
	} else {
		active(ctx, cfg)
	}
	return nil
}
