//go:build !windows

package main

import "os/exec"

func configureHookCommand(cmd *exec.Cmd, command string) {}
