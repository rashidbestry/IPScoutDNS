package main

import (
	"os/exec"
	"syscall"
)

func configureHookCommand(cmd *exec.Cmd, command string) {
	// cmd.exe does not use Go's normal CommandLineToArgvW escaping. Supply the
	// raw /S /C string with outer quotes that cmd.exe removes before execution.
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: `cmd.exe /D /S /C "` + command + `"`}
}
