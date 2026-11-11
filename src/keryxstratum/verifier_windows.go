//go:build windows

package keryxstratum

import (
	"os/exec"
	"syscall"
)

func hideVerifierWindow(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} }
