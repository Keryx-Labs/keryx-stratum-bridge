//go:build !windows

package keryxstratum

import "os/exec"

func hideVerifierWindow(cmd *exec.Cmd) {}
