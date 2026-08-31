package keryxstratum

import (
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
)

const ipfsStartupTimeout = 60 * time.Second

var ipfsProbeClient = &http.Client{Timeout: 2 * time.Second}

func ipfsAPIReachable(apiURL string) bool {
	resp, err := ipfsProbeClient.Post(trimSlash(apiURL)+"/api/v0/version", "", nil)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func isLoopbackAPI(apiURL string) bool {
	parsed, err := url.Parse(apiURL)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func resolveIPFSBinary(configured string) string {
	if configured != "" {
		if _, err := os.Stat(configured); err == nil {
			return configured
		}
		return ""
	}
	if exe, err := os.Executable(); err == nil {
		adjacent := filepath.Join(filepath.Dir(exe), "ipfs")
		if _, err := os.Stat(adjacent); err == nil {
			return adjacent
		}
	}
	if found, err := exec.LookPath("ipfs"); err == nil {
		return found
	}
	return ""
}

// ensureIPFSDaemon makes sure the IPFS API the bridge depends on (model verification
// at declare_capabilities) is reachable, starting a local kubo daemon when the API is
// local and down. Mirrors the miner's ensure_daemon. Never fatal: model verification
// keeps probing the same URL per-declare, so a daemon that comes up later heals things.
func ensureIPFSDaemon(logger *zap.SugaredLogger, apiURL, configuredBinary string) {
	if ipfsAPIReachable(apiURL) {
		logger.Info("IPFS API reachable @ " + apiURL)
		return
	}
	if !isLoopbackAPI(apiURL) {
		logger.Error("IPFS API unreachable @ " + apiURL + " — miners will fail model verification until it is up")
		return
	}
	binary := resolveIPFSBinary(configuredBinary)
	if binary == "" {
		logger.Error("IPFS API down and no ipfs binary found (config ipfs_binary, next to the executable, or PATH) — miners will fail model verification")
		return
	}

	logger.Info("IPFS daemon not running — starting " + binary)
	logFile, err := os.OpenFile("kubo.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		logger.Error("failed opening kubo.log: " + err.Error())
		return
	}
	cmd := exec.Command(binary, "daemon", "--init")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	// Own process group: Ctrl+C on the bridge must not kill kubo mid-write.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		logger.Error("failed starting ipfs daemon: " + err.Error())
		logFile.Close()
		return
	}
	logFile.Close()
	go cmd.Wait() //nolint:errcheck

	deadline := time.Now().Add(ipfsStartupTimeout)
	for time.Now().Before(deadline) {
		if ipfsAPIReachable(apiURL) {
			logger.Infof("IPFS daemon up (pid %d)", cmd.Process.Pid)
			return
		}
		if cmd.ProcessState != nil {
			logger.Error("ipfs daemon exited during startup — see kubo.log")
			return
		}
		time.Sleep(time.Second)
	}
	logger.Error("IPFS API still unreachable after " + ipfsStartupTimeout.String() + " — see kubo.log")
}

// effectiveIPFSURL mirrors newShareHandler's default.
func effectiveIPFSURL(configured string) string {
	if strings.TrimSpace(configured) == "" {
		return "http://127.0.0.1:5001"
	}
	return configured
}
