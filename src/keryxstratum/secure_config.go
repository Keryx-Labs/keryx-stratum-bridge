package keryxstratum

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/keryx-labs/keryx-stratum-bridge/src/gostratum"
)

var workerNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func loopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (cfg BridgeConfig) validate() error {
	if cfg.Network != "mainnet" && cfg.Network != "testnet" {
		return fmt.Errorf("network must be mainnet or testnet")
	}
	if cfg.PayoutAddress == "" || cfg.EscrowKeyFile == "" || cfg.EscrowCert == "" || cfg.VerifierBinary == "" || cfg.WorkerAuthFile == "" {
		return fmt.Errorf("payout_address, escrow_key_file, escrow_cert, verifier_binary and worker_auth_file are required")
	}
	if cfg.BlockTaskActivationDAA != 0 {
		return fmt.Errorf("block_task_activation_daa must be zero: block tasks are unscheduled on the pinned H15/H16 networks")
	}
	if !loopbackAddress(cfg.RPCServer) {
		return fmt.Errorf("keryxd_address must use loopback; protect remote RPC with a local authenticated tunnel")
	}
	if cfg.HealthCheckPort != "" && !loopbackAddress(cfg.HealthCheckPort) {
		return fmt.Errorf("health_check_port must use loopback")
	}
	if cfg.PromPort != "" && !loopbackAddress(cfg.PromPort) {
		return fmt.Errorf("prom_port must use loopback")
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return fmt.Errorf("tls_cert_file and tls_key_file must be set together")
	}
	if !loopbackAddress(cfg.StratumPort) && cfg.TLSCertFile == "" {
		return fmt.Errorf("a non-loopback Stratum listener requires TLS")
	}
	if math.IsNaN(cfg.MinHoldingKRX) || math.IsInf(cfg.MinHoldingKRX, 0) || cfg.MinHoldingKRX < 0 || cfg.MinHoldingKRX > float64(math.MaxUint64)/1e8 {
		return fmt.Errorf("invalid min_holding_krx")
	}
	if cfg.MaxConnections < 0 || cfg.MaxConnections > 1024 {
		return fmt.Errorf("max_connections must be within 0..1024")
	}
	return nil
}

func loadWorkerAuth(path string) (map[string][32]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read worker_auth_file")
	}
	if len(data) > 32768 {
		return nil, fmt.Errorf("worker auth file exceeds size limit")
	}
	var encoded map[string]string
	if json.Unmarshal(data, &encoded) != nil || len(encoded) == 0 || len(encoded) > 128 {
		return nil, fmt.Errorf("worker_auth_file must map 1..128 worker names to SHA256 token digests")
	}
	auth := make(map[string][32]byte)
	for name, digest := range encoded {
		b, err := hex.DecodeString(digest)
		if !workerNamePattern.MatchString(name) || err != nil || len(b) != 32 {
			return nil, fmt.Errorf("invalid worker name or token digest")
		}
		var hash [32]byte
		copy(hash[:], b)
		auth[name] = hash
	}
	return auth, nil
}

func secureAuthorize(cfg BridgeConfig, auth map[string][32]byte) gostratum.EventHandler {
	return func(ctx *gostratum.StratumContext, event gostratum.JsonRpcEvent) error {
		if ctx.IsAuthorized() || len(event.Params) != 2 || !ctx.StratumV3 {
			return relayError(ctx, event, 24, "subscribe using keryx-stratum-v3 before authorization")
		}
		login, ok := event.Params[0].(string)
		if !ok {
			return relayError(ctx, event, 24, "invalid worker credentials")
		}
		token, ok := event.Params[1].(string)
		if !ok || len(token) < 32 || len(token) > 256 {
			return relayError(ctx, event, 24, "invalid worker credentials")
		}
		parts := strings.Split(login, ".")
		if len(parts) != 2 || parts[0] != cfg.PayoutAddress || !workerNamePattern.MatchString(parts[1]) {
			return relayError(ctx, event, 24, "configured payout and worker name required")
		}
		expected, exists := auth[parts[1]]
		actual := sha256.Sum256([]byte(token))
		if !exists || subtle.ConstantTimeCompare(expected[:], actual[:]) != 1 {
			return relayError(ctx, event, 24, "invalid worker credentials")
		}
		ip := net.ParseIP(ctx.RemoteAddr)
		if !ctx.Secure && (ip == nil || !ip.IsLoopback()) {
			return relayError(ctx, event, 24, "TLS required")
		}
		return gostratum.HandleAuthorize(ctx, event)
	}
}
