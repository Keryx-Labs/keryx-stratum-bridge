package keryxstratum

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/keryx-labs/keryx-stratum-bridge/src/gostratum"
	"github.com/mattn/go-colorable"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const version = "v1.2.0-h15-h16"
const minBlockWaitTime = 500 * time.Millisecond

type BridgeConfig struct {
	Network          string        `yaml:"network"`
	PayoutAddress    string        `yaml:"payout_address"`
	WorkerAuthFile   string        `yaml:"worker_auth_file"`
	VerifierBinary   string        `yaml:"verifier_binary"`
	VerifierSHA256   string        `yaml:"verifier_sha256"`
	ServiceStateFile string        `yaml:"service_state_file"`
	TLSCertFile      string        `yaml:"tls_cert_file"`
	TLSKeyFile       string        `yaml:"tls_key_file"`
	MaxConnections   int           `yaml:"max_connections"`
	StratumPort      string        `yaml:"stratum_port"`
	RPCServer        string        `yaml:"keryxd_address"`
	PromPort         string        `yaml:"prom_port"`
	PrintStats       bool          `yaml:"print_stats"`
	UseLogFile       bool          `yaml:"log_to_file"`
	HealthCheckPort  string        `yaml:"health_check_port"`
	BlockWaitTime    time.Duration `yaml:"block_wait_time"`
	MinShareDiff     uint          `yaml:"min_share_diff"`
	ExtranonceSize   uint          `yaml:"extranonce_size"`
	// Deprecated: private H15/H16 responses are published inline.
	IPFSAPIUrl string `yaml:"ipfs_api_url"`
	// Deprecated: this entrypoint never auto-starts an IPFS daemon.
	IPFSBinary string `yaml:"ipfs_binary"`
	// EscrowCert is the 128-hex H6 delegation cert announced as /esig:<cert>. It binds the
	// bridge's escrow key to ONE payout address (produced by `keryx-cli delegate-escrow`),
	// so every worker must mine with that exact address. Single-address setups only.
	EscrowCert string `yaml:"escrow_cert"`
	// Dedicated escrow key read only by the local verifier helper. No default
	// key discovery or automatic wallet/escrow claiming occurs in this entrypoint.
	EscrowKeyFile string `yaml:"escrow_key_file"`
	// MinHoldingKRX is the balance-reward gate: a worker whose payout address holds fewer than
	// this many KRX is not dispatched jobs (no holdings = no mining in this pool). This forces
	// pool workers to hold KRX too — not just the pool operator — closing the "flee to a pool to
	// dodge holding" loophole. 0 (default) disables the gate. Self-binding on the payout address,
	// so it can't be gamed by pointing at someone else's balance.
	MinHoldingKRX float64 `yaml:"min_holding_krx"`
	// Block tasks are unscheduled on the pinned networks; only zero is accepted.
	BlockTaskActivationDAA uint64 `yaml:"block_task_activation_daa"`
	// MineWhenNotSynced serves work from a node that reports itself unsynced (test networks).
	MineWhenNotSynced bool `yaml:"mine_when_not_synced"`
	// SkipModelIPFSCheck accepts declared models without the IPFS weight check (test networks).
	SkipModelIPFSCheck bool `yaml:"skip_model_ipfs_check"`
}

func configureZap(cfg BridgeConfig) (*zap.SugaredLogger, func()) {
	pe := zap.NewProductionEncoderConfig()
	pe.EncodeTime = zapcore.RFC3339TimeEncoder
	fileEncoder := zapcore.NewJSONEncoder(pe)
	consoleEncoder := zapcore.NewConsoleEncoder(pe)

	if !cfg.UseLogFile {
		return zap.New(zapcore.NewCore(consoleEncoder,
			zapcore.AddSync(colorable.NewColorableStdout()), zap.InfoLevel)).Sugar(), func() {}
	}

	logFile, err := os.OpenFile("bridge.log", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		panic(err)
	}
	core := zapcore.NewTee(
		zapcore.NewCore(fileEncoder, zapcore.AddSync(logFile), zap.InfoLevel),
		zapcore.NewCore(consoleEncoder, zapcore.AddSync(colorable.NewColorableStdout()), zap.InfoLevel),
	)
	return zap.New(core).Sugar(), func() { logFile.Close() }
}

func ListenAndServe(cfg BridgeConfig) error {
	if cfg.Network == "" {
		cfg.Network = "mainnet"
	}
	if cfg.ServiceStateFile == "" {
		cfg.ServiceStateFile = "service-state.json"
	}
	if err := cfg.validate(); err != nil {
		return err
	}
	auth, err := loadWorkerAuth(cfg.WorkerAuthFile)
	if err != nil {
		return err
	}
	verifier, err := newProtocolVerifier(cfg)
	if err != nil {
		return err
	}
	defer verifier.Close()
	logger, logCleanup := configureZap(cfg)
	defer logCleanup()
	var tlsConfig *tls.Config
	if cfg.TLSCertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("cannot load Stratum TLS certificate/key: %w", err)
		}
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	}
	blockWaitTime := cfg.BlockWaitTime
	if blockWaitTime < minBlockWaitTime {
		blockWaitTime = minBlockWaitTime
	}
	ksApi, err := NewKeryxAPI(cfg.RPCServer, blockWaitTime, logger)
	if err != nil {
		return err
	}
	defer ksApi.wire.Close()
	defer ksApi.keryxd.Close()
	network, err := ksApi.wire.GetCurrentNetwork()
	if err != nil {
		return err
	}
	if network != cfg.Network {
		return fmt.Errorf("configured network differs from node network")
	}
	ksApi.escrowPubKey = verifier.identity.Pubkey
	ksApi.escrowCert = cfg.EscrowCert
	ksApi.payoutAddress = cfg.PayoutAddress
	ksApi.mineWhenNotSynced = cfg.MineWhenNotSynced
	// H15/H16 private inference is inline. Neither Kubo nor legacy claim spending
	// is started by this bridge. Existing escrow ownership remains with its key.
	shareHandler := newShareHandler(ksApi.keryxd, ksApi.wire, cfg.IPFSAPIUrl, nil)
	shareHandler.verifier = verifier
	shareHandler.models = make(map[string]bool)
	for _, model := range verifier.identity.Models {
		shareHandler.models[model.Model] = true
	}
	minDiff := cfg.MinShareDiff
	if minDiff < 1 {
		minDiff = 1
	}
	extranonceSize := cfg.ExtranonceSize
	if extranonceSize > 3 {
		extranonceSize = 3
	}
	minHolding := uint64(cfg.MinHoldingKRX * 1e8)
	shareHandler.minHoldingSompi = minHolding
	clientHandler := newClientListener(logger, shareHandler, float64(minDiff), int8(extranonceSize), nil, minHolding)
	service, err := newServiceRelay(ksApi, verifier, cfg.ServiceStateFile)
	if err != nil {
		return err
	}
	shareHandler.onCapabilities = clientHandler.sendChallengeToClient
	service.clients = clientHandler
	shareHandler.service = service
	monitor := newStrikeMonitor(cfg.RPCServer, verifier.identity.Pubkey, verifier.identity.Identity)
	shareHandler.strikes = monitor
	handlers := gostratum.DefaultHandlers()
	handlers[string(gostratum.StratumMethodAuthorize)] = secureAuthorize(cfg, auth)
	handlers[string(gostratum.StratumMethodSubmit)] = shareHandler.HandleSubmit
	handlers["mining.declare_capabilities"] = shareHandler.HandleDeclareCapabilities
	handlers["mining.challenge_response"] = shareHandler.HandleChallengeResponse
	handlers["mining.ai_response"] = service.HandleAnswer
	handlers["mining.ai_opening_result"] = service.HandleOpening
	for _, method := range []string{"mining.hello", "mining.telemetry"} {
		handlers[method] = func(ctx *gostratum.StratumContext, event gostratum.JsonRpcEvent) error {
			if !ctx.IsAuthorized() {
				return relayError(ctx, event, 24, "authorization required")
			}
			return ctx.Reply(gostratum.NewResponse(event, true, nil))
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	monitor.Start(ctx)
	service.Start(ctx)
	if cfg.PromPort != "" {
		StartPromServer(logger, cfg.PromPort)
	}
	if cfg.HealthCheckPort != "" {
		mux := http.NewServeMux()
		mux.Handle("/bridge/strikes", monitor)
		mux.Handle("/bridge/service", service)
		mux.HandleFunc("/bridge/pubkey", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"pubkey":%q,"service_identity":%q}`, verifier.identity.Pubkey, verifier.identity.Identity)
		})
		mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
			if !service.ready() || !verifier.healthy() || !monitor.snapshot().Available {
				http.Error(w, "service observation unavailable", http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
		})
		server := &http.Server{Addr: cfg.HealthCheckPort, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
		defer server.Close()
		go func() {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Errorw("health listener failed", "error", err)
			}
		}()
	}
	if err := ksApi.Start(ctx, func() { clientHandler.NewBlockAvailable(ksApi) }); err != nil {
		return err
	}
	go clientHandler.startChallengeLoop(ctx)
	if cfg.PrintStats {
		go shareHandler.startStatsThread()
	}
	return gostratum.NewListener(gostratum.StratumListenerConfig{Port: cfg.StratumPort, HandlerMap: handlers, StateGenerator: MiningStateGenerator, ClientListener: clientHandler, Logger: logger.Desugar(), TLSConfig: tlsConfig, MaxConnections: cfg.MaxConnections}).Listen(ctx)
}
