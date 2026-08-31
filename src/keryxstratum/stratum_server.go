package keryxstratum

import (
	"context"
	"net/http"
	_ "net/http/pprof"
	"os"
	"time"

	"github.com/mattn/go-colorable"
	"github.com/keryx-labs/keryx-stratum-bridge/src/gostratum"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const version = "v1.1.6"
const minBlockWaitTime = 500 * time.Millisecond

type BridgeConfig struct {
	StratumPort     string        `yaml:"stratum_port"`
	RPCServer       string        `yaml:"keryxd_address"`
	PromPort        string        `yaml:"prom_port"`
	PrintStats      bool          `yaml:"print_stats"`
	UseLogFile      bool          `yaml:"log_to_file"`
	HealthCheckPort string        `yaml:"health_check_port"`
	BlockWaitTime   time.Duration `yaml:"block_wait_time"`
	MinShareDiff    uint          `yaml:"min_share_diff"`
	ExtranonceSize  uint          `yaml:"extranonce_size"`
	// IPFS API endpoint used to verify miner-submitted CIDs before publishing AiResponse TXs.
	// Defaults to http://127.0.0.1:5001 if empty.
	IPFSAPIUrl string `yaml:"ipfs_api_url"`
	// IPFSBinary is the kubo binary to auto-start when the (local) IPFS API is down at
	// startup. Empty = look next to the bridge executable, then in PATH.
	IPFSBinary string `yaml:"ipfs_binary"`
	// EscrowCert is the 128-hex H6 delegation cert announced as /esig:<cert>. It binds the
	// bridge's escrow key to ONE payout address (produced by `keryx-cli delegate-escrow`),
	// so every worker must mine with that exact address. Single-address setups only.
	EscrowCert string `yaml:"escrow_cert"`
	// EscrowKeyFile is the path to the 64-char hex Schnorr private key file used to claim
	// inference_reward escrows.  Defaults to "escrow.key" (same file as keryx-miner).
	// Leave unset to use the default; set to "" to disable escrow claiming.
	// The corresponding pubkey is logged at startup so requesters know which key to use.
	EscrowKeyFile string `yaml:"escrow_key_file"`
	// MinHoldingKRX is the balance-reward gate: a worker whose payout address holds fewer than
	// this many KRX is not dispatched jobs (no holdings = no mining in this pool). This forces
	// pool workers to hold KRX too — not just the pool operator — closing the "flee to a pool to
	// dodge holding" loophole. 0 (default) disables the gate. Self-binding on the payout address,
	// so it can't be gamed by pointing at someone else's balance.
	MinHoldingKRX float64 `yaml:"min_holding_krx"`
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

	logFile, err := os.OpenFile("bridge.log", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0666)
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
	logger, logCleanup := configureZap(cfg)
	defer logCleanup()

	if cfg.PromPort != "" {
		StartPromServer(logger, cfg.PromPort)
	}

	// Model verification (declare_capabilities) needs the IPFS API from the very first
	// miner connection — bring the local daemon up before serving.
	ensureIPFSDaemon(logger, effectiveIPFSURL(cfg.IPFSAPIUrl), cfg.IPFSBinary)

	blockWaitTime := cfg.BlockWaitTime
	if blockWaitTime < minBlockWaitTime {
		blockWaitTime = minBlockWaitTime
	}
	ksApi, err := NewKeryxAPI(cfg.RPCServer, blockWaitTime, logger)
	if err != nil {
		return err
	}

	escrowStore := NewEscrowStore(ksApi.keryxd, logger.Desugar())
	if escrowStore != nil {
		// Embed this key in every coinbase so the 20% escrow cut is recoverable, not burned.
		ksApi.escrowPubKey = escrowStore.PubKeyHex()
	}
	// H6 delegation cert (/esig:) binding the escrow key to the single payout address.
	ksApi.escrowCert = cfg.EscrowCert
	if cfg.EscrowCert == "" {
		logger.Warn("no escrow_cert configured — the node rejects every template past H6 (mining requires an escrow delegation)")
	}

	if cfg.HealthCheckPort != "" {
		logger.Info("enabling health check on port " + cfg.HealthCheckPort)
		http.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		http.HandleFunc("/bridge/pubkey", func(w http.ResponseWriter, r *http.Request) {
			if escrowStore == nil {
				http.Error(w, `{"error":"escrow key not loaded"}`, http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"pubkey":"` + escrowStore.PubKeyHex() + `"}`))
		})
		go http.ListenAndServe(cfg.HealthCheckPort, nil)
	}
	shareHandler := newShareHandler(ksApi.keryxd, ksApi.wire, cfg.IPFSAPIUrl, escrowStore)
	minDiff := cfg.MinShareDiff
	if minDiff < 1 {
		minDiff = 1
	}
	extranonceSize := cfg.ExtranonceSize
	if extranonceSize > 3 {
		extranonceSize = 3
	}
	minHoldingSompi := uint64(cfg.MinHoldingKRX * 1e8)
	clientHandler := newClientListener(logger, shareHandler, float64(minDiff), int8(extranonceSize), escrowStore, minHoldingSompi)
	handlers := gostratum.DefaultHandlers()
	handlers[string(gostratum.StratumMethodSubmit)] =
		func(ctx *gostratum.StratumContext, event gostratum.JsonRpcEvent) error {
			if err := shareHandler.HandleSubmit(ctx, event); err != nil {
				ctx.Logger.Sugar().Error(err)
			}
			return nil
		}
	handlers["mining.declare_capabilities"] =
		func(ctx *gostratum.StratumContext, event gostratum.JsonRpcEvent) error {
			if err := shareHandler.HandleDeclareCapabilities(ctx, event); err != nil {
				ctx.Logger.Sugar().Error(err)
			}
			return nil
		}
	handlers["mining.challenge_response"] =
		func(ctx *gostratum.StratumContext, event gostratum.JsonRpcEvent) error {
			if err := shareHandler.HandleChallengeResponse(ctx, event); err != nil {
				ctx.Logger.Sugar().Error(err)
			}
			return nil
		}

	stratumConfig := gostratum.StratumListenerConfig{
		Port:           cfg.StratumPort,
		HandlerMap:     handlers,
		StateGenerator: MiningStateGenerator,
		ClientListener: clientHandler,
		Logger:         logger.Desugar(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	escrowStore.Start(ctx)
	ksApi.Start(ctx, func() {
		clientHandler.NewBlockAvailable(ksApi)
	})
	go clientHandler.startChallengeLoop(ctx)

	if cfg.PrintStats {
		go shareHandler.startStatsThread()
	}

	return gostratum.NewListener(stratumConfig).Listen(context.Background())
}
