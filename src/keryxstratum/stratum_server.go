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
	// EscrowKeyFile is the path to the 64-char hex Schnorr private key file used to claim
	// inference_reward escrows.  Defaults to "escrow.key" (same file as keryx-miner).
	// Leave unset to use the default; set to "" to disable escrow claiming.
	// The corresponding pubkey is logged at startup so requesters know which key to use.
	EscrowKeyFile string `yaml:"escrow_key_file"`
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

	blockWaitTime := cfg.BlockWaitTime
	if blockWaitTime < minBlockWaitTime {
		blockWaitTime = minBlockWaitTime
	}
	ksApi, err := NewKeryxAPI(cfg.RPCServer, blockWaitTime, logger)
	if err != nil {
		return err
	}

	if cfg.HealthCheckPort != "" {
		logger.Info("enabling health check on port " + cfg.HealthCheckPort)
		http.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		go http.ListenAndServe(cfg.HealthCheckPort, nil)
	}

	escrowStore := NewEscrowStore(ksApi.keryxd, logger.Desugar())
	shareHandler := newShareHandler(ksApi.keryxd, cfg.IPFSAPIUrl, escrowStore)
	minDiff := cfg.MinShareDiff
	if minDiff < 1 {
		minDiff = 1
	}
	extranonceSize := cfg.ExtranonceSize
	if extranonceSize > 3 {
		extranonceSize = 3
	}
	clientHandler := newClientListener(logger, shareHandler, float64(minDiff), int8(extranonceSize), escrowStore)
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
