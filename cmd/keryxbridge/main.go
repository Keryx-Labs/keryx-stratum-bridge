package main

import (
	"flag"
	"github.com/keryx-labs/keryx-stratum-bridge/src/keryxstratum"
	"gopkg.in/yaml.v2"
	"log"
	"os"
	"path/filepath"
	"time"
)

func main() {
	configPath := flag.String("config", "config.yaml", "configuration file")
	stratum := flag.String("stratum", "", "Stratum listen address")
	node := flag.String("keryxd", "", "local node RPC address")
	prom := flag.String("prom", "", "loopback metrics address")
	health := flag.String("hcp", "", "loopback health/status address")
	stats := flag.Bool("stats", true, "print worker and escrow service standing")
	logfile := flag.Bool("log", false, "append logs to bridge.log")
	blockwait := flag.Duration("blockwait", 500*time.Millisecond, "minimum template refresh interval")
	mindiff := flag.Uint("mindiff", 4, "share difficulty")
	extranonce := flag.Uint("extranonce", 0, "extranonce size in bytes")
	flag.Parse()
	absolute, err := filepath.Abs(*configPath)
	if err != nil {
		log.Fatal("invalid config path")
	}
	raw, err := os.ReadFile(absolute)
	if err != nil {
		log.Fatal("cannot read config file")
	}
	cfg := keryxstratum.BridgeConfig{Network: "mainnet", StratumPort: "127.0.0.1:5555", RPCServer: "127.0.0.1:22110", BlockWaitTime: 500 * time.Millisecond, MinShareDiff: 4, MaxConnections: 128}
	if err = yaml.UnmarshalStrict(raw, &cfg); err != nil {
		log.Fatalf("invalid configuration: %s", err)
	}
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "stratum":
			cfg.StratumPort = *stratum
		case "keryxd":
			cfg.RPCServer = *node
		case "prom":
			cfg.PromPort = *prom
		case "hcp":
			cfg.HealthCheckPort = *health
		case "stats":
			cfg.PrintStats = *stats
		case "log":
			cfg.UseLogFile = *logfile
		case "blockwait":
			cfg.BlockWaitTime = *blockwait
		case "mindiff":
			cfg.MinShareDiff = *mindiff
		case "extranonce":
			cfg.ExtranonceSize = *extranonce
		}
	})
	base := filepath.Dir(absolute)
	for _, path := range []*string{&cfg.EscrowKeyFile, &cfg.WorkerAuthFile, &cfg.VerifierBinary, &cfg.ServiceStateFile, &cfg.TLSCertFile, &cfg.TLSKeyFile} {
		if *path != "" && !filepath.IsAbs(*path) {
			*path = filepath.Join(base, *path)
		}
	}
	if cfg.ServiceStateFile == "" {
		cfg.ServiceStateFile = filepath.Join(base, "service-state.json")
	}
	if err = keryxstratum.ListenAndServe(cfg); err != nil {
		log.Fatal(err)
	}
}
