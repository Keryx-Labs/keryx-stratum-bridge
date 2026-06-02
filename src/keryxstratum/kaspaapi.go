package keryxstratum

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/kaspanet/kaspad/app/appmessage"
	"github.com/kaspanet/kaspad/infrastructure/network/rpcclient"
	"github.com/keryx-labs/keryx-stratum-bridge/src/gostratum"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type KeryxApi struct {
	address       string
	blockWaitTime time.Duration
	logger        *zap.SugaredLogger
	keryxd        *rpcclient.RPCClient
	connected     bool
	// escrowPubKey is the 64-hex Schnorr pubkey embedded in the coinbase as /escrow:<pk>.
	// It tells the node to route the 20% escrow cut to a CSV-locked output (claimable after
	// 36 000 blocks) instead of burning it. Empty = no escrow key available → cut is burned.
	escrowPubKey string
}

func NewKeryxAPI(address string, blockWaitTime time.Duration, logger *zap.SugaredLogger) (*KeryxApi, error) {
	client, err := rpcclient.NewRPCClient(address)
	if err != nil {
		return nil, err
	}

	return &KeryxApi{
		address:       address,
		blockWaitTime: blockWaitTime,
		logger:        logger.With(zap.String("component", "keryxapi:"+address)),
		keryxd:        client,
		connected:     true,
	}, nil
}

func (ks *KeryxApi) Start(ctx context.Context, blockCb func()) {
	ks.waitForSync(true)
	go ks.startBlockTemplateListener(ctx, blockCb)
	go ks.startStatsThread(ctx)
}

func (ks *KeryxApi) startStatsThread(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	for {
		select {
		case <-ctx.Done():
			ks.logger.Warn("context cancelled, stopping stats thread")
			return
		case <-ticker.C:
			dagResponse, err := ks.keryxd.GetBlockDAGInfo()
			if err != nil {
				ks.logger.Warn("failed to get network hashrate from keryx, prom stats will be out of date", zap.Error(err))
				continue
			}
			response, err := ks.keryxd.EstimateNetworkHashesPerSecond(dagResponse.TipHashes[0], 1000)
			if err != nil {
				ks.logger.Warn("failed to get network hashrate from keryx, prom stats will be out of date", zap.Error(err))
				continue
			}
			RecordNetworkStats(response.NetworkHashesPerSecond, dagResponse.BlockCount, dagResponse.Difficulty)
		}
	}
}

func (ks *KeryxApi) reconnect() error {
	if ks.keryxd != nil {
		return ks.keryxd.Reconnect()
	}

	client, err := rpcclient.NewRPCClient(ks.address)
	if err != nil {
		return err
	}
	ks.keryxd = client
	return nil
}

func (s *KeryxApi) waitForSync(verbose bool) error {
	if verbose {
		s.logger.Info("checking keryxd sync state")
	}
	for {
		clientInfo, err := s.keryxd.GetInfo()
		if err != nil {
			return errors.Wrapf(err, "error fetching server info from keryxd @ %s", s.address)
		}
		if clientInfo.IsSynced {
			break
		}
		s.logger.Warn("Keryx is not synced, waiting for sync before starting bridge")
		time.Sleep(5 * time.Second)
	}
	if verbose {
		s.logger.Info("keryxd synced, starting server")
	}
	return nil
}

func (s *KeryxApi) startBlockTemplateListener(ctx context.Context, blockReadyCb func()) {
	blockReadyChan := make(chan bool)
	err := s.keryxd.RegisterForNewBlockTemplateNotifications(func(_ *appmessage.NewBlockTemplateNotificationMessage) {
		blockReadyChan <- true
	})
	if err != nil {
		s.logger.Error("fatal: failed to register for block notifications from keryx")
	}

	ticker := time.NewTicker(s.blockWaitTime)
	for {
		if err := s.waitForSync(false); err != nil {
			s.logger.Error("error checking keryxd sync state, attempting reconnect: ", err)
			if err := s.reconnect(); err != nil {
				s.logger.Error("error reconnecting to keryxd, waiting before retry: ", err)
				time.Sleep(5 * time.Second)
			}
		}
		select {
		case <-ctx.Done():
			s.logger.Warn("context cancelled, stopping block update listener")
			return
		case <-blockReadyChan:
			blockReadyCb()
			ticker.Reset(s.blockWaitTime)
		case <-ticker.C:
			blockReadyCb()
		}
	}
}

func (ks *KeryxApi) GetBlockTemplate(
	client *gostratum.StratumContext) (*appmessage.GetBlockTemplateResponseMessage, error) {
	// OPoI: the node verifies the coinbase tag with verify_tag_fixed(nonce), so the
	// extra_data must carry "/{nonce_hex16}/ai:v1:{tag_fixed(nonce)}" — exactly like the
	// solo miner (keryx-miner/src/client/grpc.rs). A random tag without the nonce prefix
	// is rejected with "OPoI tag missing": parse_opoi needs the embedded nonce to recompute
	// and check the tag.
	b := make([]byte, 8)
	rand.Read(b)
	nonce := binary.LittleEndian.Uint64(b)
	// Route the 20% escrow cut to the bridge's CSV-locked escrow (claimed after the
	// challenge window) instead of letting the node burn it. Mirrors the solo miner.
	escrowPart := ""
	if ks.escrowPubKey != "" {
		escrowPart = "/escrow:" + ks.escrowPubKey
	}
	opoiTag := fmt.Sprintf("%s/%016x/ai:v1:%s", escrowPart, nonce, tagFixed(nonce))
	template, err := ks.keryxd.GetBlockTemplate(client.WalletAddr,
		fmt.Sprintf(`'%s' via keryx-labs/keryx-stratum-bridge_%s%s`, client.RemoteApp, version, opoiTag))
	if err != nil {
		return nil, errors.Wrap(err, "failed fetching new block template from keryx")
	}
	return template, nil
}
