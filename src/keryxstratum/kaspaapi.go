package keryxstratum

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/kaspanet/kaspad/app/appmessage"
	"github.com/kaspanet/kaspad/infrastructure/network/rpcclient"
	"github.com/keryx-labs/keryx-stratum-bridge/src/gostratum"
	"github.com/keryx-labs/keryx-stratum-bridge/src/keryxrpc"
	"github.com/keryx-labs/keryx-stratum-bridge/src/keryxrpc/keryxwire"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// BlockTemplate pairs the canonical keryxwire template (round-tripped to the node on
// submit, keeps the Keryx-only header fields) with its appmessage projection used by
// the bridge's serialization and scanning helpers.
type BlockTemplate struct {
	Block    *appmessage.RPCBlock
	Wire     *keryxwire.RpcBlock
	IsSynced bool
}

type KeryxApi struct {
	address       string
	blockWaitTime time.Duration
	logger        *zap.SugaredLogger
	keryxd        *rpcclient.RPCClient
	wire          *keryxrpc.Client
	connected     bool
	// escrowPubKey is the 64-hex Schnorr pubkey embedded in the coinbase as /escrow:<pk>.
	// It tells the node to route the 20% escrow cut to a CSV-locked output (claimable after
	// 36 000 blocks) instead of burning it. Empty = no escrow key available → cut is burned.
	escrowPubKey  string
	payoutAddress string
	// escrowCert is the 128-hex delegation cert embedded as /esig:<cert>. From H6 the node
	// rejects a template without a valid /escrow + /esig pair. Empty = no cert available.
	escrowCert string
	// seeds resolves the block task window seed of each template.
	seeds *seedResolver
	// mineWhenNotSynced serves work from a node that reports itself unsynced (test networks).
	mineWhenNotSynced bool
}

func NewKeryxAPI(address string, blockWaitTime time.Duration, logger *zap.SugaredLogger) (*KeryxApi, error) {
	client, err := rpcclient.NewRPCClient(address)
	if err != nil {
		return nil, err
	}

	api := &KeryxApi{
		address:       address,
		blockWaitTime: blockWaitTime,
		logger:        logger.With(zap.String("component", "keryxapi:"+address)),
		keryxd:        client,
		wire:          keryxrpc.NewClient(address),
		connected:     true,
	}
	api.seeds = newSeedResolver(api.wire)
	return api, nil
}

func (ks *KeryxApi) Start(ctx context.Context, blockCb func()) error {
	if err := ks.waitForSync(ctx, true); err != nil {
		return err
	}
	go ks.startBlockTemplateListener(ctx, blockCb)
	go ks.startStatsThread(ctx)
	return nil
}

func (ks *KeryxApi) startStatsThread(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
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
			if len(dagResponse.TipHashes) == 0 {
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

func (s *KeryxApi) waitForSync(ctx context.Context, verbose bool) error {
	if verbose {
		s.logger.Info("checking keryxd sync state")
	}
	for {
		clientInfo, err := s.keryxd.GetInfo()
		if err != nil {
			return errors.Wrapf(err, "error fetching server info from keryxd @ %s", s.address)
		}
		if clientInfo.IsSynced || s.mineWhenNotSynced {
			break
		}
		s.logger.Warn("Keryx is not synced, waiting for sync before starting bridge")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	if verbose {
		s.logger.Info("keryxd synced, starting server")
	}
	return nil
}

func (s *KeryxApi) startBlockTemplateListener(ctx context.Context, blockReadyCb func()) {
	blockReadyChan := make(chan bool, 1)
	err := s.keryxd.RegisterForNewBlockTemplateNotifications(func(_ *appmessage.NewBlockTemplateNotificationMessage) {
		select {
		case blockReadyChan <- true:
		default:
		}
	})
	if err != nil {
		s.logger.Error("fatal: failed to register for block notifications from keryx")
	}

	ticker := time.NewTicker(s.blockWaitTime)
	defer ticker.Stop()
	for {
		if err := s.waitForSync(ctx, false); err != nil {
			if ctx.Err() != nil {
				return
			}
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
	client *gostratum.StratumContext) (*BlockTemplate, error) {
	if !client.IsAuthorized() || client.WalletAddr != ks.payoutAddress {
		return nil, fmt.Errorf("unauthorized payout address")
	}
	template, err := ks.wire.GetBlockTemplate(ks.payoutAddress, ks.coinbaseExtra(GetMiningState(client).DeclaredModels()))
	if err != nil {
		return nil, errors.Wrap(err, "failed fetching new block template from keryx")
	}
	if template.Block == nil {
		return nil, errors.New("keryx returned an empty block template")
	}
	return &BlockTemplate{
		Block:    keryxrpc.BlockToAppMessage(template.Block),
		Wire:     template.Block,
		IsSynced: template.IsSynced,
	}, nil
}

// SubmitBlock pushes a solved block through the pom-aware client.
func (ks *KeryxApi) SubmitBlock(block *keryxwire.RpcBlock) (*keryxwire.SubmitBlockResponseMessage, error) {
	return ks.wire.SubmitBlock(block)
}

// RemoteApp and other miner-controlled strings must never precede consensus
// markers. The node uses first-marker-wins parsing for escrow and capabilities.
func (ks *KeryxApi) coinbaseExtra(models []string) string {
	b := make([]byte, 8)
	rand.Read(b)
	nonce := binary.LittleEndian.Uint64(b)
	extra := fmt.Sprintf("keryx-bridge/%s/escrow:%s/esig:%s/%016x/ai:v1:%s", version, ks.escrowPubKey, ks.escrowCert, nonce, tagFixed(nonce))
	if len(models) > 0 {
		extra += "/ai:cap:" + strings.Join(models, ",")
	}
	return extra
}
