package keryxstratum

import (
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kaspanet/kaspad/app/appmessage"
	"github.com/kaspanet/kaspad/domain/consensus/model/externalapi"
	"github.com/kaspanet/kaspad/domain/consensus/utils/consensushashing"
	"github.com/kaspanet/kaspad/infrastructure/network/rpcclient"
	"github.com/keryx-labs/keryx-stratum-bridge/src/gostratum"
	"github.com/pkg/errors"
	"go.uber.org/atomic"
	"go.uber.org/zap"
)

type WorkStats struct {
	BlocksFound   atomic.Int64
	SharesFound   atomic.Int64
	SharesDiff    atomic.Float64
	StaleShares   atomic.Int64
	InvalidShares atomic.Int64
	WorkerName    string
	StartTime     time.Time
	LastShare     time.Time
}

type shareHandler struct {
	keryxd       *rpcclient.RPCClient
	stats        map[string]*WorkStats
	statsLock    sync.Mutex
	overall      WorkStats
	tipBlueScore uint64
}

func newShareHandler(keryxd *rpcclient.RPCClient) *shareHandler {
	return &shareHandler{
		keryxd:    keryxd,
		stats:     map[string]*WorkStats{},
		statsLock: sync.Mutex{},
	}
}

func (sh *shareHandler) getCreateStats(ctx *gostratum.StratumContext) *WorkStats {
	sh.statsLock.Lock()
	var stats *WorkStats
	found := false
	if ctx.WorkerName != "" {
		stats, found = sh.stats[ctx.WorkerName]
	}
	if !found {
		stats, found = sh.stats[ctx.RemoteAddr]
		if found {
			delete(sh.stats, ctx.RemoteAddr)
			stats.WorkerName = ctx.WorkerName
			sh.stats[ctx.WorkerName] = stats
		}
	}
	if !found {
		stats = &WorkStats{}
		stats.LastShare = time.Now()
		stats.WorkerName = ctx.RemoteAddr
		stats.StartTime = time.Now()
		sh.stats[ctx.RemoteAddr] = stats
		InitWorkerCounters(ctx)
	}

	sh.statsLock.Unlock()
	return stats
}

type submitInfo struct {
	block    *appmessage.RPCBlock
	state    *MiningState
	noncestr string
	nonceVal uint64
	opoiTag  string // optional: 16-char hex tag from keryx-miner v0.2.9+, empty = not provided
	ipfsCID  string // optional: IPFS CID from keryx-miner v0.3.0+ (Phase 2 OPoI), empty = not provided
}

func validateSubmit(ctx *gostratum.StratumContext, event gostratum.JsonRpcEvent) (*submitInfo, error) {
	if len(event.Params) < 3 {
		RecordWorkerError(ctx.WalletAddr, ErrBadDataFromMiner)
		return nil, fmt.Errorf("malformed event, expected at least 2 params")
	}
	jobIdStr, ok := event.Params[1].(string)
	if !ok {
		RecordWorkerError(ctx.WalletAddr, ErrBadDataFromMiner)
		return nil, fmt.Errorf("unexpected type for param 1: %+v", event.Params...)
	}
	jobId, err := strconv.ParseInt(jobIdStr, 10, 0)
	if err != nil {
		RecordWorkerError(ctx.WalletAddr, ErrBadDataFromMiner)
		return nil, errors.Wrap(err, "job id is not parsable as an number")
	}
	state := GetMiningState(ctx)
	block, exists := state.GetJob(int(jobId))
	if !exists {
		RecordWorkerError(ctx.WalletAddr, ErrMissingJob)
		return nil, fmt.Errorf("job does not exist. stale?")
	}
	noncestr, ok := event.Params[2].(string)
	if !ok {
		RecordWorkerError(ctx.WalletAddr, ErrBadDataFromMiner)
		return nil, fmt.Errorf("unexpected type for param 2: %+v", event.Params...)
	}
	// Optional 4th param: OPoI tag sent by keryx-miner v0.2.9+ (backward compatible)
	var opoiTag string
	if len(event.Params) >= 4 {
		if tag, ok := event.Params[3].(string); ok {
			opoiTag = tag
		}
	}

	// Optional 5th param: IPFS CID sent by keryx-miner v0.3.0+ (Phase 2 OPoI)
	var ipfsCID string
	if len(event.Params) >= 5 {
		if cid, ok := event.Params[4].(string); ok {
			ipfsCID = cid
		}
	}

	return &submitInfo{
		state:    state,
		block:    block,
		noncestr: strings.Replace(noncestr, "0x", "", 1),
		opoiTag:  opoiTag,
		ipfsCID:  ipfsCID,
	}, nil
}

var (
	ErrStaleShare = fmt.Errorf("stale share")
	ErrDupeShare  = fmt.Errorf("duplicate share")
)

const workWindow = 8

func (sh *shareHandler) checkStales(ctx *gostratum.StratumContext, si *submitInfo) error {
	tip := sh.tipBlueScore
	if si.block.Header.BlueScore > tip {
		sh.tipBlueScore = si.block.Header.BlueScore
		return nil
	}
	if tip-si.block.Header.BlueScore > workWindow {
		RecordStaleShare(ctx)
		return errors.Wrapf(ErrStaleShare, "blueScore %d vs %d", si.block.Header.BlueScore, tip)
	}
	return nil
}

func (sh *shareHandler) HandleSubmit(ctx *gostratum.StratumContext, event gostratum.JsonRpcEvent) error {
	submitInfo, err := validateSubmit(ctx, event)
	if err != nil {
		return err
	}

	if ctx.Extranonce != "" {
		extranonce2Len := 16 - len(ctx.Extranonce)
		if len(submitInfo.noncestr) <= extranonce2Len {
			submitInfo.noncestr = ctx.Extranonce + fmt.Sprintf("%0*s", extranonce2Len, submitInfo.noncestr)
		}
	}

	state := GetMiningState(ctx)
	if state.useBigJob {
		submitInfo.nonceVal, err = strconv.ParseUint(submitInfo.noncestr, 16, 64)
		if err != nil {
			RecordWorkerError(ctx.WalletAddr, ErrBadDataFromMiner)
			return errors.Wrap(err, "failed parsing noncestr")
		}
	} else {
		submitInfo.nonceVal, err = strconv.ParseUint(submitInfo.noncestr, 16, 64)
		if err != nil {
			RecordWorkerError(ctx.WalletAddr, ErrBadDataFromMiner)
			return errors.Wrap(err, "failed parsing noncestr")
		}
	}
	stats := sh.getCreateStats(ctx)

	converted, err := appmessage.RPCBlockToDomainBlock(submitInfo.block)
	if err != nil {
		return fmt.Errorf("failed to cast block to mutable block: %+v", err)
	}
	mutableHeader := converted.Header.ToMutable()
	mutableHeader.SetNonce(submitInfo.nonceVal)

	// KeryxHash PoW verification — replaces Kaspa's pow.NewState which uses
	// KHeavyHash (no wave_mix, no KERYX_MATRIX_SALT) and would silently drop
	// every valid Keryx block found by stratum miners.
	prePowHashBytes, err := SerializeBlockHeader(submitInfo.block)
	if err != nil {
		return fmt.Errorf("failed to serialize block header for PoW: %+v", err)
	}
	var prePowHash [32]byte
	copy(prePowHash[:], prePowHashBytes)
	powValue := CalculateKeryxPoW(prePowHash, uint64(submitInfo.block.Header.Timestamp), submitInfo.nonceVal, uint64(submitInfo.block.Header.DAAScore))
	target := CalculateTarget(uint64(submitInfo.block.Header.Bits))

	// Every share must carry an OPoI tag proving the miner ran tag_fixed(nonce).
	// No tag = no inference = no mining.
	if submitInfo.opoiTag == "" {
		RecordWorkerError(ctx.WalletAddr, ErrBadDataFromMiner)
		ctx.Logger.Warn("OPoI tag missing — no inference = no mining, rejecting share",
			zap.String("nonce", submitInfo.noncestr),
			zap.String("miner", ctx.WalletAddr))
		sh.getCreateStats(ctx).InvalidShares.Add(1)
		sh.overall.InvalidShares.Add(1)
		RecordInvalidShare(ctx)
		return ctx.ReplyBadShare(event.Id)
	}
	if !verifyOPoITag(submitInfo.nonceVal, submitInfo.opoiTag) {
		RecordWorkerError(ctx.WalletAddr, ErrBadDataFromMiner)
		ctx.Logger.Warn("OPoI tag mismatch — miner skipped inference",
			zap.String("nonce", submitInfo.noncestr),
			zap.String("expected", tagFixed(submitInfo.nonceVal)),
			zap.String("got", submitInfo.opoiTag))
		sh.getCreateStats(ctx).InvalidShares.Add(1)
		sh.overall.InvalidShares.Add(1)
		RecordInvalidShare(ctx)
		return ctx.ReplyBadShare(event.Id)
	}

	// Miner included an IPFS CID — inference is complete. Publish the AiResponse TX on-chain.
	if submitInfo.ipfsCID != "" {
		ctx.Logger.Info("OPoI inference result received",
			zap.String("cid", submitInfo.ipfsCID),
			zap.String("miner", ctx.WalletAddr))
		RecordInferenceResult(ctx)
		if task := scanBlockForAiTask(submitInfo.block); task != nil {
			go SubmitAiResponseTX(sh.keryxd, ctx.Logger, task.RequestHash,
				uint64(submitInfo.block.Header.DAAScore), submitInfo.ipfsCID)
		}
	}

	if powValue.Cmp(&target) <= 0 {
		if err := sh.submit(ctx, converted, submitInfo.nonceVal, event.Id); err != nil {
			return err
		}
	}

	stats.SharesFound.Add(1)
	stats.SharesDiff.Add(state.stratumDiff.hashValue)
	stats.LastShare = time.Now()
	sh.overall.SharesFound.Add(1)
	RecordShareFound(ctx, state.stratumDiff.hashValue)

	return ctx.Reply(gostratum.JsonRpcResponse{
		Id:     event.Id,
		Result: true,
	})
}

func (sh *shareHandler) submit(ctx *gostratum.StratumContext,
	block *externalapi.DomainBlock, nonce uint64, eventId any) error {
	mutable := block.Header.ToMutable()
	mutable.SetNonce(nonce)
	block = &externalapi.DomainBlock{
		Header:       mutable.ToImmutable(),
		Transactions: block.Transactions,
	}
	_, err := sh.keryxd.SubmitBlock(block)
	blockhash := consensushashing.BlockHash(block)
	ctx.Logger.Info(fmt.Sprintf("Submitted block %s", blockhash))

	if err != nil {
		if strings.Contains(err.Error(), "ErrDuplicateBlock") {
			ctx.Logger.Warn("block rejected, stale")
			sh.getCreateStats(ctx).StaleShares.Add(1)
			sh.overall.StaleShares.Add(1)
			RecordStaleShare(ctx)
			return ctx.ReplyStaleShare(eventId)
		} else {
			ctx.Logger.Warn("block rejected, unknown issue (probably bad pow", zap.Error(err))
			sh.getCreateStats(ctx).InvalidShares.Add(1)
			sh.overall.InvalidShares.Add(1)
			RecordInvalidShare(ctx)
			return ctx.ReplyBadShare(eventId)
		}
	}

	ctx.Logger.Info(fmt.Sprintf("block accepted %s", blockhash))
	stats := sh.getCreateStats(ctx)
	stats.BlocksFound.Add(1)
	sh.overall.BlocksFound.Add(1)
	RecordBlockFound(ctx, block.Header.Nonce(), block.Header.BlueScore(), blockhash.String())

	return nil
}

func (sh *shareHandler) startStatsThread() error {
	start := time.Now()
	for {
		time.Sleep(10 * time.Second)
		sh.statsLock.Lock()
		str := "\n===============================================================================\n"
		str += "  worker name   |  avg hashrate  |   acc/stl/inv  |    blocks    |    uptime   \n"
		str += "-------------------------------------------------------------------------------\n"
		var lines []string
		totalRate := float64(0)
		for _, v := range sh.stats {
			rate := GetAverageHashrateGHs(v)
			totalRate += rate
			rateStr := fmt.Sprintf("%0.2fGH/s", rate)
			ratioStr := fmt.Sprintf("%d/%d/%d", v.SharesFound.Load(), v.StaleShares.Load(), v.InvalidShares.Load())
			lines = append(lines, fmt.Sprintf(" %-15s| %14.14s | %14.14s | %12d | %11s",
				v.WorkerName, rateStr, ratioStr, v.BlocksFound.Load(), time.Since(v.StartTime).Round(time.Second)))
		}
		sort.Strings(lines)
		str += strings.Join(lines, "\n")
		rateStr := fmt.Sprintf("%0.2fGH/s", totalRate)
		ratioStr := fmt.Sprintf("%d/%d/%d", sh.overall.SharesFound.Load(), sh.overall.StaleShares.Load(), sh.overall.InvalidShares.Load())
		str += "\n-------------------------------------------------------------------------------\n"
		str += fmt.Sprintf("                | %14.14s | %14.14s | %12d | %11s",
			rateStr, ratioStr, sh.overall.BlocksFound.Load(), time.Since(start).Round(time.Second))
		str += "\n========================================================== keryx_bridge_" + version + " ===\n"
		sh.statsLock.Unlock()
		log.Println(str)
	}
}

func GetAverageHashrateGHs(stats *WorkStats) float64 {
	return stats.SharesDiff.Load() / time.Since(stats.StartTime).Seconds()
}

// HandleDeclareCapabilities stores the SLM model IDs declared by a pool miner.
// The bridge uses these to challenge the miner with a model it actually has loaded.
func (sh *shareHandler) HandleDeclareCapabilities(ctx *gostratum.StratumContext, event gostratum.JsonRpcEvent) error {
	var models []string
	for _, p := range event.Params {
		if id, ok := p.(string); ok && len(id) == 64 {
			models = append(models, id)
		}
	}
	if len(models) == 0 {
		ctx.Logger.Warn("OPoI declare_capabilities: no valid model IDs received")
		return nil
	}
	state := GetMiningState(ctx)
	state.challengeLock.Lock()
	state.declaredModels = models
	state.challengeLock.Unlock()
	ctx.Logger.Info("OPoI declare_capabilities: miner declared models",
		zap.Int("count", len(models)),
		zap.String("first", models[0][:8]),
		zap.String("miner", ctx.WalletAddr))
	return nil
}

// HandleChallengeResponse processes a mining.challenge_response from a pool miner.
// Params: [model_id_hex, result_text] — result_text is the SLM inference output.
func (sh *shareHandler) HandleChallengeResponse(ctx *gostratum.StratumContext, event gostratum.JsonRpcEvent) error {
	if len(event.Params) < 2 {
		ctx.Logger.Warn("OPoI challenge_response: malformed event, expected 2 params")
		return nil
	}
	modelIDHex, _ := event.Params[0].(string)
	resultText, _ := event.Params[1].(string)

	state := GetMiningState(ctx)
	state.challengeLock.Lock()
	defer state.challengeLock.Unlock()

	if state.activeChallengeNonce == "" {
		ctx.Logger.Warn("OPoI challenge_response: no active challenge for this miner")
		return nil
	}
	if modelIDHex != state.activeChallengeModel {
		ctx.Logger.Warn("OPoI challenge_response: model mismatch",
			zap.String("expected", state.activeChallengeModel[:8]),
			zap.String("got", func() string {
				if len(modelIDHex) >= 8 {
					return modelIDHex[:8]
				}
				return modelIDHex
			}()))
		return nil
	}

	if resultText == "" {
		ctx.Logger.Warn("OPoI challenge_response: empty result — no inference = no mining, disconnecting",
			zap.String("model", modelIDHex[:8]),
			zap.String("miner", ctx.WalletAddr))
		state.activeChallengeNonce = ""
		ctx.Disconnect()
		return nil
	}

	ctx.Logger.Info("OPoI challenge_response: PASSED",
		zap.String("model", modelIDHex[:8]),
		zap.Int("result_len", len(resultText)),
		zap.String("miner", ctx.WalletAddr))
	state.challengePassed = true
	state.activeChallengeNonce = ""
	RecordOPoIChallengePass(ctx)
	return nil
}
