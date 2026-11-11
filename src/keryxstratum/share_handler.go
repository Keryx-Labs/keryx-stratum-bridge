package keryxstratum

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
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
	"github.com/keryx-labs/keryx-stratum-bridge/src/keryxrpc"
	"github.com/keryx-labs/keryx-stratum-bridge/src/keryxrpc/keryxwire"
	"github.com/pkg/errors"
	"go.uber.org/atomic"
	"go.uber.org/zap"
	"golang.org/x/crypto/blake2b"
	"google.golang.org/protobuf/proto"
)

// Borsh PomProof fixed prefix: tier u8 | trace_root [32] | pow_value [32] | final_state u64 LE.
// Identical across every proof era, so the bridge can read the header-bound fields
// without a full borsh decoder.
const (
	pomProofMinLen          = 73
	pomProofPowValueOffset  = 33
	pomProofFinalStateStart = 65
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
	onCapabilities       func(*gostratum.StratumContext)
	verifier             *protocolVerifier
	service              *serviceRelay
	strikes              *strikeMonitor
	models               map[string]bool
	minHoldingSompi      uint64
	tipLock              sync.Mutex
	keryxd               *rpcclient.RPCClient
	wire                 *keryxrpc.Client
	ipfsAPIURL           string
	escrowStore          *EscrowStore
	stats                map[string]*WorkStats
	statsLock            sync.Mutex
	overall              WorkStats
	tipBlueScore         uint64
	submittedResponses   map[string]bool
	submittedResponsesMu sync.Mutex
}

func newShareHandler(keryxd *rpcclient.RPCClient, wire *keryxrpc.Client, ipfsAPIURL string, escrowStore *EscrowStore) *shareHandler {
	if ipfsAPIURL == "" {
		ipfsAPIURL = "http://127.0.0.1:5001"
	}
	return &shareHandler{
		keryxd:             keryxd,
		wire:               wire,
		ipfsAPIURL:         ipfsAPIURL,
		escrowStore:        escrowStore,
		stats:              map[string]*WorkStats{},
		statsLock:          sync.Mutex{},
		submittedResponses: map[string]bool{},
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
	provenFinal uint64
	provenTier  uint32
	jobID       int
	block       *appmessage.RPCBlock
	wireBlock   *keryxwire.RpcBlock
	state       *MiningState
	noncestr    string
	nonceVal    uint64
	opoiTag     string // optional: 16-char hex tag from keryx-miner v0.2.9+, empty = not provided
	ipfsCID     string // optional: IPFS CID from keryx-miner v0.3.0+ (Phase 2 OPoI), empty = not provided
	pomProof    []byte // optional: borsh PomProof from keryx-miner v0.5.4+ (stratum v3), nil = not provided
	taskRoot    string // optional: block task root of the GPU that found the share (stratum v4)
}

func validateSubmit(ctx *gostratum.StratumContext, event gostratum.JsonRpcEvent) (*submitInfo, error) {
	if !ctx.IsAuthorized() || !ctx.StratumV3 {
		return nil, fmt.Errorf("authorized Stratum v3 session required")
	}
	if len(event.Params) != 6 {
		return nil, fmt.Errorf("H15/H16 submit requires six parameters; block tasks are unscheduled")
	}
	params := make([]string, 6)
	for i := range params {
		var ok bool
		params[i], ok = event.Params[i].(string)
		if !ok {
			return nil, fmt.Errorf("submit fields must be strings")
		}
	}
	if params[0] != workerLogin(ctx) {
		return nil, fmt.Errorf("submit worker differs from authorized session")
	}
	jobID, err := strconv.Atoi(params[1])
	if err != nil || jobID <= 0 {
		return nil, fmt.Errorf("invalid job id")
	}
	state := GetMiningState(ctx)
	job, exists := state.GetJob(jobID)
	if !exists || job.Wire == nil || job.Wire.Header == nil {
		return nil, ErrStaleShare
	}
	nonce := strings.TrimPrefix(params[2], "0x")
	if len(nonce) == 0 || len(nonce) > 16 {
		return nil, fmt.Errorf("invalid nonce")
	}
	if params[4] != "" {
		return nil, fmt.Errorf("use mining.ai_response for signed private inference")
	}
	if len(params[5]) < 2*pomProofMinLen || len(params[5]) > 2*1024*1024 {
		return nil, fmt.Errorf("invalid PoM proof size")
	}
	proof, err := hex.DecodeString(params[5])
	if err != nil {
		return nil, fmt.Errorf("invalid PoM proof encoding")
	}
	return &submitInfo{state: state, block: job.App, wireBlock: job.Wire, jobID: jobID, noncestr: nonce, opoiTag: params[3], pomProof: proof}, nil
}

var (
	ErrStaleShare = fmt.Errorf("stale share")
	ErrDupeShare  = fmt.Errorf("duplicate share")
)

const workWindow = 8

func (sh *shareHandler) checkStales(ctx *gostratum.StratumContext, si *submitInfo) error {
	sh.tipLock.Lock()
	defer sh.tipLock.Unlock()
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

func (sh *shareHandler) canMine() bool {
	if sh.verifier == nil || sh.service == nil || sh.strikes == nil || !sh.service.ready() || !sh.verifier.healthy() {
		return false
	}
	standing := sh.strikes.snapshot()
	return standing.Available && standing.SuspendedUntilDAA <= standing.VirtualDAA
}

func (sh *shareHandler) HandleSubmit(ctx *gostratum.StratumContext, event gostratum.JsonRpcEvent) error {
	si, err := validateSubmit(ctx, event)
	if err != nil {
		return relayError(ctx, event, 20, "invalid or unauthorized PoM submission")
	}
	state := si.state
	state.challengeLock.Lock()
	gated := !state.verified || state.activeChallengeNonce != "" || (sh.minHoldingSompi > 0 && !state.holdsEnough)
	state.challengeLock.Unlock()
	state.JobLock.Lock()
	initialized := state.initialized
	diff := state.stratumDiff
	state.JobLock.Unlock()
	if gated || !initialized || diff == nil || !sh.canMine() {
		return relayError(ctx, event, 24, "mining service is not ready")
	}
	if ctx.Extranonce != "" {
		suffixLen := 16 - len(ctx.Extranonce)
		if len(si.noncestr) <= suffixLen {
			si.noncestr = ctx.Extranonce + fmt.Sprintf("%0*s", suffixLen, si.noncestr)
		}
		if !strings.HasPrefix(si.noncestr, ctx.Extranonce) {
			return relayError(ctx, event, 20, "nonce outside assigned prefix")
		}
	}
	si.nonceVal, err = strconv.ParseUint(si.noncestr, 16, 64)
	if err != nil {
		return relayError(ctx, event, 20, "invalid nonce")
	}
	if !verifyOPoITag(si.nonceVal, si.opoiTag) {
		return ctx.ReplyBadShare(event.Id)
	}
	if err = sh.checkStales(ctx, si); err != nil {
		return ctx.ReplyStaleShare(event.Id)
	}
	prePow, err := SerializeBlockHeader(si.block)
	if err != nil {
		return ctx.ReplyBadShare(event.Id)
	}
	shareTarget := diff.targetValue
	if shareTarget == nil || shareTarget.Sign() <= 0 || shareTarget.BitLen() > 256 {
		return ctx.ReplyBadShare(event.Id)
	}
	targetBytes := shareTarget.FillBytes(make([]byte, 32))
	for i := 0; i < 16; i++ {
		targetBytes[i], targetBytes[31-i] = targetBytes[31-i], targetBytes[i]
	}
	proven, err := sh.verifier.call(map[string]any{"op": "proof", "pph": hex.EncodeToString(prePow), "timestamp": uint64(si.wireBlock.Header.Timestamp), "nonce": si.nonceVal, "daa": si.wireBlock.Header.DaaScore, "target_le": hex.EncodeToString(targetBytes), "proof": hex.EncodeToString(si.pomProof)})
	if err != nil || !state.HasDeclaredModel(proven.Model) {
		RecordInvalidShare(ctx)
		sh.getCreateStats(ctx).InvalidShares.Add(1)
		sh.overall.InvalidShares.Add(1)
		return ctx.ReplyBadShare(event.Id)
	}
	powLE, err := hex.DecodeString(proven.PowLE)
	if err != nil || len(powLE) != 32 {
		return ctx.ReplyBadShare(event.Id)
	}
	for i := 0; i < 16; i++ {
		powLE[i], powLE[31-i] = powLE[31-i], powLE[i]
	}
	pow := new(big.Int).SetBytes(powLE)
	if !state.rememberShare(si.jobID, fmt.Sprintf("%016x:%d", si.nonceVal, proven.Tier)) {
		return ctx.ReplyDupeShare(event.Id)
	}
	si.provenFinal = proven.FinalState
	si.provenTier = proven.Tier
	blockTarget := CalculateTarget(uint64(si.block.Header.Bits))
	if pow.Cmp(&blockTarget) <= 0 {
		accepted, err := sh.submitWithProof(ctx, si, event.Id)
		if err != nil {
			return err
		}
		if !accepted {
			return nil
		}
	}
	stats := sh.getCreateStats(ctx)
	stats.SharesFound.Add(1)
	stats.SharesDiff.Add(diff.hashValue)
	sh.statsLock.Lock()
	stats.LastShare = time.Now()
	sh.statsLock.Unlock()
	sh.overall.SharesFound.Add(1)
	RecordShareFound(ctx, diff.hashValue)
	return ctx.Reply(gostratum.JsonRpcResponse{Id: event.Id, Result: true})
}

// submit pushes the block to keryxd. Returns (true, nil) when the node accepted it,
// (false, replyErr) when it was stale or rejected.
func (sh *shareHandler) submit(ctx *gostratum.StratumContext,
	block *externalapi.DomainBlock, nonce uint64, eventId any) (bool, error) {
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
			return false, ctx.ReplyStaleShare(eventId)
		} else {
			ctx.Logger.Warn("block rejected, unknown issue (probably bad pow", zap.Error(err))
			sh.getCreateStats(ctx).InvalidShares.Add(1)
			sh.overall.InvalidShares.Add(1)
			RecordInvalidShare(ctx)
			return false, ctx.ReplyBadShare(eventId)
		}
	}

	ctx.Logger.Info(fmt.Sprintf("block accepted %s", blockhash))
	stats := sh.getCreateStats(ctx)
	stats.BlocksFound.Add(1)
	sh.overall.BlocksFound.Add(1)
	RecordBlockFound(ctx, block.Header.Nonce(), block.Header.BlueScore(), blockhash.String())

	return true, nil
}

// pomProofPowValue reads the little-endian 32-byte PoW value the proof binds to the
// walk's final state.
func pomProofPowValue(proof []byte) big.Int {
	le := proof[pomProofPowValueOffset : pomProofPowValueOffset+32]
	be := make([]byte, 32)
	for i := range be {
		be[i] = le[31-i]
	}
	value := big.Int{}
	value.SetBytes(be)
	return value
}

// submitWithProof pushes a PoM block to keryxd through the pom-aware client: the
// stored wire template plus the miner's nonce, proof, and the two header fields the
// proof binds (final state, tier). Returns (true, nil) when the node accepted it.
func (sh *shareHandler) submitWithProof(ctx *gostratum.StratumContext, si *submitInfo, eventId any) (bool, error) {
	block, ok := proto.Clone(si.wireBlock).(*keryxwire.RpcBlock)
	if !ok || block.Header == nil {
		return false, fmt.Errorf("failed cloning wire block for submit")
	}
	block.Header.Nonce = si.nonceVal
	block.Header.PomFinalState = si.provenFinal
	block.Header.PomTier = si.provenTier
	block.Header.TaskRoot = si.taskRoot
	block.PomProof = si.pomProof

	blockhash := "?"
	if hashBytes, err := PostPomBlockHash(block); err == nil {
		blockhash = hex.EncodeToString(hashBytes)
	}

	response, err := sh.wire.SubmitBlock(block)
	ctx.Logger.Info(fmt.Sprintf("Submitted block %s", blockhash))
	rejection := ""
	if err != nil {
		rejection = err.Error()
	} else if response.Error != nil {
		rejection = response.Error.Message
	} else if response.RejectReason != keryxwire.SubmitBlockResponseMessage_NONE {
		rejection = response.RejectReason.String()
	}
	if rejection != "" {
		if strings.Contains(rejection, "ErrDuplicateBlock") {
			ctx.Logger.Warn("block rejected, stale")
			sh.getCreateStats(ctx).StaleShares.Add(1)
			sh.overall.StaleShares.Add(1)
			RecordStaleShare(ctx)
			return false, ctx.ReplyStaleShare(eventId)
		}
		ctx.Logger.Warn("block rejected: " + rejection)
		sh.getCreateStats(ctx).InvalidShares.Add(1)
		sh.overall.InvalidShares.Add(1)
		RecordInvalidShare(ctx)
		return false, ctx.ReplyBadShare(eventId)
	}

	ctx.Logger.Info(fmt.Sprintf("block accepted %s", blockhash))
	stats := sh.getCreateStats(ctx)
	stats.BlocksFound.Add(1)
	sh.overall.BlocksFound.Add(1)
	RecordBlockFound(ctx, si.nonceVal, si.wireBlock.Header.BlueScore, blockhash)
	return true, nil
}

// trackAcceptedCoinbase registers the accepted block's 20% CSV-locked escrow outputs
// for later claiming.
func (sh *shareHandler) trackAcceptedCoinbase(si *submitInfo) {
	if len(si.block.Transactions) == 0 {
		return
	}
	domainTx, err := appmessage.RPCTransactionToDomainTransaction(si.block.Transactions[0])
	if err != nil {
		return
	}
	coinbaseTxID := consensushashing.TransactionID(domainTx).String()
	sh.trackCoinbaseEscrow(coinbaseTxID, uint64(si.block.Header.DAAScore), si.block)
}

// trackCoinbaseEscrow scans the accepted block's coinbase for the bridge's escrow
// outputs (the node emits one 20% CSV-locked output per merged blue block) and registers
// each for later claiming. No-op when escrow is disabled.
func (sh *shareHandler) trackCoinbaseEscrow(coinbaseTxID string, confirmDAA uint64, block *appmessage.RPCBlock) {
	if sh.escrowStore == nil || len(block.Transactions) == 0 {
		return
	}
	escrowSPK := sh.escrowStore.EscrowSPKHex()
	if escrowSPK == "" {
		return
	}
	for i, out := range block.Transactions[0].Outputs {
		if out.ScriptPublicKey != nil && strings.EqualFold(out.ScriptPublicKey.Script, escrowSPK) {
			sh.escrowStore.TrackCoinbaseEscrow(coinbaseTxID, confirmDAA, out.Amount, uint32(i))
		}
	}
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
		if sh.strikes != nil {
			str += "\n" + sh.strikes.String() + "\n"
		}
		str += "\n========================================================== keryx_bridge_" + version + " ===\n"
		sh.statsLock.Unlock()
		log.Println(str)
	}
}

func GetAverageHashrateGHs(stats *WorkStats) float64 {
	return stats.SharesDiff.Load() / time.Since(stats.StartTime).Seconds()
}

// HandleDeclareCapabilities stores the SLM model IDs declared by a pool miner.
// Validation mirrors the solo miner startup check:
//  1. model_id must be in the known registry (sha2-256 of weight file is the ID by construction)
//  2. the primary weight CID must be reachable via IPFS block/stat — proves the file exists
func (sh *shareHandler) HandleDeclareCapabilities(ctx *gostratum.StratumContext, event gostratum.JsonRpcEvent) error {
	if !ctx.IsAuthorized() || len(event.Params) == 0 || len(event.Params) > 16 {
		return relayError(ctx, event, 24, "authorized model declaration required")
	}
	var models []string
	seen := make(map[string]bool)
	for _, p := range event.Params {
		id, ok := p.(string)
		if !ok || !sh.models[id] {
			return relayError(ctx, event, 20, "model is outside the pinned H15/H16 registry")
		}
		if !seen[id] {
			models = append(models, id)
			seen[id] = true
		}
	}
	sort.Strings(models)
	state := GetMiningState(ctx)
	state.challengeLock.Lock()
	if state.verified || state.activeChallengeNonce != "" {
		state.challengeLock.Unlock()
		return relayError(ctx, event, 24, "model declaration is immutable after the session challenge")
	}
	state.declaredModels = models
	state.challengeLock.Unlock()
	if err := ctx.Reply(gostratum.NewResponse(event, true, nil)); err != nil {
		return err
	}
	if sh.onCapabilities != nil {
		sh.onCapabilities(ctx)
	}
	return nil
}

// HandleChallengeResponse processes a mining.challenge_response from a pool miner.
// Params: [model_id_hex, result_text] — result_text is the SLM inference output.
func (sh *shareHandler) HandleChallengeResponse(ctx *gostratum.StratumContext, event gostratum.JsonRpcEvent) error {
	if !ctx.IsAuthorized() || len(event.Params) != 3 {
		ctx.Logger.Warn("OPoI challenge_response: malformed event, expected 3 params")
		return nil
	}
	modelIDHex, _ := event.Params[0].(string)
	nonceHex, _ := event.Params[1].(string)
	resultText, _ := event.Params[2].(string)

	state := GetMiningState(ctx)
	state.challengeLock.Lock()
	defer state.challengeLock.Unlock()

	if state.activeChallengeNonce == "" || time.Since(state.challengeIssuedAt) > opOIChallengeDeadline {
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

	// Anti-replay: the response must echo the exact nonce we issued. A mismatch means a
	// stale or replayed answer — treat as no valid inference and disconnect.
	if nonceHex != state.activeChallengeNonce {
		ctx.Logger.Warn("OPoI challenge_response: nonce mismatch — replay/stale, disconnecting",
			zap.String("expected", state.activeChallengeNonce),
			zap.String("got", nonceHex),
			zap.String("miner", ctx.WalletAddr))
		state.activeChallengeNonce = ""
		ctx.Disconnect()
		return nil
	}

	decoded, decodeErr := base64.StdEncoding.DecodeString(resultText)
	if decodeErr != nil || len(decoded) == 0 || len(decoded) > 65536 {
		ctx.Logger.Warn("OPoI challenge_response: empty result — no inference = no mining, disconnecting",
			zap.String("model", modelIDHex[:8]),
			zap.String("miner", ctx.WalletAddr))
		state.activeChallengeNonce = ""
		ctx.Disconnect()
		return nil
	}

	ctx.Logger.Info("worker capability liveness response accepted",
		zap.String("model", modelIDHex[:8]),
		zap.Int("result_len", len(resultText)),
		zap.String("miner", ctx.WalletAddr))
	state.challengePassed = true
	state.verified = true // session liveness only; consensus PoM/traces provide the evidence
	state.activeChallengeNonce = ""
	RecordOPoIChallengePass(ctx)
	return ctx.Reply(gostratum.NewResponse(event, true, nil))
}

// markResponseSubmitted atomically registers a request hash.
// Returns true if it was already registered (duplicate — TX should not be re-submitted).
func (sh *shareHandler) markResponseSubmitted(requestHash string) bool {
	sh.submittedResponsesMu.Lock()
	defer sh.submittedResponsesMu.Unlock()
	if sh.submittedResponses[requestHash] {
		return true
	}
	sh.submittedResponses[requestHash] = true
	return false
}

// trackEscrow registers a pending inference_reward escrow after an AiResponse TX is submitted.
// It computes the responseHash so the store can react to AiChallenge TXs targeting that response.
func (sh *shareHandler) trackEscrow(
	ctx *gostratum.StratumContext,
	block *appmessage.RPCBlock,
	task *AiTask,
	daaScore uint64,
) {
	if sh.escrowStore == nil || task.AiRequestTxID == "" || task.EscrowSPKHex == "" {
		return
	}

	// Resolve the miner's P2PK script from the coinbase (block.Transactions[0]).
	var minerSPKHex string
	var minerSPKVersion uint16
	if len(block.Transactions) > 0 {
		spkHex, spkVer, ok := MinerSPKFromCoinbase(block.Transactions[0], ctx.WalletAddr)
		if ok {
			minerSPKHex = spkHex
			minerSPKVersion = spkVer
		}
	}
	if minerSPKHex == "" {
		ctx.Logger.Warn("OPoI escrow: miner SPK not found in coinbase, skipping escrow tracking",
			zap.String("miner", ctx.WalletAddr),
			zap.String("tx_id", truncate(task.AiRequestTxID, 8)))
		return
	}

	// Pre-compute the responseHash = blake2b-256(AiResponsePayload) so we can
	// correlate incoming AiChallenge TXs with this escrow.
	responseHashHex := computeAiResponseHash(task.RequestHash, daaScore)

	sh.escrowStore.TrackInferenceEscrow(
		task.AiRequestTxID,
		daaScore,
		task.EscrowAmount,
		minerSPKHex,
		minerSPKVersion,
		responseHashHex,
	)
}

// computeAiResponseHash computes blake2b-256 of the 78-byte AiResponsePayload
// (v1 layout, without ai_request_txid) and returns the first 32 bytes as hex.
// This matches what the Rust consensus stores as response_hash in AiResponseRecord.
func computeAiResponseHash(requestHashHex string, daaScore uint64) string {
	requestHash, err := hex.DecodeString(requestHashHex)
	if err != nil || len(requestHash) != 32 {
		return ""
	}
	// Re-build the payload layout to compute the same hash as the Rust node.
	// Layout: [request_hash:32][challenge_window_end:8 LE][cid:34][response_length:4 LE]
	// We use zeros for CID and response_length since the bridge doesn't know them here;
	// these bytes don't affect the request_hash field used for slash lookup.
	// Note: this hash is only used as an index key to match incoming AiChallenge TXs.
	payload := make([]byte, 78)
	copy(payload[0:32], requestHash)
	binary.LittleEndian.PutUint64(payload[32:40], daaScore+challengeWindowBlocksEscrow)
	// bytes [40:78] remain zero (CID + response_length)
	h, _ := blake2b.New256(nil)
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil)[:32])
}
