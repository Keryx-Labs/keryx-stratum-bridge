package keryxstratum

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"

	secp256k1 "github.com/kaspanet/go-secp256k1"
	"github.com/kaspanet/kaspad/infrastructure/network/rpcclient"
	"go.uber.org/zap"
)

const (
	// challengeWindowBlocksEscrow must match Rust CHALLENGE_WINDOW_BLOCKS (36 000).
	challengeWindowBlocksEscrow uint64 = 36_000
	// escrowClaimBuffer guards against OP_CSV blue-score lag (same +10 as Rust).
	escrowClaimBuffer uint64 = 10
	escrowClaimInterval       = 30 * time.Second
	// claimTxFee matches Rust CLAIM_FEE_SOMPI.
	claimTxFee          uint64 = 30_000_000
	orphanRetryCooldown uint64 = 100
	seqLockRetryCooldown uint64 = 20
	maxOrphanRetries    uint8  = 10
	escrowStateFile            = "escrow_state.json"
	escrowKeyFile              = "escrow.key"
)

// EscrowEntry mirrors keryx-miner/src/escrow.rs EscrowEntry.
// Extra bridge-only fields (miner_spk_*) use omitempty so the miner ignores them.
type EscrowEntry struct {
	// CoinbaseTxID is the source TX ID: coinbase for block rewards, AiRequest txid for inference.
	CoinbaseTxID        string  `json:"coinbase_txid"`
	BlockHash           string  `json:"block_hash"`
	ConfirmDAA          uint64  `json:"confirm_daa"`
	AmountSompi         uint64  `json:"amount_sompi"`
	OutputIndex         uint32  `json:"output_index"`
	Claimed             bool    `json:"claimed"`
	Slashed             bool    `json:"slashed"`
	OrphanSlashed       bool    `json:"orphan_slashed"`
	OrphanRetries       uint8   `json:"orphan_retries"`
	OrphanRetryAfterDAA *uint64 `json:"orphan_retry_after_daa"`
	IsInference         bool    `json:"is_inference"`
	// Bridge-only fields — ignored by the Rust miner via serde default.
	MinerSPKHex     string `json:"miner_spk_hex,omitempty"`
	MinerSPKVersion uint16 `json:"miner_spk_version,omitempty"`
}

type escrowState struct {
	Entries []*EscrowEntry `json:"entries"`
}

// EscrowStore persists escrow state in escrow_state.json (same format as keryx-miner)
// and claims matured inference_reward escrows after the 1-hour challenge window.
type EscrowStore struct {
	mu    sync.Mutex
	state escrowState
	// responseToTxID maps blake2b(AiResponsePayload)[:32] hex → AiRequestTxID.
	responseToTxID map[string]string

	privKey   *secp256k1.SchnorrKeyPair
	pubKeyHex string // 64-char hex x-only pubkey — logged for operator reference
	keryxd    *rpcclient.RPCClient
	logger    *zap.Logger

	daaLock    sync.RWMutex
	currentDAA uint64

	// One claim in flight at a time (same invariant as the Rust miner).
	pendingClaimTxID   string
	pendingClaimOutIdx uint32
}

// NewEscrowStore loads the private key from escrow.key and state from escrow_state.json.
// Returns nil (and logs a notice) if escrow.key does not exist.
func NewEscrowStore(keryxd *rpcclient.RPCClient, logger *zap.Logger) *EscrowStore {
	privKeyHex, err := readKeyFile(escrowKeyFile)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Info("OPoI escrow: escrow.key not found — inference_reward claiming disabled")
		} else {
			logger.Error("OPoI escrow: failed to read escrow.key", zap.Error(err))
		}
		return nil
	}
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil || len(privKeyBytes) != 32 {
		logger.Error("OPoI escrow: escrow.key must contain exactly 64 hex chars", zap.Error(err))
		return nil
	}
	keypair, err := secp256k1.DeserializeSchnorrPrivateKeyFromSlice(privKeyBytes)
	if err != nil {
		logger.Error("OPoI escrow: invalid Schnorr private key in escrow.key", zap.Error(err))
		return nil
	}
	pubKeyHex, err := schnorrPubKeyHex(privKeyHex)
	if err != nil {
		logger.Error("OPoI escrow: failed to derive pubkey", zap.Error(err))
		return nil
	}

	store := &EscrowStore{
		responseToTxID: make(map[string]string),
		privKey:        keypair,
		pubKeyHex:      pubKeyHex,
		keryxd:         keryxd,
		logger:         logger.Named("escrow"),
	}
	store.loadState()

	logger.Info("OPoI escrow: ready",
		zap.String("pubkey", pubKeyHex[:16]+"…"),
		zap.Int("entries", len(store.state.Entries)))
	return store
}

// PubKeyHex returns the 64-char hex x-only Schnorr pubkey of the bridge escrow key.
// Requesters must lock AiRequest.output[1] to this key to enable inference_reward claiming.
func (e *EscrowStore) PubKeyHex() string {
	return e.pubKeyHex
}

// EscrowSPKHex returns the hex of the CSV-locked escrow script for this bridge's key.
// The node creates a coinbase output with exactly this SPK for the 20% escrow cut when
// the coinbase carries /escrow:<pubkey>. Used to detect our escrow outputs on accepted blocks.
func (e *EscrowStore) EscrowSPKHex() string {
	if e == nil || e.privKey == nil {
		return ""
	}
	pub, err := schnorrPubKeyBytes(e.privKey)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(buildEscrowScript(pub))
}

// TrackCoinbaseEscrow registers a coinbase 20% escrow output for claiming after the
// challenge window. Same claim path as inference escrows (IsInference=false → paid back
// to the bridge's own P2PK). Deduplicated by (txid, outputIndex).
func (e *EscrowStore) TrackCoinbaseEscrow(coinbaseTxID string, confirmDAA, amount uint64, outputIndex uint32) {
	if e == nil || coinbaseTxID == "" || amount == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, en := range e.state.Entries {
		if en.CoinbaseTxID == coinbaseTxID && en.OutputIndex == outputIndex {
			return
		}
	}
	e.state.Entries = append(e.state.Entries, &EscrowEntry{
		CoinbaseTxID: coinbaseTxID,
		ConfirmDAA:   confirmDAA,
		AmountSompi:  amount,
		OutputIndex:  outputIndex,
		IsInference:  false,
	})
	e.saveStateLocked()
	e.logger.Info("OPoI escrow: coinbase escrow tracked",
		zap.String("tx_id", truncate(coinbaseTxID, 8)),
		zap.Uint32("out", outputIndex),
		zap.Uint64("amount", amount),
		zap.Uint64("window_end", confirmDAA+challengeWindowBlocksEscrow))
}

// TrackInferenceEscrow registers an AiRequest.output[1] inference escrow.
// Mirrors Rust EscrowWatcher.track_inference_escrow.
func (e *EscrowStore) TrackInferenceEscrow(
	aiRequestTxID string, confirmDAA, amount uint64,
	minerSPKHex string, minerSPKVersion uint16,
	responseHashHex string,
) {
	if e == nil || aiRequestTxID == "" || amount == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, en := range e.state.Entries {
		if en.CoinbaseTxID == aiRequestTxID && en.OutputIndex == 1 {
			return
		}
	}
	entry := &EscrowEntry{
		CoinbaseTxID:    aiRequestTxID,
		ConfirmDAA:      confirmDAA,
		AmountSompi:     amount,
		OutputIndex:     1,
		IsInference:     true,
		MinerSPKHex:     minerSPKHex,
		MinerSPKVersion: minerSPKVersion,
	}
	e.state.Entries = append(e.state.Entries, entry)
	if responseHashHex != "" {
		e.responseToTxID[responseHashHex] = aiRequestTxID
	}
	e.saveStateLocked()
	e.logger.Info("OPoI escrow: inference escrow tracked",
		zap.String("tx_id", truncate(aiRequestTxID, 8)),
		zap.Uint64("amount", amount),
		zap.Uint64("window_end", confirmDAA+challengeWindowBlocksEscrow))
}

// MarkSlashedByResponse prevents claiming the escrow whose AiResponse matched the challenge.
func (e *EscrowStore) MarkSlashedByResponse(responseHashHex string) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	txID, ok := e.responseToTxID[responseHashHex]
	if !ok {
		return
	}
	for _, en := range e.state.Entries {
		if en.CoinbaseTxID == txID && en.OutputIndex == 1 && !en.Claimed {
			en.Slashed = true
			RecordEscrowSlashed("challenge")
			e.logger.Warn("OPoI escrow: slashed by AiChallenge",
				zap.String("tx_id", truncate(txID, 8)))
			e.saveStateLocked()
			return
		}
	}
}

// UpdateDAA updates the bridge's view of the current DAA score.
func (e *EscrowStore) UpdateDAA(daa uint64) {
	if e == nil {
		return
	}
	e.daaLock.Lock()
	if daa > e.currentDAA {
		e.currentDAA = daa
	}
	e.daaLock.Unlock()
}

func (e *EscrowStore) getDAA() uint64 {
	e.daaLock.RLock()
	defer e.daaLock.RUnlock()
	return e.currentDAA
}

// Start launches the background claim goroutine.
func (e *EscrowStore) Start(ctx context.Context) {
	if e == nil {
		return
	}
	go e.claimLoop(ctx)
}

func (e *EscrowStore) claimLoop(ctx context.Context) {
	ticker := time.NewTicker(escrowClaimInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.processMatureClaims()
		}
	}
}

func (e *EscrowStore) processMatureClaims() {
	currentDAA := e.getDAA()
	if currentDAA == 0 {
		return
	}

	e.mu.Lock()

	if e.pendingClaimTxID != "" {
		e.mu.Unlock()
		return
	}

	isEligible := func(en *EscrowEntry) bool {
		return !en.Claimed && !en.Slashed &&
			currentDAA >= en.ConfirmDAA+challengeWindowBlocksEscrow+escrowClaimBuffer &&
			(en.OrphanRetryAfterDAA == nil || currentDAA >= *en.OrphanRetryAfterDAA)
	}

	// Inference entries first, then coinbase — same priority as the Rust miner.
	var chosen *EscrowEntry
	for _, en := range e.state.Entries {
		if en.IsInference && isEligible(en) {
			chosen = en
			break
		}
	}
	if chosen == nil {
		for _, en := range e.state.Entries {
			if !en.IsInference && isEligible(en) {
				chosen = en
				break
			}
		}
	}

	if chosen == nil {
		e.mu.Unlock()
		return
	}

	txID := chosen.CoinbaseTxID
	outIdx := chosen.OutputIndex
	e.mu.Unlock()

	e.logger.Info("OPoI escrow: claiming",
		zap.String("tx_id", truncate(txID, 8)),
		zap.Uint64("amount", chosen.AmountSompi),
		zap.Bool("is_inference", chosen.IsInference))

	rpcTx, err := BuildClaimTX(e.privKey, chosen)
	if err != nil {
		e.logger.Warn("OPoI escrow: failed to build claim TX",
			zap.String("tx_id", truncate(txID, 8)), zap.Error(err))
		return
	}

	resp, submitErr := e.keryxd.SubmitTransaction(rpcTx, false)

	e.mu.Lock()
	defer e.mu.Unlock()

	if submitErr != nil {
		e.handleClaimResult(txID, outIdx, submitErr.Error(), currentDAA)
	} else {
		e.pendingClaimTxID = txID
		e.pendingClaimOutIdx = outIdx
		e.logger.Info("OPoI escrow: claim TX submitted",
			zap.String("claim_tx_id", resp.TransactionID),
			zap.String("escrow_tx_id", truncate(txID, 8)))
		// Mark as claimed optimistically; the miner does the same.
		e.handleClaimResult(txID, outIdx, "", currentDAA)
	}
}

// handleClaimResult updates the entry after a submit attempt.  Must be called with e.mu held.
func (e *EscrowStore) handleClaimResult(txID string, outIdx uint32, errMsg string, currentDAA uint64) {
	for _, en := range e.state.Entries {
		if en.CoinbaseTxID != txID || en.OutputIndex != outIdx {
			continue
		}
		if errMsg == "" {
			en.Claimed = true
			RecordEscrowClaim(en.IsInference)
		} else {
			switch {
			case strings.Contains(errMsg, "orphan"):
				en.OrphanRetries++
				if en.OrphanRetries >= maxOrphanRetries {
					en.Slashed = true
					RecordEscrowSlashed("orphan_max_retries")
				} else {
					en.OrphanSlashed = true
					retry := currentDAA + orphanRetryCooldown
					en.OrphanRetryAfterDAA = &retry
				}
			case strings.Contains(errMsg, "sequence lock"):
				retry := currentDAA + seqLockRetryCooldown
				en.OrphanRetryAfterDAA = &retry
			default:
				en.Slashed = true
				RecordEscrowSlashed("rejected")
				e.logger.Warn("OPoI escrow: claim rejected, slashing",
					zap.String("tx_id", truncate(txID, 8)), zap.String("err", errMsg))
			}
		}
		e.pendingClaimTxID = ""
		e.pendingClaimOutIdx = 0
		break
	}
	e.saveStateLocked()
}

func (e *EscrowStore) loadState() {
	data, err := os.ReadFile(escrowStateFile)
	if err != nil {
		if !os.IsNotExist(err) {
			e.logger.Warn("OPoI escrow: could not read escrow_state.json", zap.Error(err))
		}
		return
	}
	if err := json.Unmarshal(data, &e.state); err != nil {
		e.logger.Warn("OPoI escrow: could not parse escrow_state.json, starting fresh", zap.Error(err))
		e.state = escrowState{}
	}
}

// saveStateLocked saves state; caller must hold e.mu.
func (e *EscrowStore) saveStateLocked() {
	data, err := json.MarshalIndent(e.state, "", "  ")
	if err != nil {
		e.logger.Warn("OPoI escrow: failed to serialize state", zap.Error(err))
		return
	}
	if err := os.WriteFile(escrowStateFile, data, 0o644); err != nil {
		e.logger.Warn("OPoI escrow: failed to write escrow_state.json", zap.Error(err))
	}
}

func readKeyFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
