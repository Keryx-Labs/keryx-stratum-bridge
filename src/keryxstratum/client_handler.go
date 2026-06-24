package keryxstratum

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/keryx-labs/keryx-stratum-bridge/src/gostratum"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

var bigJobRegex = regexp.MustCompile(".*BzMiner.*")

const balanceDelay = time.Minute

type clientListener struct {
	logger           *zap.SugaredLogger
	shareHandler     *shareHandler
	escrowStore      *EscrowStore
	clientLock       sync.RWMutex
	clients          map[int32]*gostratum.StratumContext
	lastBalanceCheck time.Time
	clientCounter    int32
	minShareDiff     float64
	extranonceSize   int8
	maxExtranonce    int32
	nextExtranonce   int32
	// Balance-reward gate: workers whose payout address holds < minHoldingSompi are not
	// dispatched jobs (no holdings = no mining in this pool). 0 disables the gate.
	minHoldingSompi uint64
}

func newClientListener(logger *zap.SugaredLogger, shareHandler *shareHandler, minShareDiff float64, extranonceSize int8, escrowStore *EscrowStore, minHoldingSompi uint64) *clientListener {
	return &clientListener{
		logger:          logger,
		minShareDiff:    minShareDiff,
		extranonceSize:  extranonceSize,
		maxExtranonce:   int32(math.Pow(2, (8*math.Min(float64(extranonceSize), 3))) - 1),
		nextExtranonce:  0,
		clientLock:      sync.RWMutex{},
		shareHandler:    shareHandler,
		escrowStore:     escrowStore,
		clients:         make(map[int32]*gostratum.StratumContext),
		minHoldingSompi: minHoldingSompi,
	}
}

func (c *clientListener) OnConnect(ctx *gostratum.StratumContext) {
	var extranonce int32

	idx := atomic.AddInt32(&c.clientCounter, 1)
	ctx.Id = idx
	c.clientLock.Lock()
	if c.extranonceSize > 0 {
		extranonce = c.nextExtranonce
		if c.nextExtranonce < c.maxExtranonce {
			c.nextExtranonce++
		} else {
			c.nextExtranonce = 0
			c.logger.Warn("wrapped extranonce! new clients may be duplicating work...")
		}
	}
	c.clients[idx] = ctx
	c.clientLock.Unlock()
	ctx.Logger = ctx.Logger.With(zap.Int("client_id", int(ctx.Id)))

	if c.extranonceSize > 0 {
		ctx.Extranonce = fmt.Sprintf("%0*x", c.extranonceSize*2, extranonce)
	}
	go func() {
		// hacky, but give time for the authorize to go through so we can use the worker name
		time.Sleep(5 * time.Second)
		c.shareHandler.getCreateStats(ctx)
	}()
	go func() {
		// Wait for authorize to complete, then immediately challenge the new miner.
		// No grace period: no inference = no mining.
		time.Sleep(10 * time.Second)
		if ctx.Connected() && ctx.WalletAddr != "" {
			c.sendChallengeToClient(ctx)
		}
	}()
}

func (c *clientListener) OnDisconnect(ctx *gostratum.StratumContext) {
	ctx.Done()
	c.clientLock.Lock()
	c.logger.Info("removing client ", ctx.Id)
	delete(c.clients, ctx.Id)
	c.logger.Info("removed client ", ctx.Id)
	c.clientLock.Unlock()
	RecordDisconnect(ctx)
}

func (c *clientListener) NewBlockAvailable(kapi *KeryxApi) {
	c.clientLock.Lock()
	addresses := make([]string, 0, len(c.clients))
	for _, cl := range c.clients {
		if !cl.Connected() {
			continue
		}
		go func(client *gostratum.StratumContext) {
			state := GetMiningState(client)
			if client.WalletAddr == "" {
				if time.Since(state.connectTime) > time.Second*20 {
					client.Logger.Warn("client misconfigured, no miner address specified - disconnecting", zap.String("client", client.String()))
					RecordWorkerError(client.WalletAddr, ErrNoMinerAddress)
					client.Disconnect()
				}
				return
			}
			// OPoI gate (Rule #1 — no inference = no mining): withhold all work until the
			// miner has passed its first capability challenge, and pause job dispatch while
			// a challenge is in flight. The latter also frees the GPU so the challenge
			// inference runs uncontended instead of fighting kHeavyHash for the device.
			state.challengeLock.Lock()
			gated := !state.verified || state.activeChallengeNonce != "" ||
				(c.minHoldingSompi > 0 && !state.holdsEnough)
			state.challengeLock.Unlock()
			if gated {
				return
			}
			template, err := kapi.GetBlockTemplate(client)
			if err != nil {
				if strings.Contains(err.Error(), "Could not decode address") {
					RecordWorkerError(client.WalletAddr, ErrInvalidAddressFmt)
					client.Logger.Error(fmt.Sprintf("failed fetching new block template from keryx, malformed address: %s", err))
					client.Disconnect()
				} else {
					RecordWorkerError(client.WalletAddr, ErrFailedBlockFetch)
					client.Logger.Error(fmt.Sprintf("failed fetching new block template from keryx: %s", err))
				}
				return
			}

			// Update escrow store's DAA view and check for incoming AiChallenge TXs.
			c.escrowStore.UpdateDAA(uint64(template.Block.Header.DAAScore))
			for _, rh := range scanBlockForAiChallengeResponseHashes(template.Block) {
				c.escrowStore.MarkSlashedByResponse(rh)
			}
			state.bigDiff = CalculateTarget(uint64(template.Block.Header.Bits))
			header, err := SerializeBlockHeader(template.Block)
			if err != nil {
				RecordWorkerError(client.WalletAddr, ErrBadDataFromMiner)
				client.Logger.Error(fmt.Sprintf("failed to serialize block header: %s", err))
				return
			}

			jobId := state.AddJob(template.Block)
			if !state.initialized {
				state.initialized = true
				state.useBigJob = bigJobRegex.MatchString(client.RemoteApp)
				state.stratumDiff = newKeryxDiff()
				state.stratumDiff.setDiffValue(c.minShareDiff)
				if err := client.Send(gostratum.JsonRpcEvent{
					Version: "2.0",
					Method:  "mining.set_difficulty",
					Params:  []any{state.stratumDiff.diffValue},
				}); err != nil {
					RecordWorkerError(client.WalletAddr, ErrFailedSetDiff)
					client.Logger.Error(errors.Wrap(err, "failed sending difficulty").Error(), zap.Any("context", client))
					return
				}
			}

			jobParams := []any{fmt.Sprintf("%d", jobId)}
			if state.useBigJob {
				jobParams = append(jobParams, GenerateLargeJobParams(header, uint64(template.Block.Header.Timestamp)))
			} else {
				jobParams = append(jobParams, GenerateJobHeader(header))
				jobParams = append(jobParams, template.Block.Header.Timestamp)
				// Always carry the real DAA score (ShortV2 notify, 4 params) so the miner
				// can select the correct PoW salt era and gate PoM at the hardfork. Without
				// it the miner falls back to the legacy 3-param short notify and pins DAA to
				// the salt-v4 era, which sits below the PoM activation height — it would never
				// switch to PoM and would fork at H.
				jobParams = append(jobParams, uint64(template.Block.Header.DAAScore))
			}

			// If the block template carries a pending AiRequest, dispatch it only to miners
			// that have declared the required model via mining.declare_capabilities.
			if task := scanBlockForAiTask(template.Block); task != nil {
				if taskJSON := aiTaskJSON(task); taskJSON != "" && !state.useBigJob && state.HasDeclaredModel(task.ModelIDHex) {
					// DAA already appended above; add only the task JSON → MiningNotifyWithTask (5 params).
					jobParams = append(jobParams, taskJSON)
				}
			}

			if err := client.Send(gostratum.JsonRpcEvent{
				Version: "2.0",
				Method:  "mining.notify",
				Id:      jobId,
				Params:  jobParams,
			}); err != nil {
				if errors.Is(err, gostratum.ErrorDisconnected) {
					RecordWorkerError(client.WalletAddr, ErrDisconnected)
					return
				}
				RecordWorkerError(client.WalletAddr, ErrFailedSendWork)
				client.Logger.Error(errors.Wrapf(err, "failed sending work packet %d", jobId).Error())
			}

			RecordNewJob(client)
		}(cl)

		if cl.WalletAddr != "" {
			addresses = append(addresses, cl.WalletAddr)
		}
	}
	c.clientLock.Unlock()

	if time.Since(c.lastBalanceCheck) > balanceDelay {
		c.lastBalanceCheck = time.Now()
		if len(addresses) > 0 {
			go func() {
				balances, err := kapi.keryxd.GetBalancesByAddresses(addresses)
				if err != nil {
					c.logger.Warn("failed to get balances from keryx, prom stats will be out of date", zap.Error(err))
					return
				}
				RecordBalances(balances)
				// Balance-reward gate: refresh each worker's holdsEnough from its payout-address
				// balance. Self-binding: a worker can't borrow a whale's balance because the pool
				// pays rewards to this very address. Hostile pools can disable this — cooperative layer.
				if c.minHoldingSompi > 0 {
					bal := make(map[string]uint64, len(balances.Entries))
					for _, e := range balances.Entries {
						bal[e.Address] = e.Balance
					}
					c.clientLock.RLock()
					for _, cl := range c.clients {
						if cl.WalletAddr == "" {
							continue
						}
						ok := bal[cl.WalletAddr] >= c.minHoldingSompi
						st := GetMiningState(cl)
						st.challengeLock.Lock()
						was := st.holdsEnough
						st.holdsEnough = ok
						st.challengeLock.Unlock()
						if !ok && was {
							cl.Logger.Warn("insufficient KRX holdings at payout address — mining gated until balance >= threshold",
								zap.String("addr", cl.WalletAddr), zap.Uint64("min_sompi", c.minHoldingSompi))
						}
					}
					c.clientLock.RUnlock()
				}
			}()
		}
	}
}

const opOIChallengeInterval = 60 * time.Minute
const opOIChallengeDeadline = 5 * time.Minute

// startChallengeLoop periodically sends OPoI capability challenges to all connected miners.
// The challenge model is picked randomly from those declared by the miner via
// mining.declare_capabilities. Miners with no declared models are disconnected immediately.
func (c *clientListener) startChallengeLoop(ctx context.Context) {
	ticker := time.NewTicker(opOIChallengeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.sendChallenges()
		}
	}
}

func (c *clientListener) sendChallenges() {
	c.clientLock.RLock()
	defer c.clientLock.RUnlock()
	for _, client := range c.clients {
		if !client.Connected() || client.WalletAddr == "" {
			continue
		}
		go c.sendChallengeToClient(client)
	}
}

func (c *clientListener) sendChallengeToClient(ctx *gostratum.StratumContext) {
	state := GetMiningState(ctx)

	state.challengeLock.Lock()
	if state.activeChallengeNonce != "" {
		// A challenge is already in flight; the deadline timer will kick if unanswered.
		state.challengeLock.Unlock()
		return
	}
	// No declared models = no provable inference capability = no mining.
	if len(state.declaredModels) == 0 {
		state.challengeLock.Unlock()
		ctx.Logger.Warn("OPoI: no models declared — no inference = no mining, disconnecting",
			zap.String("miner", ctx.WalletAddr))
		ctx.Disconnect()
		return
	}
	// Challenge with a random model from those declared — proves the miner has what it claims.
	var pick [8]byte
	rand.Read(pick[:]) //nolint:errcheck
	idx := binary.LittleEndian.Uint64(pick[:]) % uint64(len(state.declaredModels))
	modelID := state.declaredModels[idx]
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck — crypto/rand.Read never returns an error
	nonceHex := hex.EncodeToString(nonce)
	state.activeChallengeNonce = nonceHex
	state.activeChallengeModel = modelID
	state.challengeIssuedAt = time.Now()
	state.challengePassed = false
	state.challengeLock.Unlock()

	ctx.Logger.Info("OPoI challenge: sending to pool miner",
		zap.String("model", modelID[:8]),
		zap.String("nonce", nonceHex),
		zap.String("miner", ctx.WalletAddr))

	if err := ctx.Send(gostratum.JsonRpcEvent{
		Version: "2.0",
		Method:  "mining.challenge",
		Params:  []any{modelID, nonceHex},
	}); err != nil {
		ctx.Logger.Warn("OPoI challenge: failed to send to miner", zap.Error(err))
		return
	}

	// Deadline timer: kick if no response within the deadline window.
	go func() {
		time.Sleep(opOIChallengeDeadline)
		state.challengeLock.Lock()
		unanswered := state.activeChallengeNonce == nonceHex
		state.challengeLock.Unlock()
		if unanswered {
			ctx.Logger.Warn("OPoI challenge: deadline exceeded — no inference = no mining, disconnecting",
				zap.String("nonce", nonceHex),
				zap.String("miner", ctx.WalletAddr))
			ctx.Disconnect()
		}
	}()
}
