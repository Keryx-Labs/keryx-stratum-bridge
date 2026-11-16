package keryxstratum

import (
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

}

func (c *clientListener) OnDisconnect(ctx *gostratum.StratumContext) {
	c.clientLock.Lock()
	c.logger.Info("removing client ", ctx.Id)
	delete(c.clients, ctx.Id)
	c.logger.Info("removed client ", ctx.Id)
	c.clientLock.Unlock()
	if ctx.IsAuthorized() {
		RecordDisconnect(ctx)
	}
}

func (c *clientListener) NewBlockAvailable(kapi *KeryxApi) {
	c.clientLock.Lock()
	addresses := make([]string, 0, len(c.clients))
	for _, cl := range c.clients {
		if !cl.Connected() || !cl.IsAuthorized() {
			continue
		}
		go func(client *gostratum.StratumContext) {
			state := GetMiningState(client)
			if !state.dispatchMu.TryLock() {
				return
			}
			defer state.dispatchMu.Unlock()
			if client.WalletAddr == "" {
				if time.Since(state.connectTime) > time.Second*20 {
					client.Logger.Warn("client misconfigured, no miner address specified - disconnecting", zap.String("client", client.String()))
					RecordWorkerError(client.WalletAddr, ErrNoMinerAddress)
					client.Disconnect()
				}
				return
			}
			// Declarations admit jobs; only full PoM verification admits a share.
			state.challengeLock.Lock()
			gated := !state.capabilitiesReady ||
				(c.minHoldingSompi > 0 && !state.holdsEnough)
			state.challengeLock.Unlock()
			if gated || !c.shareHandler.canMine() {
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
			if c.escrowStore != nil {
				c.escrowStore.UpdateDAA(uint64(template.Block.Header.DAAScore))
				for _, rh := range scanBlockForAiChallengeResponseHashes(template.Block) {
					c.escrowStore.MarkSlashedByResponse(rh)
				}
			}
			if !template.IsSynced && !kapi.mineWhenNotSynced {
				return
			}
			state.bigDiff = CalculateTarget(uint64(template.Block.Header.Bits))
			header, err := SerializeBlockHeader(template.Block)
			if err != nil {
				RecordWorkerError(client.WalletAddr, ErrBadDataFromMiner)
				client.Logger.Error(fmt.Sprintf("failed to serialize block header: %s", err))
				return
			}

			jobId := state.AddJob(&BlockJob{App: template.Block, Wire: template.Wire})
			state.JobLock.Lock()
			initialized := state.initialized
			state.JobLock.Unlock()
			if !initialized {
				state.JobLock.Lock()
				state.useBigJob = false // authenticated H15/H16 clients negotiated Stratum v3
				state.stratumDiff = newKeryxDiff()
				state.stratumDiff.setDiffValue(c.minShareDiff)
				if err := client.Send(gostratum.JsonRpcEvent{
					Version: "2.0",
					Method:  "mining.set_difficulty",
					Params:  []any{state.stratumDiff.diffValue},
				}); err != nil {
					state.JobLock.Unlock()
					RecordWorkerError(client.WalletAddr, ErrFailedSetDiff)
					client.Logger.Error(errors.Wrap(err, "failed sending difficulty").Error(), zap.Any("context", client))
					return
				}
				state.initialized = true
				state.JobLock.Unlock()
			}

			jobParams := []any{fmt.Sprintf("%d", jobId)}
			if blockTaskActive(uint64(template.Block.Header.DAAScore)) {
				// v4: full header and window seed; each GPU of the worker inserts its own task root.
				seed, err := kapi.seeds.windowSeed(template.Wire.Header)
				if err != nil {
					RecordWorkerError(client.WalletAddr, ErrFailedBlockFetch)
					client.Logger.Error(fmt.Sprintf("block task window seed: %s", err))
					return
				}
				headerHex, err := v4JobHeader(template.Wire.Header)
				if err != nil {
					client.Logger.Error(fmt.Sprintf("failed encoding v4 job header: %s", err))
					return
				}
				jobParams = append(jobParams, headerHex, template.Block.Header.Timestamp,
					uint64(template.Block.Header.DAAScore), uint32(template.Block.Header.Bits), seed)
			} else if state.useBigJob {
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
				// v3 clients also receive the template bits (5th param) so the miner can
				// bound its effective target by the real block target.
				if client.StratumV3 {
					jobParams = append(jobParams, uint32(template.Block.Header.Bits))
				}
			}

			// Private inference is dispatched only by the authenticated service relay,
			// after the node confirms the obligation. Never append a legacy task here.

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

		if cl.IsAuthorized() {
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
						if !cl.IsAuthorized() {
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
