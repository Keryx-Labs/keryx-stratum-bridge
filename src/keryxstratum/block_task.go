package keryxstratum

import (
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strings"
	"sync"

	"github.com/keryx-labs/keryx-stratum-bridge/src/keryxrpc"
	"github.com/keryx-labs/keryx-stratum-bridge/src/keryxrpc/keryxwire"
	"google.golang.org/protobuf/proto"
)

// Block task window rules; must match the node's verifiable-inference block_task.rs.
const (
	blockTaskWindowDAA uint64 = 64
	blockTaskLagDAA    uint64 = 16
	seedCacheMax              = 4096
	seedWalkMax               = 4096
)

// blockTaskActivationDAA is the node's block task gate; never until set from the config.
var blockTaskActivationDAA uint64 = math.MaxUint64

func blockTaskActive(daa uint64) bool {
	return daa >= blockTaskActivationDAA
}

type chainEntry struct {
	daa            uint64
	selectedParent string
	blueWork       *big.Int
}

// seedResolver finds the window seed block of a template by walking the selected-parent chain.
type seedResolver struct {
	mu    sync.Mutex
	wire  *keryxrpc.Client
	cache map[string]chainEntry
}

func newSeedResolver(wire *keryxrpc.Client) *seedResolver {
	return &seedResolver{wire: wire, cache: make(map[string]chainEntry)}
}

func (r *seedResolver) entry(hash string) (chainEntry, error) {
	if e, ok := r.cache[hash]; ok {
		return e, nil
	}
	block, err := r.wire.GetBlock(hash, false)
	if err != nil {
		return chainEntry{}, err
	}
	if block.Header == nil || block.VerboseData == nil {
		return chainEntry{}, fmt.Errorf("block %s has no header or verbose data", hash)
	}
	bw, ok := new(big.Int).SetString(block.Header.BlueWork, 16)
	if !ok {
		bw = new(big.Int)
	}
	e := chainEntry{daa: block.Header.DaaScore, selectedParent: strings.ToLower(block.VerboseData.SelectedParentHash), blueWork: bw}
	if len(r.cache) >= seedCacheMax {
		r.cache = make(map[string]chainEntry)
	}
	r.cache[hash] = e
	return e, nil
}

// windowSeed returns the hex seed block of the block task window of a template with `header`.
func (r *seedResolver) windowSeed(header *keryxwire.RpcBlockHeader) (string, error) {
	if header.DaaScore < blockTaskLagDAA {
		return "", fmt.Errorf("no task window below daa %d", blockTaskLagDAA)
	}
	start := (header.DaaScore - blockTaskLagDAA) / blockTaskWindowDAA * blockTaskWindowDAA
	if len(header.Parents) == 0 || len(header.Parents[0].ParentHashes) == 0 {
		return "", fmt.Errorf("template has no direct parents")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var cur string
	var curWork *big.Int
	for _, p := range header.Parents[0].ParentHashes {
		p = strings.ToLower(p)
		e, err := r.entry(p)
		if err != nil {
			return "", err
		}
		if cmp := e.blueWork.Cmp(curWork0(curWork)); curWork == nil || cmp > 0 || (cmp == 0 && p > cur) {
			cur, curWork = p, e.blueWork
		}
	}
	for i := 0; i < seedWalkMax; i++ {
		e, err := r.entry(cur)
		if err != nil {
			return "", err
		}
		if e.daa <= start {
			return cur, nil
		}
		if e.selectedParent == "" {
			return "", fmt.Errorf("selected chain ends above the window start %d", start)
		}
		cur = e.selectedParent
	}
	return "", fmt.Errorf("no seed block within %d chain blocks", seedWalkMax)
}

func curWork0(w *big.Int) *big.Int {
	if w == nil {
		return new(big.Int)
	}
	return w
}

// v4JobHeader is the hex protobuf encoding of the template header sent in a v4 mining.notify.
func v4JobHeader(header *keryxwire.RpcBlockHeader) (string, error) {
	h, ok := proto.Clone(header).(*keryxwire.RpcBlockHeader)
	if !ok {
		return "", fmt.Errorf("failed cloning template header")
	}
	h.Nonce = 0
	h.TaskRoot = ""
	b, err := proto.Marshal(h)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
