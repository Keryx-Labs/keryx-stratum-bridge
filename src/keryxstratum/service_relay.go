package keryxstratum

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kaspanet/kaspad/app/appmessage"
	"github.com/kaspanet/kaspad/domain/consensus/utils/consensushashing"
	"github.com/keryx-labs/keryx-stratum-bridge/src/gostratum"
	"github.com/keryx-labs/keryx-stratum-bridge/src/keryxrpc"
	w "github.com/keryx-labs/keryx-stratum-bridge/src/keryxrpc/keryxwire"
	"golang.org/x/crypto/blake2b"
	"google.golang.org/protobuf/proto"
)

const maxServiceTasks = 1024

// Request horizon + audit span + maximum H16 opening backlog, from the pinned node.
const serviceRetentionDAA = 72_000 + 270_000 + 36_000

type relayTask struct {
	ID              string                   `json:"id"`
	Payload         string                   `json:"payload"` // encrypted on-chain request, never the plaintext prompt
	DAA             uint64                   `json:"daa"`
	Owner           string                   `json:"owner,omitempty"` // authenticated worker identity, stable across reconnects
	ResponseID      string                   `json:"response_id,omitempty"`
	AnswerDigest    string                   `json:"answer_digest,omitempty"`
	Model           string                   `json:"model,omitempty"`
	ResponsePayload string                   `json:"response_payload,omitempty"`
	PhaseRoots      map[string]string        `json:"phase_roots,omitempty"`
	DrawBlock       string                   `json:"draw_block,omitempty"`
	Draw            *w.AwaitedOpeningMessage `json:"draw,omitempty"`
}
type relayTX struct {
	TX       *appmessage.RPCTransaction `json:"tx"`
	Task     string                     `json:"task"`
	Deadline uint64                     `json:"deadline"`
	Kind     string                     `json:"kind"`
	Digest   string                     `json:"digest"`
}
type chainPoint struct {
	Hash string `json:"hash"`
	DAA  uint64 `json:"daa"`
}
type relayState struct {
	Version  int                   `json:"version"`
	Escrow   string                `json:"escrow"`
	Identity string                `json:"identity"`
	Cursor   string                `json:"cursor"`
	Tasks    map[string]*relayTask `json:"tasks"`
	Pending  map[string]*relayTX   `json:"pending"`
	Chain    []chainPoint          `json:"chain"`
}

type serviceRelay struct {
	mu         sync.Mutex
	api        *KeryxApi
	rpc        *keryxrpc.Client // independent stream: service polling does not queue behind shares
	verifier   *protocolVerifier
	clients    *clientListener
	path       string
	state      relayState
	active     map[string]uint64
	lastSent   map[string]time.Time
	lastSubmit map[string]time.Time
	lastGood   time.Time
	daa        uint64
	err        string
}

func newServiceRelay(api *KeryxApi, verifier *protocolVerifier, path string) (*serviceRelay, error) {
	if path == "" {
		return nil, fmt.Errorf("service_state_file is required")
	}
	s := &serviceRelay{api: api, rpc: keryxrpc.NewClient(api.address), verifier: verifier, path: path,
		active: make(map[string]uint64), lastSent: make(map[string]time.Time), lastSubmit: make(map[string]time.Time)}
	s.state = relayState{Version: 1, Escrow: verifier.identity.Pubkey, Identity: verifier.identity.Identity,
		Tasks: make(map[string]*relayTask), Pending: make(map[string]*relayTX)}
	info, statErr := os.Stat(path)
	if statErr == nil && info.Size() > 64*1024*1024 {
		return nil, fmt.Errorf("service state exceeds size limit")
	}
	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) > 64*1024*1024 {
			return nil, fmt.Errorf("service state exceeds size limit")
		}
		if err = json.Unmarshal(data, &s.state); err != nil {
			return nil, fmt.Errorf("invalid service state; refusing to discard obligations")
		}
		if s.state.Version != 1 || s.state.Escrow != verifier.identity.Pubkey || s.state.Identity != verifier.identity.Identity || s.state.Tasks == nil || s.state.Pending == nil || len(s.state.Tasks) > maxServiceTasks {
			return nil, fmt.Errorf("service state identity/schema mismatch")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	// Older states encoded an empty root path as null. A child path's parent
	// decodes as an empty slice, so both forms must identify the same commitment.
	for _, task := range s.state.Tasks {
		for key, root := range task.PhaseRoots {
			if !strings.HasSuffix(key, ":null") {
				continue
			}
			canonical := strings.TrimSuffix(key, ":null") + ":[]"
			if existing, ok := task.PhaseRoots[canonical]; ok && existing != root {
				return nil, fmt.Errorf("conflicting retained attention root commitments")
			}
			task.PhaseRoots[canonical] = root
			delete(task.PhaseRoots, key)
		}
	}
	for _, pending := range s.state.Pending {
		if pending.Kind == "opening" && strings.HasSuffix(pending.Digest, ":null") {
			pending.Digest = strings.TrimSuffix(pending.Digest, ":null") + ":[]"
		}
	}
	return s, nil
}

func (s *serviceRelay) saveLocked() error {
	data, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	if len(data) > 64*1024*1024 {
		return fmt.Errorf("service state exceeds size limit")
	}
	if err = os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(s.path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(s.path+".tmp", s.path)
	}
	return err
}

func (s *serviceRelay) ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err == "" && !s.lastGood.IsZero() && time.Since(s.lastGood) < 30*time.Second
}

func (s *serviceRelay) Start(ctx context.Context) {
	go func() {
		defer s.rpc.Close()
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			err := s.poll()
			s.mu.Lock()
			if err != nil {
				s.err = err.Error()
			} else {
				s.err = ""
				s.lastGood = time.Now()
			}
			s.mu.Unlock()
			if err != nil {
				s.api.logger.Warnw("inference service is withholding mining work", "reason", err.Error())
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// Requests seen in a template/selected chain are candidates only. The node's
// GetAwaitedOpenings request ledger is the sole authority to dispatch/sign them.
func (s *serviceRelay) observeLocked(block *w.RpcBlock) error {
	if block == nil || block.Header == nil {
		return fmt.Errorf("missing service block header")
	}
	for _, tx := range block.Transactions {
		if tx == nil || tx.SubnetworkId != subnetworkAiRequest {
			continue
		}
		app := keryxrpc.BlockToAppMessage(&w.RpcBlock{Header: block.Header, Transactions: []*w.RpcTransaction{tx}})
		domain, err := appmessage.RPCTransactionToDomainTransaction(app.Transactions[0])
		if err != nil {
			return fmt.Errorf("invalid node AiRequest transaction")
		}
		id := consensushashing.TransactionID(domain).String()
		if _, exists := s.state.Tasks[id]; exists {
			continue
		}
		// This is a local decryptability check, not an approval or a miner attestation.
		if _, err = s.verifier.call(map[string]any{"op": "request", "payload": tx.Payload}); err != nil {
			continue
		}
		if len(s.state.Tasks) >= maxServiceTasks {
			return fmt.Errorf("service task capacity reached; retain state and stop accepting new work")
		}
		s.state.Tasks[id] = &relayTask{ID: id, Payload: tx.Payload, DAA: block.Header.DaaScore}
	}
	return nil
}

func (s *serviceRelay) scanChainLocked(header *w.RpcBlockHeader) error {
	if len(header.Parents) == 0 || len(header.Parents[0].ParentHashes) == 0 {
		return fmt.Errorf("service template has no parents")
	}
	// Choose the same selected parent as consensus: blue work, then hash.
	var selected *w.RpcBlock
	for _, hash := range header.Parents[0].ParentHashes {
		block, err := s.rpc.GetBlock(hash, true)
		if err != nil {
			return err
		}
		if selected == nil || moreBlueWork(block, selected) {
			selected = block
		}
	}
	if selected.VerboseData == nil {
		return fmt.Errorf("selected parent has no verbose data")
	}
	head := selected.VerboseData.Hash
	if head == s.state.Cursor {
		return nil
	}
	current := selected
	var added []chainPoint
	reached := false
	retained := make(map[string]bool)
	for _, point := range s.state.Chain {
		retained[point.Hash] = true
	}
	for i := 0; i < 2048; i++ {
		if current.Header == nil || current.VerboseData == nil {
			return fmt.Errorf("incomplete service chain block")
		}
		hash := current.VerboseData.Hash
		if hash == s.state.Cursor || retained[hash] {
			reached = true
			break
		}
		if err := s.observeLocked(current); err != nil {
			return err
		}
		// Requests may be in a merged block, rather than in the selected-chain block.
		for _, merged := range current.VerboseData.MergeSetBluesHashes {
			if merged == hash {
				continue
			}
			b, err := s.rpc.GetBlock(merged, true)
			if err != nil {
				return err
			}
			if err = s.observeLocked(b); err != nil {
				return err
			}
		}
		added = append(added, chainPoint{Hash: hash, DAA: current.Header.DaaScore})
		if s.state.Cursor == "" && i >= 127 {
			reached = true
			break
		}
		parent := current.VerboseData.SelectedParentHash
		if parent == "" {
			reached = s.state.Cursor == ""
			break
		}
		var err error
		current, err = s.rpc.GetBlock(parent, true)
		if err != nil {
			return err
		}
	}
	if !reached {
		return fmt.Errorf("service checkpoint is beyond the bounded chain scan; restore/reconcile state before resuming")
	}
	// Remove the old fork suffix before retaining draw-seed candidates.
	if s.state.Cursor != "" && len(added) > 0 {
		ancestor := current.VerboseData.Hash
		for i, p := range s.state.Chain {
			if p.Hash == ancestor {
				s.state.Chain = s.state.Chain[:i+1]
				break
			}
		}
	}
	for i := len(added) - 1; i >= 0; i-- {
		s.state.Chain = append(s.state.Chain, added[i])
	}
	if len(s.state.Chain) > 8192 {
		s.state.Chain = s.state.Chain[len(s.state.Chain)-8192:]
	}
	s.state.Cursor = head
	return nil
}

func moreBlueWork(a, b *w.RpcBlock) bool {
	if a.Header == nil || a.VerboseData == nil {
		return false
	}
	if b.Header == nil || b.VerboseData == nil {
		return true
	}
	aw, bw := strings.TrimLeft(a.Header.BlueWork, "0"), strings.TrimLeft(b.Header.BlueWork, "0")
	if len(aw) != len(bw) {
		return len(aw) > len(bw)
	}
	if aw != bw {
		return aw > bw
	}
	return a.VerboseData.Hash > b.VerboseData.Hash
}

func (s *serviceRelay) poll() error {
	if !s.verifier.healthy() {
		return fmt.Errorf("protocol verifier unavailable")
	}
	template, err := s.rpc.GetBlockTemplate(s.api.payoutAddress, s.api.coinbaseExtra(nil))
	if err != nil {
		return err
	}
	if template.Block == nil || template.Block.Header == nil || (!template.IsSynced && !s.api.mineWhenNotSynced) {
		return fmt.Errorf("service node is not synced")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.daa = template.Block.Header.DaaScore
	for id, t := range s.state.Tasks {
		if s.daa > t.DAA && s.daa-t.DAA > serviceRetentionDAA && t.Draw == nil {
			delete(s.state.Tasks, id)
			delete(s.lastSent, id)
		}
	}
	if err = s.observeLocked(template.Block); err != nil {
		return err
	}
	if err = s.scanChainLocked(template.Block.Header); err != nil {
		return err
	}
	hashes := make([]string, 0, len(s.state.Tasks))
	for h := range s.state.Tasks {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)
	ledger, err := s.nodeObligationsLocked(hashes)
	if err != nil {
		return err
	}
	if !ledger.RequestsChecked {
		return fmt.Errorf("node has not checked inference obligations")
	}
	s.daa = ledger.VirtualDaaScore
	s.active = make(map[string]uint64)
	for _, r := range ledger.AwaitedRequests {
		s.active[r.RequestHash] = r.WindowEndDaa
	}
	for _, t := range s.state.Tasks {
		t.Draw = nil
	}
	for _, o := range ledger.Openings {
		if o.EscrowPubkey != s.state.Escrow {
			continue
		}
		var task *relayTask
		for _, t := range s.state.Tasks {
			if t.ResponseID == o.ResponseTxid {
				task = t
				break
			}
		}
		if task == nil {
			return fmt.Errorf("node awaits an opening with no retained worker/trace receipt")
		}
		if o.DeadlineDaa <= s.daa {
			return fmt.Errorf("an inference audit deadline has expired")
		}
		task.Draw = o
		if task.DrawBlock == "" || drawSeed(task.DrawBlock, task.ResponseID) != o.Seed {
			task.DrawBlock = ""
			for _, p := range s.state.Chain {
				if p.DAA >= o.AcceptedDaa && drawSeed(p.Hash, task.ResponseID) == o.Seed {
					task.DrawBlock = p.Hash
					break
				}
			}
		}
		if task.DrawBlock == "" {
			return fmt.Errorf("node draw has no retained canonical seed block")
		}
	}
	if err = s.saveLocked(); err != nil {
		return err
	}
	// Persist all prepared envelopes before sending them; retries reuse identical bytes.
	if err = s.submitLocked(); err != nil {
		return err
	}
	return s.dispatchLocked()
}

func drawSeed(block, response string) string {
	a, ea := hex.DecodeString(block)
	b, eb := hex.DecodeString(response)
	if ea != nil || eb != nil || len(a) != 32 || len(b) != 32 {
		return ""
	}
	h, _ := blake2b.New256(nil)
	h.Write([]byte("KeryxTraceDrawV1"))
	h.Write(a)
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

func (s *serviceRelay) workerLocked(owner, model string, busy map[string]bool) *gostratum.StratumContext {
	s.clients.clientLock.RLock()
	defer s.clients.clientLock.RUnlock()
	var selected *gostratum.StratumContext
	for _, cl := range s.clients.clients {
		if !cl.Connected() || !cl.IsAuthorized() || busy[cl.WorkerName] || (owner != "" && cl.WorkerName != owner) {
			continue
		}
		st := GetMiningState(cl)
		st.challengeLock.Lock()
		ok := st.capabilitiesReady
		st.challengeLock.Unlock()
		if !ok || !st.HasDeclaredModel(model) {
			continue
		}
		if selected == nil || cl.Id < selected.Id {
			selected = cl
		}
	}
	return selected
}

func (s *serviceRelay) dispatchLocked() error {
	busy := make(map[string]bool)
	keys := make([]string, 0, len(s.state.Tasks))
	for h := range s.state.Tasks {
		keys = append(keys, h)
	}
	sort.Strings(keys)
	// Audits take priority over new requests.
	for _, h := range keys {
		t := s.state.Tasks[h]
		if t.Draw == nil {
			continue
		}
		cl := s.workerLocked(t.Owner, t.Model, nil)
		if cl == nil {
			return fmt.Errorf("an owning audit worker is unavailable")
		}
		busy[cl.WorkerName] = true
		key := openingKey(t.Draw)
		if time.Since(s.lastSent[key]) < 10*time.Second {
			continue
		}
		if err := cl.Send(gostratum.NewEvent("", "mining.ai_opening", []any{t.ID, t.ResponseID, t.Draw.Seed, t.Draw.AttentionPath, "", ""})); err != nil {
			return err
		}
		s.lastSent[key] = time.Now()
	}
	for _, h := range keys {
		t := s.state.Tasks[h]
		if s.active[h] <= s.daa || t.ResponseID != "" {
			continue
		}
		v, err := s.verifier.call(map[string]any{"op": "request", "payload": t.Payload})
		if err != nil {
			return err
		}
		cl := s.workerLocked(t.Owner, v.Model, busy)
		if cl == nil && t.Owner != "" && time.Since(s.lastSent[h]) > 30*time.Second {
			t.Owner = ""
			cl = s.workerLocked("", v.Model, busy)
		}
		if cl == nil || busy[cl.WorkerName] {
			continue
		}
		busy[cl.WorkerName] = true
		if time.Since(s.lastSent[h]) < 30*time.Second {
			continue
		}
		t.Owner = cl.WorkerName
		t.Model = v.Model
		if err = s.saveLocked(); err != nil {
			return err
		}
		ext := map[string]any{"trace": map[string]any{"tier": v.Tier, "chain": true, "attention": true, "prompt_len": v.PromptLen}}
		if err = cl.Send(gostratum.NewEvent("", "mining.ai_request", []any{t.ID, t.ID, t.ID, v.Model, v.Prompt, v.MaxTokens, v.Reward, ext})); err != nil {
			return err
		}
		s.lastSent[h] = time.Now()
	}
	return nil
}

func openingKey(o *w.AwaitedOpeningMessage) string {
	b := []byte("[]")
	if len(o.AttentionPath) != 0 {
		b, _ = json.Marshal(o.AttentionPath)
	}
	return o.ResponseTxid + ":" + o.Seed + ":" + string(b)
}

func serviceTransaction(network, payload string) (*appmessage.RPCTransaction, string, error) {
	tx := &appmessage.RPCTransaction{SubnetworkID: network, Payload: payload, Inputs: []*appmessage.RPCTransactionInput{}, Outputs: []*appmessage.RPCTransactionOutput{}}
	domain, err := appmessage.RPCTransactionToDomainTransaction(tx)
	if err != nil {
		return nil, "", err
	}
	return tx, consensushashing.TransactionID(domain).String(), nil
}

func (s *serviceRelay) submitLocked() error {
	keys := make([]string, 0, len(s.state.Pending))
	for id := range s.state.Pending {
		keys = append(keys, id)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := s.state.Pending[keys[i]], s.state.Pending[keys[j]]
		if a.Kind != b.Kind {
			return a.Kind == "opening"
		}
		return a.Deadline < b.Deadline
	})
	sent := 0
	for _, id := range keys {
		p := s.state.Pending[id]
		t := s.state.Tasks[p.Task]
		if t == nil || p.Deadline <= s.daa {
			delete(s.state.Pending, id)
			delete(s.lastSubmit, id)
			continue
		}
		if p.Kind == "response" && s.active[p.Task] <= s.daa {
			continue
		}
		if p.Kind == "opening" && (t.Draw == nil || p.Digest != openingKey(t.Draw)) {
			delete(s.state.Pending, id)
			continue
		}
		if time.Since(s.lastSubmit[id]) < 10*time.Second {
			continue
		}
		if sent >= 4 {
			break
		}
		sent++
		s.lastSubmit[id] = time.Now()
		returnedID, err := s.rpc.SubmitServiceTransaction(p.TX.SubnetworkID, p.TX.Payload)
		if err != nil {
			s.api.logger.Warnw("prepared service transaction remains pending", "kind", p.Kind, "txid", id)
			continue
		}
		if returnedID != id {
			return fmt.Errorf("node service transaction ID mismatch")
		}
		// Mempool admission is not chain acceptance. Keep the envelope for reconciliation.
	}
	return s.saveLocked()
}

func relayError(ctx *gostratum.StratumContext, event gostratum.JsonRpcEvent, code int, message string) error {
	return ctx.Reply(gostratum.JsonRpcResponse{Id: event.Id, Result: nil, Error: []any{code, message, nil}})
}

func (s *serviceRelay) HandleAnswer(ctx *gostratum.StratumContext, event gostratum.JsonRpcEvent) error {
	if !ctx.IsAuthorized() || len(event.Params) != 6 {
		return relayError(ctx, event, 24, "authorized traced response required")
	}
	p := make([]string, 5)
	for i := range p {
		var ok bool
		p[i], ok = event.Params[i].(string)
		if !ok {
			return relayError(ctx, event, 20, "invalid response fields")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.state.Tasks[p[1]]
	if t == nil || t.Owner != ctx.WorkerName || p[0] != workerLogin(ctx) || p[2] != t.ID || p[3] != t.Model {
		return relayError(ctx, event, 24, "response does not belong to this worker/request/model")
	}
	raw, err := json.Marshal(event.Params)
	if err != nil {
		return relayError(ctx, event, 20, "invalid response")
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	if t.ResponseID != "" {
		if t.AnswerDigest != digest {
			return relayError(ctx, event, 22, "request already has another prepared response")
		}
		if err := s.saveLocked(); err != nil {
			s.err = "cannot persist prepared response"
			return relayError(ctx, event, 46, "response persistence failed")
		}
		return ctx.Reply(gostratum.NewResponse(event, true, nil))
	}
	ledger, err := s.nodeObligationsLocked([]string{t.ID})
	if err != nil || !ledger.RequestsChecked {
		return relayError(ctx, event, 46, "node obligation check unavailable")
	}
	var deadline uint64
	for _, r := range ledger.AwaitedRequests {
		if r.RequestHash == t.ID {
			deadline = r.WindowEndDaa
		}
	}
	if deadline <= ledger.VirtualDaaScore {
		return relayError(ctx, event, 21, "request is not currently awaited")
	}
	extBytes, _ := json.Marshal(event.Params[5])
	var ext struct {
		Trace string `json:"trace"`
		Body  string `json:"body"`
	}
	if json.Unmarshal(extBytes, &ext) != nil {
		return relayError(ctx, event, 20, "invalid trace extension")
	}
	v, err := s.verifier.call(map[string]any{"op": "answer", "payload": t.Payload, "request": t.ID, "text": p[4], "trace": ext.Trace, "body": ext.Body, "daa": ledger.VirtualDaaScore})
	if err != nil {
		return relayError(ctx, event, 20, "answer/trace verification failed")
	}
	tx, id, err := serviceTransaction(subnetworkAiResponse, v.Payload)
	if err != nil {
		return relayError(ctx, event, 20, "invalid signed response")
	}
	t.ResponseID = id
	t.AnswerDigest = digest
	t.ResponsePayload = v.Payload
	s.state.Pending[id] = &relayTX{TX: tx, Task: t.ID, Deadline: deadline, Kind: "response", Digest: digest}
	if err = s.saveLocked(); err != nil {
		s.err = "cannot persist prepared response"
		return relayError(ctx, event, 46, "response persistence failed")
	}
	return ctx.Reply(gostratum.NewResponse(event, true, nil))
}

func (s *serviceRelay) HandleOpening(ctx *gostratum.StratumContext, event gostratum.JsonRpcEvent) error {
	if !ctx.IsAuthorized() || len(event.Params) != 6 {
		return relayError(ctx, event, 24, "authorized opening required")
	}
	get := func(i int) string { v, _ := event.Params[i].(string); return v }
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.state.Tasks[get(1)]
	if t == nil || t.Owner != ctx.WorkerName || get(0) != workerLogin(ctx) || get(2) != t.ResponseID || t.Draw == nil {
		return relayError(ctx, event, 24, "opening does not belong to this worker/response")
	}
	if get(5) != "" {
		s.err = "owning worker could not produce an audit opening"
		return relayError(ctx, event, 46, "worker audit failure retained")
	}
	ledger, err := s.nodeObligationsLocked(nil)
	if err != nil {
		return relayError(ctx, event, 46, "node draw check unavailable")
	}
	var draw *w.AwaitedOpeningMessage
	for _, o := range ledger.Openings {
		if o.ResponseTxid == t.ResponseID && o.EscrowPubkey == s.state.Escrow {
			draw = o
			break
		}
	}
	pathBytes, _ := json.Marshal(event.Params[3])
	var path []uint64
	if draw == nil || draw.DeadlineDaa <= ledger.VirtualDaaScore || json.Unmarshal(pathBytes, &path) != nil || openingKey(draw) != openingKey(t.Draw) || fmt.Sprint(path) != fmt.Sprint(draw.AttentionPath) {
		return relayError(ctx, event, 21, "no matching current node audit draw")
	}
	previous := ""
	if len(path) > 0 {
		parent := proto.Clone(draw).(*w.AwaitedOpeningMessage)
		parent.AttentionPath = path[:len(path)-1]
		previous = t.PhaseRoots[openingKey(parent)]
	}
	v, err := s.verifier.call(map[string]any{"op": "opening", "body": get(4), "response": t.ResponseID, "seed_block": t.DrawBlock, "draw_seed": draw.Seed, "path": path, "pieces": draw.Pieces, "payload": t.Payload, "request": t.ID, "signed_response": t.ResponsePayload, "previous_root": previous})
	if err != nil {
		return relayError(ctx, event, 20, "invalid audit opening or seed binding")
	}
	for _, payload := range v.Payloads {
		tx, id, err := serviceTransaction("0600000000000000000000000000000000000000", payload)
		if err != nil {
			return relayError(ctx, event, 20, "invalid signed opening")
		}
		s.state.Pending[id] = &relayTX{TX: tx, Task: t.ID, Deadline: draw.DeadlineDaa, Kind: "opening", Digest: openingKey(draw)}
	}
	if v.AttentionRoot != "" {
		if t.PhaseRoots == nil {
			t.PhaseRoots = make(map[string]string)
		}
		t.PhaseRoots[openingKey(draw)] = v.AttentionRoot
	}
	if err = s.saveLocked(); err != nil {
		s.err = "cannot persist prepared opening"
		return relayError(ctx, event, 46, "opening persistence failed")
	}
	return ctx.Reply(gostratum.NewResponse(event, true, nil))
}

func workerLogin(ctx *gostratum.StratumContext) string {
	if ctx.WorkerName == "" {
		return ctx.WalletAddr
	}
	return ctx.WalletAddr + "." + ctx.WorkerName
}

// Loopback operator status contains no task payloads, plaintext or worker tokens.
func (s *serviceRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	audits := 0
	for _, t := range s.state.Tasks {
		if t.Draw != nil {
			audits++
		}
	}
	fresh := !s.lastGood.IsZero() && time.Since(s.lastGood) < 30*time.Second
	ready := fresh && s.err == ""
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(map[string]any{"ready": ready, "observed_utc": s.lastGood.UTC(), "virtual_daa": s.daa, "retained_requests": len(s.state.Tasks), "prepared_envelopes": len(s.state.Pending), "pending_audits": audits, "error": s.err})
}
