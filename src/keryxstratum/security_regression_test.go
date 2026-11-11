package keryxstratum

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/keryx-labs/keryx-stratum-bridge/src/gostratum"
	w "github.com/keryx-labs/keryx-stratum-bridge/src/keryxrpc/keryxwire"
	"go.uber.org/zap"
)

func TestEscrowStandingUsesDelegatedIdentity(t *testing.T) {
	r := &w.GetServiceStrikesResponseMessage{VirtualDaaScore: 100,
		Strikes:         []*w.ServiceStrikeMessage{{Miner: "escrow", ConsecutiveMisses: 99}, {Miner: "identity", ConsecutiveMisses: 2, LastStrikeDaaScore: 80}},
		LifetimeStrikes: []*w.ServiceStrikeTotalMessage{{Miner: "identity", Strikes: 7}},
		Suspended:       []*w.ServiceSuspensionMessage{{Miner: "identity", UntilDaaScore: 200}},
		PendingBurns:    []*w.ServicePendingBurnMessage{{Miner: "identity", BurnedClaims: 3, BurnedSompi: 9007199254740999}},
	}
	v := projectStanding(r, "escrow", "identity", time.Now().UTC())
	if v.ConsecutiveMisses != 2 || v.LifetimeStrikes != 7 || v.SuspendedUntilDAA != 200 || v.BurnedSompi != "9007199254740999" || v.BurnedClaims != 3 {
		t.Fatalf("wrong delegated standing: %+v", v)
	}
	m := &strikeMonitor{value: v}
	m.value.ObservedUTC = time.Now().Add(-time.Minute)
	stale := m.snapshot()
	if stale.Available || stale.ConsecutiveMisses != 2 {
		t.Fatal("stale data must retain the observation and report unavailable")
	}
}

func TestUnsyncedNodeCannotReplaceStrikeObservationWithZero(t *testing.T) {
	m := &strikeMonitor{value: escrowStanding{EscrowKey: "escrow", ServiceIdentity: "identity",
		ObservedUTC: time.Now().UTC(), Available: true, ConsecutiveMisses: 2, LifetimeStrikes: 7},
		nodeSynced: func() (bool, error) { return false, nil }}
	m.poll()
	v := m.snapshot()
	if v.Available || v.ConsecutiveMisses != 2 || v.LifetimeStrikes != 7 || v.Error == "" {
		t.Fatalf("unsynced node overwrote or advertised the previous standing: %+v", v)
	}
}

func TestPoMCapabilitiesAdmitJobsWithoutLegacyChallenge(t *testing.T) {
	const model = "399984045600f7d58d1b2cf01e6a4bf466fa15c7ac31bd0dd1a71e003b617cc6"
	ctx, conn := gostratum.NewMockContext(context.Background(), zap.NewNop(), MiningStateGenerator())
	t.Cleanup(func() { conn.Close() })
	ctx.StratumV3 = true
	ctx.MarkAuthorized()
	sh := &shareHandler{models: map[string]bool{model: true}}
	reply := make(chan []byte, 1)
	conn.AsyncReadTestDataFromBuffer(func(data []byte) { reply <- data })
	if err := sh.HandleDeclareCapabilities(ctx, gostratum.NewEvent("1", "mining.declare_capabilities", []any{model})); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reply:
	case <-time.After(time.Second):
		t.Fatal("missing model declaration reply")
	}
	state := GetMiningState(ctx)
	if !state.capabilitiesReady || !state.HasDeclaredModel(model) {
		t.Fatal("official PoM miner would wait for a job behind an ignored legacy challenge")
	}
	if sh.canMine() {
		t.Fatal("a model declaration bypassed verifier, service or strike readiness")
	}
	// Official miner periodically repeats the same declaration on a live session.
	conn.AsyncReadTestDataFromBuffer(func(data []byte) { reply <- data })
	if err := sh.HandleDeclareCapabilities(ctx, gostratum.NewEvent("2", "mining.declare_capabilities", []any{model})); err != nil {
		t.Fatal(err)
	}
	select {
	case data := <-reply:
		if !strings.Contains(string(data), `"result":true`) {
			t.Fatalf("periodic identical declaration was rejected: %s", data)
		}
	case <-time.After(time.Second):
		t.Fatal("missing repeated declaration reply")
	}
}

func TestStratumDifficultyMatchesOfficialMinerTargets(t *testing.T) {
	for _, tc := range []struct {
		diff   float64
		target string
	}{
		{1, "00000000ffff0000000000000000000000000000000000000000000000000000"},
		{4, "000000003fffc000000000000000000000000000000000000000000000000000"},
	} {
		want, ok := new(big.Int).SetString(tc.target, 16)
		if !ok || DiffToTarget(tc.diff).Cmp(want) != 0 {
			t.Fatalf("difficulty %v does not match the official miner target", tc.diff)
		}
	}
}

func TestAuthorizationRejectsCrossPayoutAndWrongToken(t *testing.T) {
	token := strings.Repeat("test-only-token-", 4)
	cfg := BridgeConfig{PayoutAddress: "keryx:q"}
	auth := map[string][32]byte{"rig01": sha256.Sum256([]byte(token))}
	for _, tc := range []struct {
		name, login, password string
		want                  bool
	}{
		{"valid", "keryx:q.rig01", token, true},
		{"another payout", "keryx:p.rig01", token, false},
		{"unknown worker", "keryx:q.rig02", token, false},
		{"wrong token", "keryx:q.rig01", strings.Repeat("x", 64), false},
		{"injected marker", "keryx:q/escrow:attacker.rig01", token, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, conn := gostratum.NewMockContext(context.Background(), zap.NewNop(), MiningStateGenerator())
			t.Cleanup(func() { conn.Close() })
			ctx.StratumV3 = true
			done := make(chan struct{}, 1)
			conn.AsyncReadTestDataFromBuffer(func([]byte) { done <- struct{}{} })
			err := secureAuthorize(cfg, auth)(ctx, gostratum.NewEvent("1", "mining.authorize", []any{tc.login, tc.password}))
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("missing authorization reply")
			}
			if ctx.IsAuthorized() != tc.want {
				t.Fatalf("authorized=%v", ctx.IsAuthorized())
			}
		})
	}
}

func TestBoundedHelperReplyRejectsOversizedUnterminatedLine(t *testing.T) {
	reader := bufio.NewReaderSize(strings.NewReader(strings.Repeat("a", 4096)), 32)
	if _, err := readBoundedLine(reader, 64); err == nil {
		t.Fatal("oversized helper reply accepted")
	}
}

func TestDuplicateSharesStayRejectedUntilJobExpires(t *testing.T) {
	state := MiningStateGenerator().(*MiningState)
	id := state.AddJob(&BlockJob{})
	if !state.rememberShare(id, "nonce:tier") || state.rememberShare(id, "nonce:tier") {
		t.Fatal("duplicate work was credited")
	}
	for i := 0; i < maxjobs; i++ {
		state.AddJob(&BlockJob{})
	}
	if _, ok := state.GetJob(id); ok {
		t.Fatal("expired job remains live")
	}
	if state.rememberShare(id, "other nonce") {
		t.Fatal("expired job was reinserted during verification")
	}
}

func TestCoinbaseMarkersCannotComeFromMinerApplicationName(t *testing.T) {
	api := &KeryxApi{escrowPubKey: strings.Repeat("a", 64), escrowCert: strings.Repeat("b", 128)}
	extra := api.coinbaseExtra([]string{strings.Repeat("c", 64)})
	if strings.Count(extra, "/escrow:") != 1 || strings.Count(extra, "/esig:") != 1 || !strings.HasPrefix(extra, fmt.Sprintf("keryx-bridge/%s/escrow:%s", version, api.escrowPubKey)) {
		t.Fatal("noncanonical consensus markers")
	}
}
