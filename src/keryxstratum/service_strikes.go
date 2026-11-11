package keryxstratum

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/keryx-labs/keryx-stratum-bridge/src/keryxrpc"
	w "github.com/keryx-labs/keryx-stratum-bridge/src/keryxrpc/keryxwire"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type escrowStanding struct {
	EscrowKey         string    `json:"escrow_key"`
	ServiceIdentity   string    `json:"service_identity"`
	ObservedUTC       time.Time `json:"observed_utc"`
	VirtualDAA        uint64    `json:"virtual_daa"`
	Available         bool      `json:"available"`
	ConsecutiveMisses uint32    `json:"consecutive_misses"`
	LifetimeStrikes   uint32    `json:"lifetime_strikes"`
	LastStrikeDAA     uint64    `json:"last_strike_daa"`
	SuspendedUntilDAA uint64    `json:"suspended_until_daa"`
	PendingBurns      uint64    `json:"pending_burns"`
	BurnedClaims      uint64    `json:"burned_claims"`
	BurnedSompi       string    `json:"burned_sompi"`
	Error             string    `json:"error,omitempty"`
}
type strikeMonitor struct {
	mu         sync.RWMutex
	value      escrowStanding
	rpc        *keryxrpc.Client
	nodeSynced func() (bool, error)
}

var escrowStrikeGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "ks_escrow_service_status", Help: "Node service standing by delegated escrow key and payout identity; missing/stale observations are unavailable."}, []string{"escrow_key", "service_identity", "field"})

func newStrikeMonitor(address, key, identity string, nodeSynced func() (bool, error)) *strikeMonitor {
	return &strikeMonitor{rpc: keryxrpc.NewClient(address), nodeSynced: nodeSynced, value: escrowStanding{EscrowKey: key, ServiceIdentity: identity, BurnedSompi: "0"}}
}

func (m *strikeMonitor) snapshot() escrowStanding {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v := m.value
	if v.ObservedUTC.IsZero() || time.Since(v.ObservedUTC) > 45*time.Second {
		v.Available = false
		v.Error = "node observation unavailable or stale"
	}
	return v
}
func (m *strikeMonitor) Start(ctx context.Context) {
	go func() {
		defer m.rpc.Close()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			m.poll()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
func (m *strikeMonitor) poll() {
	if m.nodeSynced == nil {
		m.unavailable("node sync observation unavailable")
		return
	}
	synced, syncErr := m.nodeSynced()
	if syncErr != nil || !synced {
		m.unavailable("node strike observation unavailable: node is not synced")
		return
	}
	r, err := m.rpc.GetServiceStrikes()
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.value.Available = false
		m.value.Error = "node strike RPC unavailable"
		escrowStrikeGauge.WithLabelValues(m.value.EscrowKey, m.value.ServiceIdentity, "available").Set(0)
		return
	}
	v := projectStanding(r, m.value.EscrowKey, m.value.ServiceIdentity, time.Now().UTC())
	m.value = v
	for field, value := range map[string]float64{"available": boolFloat(v.Available), "consecutive_misses": float64(v.ConsecutiveMisses), "lifetime_strikes": float64(v.LifetimeStrikes), "last_strike_daa": float64(v.LastStrikeDAA), "suspended_until_daa": float64(v.SuspendedUntilDAA), "pending_burns": float64(v.PendingBurns), "burned_claims": float64(v.BurnedClaims), "burned_sompi": sompiFloat(v.BurnedSompi), "observed_unix": float64(v.ObservedUTC.Unix())} {
		escrowStrikeGauge.WithLabelValues(v.EscrowKey, v.ServiceIdentity, field).Set(value)
	}
}

func (m *strikeMonitor) unavailable(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.value.Available = false
	m.value.Error = reason
	escrowStrikeGauge.WithLabelValues(m.value.EscrowKey, m.value.ServiceIdentity, "available").Set(0)
}
func boolFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
func (m *strikeMonitor) String() string {
	v := m.snapshot()
	if !v.Available {
		return fmt.Sprintf("escrow %s: node strikes unavailable (last observation %s)", v.EscrowKey, v.ObservedUTC.Format(time.RFC3339))
	}
	return fmt.Sprintf("escrow %s | identity %s | strikes %d consecutive / %d lifetime | pending burns %d (%s sompi) | suspended until DAA %d", v.EscrowKey, v.ServiceIdentity, v.ConsecutiveMisses, v.LifetimeStrikes, v.PendingBurns, v.BurnedSompi, v.SuspendedUntilDAA)
}
func (m *strikeMonitor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	v := m.snapshot()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if !v.Available {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(v)
}

func projectStanding(r *w.GetServiceStrikesResponseMessage, key, identity string, observed time.Time) escrowStanding {
	v := escrowStanding{EscrowKey: key, ServiceIdentity: identity, Available: true, ObservedUTC: observed, VirtualDAA: r.VirtualDaaScore, BurnedSompi: "0"}
	// Consensus penalties are keyed by miner_key(payout SPK), not by the hot
	// escrow key itself. The delegation certificate verified at startup supplies
	// the binding used here. Never attribute an IP/client-side challenge to it.
	for _, x := range r.Strikes {
		if strings.EqualFold(x.Miner, v.ServiceIdentity) {
			v.ConsecutiveMisses = x.ConsecutiveMisses
			v.LastStrikeDAA = x.LastStrikeDaaScore
		}
	}
	for _, x := range r.LifetimeStrikes {
		if strings.EqualFold(x.Miner, v.ServiceIdentity) {
			v.LifetimeStrikes = x.Strikes
		}
	}
	for _, x := range r.Suspended {
		if strings.EqualFold(x.Miner, v.ServiceIdentity) && x.UntilDaaScore > v.SuspendedUntilDAA {
			v.SuspendedUntilDAA = x.UntilDaaScore
		}
	}
	var burned uint64
	for _, x := range r.PendingBurns {
		if strings.EqualFold(x.Miner, v.ServiceIdentity) {
			v.PendingBurns++
			v.BurnedClaims += uint64(x.BurnedClaims)
			if ^uint64(0)-burned < x.BurnedSompi {
				v.Available = false
				v.Error = "node burn total overflow"
			} else {
				burned += x.BurnedSompi
			}
		}
	}
	v.BurnedSompi = strconv.FormatUint(burned, 10)

	return v
}

func sompiFloat(amount string) float64 { v, _ := strconv.ParseFloat(amount, 64); return v }
