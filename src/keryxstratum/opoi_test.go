package keryxstratum

import (
	"encoding/hex"
	"testing"
)

// TestForwardFixedRegression pins the fixed-point MLP output against the Rust
// reference vector in keryx-node/inference/src/model_fixed.rs
// (fixed_point_regression_nonce_42): forward(from_nonce(42)) == b693a987fbe88110.
// This guarantees the Go port is bit-exact with the node's verifier, so the
// coinbase tag we embed will pass verify_tag_fixed on-chain.
func TestForwardFixedRegression(t *testing.T) {
	// Rebuild from_nonce(42) WITHOUT the phase-2 salt (the regression vector is unsalted).
	var input [32]byte
	for i := uint(0); i < 8; i++ {
		input[i] = byte(uint64(42) >> (i * 8))
	}
	for i := 8; i < 32; i++ {
		input[i] = byte(modelSeed >> (uint((i-8)%8) * 8))
	}
	out := forwardFixed(input)
	got := hex.EncodeToString(out[:8])
	const want = "b693a987fbe88110"
	if got != want {
		t.Fatalf("forwardFixed regression mismatch: got %s want %s", got, want)
	}
}
