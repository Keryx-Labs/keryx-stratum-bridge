package keryxstratum

// Fixed-point MLP for OPoI Phase 2 — port of keryx-node/inference/src/model_fixed.rs.
//
// Implements the same deterministic 3-layer MLP (32→256→128→32, i32/i64 only)
// so the bridge can verify that stratum miners actually ran the computation.
// Results are bit-exact with the Rust implementation on every platform.

import "encoding/hex"

const (
	modelSeed      uint64 = 0x4B657279784F5000
	phase2OPoISalt uint64 = 0x00323a585952454B // u64::from_le_bytes(*b"KERYX:2\0")

	normShift = 10

	nIn, nH1, nH2, nOut = 32, 256, 128, 32
	heL1, heL2, heL3    = int64(256), int64(90), int64(128)

	lcgMul  uint64 = 6_364_136_223_846_793_005
	lcgAdd  uint64 = 1_442_695_040_888_963_407
	layerMul uint64 = 0xDEADBEEFCAFE1337
)

// lcgWeight advances the LCG state and returns a weight in (-heScale, +heScale).
// Matches the Rust model_fixed::lcg_weight exactly (upper-32-bit extraction).
func lcgWeight(state *uint64, heScale int64) int32 {
	*state = *state*lcgMul + lcgAdd
	upper32 := uint32(*state >> 32)
	raw := int64(int32(upper32)) // reinterpret bits as signed, sign-extend to i64
	return int32((raw * heScale) >> 31)
}

// makeWeights generates the weight matrix for one layer using the shared LCG.
func makeWeights(rows, cols int, layerID uint64, he int64) []int32 {
	s := modelSeed + layerID*layerMul
	w := make([]int32, rows*cols)
	for i := range w {
		w[i] = lcgWeight(&s, he)
	}
	return w
}

// forwardFixed runs the fixed-point MLP forward pass and returns 32 output bytes.
func forwardFixed(input [32]byte) [32]byte {
	// Center input: raw [0,255] → signed [-128,127]
	x := make([]int64, nIn)
	for i, b := range input {
		x[i] = int64(b) - 128
	}

	// Layer 1: nIn → nH1, ReLU
	w1 := makeWeights(nH1, nIn, 0, heL1)
	h1 := make([]int64, nH1)
	for i := range h1 {
		var acc int64
		for j := 0; j < nIn; j++ {
			acc += x[j] * int64(w1[i*nIn+j])
		}
		if v := acc >> normShift; v > 0 {
			h1[i] = v
		}
	}

	// Layer 2: nH1 → nH2, ReLU
	w2 := makeWeights(nH2, nH1, 1, heL2)
	h2 := make([]int64, nH2)
	for i := range h2 {
		var acc int64
		for j := 0; j < nH1; j++ {
			acc += h1[j] * int64(w2[i*nH1+j])
		}
		if v := acc >> normShift; v > 0 {
			h2[i] = v
		}
	}

	// Layer 3: nH2 → nOut, identity
	w3 := makeWeights(nOut, nH2, 2, heL3)
	h3 := make([]int64, nOut)
	for i := range h3 {
		var acc int64
		for j := 0; j < nH2; j++ {
			acc += h2[j] * int64(w3[i*nH2+j])
		}
		h3[i] = acc
	}

	// XOR-fold each i64 output into 1 byte (same as Rust's to_le_bytes XOR)
	var out [32]byte
	for i, v := range h3 {
		out[i] = byte(v) ^ byte(v>>8) ^ byte(v>>16) ^ byte(v>>24) ^
			byte(v>>32) ^ byte(v>>40) ^ byte(v>>48) ^ byte(v>>56)
	}
	return out
}

// tagFixed computes the 16-char hex OPoI tag for the given PoW nonce.
// Matches keryx_inference::tag_fixed(nonce) exactly.
func tagFixed(nonce uint64) string {
	saltedNonce := nonce ^ phase2OPoISalt

	// InferenceTask::from_nonce: nonce in [0..8] LE, MODEL_SEED bytes repeated in [8..32]
	var input [32]byte
	for i := uint(0); i < 8; i++ {
		input[i] = byte(saltedNonce >> (i * 8))
	}
	for i := 8; i < 32; i++ {
		input[i] = byte(modelSeed >> (uint((i-8)%8) * 8))
	}

	out := forwardFixed(input)
	return hex.EncodeToString(out[:8])
}

// verifyOPoITag returns true iff submittedTag equals tagFixed(nonce).
func verifyOPoITag(nonce uint64, submittedTag string) bool {
	return len(submittedTag) == 16 && tagFixed(nonce) == submittedTag
}
