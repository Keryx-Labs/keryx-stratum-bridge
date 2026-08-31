package keryxstratum

import (
	"encoding/binary"
	"math/big"
	"testing"
)

// The borsh PomProof prefix is tier u8 | trace_root [32] | pow_value [32] | final_state u64 LE.
func TestPomProofPrefixExtraction(t *testing.T) {
	proof := make([]byte, pomProofMinLen)
	proof[0] = 3 // tier

	// pow_value = 0x01 at the most significant byte (little-endian: last byte of the field)
	proof[pomProofPowValueOffset+31] = 0x01
	// low byte too, so both ends of the reversal are exercised
	proof[pomProofPowValueOffset] = 0xff

	binary.LittleEndian.PutUint64(proof[pomProofFinalStateStart:pomProofFinalStateStart+8], 0xdeadbeef12345678)

	powValue := pomProofPowValue(proof)
	expected := new(big.Int).Lsh(big.NewInt(1), 248)
	expected.Add(expected, big.NewInt(0xff))
	if powValue.Cmp(expected) != 0 {
		t.Fatalf("pow value mismatch: got %x, want %x", &powValue, expected)
	}

	finalState := binary.LittleEndian.Uint64(proof[pomProofFinalStateStart : pomProofFinalStateStart+8])
	if finalState != 0xdeadbeef12345678 {
		t.Fatalf("final state mismatch: got %x", finalState)
	}
	if proof[0] != 3 {
		t.Fatalf("tier mismatch")
	}
}
