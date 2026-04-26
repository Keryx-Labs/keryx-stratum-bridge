package keryxstratum

import (
	"encoding/binary"
	"math/big"

	"golang.org/x/crypto/sha3"
)

// KeryxHash algorithm constants — must stay in sync with keryx-node/consensus/pow/src/matrix.rs.

// keryxMatrixSalt is XORed into the pre_pow_hash before seeding the PRNG.
// Changing this value is an incompatible hard fork.
var keryxMatrixSalt = [32]byte{'K', 'E', 'R', 'Y', 'X', ':', 'K', 'e', 'r', 'y', 'x', 'H', 'a', 's', 'h', '-', 'v', '1', ':', '2', '0', '2', '6', '-', '0', '4', '-', '1', '2', ':', 'x', 'x'}

// waveMixKeys are the per-round XOR constants for the ARX post-processing step.
var waveMixKeys = [4]uint64{
	0x9e3779b97f4a7c15, // fractional bits of φ
	0x6c62272e07bb0142, // Keryx network discriminator
	0xb5ad4eceda1ce2a9, // fractional bits of √3
	0x243f6a8885a308d3, // fractional bits of π
}

// waveMixRotations are the bit-rotation amounts used in each ARX round.
// Values are coprime to 64 to avoid fixed-point cycles.
var waveMixRotations = [4]uint{17, 31, 47, 13}

// --- XoShiRo256++ PRNG (identical to keryx-node/consensus/pow/src/xoshiro.rs) ---

type xoShiRo256PlusPlus struct {
	s [4]uint64
}

func newXoShiRo(seed [32]byte) *xoShiRo256PlusPlus {
	return &xoShiRo256PlusPlus{s: [4]uint64{
		binary.LittleEndian.Uint64(seed[0:8]),
		binary.LittleEndian.Uint64(seed[8:16]),
		binary.LittleEndian.Uint64(seed[16:24]),
		binary.LittleEndian.Uint64(seed[24:32]),
	}}
}

func rotl64(x uint64, k uint) uint64 {
	return (x << k) | (x >> (64 - k))
}

func (rng *xoShiRo256PlusPlus) next() uint64 {
	result := rotl64(rng.s[0]+rng.s[3], 23) + rng.s[0]
	t := rng.s[1] << 17
	rng.s[2] ^= rng.s[0]
	rng.s[3] ^= rng.s[1]
	rng.s[1] ^= rng.s[2]
	rng.s[0] ^= rng.s[3]
	rng.s[2] ^= t
	rng.s[3] = rotl64(rng.s[3], 45)
	return result
}

// --- Matrix generation (identical to keryx-node/consensus/pow/src/matrix.rs) ---

type keryxMatrix [64][64]uint16

// generateKeryxMatrix derives the 64×64 PoW matrix from a pre_pow_hash.
// KERYX_MATRIX_SALT is XORed into the seed before the PRNG, ensuring no Kaspa
// nonce can satisfy the Keryx target.
func generateKeryxMatrix(prePowHash [32]byte) keryxMatrix {
	var salted [32]byte
	for i := range prePowHash {
		salted[i] = prePowHash[i] ^ keryxMatrixSalt[i]
	}
	rng := newXoShiRo(salted)
	for {
		var mat keryxMatrix
		for i := 0; i < 64; i++ {
			for j := 0; j < 64; j += 16 {
				val := rng.next()
				for shift := 0; shift < 16; shift++ {
					mat[i][j+shift] = uint16((val >> (4 * uint(shift))) & 0x0F)
				}
			}
		}
		if keryxMatrixRank(mat) == 64 {
			return mat
		}
	}
}

// keryxMatrixRank computes the rank of the 64×64 matrix via Gaussian elimination.
func keryxMatrixRank(mat keryxMatrix) int {
	const eps = 1e-9
	var m [64][64]float64
	for i := 0; i < 64; i++ {
		for j := 0; j < 64; j++ {
			m[i][j] = float64(mat[i][j])
		}
	}
	rank := 0
	var rowSelected [64]bool
	for i := 0; i < 64; i++ {
		j := 0
		for j < 64 {
			v := m[j][i]
			if v < 0 {
				v = -v
			}
			if !rowSelected[j] && v > eps {
				break
			}
			j++
		}
		if j == 64 {
			continue
		}
		rank++
		rowSelected[j] = true
		for p := i + 1; p < 64; p++ {
			m[j][p] /= m[j][i]
		}
		for k := 0; k < 64; k++ {
			v := m[k][i]
			if v < 0 {
				v = -v
			}
			if k != j && v > eps {
				for p := i + 1; p < 64; p++ {
					m[k][p] -= m[j][p] * m[k][i]
				}
			}
		}
	}
	return rank
}

// --- wave_mix ARX post-processing (identical to keryx-node/consensus/pow/src/matrix.rs) ---

// waveMix applies 4 rounds of ARX (Add-Rotate-XOR) to the 32-byte matrix product.
// It runs after the matrix multiply and before the final cSHAKE256("HeavyHash").
func waveMix(data [32]byte) [32]byte {
	w := [4]uint64{
		binary.LittleEndian.Uint64(data[0:8]),
		binary.LittleEndian.Uint64(data[8:16]),
		binary.LittleEndian.Uint64(data[16:24]),
		binary.LittleEndian.Uint64(data[24:32]),
	}
	for r := 0; r < 4; r++ {
		// Step A: vertical pairs, independent → GPU-parallel
		w[0] = rotl64(w[0]+w[1], waveMixRotations[0]) ^ waveMixKeys[r%4]
		w[2] = rotl64(w[2]+w[3], waveMixRotations[2]) ^ waveMixKeys[(r+2)%4]
		// Step B: diagonal pairs use updated w[0]/w[2] → full avalanche
		w[1] = rotl64(w[1]+w[2], waveMixRotations[1]) ^ waveMixKeys[(r+1)%4]
		w[3] = rotl64(w[3]+w[0], waveMixRotations[3]) ^ waveMixKeys[(r+3)%4]
	}
	var out [32]byte
	binary.LittleEndian.PutUint64(out[0:8], w[0])
	binary.LittleEndian.PutUint64(out[8:16], w[1])
	binary.LittleEndian.PutUint64(out[16:24], w[2])
	binary.LittleEndian.PutUint64(out[24:32], w[3])
	return out
}

// --- Full KeryxHash pipeline ---

// computePowHash computes cSHAKE256("ProofOfWorkHash", prePowHash || timestamp_LE || zeros32 || nonce_LE).
func computePowHash(prePowHash [32]byte, timestamp, nonce uint64) [32]byte {
	h := sha3.NewCShake256(nil, []byte("ProofOfWorkHash"))
	h.Write(prePowHash[:])
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], timestamp)
	h.Write(buf[:])
	h.Write(make([]byte, 32))
	binary.LittleEndian.PutUint64(buf[:], nonce)
	h.Write(buf[:])
	var out [32]byte
	h.Read(out[:])
	return out
}

// applyKeryxHash applies matrix multiply + wave_mix + cSHAKE256("HeavyHash") to a PowHash output.
func applyKeryxHash(mat keryxMatrix, powHash [32]byte) [32]byte {
	// Split 32 bytes into 64 nibbles
	var vec [64]uint8
	for i, b := range powHash {
		vec[2*i] = b >> 4
		vec[2*i+1] = b & 0x0F
	}
	// 64×64 matrix-vector multiply, keep top 4 bits of each 16-bit accumulator
	var product [32]byte
	for i := 0; i < 32; i++ {
		var sum1, sum2 uint32
		for j := 0; j < 64; j++ {
			sum1 += uint32(mat[2*i][j]) * uint32(vec[j])
			sum2 += uint32(mat[2*i+1][j]) * uint32(vec[j])
		}
		product[i] = byte(((sum1>>10)<<4)|(sum2>>10)) ^ powHash[i]
	}
	// wave_mix ARX post-processing
	product = waveMix(product)
	// Final cSHAKE256("HeavyHash")
	h := sha3.NewCShake256(nil, []byte("HeavyHash"))
	h.Write(product[:])
	var out [32]byte
	h.Read(out[:])
	return out
}

// CalculateKeryxPoW returns the KeryxHash PoW value as a big.Int for comparison
// against the block target. The result is a 256-bit integer derived from the
// final hash bytes interpreted in little-endian order.
func CalculateKeryxPoW(prePowHash [32]byte, timestamp, nonce uint64) *big.Int {
	powHash := computePowHash(prePowHash, timestamp, nonce)
	matrix := generateKeryxMatrix(prePowHash)
	finalHash := applyKeryxHash(matrix, powHash)

	// big.Int uses big-endian: reverse the LE hash bytes
	reversed := make([]byte, 32)
	for i, b := range finalHash {
		reversed[31-i] = b
	}
	return new(big.Int).SetBytes(reversed)
}
