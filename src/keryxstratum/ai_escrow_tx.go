package keryxstratum

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"

	secp256k1 "github.com/kaspanet/go-secp256k1"
	"github.com/kaspanet/kaspad/app/appmessage"
	"golang.org/x/crypto/blake2b"
)

const (
	subnetworkNative = "0000000000000000000000000000000000000000"
	opCSV            = 0xb1
	opCheckSig       = 0xac
	opData32         = 0x20
	sigHashAll       = 0x01
)

// BuildClaimTX builds a signed claim TX for an EscrowEntry.
//
// The escrow script is derived from the bridge's private key (same as the miner does).
// The miner payout script is stored in EscrowEntry.MinerSPKHex for inference entries.
func BuildClaimTX(privKey *secp256k1.SchnorrKeyPair, entry *EscrowEntry) (*appmessage.RPCTransaction, error) {
	if entry.AmountSompi <= claimTxFee {
		return nil, fmt.Errorf("amount %d ≤ fee %d", entry.AmountSompi, claimTxFee)
	}
	amountOut := entry.AmountSompi - claimTxFee

	txIDBytes, err := hex.DecodeString(entry.CoinbaseTxID)
	if err != nil || len(txIDBytes) != 32 {
		return nil, fmt.Errorf("invalid TX ID: %w", err)
	}
	var txIDArr [32]byte
	copy(txIDArr[:], txIDBytes)

	// Derive the bridge's escrow script and pubkey (same logic as Rust build_escrow_script).
	pubKeyBytes, err := schnorrPubKeyBytes(privKey)
	if err != nil {
		return nil, fmt.Errorf("pubkey derivation: %w", err)
	}
	escrowScript := buildEscrowScript(pubKeyBytes)

	// Resolve payout script.
	var payoutSPKBytes []byte
	var payoutSPKVersion uint16
	if entry.MinerSPKHex != "" {
		payoutSPKBytes, err = hex.DecodeString(entry.MinerSPKHex)
		if err != nil {
			return nil, fmt.Errorf("invalid miner SPK: %w", err)
		}
		payoutSPKVersion = entry.MinerSPKVersion
	} else {
		// Coinbase entry: pay to the bridge's own P2PK script.
		payoutSPKBytes = buildP2PKScript(pubKeyBytes)
		payoutSPKVersion = 0
	}

	// Compute the Schnorr sighash (mirrors Rust compute_sighash exactly).
	sighash := computeSighash(
		&txIDArr,
		entry.OutputIndex,
		entry.AmountSompi,
		escrowScript,
		payoutSPKVersion,
		payoutSPKBytes,
		amountOut,
	)

	h := secp256k1.Hash(sighash)
	sig, err := privKey.SchnorrSign(&h)
	if err != nil {
		return nil, fmt.Errorf("Schnorr sign: %w", err)
	}

	// signature_script: OpData65 (0x41) | 64-byte sig | SIG_HASH_ALL
	sigBytes := sig.Serialize()
	sigScript := make([]byte, 66)
	sigScript[0] = 0x41
	copy(sigScript[1:65], sigBytes[:])
	sigScript[65] = sigHashAll

	return &appmessage.RPCTransaction{
		Version:  0,
		LockTime: 0,
		Inputs: []*appmessage.RPCTransactionInput{{
			PreviousOutpoint: &appmessage.RPCOutpoint{
				TransactionID: entry.CoinbaseTxID,
				Index:         entry.OutputIndex,
			},
			SignatureScript: hex.EncodeToString(sigScript),
			Sequence:        challengeWindowBlocksEscrow,
			SigOpCount:      1,
		}},
		Outputs: []*appmessage.RPCTransactionOutput{{
			Amount: amountOut,
			ScriptPublicKey: &appmessage.RPCScriptPublicKey{
				Version: payoutSPKVersion,
				Script:  hex.EncodeToString(payoutSPKBytes),
			},
		}},
		SubnetworkID: subnetworkNative,
		Gas:          0,
		Payload:      "",
	}, nil
}

// MinerSPKFromCoinbase finds the P2PK output in the coinbase that belongs to minerAddr.
func MinerSPKFromCoinbase(coinbase *appmessage.RPCTransaction, minerAddr string) (spkHex string, spkVersion uint16, ok bool) {
	for _, out := range coinbase.Outputs {
		if out.VerboseData != nil && out.VerboseData.ScriptPublicKeyAddress == minerAddr {
			if out.ScriptPublicKey != nil {
				return out.ScriptPublicKey.Script, out.ScriptPublicKey.Version, true
			}
		}
	}
	return "", 0, false
}

// buildEscrowScript mirrors Rust build_escrow_script.
// `<CHALLENGE_WINDOW_LE_minimal> OP_CSV OP_DATA32 <pubkey_32> OP_CHECKSIG`
func buildEscrowScript(pubkey []byte) []byte {
	le := make([]byte, 8)
	binary.LittleEndian.PutUint64(le, challengeWindowBlocksEscrow)
	trimLen := 8
	for trimLen > 1 && le[trimLen-1] == 0 {
		trimLen--
	}
	seq := le[:trimLen]

	script := make([]byte, 0, 3+len(seq)+33+1)
	script = append(script, byte(len(seq)))
	script = append(script, seq...)
	script = append(script, opCSV, opData32)
	script = append(script, pubkey...)
	script = append(script, opCheckSig)
	return script
}

// buildP2PKScript returns `OP_DATA32 <pubkey_32> OP_CHECKSIG`.
func buildP2PKScript(pubkey []byte) []byte {
	script := make([]byte, 0, 34)
	script = append(script, opData32)
	script = append(script, pubkey...)
	script = append(script, opCheckSig)
	return script
}

// computeSighash mirrors Rust compute_sighash (SIG_HASH_ALL, single input, native subnetwork).
// Uses Blake2b-256 keyed with b"TransactionSigningHash".
func computeSighash(
	txID *[32]byte,
	outputIndex uint32,
	escrowAmount uint64,
	escrowScript []byte,
	payoutSPKVersion uint16,
	payoutSPKScript []byte,
	payoutAmount uint64,
) [32]byte {
	const key = "TransactionSigningHash"
	newH := func() hash.Hash {
		h, _ := blake2b.New256([]byte(key))
		return h
	}

	// previous_outputs_hash
	prevOutHash := func() []byte {
		h := newH()
		h.Write(txID[:])
		writeU32LE(h, outputIndex)
		return h.Sum(nil)
	}()

	// sequences_hash
	seqsHash := func() []byte {
		h := newH()
		writeU64LE(h, challengeWindowBlocksEscrow)
		return h.Sum(nil)
	}()

	// sig_op_counts_hash
	sigopsHash := func() []byte {
		h := newH()
		h.Write([]byte{1})
		return h.Sum(nil)
	}()

	// outputs_hash
	outsHash := func() []byte {
		h := newH()
		writeU64LE(h, payoutAmount)
		writeU16LE(h, payoutSPKVersion)
		writeU64LE(h, uint64(len(payoutSPKScript)))
		h.Write(payoutSPKScript)
		return h.Sum(nil)
	}()

	// payload_hash = ZERO_HASH (native + empty payload)
	payloadHash := [32]byte{}

	h := newH()
	writeU16LE(h, 0)         // tx.version
	h.Write(prevOutHash)
	h.Write(seqsHash)
	h.Write(sigopsHash)
	h.Write(txID[:])                             // prev_outpoint.transaction_id
	writeU32LE(h, outputIndex)                   // prev_outpoint.index
	writeU16LE(h, 0)                             // utxo spk version
	writeU64LE(h, uint64(len(escrowScript)))     // write_var_bytes len
	h.Write(escrowScript)                        // write_var_bytes data
	writeU64LE(h, escrowAmount)                  // utxo.amount
	writeU64LE(h, challengeWindowBlocksEscrow)   // input.sequence
	h.Write([]byte{1})                           // input.sig_op_count
	h.Write(outsHash)
	writeU64LE(h, 0)                             // tx.lock_time
	h.Write(make([]byte, 20))                    // subnetwork_id (NATIVE)
	writeU64LE(h, 0)                             // tx.gas
	h.Write(payloadHash[:])                      // payload_hash
	h.Write([]byte{sigHashAll})

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// schnorrPubKeyBytes derives the 32-byte x-only pubkey from a SchnorrKeyPair.
func schnorrPubKeyBytes(kp *secp256k1.SchnorrKeyPair) ([]byte, error) {
	pub, err := kp.SchnorrPublicKey()
	if err != nil {
		return nil, err
	}
	s, err := pub.Serialize()
	if err != nil {
		return nil, err
	}
	return s[:], nil
}

// schnorrPubKeyHex derives the 64-char hex x-only pubkey from a 64-char hex privkey string.
func schnorrPubKeyHex(privKeyHex string) (string, error) {
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return "", err
	}
	kp, err := secp256k1.DeserializeSchnorrPrivateKeyFromSlice(privKeyBytes)
	if err != nil {
		return "", err
	}
	pub, err := kp.SchnorrPublicKey()
	if err != nil {
		return "", err
	}
	s, err := pub.Serialize()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(s[:]), nil
}

func writeU16LE(h hash.Hash, v uint16) {
	b := [2]byte{}
	binary.LittleEndian.PutUint16(b[:], v)
	h.Write(b[:])
}
func writeU32LE(h hash.Hash, v uint32) {
	b := [4]byte{}
	binary.LittleEndian.PutUint32(b[:], v)
	h.Write(b[:])
}
func writeU64LE(h hash.Hash, v uint64) {
	b := [8]byte{}
	binary.LittleEndian.PutUint64(b[:], v)
	h.Write(b[:])
}
