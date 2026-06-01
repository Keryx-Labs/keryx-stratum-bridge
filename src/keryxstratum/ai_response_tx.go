package keryxstratum

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/kaspanet/kaspad/app/appmessage"
	"github.com/kaspanet/kaspad/infrastructure/network/rpcclient"
	"go.uber.org/zap"
)

const (
	subnetworkAiResponse  = "0400000000000000000000000000000000000000"
	aiResponsePayloadLen  = 78
	challengeWindowBlocks = 36_000

	// base58btc alphabet used by IPFS CIDv0 (identical to Bitcoin's).
	cidBase58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)

// decodeCIDToMultihash converts a base58btc CIDv0 string ("Qm...") or a 68-char
// hex string into the raw 34-byte IPFS sha2-256 multihash [0x12 0x20 <digest:32>].
func decodeCIDToMultihash(cid string) ([34]byte, error) {
	var raw []byte
	if len(cid) == 68 {
		var err error
		raw, err = hex.DecodeString(cid)
		if err != nil {
			return [34]byte{}, fmt.Errorf("invalid CID hex: %w", err)
		}
	} else {
		raw = base58btcDecode(cid)
	}
	if len(raw) != 34 {
		return [34]byte{}, fmt.Errorf("decoded CID has wrong length %d (expected 34)", len(raw))
	}
	if raw[0] != 0x12 || raw[1] != 0x20 {
		return [34]byte{}, fmt.Errorf("CID multihash header 0x%02x%02x is not sha2-256 (0x1220)", raw[0], raw[1])
	}
	var out [34]byte
	copy(out[:], raw)
	return out, nil
}

// base58btcDecode decodes a base58btc string to bytes using the Bitcoin/IPFS alphabet.
func base58btcDecode(s string) []byte {
	var lookup [256]int8
	for i := range lookup {
		lookup[i] = -1
	}
	for i, c := range []byte(cidBase58Alphabet) {
		lookup[c] = int8(i)
	}

	n := new(big.Int)
	b58 := big.NewInt(58)
	for _, c := range []byte(s) {
		v := lookup[c]
		if v < 0 {
			return nil
		}
		n.Mul(n, b58).Add(n, big.NewInt(int64(v)))
	}

	decoded := n.Bytes()

	// Preserve leading zero bytes for each leading '1' character.
	leadingZeros := 0
	for _, c := range []byte(s) {
		if c != '1' {
			break
		}
		leadingZeros++
	}
	result := make([]byte, leadingZeros+len(decoded))
	copy(result[leadingZeros:], decoded)
	return result
}

// buildAiResponsePayload constructs the 78-byte AiResponse TX payload.
// Layout: [request_hash:32][challenge_window_end:8 LE][response_ipfs_cid:34][response_length:4 LE]
func buildAiResponsePayload(requestHashHex string, daaScore uint64, cid [34]byte) ([]byte, error) {
	requestHash, err := hex.DecodeString(requestHashHex)
	if err != nil || len(requestHash) != 32 {
		return nil, fmt.Errorf("invalid request_hash %q: %w", requestHashHex, err)
	}
	payload := make([]byte, aiResponsePayloadLen)
	copy(payload[0:32], requestHash)
	binary.LittleEndian.PutUint64(payload[32:40], daaScore+challengeWindowBlocks)
	copy(payload[40:74], cid[:])
	// response_length is informational; bridge does not know the token count.
	binary.LittleEndian.PutUint32(payload[74:78], 0)
	return payload, nil
}

// SubmitAiResponseTX builds and submits a SUBNETWORK_AI_RESPONSE transaction on-chain.
// AiResponse TXs are data-publication transactions — they carry no inputs or outputs.
// Called in a goroutine from HandleSubmit when the miner includes an IPFS CID.
func SubmitAiResponseTX(
	keryxd *rpcclient.RPCClient,
	logger *zap.Logger,
	requestHashHex string,
	daaScore uint64,
	cidStr string,
) {
	cid, err := decodeCIDToMultihash(cidStr)
	if err != nil {
		logger.Warn("OPoI AiResponse: failed to decode CID",
			zap.String("cid", cidStr),
			zap.Error(err))
		return
	}
	payload, err := buildAiResponsePayload(requestHashHex, daaScore, cid)
	if err != nil {
		logger.Warn("OPoI AiResponse: failed to build payload", zap.Error(err))
		return
	}
	tx := &appmessage.RPCTransaction{
		Version:      0,
		Inputs:       []*appmessage.RPCTransactionInput{},
		Outputs:      []*appmessage.RPCTransactionOutput{},
		LockTime:     0,
		SubnetworkID: subnetworkAiResponse,
		Gas:          0,
		Payload:      hex.EncodeToString(payload),
	}
	resp, err := keryxd.SubmitTransaction(tx, false)
	if err != nil {
		logger.Warn("OPoI AiResponse: SubmitTransaction failed",
			zap.String("request_hash", truncate(requestHashHex, 8)),
			zap.String("cid", cidStr),
			zap.Error(err))
		return
	}
	logger.Info("OPoI AiResponse: TX submitted on-chain",
		zap.String("tx_id", resp.TransactionID),
		zap.String("request_hash", truncate(requestHashHex, 8)),
		zap.String("cid", cidStr))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
