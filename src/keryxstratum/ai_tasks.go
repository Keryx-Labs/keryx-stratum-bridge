package keryxstratum

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/kaspanet/kaspad/app/appmessage"
)

const subnetworkAiRequest = "0300000000000000000000000000000000000000"

// TinyLlamaModelIDHex is the default challenge model (sha256(weights)).
const TinyLlamaModelIDHex = "e64af368ec9351a5a4c0ec7ae47d42ada7f6b3f1a6e60fc73d0eb6ca2953645c"

// legacyModelIDs are blake2b(model_name) hashes used before commit 9cfe9812.
// These AiRequest TXs omit the priority_fee field, so prompt starts at offset 44.
var legacyModelIDs = map[string]bool{
	"7b240ed76ba8466cf97deb9be635812d12d04996cb5612cbf99d244d6d551e9f": true,
	"9b59a0a3733ce8cf520ca2a3556a8b0ca32164bd7fd30ba32d8ddf896850f0b8": true,
}

// AiTask is the JSON payload sent as the 5th param in mining.notify when a pending
// AiRequest is found in the block template.
type AiTask struct {
	StableID        string `json:"stable_id"`
	ModelIDHex      string `json:"model_id_hex"`
	Prompt          string `json:"prompt"`
	MaxTokens       uint32 `json:"max_tokens"`
	InferenceReward uint64 `json:"inference_reward"`
	RequestHash     string `json:"request_hash"`
}

// extractAiTask decodes a SUBNETWORK_AI_REQUEST transaction payload into an AiTask.
// Binary layout: [model_id:32][max_tokens:4 LE][inference_reward:8 LE][priority_fee:8 LE][prompt:variable]
// Legacy layout (blake2b model IDs): [model_id:32][max_tokens:4 LE][inference_reward:8 LE][prompt:variable]
func extractAiTask(tx *appmessage.RPCTransaction) *AiTask {
	if !strings.EqualFold(tx.SubnetworkID, subnetworkAiRequest) {
		return nil
	}
	payload, err := hex.DecodeString(tx.Payload)
	if err != nil || len(payload) < 44 {
		return nil
	}

	modelIDHex := hex.EncodeToString(payload[:32])
	maxTokens := binary.LittleEndian.Uint32(payload[32:36])
	inferenceReward := binary.LittleEndian.Uint64(payload[36:44])

	var prompt string
	if legacyModelIDs[modelIDHex] {
		prompt = string(payload[44:])
	} else {
		if len(payload) < 52 {
			return nil
		}
		// priority_fee occupies bytes [44:52]; skip it
		prompt = string(payload[52:])
	}
	if prompt == "" {
		return nil
	}

	// stable_id: sha256(first 44 bytes of payload) → first 8 bytes hex.
	// Stable across consecutive block templates that include the same AiRequest TX.
	h := sha256.Sum256(payload[:44])
	stableID := hex.EncodeToString(h[:8])

	requestHash := ""
	if tx.VerboseData != nil {
		requestHash = tx.VerboseData.TransactionID
	}
	if requestHash == "" {
		requestHash = hex.EncodeToString(h[:])
	}

	return &AiTask{
		StableID:        stableID,
		ModelIDHex:      modelIDHex,
		Prompt:          prompt,
		MaxTokens:       maxTokens,
		InferenceReward: inferenceReward,
		RequestHash:     requestHash,
	}
}

// scanBlockForAiTask returns the first pending AiRequest TX in a block template, or nil.
func scanBlockForAiTask(block *appmessage.RPCBlock) *AiTask {
	for _, tx := range block.Transactions {
		if task := extractAiTask(tx); task != nil {
			return task
		}
	}
	return nil
}

// aiTaskJSON serializes an AiTask to JSON, returning "" on error.
func aiTaskJSON(task *AiTask) string {
	b, err := json.Marshal(task)
	if err != nil {
		return ""
	}
	return string(b)
}
