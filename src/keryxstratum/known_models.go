package keryxstratum

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// modelSpec mirrors keryx-miner/src/models.rs — must stay in sync with the Rust registry.
// model_id = sha2-256(primary weight file) = CIDv0_bytes[2:34].
// weightCID is the CIDv0 of the primary weight file; used to verify the model is present on IPFS.
type modelSpec struct {
	name      string
	weightCID string
}

// knownModelRegistry maps model_id hex to its spec.
// Ported from keryx-miner/src/models.rs.
var knownModelRegistry = map[string]modelSpec{
	"e64af368ec9351a5a4c0ec7ae47d42ada7f6b3f1a6e60fc73d0eb6ca2953645c": {
		name:      "tinyllama",
		weightCID: "QmdqcmS8aMngiZWYYdeZEaW22N6XRTd9zK5ZCJG1MPmrQ3",
	},
	"9429673316bc40ec0667894534578b41236fc7eea4d931f1489c34c5837f42f4": {
		name:      "deepseek-r1-8b",
		weightCID: "QmYK1faUGNMYZ2UKeSpUoUoFpRarZQEwfPCHbYNG2ib2mR",
	},
	"bed9b0f551f5b95bf9da5888a48f0f87c37ad6b72519c4cbd775f54ac0b9fc62": {
		name:      "deepseek-r1-32b",
		weightCID: "QmSrmkEoJUPf7r9t4o79F5APycnGrRu2icaU3KKPdFVUk7",
	},
	"aad2cf3348d8c7fdbd2c0dd58e0d99368450d43c9584aef81a467dd347561344": {
		name:      "llama-3.3-70b",
		weightCID: "QmbRQJFZ9NuZQW9uXezANTwunnwJCKybHiCFnVQ7D4SZKb",
	},
}

var ipfsStatClient = &http.Client{Timeout: 10 * time.Second}

// isKnownModel reports whether the hex model_id is in the on-chain registry.
func isKnownModel(modelIDHex string) bool {
	_, ok := knownModelRegistry[modelIDHex]
	return ok
}

// modelName returns the human-readable name for a model_id hex, or the first 8 chars if unknown.
func modelName(modelIDHex string) string {
	if spec, ok := knownModelRegistry[modelIDHex]; ok {
		return spec.name
	}
	return truncate(modelIDHex, 8)
}

// verifyModelOnIPFS checks that the primary weight CID for the given model_id is reachable via
// the IPFS node at ipfsAPIURL. Uses /api/v0/block/stat which only resolves the root DAG node
// (fast — does not download the full file). This mirrors the sha256(weight_file)==model_id check
// done by the solo miner at startup: a CIDv0 IS sha2-256(content) by construction.
func verifyModelOnIPFS(modelIDHex, ipfsAPIURL string) error {
	spec, ok := knownModelRegistry[modelIDHex]
	if !ok {
		return fmt.Errorf("unknown model_id")
	}
	url := fmt.Sprintf("%s/api/v0/block/stat?arg=%s", trimSlash(ipfsAPIURL), spec.weightCID)
	resp, err := ipfsStatClient.Post(url, "", nil)
	if err != nil {
		return fmt.Errorf("IPFS unreachable: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("weight CID %s not found (HTTP %d)", spec.weightCID, resp.StatusCode)
	}
	return nil
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
