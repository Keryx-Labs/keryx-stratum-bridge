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
// Ported from keryx-miner/src/models.rs — the five-tier lineup active since H6.
// model_id hex = base58decode(weightCID)[2..34].
var knownModelRegistry = map[string]modelSpec{
	"bd34568cd89f5f19c6c3a6e1a61b929bc868709409eaad8e672d85f3c1eb5710": {
		name:      "qwen3.5-9b-abliterated",
		weightCID: "Qmb5E3zospd78SfiRHB9iZWNz29xuwRJufieZbWzEFBuGB",
	},
	"fa2f13be0850e26c5ce86c7ac79da85e300c1da8b3290f9a18d47105f1f2140a": {
		name:      "glm-4-9b-0414",
		weightCID: "QmfBGGZumBR4XGFLLPjYozvhRSt3kXjrgsV3jXciCdAeM7",
	},
	"399984045600f7d58d1b2cf01e6a4bf466fa15c7ac31bd0dd1a71e003b617cc6": {
		name:      "gemma-4-12b-abliterated",
		weightCID: "QmSDVicqRDwitecBaPitHsAePLUEamgL4KfrBWYHVWQyx9",
	},
	"b8bdc01fa407eab943e4fefc807483b39f8142785256049e1f559698a5284746": {
		name:      "qwen3.6-27b",
		weightCID: "QmamoYQGGAkBaqiWuNmwxeC9AQnt9F7sLyX57VoqbJWeUV",
	},
	"3dc09358ad75c6ef0c9c86ee4f47c4d6acda961fecbd0e4f9cf55e8f0fdffddb": {
		name:      "kimi-linear-48b",
		weightCID: "QmSVhtoNrL8bWJXZuEXMMWqty8qHScQMRuacuoa9ujsYqp",
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
