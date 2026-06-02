package keryxstratum

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/kaspanet/kaspad/app/appmessage"
)

// model IDs from known_models.go / legacyModelIDs
const testModernModelID = "e64af368ec9351a5a4c0ec7ae47d42ada7f6b3f1a6e60fc73d0eb6ca2953645c" // tinyllama
const testLegacyModelID = "7b240ed76ba8466cf97deb9be635812d12d04996cb5612cbf99d244d6d551e9f" // blake2b era

// buildModernPayload creates a 52-byte header + prompt hex (modern layout).
func buildModernPayload(modelIDHex string, maxTokens uint32, inferenceReward, priorityFee uint64, prompt string) string {
	modelID, _ := hex.DecodeString(modelIDHex)
	payload := make([]byte, 52+len(prompt))
	copy(payload[0:32], modelID)
	binary.LittleEndian.PutUint32(payload[32:36], maxTokens)
	binary.LittleEndian.PutUint64(payload[36:44], inferenceReward)
	binary.LittleEndian.PutUint64(payload[44:52], priorityFee)
	copy(payload[52:], prompt)
	return hex.EncodeToString(payload)
}

// buildLegacyPayload creates a 44-byte header + prompt hex (legacy blake2b layout).
func buildLegacyPayload(modelIDHex string, maxTokens uint32, inferenceReward uint64, prompt string) string {
	modelID, _ := hex.DecodeString(modelIDHex)
	payload := make([]byte, 44+len(prompt))
	copy(payload[0:32], modelID)
	binary.LittleEndian.PutUint32(payload[32:36], maxTokens)
	binary.LittleEndian.PutUint64(payload[36:44], inferenceReward)
	copy(payload[44:], prompt)
	return hex.EncodeToString(payload)
}

func mockAiRequestTx(payloadHex string) *appmessage.RPCTransaction {
	return &appmessage.RPCTransaction{
		SubnetworkID: subnetworkAiRequest,
		Payload:      payloadHex,
	}
}

// --- extractAiTask ---

func TestExtractAiTask_Modern(t *testing.T) {
	prompt := "What is Keryx?"
	task := extractAiTask(mockAiRequestTx(
		buildModernPayload(testModernModelID, 256, 50_000_000, 30_000_000, prompt),
	))
	if task == nil {
		t.Fatal("expected non-nil AiTask")
	}
	if task.ModelIDHex != testModernModelID {
		t.Errorf("model_id: got %s", task.ModelIDHex)
	}
	if task.MaxTokens != 256 {
		t.Errorf("max_tokens: want 256, got %d", task.MaxTokens)
	}
	if task.InferenceReward != 50_000_000 {
		t.Errorf("inference_reward: want 50000000, got %d", task.InferenceReward)
	}
	if task.Prompt != prompt {
		t.Errorf("prompt: want %q, got %q", prompt, task.Prompt)
	}
	if task.StableID == "" {
		t.Error("stable_id must be non-empty")
	}
}

func TestExtractAiTask_Legacy(t *testing.T) {
	prompt := "Legacy inference request"
	task := extractAiTask(mockAiRequestTx(
		buildLegacyPayload(testLegacyModelID, 128, 10_000_000, prompt),
	))
	if task == nil {
		t.Fatal("expected non-nil AiTask for legacy model ID")
	}
	if task.Prompt != prompt {
		t.Errorf("legacy prompt: want %q, got %q", prompt, task.Prompt)
	}
	if task.InferenceReward != 10_000_000 {
		t.Errorf("legacy inference_reward: want 10000000, got %d", task.InferenceReward)
	}
}

func TestExtractAiTask_WrongSubnetwork(t *testing.T) {
	tx := &appmessage.RPCTransaction{
		SubnetworkID: "0000000000000000000000000000000000000000",
		Payload:      buildModernPayload(testModernModelID, 256, 50_000_000, 30_000_000, "hello"),
	}
	if extractAiTask(tx) != nil {
		t.Fatal("expected nil for wrong subnetwork")
	}
}

func TestExtractAiTask_TooShort(t *testing.T) {
	tx := mockAiRequestTx(hex.EncodeToString(make([]byte, 20)))
	if extractAiTask(tx) != nil {
		t.Fatal("expected nil for payload < 44 bytes")
	}
}

func TestExtractAiTask_EmptyPrompt(t *testing.T) {
	// exactly 52 bytes, no prompt
	modelID, _ := hex.DecodeString(testModernModelID)
	payload := make([]byte, 52)
	copy(payload[0:32], modelID)
	binary.LittleEndian.PutUint32(payload[32:36], 256)
	binary.LittleEndian.PutUint64(payload[36:44], 50_000_000)
	binary.LittleEndian.PutUint64(payload[44:52], 30_000_000)
	if extractAiTask(mockAiRequestTx(hex.EncodeToString(payload))) != nil {
		t.Fatal("expected nil for empty prompt")
	}
}

func TestExtractAiTask_StableID_Consistent(t *testing.T) {
	payload := buildModernPayload(testModernModelID, 512, 100_000_000, 30_000_000, "hello keryx")
	t1 := extractAiTask(mockAiRequestTx(payload))
	t2 := extractAiTask(mockAiRequestTx(payload))
	if t1 == nil || t2 == nil {
		t.Fatal("both tasks must be non-nil")
	}
	if t1.StableID != t2.StableID {
		t.Errorf("stable_id must be consistent across calls: %s vs %s", t1.StableID, t2.StableID)
	}
}

// --- scanBlockForAiTask ---

func TestScanBlockForAiTask_Found(t *testing.T) {
	block := &appmessage.RPCBlock{
		Transactions: []*appmessage.RPCTransaction{
			{SubnetworkID: "0100000000000000000000000000000000000000"}, // coinbase
			mockAiRequestTx(buildModernPayload(testModernModelID, 256, 50_000_000, 30_000_000, "What is decentralized AI?")),
		},
	}
	task := scanBlockForAiTask(block)
	if task == nil {
		t.Fatal("expected AiTask to be found")
	}
	if task.Prompt != "What is decentralized AI?" {
		t.Errorf("unexpected prompt: %s", task.Prompt)
	}
}

func TestScanBlockForAiTask_None(t *testing.T) {
	block := &appmessage.RPCBlock{
		Transactions: []*appmessage.RPCTransaction{
			{SubnetworkID: "0100000000000000000000000000000000000000"},
		},
	}
	if scanBlockForAiTask(block) != nil {
		t.Fatal("expected nil when no AiRequest TX present")
	}
}

func TestScanBlockForAiTask_ReturnsFirst(t *testing.T) {
	block := &appmessage.RPCBlock{
		Transactions: []*appmessage.RPCTransaction{
			mockAiRequestTx(buildModernPayload(testModernModelID, 64, 10_000_000, 30_000_000, "first")),
			mockAiRequestTx(buildModernPayload(testModernModelID, 64, 20_000_000, 30_000_000, "second")),
		},
	}
	task := scanBlockForAiTask(block)
	if task == nil || task.Prompt != "first" {
		t.Fatalf("expected first task, got %v", task)
	}
}

// --- computeAiResponseHash ---

func TestComputeAiResponseHash_Deterministic(t *testing.T) {
	reqHash := strings.Repeat("ab", 32)
	h1 := computeAiResponseHash(reqHash, 12345)
	h2 := computeAiResponseHash(reqHash, 12345)
	if h1 != h2 {
		t.Fatal("computeAiResponseHash must be deterministic")
	}
	if len(h1) != 64 {
		t.Errorf("expected 64-char hex, got len=%d", len(h1))
	}
}

func TestComputeAiResponseHash_VariesByDAA(t *testing.T) {
	reqHash := strings.Repeat("cd", 32)
	if computeAiResponseHash(reqHash, 1000) == computeAiResponseHash(reqHash, 2000) {
		t.Fatal("hash should differ for different DAA scores")
	}
}

func TestComputeAiResponseHash_VariesByRequest(t *testing.T) {
	h1 := computeAiResponseHash(strings.Repeat("aa", 32), 1000)
	h2 := computeAiResponseHash(strings.Repeat("bb", 32), 1000)
	if h1 == h2 {
		t.Fatal("hash should differ for different request hashes")
	}
}

func TestComputeAiResponseHash_InvalidInput(t *testing.T) {
	if computeAiResponseHash("not-hex", 0) != "" {
		t.Fatal("expected empty string for invalid request hash hex")
	}
	if computeAiResponseHash(strings.Repeat("aa", 16), 0) != "" {
		t.Fatal("expected empty string for request hash < 32 bytes")
	}
}

// --- markResponseSubmitted (deduplication) ---

func TestMarkResponseSubmitted_FirstCall(t *testing.T) {
	sh := &shareHandler{submittedResponses: map[string]bool{}}
	if sh.markResponseSubmitted("req-hash-1") {
		t.Fatal("first call should return false (not a duplicate)")
	}
}

func TestMarkResponseSubmitted_SecondCall(t *testing.T) {
	sh := &shareHandler{submittedResponses: map[string]bool{}}
	sh.markResponseSubmitted("req-hash-2")
	if !sh.markResponseSubmitted("req-hash-2") {
		t.Fatal("second call should return true (duplicate)")
	}
}

func TestMarkResponseSubmitted_IndependentKeys(t *testing.T) {
	sh := &shareHandler{submittedResponses: map[string]bool{}}
	sh.markResponseSubmitted("req-a")
	if sh.markResponseSubmitted("req-b") {
		t.Fatal("different request hashes must not interfere")
	}
}
