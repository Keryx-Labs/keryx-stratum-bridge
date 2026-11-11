package gostratum

import (
	"encoding/json"
	"testing"
)

func TestEventPreservesLargeAttentionIndexes(t *testing.T) {
	event, err := UnmarshalEvent(`{"id":1,"method":"mining.ai_opening_result","params":[9007199254740993]}`)
	if err != nil {
		t.Fatal(err)
	}
	n, ok := event.Params[0].(json.Number)
	if !ok || n.String() != "9007199254740993" {
		t.Fatal("64-bit wire value was rounded")
	}
}

func TestWalletRejectsConsensusMarkerSuffix(t *testing.T) {
	if _, err := CleanWallet("keryx:qqqq/escrow:attacker"); err == nil {
		t.Fatal("wallet suffix injection accepted")
	}
}
