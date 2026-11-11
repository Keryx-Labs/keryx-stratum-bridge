package gostratum

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
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

func TestContextMethodsDoNotCopyConcurrentConnectionState(t *testing.T) {
	ctx, conn := NewMockContext(context.Background(), zap.NewNop(), nil)
	t.Cleanup(func() { conn.Close() })
	var asContext context.Context = ctx
	var readers sync.WaitGroup
	start := make(chan struct{})
	readers.Add(2)
	for range 2 {
		go func() {
			defer readers.Done()
			<-start
			for range 1000 {
				asContext.Done()
				asContext.Deadline()
				asContext.Value(struct{}{})
			}
		}()
	}
	close(start)
	time.Sleep(time.Millisecond)
	ctx.Disconnect()
	readers.Wait()
	select {
	case <-asContext.Done():
	default:
		t.Fatal("disconnect did not cancel the connection context")
	}
}

func TestWalletRejectsConsensusMarkerSuffix(t *testing.T) {
	if _, err := CleanWallet("keryx:qqqq/escrow:attacker"); err == nil {
		t.Fatal("wallet suffix injection accepted")
	}
}
