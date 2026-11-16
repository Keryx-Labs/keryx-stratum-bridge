package gostratum

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mattn/go-colorable"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func testLogger() *zap.Logger {
	cfg := zap.NewDevelopmentEncoderConfig()
	cfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
	return zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(cfg),
		zapcore.AddSync(colorable.NewColorableStdout()),
		zapcore.DebugLevel,
	))
}

func TestAcceptContextLifetime(t *testing.T) {
	logger := testLogger()

	cfg := DefaultConfig(logger)
	cfg.Port = "127.0.0.1:0"
	listener := NewListener(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)

	defer cancel()
	if err := listener.Listen(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("listener did not stop on cancellation: %v", err)
	}
}

func TestNewClient(t *testing.T) {
	logger := testLogger()
	listener := NewListener(DefaultConfig(logger))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	mc := NewMockConnection()
	t.Cleanup(func() { mc.Close() })
	listener.connectionSlots <- struct{}{}
	listener.newClient(ctx, mc)
	// send in the authorize event
	event, _ := json.Marshal(NewEvent("1", "mining.authorize", []any{
		"keryx:qqayxgcjfh6d7uxpj4w3qzjvx73vdehfx22fl6cacmn44rpj5geg2rxyuhga4.rig01", "test",
	}))
	mc.AsyncWriteTestDataToReadBuffer(string(event) + "\n")

	responseReceived := false
	mc.ReadTestDataFromBuffer(func(b []byte) {
		expected := JsonRpcResponse{
			Id:     "1",
			Error:  nil,
			Result: true,
		}
		decoded := JsonRpcResponse{}
		if err := json.Unmarshal(b, &decoded); err != nil {
			t.Fatal(err)
		}
		if d := cmp.Diff(&expected, &decoded); d != "" {
			t.Fatalf("response incorrect: %s", d)
		}
		// done
		responseReceived = true
	})

	if !responseReceived {
		t.Fatalf("failed to properly respond to authorize")
	}
}

func TestWalletValidation(t *testing.T) {
	tests := []struct {
		in        string
		expected  string
		shouldErr bool
	}{
		{
			in:       "keryx:qqayxgcjfh6d7uxpj4w3qzjvx73vdehfx22fl6cacmn44rpj5geg2rxyuhga4",
			expected: "keryx:qqayxgcjfh6d7uxpj4w3qzjvx73vdehfx22fl6cacmn44rpj5geg2rxyuhga4",
		},
		{
			in:       "keryx:qqkrl0er5ka5snd55gr9rcf6rlpx8nln8gf3jxf83w4dc0khfqmauy6qs83zm",
			expected: "keryx:qqkrl0er5ka5snd55gr9rcf6rlpx8nln8gf3jxf83w4dc0khfqmauy6qs83zm",
		},
		{
			in:       "qqkrl0er5ka5snd55gr9rcf6rlpx8nln8gf3jxf83w4dc0khfqmauy6qs83zm",
			expected: "keryx:qqkrl0er5ka5snd55gr9rcf6rlpx8nln8gf3jxf83w4dc0khfqmauy6qs83zm",
		},
	}

	for _, v := range tests {
		cleaned, err := CleanWallet(v.in)
		if err != nil && !v.shouldErr {
			t.Fatalf("Unexpected error for wallet %+v", v)
		}
		if cleaned != v.expected {
			t.Fatalf("expected %s, got %s", v.expected, cleaned)
		}
	}
}
