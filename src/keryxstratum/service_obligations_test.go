package keryxstratum

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/keryx-labs/keryx-stratum-bridge/src/keryxrpc"
	w "github.com/keryx-labs/keryx-stratum-bridge/src/keryxrpc/keryxwire"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type obligationNode interface{}

func TestNodeObligationsQueryAuditsOfRetainedResponses(t *testing.T) {
	key := strings.Repeat("1", 64)
	responseIDs := []string{strings.Repeat("2", 64), strings.Repeat("3", 64)}
	requestID := strings.Repeat("4", 64)
	queries := make(chan *w.GetAwaitedOpeningsRequestMessage, 2)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "protowire.RPC", HandlerType: (*obligationNode)(nil),
		Streams: []grpc.StreamDesc{{StreamName: "MessageStream", ClientStreams: true, ServerStreams: true,
			Handler: func(_ any, stream grpc.ServerStream) error {
				var message w.KaspadMessage
				if err := stream.RecvMsg(&message); err != nil {
					return err
				}
				query := message.GetGetAwaitedOpeningsRequest()
				queries <- proto.Clone(query).(*w.GetAwaitedOpeningsRequestMessage)
				result := &w.GetAwaitedOpeningsResponseMessage{VirtualDaaScore: 5000, RequestsChecked: true}
				// The official node returns audits only for explicitly requested response IDs.
				for _, id := range query.ResponseTxids {
					if slices.Contains(responseIDs, id) {
						result.Openings = append(result.Openings, &w.AwaitedOpeningMessage{
							ResponseTxid: id, EscrowPubkey: key, DeadlineDaa: 8000, Pieces: 3,
						})
					}
				}
				return stream.SendMsg(&w.KaspadMessage{Payload: &w.KaspadMessage_GetAwaitedOpeningsResponse{GetAwaitedOpeningsResponse: result}})
			}}},
	}, struct{}{})
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	client := keryxrpc.NewClient(listener.Addr().String())
	t.Cleanup(client.Close)
	relay := &serviceRelay{rpc: client, state: relayState{Escrow: key, Tasks: map[string]*relayTask{
		"answered-a": {ResponseID: responseIDs[0]},
		"answered-b": {ResponseID: responseIDs[1]},
		"unanswered": {},
	}}}
	// Responses still require audits after no request remains active.
	for _, requests := range [][]string{{requestID}, nil} {
		observed, err := relay.nodeObligationsLocked(requests)
		if err != nil {
			t.Fatal(err)
		}
		query := <-queries
		if query.EscrowPubkey != key || !slices.Equal(query.RequestHashes, requests) {
			t.Fatal("request ownership query changed")
		}
		if len(observed.Openings) != 2 || !slices.Equal(query.ResponseTxids, responseIDs) {
			t.Fatalf("retained response audits were not queried: response IDs %v, openings %d", query.ResponseTxids, len(observed.Openings))
		}
	}
}

func TestOpeningKeyMatchesRootAndChildParent(t *testing.T) {
	root := &w.AwaitedOpeningMessage{ResponseTxid: "response", Seed: "seed"}
	child := &w.AwaitedOpeningMessage{ResponseTxid: "response", Seed: "seed", AttentionPath: []uint64{1}}
	parent := proto.Clone(child).(*w.AwaitedOpeningMessage)
	parent.AttentionPath = parent.AttentionPath[:len(parent.AttentionPath)-1]
	if openingKey(root) != openingKey(parent) {
		t.Fatalf("first attention phase cannot recover the root commitment: root %s, parent %s", openingKey(root), openingKey(parent))
	}
}

func TestRetainedAttentionRootsMigrateWithoutDiscardingCommitments(t *testing.T) {
	legacy := "response:seed:null"
	canonical := "response:seed:[]"
	root := strings.Repeat("a", 64)
	for _, conflict := range []bool{false, true} {
		name := "legacy state"
		if conflict {
			name = "conflicting commitments"
		}
		t.Run(name, func(t *testing.T) {
			roots := map[string]string{legacy: root}
			if conflict {
				roots[canonical] = strings.Repeat("b", 64)
			}
			state := relayState{Version: 1, Escrow: "escrow", Identity: "identity",
				Tasks:   map[string]*relayTask{"request": {PhaseRoots: roots}},
				Pending: map[string]*relayTX{"opening": {Kind: "opening", Digest: legacy}},
			}
			path := filepath.Join(t.TempDir(), "state.json")
			raw, err := json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			verifier := &protocolVerifier{identity: verifierResult{Pubkey: "escrow", Identity: "identity"}}
			relay, err := newServiceRelay(&KeryxApi{address: "127.0.0.1:1"}, verifier, path)
			if conflict {
				if err == nil {
					t.Fatal("ambiguous retained commitments were accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(relay.rpc.Close)
			if relay.state.Tasks["request"].PhaseRoots[canonical] != root || relay.state.Tasks["request"].PhaseRoots[legacy] != "" || relay.state.Pending["opening"].Digest != canonical {
				t.Fatal("legacy opening state was lost or changed during migration")
			}
		})
	}
}
