package keryxstratum

import (
	"net"
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
