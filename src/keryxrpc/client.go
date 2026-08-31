// Package keryxrpc is a minimal gRPC client for the Keryx-specific RPC surface the
// upstream kaspad Go library cannot carry: block templates and block submission with
// the PoM fields (RpcBlock.pomProof, header pomFinalState/serviceStateHash/pomTier).
// Everything else (stats, balances, notifications) stays on the kaspad rpcclient.
package keryxrpc

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/keryx-labs/keryx-stratum-bridge/src/keryxrpc/keryxwire"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
)

const (
	// Large enough for proof-carrying blocks; mirrors the node's gRPC limits.
	maxMsgSize     = 512 * 1024 * 1024
	requestTimeout = 15 * time.Second
)

// streamDesc invokes protowire.RPC/MessageStream by hand. The wire only cares about
// the method string and field numbers, so our proto package name can differ from the
// node's (avoids clashing with the kaspad library's registered protowire types).
var streamDesc = &grpc.StreamDesc{
	StreamName:    "MessageStream",
	ClientStreams: true,
	ServerStreams: true,
}

const messageStreamMethod = "/protowire.RPC/MessageStream"

type Client struct {
	address string

	mu     sync.Mutex
	conn   *grpc.ClientConn
	stream grpc.ClientStream
}

func NewClient(address string) *Client {
	return &Client{address: address}
}

func (c *Client) ensureStream() error {
	if c.stream != nil {
		return nil
	}
	if c.conn == nil {
		conn, err := grpc.Dial(c.address, grpc.WithInsecure(),
			grpc.WithDefaultCallOptions(
				grpc.MaxCallRecvMsgSize(maxMsgSize),
				grpc.MaxCallSendMsgSize(maxMsgSize),
			))
		if err != nil {
			return errors.Wrapf(err, "failed dialing keryxd @ %s", c.address)
		}
		c.conn = conn
	}
	stream, err := c.conn.NewStream(context.Background(), streamDesc, messageStreamMethod)
	if err != nil {
		return errors.Wrap(err, "failed opening MessageStream to keryxd")
	}
	c.stream = stream
	return nil
}

func (c *Client) teardownStream() {
	if c.stream != nil {
		c.stream.CloseSend() //nolint:errcheck
		c.stream = nil
	}
	if c.conn != nil {
		c.conn.Close() //nolint:errcheck
		c.conn = nil
	}
}

// roundTrip sends one request and waits for the first recognizable response payload.
// Requests are serialized: the node answers in order, and the bridge never registers
// for notifications on this stream, so the next decoded payload is our response.
func (c *Client) roundTrip(req *keryxwire.KaspadMessage) (*keryxwire.KaspadMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.ensureStream(); err != nil {
		c.teardownStream()
		return nil, err
	}
	if err := c.stream.SendMsg(req); err != nil {
		c.teardownStream()
		return nil, errors.Wrap(err, "failed sending request to keryxd")
	}

	type recvResult struct {
		msg *keryxwire.KaspadMessage
		err error
	}
	resultChan := make(chan recvResult, 1)
	stream := c.stream
	go func() {
		for {
			msg := &keryxwire.KaspadMessage{}
			if err := stream.RecvMsg(msg); err != nil {
				resultChan <- recvResult{nil, err}
				return
			}
			// Unknown payload types decode to a nil Payload — skip them.
			if msg.Payload != nil {
				resultChan <- recvResult{msg, nil}
				return
			}
		}
	}()

	select {
	case result := <-resultChan:
		if result.err != nil {
			c.teardownStream()
			return nil, errors.Wrap(result.err, "failed receiving response from keryxd")
		}
		return result.msg, nil
	case <-time.After(requestTimeout):
		// Force the pending RecvMsg to error out so the goroutine exits.
		c.teardownStream()
		return nil, fmt.Errorf("timed out waiting for keryxd response")
	}
}

func (c *Client) GetBlockTemplate(payAddress, extraData string) (*keryxwire.GetBlockTemplateResponseMessage, error) {
	msg, err := c.roundTrip(&keryxwire.KaspadMessage{
		Payload: &keryxwire.KaspadMessage_GetBlockTemplateRequest{
			GetBlockTemplateRequest: &keryxwire.GetBlockTemplateRequestMessage{
				PayAddress: payAddress,
				ExtraData:  extraData,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	response, ok := msg.Payload.(*keryxwire.KaspadMessage_GetBlockTemplateResponse)
	if !ok {
		return nil, fmt.Errorf("unexpected response type %T to getBlockTemplate", msg.Payload)
	}
	if response.GetBlockTemplateResponse.Error != nil {
		return nil, fmt.Errorf("getBlockTemplate error: %s", response.GetBlockTemplateResponse.Error.Message)
	}
	return response.GetBlockTemplateResponse, nil
}

func (c *Client) SubmitBlock(block *keryxwire.RpcBlock) (*keryxwire.SubmitBlockResponseMessage, error) {
	msg, err := c.roundTrip(&keryxwire.KaspadMessage{
		Payload: &keryxwire.KaspadMessage_SubmitBlockRequest{
			SubmitBlockRequest: &keryxwire.SubmitBlockRequestMessage{
				Block:             block,
				AllowNonDAABlocks: false,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	response, ok := msg.Payload.(*keryxwire.KaspadMessage_SubmitBlockResponse)
	if !ok {
		return nil, fmt.Errorf("unexpected response type %T to submitBlock", msg.Payload)
	}
	return response.SubmitBlockResponse, nil
}

func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.teardownStream()
}
