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

func (c *Client) ensureStream(ctx context.Context) error {
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
	stream, err := c.conn.NewStream(ctx, streamDesc, messageStreamMethod)
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

// Each request has its own deadline-bound stream on a reusable connection.
// This bounds dial/send/receive together and avoids accepting a late reply for
// another request after a timeout. This stream never subscribes to notifications.
func (c *Client) roundTrip(req *keryxwire.KaspadMessage) (*keryxwire.KaspadMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	if err := c.ensureStream(ctx); err != nil {
		c.teardownStream()
		return nil, err
	}
	defer func() {
		if c.stream != nil {
			c.stream.CloseSend()
			c.stream = nil
		}
	}()
	if err := c.stream.SendMsg(req); err != nil {
		c.teardownStream()
		return nil, errors.Wrap(err, "failed sending node request")
	}
	for i := 0; i < 16; i++ {
		msg := &keryxwire.KaspadMessage{}
		if err := c.stream.RecvMsg(msg); err != nil {
			c.teardownStream()
			return nil, errors.Wrap(err, "failed receiving node response")
		}
		if msg.Payload != nil {
			return msg, nil
		}
	}
	c.teardownStream()
	return nil, fmt.Errorf("too many unrecognized node responses")
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

func (c *Client) GetBlock(hash string, includeTransactions bool) (*keryxwire.RpcBlock, error) {
	msg, err := c.roundTrip(&keryxwire.KaspadMessage{
		Payload: &keryxwire.KaspadMessage_GetBlockRequest{
			GetBlockRequest: &keryxwire.GetBlockRequestMessage{
				Hash:                hash,
				IncludeTransactions: includeTransactions,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	response, ok := msg.Payload.(*keryxwire.KaspadMessage_GetBlockResponse)
	if !ok {
		return nil, fmt.Errorf("unexpected response type %T to getBlock", msg.Payload)
	}
	if response.GetBlockResponse.Error != nil {
		return nil, fmt.Errorf("getBlock error: %s", response.GetBlockResponse.Error.Message)
	}
	if response.GetBlockResponse.Block == nil {
		return nil, fmt.Errorf("getBlock returned no block for %s", hash)
	}
	return response.GetBlockResponse.Block, nil
}

func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.teardownStream()
}
