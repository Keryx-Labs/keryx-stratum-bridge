package keryxrpc

import (
	"fmt"
	"github.com/keryx-labs/keryx-stratum-bridge/src/keryxrpc/keryxwire"
	"strings"
)

// Service publications have no inputs or outputs; this method cannot spend funds.
func (c *Client) SubmitServiceTransaction(subnetwork, payload string) (string, error) {
	msg, err := c.roundTrip(&keryxwire.KaspadMessage{Payload: &keryxwire.KaspadMessage_SubmitTransactionRequest{SubmitTransactionRequest: &keryxwire.SubmitTransactionRequestMessage{Transaction: &keryxwire.RpcTransaction{SubnetworkId: subnetwork, Payload: payload}}}})
	if err != nil {
		return "", err
	}
	r := msg.GetSubmitTransactionResponse()
	if r == nil {
		return "", fmt.Errorf("unexpected submit-transaction response")
	}
	if r.Error != nil {
		return "", fmt.Errorf("node service transaction rejected")
	}
	return r.TransactionId, nil
}

func (c *Client) GetCurrentNetwork() (string, error) {
	msg, err := c.roundTrip(&keryxwire.KaspadMessage{Payload: &keryxwire.KaspadMessage_GetCurrentNetworkRequest{GetCurrentNetworkRequest: &keryxwire.GetCurrentNetworkRequestMessage{}}})
	if err != nil {
		return "", err
	}
	r := msg.GetGetCurrentNetworkResponse()
	if r == nil {
		return "", fmt.Errorf("unexpected current-network response")
	}
	if r.Error != nil {
		return "", fmt.Errorf("current-network RPC failed")
	}
	return strings.ToLower(r.CurrentNetwork), nil
}

func (c *Client) GetServiceStrikes() (*keryxwire.GetServiceStrikesResponseMessage, error) {
	msg, err := c.roundTrip(&keryxwire.KaspadMessage{Payload: &keryxwire.KaspadMessage_GetServiceStrikesRequest{GetServiceStrikesRequest: &keryxwire.GetServiceStrikesRequestMessage{}}})
	if err != nil {
		return nil, err
	}
	r := msg.GetGetServiceStrikesResponse()
	if r == nil {
		return nil, fmt.Errorf("unexpected getServiceStrikes response")
	}
	if r.Error != nil {
		return nil, fmt.Errorf("getServiceStrikes: %s", r.Error.Message)
	}
	return r, nil
}

// The node queries openings only for the explicitly supplied response transaction IDs.
// The escrow key identifies request obligations; it does not enumerate response audits.
func (c *Client) GetAwaitedOpenings(key string, requests, responses []string) (*keryxwire.GetAwaitedOpeningsResponseMessage, error) {
	msg, err := c.roundTrip(&keryxwire.KaspadMessage{Payload: &keryxwire.KaspadMessage_GetAwaitedOpeningsRequest{GetAwaitedOpeningsRequest: &keryxwire.GetAwaitedOpeningsRequestMessage{EscrowPubkey: key, RequestHashes: requests, ResponseTxids: responses}}})
	if err != nil {
		return nil, err
	}
	r := msg.GetGetAwaitedOpeningsResponse()
	if r == nil {
		return nil, fmt.Errorf("unexpected getAwaitedOpenings response")
	}
	if r.Error != nil {
		return nil, fmt.Errorf("getAwaitedOpenings: %s", r.Error.Message)
	}
	return r, nil
}
