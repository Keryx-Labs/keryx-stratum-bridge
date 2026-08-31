package keryxrpc

import (
	"github.com/kaspanet/kaspad/app/appmessage"
	"github.com/keryx-labs/keryx-stratum-bridge/src/keryxrpc/keryxwire"
)

// BlockToAppMessage projects a keryxwire template block onto the kaspad appmessage
// type used by the bridge's existing serialization/scanning helpers. The Keryx-only
// header fields have no appmessage slot; submission goes through the original
// keryxwire block, so nothing is lost.
func BlockToAppMessage(block *keryxwire.RpcBlock) *appmessage.RPCBlock {
	header := block.Header
	parents := make([]*appmessage.RPCBlockLevelParents, len(header.Parents))
	for i, level := range header.Parents {
		parents[i] = &appmessage.RPCBlockLevelParents{ParentHashes: level.ParentHashes}
	}
	transactions := make([]*appmessage.RPCTransaction, len(block.Transactions))
	for i, tx := range block.Transactions {
		inputs := make([]*appmessage.RPCTransactionInput, len(tx.Inputs))
		for j, input := range tx.Inputs {
			inputs[j] = &appmessage.RPCTransactionInput{
				PreviousOutpoint: &appmessage.RPCOutpoint{
					TransactionID: input.PreviousOutpoint.TransactionId,
					Index:         input.PreviousOutpoint.Index,
				},
				SignatureScript: input.SignatureScript,
				Sequence:        input.Sequence,
				SigOpCount:      byte(input.SigOpCount),
			}
		}
		outputs := make([]*appmessage.RPCTransactionOutput, len(tx.Outputs))
		for j, output := range tx.Outputs {
			var spk *appmessage.RPCScriptPublicKey
			if output.ScriptPublicKey != nil {
				spk = &appmessage.RPCScriptPublicKey{
					Version: uint16(output.ScriptPublicKey.Version),
					Script:  output.ScriptPublicKey.ScriptPublicKey,
				}
			}
			outputs[j] = &appmessage.RPCTransactionOutput{
				Amount:          output.Amount,
				ScriptPublicKey: spk,
			}
		}
		transactions[i] = &appmessage.RPCTransaction{
			Version:      uint16(tx.Version),
			Inputs:       inputs,
			Outputs:      outputs,
			LockTime:     tx.LockTime,
			SubnetworkID: tx.SubnetworkId,
			Gas:          tx.Gas,
			Payload:      tx.Payload,
		}
	}
	return &appmessage.RPCBlock{
		Header: &appmessage.RPCBlockHeader{
			Version:              header.Version,
			Parents:              parents,
			HashMerkleRoot:       header.HashMerkleRoot,
			AcceptedIDMerkleRoot: header.AcceptedIdMerkleRoot,
			UTXOCommitment:       header.UtxoCommitment,
			Timestamp:            header.Timestamp,
			Bits:                 header.Bits,
			Nonce:                header.Nonce,
			DAAScore:             header.DaaScore,
			BlueScore:            header.BlueScore,
			BlueWork:             header.BlueWork,
			PruningPoint:         header.PruningPoint,
		},
		Transactions: transactions,
	}
}
