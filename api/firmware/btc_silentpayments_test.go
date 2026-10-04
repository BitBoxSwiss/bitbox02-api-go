// SPDX-License-Identifier: Apache-2.0

package firmware

import (
	"bytes"
	"testing"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/common"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/mocks"
	"github.com/BitBoxSwiss/bitbox02-api-go/util/semver"
	"github.com/btcsuite/btcd/address/v2/bech32"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestBTCSignSilentPaymentCompleteness(t *testing.T) {
	// Reuse the independently generated proof from TestDLEQVerify. The input key is p1,
	// the scan key is gen2, and the shared secret included with the proof is p2.
	inputKey, err := btcec.ParsePubKey(unhex("021b8594084a12da837a78f9337e3d29169025a8ddbe9f9933a131607c6e62d21e"))
	require.NoError(t, err)
	scanKey := unhex("0389140f7bb852f020f154e55908fe3699dc9f65153e681527f0d55aabed937f4b")
	sharedSecret := unhex("03019807775b92c83d24e3001b55f60373e0bdc7d7cc7bc86befecf5bb987b54ac")
	proof := append(bytes.Clone(sharedSecret), unhex("6c885f825f6ce7565bc6d0bfda90506b11e2682dfe943f5a85badf1c8a96edc5f5e03f5ee2c58bf979646fbada920f9f1c5bd92805fb5b01534b42d26a550f79")...)
	// Use the input key as the recipient's spend key for this protocol fixture.
	addressData, err := bech32.ConvertBits(append(scanKey, inputKey.SerializeCompressed()...), 8, 5, true)
	require.NoError(t, err)
	address, err := bech32.EncodeM("sp", append([]byte{0}, addressData...))
	require.NoError(t, err)
	silentOutput := &messages.BTCSignOutputRequest{
		SilentPayment: &messages.BTCSignOutputRequest_SilentPayment{Address: address},
		Value:         1000,
	}
	ordinaryOutput := &messages.BTCSignOutputRequest{Value: 2000}
	input := &BTCTxInput{
		Input: &messages.BTCSignInputRequest{
			PrevOutHash: bytes.Repeat([]byte{1}, 32),
		},
		BIP352Pubkey: inputKey.SerializeCompressed(),
	}
	fixtureTx := &BTCTx{Inputs: []*BTCTxInput{input}}
	cPub, err := btcec.ParsePubKey(sharedSecret)
	require.NoError(t, err)
	ecdh := scalarMult(bip352SmallestOutpointHash(fixtureTx, inputKey), cPub)
	outputKey := pubkeyAdd(inputKey, scalarBaseMult(bip352CalculateTk(ecdh, 0)))
	script, err := txscript.PayToTaprootScript(outputKey)
	require.NoError(t, err)
	invalidProof := bytes.Clone(proof)
	invalidProof[len(invalidProof)-1] ^= 1
	wrongScript := bytes.Clone(script)
	wrongScript[len(wrongScript)-1] ^= 1

	type outputExchange struct {
		index  uint32
		script []byte
		proof  []byte
	}
	ordinary := outputExchange{index: 0}
	valid := outputExchange{index: 1, script: script, proof: proof}
	for _, test := range []struct {
		name          string
		outputs       []*messages.BTCSignOutputRequest
		exchanges     []outputExchange
		expectedError string
	}{
		{
			name:      "ordinary output",
			outputs:   []*messages.BTCSignOutputRequest{ordinaryOutput},
			exchanges: []outputExchange{ordinary},
		},
		{
			name:      "valid mixed outputs",
			outputs:   []*messages.BTCSignOutputRequest{ordinaryOutput, silentOutput},
			exchanges: []outputExchange{ordinary, valid},
		},
		{
			name:    "valid multiple silent payments",
			outputs: []*messages.BTCSignOutputRequest{ordinaryOutput, silentOutput, silentOutput},
			exchanges: []outputExchange{
				ordinary, valid, {index: 2, script: script, proof: proof},
			},
		},
		{
			name:          "immediate completion",
			outputs:       []*messages.BTCSignOutputRequest{ordinaryOutput, silentOutput},
			expectedError: "missing verified silent payment output",
		},
		{
			name:          "silent payment exchange omitted",
			outputs:       []*messages.BTCSignOutputRequest{ordinaryOutput, silentOutput},
			exchanges:     []outputExchange{ordinary},
			expectedError: "missing verified silent payment output",
		},
		{
			name:          "duplicate does not cover another silent payment",
			outputs:       []*messages.BTCSignOutputRequest{ordinaryOutput, silentOutput, silentOutput},
			exchanges:     []outputExchange{ordinary, valid, valid},
			expectedError: "missing verified silent payment output",
		},
		{
			name:          "generated output and proof omitted",
			outputs:       []*messages.BTCSignOutputRequest{ordinaryOutput, silentOutput},
			exchanges:     []outputExchange{{index: 1}},
			expectedError: "missing generated silent payment output",
		},
		{
			name:          "generated output empty",
			outputs:       []*messages.BTCSignOutputRequest{ordinaryOutput, silentOutput},
			exchanges:     []outputExchange{{index: 1, script: []byte{}, proof: proof}},
			expectedError: "missing generated silent payment output",
		},
		{
			name:          "proof omitted",
			outputs:       []*messages.BTCSignOutputRequest{ordinaryOutput, silentOutput},
			exchanges:     []outputExchange{{index: 1, script: script}},
			expectedError: "wrong DLEQ proof size",
		},
		{
			name:          "proof truncated",
			outputs:       []*messages.BTCSignOutputRequest{ordinaryOutput, silentOutput},
			exchanges:     []outputExchange{{index: 1, script: script, proof: proof[:len(proof)-1]}},
			expectedError: "wrong DLEQ proof size",
		},
		{
			name:          "invalid proof",
			outputs:       []*messages.BTCSignOutputRequest{ordinaryOutput, silentOutput},
			exchanges:     []outputExchange{{index: 1, script: script, proof: invalidProof}},
			expectedError: "DLEQ proof verification failed",
		},
		{
			name:          "incorrect script",
			outputs:       []*messages.BTCSignOutputRequest{ordinaryOutput, silentOutput},
			exchanges:     []outputExchange{{index: 1, script: wrongScript, proof: proof}},
			expectedError: "incorrect silent payment output",
		},
		{
			name:          "generated data for ordinary output",
			outputs:       []*messages.BTCSignOutputRequest{ordinaryOutput},
			exchanges:     []outputExchange{{index: 0, script: script, proof: proof}},
			expectedError: "unexpected silent payment output data",
		},
		{
			name:          "proof alone for ordinary output",
			outputs:       []*messages.BTCSignOutputRequest{ordinaryOutput},
			exchanges:     []outputExchange{{index: 0, proof: proof}},
			expectedError: "unexpected silent payment output data",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			step := 0
			device := newDevice(t, semver.NewSemVer(9, 21, 0), common.ProductBitBox02Multi,
				&mocks.Communication{}, func(request *messages.Request) *messages.Response {
					next := &messages.BTCSignNextResponse{Type: messages.BTCSignNextResponse_DONE}
					if step == 0 {
						require.NotNil(t, request.GetBtcSignInit())
					} else {
						exchange := test.exchanges[step-1]
						require.True(t, proto.Equal(test.outputs[exchange.index], request.GetBtcSignOutput()))
						next.GeneratedOutputPkscript = exchange.script
						next.SilentPaymentDleqProof = exchange.proof
					}
					if step < len(test.exchanges) {
						next.Type = messages.BTCSignNextResponse_OUTPUT
						next.Index = test.exchanges[step].index
					}
					step++
					return &messages.Response{Response: &messages.Response_BtcSignNext{BtcSignNext: next}}
				})
			result, err := device.BTCSign(messages.BTCCoin_BTC, nil, nil,
				&BTCTx{Version: 2, Inputs: []*BTCTxInput{input}, Outputs: test.outputs},
				messages.BTCSignInitRequest_DEFAULT)
			if test.expectedError != "" {
				require.ErrorContains(t, err, test.expectedError)
				require.Nil(t, result)
			} else {
				require.NoError(t, err)
				expected := map[int][]byte{}
				for i, output := range test.outputs {
					if output.SilentPayment != nil {
						expected[i] = script
					}
				}
				require.Equal(t, expected, result.GeneratedOutputs)
			}
			require.Equal(t, len(test.exchanges)+1, step)
		})
	}
}
