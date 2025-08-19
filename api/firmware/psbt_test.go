// Copyright 2025 Shift Crypto AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package firmware

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/BitBoxSwiss/bitbox02-api-go/util/errp"
	"github.com/BitBoxSwiss/bitbox02-api-go/util/semver"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type psbtPrevoutFetcher struct {
	psbt *psbt.Packet
}

// FetchPrevOutput implements `txscript.PrevOutputFetcher`.
func (p psbtPrevoutFetcher) FetchPrevOutput(op wire.OutPoint) *wire.TxOut {
	for inputIndex := range p.psbt.Inputs {
		psbtInput := &p.psbt.Inputs[inputIndex]
		txInput := p.psbt.UnsignedTx.TxIn[inputIndex]
		if txInput.PreviousOutPoint.String() == op.String() {
			if psbtInput.WitnessUtxo != nil {
				return psbtInput.WitnessUtxo
			}
			if psbtInput.NonWitnessUtxo != nil {
				return psbtInput.NonWitnessUtxo.TxOut[txInput.PreviousOutPoint.Index]
			}
		}
	}
	return nil
}

func txValidityCheck(psbt_ *psbt.Packet) error {
	signedTx, err := psbt.Extract(psbt_)
	if err != nil {
		return err
	}
	prevOutputs := psbtPrevoutFetcher{psbt: psbt_}
	sigHashes := txscript.NewTxSigHashes(signedTx, prevOutputs)
	for index, txInput := range signedTx.TxIn {
		spentOutput := prevOutputs.FetchPrevOutput(txInput.PreviousOutPoint)
		engine, err := txscript.NewEngine(spentOutput.PkScript, signedTx, index,
			txscript.StandardVerifyFlags, nil, sigHashes, spentOutput.Value, prevOutputs)
		if err != nil {
			return errp.WithStack(err)
		}
		if err := engine.Execute(); err != nil {
			spew.Dump(err.(txscript.Error).ErrorCode)
			return errp.WithStack(err)
		}
	}
	return nil
}

func TestPayloadFromPkScript(t *testing.T) {
	tests := []struct {
		name            string
		address         string
		expectedType    messages.BTCOutputType
		expectedPayload string
	}{
		{
			name:            "P2PKH",
			address:         "1AMZK8xzHJWsuRErpGZTiW4jKz8fdfLUGE",
			expectedPayload: "669c6cb1883c50a1b10c34bd1693c1f34fe3d798",
			expectedType:    messages.BTCOutputType_P2PKH,
		},
		{
			name:            "P2SH",
			address:         "3JFL8CgtV4ZtMFYeP5LgV4JppLkHw5Gw9T",
			expectedPayload: "b59e844a19063a882b3c34b64b941a8acdad74ee",
			expectedType:    messages.BTCOutputType_P2SH,
		},
		{
			name:            "P2WPKH",
			address:         "bc1qkl8ms75cq6ajxtny7e88z3u9hkpkvktt5jwh6u",
			expectedPayload: "b7cfb87a9806bb232e64f64e714785bd8366596b",
			expectedType:    messages.BTCOutputType_P2WPKH,
		},
		{
			name:            "P2WSH",
			address:         "bc1q2fhgukymf0caaqrhfxrdju4wm94wwrch2ukntl5fuc0faz8zm49q0h6ss8",
			expectedPayload: "526e8e589b4bf1de80774986d972aed96ae70f17572d35fe89e61e9e88e2dd4a",
			expectedType:    messages.BTCOutputType_P2WSH,
		},
		{
			name:            "P2TR",
			address:         "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
			expectedPayload: "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
			expectedType:    messages.BTCOutputType_P2TR,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := btcutil.DecodeAddress(tt.address, &chaincfg.MainNetParams)
			require.NoError(t, err)

			pkScript, err := txscript.PayToAddrScript(addr)
			require.NoError(t, err)

			outputType, payload, err := payloadFromPkScript(pkScript)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedType, outputType)
			assert.Equal(t, tt.expectedPayload, hex.EncodeToString(payload))
		})
	}
}

// Test that a PSBT containing only p2wpkh inputs is converted correctly to a transaction to be
// signed by the BitBox.
func TestNewBTCTxFromPSBT_P2WPKH(t *testing.T) {
	// Based on mnemonic:
	// route glue else try obey local kidney future teach unaware pulse exclude.
	psbtStr := "cHNidP8BAHECAAAAAfbXTun4YYxDroWyzRq3jDsWFVlsZ7HUzxiORY/iR4goAAAAAAD9////AuLCAAAAAAAAFgAUg3w5W0zt3AmxRmgA5Q6wZJUDRhUowwAAAAAAABYAFJjQqUoXDcwUEqfExu9pnaSn5XBct0ElAAABAR+ghgEAAAAAABYAFHn03igII+hp819N2Zlb5LnN8atRAQDfAQAAAAABAZ9EJlMJnXF5bFVrb1eFBYrEev3pg35WpvS3RlELsMMrAQAAAAD9////AqCGAQAAAAAAFgAUefTeKAgj6GnzX03ZmVvkuc3xq1EoRs4JAAAAABYAFKG2PzjYjknaA6lmXFqPaSgHwXX9AkgwRQIhAL0v0r3LisQ9KOlGzMhM/xYqUmrv2a5sORRlkX1fqDC8AiB9XqxSNEdb4mPnp7ylF1cAlbAZ7jMhgIxHUXylTww3bwEhA0AEOM0yYEpexPoKE3vT51uxZ+8hk9sOEfBFKOeo6oDDAAAAACIGAyNQfmAT/YLmZaxxfDwClmVNt2BkFnfQu/i8Uc/hHDUiGBKiwYlUAACAAQAAgAAAAIAAAAAAAAAAAAAAIgIDnxFM7Qr9LvJwQDB9GozdTRIe3MYVuHOqT7dU2EuvHrIYEqLBiVQAAIABAACAAAAAgAEAAAAAAAAAAA=="

	expectedTx := &BTCTx{
		Version: 2,
		Inputs: []*BTCTxInput{{
			Input: &messages.BTCSignInputRequest{
				PrevOutHash: []byte{
					0xf6, 0xd7, 0x4e, 0xe9, 0xf8, 0x61, 0x8c, 0x43,
					0xae, 0x85, 0xb2, 0xcd, 0x1a, 0xb7, 0x8c, 0x3b,
					0x16, 0x15, 0x59, 0x6c, 0x67, 0xb1, 0xd4, 0xcf,
					0x18, 0x8e, 0x45, 0x8f, 0xe2, 0x47, 0x88, 0x28,
				},
				PrevOutIndex:      0,
				PrevOutValue:      100000,
				Sequence:          0xfffffffd,
				Keypath:           []uint32{84 + HARDENED, 1 + HARDENED, HARDENED, 0, 0},
				ScriptConfigIndex: 0,
			},
			PrevTx: &BTCPrevTx{
				Version: 1,
				Inputs: []*messages.BTCPrevTxInputRequest{{
					PrevOutHash: []byte{
						0x9f, 0x44, 0x26, 0x53, 0x09, 0x9d, 0x71, 0x79,
						0x6c, 0x55, 0x6b, 0x6f, 0x57, 0x85, 0x05, 0x8a,
						0xc4, 0x7a, 0xfd, 0xe9, 0x83, 0x7e, 0x56, 0xa6,
						0xf4, 0xb7, 0x46, 0x51, 0x0b, 0xb0, 0xc3, 0x2b,
					},
					PrevOutIndex:    1,
					SignatureScript: []byte{},
					Sequence:        0xfffffffd,
				}},
				Outputs: []*messages.BTCPrevTxOutputRequest{
					{
						Value: 100000,
						PubkeyScript: []byte{
							0x00, 0x14, 0x79, 0xf4, 0xde, 0x28, 0x08, 0x23,
							0xe8, 0x69, 0xf3, 0x5f, 0x4d, 0xd9, 0x99, 0x5b,
							0xe4, 0xb9, 0xcd, 0xf1, 0xab, 0x51,
						},
					},
					{
						Value: 164513320,
						PubkeyScript: []byte{
							0x00, 0x14, 0xa1, 0xb6, 0x3f, 0x38, 0xd8, 0x8e,
							0x49, 0xda, 0x03, 0xa9, 0x66, 0x5c, 0x5a, 0x8f,
							0x69, 0x28, 0x07, 0xc1, 0x75, 0xfd,
						},
					},
				},
				Locktime: 0,
			},
		}},
		Outputs: []*messages.BTCSignOutputRequest{
			{
				Ours:  false,
				Type:  messages.BTCOutputType_P2WPKH,
				Value: 49890,
				Payload: []byte{
					0x83, 0x7c, 0x39, 0x5b, 0x4c, 0xed, 0xdc, 0x09,
					0xb1, 0x46, 0x68, 0x00, 0xe5, 0x0e, 0xb0, 0x64,
					0x95, 0x03, 0x46, 0x15,
				},
			},
			{
				Ours:              true,
				Value:             49960,
				Keypath:           []uint32{84 + HARDENED, 1 + HARDENED, HARDENED, 1, 0},
				ScriptConfigIndex: 0,
			},
		},
		Locktime: 2441655,
	}

	expectedScriptConfig := &messages.BTCScriptConfigWithKeypath{
		ScriptConfig: NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH),
		Keypath:      []uint32{84 + HARDENED, 1 + HARDENED, HARDENED},
	}

	psbt_, err := psbt.NewFromRawBytes(bytes.NewBufferString(psbtStr), true)
	require.NoError(t, err)
	ourRootFingerprint := []byte{0x12, 0xa2, 0xc1, 0x89}
	result, err := newBTCTxFromPSBT(psbt_, ourRootFingerprint, nil)
	require.NoError(t, err)
	require.Equal(t, expectedTx, result.tx)
	assert.Len(t, result.scriptConfigs, 1)
	require.True(t, proto.Equal(result.scriptConfigs[0], expectedScriptConfig))
}

func TestSimulatorBTCPSBTTaprootKeySpend(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()

		fingerprint, err := device.RootFingerprint()
		require.NoError(t, err)

		changePath := []uint32{86 + HARDENED, 1 + HARDENED, 0 + HARDENED, 1, 0}
		changePubKey := simulatorPub(t, device, changePath...)
		_, changePkScript := makeTaprootOutput(t, changePubKey)

		input0Path := []uint32{86 + HARDENED, 1 + HARDENED, 0 + HARDENED, 0, 0}
		input0Pubkey := simulatorPub(t, device, input0Path...)
		_, input0PkScript := makeTaprootOutput(t, input0Pubkey)

		input1Path := []uint32{86 + HARDENED, 1 + HARDENED, 0 + HARDENED, 0, 1}
		input1PubKey := simulatorPub(t, device, input1Path...)
		_, input1PkScript := makeTaprootOutput(t, input1PubKey)

		// A previous tx which creates some UTXOs we can reference later.
		prevTx := &wire.MsgTx{
			Version:  2,
			LockTime: 0,
			TxIn: []*wire.TxIn{
				{
					PreviousOutPoint: *mustOutpoint("3131313131313131313131313131313131313131313131313131313131313131:0"),
					SignatureScript:  nil,
					Sequence:         0xFFFFFFFF,
					Witness:          nil,
				},
			},
			TxOut: []*wire.TxOut{
				{
					Value:    100_000_000,
					PkScript: input0PkScript,
				},
				{
					Value:    100_000_000,
					PkScript: input1PkScript,
				},
			},
		}

		tx := &wire.MsgTx{
			Version:  2,
			LockTime: 0,
			TxIn: []*wire.TxIn{
				{
					PreviousOutPoint: wire.OutPoint{
						Hash:  prevTx.TxHash(),
						Index: 0,
					},
					SignatureScript: nil,
					Sequence:        0xFFFFFFFF,
					Witness:         nil,
				},
				{
					PreviousOutPoint: wire.OutPoint{
						Hash:  prevTx.TxHash(),
						Index: 1,
					},
					SignatureScript: nil,
					Sequence:        0xFFFFFFFF,
					Witness:         nil,
				},
			},
			TxOut: []*wire.TxOut{
				{
					Value:    100_000_000,
					PkScript: changePkScript,
				},
				{
					Value: 20_000_000,
					// random private key:
					// 9dbb534622a6100a39b73dece43c6d4db14b9a612eb46a6c64c2bb849e283ce8
					PkScript: p2trPkScript(unhex("e4adbb12c3426ec71ebb10688d8ae69d531ca822a2b790acee216a7f1b95b576")),
				},
			},
		}
		psbt_, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)

		// Add input and change infos.
		psbt_.Inputs[0].WitnessUtxo = prevTx.TxOut[0]
		psbt_.Inputs[0].TaprootInternalKey = schnorr.SerializePubKey(input0Pubkey)
		psbt_.Inputs[0].TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{{
			XOnlyPubKey:          psbt_.Inputs[0].TaprootInternalKey,
			MasterKeyFingerprint: binary.LittleEndian.Uint32(fingerprint),
			Bip32Path:            input0Path,
		}}

		psbt_.Inputs[1].WitnessUtxo = prevTx.TxOut[1]
		psbt_.Inputs[1].TaprootInternalKey = schnorr.SerializePubKey(input1PubKey)
		psbt_.Inputs[1].TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{{
			XOnlyPubKey:          psbt_.Inputs[1].TaprootInternalKey,
			MasterKeyFingerprint: binary.LittleEndian.Uint32(fingerprint),
			Bip32Path:            input1Path,
		}}

		psbt_.Outputs[0].TaprootInternalKey = schnorr.SerializePubKey(changePubKey)
		psbt_.Outputs[0].TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{{
			XOnlyPubKey:          psbt_.Outputs[0].TaprootInternalKey,
			MasterKeyFingerprint: binary.LittleEndian.Uint32(fingerprint),
			Bip32Path:            changePath,
		}}

		// Sign & validate.
		require.NoError(t, device.BTCSignPSBT(messages.BTCCoin_TBTC, psbt_, nil))
		require.NoError(t, psbt.MaybeFinalizeAll(psbt_))
		require.NoError(t, txValidityCheck(psbt_))
	})
}

func TestSimulatorBTCPSBTMixedSpend(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()

		fingerprint, err := device.RootFingerprint()
		require.NoError(t, err)

		// Derivation paths
		changePath := []uint32{86 + HARDENED, 1 + HARDENED, 0 + HARDENED, 1, 0}
		input0Path := []uint32{86 + HARDENED, 1 + HARDENED, 0 + HARDENED, 0, 0} // P2TR
		input1Path := []uint32{84 + HARDENED, 1 + HARDENED, 0 + HARDENED, 0, 0} // P2WPKH
		input2Path := []uint32{49 + HARDENED, 1 + HARDENED, 0 + HARDENED, 0, 0} // P2SH-P2WPKH

		// Generate public keys
		input0Pub := simulatorPub(t, device, input0Path...)
		input1Pub := simulatorPub(t, device, input1Path...)
		input2Pub := simulatorPub(t, device, input2Path...)

		// Convert to required formats
		changePubKey := simulatorPub(t, device, changePath...)
		_, changePkScript := makeTaprootOutput(t, changePubKey)
		// P2WPKH redeem script
		input2RedeemScript := p2wpkhPkScript(input2Pub)

		// Previous transaction with mixed outputs
		prevTx := &wire.MsgTx{
			Version:  2,
			LockTime: 0,
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: *mustOutpoint("3131313131313131313131313131313131313131313131313131313131313131:0"),
				Sequence:         0xFFFFFFFF,
			}},
			TxOut: []*wire.TxOut{
				{ // P2TR
					Value: 100_000_000,
					PkScript: func() []byte {
						_, script := makeTaprootOutput(t, input0Pub)
						return script
					}(),
				},
				{ // P2WPKH
					Value:    100_000_000,
					PkScript: p2wpkhPkScript(input1Pub),
				},
				{ // P2SH-P2WPKH
					Value:    100_000_000,
					PkScript: p2shPkScript(input2RedeemScript),
				},
			},
		}

		// Spending transaction
		tx := &wire.MsgTx{
			Version:  2,
			LockTime: 0,
			TxIn: []*wire.TxIn{
				{PreviousOutPoint: wire.OutPoint{Hash: prevTx.TxHash(), Index: 0}}, // P2TR input
				{PreviousOutPoint: wire.OutPoint{Hash: prevTx.TxHash(), Index: 1}}, // P2WPKH input
				{PreviousOutPoint: wire.OutPoint{Hash: prevTx.TxHash(), Index: 2}}, // P2SH-P2WPKH input
			},
			TxOut: []*wire.TxOut{
				{ // Change output (P2TR)
					Value:    100_000_000,
					PkScript: changePkScript,
				},
				{ // External output
					Value: 20_000_000,
					// random private key:
					// 9dbb534622a6100a39b73dece43c6d4db14b9a612eb46a6c64c2bb849e283ce8
					PkScript: p2trPkScript(unhex("e4adbb12c3426ec71ebb10688d8ae69d531ca822a2b790acee216a7f1b95b576")),
				},
			},
		}

		psbt_, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)

		// Setup PSBT inputs
		// Input 0 (P2TR)
		psbt_.Inputs[0].NonWitnessUtxo = prevTx
		psbt_.Inputs[0].WitnessUtxo = prevTx.TxOut[0]
		psbt_.Inputs[0].TaprootInternalKey = schnorr.SerializePubKey(changePubKey)
		psbt_.Inputs[0].TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{{
			XOnlyPubKey:          psbt_.Inputs[0].TaprootInternalKey,
			MasterKeyFingerprint: binary.LittleEndian.Uint32(fingerprint),
			Bip32Path:            input0Path,
		}}

		// Input 1 (P2WPKH)
		psbt_.Inputs[1].NonWitnessUtxo = prevTx
		psbt_.Inputs[1].WitnessUtxo = prevTx.TxOut[1]
		psbt_.Inputs[1].Bip32Derivation = []*psbt.Bip32Derivation{{
			PubKey:               input1Pub.SerializeCompressed(),
			MasterKeyFingerprint: binary.LittleEndian.Uint32(fingerprint),
			Bip32Path:            input1Path,
		}}

		// Input 2 (P2SH-P2WPKH)
		psbt_.Inputs[2].NonWitnessUtxo = prevTx
		psbt_.Inputs[2].WitnessUtxo = prevTx.TxOut[2]
		psbt_.Inputs[2].Bip32Derivation = []*psbt.Bip32Derivation{{
			PubKey:               input2Pub.SerializeCompressed(),
			MasterKeyFingerprint: binary.LittleEndian.Uint32(fingerprint),
			Bip32Path:            input2Path,
		}}
		psbt_.Inputs[2].RedeemScript = input2RedeemScript

		// Setup change output
		psbt_.Outputs[0].TaprootInternalKey = schnorr.SerializePubKey(changePubKey)
		psbt_.Outputs[0].TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{{
			XOnlyPubKey:          psbt_.Outputs[0].TaprootInternalKey,
			MasterKeyFingerprint: binary.LittleEndian.Uint32(fingerprint),
			Bip32Path:            changePath,
		}}

		// Sign & validate
		require.NoError(t, device.BTCSignPSBT(messages.BTCCoin_TBTC, psbt_, nil))
		require.NoError(t, psbt.MaybeFinalizeAll(psbt_))
		require.NoError(t, txValidityCheck(psbt_))
	})
}

func TestSimulatorBTCPSBTSilentPayment(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()

		fingerprint, err := device.RootFingerprint()
		require.NoError(t, err)

		// Derivation paths
		changePath := []uint32{86 + HARDENED, 0 + HARDENED, 0 + HARDENED, 1, 0}
		input0Path := []uint32{86 + HARDENED, 0 + HARDENED, 0 + HARDENED, 0, 0} // P2TR
		input1Path := []uint32{84 + HARDENED, 0 + HARDENED, 0 + HARDENED, 0, 0} // P2WPKH
		input2Path := []uint32{49 + HARDENED, 0 + HARDENED, 0 + HARDENED, 0, 0} // P2SH-P2WPKH

		// Generate public keys
		input0Pub := simulatorPub(t, device, input0Path...)
		input1Pub := simulatorPub(t, device, input1Path...)
		input2Pub := simulatorPub(t, device, input2Path...)

		// Convert to required formats
		changePubKey := simulatorPub(t, device, changePath...)
		_, changePkScript := makeTaprootOutput(t, changePubKey)
		// P2WPKH redeem script
		input2RedeemScript := p2wpkhPkScript(input2Pub)

		// Previous transaction with mixed outputs
		prevTx := &wire.MsgTx{
			Version:  2,
			LockTime: 0,
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: *mustOutpoint("3131313131313131313131313131313131313131313131313131313131313131:0"),
				Sequence:         0xFFFFFFFF,
			}},
			TxOut: []*wire.TxOut{
				{ // P2TR
					Value: 100_000_000,
					PkScript: func() []byte {
						_, script := makeTaprootOutput(t, input0Pub)
						return script
					}(),
				},
				{ // P2WPKH
					Value:    100_000_000,
					PkScript: p2wpkhPkScript(input1Pub),
				},
				{ // P2SH-P2WPKH
					Value:    100_000_000,
					PkScript: p2shPkScript(input2RedeemScript),
				},
			},
		}

		// Spending transaction
		tx := &wire.MsgTx{
			Version:  2,
			LockTime: 0,
			TxIn: []*wire.TxIn{
				{PreviousOutPoint: wire.OutPoint{Hash: prevTx.TxHash(), Index: 0}}, // P2TR input
				{PreviousOutPoint: wire.OutPoint{Hash: prevTx.TxHash(), Index: 1}}, // P2WPKH input
				{PreviousOutPoint: wire.OutPoint{Hash: prevTx.TxHash(), Index: 2}}, // P2SH-P2WPKH input
			},
			TxOut: []*wire.TxOut{
				{ // Change output (P2TR)
					Value:    100_000_000,
					PkScript: changePkScript,
				},
				{ // External output
					Value: 20_000_000,
					// Will be generated, silent payment output
					PkScript: nil,
				},
			},
		}

		psbt_, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)

		// Setup PSBT inputs
		// Input 0 (P2TR)
		psbt_.Inputs[0].NonWitnessUtxo = prevTx
		psbt_.Inputs[0].WitnessUtxo = prevTx.TxOut[0]
		psbt_.Inputs[0].TaprootInternalKey = schnorr.SerializePubKey(input0Pub)
		psbt_.Inputs[0].TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{{
			XOnlyPubKey:          psbt_.Inputs[0].TaprootInternalKey,
			MasterKeyFingerprint: binary.LittleEndian.Uint32(fingerprint),
			Bip32Path:            input0Path,
		}}

		// Input 1 (P2WPKH)
		psbt_.Inputs[1].NonWitnessUtxo = prevTx
		psbt_.Inputs[1].WitnessUtxo = prevTx.TxOut[1]
		psbt_.Inputs[1].Bip32Derivation = []*psbt.Bip32Derivation{{
			PubKey:               input1Pub.SerializeCompressed(),
			MasterKeyFingerprint: binary.LittleEndian.Uint32(fingerprint),
			Bip32Path:            input1Path,
		}}

		// Input 2 (P2SH-P2WPKH)
		psbt_.Inputs[2].NonWitnessUtxo = prevTx
		psbt_.Inputs[2].WitnessUtxo = prevTx.TxOut[2]
		psbt_.Inputs[2].Bip32Derivation = []*psbt.Bip32Derivation{{
			PubKey:               input2Pub.SerializeCompressed(),
			MasterKeyFingerprint: binary.LittleEndian.Uint32(fingerprint),
			Bip32Path:            input2Path,
		}}
		psbt_.Inputs[2].RedeemScript = input2RedeemScript

		// Setup change output
		psbt_.Outputs[0].TaprootInternalKey = schnorr.SerializePubKey(changePubKey)
		psbt_.Outputs[0].TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{{
			XOnlyPubKey:          psbt_.Outputs[0].TaprootInternalKey,
			MasterKeyFingerprint: binary.LittleEndian.Uint32(fingerprint),
			Bip32Path:            changePath,
		}}

		// Sign & validate
		signOptions := &PSBTSignOptions{
			Outputs: map[int]*PSBTSignOutputOptions{
				1: {
					SilentPaymentAddress: "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
				},
			},
		}
		err = device.BTCSignPSBT(messages.BTCCoin_BTC, psbt_, signOptions)
		if !device.version.AtLeast(semver.NewSemVer(9, 21, 0)) {
			require.EqualError(t, err, UnsupportedError("9.21.0").Error())
			return
		}
		require.NoError(t, err)
		require.NoError(t, psbt.MaybeFinalizeAll(psbt_))
		require.NoError(t, txValidityCheck(psbt_))
	})
}
