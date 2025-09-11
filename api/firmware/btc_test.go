// Copyright 2018-2019 Shift Cryptosecurity AG
// Copyright 2024 Shift Crypto AG
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
	"errors"
	"testing"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/BitBoxSwiss/bitbox02-api-go/util/semver"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const hardenedKeyStart = 0x80000000

func p2wpkhPkScript(pubkey *btcec.PublicKey) []byte {
	pubkeyHash := btcutil.Hash160(pubkey.SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubkeyHash, &chaincfg.MainNetParams)
	if err != nil {
		panic(err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		panic(err)
	}
	return pkScript
}

func p2trPkScript(xonlyPubkey []byte) []byte {
	addr, err := btcutil.NewAddressTaproot(xonlyPubkey, &chaincfg.MainNetParams)
	if err != nil {
		panic(err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		panic(err)
	}
	return pkScript
}

func p2shPkScript(redeemScript []byte) []byte {
	addr, err := btcutil.NewAddressScriptHash(redeemScript, &chaincfg.MainNetParams)
	if err != nil {
		panic(err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		panic(err)
	}
	return pkScript
}

//nolint:unparam
func mustOutpoint(s string) *wire.OutPoint {
	outPoint, err := wire.NewOutPointFromString(s)
	if err != nil {
		panic(err)
	}
	return outPoint
}

func parseECDSASignature(t *testing.T, sig []byte) *ecdsa.Signature {
	t.Helper()
	require.Len(t, sig, 64)
	r := new(btcec.ModNScalar)
	r.SetByteSlice(sig[:32])
	s := new(btcec.ModNScalar)
	s.SetByteSlice(sig[32:])
	return ecdsa.NewSignature(r, s)
}

func TestNewXPub(t *testing.T) {
	xpub, err := NewXPub(
		"xpub6FEZ9Bv73h1vnE4TJG4QFj2RPXJhhsPbnXgFyH3ErLvpcZrDcynY65bhWga8PazWHLSLi23PoBhGcLcYW6JRiJ12zXZ9Aop4LbAqsS3gtcy")
	require.NoError(t, err)
	require.Equal(t, &messages.XPub{
		Depth:             []byte("\x04"),
		ParentFingerprint: []byte("\xe7\x67\xd2\xc3"),
		ChildNum:          hardenedKeyStart + 2,
		ChainCode:         []byte("\xda\x35\xa6\x5b\xdf\x92\x8b\x8b\xd7\x6f\xd4\xb3\xe2\x5c\xd6\x36\xda\x4f\xfe\x90\x54\x8d\x61\x7d\x18\x34\x65\xac\xb6\x5a\xa6\xad"),
		PublicKey:         []byte("\x03\x8e\xcd\x65\x6c\x32\xad\xc6\x42\xa6\xd3\x2f\x88\x4a\xe3\xa0\x4c\xd3\x8b\xbf\x2d\x42\xaf\xff\x76\xb7\x7a\xde\xc4\x64\x3b\x0e\x1c"),
	}, xpub)
}

func TestSimulatorBTCXpub(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()
		xpub, err := device.BTCXPub(messages.BTCCoin_TBTC, []uint32{
			49 + hardenedKeyStart,
			1 + hardenedKeyStart,
			0 + hardenedKeyStart,
		}, messages.BTCPubRequest_YPUB, false)
		require.NoError(t, err)
		require.Equal(t, "ypub6WqXiL3fbDK5QNPe3hN4uSVkEvuE8wXoNCcecgggSuKVpU3Kc4fTvhuLgUhtnbAdaTb9gpz5PQdvzcsKPTLgW2CPkF5ZNRzQeKFT4NSc1xN", xpub)
	})
}

func TestSimulatorBTCAddress(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()
		// TBTC, P2WPKH
		address, err := device.BTCAddress(
			messages.BTCCoin_TBTC,
			[]uint32{
				84 + hardenedKeyStart,
				1 + hardenedKeyStart,
				0 + hardenedKeyStart,
				1,
				10,
			},
			NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH),
			false,
		)
		require.NoError(t, err)
		require.Equal(t, "tb1qq064dxjgl9h9wzgsmzy6t6306qew42w9ka02u3", address)

		// BTC, P2WPKH
		address, err = device.BTCAddress(
			messages.BTCCoin_BTC,
			[]uint32{
				84 + hardenedKeyStart,
				0 + hardenedKeyStart,
				0 + hardenedKeyStart,
				1,
				10,
			},
			NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH),
			false,
		)
		require.NoError(t, err)
		require.Equal(t, "bc1qcq0ceq9vs24g4tnkkx3k2rry9j44r74huc3d7s", address)

		// RBTC, P2WPKH
		address, err = device.BTCAddress(
			messages.BTCCoin_RBTC,
			[]uint32{
				84 + hardenedKeyStart,
				1 + hardenedKeyStart,
				0 + hardenedKeyStart,
				1,
				10,
			},
			NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH),
			false,
		)
		// Regtest (RBTC) support added in v9.21.0
		if device.Version().AtLeast(semver.NewSemVer(9, 21, 0)) {
			require.NoError(t, err)
			require.Equal(t, "bcrt1qq064dxjgl9h9wzgsmzy6t6306qew42w955k8tc", address)
		} else {
			require.Error(t, err)
		}
	})
}

func simulatorPub(t *testing.T, device *Device, keypath ...uint32) *btcec.PublicKey {
	t.Helper()

	xpubStr, err := device.BTCXPub(messages.BTCCoin_BTC, keypath, messages.BTCPubRequest_XPUB, false)
	require.NoError(t, err)

	xpub, err := hdkeychain.NewKeyFromString(xpubStr)
	require.NoError(t, err)
	pubKey, err := xpub.ECPubKey()
	require.NoError(t, err)
	return pubKey
}

func TestSimulatorBTCSignMessage(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()
		coin := messages.BTCCoin_BTC
		keypath := []uint32{49 + hardenedKeyStart, 0 + hardenedKeyStart, 0 + hardenedKeyStart, 0, 10}

		pubKey := simulatorPub(t, device, keypath...)

		result, err := device.BTCSignMessage(
			coin,
			&messages.BTCScriptConfigWithKeypath{
				ScriptConfig: NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH_P2SH),
				Keypath:      keypath,
			},
			[]byte("message"),
		)
		require.NoError(t, err)
		sigHash := chainhash.DoubleHashB([]byte("\x18Bitcoin Signed Message:\n\x07message"))
		require.True(t, parseECDSASignature(t, result.Signature).Verify(sigHash, pubKey))
	})
}

func TestBTCXPub(t *testing.T) {
	testConfigurations(t, func(t *testing.T, env *testEnv) {
		t.Helper()
		expected := "mocked-xpub"
		xpubType := messages.BTCPubRequest_YPUB
		expectedPubRequest := &messages.BTCPubRequest{
			Coin: messages.BTCCoin_TBTC,
			Keypath: []uint32{
				49 + hardenedKeyStart,
				1 + hardenedKeyStart,
				0 + hardenedKeyStart,
				2,
				10,
			},
			Output: &messages.BTCPubRequest_XpubType{
				XpubType: xpubType,
			},
			Display: true,
		}

		// Unexpected response
		env.onRequest = func(request *messages.Request) *messages.Response {
			return testDeviceResponseOK
		}
		_, err := env.device.BTCXPub(
			expectedPubRequest.Coin,
			expectedPubRequest.Keypath,
			xpubType,
			expectedPubRequest.Display,
		)
		require.Error(t, err)

		// Happy case.
		env.onRequest = func(request *messages.Request) *messages.Response {
			pubRequest, ok := request.Request.(*messages.Request_BtcPub)
			require.True(t, ok)
			require.Equal(t,
				expectedPubRequest,
				pubRequest.BtcPub)
			return &messages.Response{
				Response: &messages.Response_Pub{
					Pub: &messages.PubResponse{
						Pub: expected,
					},
				},
			}
		}
		address, err := env.device.BTCXPub(
			expectedPubRequest.Coin,
			expectedPubRequest.Keypath,
			xpubType,
			expectedPubRequest.Display,
		)
		require.NoError(t, err)
		require.Equal(t, expected, address)

		// Query error.
		expectedErr := errors.New("error")
		env.communication.MockQuery = func(msg []byte) ([]byte, error) {
			return nil, expectedErr
		}
		_, err = env.device.BTCXPub(
			expectedPubRequest.Coin,
			expectedPubRequest.Keypath,
			xpubType,
			expectedPubRequest.Display,
		)
		require.Equal(t, expectedErr, err)
	})
}

func TestBTCAddress(t *testing.T) {
	testConfigurations(t, func(t *testing.T, env *testEnv) {
		t.Helper()
		expected := "mocked-address"
		scriptConfig := NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH_P2SH)
		expectedPubRequest := &messages.BTCPubRequest{
			Coin: messages.BTCCoin_TBTC,
			Keypath: []uint32{
				49 + hardenedKeyStart,
				1 + hardenedKeyStart,
				0 + hardenedKeyStart,
				2,
				10,
			},
			Output: &messages.BTCPubRequest_ScriptConfig{
				ScriptConfig: scriptConfig,
			},
			Display: true,
		}

		// Unexpected response
		env.onRequest = func(request *messages.Request) *messages.Response {
			return testDeviceResponseOK
		}
		_, err := env.device.BTCAddress(
			expectedPubRequest.Coin,
			expectedPubRequest.Keypath,
			scriptConfig,
			expectedPubRequest.Display,
		)
		require.Error(t, err)
		// Happy case.
		env.onRequest = func(request *messages.Request) *messages.Response {
			pubRequest, ok := request.Request.(*messages.Request_BtcPub)
			require.True(t, ok)
			require.True(t, proto.Equal(
				expectedPubRequest,
				pubRequest.BtcPub,
			))
			return &messages.Response{
				Response: &messages.Response_Pub{
					Pub: &messages.PubResponse{
						Pub: expected,
					},
				},
			}
		}
		address, err := env.device.BTCAddress(
			expectedPubRequest.Coin,
			expectedPubRequest.Keypath,
			scriptConfig,
			expectedPubRequest.Display,
		)
		require.NoError(t, err)
		require.Equal(t, expected, address)

		// Query error.
		expectedErr := errors.New("error")
		env.communication.MockQuery = func(msg []byte) ([]byte, error) {
			return nil, expectedErr
		}
		_, err = env.device.BTCAddress(
			expectedPubRequest.Coin,
			expectedPubRequest.Keypath,
			scriptConfig,
			expectedPubRequest.Display,
		)
		require.Equal(t, expectedErr, err)
	})
}

func TestBTCSignMessage(t *testing.T) {
	testConfigurations(t, func(t *testing.T, env *testEnv) {
		t.Helper()
		hostNonce := []byte("\x55\xae\x3b\xbb\x4c\x9e\xc5\x27\xca\xc1\x48\x92\xe9\xd7\x29\x81\x82\xf2\x1d\x5c\xa0\xa5\xf3\xc4\x30\x42\x3e\x52\xfe\x1c\xb9\x10")
		expectedSig := []byte("\xb1\xf8\x62\x29\x55\xc2\x67\xf9\x01\x0b\xd9\x1d\xa8\x46\x93\x67\xb5\xd1\xab\xd1\x95\x72\x1c\xa8\xc1\xd0\xc5\x2a\x37\x73\x84\xbb\x44\xa9\x92\x7e\x42\xaf\xf8\x91\xfa\x8b\xd1\x9e\x77\x86\x62\x1e\x57\xfb\xe4\x14\x79\x9d\x71\x29\x25\xed\xbc\x3b\x5b\x68\xc8\x95\x00")
		env.onRequest = func(request *messages.Request) *messages.Response {
			if req, ok := request.Request.(*messages.Request_Btc).Btc.Request.(*messages.BTCRequest_SignMessage); ok && req.SignMessage.HostNonceCommitment != nil {
				return &messages.Response{
					Response: &messages.Response_Btc{
						Btc: &messages.BTCResponse{
							Response: &messages.BTCResponse_AntikleptoSignerCommitment{
								AntikleptoSignerCommitment: &messages.AntiKleptoSignerCommitment{
									Commitment: []byte("\x02\xed\xee\x9d\x17\x5a\xd5\xcf\x66\xf5\x46\xe0\x72\xfe\x08\x7f\xc1\x5c\x5c\xa8\x4e\x51\xbe\x6e\x72\x5f\x5b\x33\x77\xbf\xfc\x96\x22"),
								},
							},
						},
					},
				}
			}
			return &messages.Response{
				Response: &messages.Response_Btc{
					Btc: &messages.BTCResponse{
						Response: &messages.BTCResponse_SignMessage{
							SignMessage: &messages.BTCSignMessageResponse{
								Signature: expectedSig,
							},
						},
					},
				},
			}
		}
		// Mock host nonce.
		generateHostNonce = func() ([]byte, error) {
			return hostNonce, nil
		}
		result, err := env.device.BTCSignMessage(
			messages.BTCCoin_BTC,
			&messages.BTCScriptConfigWithKeypath{
				ScriptConfig: NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH_P2SH),
				Keypath:      []uint32{49 + hardenedKeyStart, 0 + hardenedKeyStart, 0 + hardenedKeyStart, 0, 0},
			},
			[]byte("message"),
		)
		if env.version.AtLeast(semver.NewSemVer(9, 2, 0)) {
			require.NoError(t, err)
			require.Equal(t, expectedSig[:64], result.Signature)
			require.Equal(t, byte(0), result.RecID)
			require.Equal(t, result.ElectrumSig65, append([]byte{31}, expectedSig[:64]...))
		} else {
			require.EqualError(t, err, UnsupportedError("9.2.0").Error())
		}
	})
}

func makeTaprootOutput(t *testing.T, pubkey *btcec.PublicKey) (*btcec.PublicKey, []byte) {
	t.Helper()
	outputKey := txscript.ComputeTaprootKeyNoScript(pubkey)
	outputPkScript, err := txscript.PayToTaprootScript(outputKey)
	require.NoError(t, err)
	return outputKey, outputPkScript
}

// Test signing; all inputs are BIP86 Taproot keyspends.
func TestSimulatorBTCSignTaprootKeySpend(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()
		coin := messages.BTCCoin_BTC
		accountKeypath := []uint32{86 + hardenedKeyStart, 0 + hardenedKeyStart, 0 + hardenedKeyStart}
		inputKeypath := []uint32{86 + hardenedKeyStart, 0 + hardenedKeyStart, 0 + hardenedKeyStart, 0, 0}
		input2Keypath := []uint32{86 + hardenedKeyStart, 0 + hardenedKeyStart, 0 + hardenedKeyStart, 0, 1}
		changeKeypath := []uint32{86 + hardenedKeyStart, 0 + hardenedKeyStart, 0 + hardenedKeyStart, 1, 0}

		_, input1PkScript := makeTaprootOutput(t, simulatorPub(t, device, inputKeypath...))
		_, input2PkScript := makeTaprootOutput(t, simulatorPub(t, device, input2Keypath...))

		prevTx := &wire.MsgTx{
			Version: 2,
			TxIn: []*wire.TxIn{
				{
					PreviousOutPoint: *mustOutpoint("3131313131313131313131313131313131313131313131313131313131313131:0"),
					Sequence:         0xFFFFFFFF,
				},
			},
			TxOut: []*wire.TxOut{
				{
					Value:    60_000_000,
					PkScript: input1PkScript,
				},
				{
					Value:    40_000_000,
					PkScript: input2PkScript,
				},
			},
			LockTime: 0,
		}

		scriptConfigs := []*messages.BTCScriptConfigWithKeypath{
			{
				ScriptConfig: NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2TR),
				Keypath:      accountKeypath,
			},
		}
		require.False(t, BTCSignNeedsPrevTxs(scriptConfigs))

		prevTxHash := prevTx.TxHash()
		_, err := device.BTCSign(
			coin,
			scriptConfigs,
			nil,
			&BTCTx{
				Version: 2,
				Inputs: []*BTCTxInput{
					{
						Input: &messages.BTCSignInputRequest{
							PrevOutHash:       prevTxHash[:],
							PrevOutIndex:      0,
							PrevOutValue:      uint64(prevTx.TxOut[0].Value),
							Sequence:          0xFFFFFFFF,
							Keypath:           inputKeypath,
							ScriptConfigIndex: 0,
						},
					},
					{
						Input: &messages.BTCSignInputRequest{
							PrevOutHash:       prevTxHash[:],
							PrevOutIndex:      1,
							PrevOutValue:      uint64(prevTx.TxOut[1].Value),
							Sequence:          0xFFFFFFFF,
							Keypath:           input2Keypath,
							ScriptConfigIndex: 0,
						},
					},
				},
				Outputs: []*messages.BTCSignOutputRequest{
					{
						Ours:    true,
						Value:   70_000_000,
						Keypath: changeKeypath,
					},
					{
						Value:   20_000_000,
						Payload: []byte("11111111111111111111111111111111"),
						Type:    messages.BTCOutputType_P2WSH,
					},
				},
				Locktime: 0,
			},
			messages.BTCSignInitRequest_DEFAULT,
		)
		require.NoError(t, err)
	})
}

// Test signing; mixed input types (p2wpkh, p2wpkh-p2sh, p2tr)
func TestSimulatorBTCSignMixed(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()
		coin := messages.BTCCoin_BTC
		changeKeypath := []uint32{86 + hardenedKeyStart, 0 + hardenedKeyStart, 0 + hardenedKeyStart, 1, 0}
		input0Keypath := []uint32{86 + hardenedKeyStart, 0 + hardenedKeyStart, 0 + hardenedKeyStart, 0, 0}
		input1Keypath := []uint32{84 + hardenedKeyStart, 0 + hardenedKeyStart, 0 + hardenedKeyStart, 0, 0}
		input2Keypath := []uint32{49 + hardenedKeyStart, 0 + hardenedKeyStart, 0 + hardenedKeyStart, 0, 0}

		prevTx := &wire.MsgTx{
			Version: 2,
			TxIn: []*wire.TxIn{
				{
					PreviousOutPoint: *mustOutpoint("3131313131313131313131313131313131313131313131313131313131313131:0"),
					Sequence:         0xFFFFFFFF,
				},
			},
			TxOut: []*wire.TxOut{
				{
					Value: 100_000_000,
					PkScript: func() []byte {
						_, script := makeTaprootOutput(t, simulatorPub(t, device, input0Keypath...))
						return script
					}(),
				},
				{
					Value:    100_000_000,
					PkScript: p2wpkhPkScript(simulatorPub(t, device, input1Keypath...)),
				},
				{
					Value:    100_000_000,
					PkScript: p2shPkScript(p2wpkhPkScript(simulatorPub(t, device, input2Keypath...))),
				},
			},
			LockTime: 0,
		}
		convertedPrevTx := NewBTCPrevTxFromBtcd(prevTx)

		scriptConfigs := []*messages.BTCScriptConfigWithKeypath{
			{
				ScriptConfig: NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2TR),
				Keypath:      input0Keypath[:3],
			},
			{
				ScriptConfig: NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH),
				Keypath:      input1Keypath[:3],
			},

			{
				ScriptConfig: NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH_P2SH),
				Keypath:      input2Keypath[:3],
			},
		}
		require.True(t, BTCSignNeedsPrevTxs(scriptConfigs))

		prevTxHash := prevTx.TxHash()
		_, err := device.BTCSign(
			coin,
			scriptConfigs,
			nil,
			&BTCTx{
				Version: 2,
				Inputs: []*BTCTxInput{
					{
						Input: &messages.BTCSignInputRequest{
							PrevOutHash:       prevTxHash[:],
							PrevOutIndex:      0,
							PrevOutValue:      uint64(prevTx.TxOut[0].Value),
							Sequence:          0xFFFFFFFF,
							Keypath:           input0Keypath,
							ScriptConfigIndex: 0,
						},
						PrevTx: convertedPrevTx,
					},
					{
						Input: &messages.BTCSignInputRequest{
							PrevOutHash:       prevTxHash[:],
							PrevOutIndex:      1,
							PrevOutValue:      uint64(prevTx.TxOut[1].Value),
							Sequence:          0xFFFFFFFF,
							Keypath:           input1Keypath,
							ScriptConfigIndex: 1,
						},
						PrevTx: convertedPrevTx,
					},
					{
						Input: &messages.BTCSignInputRequest{
							PrevOutHash:       prevTxHash[:],
							PrevOutIndex:      2,
							PrevOutValue:      uint64(prevTx.TxOut[2].Value),
							Sequence:          0xFFFFFFFF,
							Keypath:           input2Keypath,
							ScriptConfigIndex: 2,
						},
						PrevTx: convertedPrevTx,
					},
				},
				Outputs: []*messages.BTCSignOutputRequest{
					{
						Ours:    true,
						Value:   270_000_000,
						Keypath: changeKeypath,
					},
					{
						Value:   20_000_000,
						Payload: []byte("11111111111111111111111111111111"),
						Type:    messages.BTCOutputType_P2WSH,
					},
				},
				Locktime: 0,
			},
			messages.BTCSignInitRequest_DEFAULT,
		)
		require.NoError(t, err)
	})
}

// Test that we can send to a silent payment output (generated by the BitBox) and verify the
// corresponding DLEQ proof on the host that the output was generated correctly.
func TestSimulatorBTCSignSilentPayment(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()
		coin := messages.BTCCoin_BTC
		accountKeypath := []uint32{86 + hardenedKeyStart, 0 + hardenedKeyStart, 0 + hardenedKeyStart}
		input1Keypath := []uint32{86 + hardenedKeyStart, 0 + hardenedKeyStart, 0 + hardenedKeyStart, 0, 0}
		input2Keypath := []uint32{86 + hardenedKeyStart, 0 + hardenedKeyStart, 0 + hardenedKeyStart, 0, 1}
		changeKeypath := []uint32{86 + hardenedKeyStart, 0 + hardenedKeyStart, 0 + hardenedKeyStart, 1, 0}
		input1Pubkey := simulatorPub(t, device, input1Keypath...)
		input2Pubkey := simulatorPub(t, device, input2Keypath...)
		input1OutputKey, input1PkScript := makeTaprootOutput(t, input1Pubkey)
		input2OutputKey, input2PkScript := makeTaprootOutput(t, input2Pubkey)

		prevTx := &wire.MsgTx{
			Version: 2,
			TxIn: []*wire.TxIn{
				{
					PreviousOutPoint: *mustOutpoint("3131313131313131313131313131313131313131313131313131313131313131:0"),
					Sequence:         0xFFFFFFFF,
				},
			},
			TxOut: []*wire.TxOut{
				{
					Value:    60_000_000,
					PkScript: input1PkScript,
				},
				{
					Value:    40_000_000,
					PkScript: input2PkScript,
				},
			},
			LockTime: 0,
		}
		prevTxHash := prevTx.TxHash()
		result, err := device.BTCSign(
			coin,
			[]*messages.BTCScriptConfigWithKeypath{
				{
					ScriptConfig: NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2TR),
					Keypath:      accountKeypath,
				},
			},
			nil,
			&BTCTx{
				Version: 2,
				Inputs: []*BTCTxInput{
					{
						Input: &messages.BTCSignInputRequest{
							PrevOutHash:       prevTxHash[:],
							PrevOutIndex:      0,
							PrevOutValue:      uint64(prevTx.TxOut[0].Value),
							Sequence:          0xFFFFFFFF,
							Keypath:           input1Keypath,
							ScriptConfigIndex: 0,
						},
						BIP352Pubkey: schnorr.SerializePubKey(input1OutputKey),
					},
					{
						Input: &messages.BTCSignInputRequest{
							PrevOutHash:       prevTxHash[:],
							PrevOutIndex:      1,
							PrevOutValue:      uint64(prevTx.TxOut[1].Value),
							Sequence:          0xFFFFFFFF,
							Keypath:           input2Keypath,
							ScriptConfigIndex: 0,
						},
						BIP352Pubkey: schnorr.SerializePubKey(input2OutputKey),
					},
				},
				Outputs: []*messages.BTCSignOutputRequest{
					{
						Ours:    true,
						Value:   70_000_000,
						Keypath: changeKeypath,
					},
					{
						Value: 20_000_000,
						SilentPayment: &messages.BTCSignOutputRequest_SilentPayment{
							Address: "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
						},
					},
				},
				Locktime: 0,
			},
			messages.BTCSignInitRequest_DEFAULT,
		)

		if device.version.AtLeast(semver.NewSemVer(9, 21, 0)) {
			require.NoError(t, err)
			require.Equal(t,
				map[int][]byte{
					1: unhex("5120f99b8e8d97aa7b068dd7b4e7ae31f51784f5c2a0cae280748cfd23832b7dcba7"),
				},
				result.GeneratedOutputs,
			)
		} else {
			require.EqualError(t, err, UnsupportedError("9.21.0").Error())
		}
	})
}

// Tests that the BitBox displays the output as being of the same account in a self-send.
func TestSimulatorSignBTCTransactionSendSelfSameAccount(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()
		coin := messages.BTCCoin_BTC

		input0Keypath := []uint32{86 + hardenedKeyStart, 0 + hardenedKeyStart, 0 + hardenedKeyStart, 0, 0}
		input1Keypath := []uint32{86 + hardenedKeyStart, 0 + hardenedKeyStart, 0 + hardenedKeyStart, 0, 1}

		prevTx := &wire.MsgTx{
			Version: 2,
			TxIn: []*wire.TxIn{
				{
					PreviousOutPoint: *mustOutpoint("3131313131313131313131313131313131313131313131313131313131313131:0"),
					Sequence:         0xFFFFFFFF,
				},
			},
			TxOut: []*wire.TxOut{
				{
					Value: 100_000_000,
					PkScript: func() []byte {
						_, script := makeTaprootOutput(t, simulatorPub(t, device, input0Keypath...))
						return script
					}(),
				},
			},
			LockTime: 0,
		}
		convertedPrevTx := NewBTCPrevTxFromBtcd(prevTx)

		scriptConfigs := []*messages.BTCScriptConfigWithKeypath{
			{
				ScriptConfig: NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2TR),
				Keypath:      input0Keypath[:3],
			},
		}

		prevTxHash := prevTx.TxHash()
		_, err := device.BTCSign(
			coin,
			scriptConfigs,
			nil,
			&BTCTx{
				Version: 2,
				Inputs: []*BTCTxInput{
					{
						Input: &messages.BTCSignInputRequest{
							PrevOutHash:       prevTxHash[:],
							PrevOutIndex:      0,
							PrevOutValue:      uint64(prevTx.TxOut[0].Value),
							Sequence:          0xFFFFFFFF,
							Keypath:           input0Keypath,
							ScriptConfigIndex: 0,
						},
						PrevTx: convertedPrevTx,
					},
				},
				Outputs: []*messages.BTCSignOutputRequest{
					{
						Ours:    true,
						Value:   70_000_000,
						Keypath: input1Keypath,
					},
				},
				Locktime: 0,
			},
			messages.BTCSignInitRequest_DEFAULT,
		)
		require.NoError(t, err)

		switch {
		// Display changed in v9.22.0.
		case device.Version().AtLeast(semver.NewSemVer(9, 22, 0)):
			require.Contains(t,
				stdOut.String(),
				"This BitBox (same account): bc1psz0tsdr9sgnukfcx4gtwpp5exyeqdycfqjvm2jw6tvsj3k3eavts20yuag",
			)
		case device.Version().AtLeast(semver.NewSemVer(9, 20, 0)):
			require.Contains(t,
				stdOut.String(),
				"This BitBox02: bc1psz0tsdr9sgnukfcx4gtwpp5exyeqdycfqjvm2jw6tvsj3k3eavts20yuag",
			)
		}
		// Before simulator v9.20, address confirmation data was not written to stdout.
	})
}

// Tests that the BitBox displays the output as being of the same keystore, but different account.
func TestSimulatorSignBTCTransactionSendSelfDifferentAccount(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()
		coin := messages.BTCCoin_BTC

		input0Keypath := []uint32{86 + hardenedKeyStart, 0 + hardenedKeyStart, 0 + hardenedKeyStart, 0, 0}
		input1Keypath := []uint32{86 + hardenedKeyStart, 0 + hardenedKeyStart, 1 + hardenedKeyStart, 0, 0}

		prevTx := &wire.MsgTx{
			Version: 2,
			TxIn: []*wire.TxIn{
				{
					PreviousOutPoint: *mustOutpoint("3131313131313131313131313131313131313131313131313131313131313131:0"),
					Sequence:         0xFFFFFFFF,
				},
			},
			TxOut: []*wire.TxOut{
				{
					Value: 100_000_000,
					PkScript: func() []byte {
						_, script := makeTaprootOutput(t, simulatorPub(t, device, input0Keypath...))
						return script
					}(),
				},
			},
			LockTime: 0,
		}
		convertedPrevTx := NewBTCPrevTxFromBtcd(prevTx)

		scriptConfigs := []*messages.BTCScriptConfigWithKeypath{
			{
				ScriptConfig: NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2TR),
				Keypath:      input0Keypath[:3],
			},
		}
		outputScriptConfigs := []*messages.BTCScriptConfigWithKeypath{
			{
				ScriptConfig: NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2TR),
				Keypath:      input1Keypath[:3],
			},
		}
		outputScriptConfigIndex := uint32(0)

		prevTxHash := prevTx.TxHash()
		_, err := device.BTCSign(
			coin,
			scriptConfigs,
			outputScriptConfigs,
			&BTCTx{
				Version: 2,
				Inputs: []*BTCTxInput{
					{
						Input: &messages.BTCSignInputRequest{
							PrevOutHash:       prevTxHash[:],
							PrevOutIndex:      0,
							PrevOutValue:      uint64(prevTx.TxOut[0].Value),
							Sequence:          0xFFFFFFFF,
							Keypath:           input0Keypath,
							ScriptConfigIndex: 0,
						},
						PrevTx: convertedPrevTx,
					},
				},
				Outputs: []*messages.BTCSignOutputRequest{
					{
						Ours:                    true,
						Value:                   70_000_000,
						Keypath:                 input1Keypath,
						OutputScriptConfigIndex: &outputScriptConfigIndex,
					},
				},
				Locktime: 0,
			},
			messages.BTCSignInitRequest_DEFAULT,
		)

		// Introduced in v9.22.0.
		if !device.Version().AtLeast(semver.NewSemVer(9, 22, 0)) {
			require.EqualError(t, err, UnsupportedError("9.22.0").Error())
			return
		}
		require.NoError(t, err)
		require.Contains(t,
			stdOut.String(),
			"This BitBox (account #2): bc1pzeyhtmk2d5jrjunam30dus0p34095m622dq7trm7r0g8pwac2gvqxh8d47",
		)
	})
}
