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
	"errors"
	"testing"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/BitBoxSwiss/bitbox02-api-go/util/semver"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const hardenedKeyStart = 0x80000000

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

func TestBTCXpub(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device) {
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

func TestBTCAddress(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device) {
		t.Helper()
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
	})
}

func parseXPub(t *testing.T, xpubStr string, keypath ...uint32) *hdkeychain.ExtendedKey {
	t.Helper()
	xpub, err := hdkeychain.NewKeyFromString(xpubStr)
	require.NoError(t, err)

	for _, child := range keypath {
		xpub, err = xpub.Derive(child)
		require.NoError(t, err)
	}
	return xpub
}

func TestSimulatorBTCSignMessage(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device) {
		t.Helper()
		coin := messages.BTCCoin_BTC
		accountKeypath := []uint32{49 + hardenedKeyStart, 0 + hardenedKeyStart, 0 + hardenedKeyStart}

		xpubStr, err := device.BTCXPub(coin, accountKeypath, messages.BTCPubRequest_XPUB, false)
		require.NoError(t, err)

		xpub := parseXPub(t, xpubStr, 0, 10)
		pubKey, err := xpub.ECPubKey()
		require.NoError(t, err)

		sig, _, _, err := device.BTCSignMessage(
			coin,
			&messages.BTCScriptConfigWithKeypath{
				ScriptConfig: NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH_P2SH),
				Keypath:      append(accountKeypath, 0, 10),
			},
			[]byte("message"),
		)
		require.NoError(t, err)
		sigHash := chainhash.DoubleHashB([]byte("\x18Bitcoin Signed Message:\n\x07message"))
		require.True(t, parseECDSASignature(t, sig).Verify(sigHash, pubKey))
	})
}

func TestSimulatorBTCXPub(t *testing.T) {
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

func TestSimulatorBTCAddress(t *testing.T) {
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
		sig, recID, electrumSig65, err := env.device.BTCSignMessage(
			messages.BTCCoin_BTC,
			&messages.BTCScriptConfigWithKeypath{
				ScriptConfig: NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH_P2SH),
				Keypath:      []uint32{49 + hardenedKeyStart, 0 + hardenedKeyStart, 0 + hardenedKeyStart, 0, 0},
			},
			[]byte("message"),
		)
		if env.version.AtLeast(semver.NewSemVer(9, 2, 0)) {
			require.NoError(t, err)
			require.Equal(t, expectedSig[:64], sig)
			require.Equal(t, byte(0), recID)
			require.Equal(t, electrumSig65, append([]byte{31}, expectedSig[:64]...))
		} else {
			require.EqualError(t, err, UnsupportedError("9.2.0").Error())
		}
	})
}
