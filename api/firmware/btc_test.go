// Copyright 2018-2019 Shift Cryptosecurity AG
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

package firmware_test

import (
	"errors"
	"testing"

	"github.com/digitalbitbox/bitbox02-api-go/api/firmware"
	"github.com/digitalbitbox/bitbox02-api-go/api/firmware/messages"
	"github.com/digitalbitbox/bitbox02-api-go/util/semver"
	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/require"
)

const hardenedKeyStart = 0x80000000

func TestNewXPub(t *testing.T) {
	xpub, err := firmware.NewXPub(
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

func TestBTCXPub(t *testing.T) {
	testConfigurations(t, func(env *testEnv, t *testing.T) {
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
			return responseSuccess
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
	testConfigurations(t, func(env *testEnv, t *testing.T) {
		expected := "mocked-address"
		scriptConfig := firmware.NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH_P2SH)
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
			return responseSuccess
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
	testConfigurations(t, func(env *testEnv, t *testing.T) {
		env.onRequest = func(request *messages.Request) *messages.Response {
			return &messages.Response{
				Response: &messages.Response_Btc{
					Btc: &messages.BTCResponse{
						Response: &messages.BTCResponse_SignMessage{
							SignMessage: &messages.BTCSignMessageResponse{
								Signature: []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x02"),
							},
						},
					},
				},
			}
		}
		sig, recID, electrumSig65, err := env.device.BTCSignMessage(
			messages.BTCCoin_BTC,
			&messages.BTCScriptConfigWithKeypath{
				ScriptConfig: firmware.NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH_P2SH),
				Keypath:      []uint32{49 + hardenedKeyStart, 0 + hardenedKeyStart, 0 + hardenedKeyStart, 0, 0},
			},
			[]byte("message"),
		)
		if env.version.AtLeast(semver.NewSemVer(9, 2, 0)) {
			require.NoError(t, err)
			require.Equal(t, []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), sig)
			require.Equal(t, byte(2), recID)
			require.Equal(t, electrumSig65, []byte("\x21aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
		} else {
			require.EqualError(t, err, firmware.UnsupportedError("9.2.0").Error())
		}
	})
}
