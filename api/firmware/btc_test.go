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
	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/require"
)

const hardenedKeyStart = 0x80000000

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
