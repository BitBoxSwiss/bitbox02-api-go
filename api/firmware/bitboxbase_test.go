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
	"testing"

	"github.com/digitalbitbox/bitbox02-api-go/api/common"
	"github.com/digitalbitbox/bitbox02-api-go/api/firmware/messages"
	"github.com/stretchr/testify/require"
)

func TestBitBoxBaseConfirmPairing(t *testing.T) {
	testConfigurations(t, func(env *testEnv, t *testing.T) {
		env.onRequest = func(*messages.Request) *messages.Response {
			return responseSuccess
		}

		err := env.device.BitBoxBaseConfirmPairing(make([]byte, 32))
		require.Equal(t, env.product == common.ProductBitBoxBaseStandard, err == nil)
	})
}

func TestBitBoxBaseSetConfig(t *testing.T) {
	testConfigurations(t, func(env *testEnv, t *testing.T) {
		env.onRequest = func(*messages.Request) *messages.Response {
			return responseSuccess
		}
		if env.product != common.ProductBitBoxBaseStandard {
			// Wrong product.
			require.Error(t,
				env.device.BitBoxBaseSetConfig(
					messages.BitBoxBaseSetConfigRequest_LED_ALWAYS,
					messages.BitBoxBaseSetConfigRequest_SCREEN_ALWAYS,
					nil,
					"",
				),
			)
			return
		}
		require.NoError(t,
			env.device.BitBoxBaseSetConfig(
				messages.BitBoxBaseSetConfigRequest_LED_ALWAYS,
				messages.BitBoxBaseSetConfigRequest_SCREEN_ALWAYS,
				nil,
				"",
			),
		)
		ip := [4]uint8{192, 168, 1, 24}
		require.NoError(t,
			env.device.BitBoxBaseSetConfig(
				messages.BitBoxBaseSetConfigRequest_LED_ALWAYS,
				messages.BitBoxBaseSetConfigRequest_SCREEN_ALWAYS,
				&ip,
				"",
			),
		)

		// Hostname too long.
		require.Error(t,
			env.device.BitBoxBaseSetConfig(
				messages.BitBoxBaseSetConfigRequest_LED_ALWAYS,
				messages.BitBoxBaseSetConfigRequest_SCREEN_ALWAYS,
				&ip,
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			),
		)
	})
}
