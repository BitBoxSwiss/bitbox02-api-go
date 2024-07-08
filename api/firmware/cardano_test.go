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
	"encoding/hex"
	"testing"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/stretchr/testify/require"
)

func TestSimulatorCardanoXPubs(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device) {
		t.Helper()
		xpubs, err := device.CardanoXPubs(
			[][]uint32{
				{1852 + hardenedKeyStart, 1815 + hardenedKeyStart, hardenedKeyStart},
				{1852 + hardenedKeyStart, 1815 + hardenedKeyStart, hardenedKeyStart + 1},
			},
		)
		require.NoError(t, err)
		require.Len(t, xpubs, 2)
		require.Equal(t,
			"9fc9550e8379cb97c2d2557d89574207c6cf4d4ff62b37e377f2b3b3c284935b677f0fe5a4a6928c7b982c0c149f140c26c0930b73c2fe16feddfa21625e0316",
			hex.EncodeToString(xpubs[0]),
		)
		require.Equal(t,
			"7ffd0bd7d54f1648ac59a357d3eb27b878c2f7c09739d3b7c7e6662d496dea16f10ef525258833d37db047cd530bf373ebcb283495aa4c768424a2af37cee661",
			hex.EncodeToString(xpubs[1]),
		)
	})
}

func TestSimulatorCardanoAddress(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device) {
		t.Helper()
		const account = uint32(1)
		const rolePayment = uint32(0)     // receive
		const roleStake = uint32(2)       // stake role must be 2
		const addressIdx = uint32(10)     // address index
		const stakeAddressIdx = uint32(0) // stake addr idx must be 0
		address, err := device.CardanoAddress(
			messages.CardanoNetwork_CardanoMainnet,
			&messages.CardanoScriptConfig{
				Config: &messages.CardanoScriptConfig_PkhSkh_{
					PkhSkh: &messages.CardanoScriptConfig_PkhSkh{
						KeypathPayment: []uint32{1852 + hardenedKeyStart, 1815 + hardenedKeyStart, account + hardenedKeyStart, rolePayment, addressIdx},
						KeypathStake:   []uint32{1852 + hardenedKeyStart, 1815 + hardenedKeyStart, account + hardenedKeyStart, roleStake, stakeAddressIdx},
					},
				},
			},
			false,
		)
		require.NoError(t, err)
		require.Equal(t,
			"addr1qxdq2ez52f5gtva3m77xgf5x4a7ap78mal43e5hhszyqehaaddssj2eta30yv9chr0sf4gu0jw77gag2g464yq0c70gqks5cr4",
			address,
		)
	})
}
