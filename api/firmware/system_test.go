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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSimulatorDeviceName(t *testing.T) {
	testSimulatorsAfterPairing(t, func(t *testing.T, device *Device) {
		t.Helper()
		info, err := device.DeviceInfo()
		require.NoError(t, err)
		require.Equal(t, "My BitBox", info.Name)

		// Name too long.
		require.Error(t, device.SetDeviceName(
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))

		require.NoError(t, device.SetDeviceName("new name"))
		info, err = device.DeviceInfo()
		require.NoError(t, err)
		require.Equal(t, "new name", info.Name)
	})
}

func TestSimulatorSetPassword(t *testing.T) {
	for _, seedLen := range []int{16, 32} {
		t.Run(fmt.Sprintf("seedLen=%d", seedLen), func(t *testing.T) {
			testSimulatorsAfterPairing(t, func(t *testing.T, device *Device) {
				t.Helper()
				require.NoError(t, device.SetPassword(seedLen))
				require.Equal(t, StatusSeeded, device.Status())
			})
		})
	}
}
