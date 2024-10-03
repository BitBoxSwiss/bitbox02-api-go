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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSimulatorBackups(t *testing.T) {
	const seedLen = 32
	const testName = "test wallet name"
	testSimulatorsAfterPairing(t, func(t *testing.T, device *Device) {
		t.Helper()
		require.NoError(t, device.SetDeviceName(testName))

		require.NoError(t, device.SetPassword(seedLen))
		require.Equal(t, StatusSeeded, device.Status())

		list, err := device.ListBackups()
		require.NoError(t, err)
		require.Empty(t, list)

		_, err = device.CheckBackup(true)
		require.Error(t, err)

		require.NoError(t, device.CreateBackup())
		require.Equal(t, StatusUnlocked, device.Status())

		list, err = device.ListBackups()
		require.NoError(t, err)
		require.Len(t, list, 1)
		require.Equal(t, testName, list[0].Name)

		id, err := device.CheckBackup(true)
		require.NoError(t, err)
		require.Equal(t, list[0].ID, id)

		require.Error(t, device.RestoreBackup(list[0].ID))
		require.NoError(t, device.Reset())
		require.NoError(t, device.RestoreBackup(list[0].ID))
		id, err = device.CheckBackup(true)
		require.NoError(t, err)
		require.Equal(t, list[0].ID, id)
	})
}
