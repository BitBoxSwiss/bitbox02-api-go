// SPDX-License-Identifier: Apache-2.0

package firmware

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSimulatorBackups(t *testing.T) {
	const seedLen = 32
	const testName = "test wallet name"
	testSimulatorsAfterPairing(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
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
		require.Equal(t, StatusInitialized, device.Status())

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
