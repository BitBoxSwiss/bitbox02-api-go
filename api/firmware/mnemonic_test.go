// SPDX-License-Identifier: Apache-2.0

package firmware

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSimulatorShowMnemonic(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()
		require.NoError(t, device.ShowMnemonic())
	})
}

func TestSimulatorSetMnemonicPassphraseEnabled(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()
		info, err := device.DeviceInfo()
		require.NoError(t, err)
		require.False(t, info.MnemonicPassphraseEnabled)

		require.NoError(t, device.SetMnemonicPassphraseEnabled(true))

		info, err = device.DeviceInfo()
		require.NoError(t, err)
		require.True(t, info.MnemonicPassphraseEnabled)

		require.NoError(t, device.SetMnemonicPassphraseEnabled(false))

		info, err = device.DeviceInfo()
		require.NoError(t, err)
		require.False(t, info.MnemonicPassphraseEnabled)
	})

}
