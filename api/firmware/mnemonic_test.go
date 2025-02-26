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
