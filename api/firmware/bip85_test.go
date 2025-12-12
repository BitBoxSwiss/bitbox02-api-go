// SPDX-License-Identifier: Apache-2.0

package firmware

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSimulatorBIP85AppBip39(t *testing.T) {
	// Can't test this yet as the simulator panics at trinary_choice (12, 18, 24 word choice).
	t.Skip()
}

func TestSimulatorBIP85AppLN(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()
		entropy, err := device.BIP85AppLN()
		require.NoError(t, err)
		require.Equal(t,
			"d05448562b8b64994b7de7eac43cdc8a",
			hex.EncodeToString(entropy))
	})
}
