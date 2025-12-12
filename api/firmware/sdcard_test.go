// SPDX-License-Identifier: Apache-2.0

package firmware

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSimulatorCheckSDCard(t *testing.T) {
	testSimulatorsAfterPairing(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()
		inserted, err := device.CheckSDCard()
		require.NoError(t, err)
		// Simulator always returns true.
		require.True(t, inserted)
	})
}

func TestSimutorInsertSDCard(t *testing.T) {
	testSimulatorsAfterPairing(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()
		require.NoError(t, device.InsertSDCard())
	})
}
