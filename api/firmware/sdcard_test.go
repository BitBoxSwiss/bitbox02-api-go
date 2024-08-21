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

func TestSimulatorCheckSDCard(t *testing.T) {
	testSimulatorsAfterPairing(t, func(t *testing.T, device *Device) {
		t.Helper()
		inserted, err := device.CheckSDCard()
		require.NoError(t, err)
		// Simulator always returns true.
		require.True(t, inserted)
	})
}

func TestSimutorInsertSDCard(t *testing.T) {
	testSimulatorsAfterPairing(t, func(t *testing.T, device *Device) {
		t.Helper()
		require.NoError(t, device.InsertSDCard())
	})
}
