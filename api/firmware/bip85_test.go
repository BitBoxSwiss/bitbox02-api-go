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
