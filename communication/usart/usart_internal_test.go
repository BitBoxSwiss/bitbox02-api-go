// SPDX-License-Identifier: Apache-2.0

package usart

import (
	"encoding/hex"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestChecksum(t *testing.T) {
	data, err := os.ReadFile("testdata/chunk.bin")
	require.NoError(t, err)
	require.Equal(t, "4700", hex.EncodeToString(computeChecksum(data)))
}
