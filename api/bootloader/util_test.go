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

package bootloader

import (
	"encoding/hex"
	"os"
	"testing"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/common"
	"github.com/stretchr/testify/require"
)

func TestHashFirmware(t *testing.T) {
	emptyHash := []byte("\xad\x27\x67\x91\x84\x74\xf3\x30\x02\x95\xb2\xef\x94\x9a\xe8\x13\xd7\x87\x0c\xed\x70\x30\x58\x29\xa0\x12\x91\xa4\x8f\x8b\xbc\x78")
	require.Equal(t, emptyHash, HashFirmware(5, []byte{}))

	unsignedFirmware, err := os.ReadFile("testdata/firmware-btc.v4.2.2.bin")
	require.NoError(t, err)
	require.Equal(t,
		[]byte("\x9a\xfc\x65\xa1\x99\x6c\x0d\xfd\xbb\x17\x08\xbf\x51\x8d\x96\x8c\xde\xc7\xe3\xc3\x52\x56\x1e\x2b\x09\x1d\x91\x83\x6c\x06\x8a\xe5"),
		HashFirmware(7, unsignedFirmware),
	)
}

func TestParseSignedFirmmare(t *testing.T) {
	unsignedFirmware, err := os.ReadFile("testdata/firmware-btc.v4.2.2.bin")
	require.NoError(t, err)

	signedFirmware, err := os.ReadFile("testdata/firmware-btc.v4.2.2.signed.bin")
	require.NoError(t, err)

	product, sigData, firmware, err := ParseSignedFirmware(signedFirmware)
	require.NoError(t, err)

	expectedSigData := "0000000027a8678099f9f52b142a0692b320d6053d3f7c637273a236654ce4e5346efaffb35034df24eca2e500bbd24b84ba79799d4d7ad5492516b5122587d41a63d9d7c2565124b98a5d9da8bfab7e566371c936b1435d7980d4c09bc31b84431c2e3c6b62829093f478be5356657aa525d6a5fc793acd2641f9bd2d3587dea6a33ad7c6789655ce072bf02908b5d795a87b6789cac63e98bf7849d740d47fb62f3fef88c6db3cb260c53302eb133a89b3529e2f8ae20e99ed0fe3d32cd30db880ffbc47be63edb71c681a3a0d45716746db7704c915d617fcf1c895ca949bb3adcc9a666c73dd373cdf9d4ccf9ff102bde32307f29ecdbf981b3553af7ba3509ff565000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003d8054281b0f6733469f58e0406cba24fefcea8704cd6e8d990bd98fa33d2b0a0942dcafc81f912216ca86cab2000b6de96f1567d5209ab6167278dc585b011d070000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000017a44e602e19792e468a110b997f74b4149a4aca55e98a8b94f219739886c0227f6267ff582f2c1293f71f5afcb5ba6065ebeb454aa142f389f2bb91da62e4281f557a14e9974a3df39c9451b88766c4de7d1fcb8173fcdef82e316e8a8fd4822947a103aeee373e7c687228fadbd5b7ae3032886da057d53338abd889bff301"
	require.Equal(t, expectedSigData, hex.EncodeToString(sigData))
	require.Equal(t, common.ProductBitBox02BTCOnly, product)
	require.Equal(t, unsignedFirmware, firmware)

	// Test invalid magic
	signedFirmware[0] = 0
	_, _, _, err = ParseSignedFirmware(signedFirmware)
	require.Error(t, err)

}
