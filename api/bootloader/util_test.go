// SPDX-License-Identifier: Apache-2.0

package bootloader

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/common"
	"github.com/stretchr/testify/require"
)

func TestHashFirmware(t *testing.T) {
	emptyHash := []byte("\xad\x27\x67\x91\x84\x74\xf3\x30\x02\x95\xb2\xef\x94\x9a\xe8\x13\xd7\x87\x0c\xed\x70\x30\x58\x29\xa0\x12\x91\xa4\x8f\x8b\xbc\x78")
	hash, err := HashFirmware(common.ProductBitBox02BTCOnly, 5, nil)
	require.NoError(t, err)
	require.Equal(t, emptyHash, hash)

	unsignedFirmware, err := os.ReadFile("testdata/firmware-btc.v4.2.2.bin")
	require.NoError(t, err)
	hash, err = HashFirmware(common.ProductBitBox02BTCOnly, 7, unsignedFirmware)
	require.NoError(t, err)
	require.Equal(t,
		[]byte("\x9a\xfc\x65\xa1\x99\x6c\x0d\xfd\xbb\x17\x08\xbf\x51\x8d\x96\x8c\xde\xc7\xe3\xc3\x52\x56\x1e\x2b\x09\x1d\x91\x83\x6c\x06\x8a\xe5"),
		hash,
	)
}

// Independent hashes of the existing firmware fixture cover both hash-format transitions.
func TestHashFirmwareSchemes(t *testing.T) {
	firmware, err := os.ReadFile("testdata/firmware-btc.v4.2.2.bin")
	require.NoError(t, err)
	for product, versions := range map[common.Product]map[uint32]string{
		common.ProductBitBox02Multi: {
			50: "ed12ef2f2726e1e9deb46fc6b35fb9002e1d3d0046fdd12ed7588a930602cc06",
			51: "203510589c84e7de081b46449fc10d061fef8181d751c09687cff5a7ab2505a9",
			56: "f90cd5f1b068322cc157ec3a3d855089f868c2343ccc2fe81153054dfc8d5ac8",
			57: "11ea56fc5e8fe12354fb1be2cfbec176a5d91a1777cd7c9532fd7a0f1d6c3523",
		},
		common.ProductBitBox02BTCOnly: {
			50: "ed12ef2f2726e1e9deb46fc6b35fb9002e1d3d0046fdd12ed7588a930602cc06",
			51: "b121f803c12d3a469e811f354fa7f51e0c5bfe498ffc2ee04e0adf395002935f",
			56: "694ae474079df19c5a910307f9a31c05dc0a0f4d12ce5afe037f13170572a139",
			57: "b970bfede4fd9f2605c20ad5018728b1af3792cd4705da1911d0415a1d59a65b",
		},
		common.ProductBitBox02PlusMulti: {
			50: "ed12ef2f2726e1e9deb46fc6b35fb9002e1d3d0046fdd12ed7588a930602cc06",
			51: "43f4afbe25a7b60d7fd4ff80d189db4f42bdadb26964b2d0e189354fd4e65137",
			56: "6f89447df43f16b9388930e0e1137b1ac79a1aeffa70adcb7f1c6f5dcf5e1fc6",
			57: "4b1085af32d2dfdbc5d05f5357c248a3f828dcb1d69b5c9b701d7dc6eb6858fb",
		},
		common.ProductBitBox02PlusBTCOnly: {
			50: "ed12ef2f2726e1e9deb46fc6b35fb9002e1d3d0046fdd12ed7588a930602cc06",
			51: "44aa6c520df04fddafa6484f5643d0d93ef647e4503886210924ff568a43211a",
			56: "052fa6e5ebbce808a8b3c699e614ebfd4999c949156310e2fc8e11b70de076fb",
			57: "ef8df2e8ba52689476d617e995f2cf9f39a093d03b89e6671af026a041275b02",
		},
	} {
		for version, expectedHash := range versions {
			t.Run(fmt.Sprintf("%s/%d", product, version), func(t *testing.T) {
				hash, err := HashFirmware(product, version, firmware)
				require.NoError(t, err)
				require.Equal(t, expectedHash, hex.EncodeToString(hash))
			})
		}
	}
}

// Hashing must reject unknown products and firmware that does not fit in flash.
func TestHashFirmwareInvalid(t *testing.T) {
	_, err := HashFirmware("unknown", 57, nil)
	require.Error(t, err)
	_, err = HashFirmware(common.ProductBitBox02Multi, 57, make([]byte, maxFirmwareSize+1))
	require.Error(t, err)
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
