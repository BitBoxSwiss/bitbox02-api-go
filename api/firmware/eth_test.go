// SPDX-License-Identifier: Apache-2.0

package firmware

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func hashKeccak(b []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	return h.Sum(nil)
}

func parseTypeNoErr(t *testing.T, typ string, types map[string]interface{}) *messages.ETHSignTypedMessageRequest_MemberType {
	t.Helper()
	parsed, err := parseType(typ, types)
	require.NoError(t, err)
	return parsed
}

func TestParseType(t *testing.T) {
	require.Equal(t,
		&messages.ETHSignTypedMessageRequest_MemberType{
			Type: messages.ETHSignTypedMessageRequest_STRING,
		},
		parseTypeNoErr(t, "string", nil),
	)

	// Bytes.
	require.Equal(t,
		&messages.ETHSignTypedMessageRequest_MemberType{
			Type: messages.ETHSignTypedMessageRequest_BYTES,
		},
		parseTypeNoErr(t, "bytes", nil),
	)
	require.Equal(t,
		&messages.ETHSignTypedMessageRequest_MemberType{
			Type: messages.ETHSignTypedMessageRequest_BYTES,
			Size: 1,
		},
		parseTypeNoErr(t, "bytes1", nil),
	)
	require.Equal(t,
		&messages.ETHSignTypedMessageRequest_MemberType{
			Type: messages.ETHSignTypedMessageRequest_BYTES,
			Size: 10,
		},
		parseTypeNoErr(t, "bytes10", nil),
	)
	require.Equal(t,
		&messages.ETHSignTypedMessageRequest_MemberType{
			Type: messages.ETHSignTypedMessageRequest_BYTES,
			Size: 32,
		},
		parseTypeNoErr(t, "bytes32", nil),
	)
	require.Equal(t,
		&messages.ETHSignTypedMessageRequest_MemberType{
			Type: messages.ETHSignTypedMessageRequest_BOOL,
		},
		parseTypeNoErr(t, "bool", nil),
	)
	require.Equal(t,
		&messages.ETHSignTypedMessageRequest_MemberType{
			Type: messages.ETHSignTypedMessageRequest_ADDRESS,
		},
		parseTypeNoErr(t, "address", nil),
	)
	// Uints.
	require.Equal(t,
		&messages.ETHSignTypedMessageRequest_MemberType{
			Type: messages.ETHSignTypedMessageRequest_UINT,
			Size: 1,
		},
		parseTypeNoErr(t, "uint8", nil),
	)
	require.Equal(t,
		&messages.ETHSignTypedMessageRequest_MemberType{
			Type: messages.ETHSignTypedMessageRequest_UINT,
			Size: 2,
		},
		parseTypeNoErr(t, "uint16", nil),
	)
	require.Equal(t,
		&messages.ETHSignTypedMessageRequest_MemberType{
			Type: messages.ETHSignTypedMessageRequest_UINT,
			Size: 32,
		},
		parseTypeNoErr(t, "uint256", nil),
	)
	_, err := parseType("uint", nil)
	require.Error(t, err)
	// Ints.
	require.Equal(t,
		&messages.ETHSignTypedMessageRequest_MemberType{
			Type: messages.ETHSignTypedMessageRequest_INT,
			Size: 1,
		},
		parseTypeNoErr(t, "int8", nil),
	)
	require.Equal(t,
		&messages.ETHSignTypedMessageRequest_MemberType{
			Type: messages.ETHSignTypedMessageRequest_INT,
			Size: 2,
		},
		parseTypeNoErr(t, "int16", nil),
	)
	require.Equal(t,
		&messages.ETHSignTypedMessageRequest_MemberType{
			Type: messages.ETHSignTypedMessageRequest_INT,
			Size: 32,
		},
		parseTypeNoErr(t, "int256", nil),
	)
	_, err = parseType("int", nil)
	require.Error(t, err)

	// Arrays.
	require.Equal(t,
		&messages.ETHSignTypedMessageRequest_MemberType{
			Type: messages.ETHSignTypedMessageRequest_ARRAY,
			ArrayType: &messages.ETHSignTypedMessageRequest_MemberType{
				Type: messages.ETHSignTypedMessageRequest_STRING,
			},
		},
		parseTypeNoErr(t, "string[]", nil),
	)
	require.Equal(t,
		&messages.ETHSignTypedMessageRequest_MemberType{
			Type: messages.ETHSignTypedMessageRequest_ARRAY,
			Size: 521,
			ArrayType: &messages.ETHSignTypedMessageRequest_MemberType{
				Type: messages.ETHSignTypedMessageRequest_STRING,
			},
		},
		parseTypeNoErr(t, "string[521]", nil),
	)
	require.Equal(t,
		&messages.ETHSignTypedMessageRequest_MemberType{
			Type: messages.ETHSignTypedMessageRequest_ARRAY,
			Size: 521,
			ArrayType: &messages.ETHSignTypedMessageRequest_MemberType{
				Type: messages.ETHSignTypedMessageRequest_UINT,
				Size: 4,
			},
		},
		parseTypeNoErr(t, "uint32[521]", nil),
	)
	require.Equal(t,
		&messages.ETHSignTypedMessageRequest_MemberType{
			Type: messages.ETHSignTypedMessageRequest_ARRAY,
			ArrayType: &messages.ETHSignTypedMessageRequest_MemberType{
				Type: messages.ETHSignTypedMessageRequest_ARRAY,
				Size: 521,
				ArrayType: &messages.ETHSignTypedMessageRequest_MemberType{
					Type: messages.ETHSignTypedMessageRequest_UINT,
					Size: 4,
				},
			},
		},
		parseTypeNoErr(t, "uint32[521][]", nil),
	)

	// Structs
	_, err = parseType("Unknown", nil)
	require.Error(t, err)

	require.Equal(t,
		&messages.ETHSignTypedMessageRequest_MemberType{
			Type:       messages.ETHSignTypedMessageRequest_STRUCT,
			StructName: "Person",
		},
		parseTypeNoErr(t, "Person", map[string]interface{}{"Person": nil}),
	)

}

func TestEncodeValue(t *testing.T) {
	encoded, err := encodeValue(parseTypeNoErr(t, "bytes", nil), "foo")
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), encoded)

	encoded, err = encodeValue(parseTypeNoErr(t, "bytes3", nil), "0xaabbcc")
	require.NoError(t, err)
	require.Equal(t, []byte("\xaa\xbb\xcc"), encoded)

	encoded, err = encodeValue(parseTypeNoErr(t, "uint64", nil), float64(2983742332))
	require.NoError(t, err)
	require.Equal(t, []byte("\xb1\xd8\x4b\x7c"), encoded)

	encoded, err = encodeValue(parseTypeNoErr(t, "uint64", nil), "0xb1d84b7c")
	require.NoError(t, err)
	require.Equal(t, []byte("\xb1\xd8\x4b\x7c"), encoded)

	encoded, err = encodeValue(parseTypeNoErr(t, "int64", nil), float64(2983742332))
	require.NoError(t, err)
	require.Equal(t, []byte("\xb1\xd8\x4b\x7c"), encoded)

	encoded, err = encodeValue(parseTypeNoErr(t, "int64", nil), float64(-2983742332))
	require.NoError(t, err)
	require.Equal(t, []byte("\xff\x4e\x27\xb4\x84"), encoded)

	encoded, err = encodeValue(parseTypeNoErr(t, "string", nil), "foo")
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), encoded)

	encoded, err = encodeValue(parseTypeNoErr(t, "address", nil), "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	require.NoError(t, err)
	require.Equal(t, []byte("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"), encoded)

	encoded, err = encodeValue(parseTypeNoErr(t, "bool", nil), false)
	require.NoError(t, err)
	require.Equal(t, []byte{0}, encoded)

	encoded, err = encodeValue(parseTypeNoErr(t, "bool", nil), true)
	require.NoError(t, err)
	require.Equal(t, []byte{1}, encoded)

	// Array encodes its size.
	encoded, err = encodeValue(parseTypeNoErr(t, "bool[]", nil), []interface{}{})
	require.NoError(t, err)
	require.Equal(t, []byte("\x00\x00\x00\x00"), encoded)
	encoded, err = encodeValue(parseTypeNoErr(t, "uint8[]", nil), []interface{}{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
	require.NoError(t, err)
	require.Equal(t, []byte("\x00\x00\x00\x0a"), encoded)
	encoded, err = encodeValue(parseTypeNoErr(t, "uint8[]", nil), make([]interface{}, 1000))
	require.NoError(t, err)
	require.Equal(t, []byte("\x00\x00\x03\xe8"), encoded)
}

func TestSimulatorETHPub(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()
		chainID := uint64(1)
		xpub, err := device.ETHPub(
			chainID,
			[]uint32{
				44 + hardenedKeyStart,
				60 + hardenedKeyStart,
				0 + hardenedKeyStart,
				0,
			},
			messages.ETHPubRequest_XPUB,
			false,
			nil,
		)
		require.NoError(t, err)
		require.Equal(t,
			"xpub6F2rrkQ947NAvxGQdZPcw1fMHdnJMxXCPtGKWdmf1aaumRkaCoJF72yFYhKRmkbat27bhDy79FWndkS3skRNLgbsuuJKqBoFyUcrp5ZgmC3",
			xpub,
		)

		address, err := device.ETHPub(
			chainID,
			[]uint32{
				44 + hardenedKeyStart,
				60 + hardenedKeyStart,
				0 + hardenedKeyStart,
				0,
				1,
			},
			messages.ETHPubRequest_ADDRESS,
			false,
			nil,
		)
		require.NoError(t, err)
		require.Equal(t,
			"0x6A2A567cB891DeF8eA8C215C85f93d2f0F844ceB",
			address,
		)
	})
}

func TestSimulatorETHSignMessage(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()
		chainID := uint64(1)
		keypath := []uint32{
			44 + hardenedKeyStart,
			60 + hardenedKeyStart,
			0 + hardenedKeyStart,
			0,
			10,
		}
		pubKey := simulatorPub(t, device, keypath...)

		sig, err := device.ETHSignMessage(
			chainID,
			keypath,
			[]byte("message"),
		)
		require.NoError(t, err)

		sigHash := hashKeccak([]byte("\x19Ethereum Signed Message:\n7message"))
		require.True(t, parseECDSASignature(t, sig[:64]).Verify(sigHash, pubKey))
	})
}

func TestSimulatorETHSignTypedMessage(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()
		msg := []byte(`
{
    "types": {
        "EIP712Domain": [
            { "name": "name", "type": "string" },
            { "name": "version", "type": "string" },
            { "name": "chainId", "type": "uint256" },
            { "name": "verifyingContract", "type": "address" }
        ],
        "Attachment": [
            { "name": "contents", "type": "string" }
        ],
        "Person": [
            { "name": "name", "type": "string" },
            { "name": "wallet", "type": "address" },
            { "name": "age", "type": "uint8" }
        ],
        "Mail": [
            { "name": "from", "type": "Person" },
            { "name": "to", "type": "Person" },
            { "name": "contents", "type": "string" },
            { "name": "attachments", "type": "Attachment[]" }
        ]
    },
    "primaryType": "Mail",
    "domain": {
        "name": "Ether Mail",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
    },
    "message": {
        "from": {
            "name": "Cow",
            "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
            "age": 20
        },
        "to": {
            "name": "Bob",
            "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
            "age": "0x1e"
        },
        "contents": "Hello, Bob!",
        "attachments": [{ "contents": "attachment1" }, { "contents": "attachment2" }]
    }
}`)

		sig, err := device.ETHSignTypedMessage(
			1,
			[]uint32{
				44 + hardenedKeyStart,
				60 + hardenedKeyStart,
				0 + hardenedKeyStart,
				0,
				10,
			},
			msg,
		)
		require.NoError(t, err)
		require.Len(t, sig, 65)
	})
}

func TestSimulatorETHSign(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()
		chainID := uint64(1)
		keypath := []uint32{
			44 + hardenedKeyStart,
			60 + hardenedKeyStart,
			0 + hardenedKeyStart,
			0,
			10,
		}
		nonce := uint64(8156)
		gasPrice := new(big.Int).SetUint64(6000000000)
		gasLimit := uint64(21000)
		recipient := [20]byte{0x04, 0xf2, 0x64, 0xcf, 0x34, 0x44, 0x03, 0x13, 0xb4, 0xa0,
			0x19, 0x2a, 0x35, 0x28, 0x14, 0xfb, 0xe9, 0x27, 0xb8, 0x85}
		value := new(big.Int).SetUint64(530564000000000000)

		sig, err := device.ETHSign(
			chainID,
			keypath,
			nonce,
			gasPrice,
			gasLimit,
			recipient,
			value,
			nil,
			messages.ETHAddressCase_ETH_ADDRESS_CASE_MIXED,
		)
		require.NoError(t, err)

		require.Len(t, sig, 65, "The signature should have exactly 65 bytes")
	})
}

func TestSimulatorETHSignEIP1559(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()
		chainID := uint64(1)
		keypath := []uint32{
			44 + hardenedKeyStart,
			60 + hardenedKeyStart,
			0 + hardenedKeyStart,
			0,
			10,
		}
		nonce := uint64(8156)
		maxPriorityFeePerGas := new(big.Int)
		maxFeePerGas := new(big.Int).SetUint64(6000000000)
		gasLimit := uint64(21000)
		recipient := [20]byte{0x04, 0xf2, 0x64, 0xcf, 0x34, 0x44, 0x03, 0x13, 0xb4, 0xa0,
			0x19, 0x2a, 0x35, 0x28, 0x14, 0xfb, 0xe9, 0x27, 0xb8, 0x85}
		value := new(big.Int).SetUint64(530564000000000000)

		sig, err := device.ETHSignEIP1559(
			chainID,
			keypath,
			nonce,
			maxPriorityFeePerGas,
			maxFeePerGas,
			gasLimit,
			recipient,
			value,
			nil,
			messages.ETHAddressCase_ETH_ADDRESS_CASE_MIXED,
		)
		require.NoError(t, err)

		require.Len(t, sig, 65, "The signature should have exactly 65 bytes")
	})
}
