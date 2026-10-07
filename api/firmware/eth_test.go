// SPDX-License-Identifier: Apache-2.0

package firmware

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/common"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/mocks"
	"github.com/BitBoxSwiss/bitbox02-api-go/util/semver"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func hashKeccak(b []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	return h.Sum(nil)
}

var eip712Msg = []byte(`
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

func parseTypeNoErr(t *testing.T, typ string, types map[string][]ethTypedMessageMember) *messages.ETHSignTypedMessageRequest_MemberType {
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
		parseTypeNoErr(t, ethTypedMessageStringType, nil),
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
		parseTypeNoErr(t, "Person", map[string][]ethTypedMessageMember{"Person": {}}),
	)

	_, err = parseType("string]", nil)
	require.Error(t, err)
}

func TestParseTypedMessageRejectsMalformedStructure(t *testing.T) {
	for _, jsonMsg := range []string{
		`{}`,
		`{"types":[],"primaryType":"Message","domain":{},"message":{}}`,
		`{"types":{"EIP712Domain":null},"primaryType":"EIP712Domain","domain":{},"message":{}}`,
		`{"types":{"EIP712Domain":[]},"domain":{},"message":{}}`,
		`{"types":{"EIP712Domain":[]},"primaryType":null,"domain":{},"message":{}}`,
		`{"types":{"EIP712Domain":[{"type":"string"}]},"primaryType":"EIP712Domain","domain":{},"message":{}}`,
		`{"types":{"EIP712Domain":[{"name":null,"type":"string"}]},"primaryType":"EIP712Domain","domain":{},"message":{}}`,
		`{"types":{"EIP712Domain":[null]},"primaryType":"EIP712Domain","domain":{},"message":{}}`,
		`{"types":{"EIP712Domain":[{"name":"name"}]},"primaryType":"EIP712Domain","domain":{},"message":{}}`,
	} {
		_, _, err := parseTypedMessage([]byte(jsonMsg))
		require.Error(t, err)
	}
}

func TestParseTypedMessageUsesExactFieldNames(t *testing.T) {
	msg, _, err := parseTypedMessage([]byte(`{
		"types": {
			"EIP712Domain": [],
			"Message": [{
				"name": "value",
				"Name": "wrongName",
				"type": "string",
				"Type": "bytes"
			}]
		},
		"Types": {"Broken": null},
		"primaryType": "Message",
		"PrimaryType": "Wrong",
		"domain": {"name": "expected"},
		"Domain": {"name": "wrong"},
		"message": {"value": "expected"},
		"Message": {"value": "wrong"}
	}`))
	require.NoError(t, err)
	require.Equal(t, "Message", msg.PrimaryType)
	require.Equal(t, map[string]interface{}{"name": "expected"}, msg.Domain)
	require.Equal(t, map[string]interface{}{"value": "expected"}, msg.Message)
	require.Equal(t,
		[]ethTypedMessageMember{{Name: "value", Type: ethTypedMessageStringType}},
		msg.Types["Message"],
	)
	require.NotContains(t, msg.Types, "Broken")
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
	require.Equal(t, []byte("\x00\xb1\xd8\x4b\x7c"), encoded)

	encoded, err = encodeValue(parseTypeNoErr(t, "int64", nil), float64(-2983742332))
	require.NoError(t, err)
	require.Equal(t, []byte("\xff\x4e\x27\xb4\x84"), encoded)

	encoded, err = encodeValue(parseTypeNoErr(t, ethTypedMessageStringType, nil), "foo")
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

	for _, test := range []struct {
		typ   string
		value interface{}
	}{
		{"bytes", true}, {"bool", "true"}, {ethTypedMessageStringType, true}, {"string[]", true},
	} {
		_, err := encodeValue(parseTypeNoErr(t, test.typ, nil), test.value)
		require.Error(t, err, test.typ)
	}
}

func TestEncodeValueSignedIntegers(t *testing.T) {
	for _, test := range []struct {
		value int64
		hex   string
	}{
		{0, "00"}, {1, "01"}, {-1, "ff"},
		{127, "7f"}, {128, "0080"}, {129, "0081"},
		{-127, "81"}, {-128, "80"}, {-129, "ff7f"},
		{255, "00ff"}, {256, "0100"}, {-255, "ff01"}, {-256, "ff00"},
		{32767, "7fff"}, {32768, "008000"},
		{-32768, "8000"}, {-32769, "ff7fff"},
		{65535, "00ffff"}, {65536, "010000"},
	} {
		decimal := big.NewInt(test.value).String()
		t.Run(decimal, func(t *testing.T) {
			for _, input := range []interface{}{decimal, float64(test.value)} {
				encoded, err := encodeValue(parseTypeNoErr(t, "int64", nil), input)
				require.NoError(t, err)
				require.Equal(t, test.hex, fmt.Sprintf("%x", encoded))
			}
		})
	}
}

func TestBigendianIntSignedWidths(t *testing.T) {
	for size := 1; size <= 32; size++ {
		limit := new(big.Int).Lsh(big.NewInt(1), uint(8*size-1))
		maximum := new(big.Int).Sub(limit, big.NewInt(1))
		minimum := new(big.Int).Neg(limit)
		for _, value := range []*big.Int{minimum, maximum} {
			original := new(big.Int).Set(value)
			encoded := bigendianInt(value)
			require.Len(t, encoded, size)
			decoded := new(big.Int).SetBytes(encoded)
			if encoded[0]&0x80 != 0 {
				decoded.Sub(decoded, new(big.Int).Lsh(big.NewInt(1), uint(8*size)))
			}
			require.Zero(t, decoded.Cmp(value))
			require.Zero(t, original.Cmp(value), "encoding must not mutate its input")
		}
	}
}

func TestHandleETHDataStreamingOutOfBounds(t *testing.T) {
	device := &Device{}
	_, err := device.nonAtomicHandleETHDataStreaming(
		[]byte("hello"),
		&messages.ETHResponse{
			Response: &messages.ETHResponse_DataRequestChunk{
				DataRequestChunk: &messages.ETHSignDataRequestChunkResponse{
					Offset: 4,
					Length: 2,
				},
			},
		},
	)
	require.EqualError(t, err, "unexpected response")
}

func TestGetValueReturnsType(t *testing.T) {
	msg, _, err := parseTypedMessage([]byte(`
{
	"types": {
		"EIP712Domain": [{ "name": "name", "type": "string" }],
		"Mail": [
			{ "name": "contents", "type": "string" },
			{ "name": "payload", "type": "bytes" }
		]
	},
	"primaryType": "Mail",
	"domain": { "name": "Test" },
	"message": {
		"contents": "hello",
		"payload": "0xaabb"
	}
}`))
	require.NoError(t, err)

	value, dataType, err := getValue(&messages.ETHTypedMessageValueResponse{
		RootObject: messages.ETHTypedMessageValueResponse_DOMAIN,
		Path:       []uint32{0},
	}, msg)
	require.NoError(t, err)
	require.Equal(t, []byte("Test"), value)
	require.Equal(t, messages.ETHSignTypedMessageRequest_STRING, dataType)

	value, dataType, err = getValue(&messages.ETHTypedMessageValueResponse{
		RootObject: messages.ETHTypedMessageValueResponse_MESSAGE,
		Path:       []uint32{1},
	}, msg)
	require.NoError(t, err)
	require.Equal(t, []byte{0xaa, 0xbb}, value)
	require.Equal(t, messages.ETHSignTypedMessageRequest_BYTES, dataType)
}

func TestGetValueRejectsMalformedValues(t *testing.T) {
	msg, _, err := parseTypedMessage(eip712Msg)
	require.NoError(t, err)

	getErr := func(root messages.ETHTypedMessageValueResponse_RootObject, path ...uint32) error {
		_, _, err := getValue(&messages.ETHTypedMessageValueResponse{RootObject: root, Path: path}, msg)
		return err
	}

	msg.Message["from"] = []interface{}{}
	require.ErrorContains(t, getErr(messages.ETHTypedMessageValueResponse_MESSAGE, 0, 0), "expected struct value to be an object")
	require.ErrorContains(t, getErr(messages.ETHTypedMessageValueResponse_MESSAGE, 99), "struct member index out of bounds")

	delete(msg.Domain, "chainId")
	require.ErrorContains(t, getErr(messages.ETHTypedMessageValueResponse_DOMAIN, 2), `typed data value "chainId" is missing`)

	msg.Domain["name"] = float64(1)
	require.ErrorContains(t, getErr(messages.ETHTypedMessageValueResponse_DOMAIN, 0), "expected string value")

	msg.Message["attachments"] = map[string]interface{}{}
	require.ErrorContains(t, getErr(messages.ETHTypedMessageValueResponse_MESSAGE, 3, 0), "expected array value")

	msg.Message["attachments"] = []interface{}{}
	require.ErrorContains(t, getErr(messages.ETHTypedMessageValueResponse_MESSAGE, 3, 0), "array index out of bounds")
}

func TestETHSignTypedMessageRejectsLargeString(t *testing.T) {
	communication := &mocks.Communication{}
	device := newDevice(
		t,
		semver.NewSemVer(9, 26, 0),
		common.ProductBitBox02Multi,
		communication,
		func(request *messages.Request) *messages.Response {
			ethRequest, ok := request.Request.(*messages.Request_Eth)
			require.True(t, ok)

			switch ethRequest.Eth.Request.(type) {
			case *messages.ETHRequest_SignTypedMsg:
				return &messages.Response{
					Response: &messages.Response_Eth{
						Eth: &messages.ETHResponse{
							Response: &messages.ETHResponse_TypedMsgValue{
								TypedMsgValue: &messages.ETHTypedMessageValueResponse{
									RootObject: messages.ETHTypedMessageValueResponse_MESSAGE,
									Path:       []uint32{0},
								},
							},
						},
					},
				}
			default:
				t.Fatal("unexpected follow-up request")
				return nil
			}
		},
	)

	_, err := device.ETHSignTypedMessage(
		1,
		[]uint32{44 + hardenedKeyStart, 60 + hardenedKeyStart, hardenedKeyStart, 0, 10},
		[]byte(`{
			"types": {
				"EIP712Domain": [{ "name": "name", "type": "string" }],
				"Msg": [{ "name": "text", "type": "string" }]
			},
			"primaryType": "Msg",
			"domain": { "name": "Test" },
			"message": { "text": "`+string(bytes.Repeat([]byte("a"), ethStreamingThreshold+1))+`" }
		}`),
		false,
	)
	require.EqualError(t, err, "string value exceeds maximum size")
}

func TestSimulatorETHPub(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *simulatorStdout) {
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
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *simulatorStdout) {
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
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *simulatorStdout) {
		t.Helper()
		sig, err := device.ETHSignTypedMessage(
			1,
			[]uint32{
				44 + hardenedKeyStart,
				60 + hardenedKeyStart,
				0 + hardenedKeyStart,
				0,
				10,
			},
			eip712Msg,
			true,
		)
		require.NoError(t, err)
		require.Len(t, sig, 65)
	})
}

func TestSimulatorETHSignTypedMessageSignedIntegers(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *simulatorStdout) {
		t.Helper()
		keypath := []uint32{44 + hardenedKeyStart, 60 + hardenedKeyStart, hardenedKeyStart, 0, 10}
		pubKey := simulatorPub(t, device, keypath...)
		sig, err := device.ETHSignTypedMessage(1, keypath, []byte(`{
			"types": {
				"EIP712Domain": [{"name": "name", "type": "string"}],
				"SignedIntegers": [
					{"name": "positive", "type": "int16"},
					{"name": "negative", "type": "int8"},
					{"name": "zero", "type": "int8"}
				]
			},
			"primaryType": "SignedIntegers",
			"domain": {"name": "Signed integers"},
			"message": {"positive": 128, "negative": -128, "zero": 0}
		}`), true)
		require.NoError(t, err)
		require.Len(t, sig, 65)

		// Compute the EIP-712 digest independently of the wire encoder. The device
		// must sign +128, -128 and zero, not reinterpret or reject their sign bytes.
		domainHash := hashKeccak(bytes.Join([][]byte{
			hashKeccak([]byte("EIP712Domain(string name)")),
			hashKeccak([]byte("Signed integers")),
		}, nil))
		messageHash := hashKeccak(bytes.Join([][]byte{
			hashKeccak([]byte("SignedIntegers(int16 positive,int8 negative,int8 zero)")),
			append(make([]byte, 31), 0x80),
			append(bytes.Repeat([]byte{0xff}, 31), 0x80),
			make([]byte, 32),
		}, nil))
		digest := hashKeccak(bytes.Join([][]byte{{0x19, 0x01}, domainHash, messageHash}, nil))
		require.True(t, parseECDSASignature(t, sig[:64]).Verify(digest, pubKey))
	})
}

func TestSimulatorETHSignTypedMessageAntikleptoEnabled(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *simulatorStdout) {
		t.Helper()
		keypath := []uint32{
			44 + hardenedKeyStart,
			60 + hardenedKeyStart,
			0 + hardenedKeyStart,
			0,
			10,
		}

		sig1, err := device.ETHSignTypedMessage(1, keypath, eip712Msg, true)
		require.NoError(t, err)
		sig2, err := device.ETHSignTypedMessage(1, keypath, eip712Msg, true)
		require.NoError(t, err)

		require.Len(t, sig1, 65)
		require.Len(t, sig2, 65)
		require.NotEqual(t, sig1, sig2)
	})
}

func TestSimulatorETHSignTypedMessageAntikleptoDisabled(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *simulatorStdout) {
		t.Helper()
		keypath := []uint32{
			44 + hardenedKeyStart,
			60 + hardenedKeyStart,
			0 + hardenedKeyStart,
			0,
			10,
		}

		if device.Version().AtLeast(semver.NewSemVer(9, 26, 0)) {
			sig1, err := device.ETHSignTypedMessage(1, keypath, eip712Msg, false)
			require.NoError(t, err)
			sig2, err := device.ETHSignTypedMessage(1, keypath, eip712Msg, false)
			require.NoError(t, err)

			require.Len(t, sig1, 65)
			require.Len(t, sig2, 65)
			require.Equal(t, sig1, sig2)
			return
		}

		_, err := device.ETHSignTypedMessage(1, keypath, eip712Msg, false)
		require.EqualError(t, err, UnsupportedError("9.26.0").Error())
	})
}

func TestSimulatorETHSign(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *simulatorStdout) {
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

func TestSimulatorETHSignStreaming(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *simulatorStdout) {
		t.Helper()
		if !device.Version().AtLeast(semver.NewSemVer(9, 26, 0)) {
			t.Skip("requires firmware >= 9.26.0")
		}

		sig, err := device.ETHSign(
			1,
			[]uint32{
				44 + hardenedKeyStart,
				60 + hardenedKeyStart,
				0 + hardenedKeyStart,
				0,
				10,
			},
			8156,
			new(big.Int).SetUint64(6000000000),
			21000,
			[20]byte{0x04, 0xf2, 0x64, 0xcf, 0x34, 0x44, 0x03, 0x13, 0xb4, 0xa0,
				0x19, 0x2a, 0x35, 0x28, 0x14, 0xfb, 0xe9, 0x27, 0xb8, 0x85},
			new(big.Int).SetUint64(530564000000000000),
			bytes.Repeat([]byte{0xab}, 10000),
			messages.ETHAddressCase_ETH_ADDRESS_CASE_MIXED,
		)
		require.NoError(t, err)
		require.Len(t, sig, 65)
	})
}

func TestSimulatorETHSignEIP1559(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *simulatorStdout) {
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
			nil,
		)
		require.NoError(t, err)

		require.Len(t, sig, 65, "The signature should have exactly 65 bytes")
	})
}

func TestSimulatorETHSignEIP1559Streaming(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *simulatorStdout) {
		t.Helper()
		if !device.Version().AtLeast(semver.NewSemVer(9, 26, 0)) {
			t.Skip("requires firmware >= 9.26.0")
		}

		sig, err := device.ETHSignEIP1559(
			1,
			[]uint32{
				44 + hardenedKeyStart,
				60 + hardenedKeyStart,
				0 + hardenedKeyStart,
				0,
				10,
			},
			8156,
			new(big.Int),
			new(big.Int).SetUint64(6000000000),
			21000,
			[20]byte{0x04, 0xf2, 0x64, 0xcf, 0x34, 0x44, 0x03, 0x13, 0xb4, 0xa0,
				0x19, 0x2a, 0x35, 0x28, 0x14, 0xfb, 0xe9, 0x27, 0xb8, 0x85},
			new(big.Int).SetUint64(530564000000000000),
			bytes.Repeat([]byte{0xcd}, 10000),
			messages.ETHAddressCase_ETH_ADDRESS_CASE_MIXED,
			nil,
		)
		require.NoError(t, err)
		require.Len(t, sig, 65)
	})
}

func TestSimulatorETHSignTypedMessageStreamingBytes(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *simulatorStdout) {
		t.Helper()

		sig, err := device.ETHSignTypedMessage(
			1,
			[]uint32{
				44 + hardenedKeyStart,
				60 + hardenedKeyStart,
				0 + hardenedKeyStart,
				0,
				10,
			},
			[]byte(`{
				"types": {
					"EIP712Domain": [{ "name": "name", "type": "string" }],
					"Msg": [{ "name": "data", "type": "bytes" }]
				},
				"primaryType": "Msg",
				"domain": { "name": "Test" },
				"message": { "data": "0x`+string(bytes.Repeat([]byte("aa"), 10000))+`" }
			}`),
			false,
		)

		if !device.Version().AtLeast(semver.NewSemVer(9, 26, 0)) {
			require.EqualError(t, err, UnsupportedError("9.26.0").Error())
			return
		}

		require.NoError(t, err)
		require.Len(t, sig, 65)
	})
}
