// Copyright 2022 Shift Crypto AG
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

	"github.com/digitalbitbox/bitbox02-api-go/api/firmware/messages"
	"github.com/stretchr/testify/require"
)

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
