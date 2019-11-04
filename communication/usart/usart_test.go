// Copyright 2018-2019 Shift Cryptosecurity AG
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

package usart_test

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"
	"testing/quick"

	"github.com/digitalbitbox/bitbox02-api-go/communication/usart"
	"github.com/stretchr/testify/require"
)

func mustDecodeHex(str string) []byte {
	decoded, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	return decoded
}

var tests = []struct {
	cmd     byte
	decoded string
	encoded string
}{
	{0xc3, "76", "7e01c37677c37e"},
	{0xc3, "680000", "7e01c368000069c37e"},
	{0xc3, "6542", "7e01c3654267057e"},
}

type deviceMock struct {
	io.Writer
	io.Reader
}

func (device *deviceMock) Close() error {
	return nil
}

// TestReadWrite encodes random data and checks that decoding is the inverse of encoding.
func TestReadWrite(t *testing.T) {
	f := func(cmd byte, data, prefix, suffix []byte) bool {
		writer := new(bytes.Buffer)
		err := usart.NewCommunication(
			&deviceMock{Writer: writer},
			cmd,
		).SendFrame(data)
		if err != nil {
			return false
		}
		encoded := writer.Bytes()
		// All frames start with 0x7e
		require.Equal(t, byte(0x7e), encoded[0])
		// Version (currently 0x01) is always the second byte.
		require.Equal(t, byte(0x01), encoded[1])

		reader := new(bytes.Buffer)
		// Any garbage data before the marker is skipped over
		reader.Write(bytes.ReplaceAll(prefix, []byte{0x7e}, nil))
		reader.Write(encoded)
		// Decoding until the marker, even if there is more data available.
		reader.Write(suffix)
		read, err := usart.NewCommunication(
			&deviceMock{
				Reader: bytes.NewReader(reader.Bytes()),
			},
			cmd,
		).ReadFrame()
		if err != nil {
			return false
		}
		return bytes.Equal(data, read)
	}
	require.NoError(t, quick.Check(f, nil))
}

func TestWrite(t *testing.T) {
	for _, test := range tests {
		test := test
		t.Run("", func(t *testing.T) {
			buf := new(bytes.Buffer)
			err := usart.NewCommunication(
				&deviceMock{Writer: buf},
				test.cmd,
			).SendFrame(mustDecodeHex(test.decoded))
			require.NoError(t, err)
			require.Equal(t, test.encoded, hex.EncodeToString(buf.Bytes()))
		})
	}
}

func TestRead(t *testing.T) {
	for _, test := range tests {
		test := test
		t.Run("", func(t *testing.T) {
			communication := usart.NewCommunication(
				&deviceMock{
					Reader: bytes.NewReader(mustDecodeHex(test.encoded)),
				},
				test.cmd,
			)
			read, err := communication.ReadFrame()
			require.NoError(t, err)
			require.Equal(t, test.decoded, hex.EncodeToString(read))
		})
	}
}
