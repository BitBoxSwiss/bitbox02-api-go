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
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHashFirmware(t *testing.T) {
	emptyHash := []byte("\xad\x27\x67\x91\x84\x74\xf3\x30\x02\x95\xb2\xef\x94\x9a\xe8\x13\xd7\x87\x0c\xed\x70\x30\x58\x29\xa0\x12\x91\xa4\x8f\x8b\xbc\x78")
	require.Equal(t, emptyHash, HashFirmware(5, []byte{}))

	unsignedFirmware, err := ioutil.ReadFile("testdata/firmware-btc.v4.2.2.bin")
	require.NoError(t, err)
	require.Equal(t,
		[]byte("\x9a\xfc\x65\xa1\x99\x6c\x0d\xfd\xbb\x17\x08\xbf\x51\x8d\x96\x8c\xde\xc7\xe3\xc3\x52\x56\x1e\x2b\x09\x1d\x91\x83\x6c\x06\x8a\xe5"),
		HashFirmware(7, unsignedFirmware),
	)
}
