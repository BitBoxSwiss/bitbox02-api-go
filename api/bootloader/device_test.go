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

// Package bootloader contains the API to the physical device.
package bootloader_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/digitalbitbox/bitbox02-api-go/api/bootloader"
	"github.com/digitalbitbox/bitbox02-api-go/api/common"
	"github.com/digitalbitbox/bitbox02-api-go/util/semver"
	"github.com/stretchr/testify/require"
)

type communicationMock struct {
	query func([]byte) ([]byte, error)
	close func()
}

func (communication *communicationMock) SendFrame(msg string) error {
	panic("TODO")
}

func (communication *communicationMock) Query(msg []byte) ([]byte, error) {
	return communication.query(msg)
}

func (communication *communicationMock) Close() {
	communication.close()
}

type testEnv struct {
	edition       common.Edition
	communication *communicationMock
	device        *bootloader.Device
	currentStatus *bootloader.Status
}

func testConfigurations(t *testing.T, run func(*testEnv, *testing.T)) {
	for _, edition := range []common.Edition{
		common.EditionStandard,
		common.EditionBTCOnly,
	} {
		var env testEnv
		env.edition = edition
		env.communication = &communicationMock{}
		env.currentStatus = nil
		env.device = bootloader.NewDevice(
			semver.NewSemVer(1, 0, 1),
			env.edition,
			env.communication,
			func(status *bootloader.Status) {
				env.currentStatus = status
			},
		)
		t.Run(fmt.Sprintf("%v", env), func(t *testing.T) {
			run(&env, t)
		})
	}
}

func TestEdition(t *testing.T) {
	testConfigurations(t, func(env *testEnv, t *testing.T) {
		require.Equal(t, env.edition, env.device.Edition())
	})

}

func TestClose(t *testing.T) {
	testConfigurations(t, func(env *testEnv, t *testing.T) {
		called := false
		env.communication.close = func() {
			called = true
		}
		env.device.Close()
		require.True(t, called)
	})
}

func TestVersions(t *testing.T) {
	testConfigurations(t, func(env *testEnv, t *testing.T) {
		t.Run("happy", func(t *testing.T) {
			env.communication.query = func(msg []byte) ([]byte, error) {
				require.Equal(t, []byte("v"), msg)
				// little endian 323213
				firmwareVersion := "\x8d\xee\x04\x00"
				// little endian 7654
				signingPubkeysVersion := "\xe6\x1d\x00\x00"
				return []byte("v\x00" + firmwareVersion + signingPubkeysVersion), nil
			}
			firmwareVersion, signingPubkeysVersion, err := env.device.Versions()
			require.NoError(t, err)
			require.Equal(t, uint32(323213), firmwareVersion)
			require.Equal(t, uint32(7654), signingPubkeysVersion)
		})

		// error response
		expectedErr := errors.New("fail")
		env.communication.query = func(msg []byte) ([]byte, error) {
			return nil, expectedErr
		}
		_, _, err := env.device.Versions()
		require.Equal(t, expectedErr, err)

		for _, testResponse := range []string{
			"",
			"v\x00",         // too short
			"a\x00aaaaaaaa", // wrong cmd
			"x\x00aaaaaaaa", // wrong cmd, good len
			"v\x01aaaaaaaa", // wrong op status
		} {
			env.communication.query = func([]byte) ([]byte, error) {
				return []byte(testResponse), nil
			}
			_, _, err := env.device.Versions()
			require.Error(t, err)
		}
	})
}

func TestGetHashes(t *testing.T) {
	testConfigurations(t, func(env *testEnv, t *testing.T) {
		for _, test := range []struct {
			param1      bool
			param2      bool
			expectedMsg string
		}{
			{false, false, "h\x00\x00"},
			{false, true, "h\x00\x01"},
			{true, false, "h\x01\x00"},
			{true, true, "h\x01\x01"},
		} {
			t.Run("happy", func(t *testing.T) {
				h1 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				h2 := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
				env.communication.query = func(msg []byte) ([]byte, error) {
					require.Equal(t, []byte(test.expectedMsg), msg)
					return []byte("h\x00" + h1 + h2), nil
				}
				firmwareHash, signingKeyDatahash, err := env.device.GetHashes(
					test.param1, test.param2)
				require.NoError(t, err)
				require.Equal(t, []byte(h1), firmwareHash)
				require.Equal(t, []byte(h2), signingKeyDatahash)
			})

			// error response
			expectedErr := errors.New("fail")
			env.communication.query = func(msg []byte) ([]byte, error) {
				return nil, expectedErr
			}
			_, _, err := env.device.GetHashes(false, false)
			require.Equal(t, expectedErr, err)

			// response too short
			env.communication.query = func(msg []byte) ([]byte, error) {
				return []byte("h\x00"), nil
			}
			_, _, err = env.device.GetHashes(false, false)
			require.Error(t, err)
		}
	})
}
