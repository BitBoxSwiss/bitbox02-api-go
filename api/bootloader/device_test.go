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

package bootloader_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/digitalbitbox/bitbox02-api-go/api/bootloader"
	"github.com/digitalbitbox/bitbox02-api-go/api/common"
	"github.com/digitalbitbox/bitbox02-api-go/util/semver"
	"github.com/stretchr/testify/require"
)

type communicationMock struct {
	sendFrame func(msg string) error
	query     func([]byte) ([]byte, error)
	close     func()
}

func (communication *communicationMock) SendFrame(msg string) error {
	return communication.sendFrame(msg)
}

func (communication *communicationMock) Query(msg []byte) ([]byte, error) {
	return communication.query(msg)
}

func (communication *communicationMock) Close() {
	communication.close()
}

type testEnv struct {
	product         common.Product
	communication   *communicationMock
	onStatusChanged func(*bootloader.Status)
	device          *bootloader.Device
}

func testConfigurations(t *testing.T, run func(*testEnv, *testing.T)) {
	for _, product := range []common.Product{
		common.ProductBitBox02Multi,
		common.ProductBitBox02BTCOnly,
		common.ProductBitBoxBaseStandard,
	} {
		var env testEnv
		env.product = product
		env.communication = &communicationMock{}
		env.device = bootloader.NewDevice(
			semver.NewSemVer(1, 0, 1),
			env.product,
			env.communication,
			func(status *bootloader.Status) { env.onStatusChanged(status) },
		)
		t.Run(fmt.Sprintf("%v", env), func(t *testing.T) {
			run(&env, t)
		})
	}
}

func TestProduct(t *testing.T) {
	testConfigurations(t, func(env *testEnv, t *testing.T) {
		require.Equal(t, env.product, env.device.Product())
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
			testResponse := testResponse
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
			test := test
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

// TestSignedFirmwareVersion tests device.SignedFirmwareVersion.
func TestSignedFirmwareVersion(t *testing.T) {
	signedFirmware, err := ioutil.ReadFile("testdata/firmware-btc.v4.2.2.signed.bin")
	if err != nil {
		panic(err)
	}

	testConfigurations(t, func(env *testEnv, t *testing.T) {
		if env.product != common.ProductBitBox02BTCOnly {
			return
		}

		// Invalid firmware.
		_, err := env.device.SignedFirmwareVersion(nil)
		require.Error(t, err)

		// Valid firmware.
		version, err := env.device.SignedFirmwareVersion(signedFirmware)
		require.NoError(t, err)
		require.Equal(t, uint32(7), version)
	})
}

// TestUpgradeFirmware tests a successful firmware upgrade with a real-world signed firmware
// fixture.
func TestUpgradeFirmware(t *testing.T) {
	testConfigurations(t, func(env *testEnv, t *testing.T) {
		if env.product != common.ProductBitBox02BTCOnly {
			return
		}

		const chunkSize = 4096

		signedFirmware, err := ioutil.ReadFile("testdata/firmware-btc.v4.2.2.signed.bin")
		if err != nil {
			panic(err)
		}
		unsignedFirmware, err := ioutil.ReadFile("testdata/firmware-btc.v4.2.2.bin")
		if err != nil {
			panic(err)
		}
		const numChunks = 100
		const expectedSigData = "0000000027a8678099f9f52b142a0692b320d6053d3f7c637273a236654ce4e5346efaffb35034df24eca2e500bbd24b84ba79799d4d7ad5492516b5122587d41a63d9d7c2565124b98a5d9da8bfab7e566371c936b1435d7980d4c09bc31b84431c2e3c6b62829093f478be5356657aa525d6a5fc793acd2641f9bd2d3587dea6a33ad7c6789655ce072bf02908b5d795a87b6789cac63e98bf7849d740d47fb62f3fef88c6db3cb260c53302eb133a89b3529e2f8ae20e99ed0fe3d32cd30db880ffbc47be63edb71c681a3a0d45716746db7704c915d617fcf1c895ca949bb3adcc9a666c73dd373cdf9d4ccf9ff102bde32307f29ecdbf981b3553af7ba3509ff565000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003d8054281b0f6733469f58e0406cba24fefcea8704cd6e8d990bd98fa33d2b0a0942dcafc81f912216ca86cab2000b6de96f1567d5209ab6167278dc585b011d070000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000017a44e602e19792e468a110b997f74b4149a4aca55e98a8b94f219739886c0227f6267ff582f2c1293f71f5afcb5ba6065ebeb454aa142f389f2bb91da62e4281f557a14e9974a3df39c9451b88766c4de7d1fcb8173fcdef82e316e8a8fd4822947a103aeee373e7c687228fadbd5b7ae3032886da057d53338abd889bff301"

		var currentStatus bootloader.Status
		env.onStatusChanged = func(status *bootloader.Status) {
			require.Equal(t, env.device.Status(), status)
			currentStatus = *status
		}

		// We record all api messages (and status at the time) and check they are correct after.
		msgs := [][]byte{}
		statuses := []bootloader.Status{}
		env.communication.query = func(msg []byte) ([]byte, error) {
			msgs = append(msgs, msg)
			statuses = append(statuses, currentStatus)
			return []byte{msg[0], 0x00}, nil
		}
		env.communication.sendFrame = func(msg string) error {
			msgs = append(msgs, []byte(msg))
			statuses = append(statuses, currentStatus)
			return nil
		}

		const rebootSeconds = 5
		sleepCalls := 0
		env.device.TstSetSleep(func(d time.Duration) {
			require.Equal(t, time.Second, d)
			require.True(t, sleepCalls < rebootSeconds)
			require.True(t, currentStatus.UpgradeSuccessful)
			require.Equal(t, rebootSeconds-sleepCalls, currentStatus.RebootSeconds)
			sleepCalls++
		})

		require.Zero(t, *env.device.Status())
		require.NoError(t, env.device.UpgradeFirmware(signedFirmware))

		takeOne := func() ([]byte, bootloader.Status) {
			require.NotEmpty(t, msgs)
			require.NotEmpty(t, statuses)
			msg, status := msgs[0], statuses[0]
			msgs, statuses = msgs[1:], statuses[1:]
			return msg, status
		}
		reassembledFirmware := []byte{}

		msg, status := takeOne()
		require.True(t, status.Upgrading)
		require.Zero(t, status.Progress)

		// byte(d) is 100 => 100 chunks
		// erase and set progress bar to 100 chunks
		require.Equal(t, []byte("ed"), msg)

		// flash chunks
		for chunkIndex := 0; chunkIndex < numChunks; chunkIndex++ {
			msg, status = takeOne()

			require.True(t, status.Upgrading)
			require.Equal(t, float64(chunkIndex)/float64(numChunks), status.Progress)

			require.Len(t, msg, 2+chunkSize)
			opCode, index, chunk := msg[0], msg[1], msg[2:]
			require.Equal(t, byte('w'), opCode)
			require.Equal(t, byte(chunkIndex), index)
			reassembledFirmware = append(reassembledFirmware, chunk...)
		}
		require.Len(t, reassembledFirmware, numChunks*chunkSize)
		reassembledFirmware, _ = reassembledFirmware[:len(unsignedFirmware)], reassembledFirmware[len(unsignedFirmware):]
		require.True(t, bytes.Equal(reassembledFirmware, unsignedFirmware))

		// flash sigdata
		msg, status = takeOne()
		require.True(t, status.Upgrading)
		require.Equal(t, 1., status.Progress)
		require.Equal(t, byte('s'), msg[0])
		require.Equal(t, expectedSigData, hex.EncodeToString(msg[1:]))

		status = *env.device.Status()
		require.True(t, status.Upgrading)
		require.Equal(t, 0., status.Progress)
		require.True(t, status.UpgradeSuccessful)

		// reboot
		msg, status = takeOne()
		require.Equal(t, byte('r'), msg[0])
		require.Equal(t, 1, status.RebootSeconds)
	})
}

func TestErased(t *testing.T) {
	testConfigurations(t, func(env *testEnv, t *testing.T) {
		var versionResponse, hashesResponse []byte
		env.communication.query = func(msg []byte) ([]byte, error) {
			switch msg[0] {
			case byte('v'):
				return versionResponse, nil
			case byte('h'):
				return hashesResponse, nil
			default:
				return nil, errors.New("unexpected query")
			}
		}

		versionResponse = []byte("invalid")
		hashesResponse = []byte("h\x00\x92\xb6\x23\x1a\x13\x8c\xca\xf2\xd2\x1b\x63\xc2\x0a\x0c\x4b\x12\x97\x8c\x9d\x26\x8b\xf5\x61\x74\x4a\x95\xf5\x9f\x22\xcd\xf0\xce\x0e\xd3\x47\xc8\x4e\x91\x1e\xe7\x72\x3c\xf3\xe0\x89\x91\x5a\x0b\xfa\x4b\x4c\x69\xe0\xb1\x71\xdf\xb2\xa3\x8a\xea\x86\xea\x74\xe7")
		_, err := env.device.Erased()
		require.Error(t, err)

		versionResponse = []byte("v\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
		hashesResponse = []byte("invalid")
		_, err = env.device.Erased()
		require.Error(t, err)

		// Not erased fixtures.
		versionResponse = []byte("v\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
		hashesResponse = []byte("h\x00\x92\xb6\x23\x1a\x13\x8c\xca\xf2\xd2\x1b\x63\xc2\x0a\x0c\x4b\x12\x97\x8c\x9d\x26\x8b\xf5\x61\x74\x4a\x95\xf5\x9f\x22\xcd\xf0\xce\x0e\xd3\x47\xc8\x4e\x91\x1e\xe7\x72\x3c\xf3\xe0\x89\x91\x5a\x0b\xfa\x4b\x4c\x69\xe0\xb1\x71\xdf\xb2\xa3\x8a\xea\x86\xea\x74\xe7")
		erased, err := env.device.Erased()
		require.NoError(t, err)
		require.False(t, erased)

		// Erased fixtures.
		versionResponse = []byte("v\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
		hashesResponse = []byte("h\x00\xad\x27\x67\x91\x84\x74\xf3\x30\x02\x95\xb2\xef\x94\x9a\xe8\x13\xd7\x87\x0c\xed\x70\x30\x58\x29\xa0\x12\x91\xa4\x8f\x8b\xbc\x78\x0e\xd3\x47\xc8\x4e\x91\x1e\xe7\x72\x3c\xf3\xe0\x89\x91\x5a\x0b\xfa\x4b\x4c\x69\xe0\xb1\x71\xdf\xb2\xa3\x8a\xea\x86\xea\x74\xe7")
		erased, err = env.device.Erased()
		require.NoError(t, err)
		require.True(t, erased)
	})
}
