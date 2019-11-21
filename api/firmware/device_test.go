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

package firmware_test

import (
	"crypto/rand"
	"errors"
	"fmt"
	"testing"

	"github.com/digitalbitbox/bitbox02-api-go/api/common"
	"github.com/digitalbitbox/bitbox02-api-go/api/firmware"
	"github.com/digitalbitbox/bitbox02-api-go/api/firmware/messages"
	"github.com/digitalbitbox/bitbox02-api-go/util/semver"
	"github.com/flynn/noise"
	"github.com/golang/protobuf/proto"
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

type configMock struct{}

func (config *configMock) ContainsDeviceStaticPubkey(pubkey []byte) bool {
	return false
}
func (config *configMock) AddDeviceStaticPubkey(pubkey []byte) error {
	return nil
}
func (config *configMock) GetAppNoiseStaticKeypair() *noise.DHKey {
	return nil
}
func (config *configMock) SetAppNoiseStaticKeypair(key *noise.DHKey) error {
	return nil
}

type loggerMock struct{}

func (logger *loggerMock) Error(msg string, err error) {
}
func (logger *loggerMock) Info(msg string) {
}
func (logger *loggerMock) Debug(msg string) {
}

// newDevice creates a device to test with, with init/pairing already processed.
func newDevice(
	t *testing.T,
	version *semver.SemVer,
	product common.Product,
	communication *communicationMock,
	onRequest func(*messages.Request) *messages.Response,
) *firmware.Device {

	device := firmware.NewDevice(
		version,
		&product,
		&configMock{}, communication, &loggerMock{},
	)

	cipherSuite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	keypair, err := cipherSuite.GenerateKeypair(rand.Reader)
	require.NoError(t, err)

	handshake, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeXX,
		StaticKeypair: keypair,
		Prologue:      []byte("Noise_XX_25519_ChaChaPoly_SHA256"),
		Initiator:     false,
	})
	require.NoError(t, err)
	var sendCipher, receiveCipher *noise.CipherState
	shakingHands := false

	var handleRequest func(request *messages.Request) *messages.Response
	communication.query = func(msg []byte) ([]byte, error) {
		if shakingHands {
			var err error
			_, receiveCipher, sendCipher, err = handshake.ReadMessage(nil, msg)
			require.NoError(t, err)
			require.Equal(t, sendCipher == nil, receiveCipher == nil)
			if sendCipher != nil { // handshake done
				shakingHands = false
				return []byte{0}, nil // 0 = do not require pairing verification
			}
			msgSend, _, _, err := handshake.WriteMessage(nil, nil)
			require.NoError(t, err)
			return msgSend, nil
		}

		switch msg[0] {
		case byte('a'): // OP_ATTESTATION
			return make([]byte, 1+32+64+64+32+64), nil
		case byte('u'): // OP_UNLOCK
			return []byte{0x02}, nil // OP_STATUS_FAILURE_UNINITIALIZED
		case byte('h'): // OP_I_CAN_HAS_HANDSHAKE
			shakingHands = true
			return []byte{0x00}, nil // OP_STATUS_SUCCESS
		case byte('v'): // OP_I_CAN_HAS_PAIRIN_VERIFICASHUN
			// confirm pairing
			return []byte{0x00}, nil // OP_STATUS_SUCCESS
		case byte('n'): // OP_NOISE_MSG
			decrypted, err := receiveCipher.Decrypt(nil, nil, msg[1:])
			require.NoError(t, err)

			request := &messages.Request{}
			require.NoError(t, proto.Unmarshal(decrypted, request))

			require.NotNil(t, request)
			response := handleRequest(request)

			responseBytes, err := proto.Marshal(response)
			require.NoError(t, err)
			return sendCipher.Encrypt(nil, nil, responseBytes), nil
		}
		require.Fail(t, "unexpected opcode")
		return nil, nil
	}
	require.NoError(t, device.Init())

	// ChannelHashVerify calls DeviceInfo() to figure out if the device is initialized or not.
	handleRequest = func(request *messages.Request) *messages.Response {
		_, ok := request.Request.(*messages.Request_DeviceInfo)
		require.True(t, ok)
		return &messages.Response{
			Response: &messages.Response_DeviceInfo{
				DeviceInfo: &messages.DeviceInfoResponse{
					Initialized: false,
				},
			},
		}
	}
	device.ChannelHashVerify(true)

	handleRequest = onRequest
	return device
}

var responseSuccess = &messages.Response{
	Response: &messages.Response_Success{
		Success: &messages.Success{},
	},
}

type testEnv struct {
	version       *semver.SemVer
	product       common.Product
	communication *communicationMock
	device        *firmware.Device
	onRequest     func(*messages.Request) *messages.Response
}

func testConfigurations(t *testing.T, run func(*testEnv, *testing.T)) {
	versions := []*semver.SemVer{
		semver.NewSemVer(4, 2, 0),
		semver.NewSemVer(4, 3, 0),
	}
	products := []common.Product{
		common.ProductBitBox02Multi,
		common.ProductBitBox02BTCOnly,
		common.ProductBitBoxBaseStandard,
	}
	for _, version := range versions {
		for _, product := range products {
			var env testEnv
			env.version = version
			env.product = product
			env.communication = &communicationMock{}

			env.device = newDevice(
				t,
				env.version,
				product,
				env.communication,
				func(request *messages.Request) *messages.Response { return env.onRequest(request) },
			)
			t.Run(fmt.Sprintf("%v", env), func(t *testing.T) {
				run(&env, t)
			})
		}
	}
}

func TestVersion(t *testing.T) {
	testConfigurations(t, func(env *testEnv, t *testing.T) {
		require.Equal(t, env.version, env.device.Version())
	})
}

func TestClose(t *testing.T) {
	testConfigurations(t, func(env *testEnv, t *testing.T) {
		called := false
		env.communication.close = func() { called = true }
		env.device.Close()
		require.True(t, called)
	})
}

func TestRandom(t *testing.T) {
	testConfigurations(t, func(env *testEnv, t *testing.T) {
		expected := []byte{1, 2, 3}
		env.onRequest = func(request *messages.Request) *messages.Response {
			_, ok := request.Request.(*messages.Request_RandomNumber)
			require.True(t, ok)
			return &messages.Response{
				Response: &messages.Response_RandomNumber{
					RandomNumber: &messages.RandomNumberResponse{
						Number: expected,
					},
				},
			}
		}
		random, err := env.device.Random()
		require.NoError(t, err)
		require.Equal(t, expected, random)

		// Wrong response.
		env.onRequest = func(request *messages.Request) *messages.Response {
			return responseSuccess
		}
		_, err = env.device.Random()
		require.Error(t, err)

		// Query error.
		expectedErr := errors.New("error")
		env.communication.query = func(msg []byte) ([]byte, error) {
			return nil, expectedErr
		}
		_, err = env.device.Random()
		require.Equal(t, expectedErr, err)
	})
}

func TestSetDeviceName(t *testing.T) {
	testConfigurations(t, func(env *testEnv, t *testing.T) {
		// Name too long.
		require.Error(t, env.device.SetDeviceName(
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))

		expected := "Satoshi"
		env.onRequest = func(request *messages.Request) *messages.Response {
			setDeviceName, ok := request.Request.(*messages.Request_DeviceName)
			require.True(t, ok)
			require.Equal(t, expected, setDeviceName.DeviceName.Name)
			return responseSuccess
		}
		require.NoError(t, env.device.SetDeviceName(expected))

		// Wrong response.
		env.onRequest = func(request *messages.Request) *messages.Response {
			return &messages.Response{
				Response: &messages.Response_RandomNumber{
					RandomNumber: &messages.RandomNumberResponse{},
				},
			}
		}
		require.Error(t, env.device.SetDeviceName(expected))

		// Query error.
		expectedErr := errors.New("error")
		env.communication.query = func(msg []byte) ([]byte, error) {
			return nil, expectedErr
		}
		require.Equal(t, expectedErr, env.device.SetDeviceName(expected))
	})
}
