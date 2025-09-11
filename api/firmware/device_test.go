// Copyright 2018-2019 Shift Cryptosecurity AG
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

package firmware

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/common"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/mocks"
	"github.com/BitBoxSwiss/bitbox02-api-go/communication/u2fhid"
	"github.com/BitBoxSwiss/bitbox02-api-go/util/errp"
	"github.com/BitBoxSwiss/bitbox02-api-go/util/semver"
	"github.com/flynn/noise"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func runSimulator(filename string) (func() error, *Device, *bytes.Buffer, error) {
	cmd := exec.Command("stdbuf", "-oL", filename)

	// Create pipe before starting process
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, nil, err
	}

	var stdoutBuf bytes.Buffer
	scanner := bufio.NewScanner(stdout)
	go func() {
		for scanner.Scan() {
			stdoutBuf.Write(scanner.Bytes())
			stdoutBuf.WriteByte('\n')
		}
	}()

	var conn net.Conn
	for range 200 {
		conn, err = net.Dial("tcp", "localhost:15423")
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	const bitboxCMD = 0x80 + 0x40 + 0x01

	communication := u2fhid.NewCommunication(conn, bitboxCMD)
	device := NewDevice(nil, nil,
		&mocks.Config{}, communication, &mocks.Logger{},
	)
	return func() error {
		if err := conn.Close(); err != nil {
			return err
		}
		return cmd.Process.Kill()
	}, device, &stdoutBuf, nil
}

// Download BitBox simulators based on testdata/simulators.json to testdata/simulators/*.
// Skips the download if the file already exists and has the corect hash.
func downloadSimulators() ([]string, error) {
	type simulator struct {
		URL    string `json:"url"`
		Sha256 string `json:"sha256"`
	}
	data, err := os.ReadFile("./testdata/simulators.json")
	if err != nil {
		return nil, err
	}
	var simulators []simulator
	if err := json.Unmarshal(data, &simulators); err != nil {
		return nil, err
	}

	hashesMatch := func(file *os.File, expectedHash string) (bool, error) {
		hasher := sha256.New()
		if _, err := io.Copy(hasher, file); err != nil {
			return false, err
		}
		actualHash := hex.EncodeToString(hasher.Sum(nil))
		return actualHash == expectedHash, nil
	}

	fileNotExistOrHashMismatch := func(filename, expectedHash string) (bool, error) {
		file, err := os.Open(filename)
		if os.IsNotExist(err) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		defer file.Close()

		match, err := hashesMatch(file, expectedHash)
		if err != nil {
			return false, err
		}
		return !match, nil
	}

	downloadFile := func(url, filename string) error {
		resp, err := http.Get(url)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("bad status: %s", resp.Status)
		}

		// Create the file
		out, err := os.Create(filename)
		if err != nil {
			return err
		}
		defer out.Close()

		_, err = io.Copy(out, resp.Body)
		return err
	}
	filenames := []string{}
	for _, simulator := range simulators {
		simUrl, err := url.Parse(simulator.URL)
		if err != nil {
			return nil, err
		}
		filename := filepath.Join("testdata", "simulators", path.Base(simUrl.Path))
		if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
			return nil, err
		}
		doDownload, err := fileNotExistOrHashMismatch(filename, simulator.Sha256)
		if err != nil {
			return nil, err
		}
		if doDownload {
			fmt.Printf("Downloading %s to %s\n", simulator.URL, filename)
			if err := downloadFile(simulator.URL, filename); err != nil {
				return nil, err
			}
			// If we downloaded the file, check again the hash.
			file, err := os.Open(filename)
			if err != nil {
				// This should never happen, as we just downloaded it
				return nil, err
			}
			match, err := hashesMatch(file, simulator.Sha256)
			if err != nil {
				return nil, err
			}
			if !match {
				return nil, errp.Newf("downloaded file %s does not match expected hash %s", filename, simulator.Sha256)
			}
			if err := os.Chmod(filename, 0755); err != nil {
				return nil, err
			}
		} else {
			fmt.Printf("Skipping download of %s, file already exists and has the correct hash\n", filename)
		}
		filenames = append(filenames, filename)
	}
	return filenames, nil
}

var downloadSimulatorsOnce = sync.OnceValues(downloadSimulators)

// Runs tests against a simulator which is not initialized (not paired, not seeded).
func testSimulators(t *testing.T, run func(*testing.T, *Device, *bytes.Buffer)) {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("Skipping simulator tests: not running on linux-amd64")
	}

	var simulatorFilenames []string
	envSimulator := os.Getenv("SIMULATOR")
	if envSimulator != "" {
		simulatorFilenames = []string{envSimulator}
	} else {
		var err error
		simulatorFilenames, err = downloadSimulatorsOnce()
		require.NoError(t, err)
	}

	for _, simulatorFilename := range simulatorFilenames {
		t.Run(filepath.Base(simulatorFilename), func(t *testing.T) {
			teardown, device, stdOut, err := runSimulator(simulatorFilename)
			require.NoError(t, err)
			defer func() { require.NoError(t, teardown()) }()
			run(t, device, stdOut)
		})
	}
}

// Runs tests against a simulator which is not initialized, but paired (not seeded).
func testSimulatorsAfterPairing(t *testing.T, run func(*testing.T, *Device, *bytes.Buffer)) {
	t.Helper()
	testSimulators(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()
		require.NoError(t, device.Init())
		device.ChannelHashVerify(true)
		run(t, device, stdOut)
	})
}

// Runs tests againt a simulator that is seeded with this mnemonic: boring mistake dish oyster truth
// pigeon viable emerge sort crash wire portion cannon couple enact box walk height pull today solid
// off enable tide
func testInitializedSimulators(t *testing.T, run func(*testing.T, *Device, *bytes.Buffer)) {
	t.Helper()
	testSimulatorsAfterPairing(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()
		require.NoError(t, device.RestoreFromMnemonic())
		run(t, device, stdOut)
	})
}

func TestSimulatorRootFingerprint(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()
		fp, err := device.RootFingerprint()
		require.NoError(t, err)
		require.Equal(t, "4c00739d", hex.EncodeToString(fp))
	})
}

// newDevice creates a device to test with, with init/pairing already processed.
func newDevice(
	t *testing.T,
	version *semver.SemVer,
	product common.Product,
	communication *mocks.Communication,
	onRequest func(*messages.Request) *messages.Response,
) *Device {
	t.Helper()

	device := NewDevice(
		version,
		&product,
		&mocks.Config{}, communication, &mocks.Logger{},
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

	// upgrades query with HWW_* framing for >=v7.0.0 versions
	v7_0_0Query := func(query func(msg []byte) ([]byte, error)) func(msg []byte) ([]byte, error) {
		if !version.AtLeast(semver.NewSemVer(7, 0, 0)) {
			return query
		}
		return func(msg []byte) ([]byte, error) {
			// TODO: modularize and unit test the full hww* arbitration / canceling.
			// 0x00 = HWW_REQ_NEW
			require.Equal(t, byte(0x00), msg[0])
			msg = msg[1:]

			response, err := query(msg)
			if err != nil {
				return nil, err
			}

			// prepend HWW_RSP_ACK
			response = append([]byte{0x00}, response...)
			return response, nil
		}
	}

	communication.MockQuery = v7_0_0Query(func(msg []byte) ([]byte, error) {
		if shakingHands {
			//nolint:misspell
			if version.AtLeast(semver.NewSemVer(7, 0, 0)) {
				// 'H' = OP_HER_COMEZ_TEH_HANDSHAEK
				require.Equal(t, byte('H'), msg[0])
				msg = msg[1:]
			}

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
			if version.AtLeast(semver.NewSemVer(7, 0, 0)) {
				// prepend OP_STATUS_SUCCESS
				msgSend = append([]byte{0x00}, msgSend...)
			}
			return msgSend, nil
		}

		handleProtobufMsg := func(msg []byte) []byte {
			decrypted, err := receiveCipher.Decrypt(nil, nil, msg)
			require.NoError(t, err)

			request := &messages.Request{}
			require.NoError(t, proto.Unmarshal(decrypted, request))

			require.NotNil(t, request)
			response := handleRequest(request)

			responseBytes, err := proto.Marshal(response)
			require.NoError(t, err)
			encrypted, err := sendCipher.Encrypt(nil, nil, responseBytes)
			require.NoError(t, err)
			if version.AtLeast(semver.NewSemVer(7, 0, 0)) {
				// prepend OP_STATUS_SUCCESS
				encrypted = append([]byte{0x00}, encrypted...)
			}
			return encrypted
		}

		switch msg[0] {
		case byte('a'): // OP_ATTESTATION
			if !version.AtLeast(semver.NewSemVer(2, 0, 0)) {
				break
			}
			return make([]byte, 1+32+64+64+32+64), nil
		case byte('u'): // OP_UNLOCK
			if !version.AtLeast(semver.NewSemVer(2, 0, 0)) {
				break
			}
			return []byte{0x02}, nil // OP_STATUS_FAILURE_UNINITIALIZED
		case byte('h'): // OP_I_CAN_HAS_HANDSHAKE
			shakingHands = true
			return []byte{0x00}, nil // OP_STATUS_SUCCESS
		case byte('v'): // OP_I_CAN_HAS_PAIRIN_VERIFICASHUN
			// confirm pairing
			return []byte{0x00}, nil // OP_STATUS_SUCCESS
		case byte('n'): // OP_NOISE_MSG
			if !version.AtLeast(semver.NewSemVer(4, 0, 0)) {
				break
			}
			return handleProtobufMsg(msg[1:]), nil
		}
		return handleProtobufMsg(msg), nil
	})

	require.NoError(t, device.Init())
	if version.AtLeast(lowestNonSupportedFirmwareVersion) {
		require.Equal(t, StatusRequireAppUpgrade, device.Status())
		return nil
	}

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

	{ // Test upgrade required and actual upgrade, which for the firmware only means to reboot into the bootloader.
		lowestSupported := map[common.Product]*semver.SemVer{
			common.ProductBitBox02Multi:       lowestSupportedFirmwareVersion,
			common.ProductBitBox02BTCOnly:     lowestSupportedFirmwareVersionBTCOnly,
			common.ProductBitBox02PlusMulti:   lowestSupportedFirmwareVersion,
			common.ProductBitBox02PlusBTCOnly: lowestSupportedFirmwareVersionBTCOnly,
		}
		lowestSupportedFirmwareVersion, ok := lowestSupported[product]
		require.True(t, ok)
		if !version.AtLeast(lowestSupportedFirmwareVersion) {
			require.Equal(t, StatusRequireFirmwareUpgrade, device.Status())

			// Test upgrade.
			// Expecting reboot command (with no response)
			called := false
			communication.MockQuery = v7_0_0Query(func(msg []byte) ([]byte, error) {
				called = true
				if version.AtLeast(semver.NewSemVer(4, 0, 0)) {
					require.Equal(t, "n", string(msg[:1]), version) // OP_NOISE
					msg = msg[1:]
				}

				decrypted, err := receiveCipher.Decrypt(nil, nil, msg)
				require.NoError(t, err)

				request := &messages.Request{}
				require.NoError(t, proto.Unmarshal(decrypted, request))

				require.NotNil(t, request)
				_, ok := request.Request.(*messages.Request_Reboot)
				require.True(t, ok)
				return msg[:1], nil
			})

			// Actually, before v4.0.0 there was no opNoise, so the encrypted reboot command could
			// by chance start with opUnlock or opAttestation, in which case those api endpoints
			// would be called instead, resulting in an error in UpgradeFirmware(). We do not test
			// this explicitly now, a re-try usually solves the issue for the user.
			require.NoError(t, device.UpgradeFirmware())
			require.True(t, called)
			return nil
		}
	}

	handleRequest = onRequest
	return device
}

var testDeviceResponseOK = &messages.Response{
	Response: &messages.Response_Success{
		Success: &messages.Success{},
	},
}

type testEnv struct {
	version       *semver.SemVer
	product       common.Product
	communication *mocks.Communication
	device        *Device
	onRequest     func(*messages.Request) *messages.Response
}

func testConfigurations(t *testing.T, run func(*testing.T, *testEnv)) {
	t.Helper()
	versions := []*semver.SemVer{
		semver.NewSemVer(1, 0, 0),
		semver.NewSemVer(2, 0, 0),
		semver.NewSemVer(3, 0, 0),
		semver.NewSemVer(4, 1, 0),
		semver.NewSemVer(4, 1, 1),
		semver.NewSemVer(4, 2, 0),
		semver.NewSemVer(4, 2, 1),
		semver.NewSemVer(4, 3, 0),
		semver.NewSemVer(5, 0, 0),
		semver.NewSemVer(6, 0, 0),
		semver.NewSemVer(7, 0, 0),
		semver.NewSemVer(8, 0, 0),
		semver.NewSemVer(9, 1, 0),
		semver.NewSemVer(9, 2, 0),
		semver.NewSemVer(9, 4, 0),
		semver.NewSemVer(9, 5, 0),
		lowestNonSupportedFirmwareVersion,
	}
	products := []common.Product{
		common.ProductBitBox02Multi,
		common.ProductBitBox02BTCOnly,
		common.ProductBitBox02PlusMulti,
		common.ProductBitBox02PlusBTCOnly,
	}
	for _, version := range versions {
		for _, product := range products {
			var env testEnv
			env.version = version
			env.product = product
			env.communication = &mocks.Communication{}

			env.device = newDevice(
				t,
				env.version,
				product,
				env.communication,
				func(request *messages.Request) *messages.Response { return env.onRequest(request) },
			)
			// Device could not be initialized (unit tests for this in `newDevice()`), so there is
			// nothing more to do.
			if env.device == nil {
				continue
			}
			t.Run(fmt.Sprintf("%v %s", env, env.version), func(t *testing.T) {
				run(t, &env)
			})
		}
	}
}

func TestVersion(t *testing.T) {
	testConfigurations(t, func(t *testing.T, env *testEnv) {
		t.Helper()
		require.Equal(t, env.version, env.device.Version())
	})
}

func TestSimulatorProduct(t *testing.T) {
	testSimulators(t, func(t *testing.T, device *Device, stdOut *bytes.Buffer) {
		t.Helper()
		require.NoError(t, device.Init())
		// Since v9.24.0, the simulator simulates a Nova device.
		if device.Version().AtLeast(semver.NewSemVer(9, 24, 0)) {
			require.Equal(t, common.ProductBitBox02PlusMulti, device.Product())
		} else {
			require.Equal(t, common.ProductBitBox02Multi, device.Product())
		}
	})
}

func TestProduct(t *testing.T) {
	testConfigurations(t, func(t *testing.T, env *testEnv) {
		t.Helper()
		require.Equal(t, env.product, env.device.Product())
	})
}

func TestClose(t *testing.T) {
	testConfigurations(t, func(t *testing.T, env *testEnv) {
		t.Helper()
		called := false
		env.communication.MockClose = func() { called = true }
		env.device.Close()
		require.True(t, called)
	})
}

func TestSetDeviceName(t *testing.T) {
	testConfigurations(t, func(t *testing.T, env *testEnv) {
		t.Helper()
		// Name too long.
		require.Error(t, env.device.SetDeviceName(
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))

		expected := "Satoshi"
		env.onRequest = func(request *messages.Request) *messages.Response {
			setDeviceName, ok := request.Request.(*messages.Request_DeviceName)
			require.True(t, ok)
			require.Equal(t, expected, setDeviceName.DeviceName.Name)
			return testDeviceResponseOK
		}
		require.NoError(t, env.device.SetDeviceName(expected))

		// Wrong response.
		env.onRequest = func(request *messages.Request) *messages.Response {
			return &messages.Response{
				Response: &messages.Response_DeviceInfo{
					DeviceInfo: &messages.DeviceInfoResponse{},
				},
			}
		}
		require.Error(t, env.device.SetDeviceName(expected))

		// Query error.
		expectedErr := errors.New("error")
		env.communication.MockQuery = func(msg []byte) ([]byte, error) {
			return nil, expectedErr
		}
		require.Equal(t, expectedErr, env.device.SetDeviceName(expected))
	})
}
