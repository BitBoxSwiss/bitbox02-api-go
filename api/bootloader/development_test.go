// SPDX-License-Identifier: Apache-2.0

package bootloader_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"testing"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/bootloader"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/common"
	"github.com/BitBoxSwiss/bitbox02-api-go/util/semver"
	"github.com/stretchr/testify/require"
)

// Extending OP_VERSIONS must preserve the old counters and tolerate future trailing fields.
func TestVersionsStage0(t *testing.T) {
	legacy := binary.LittleEndian.AppendUint32([]byte{'v', 0}, 56)
	legacy = binary.LittleEndian.AppendUint32(legacy, 4)
	for _, test := range []struct {
		name   string
		tail   []byte
		stage0 uint16
	}{
		{"legacy", nil, 0},
		{"unknown", []byte{0, 0}, 0},
		{"stage0-v3", []byte{3, 0}, 3},
		{"future", []byte{0x34, 0x12, 7, 8}, 0x1234},
	} {
		t.Run(test.name, func(t *testing.T) {
			communication := &communicationMock{query: func(msg []byte) ([]byte, error) {
				require.Equal(t, []byte{'v'}, msg)
				return append(bytes.Clone(legacy), test.tail...), nil
			}}
			device := bootloader.NewDevice(semver.NewSemVer(1, 2, 4), common.ProductBitBox02Multi, communication, nil)
			info, err := device.Versions()
			require.NoError(t, err)
			require.Equal(t, uint32(56), info.FirmwareVersion)
			require.Equal(t, uint32(4), info.SigningPubkeysVersion)
			if test.stage0 == 0 {
				require.Nil(t, info.Stage0Version)
			} else {
				require.NotNil(t, info.Stage0Version)
				require.Equal(t, test.stage0, *info.Stage0Version)
			}
		})
	}
	for _, length := range []int{0, 1, 7, 9} {
		communication := &communicationMock{query: func([]byte) ([]byte, error) {
			return append([]byte{'v', 0}, make([]byte, length)...), nil
		}}
		device := bootloader.NewDevice(semver.NewSemVer(1, 2, 4), common.ProductBitBox02Multi, communication, nil)
		_, err := device.Versions()
		require.Error(t, err)
	}
}

// Unsigned uploads must omit signature writes and must never be offered to production devices.
func TestUpgradeUnsignedFirmware(t *testing.T) {
	for _, development := range []bool{false, true} {
		firmware := bytes.Repeat([]byte{0x42}, 4097)
		var commands []byte
		var written []byte
		communication := &communicationMock{
			query: func(msg []byte) ([]byte, error) {
				commands = append(commands, msg[0])
				switch msg[0] {
				case 'e':
					require.Equal(t, []byte{'e', 2}, msg)
				case 'w':
					require.Equal(t, byte(len(written)/4096), msg[1])
					written = append(written, msg[2:]...)
				default:
					t.Fatalf("unexpected command %q", msg[0])
				}
				return []byte{msg[0], 0}, nil
			},
			sendFrame: func(msg string) error {
				commands = append(commands, msg...)
				return nil
			},
		}
		device := bootloader.NewDevice(semver.NewSemVer(1, 2, 2), common.ProductBitBox02Multi,
			communication, func(*bootloader.Status) {}, bootloader.WithDevelopment(development))
		err := device.UpgradeUnsignedFirmware(firmware)
		if !development {
			require.Error(t, err)
			require.Empty(t, commands)
			continue
		}
		require.NoError(t, err)
		require.Equal(t, []byte("ewwr"), commands)
		require.Equal(t, firmware, written[:len(firmware)])
		require.Equal(t, bytes.Repeat([]byte{0xff}, 8192-len(firmware)), written[len(firmware):])
		require.True(t, device.Status().UpgradeSuccessful)
		require.Error(t, device.UpgradeUnsignedFirmware(firmware))
	}
}

// A failed write must prevent reboot; retrying must clear the previous error status.
func TestUpgradeUnsignedFirmwareFailure(t *testing.T) {
	fail := true
	communication := &communicationMock{query: func(msg []byte) ([]byte, error) {
		if fail {
			return nil, errors.New("write failed")
		}
		return []byte{msg[0], 0}, nil
	}, sendFrame: func(string) error {
		require.False(t, fail)
		return nil
	}}
	device := bootloader.NewDevice(semver.NewSemVer(1, 2, 4), common.ProductBitBox02Multi,
		communication, func(*bootloader.Status) {}, bootloader.WithDevelopment(true))
	require.Error(t, device.UpgradeUnsignedFirmware(nil))
	require.Error(t, device.UpgradeUnsignedFirmware(make([]byte, 884737)))
	require.Error(t, device.UpgradeUnsignedFirmware([]byte{1}))
	require.False(t, device.Status().Upgrading)
	require.False(t, device.Status().UpgradeSuccessful)
	fail = false
	require.NoError(t, device.UpgradeUnsignedFirmware([]byte{1}))
	require.Empty(t, device.Status().ErrMsg)
}

// Development devices must still report signature failures for regular signed releases.
func TestDevelopmentSignedFirmwareFailure(t *testing.T) {
	firmware, err := os.ReadFile("testdata/firmware-btc.v4.2.2.signed.bin")
	require.NoError(t, err)
	communication := &communicationMock{query: func(msg []byte) ([]byte, error) {
		if msg[0] == 's' {
			return []byte{'s', 1}, nil
		}
		return []byte{msg[0], 0}, nil
	}, sendFrame: func(string) error {
		t.Fatal("must not reboot after a failed signature check")
		return nil
	}}
	device := bootloader.NewDevice(semver.NewSemVer(1, 2, 4), common.ProductBitBox02BTCOnly,
		communication, func(*bootloader.Status) {}, bootloader.WithDevelopment(true))
	require.Error(t, device.UpgradeFirmware(firmware))
	require.False(t, device.Status().Upgrading)
	require.False(t, device.Status().UpgradeSuccessful)
}

// The stored counter remains 56 while the bootloader's hash scheme changes.
func TestContainsFirmware(t *testing.T) {
	firmware, err := os.ReadFile("testdata/firmware-btc.v4.2.2.bin")
	require.NoError(t, err)
	for _, test := range []struct {
		version *semver.SemVer
		hash    string
	}{
		{semver.NewSemVer(1, 0, 0), "c130ffbcfffbb47be8780300b0476c91795f5e1d815dfe4c91db2edbec53d322"},
		{semver.NewSemVer(1, 2, 2), "f90cd5f1b068322cc157ec3a3d855089f868c2343ccc2fe81153054dfc8d5ac8"},
		{semver.NewSemVer(1, 2, 4), "a69c75696c16fc75002224264647c4e10ec31c9aef8c188ce5e4f43e8a207511"},
	} {
		t.Run(test.version.String(), func(t *testing.T) {
			hash, err := hex.DecodeString(test.hash)
			require.NoError(t, err)
			communication := &communicationMock{query: func(msg []byte) ([]byte, error) {
				switch msg[0] {
				case 'v':
					return []byte{'v', 0, 56, 0, 0, 0, 4, 0, 0, 0}, nil
				case 'h':
					require.Equal(t, []byte{'h', 0, 0}, msg)
					return append(append([]byte{'h', 0}, hash...), make([]byte, 32)...), nil
				default:
					return nil, errors.New("unexpected command")
				}
			}}
			device := bootloader.NewDevice(test.version, common.ProductBitBox02Multi, communication, nil)
			matches, err := device.ContainsFirmware(firmware)
			require.NoError(t, err)
			require.True(t, matches)
			matches, err = device.ContainsFirmware([]byte("different firmware"))
			require.NoError(t, err)
			require.False(t, matches)
		})
	}
}
