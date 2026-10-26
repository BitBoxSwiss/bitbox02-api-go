// SPDX-License-Identifier: Apache-2.0

package firmware

import (
	"fmt"
	"testing"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/common"
	"github.com/BitBoxSwiss/bitbox02-api-go/util/semver"
	"github.com/stretchr/testify/require"
)

func TestSimulatorDeviceLanguage(t *testing.T) {
	testSimulatorsAfterPairing(t, func(t *testing.T, device *Device, stdOut *simulatorStdout) {
		t.Helper()
		info, err := device.DeviceInfo()
		require.NoError(t, err)
		if len(info.SupportedLanguages) == 0 {
			require.Empty(t, info.Language)
			t.Skip("simulator does not support device languages")
		}
		require.Equal(t, "en", info.Language)
		require.Contains(t, info.SupportedLanguages, "en")
		require.Contains(t, info.SupportedLanguages, "de")
		supportedLanguages := info.SupportedLanguages

		for _, language := range []string{"de", "en"} {
			require.NoError(t, device.SetDeviceLanguage(language))
			info, err = device.DeviceInfo()
			require.NoError(t, err)
			require.Equal(t, language, info.Language)
			require.Equal(t, supportedLanguages, info.SupportedLanguages)

			err = device.SetDeviceLanguage("invalid")
			require.True(t, isErrorCode(err, ErrInvalidInput), "unexpected error: %v", err)
			info, err = device.DeviceInfo()
			require.NoError(t, err)
			require.Equal(t, language, info.Language)
			require.Equal(t, supportedLanguages, info.SupportedLanguages)
		}
	})
}

func TestSimulatorDeviceName(t *testing.T) {
	testSimulatorsAfterPairing(t, func(t *testing.T, device *Device, stdOut *simulatorStdout) {
		t.Helper()
		info, err := device.DeviceInfo()
		require.NoError(t, err)
		switch device.Product() {
		case common.ProductBitBox02PlusMulti, common.ProductBitBox02PlusBTCOnly:
			require.Equal(t, "BitBox HCXT", info.Name)
		default:
			require.Equal(t, "My BitBox", info.Name)
		}

		// Name too long.
		require.Error(t, device.SetDeviceName(
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))

		require.NoError(t, device.SetDeviceName("new name"))
		info, err = device.DeviceInfo()
		require.NoError(t, err)
		require.Equal(t, "new name", info.Name)
	})
}

func TestSimulatorSetPassword(t *testing.T) {
	for _, seedLen := range []int{16, 32} {
		t.Run(fmt.Sprintf("seedLen=%d", seedLen), func(t *testing.T) {
			testSimulatorsAfterPairing(t, func(t *testing.T, device *Device, stdOut *simulatorStdout) {
				t.Helper()
				require.NoError(t, device.SetPassword(seedLen))
				require.Equal(t, StatusSeeded, device.Status())
			})
		})
	}
}

func TestSimulatorChangePassword(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *simulatorStdout) {
		t.Helper()
		err := device.ChangePassword()
		if device.Version().AtLeast(semver.NewSemVer(9, 25, 0)) {
			require.NoError(t, err)
			// Status should remain StatusInitialized
			require.Equal(t, StatusInitialized, device.Status())
		} else {
			// Old firmware versions don't support ChangePassword
			require.EqualError(t, err, UnsupportedError("9.25.0").Error())
		}
	})
}
