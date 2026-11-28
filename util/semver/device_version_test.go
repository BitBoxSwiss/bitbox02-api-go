// SPDX-License-Identifier: Apache-2.0

package semver_test

import (
	"testing"

	"github.com/BitBoxSwiss/bitbox02-api-go/util/semver"
	"github.com/stretchr/testify/require"
)

// Development markers must match Python and must not match substrings in other identifiers.
func TestParseDeviceVersion(t *testing.T) {
	for _, test := range []struct {
		raw         string
		version     string
		development bool
	}{
		{"v7.1.0", "7.1.0", false},
		{"bb02:v9.0.0", "9.0.0", false},
		{"v9.28.0", "9.28.0", false},
		{"v9.28.0-pre+abc123", "9.28.0", false},
		{"v9.28.0-pre+abc123.dev", "9.28.0", true},
		{"bb02.bl:v1.0.0-dev", "1.0.0", true},
		{"v1.2.4+dev", "1.2.4", true},
		{"v1.2.4+dev.abc123", "1.2.4", true},
		{"v1.2.4-dev+abc123", "1.2.4", true},
		{"v1.2.4-pre+git.123.dev", "1.2.4", true},
		{"v1.2.4-alpha.dev+git.123", "1.2.4", true},
		{"v1.2.4", "1.2.4", false},
		{"v1.2.4+git.123", "1.2.4", false},
		{"v1.2.4+device", "1.2.4", false},
		{"v1.2.4-development", "1.2.4", false},
		{"v1.2.4+notdev", "1.2.4", false},
		{"v1.2.4-pre-dev", "1.2.4", false},
		{"v1.2.4+DEV", "1.2.4", false},
		{"dev:v1.2.4", "1.2.4", false},
		{"v1.2.4-01", "1.2.4", false},
	} {
		t.Run(test.raw, func(t *testing.T) {
			version, development, err := semver.ParseDeviceVersion(test.raw)
			require.NoError(t, err)
			require.Equal(t, test.version, version.String())
			require.Equal(t, test.development, development)
		})
	}
	for _, raw := range []string{"", "1.2.4", "v1.2", "v1.a.4", "v1.2.4+", "v1.2.4-dev!", "v1.2.4+dev..abc"} {
		t.Run(raw, func(t *testing.T) {
			_, _, err := semver.ParseDeviceVersion(raw)
			require.Error(t, err)
		})
	}
}

// The captured numeric version must use the shared parser's behavior, including its errors.
func TestParseDeviceVersionNumericVersion(t *testing.T) {
	for _, numeric := range []string{"1.2.4", "01.02.004", "65536.0.0", "999999999999999999999999.0.0"} {
		t.Run(numeric, func(t *testing.T) {
			expected, expectedErr := semver.NewSemVerFromString(numeric)
			version, development, err := semver.ParseDeviceVersion("bb02.bl:v" + numeric + "-pre+abc.dev")
			if expectedErr != nil {
				require.Error(t, err)
				require.Nil(t, version)
				return
			}
			require.NoError(t, err)
			require.Equal(t, expected, version)
			require.True(t, development)
		})
	}
}
