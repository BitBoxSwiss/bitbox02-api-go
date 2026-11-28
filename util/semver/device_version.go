// SPDX-License-Identifier: Apache-2.0

package semver

import (
	"regexp"
	"strings"

	"github.com/BitBoxSwiss/bitbox02-api-go/util/errp"
)

var deviceVersionPattern = regexp.MustCompile(`v([0-9]+\.[0-9]+\.[0-9]+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)

// ParseDeviceVersion parses a device version, including legacy prefixes, and reports whether an
// exact "dev" identifier occurs in its prerelease or build metadata. The returned version is numeric.
func ParseDeviceVersion(raw string) (*SemVer, bool, error) {
	match := deviceVersionPattern.FindStringSubmatch(raw)
	if match == nil {
		return nil, false, errp.Newf("invalid device version: %q", raw)
	}
	development := false
	for _, metadata := range match[2:] {
		for _, identifier := range strings.Split(metadata, ".") {
			if identifier == "dev" {
				development = true
			}
		}
	}
	version, err := NewSemVerFromString(match[1])
	return version, development, err
}
