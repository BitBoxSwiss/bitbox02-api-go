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

// Package firmware contains the API to the physical device.
package firmware

import (
	"github.com/digitalbitbox/bitbox02-api-go/api/common"
	"github.com/digitalbitbox/bitbox02-api-go/util/semver"
)

// TstLowestNonSupportedFirmwareVersion exposes lowestNonSupportedFirmwareVersion to tests.
var TstLowestNonSupportedFirmwareVersion = lowestNonSupportedFirmwareVersion

// TstLowestSupportedFirmwareVersions exposes the minimum versions per product to tests.
var TstLowestSupportedFirmwareVersions = map[common.Product]*semver.SemVer{
	common.ProductBitBox02Multi:      lowestSupportedFirmwareVersion,
	common.ProductBitBox02BTCOnly:    lowestSupportedFirmwareVersionBTCOnly,
	common.ProductBitBoxBaseStandard: lowestSupportedFirmwareVersionBitBoxBaseStandard,
}
