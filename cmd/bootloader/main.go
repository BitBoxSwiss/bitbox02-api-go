// Copyright 2025 Shift Crypto AG
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

// Package main is a playground for devs to interact with a live device.
package main

import (
	"fmt"
	"log"
	"regexp"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/bootloader"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/common"
	"github.com/BitBoxSwiss/bitbox02-api-go/communication/u2fhid"
	"github.com/BitBoxSwiss/bitbox02-api-go/util/errp"
	"github.com/BitBoxSwiss/bitbox02-api-go/util/semver"
	"github.com/karalabe/hid"
)

const (
	bitbox02VendorID  = 0x03eb
	bitbox02ProductID = 0x2403

	HARDENED = 0x80000000
)

func errpanic(err error) {
	if err != nil {
		log.Fatalf("%+v", err)
	}
}

func isBitBox02Bootloader(deviceInfo *hid.DeviceInfo) bool {
	return (deviceInfo.Product == common.BootloaderDeviceProductStringBitBox02Multi ||
		deviceInfo.Product == common.BootloaderDeviceProductStringBitBox02BTCOnly ||
		deviceInfo.Product == common.BootloaderDeviceProductStringBitBox02PlusMulti ||
		deviceInfo.Product == common.BootloaderDeviceProductStringBitBox02PlusBTCOnly) &&
		deviceInfo.VendorID == bitbox02VendorID &&
		deviceInfo.ProductID == bitbox02ProductID &&
		(deviceInfo.UsagePage == 0xffff || deviceInfo.Interface == 0)
}

func parseVersion(serial string) (*semver.SemVer, error) {
	match := regexp.MustCompile(`v([0-9]+\.[0-9]+\.[0-9]+)`).FindStringSubmatch(serial)
	if len(match) != 2 {
		return nil, errp.Newf("Could not find the version in '%s'.", serial)
	}
	version, err := semver.NewSemVerFromString(match[1])
	if err != nil {
		return nil, err
	}
	return version, err
}

func main() {
	deviceInfo := func() *hid.DeviceInfo {
		infos, err := hid.Enumerate(0, 0)
		errpanic(err)
		for idx := range infos {
			di := &infos[idx]
			if di.Serial == "" || di.Product == "" {
				continue
			}
			if isBitBox02Bootloader(di) {
				return di
			}
		}
		panic("could no find a bitbox02")

	}()

	hidDevice, err := deviceInfo.Open()
	errpanic(err)
	const bitbox02BootloaderCMD = 0x80 + 0x40 + 0x03
	comm := u2fhid.NewCommunication(u2fhid.NewHidDevice(hidDevice), bitbox02BootloaderCMD)
	version, err := parseVersion(deviceInfo.Serial)
	errpanic(err)
	product, err := common.ProductFromDeviceProductString(deviceInfo.Product)
	errpanic(err)
	device := bootloader.NewDevice(version, product, comm, func(*bootloader.Status) {})
	firmwareVersion, signingPubkeysVersion, err := device.Versions()
	errpanic(err)
	fmt.Println("Firmware monotonic version:", firmwareVersion)
	fmt.Println("Signing pubkeys monotonic version:", signingPubkeysVersion)
	fmt.Println("Product:", device.Product())
	hardware, err := device.Hardware()
	errpanic(err)
	fmt.Printf("Hardware: %+v\n", hardware)
}
