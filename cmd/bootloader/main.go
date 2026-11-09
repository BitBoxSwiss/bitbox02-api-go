// SPDX-License-Identifier: Apache-2.0

// Package main is a playground for devs to interact with a live device.
package main

import (
	"fmt"
	"log"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/bootloader"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/common"
	"github.com/BitBoxSwiss/bitbox02-api-go/communication/u2fhid"
	"github.com/BitBoxSwiss/bitbox02-api-go/communication/u2fhid/hiddevice"
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
	comm := u2fhid.NewCommunication(hiddevice.New(hidDevice), bitbox02BootloaderCMD)
	version, development, err := semver.ParseDeviceVersion(deviceInfo.Serial)
	errpanic(err)
	product, err := common.ProductFromDeviceProductString(deviceInfo.Product)
	errpanic(err)
	device := bootloader.NewDevice(version, product, comm, func(*bootloader.Status) {},
		bootloader.WithDevelopment(development))
	versions, err := device.Versions()
	errpanic(err)
	fmt.Println("Firmware monotonic version:", versions.FirmwareVersion)
	fmt.Println("Signing pubkeys monotonic version:", versions.SigningPubkeysVersion)
	fmt.Println("Product:", device.Product())
	hardware, err := device.Hardware()
	errpanic(err)
	fmt.Printf("Hardware: %+v\n", hardware)
}
