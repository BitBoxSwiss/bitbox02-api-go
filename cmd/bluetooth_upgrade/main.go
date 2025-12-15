// SPDX-License-Identifier: Apache-2.0

// Package main is a playground to play with the BitBox02 miniscript support.
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/common"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/mocks"
	"github.com/BitBoxSwiss/bitbox02-api-go/communication/u2fhid"
	"github.com/BitBoxSwiss/bitbox02-api-go/communication/u2fhid/hiddevice"
	"github.com/karalabe/hid"
)

const (
	bitbox02VendorID  = 0x03eb
	bitbox02ProductID = 0x2403
	bitboxCMD         = 0x80 + 0x40 + 0x01

	HARDENED = 0x80000000
)

func errpanic(err error) {
	if err != nil {
		log.Fatalf("%+v", err)
	}
}

func isBitBox02(deviceInfo *hid.DeviceInfo) bool {
	return (deviceInfo.Product == common.FirmwareDeviceProductStringBitBox02Multi ||
		deviceInfo.Product == common.FirmwareDeviceProductStringBitBox02BTCOnly ||
		deviceInfo.Product == common.FirmwareDeviceProductStringBitBox02PlusMulti ||
		deviceInfo.Product == common.FirmwareDeviceProductStringBitBox02PlusBTCOnly) &&
		deviceInfo.VendorID == bitbox02VendorID &&
		deviceInfo.ProductID == bitbox02ProductID &&
		(deviceInfo.UsagePage == 0xffff || deviceInfo.Interface == 0)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage:", os.Args[0], "filename")
		os.Exit(1)
	}
	filename := os.Args[1]

	firmwareBytes, err := os.ReadFile(filename)
	errpanic(err)

	deviceInfo := func() *hid.DeviceInfo {
		infos, err := hid.Enumerate(0, 0)
		errpanic(err)
		for idx := range infos {
			di := &infos[idx]
			if di.Serial == "" || di.Product == "" {
				continue
			}
			if isBitBox02(di) {
				return di
			}
		}
		panic("could no find a bitbox02")

	}()

	hidDevice, err := deviceInfo.Open()
	errpanic(err)

	comm := u2fhid.NewCommunication(hiddevice.New(hidDevice), bitboxCMD)
	device := firmware.NewDevice(nil, nil, &mocks.Config{}, comm, &mocks.Logger{})
	errpanic(device.Init())
	device.ChannelHashVerify(true)

	errpanic(device.BluetoothUpgrade(firmwareBytes))
}
