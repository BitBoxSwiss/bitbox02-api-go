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

// Package main is a playground for devs to interact with a live device.
package main

import (
	"log"

	"github.com/digitalbitbox/bitbox02-api-go/api/common"
	"github.com/digitalbitbox/bitbox02-api-go/api/firmware"
	"github.com/digitalbitbox/bitbox02-api-go/api/firmware/messages"
	"github.com/digitalbitbox/bitbox02-api-go/api/firmware/mocks"
	"github.com/digitalbitbox/bitbox02-api-go/communication/u2fhid"
	"github.com/karalabe/usb"
)

const (
	bitbox02VendorID  = 0x03eb
	bitbox02ProductID = 0x2403
)

func errpanic(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func isBitBox02(deviceInfo usb.DeviceInfo) bool {
	return (deviceInfo.Product == common.FirmwareHIDProductStringStandard ||
		deviceInfo.Product == common.FirmwareHIDProductStringBTCOnly) &&
		deviceInfo.VendorID == bitbox02VendorID &&
		deviceInfo.ProductID == bitbox02ProductID &&
		(deviceInfo.UsagePage == 0xffff || deviceInfo.Interface == 0)
}

func main() {
	deviceInfo := func() usb.DeviceInfo {
		infos, err := usb.EnumerateHid(0, 0)
		errpanic(err)
		for _, di := range infos {
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

	const bitboxCMD = 0x80 + 0x40 + 0x01
	comm := u2fhid.NewCommunication(hidDevice, bitboxCMD)
	device := firmware.NewDevice(nil, nil, &mocks.Config{}, comm, &mocks.Logger{})
	device.Init()
	device.ChannelHashVerify(true)
	const HARDENED = 0x80000000
	keypathAccount := []uint32{48 + HARDENED, 0 + HARDENED, 0 + HARDENED, 2 + HARDENED}
	coin := messages.BTCCoin_BTC
	ourXPub, err := device.BTCXPub(
		coin,
		keypathAccount,
		messages.BTCPubRequest_XPUB,
		false,
	)
	errpanic(err)
	scriptConfig, err := firmware.NewBTCScriptConfigMultisig(
		1,
		[]string{
			ourXPub,
			"xpub6FEZ9Bv73h1vnE4TJG4QFj2RPXJhhsPbnXgFyH3ErLvpcZrDcynY65bhWga8PazWHLSLi23PoBhGcLcYW6JRiJ12zXZ9Aop4LbAqsS3gtcy",
		},
		0, // ourXPubIndex,
	)
	errpanic(err)
	device.BTCAddress(coin, append(keypathAccount, 0, 0), scriptConfig, true)
}
