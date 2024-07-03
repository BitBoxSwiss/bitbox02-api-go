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

// Package main is a playground to play with the BitBox02 miniscript support.
package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/common"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/mocks"
	"github.com/BitBoxSwiss/bitbox02-api-go/communication/u2fhid"
	"github.com/karalabe/usb"
)

const (
	bitbox02VendorID  = 0x03eb
	bitbox02ProductID = 0x2403
	bitboxCMD         = 0x80 + 0x40 + 0x01

	HARDENED = 0x80000000
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func errpanic(err error) {
	if err != nil {
		log.Fatalf("%+v", err)
	}
}

func isBitBox02(deviceInfo *usb.DeviceInfo) bool {
	return (deviceInfo.Product == common.FirmwareHIDProductStringStandard ||
		deviceInfo.Product == common.FirmwareHIDProductStringBTCOnly) &&
		deviceInfo.VendorID == bitbox02VendorID &&
		deviceInfo.ProductID == bitbox02ProductID &&
		(deviceInfo.UsagePage == 0xffff || deviceInfo.Interface == 0)
}

func main() {
	deviceInfo := func() *usb.DeviceInfo {
		infos, err := usb.EnumerateHid(0, 0)
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

	comm := u2fhid.NewCommunication(hidDevice, bitboxCMD)
	device := firmware.NewDevice(nil, nil, &mocks.Config{}, comm, &mocks.Logger{})
	errpanic(device.Init())
	device.ChannelHashVerify(true)

	ourRootFingerprint, err := device.RootFingerprint()
	errpanic(err)
	fmt.Printf("Root fingerprint: %x\n", ourRootFingerprint)

	value := uint64(123456)
	paymentRequestIndex := uint32(0)

	// Manually created. To test with a real device, modify and compile/use a firmware where "Test
	// Merchant" (private key "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") is included in the identities in
	// payment_request.rs.
	paymentRequest := &messages.BTCPaymentRequestRequest{
		RecipientName: "Test Merchant",
		Memos: []*messages.BTCPaymentRequestRequest_Memo{
			{
				Memo: &messages.BTCPaymentRequestRequest_Memo_TextMemo_{
					TextMemo: &messages.BTCPaymentRequestRequest_Memo_TextMemo{
						Note: "TextMemo",
					},
				},
			},
		},
		Nonce:       nil,
		TotalAmount: value,
		Signature:   unhex("b719cf98cc8a0f9191d4be1a6609037b5b084674d8e64b13199408813459a1b3033ff58c6468b35acc4ded661c8e23348823887046c778e6eba2e5b9586b9a25"),
	}

	_, err = device.BTCSign(
		messages.BTCCoin_TBTC,
		[]*messages.BTCScriptConfigWithKeypath{
			{
				ScriptConfig: firmware.NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH),
				Keypath:      []uint32{84 + HARDENED, 1 + HARDENED, 0 + HARDENED},
			},
		},
		&firmware.BTCTx{
			Version: 2,
			Inputs: []*firmware.BTCTxInput{{
				Input: &messages.BTCSignInputRequest{
					PrevOutHash:       unhex("c58b7e3f1200e0c0ec9a5e81e925baface2cc1d4715514f2d8205be2508b48ee"),
					PrevOutIndex:      0,
					PrevOutValue:      uint64(1e8 * 0.60005),
					Sequence:          0xFFFFFFFF,
					Keypath:           []uint32{84 + HARDENED, 1 + HARDENED, 0 + HARDENED, 0, 0},
					ScriptConfigIndex: 0,
				},
				PrevTx: &firmware.BTCPrevTx{
					Version: 1,
					Inputs: []*messages.BTCPrevTxInputRequest{
						{
							PrevOutHash:     []byte("11111111111111111111111111111111"),
							PrevOutIndex:    0,
							SignatureScript: []byte("some signature script"),
							Sequence:        0xFFFFFFFF,
						},
					},
					Outputs: []*messages.BTCPrevTxOutputRequest{
						{
							Value:        uint64(1e8 * 0.60005),
							PubkeyScript: []byte("some pubkey script"),
						},
					},
					Locktime: 0,
				},
			}},
			Outputs: []*messages.BTCSignOutputRequest{
				// Address: tb1q2q0j6gmfxynj40p0kxsr9jkagcvgpuqvqynnup
				{
					Ours:                false,
					Type:                messages.BTCOutputType_P2WPKH,
					Value:               value,
					Payload:             unhex("501f2d236931272abc2fb1a032cadd461880f00c"),
					PaymentRequestIndex: &paymentRequestIndex,
				},
			},
			Locktime:        0,
			PaymentRequests: []*messages.BTCPaymentRequestRequest{paymentRequest},
		},
		messages.BTCSignInitRequest_DEFAULT,
	)
	errpanic(err)
}
