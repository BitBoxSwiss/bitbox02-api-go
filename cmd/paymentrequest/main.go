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
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"log"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/common"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/mocks"
	"github.com/BitBoxSwiss/bitbox02-api-go/communication/u2fhid"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/wire"
	"github.com/karalabe/hid"
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

func isBitBox02(deviceInfo *hid.DeviceInfo) bool {
	return (deviceInfo.Product == common.FirmwareDeviceProductStringBitBox02Multi ||
		deviceInfo.Product == common.FirmwareDeviceProductStringBitBox02BTCOnly ||
		deviceInfo.Product == common.FirmwareDeviceProductStringBitBox02PlusMulti ||
		deviceInfo.Product == common.FirmwareDeviceProductStringBitBox02PlusBTCOnly) &&
		deviceInfo.VendorID == bitbox02VendorID &&
		deviceInfo.ProductID == bitbox02ProductID &&
		(deviceInfo.UsagePage == 0xffff || deviceInfo.Interface == 0)
}

func hashDataLenPrefixed(hasher hash.Hash, data []byte) {
	_ = wire.WriteVarInt(hasher, 0, uint64(len(data)))
	hasher.Write(data)
}

func computeSighash(paymentRequest *messages.BTCPaymentRequestRequest, slip44 uint32, outputValue uint64, outputAddress string) ([]byte, error) {
	sighash := sha256.New()

	// versionMagic
	sighash.Write([]byte("SL\x00\x24"))

	// nonce
	hashDataLenPrefixed(sighash, paymentRequest.Nonce)

	// recipientName
	hashDataLenPrefixed(sighash, []byte(paymentRequest.RecipientName))

	// memos
	_ = wire.WriteVarInt(sighash, 0, uint64(len(paymentRequest.Memos)))
	for _, memo := range paymentRequest.Memos {
		switch m := memo.Memo.(type) {
		case *messages.BTCPaymentRequestRequest_Memo_TextMemo_:
			_ = binary.Write(sighash, binary.LittleEndian, uint32(1))
			hashDataLenPrefixed(sighash, []byte(m.TextMemo.Note))
		default:
			return nil, errors.New("unsupported memo type")
		}
	}

	// coinType
	_ = binary.Write(sighash, binary.LittleEndian, slip44)

	// outputsHash (only one output for now)
	outputHasher := sha256.New()
	_ = binary.Write(outputHasher, binary.LittleEndian, outputValue)
	hashDataLenPrefixed(outputHasher, []byte(outputAddress))
	sighash.Write(outputHasher.Sum(nil))

	return sighash.Sum(nil), nil
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

	// To test with a real device, modify and compile/use a firmware where "Test
	// Merchant" (private key "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") is included in the identities in
	// payment_request.rs.
	paymentRequest := &messages.BTCPaymentRequestRequest{
		RecipientName: "Test Merchant",
		Memos: []*messages.BTCPaymentRequestRequest_Memo{
			{
				Memo: &messages.BTCPaymentRequestRequest_Memo_TextMemo_{
					TextMemo: &messages.BTCPaymentRequestRequest_Memo_TextMemo{
						Note: "TextMemo line1\nTextMemo line2",
					},
				},
			},
		},
		Nonce:       nil,
		TotalAmount: value,
	}

	// Sign the payment request.
	sighash, err := computeSighash(paymentRequest, 1, value, "tb1q2q0j6gmfxynj40p0kxsr9jkagcvgpuqvqynnup")
	errpanic(err)
	privKey, _ := btcec.PrivKeyFromBytes([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	errpanic(err)
	signature, err := ecdsa.SignCompact(privKey, sighash, true)
	errpanic(err)
	paymentRequest.Signature = signature[1:]

	_, _, err = device.BTCSign(
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
