// Copyright 2018-2019 Shift Cryptosecurity AG
// Copyright 2020 Shift Crypto AG
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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"

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

	HARDENED = 0x80000000
)

func errpanic(err error) {
	if err != nil {
		log.Fatalf("%+v", err)
	}
}

func isBitBox02(deviceInfo usb.DeviceInfo) bool {
	return (deviceInfo.Product == common.FirmwareHIDProductStringStandard ||
		deviceInfo.Product == common.FirmwareHIDProductStringBTCOnly) &&
		deviceInfo.VendorID == bitbox02VendorID &&
		deviceInfo.ProductID == bitbox02ProductID &&
		(deviceInfo.UsagePage == 0xffff || deviceInfo.Interface == 0)
}

type blockchairTx struct {
	Inputs []struct {
		TxHash          string `json:"transaction_hash"`
		Index           uint32
		Value           uint64
		Sequence        uint32 `json:"spending_sequence"`
		SignatureScript string `json:"spending_signature_hex"`
	}
	Outputs []struct {
		Value        uint64
		PubKeyScript string `json:"script_hex"`
	}
	Transaction struct {
		Version  uint32
		Locktime uint32 `json:"lock_time"`
	}
}

func getTx(txID string) *blockchairTx {
	response, err := http.Get(
		"https://api.blockchair.com/bitcoin/testnet/dashboards/transaction/" + txID)
	errpanic(err)
	defer response.Body.Close()
	var jsonData struct {
		Data map[string]*blockchairTx
	}
	errpanic(json.NewDecoder(response.Body).Decode(&jsonData))
	return jsonData.Data[txID]
}

// Experiment with testnet transactions.
// Uses blockchair.com to convert a testnet transaction to the input required by BTCSign(),
// including the previous transactions.
func signFromTxID(device *firmware.Device, txID string) {
	tx := getTx(txID)
	inputs := []*firmware.BTCTxInput{}
	outputs := []*messages.BTCSignOutputRequest{}

	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		errpanic(err)
		return b
	}

	reverse := func(bs []byte) []byte {
		result := make([]byte, len(bs))
		for i, b := range bs {
			result[len(bs)-1-i] = b
		}
		return result
	}

	for _, inp := range tx.Inputs {
		prevtx := getTx(inp.TxHash)

		prevInputs := []*messages.BTCPrevTxInputRequest{}
		for _, prevInp := range prevtx.Inputs {
			prevInputs = append(prevInputs, &messages.BTCPrevTxInputRequest{
				PrevOutHash:     reverse(unhex(prevInp.TxHash)),
				PrevOutIndex:    prevInp.Index,
				SignatureScript: unhex(prevInp.SignatureScript),
				Sequence:        prevInp.Sequence,
			})
		}

		prevOutputs := []*messages.BTCPrevTxOutputRequest{}
		for _, prevOutp := range prevtx.Outputs {
			prevOutputs = append(prevOutputs, &messages.BTCPrevTxOutputRequest{
				Value:        prevOutp.Value,
				PubkeyScript: unhex(prevOutp.PubKeyScript),
			})
		}

		inputs = append(inputs, &firmware.BTCTxInput{
			Input: &messages.BTCSignInputRequest{
				PrevOutHash:  reverse(unhex(inp.TxHash)),
				PrevOutIndex: inp.Index,
				PrevOutValue: inp.Value,
				Sequence:     inp.Sequence,
				Keypath:      []uint32{84 + HARDENED, 1 + HARDENED, 0 + HARDENED, 0, 0},
			},
			PrevTx: &firmware.BTCPrevTx{
				Version:  prevtx.Transaction.Version,
				Inputs:   prevInputs,
				Outputs:  prevOutputs,
				Locktime: prevtx.Transaction.Locktime,
			},
		})
	}
	for _, outp := range tx.Outputs {
		outputs = append(outputs, &messages.BTCSignOutputRequest{
			Ours: false,
			// TODO: parse pubkey script
			Type:    messages.BTCOutputType_P2WSH,
			Payload: []byte("11111111111111111111111111111111"),
			Value:   outp.Value,
		})
	}
	_, err := device.BTCSign(
		messages.BTCCoin_TBTC,
		[]*messages.BTCScriptConfigWithKeypath{
			{
				ScriptConfig: firmware.NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH),
				Keypath:      []uint32{84 + HARDENED, 1 + HARDENED, 0 + HARDENED},
			},
		},
		&firmware.BTCTx{
			Version:  tx.Transaction.Version,
			Inputs:   inputs,
			Outputs:  outputs,
			Locktime: tx.Transaction.Locktime,
		},
		messages.BTCSignInitRequest_DEFAULT,
	)
	errpanic(err)

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
	device.SetOnEvent(func(ev firmware.Event, meta interface{}) {
		if ev == firmware.EventAttestationCheckDone {
			attestation := device.Attestation()
			fmt.Println("Attestation check:", *attestation)
		}
	})
	errpanic(device.Init())
	device.ChannelHashVerify(true)

	rootFingerprint, err := device.RootFingerprint()
	errpanic(err)
	fmt.Printf("Root fingerprint: %x\n", rootFingerprint)

	info, err := device.DeviceInfo()
	errpanic(err)
	fmt.Printf("Device info: %+v", info)
	//signFromTxID(device, "48e83b2a44c21dab01fc7bad0df1b1d7a59e48af79069454a8320ec6a9d1aefb")

	sig, err := device.ETHSignEIP1559(
		1,
		[]uint32{44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0},
		1,
		new(big.Int).SetBytes([]byte("\x77\x35\x94\x00")),
		new(big.Int).SetBytes([]byte("\x02\x54\x0b\xe4\x00")),
		21000,
		[20]byte{0xd6, 0x10, 0x54, 0xf4, 0x45, 0x6d, 0x05, 0x55, 0xdc, 0x2d, 0xd8, 0x2b, 0x77, 0xf7, 0xad, 0x60, 0x74, 0x83, 0x61, 0x49},
		new(big.Int).SetBytes([]byte("\x5a\xf3\x10\x7a\x40\x00")),
		nil,
	)
	errpanic(err)
	fmt.Println(sig)

	sig, err = device.ETHSignTypedMessage(
		1,
		[]uint32{44 + HARDENED, 60 + HARDENED, 0 + HARDENED, 0, 0},
		[]byte(`{
    "types": {
        "EIP712Domain": [
            { "name": "name", "type": "string" },
            { "name": "version", "type": "string" },
            { "name": "chainId", "type": "uint256" },
            { "name": "verifyingContract", "type": "address" }
        ],
        "Attachment": [
            { "name": "contents", "type": "string" }
        ],
        "Person": [
            { "name": "name", "type": "string" },
            { "name": "wallet", "type": "address" },
            { "name": "age", "type": "uint8" }
        ],
        "Mail": [
            { "name": "from", "type": "Person" },
            { "name": "to", "type": "Person" },
            { "name": "contents", "type": "string" },
            { "name": "attachments", "type": "Attachment[]" }
        ]
    },
    "primaryType": "Mail",
    "domain": {
        "name": "Ether Mail",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
    },
    "message": {
        "from": {
            "name": "Cow",
            "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
            "age": 20
        },
        "to": {
            "name": "Bob",
            "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
            "age": "0x1e"
        },
        "contents": "Hello, Bob!",
        "attachments": [{ "contents": "attachment1" }, { "contents": "attachment2" }]
    }
}`),
	)
	errpanic(err)
	fmt.Println(sig)
	// _, _, _, err = device.BTCSignMessage(messages.BTCCoin_BTC,
	// 	&messages.BTCScriptConfigWithKeypath{
	// 		ScriptConfig: firmware.NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH),
	// 		Keypath:       []uint32{84 + HARDENED, 0 + HARDENED, 0 + HARDENED, 0, 0},
	// 	},
	// 	[]byte(`asdsad`),
	// )
	// errpanic(err)

}
