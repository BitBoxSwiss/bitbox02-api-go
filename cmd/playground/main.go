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
	"log"
	"net/http"

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

	const HARDENED = 0x80000000

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
			Type:  messages.BTCOutputType_P2WSH,
			Hash:  []byte("11111111111111111111111111111111"),
			Value: outp.Value,
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
	device.Init()
	device.ChannelHashVerify(true)

	signFromTxID(device, "48e83b2a44c21dab01fc7bad0df1b1d7a59e48af79069454a8320ec6a9d1aefb")

	// const HARDENED = 0x80000000

	// fmt.Println(device.BTCSignMessage(
	// 	messages.BTCCoin_BTC,
	// 	&messages.BTCScriptConfigWithKeypath{
	// 		ScriptConfig: firmware.NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH_P2SH),
	// 		Keypath:      []uint32{49 + HARDENED, 0 + HARDENED, 0 + HARDENED, 0, 0},
	// 	},
	// 	[]byte("message"),
	// ))

	// keypathAccount := []uint32{48 + HARDENED, 0 + HARDENED, 0 + HARDENED, 2 + HARDENED}
	// coin := messages.BTCCoin_BTC
	// ourXPub, err := device.BTCXPub(
	// 	coin,
	// 	keypathAccount,
	// 	messages.BTCPubRequest_XPUB,
	// 	false,
	// )
	// errpanic(err)

	// scriptConfig, err := firmware.NewBTCScriptConfigMultisig(
	// 	1,
	// 	[]string{
	// 		ourXPub,
	// 		"xpub6FEZ9Bv73h1vnE4TJG4QFj2RPXJhhsPbnXgFyH3ErLvpcZrDcynY65bhWga8PazWHLSLi23PoBhGcLcYW6JRiJ12zXZ9Aop4LbAqsS3gtcy",
	// 	},
	// 	0, // ourXPubIndex,
	// )
	// errpanic(err)
	// fmt.Println(device.BTCAddress(coin, append(keypathAccount, 0, 0), scriptConfig, true))
}
