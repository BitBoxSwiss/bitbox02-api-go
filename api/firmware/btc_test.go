// SPDX-License-Identifier: Apache-2.0

package firmware

import (
	"errors"
	"fmt"
	"testing"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/BitBoxSwiss/bitbox02-api-go/util/semver"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const hardenedKeyStart = 0x80000000

func parseECDSASignature(t *testing.T, sig []byte) *ecdsa.Signature {
	t.Helper()
	require.Len(t, sig, 64)
	r := new(btcec.ModNScalar)
	require.False(t, r.SetByteSlice(sig[:32]), "ECDSA r scalar overflows the group order")
	require.False(t, r.IsZero(), "ECDSA r scalar is zero")
	s := new(btcec.ModNScalar)
	require.False(t, s.SetByteSlice(sig[32:]), "ECDSA s scalar overflows the group order")
	require.False(t, s.IsZero(), "ECDSA s scalar is zero")
	return ecdsa.NewSignature(r, s)
}

func TestNewXPub(t *testing.T) {
	xpub, err := NewXPub(
		"xpub6FEZ9Bv73h1vnE4TJG4QFj2RPXJhhsPbnXgFyH3ErLvpcZrDcynY65bhWga8PazWHLSLi23PoBhGcLcYW6JRiJ12zXZ9Aop4LbAqsS3gtcy")
	require.NoError(t, err)
	require.Equal(t, &messages.XPub{
		Depth:             []byte("\x04"),
		ParentFingerprint: []byte("\xe7\x67\xd2\xc3"),
		ChildNum:          hardenedKeyStart + 2,
		ChainCode:         []byte("\xda\x35\xa6\x5b\xdf\x92\x8b\x8b\xd7\x6f\xd4\xb3\xe2\x5c\xd6\x36\xda\x4f\xfe\x90\x54\x8d\x61\x7d\x18\x34\x65\xac\xb6\x5a\xa6\xad"),
		PublicKey:         []byte("\x03\x8e\xcd\x65\x6c\x32\xad\xc6\x42\xa6\xd3\x2f\x88\x4a\xe3\xa0\x4c\xd3\x8b\xbf\x2d\x42\xaf\xff\x76\xb7\x7a\xde\xc4\x64\x3b\x0e\x1c"),
	}, xpub)
}

func TestComputePaymentRequestSighashRefund(t *testing.T) {
	refund := &messages.BTCPaymentRequestRequest_Memo_RefundMemo{
		Address: "bc1qaff6ey7a8nztdl8ufluu5eagpwy6sntmaf53pf",
	}
	request := &messages.BTCPaymentRequestRequest{
		RecipientName: "Test Swap",
		TotalAmount:   100000,
		Memos: []*messages.BTCPaymentRequestRequest_Memo{
			{Memo: &messages.BTCPaymentRequestRequest_Memo_CoinPurchaseMemo_{
				CoinPurchaseMemo: &messages.BTCPaymentRequestRequest_Memo_CoinPurchaseMemo{
					CoinType: 60,
					Amount:   "0.25 ETH",
					Address:  "0x773A77b9D32589be03f9132AF759e294f7851be9",
				},
			}},
			{Memo: &messages.BTCPaymentRequestRequest_Memo_RefundMemo_{RefundMemo: refund}},
		},
	}
	const outputAddress = "bc1qkkweqa5vk942jgevs0x0h8hsmqgfr08n6l7tu9"
	sighash, err := ComputePaymentRequestSighash(request, 0, 100000, outputAddress)
	require.NoError(t, err)
	// Matches the first assertion in the firmware unit test
	// hww::api::payment_request::tests::test_sighash_refund.
	require.Equal(t,
		unhex("eda7a0a2a0f1e24227e58add144371008744d6fbc14aca0a415f0b1281e10863"),
		sighash,
	)

	refund.Address = outputAddress
	changedSighash, err := ComputePaymentRequestSighash(request, 0, 100000, outputAddress)
	require.NoError(t, err)
	require.NotEqual(t, sighash, changedSighash)
}

func TestSimulatorBTCXpub(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *simulatorStdout) {
		t.Helper()
		xpub, err := device.BTCXPub(messages.BTCCoin_TBTC, []uint32{
			49 + hardenedKeyStart,
			1 + hardenedKeyStart,
			0 + hardenedKeyStart,
		}, messages.BTCPubRequest_YPUB, false)
		require.NoError(t, err)
		require.Equal(t, "ypub6WqXiL3fbDK5QNPe3hN4uSVkEvuE8wXoNCcecgggSuKVpU3Kc4fTvhuLgUhtnbAdaTb9gpz5PQdvzcsKPTLgW2CPkF5ZNRzQeKFT4NSc1xN", xpub)
	})
}

func TestSimulatorBTCXPubs(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *simulatorStdout) {
		t.Helper()
		xpubs, err := device.BTCXPubs(messages.BTCCoin_TBTC,
			[][]uint32{
				{
					49 + hardenedKeyStart,
					1 + hardenedKeyStart,
					0 + hardenedKeyStart,
				},
				{
					84 + hardenedKeyStart,
					1 + hardenedKeyStart,
					0 + hardenedKeyStart,
				},
				{
					86 + hardenedKeyStart,
					1 + hardenedKeyStart,
					0 + hardenedKeyStart,
				},
			}, messages.BTCXpubsRequest_TPUB)

		require.NoError(t, err)
		require.Equal(t,
			[]string{
				"tpubDCNtvuCS9oj3psPNfXZXuGjcQ5rSBi3MzigjBqqwQohWWetoRdLzT5v2uJq6KBTwxj1FYvuPTr7RoWkN4cmubDy5wW8SU3q9xYnDRpQepiT",
				"tpubDCYNsKenq7Cuuf4fHsu2fsWA7Wb5cTD2qRUrw6uHbNNYQoNkEoJk4hgNhxbnGss5gnEe2MpqN2qbRVqWJGmuofAWmwFFi4CZ9Tg1LHKJDhF",
				"tpubDDc6eecoyYxL4g3WKYpbbinyUmnfVikQCzHTPd6rJQivaPqGKBFiueQqWoAYonB8hAEXGM1ak7LqrnwczH24EbW7jbG5bNK5rncmRXtv7nG",
			},
			xpubs)
	})
}

func TestSimulatorBTCAddress(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *simulatorStdout) {
		t.Helper()
		// TBTC, P2WPKH
		address, err := device.BTCAddress(
			messages.BTCCoin_TBTC,
			[]uint32{
				84 + hardenedKeyStart,
				1 + hardenedKeyStart,
				0 + hardenedKeyStart,
				1,
				10,
			},
			NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH),
			false,
		)
		require.NoError(t, err)
		require.Equal(t, "tb1qq064dxjgl9h9wzgsmzy6t6306qew42w9ka02u3", address)

		// BTC, P2WPKH
		address, err = device.BTCAddress(
			messages.BTCCoin_BTC,
			[]uint32{
				84 + hardenedKeyStart,
				0 + hardenedKeyStart,
				0 + hardenedKeyStart,
				1,
				10,
			},
			NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH),
			false,
		)
		require.NoError(t, err)
		require.Equal(t, "bc1qcq0ceq9vs24g4tnkkx3k2rry9j44r74huc3d7s", address)

		// RBTC, P2WPKH
		address, err = device.BTCAddress(
			messages.BTCCoin_RBTC,
			[]uint32{
				84 + hardenedKeyStart,
				1 + hardenedKeyStart,
				0 + hardenedKeyStart,
				1,
				10,
			},
			NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH),
			false,
		)
		// Regtest (RBTC) support added in v9.21.0
		if device.Version().AtLeast(semver.NewSemVer(9, 21, 0)) {
			require.NoError(t, err)
			require.Equal(t, "bcrt1qq064dxjgl9h9wzgsmzy6t6306qew42w955k8tc", address)
		} else {
			require.Error(t, err)
		}
	})
}

func mustXpub(xpubStr string, keypath ...uint32) *hdkeychain.ExtendedKey {
	xpub, err := hdkeychain.NewKeyFromString(xpubStr)
	if err != nil {
		panic(err)
	}
	for _, childIndex := range keypath {
		xpub, err = xpub.Derive(childIndex)
		if err != nil {
			panic(err)
		}
	}
	return xpub
}

func simulatorPub(t *testing.T, device *Device, keypath ...uint32) *btcec.PublicKey {
	t.Helper()

	xpubStr, err := device.BTCXPub(messages.BTCCoin_BTC, keypath, messages.BTCPubRequest_XPUB, false)
	require.NoError(t, err)

	xpub := mustXpub(xpubStr)
	pubKey, err := xpub.ECPubKey()
	require.NoError(t, err)
	return pubKey
}

func TestSimulatorBTCSignMessage(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *simulatorStdout) {
		t.Helper()
		coin := messages.BTCCoin_BTC
		keypath := []uint32{49 + hardenedKeyStart, 0 + hardenedKeyStart, 0 + hardenedKeyStart, 0, 10}

		pubKey := simulatorPub(t, device, keypath...)

		result, err := device.BTCSignMessage(
			coin,
			&messages.BTCScriptConfigWithKeypath{
				ScriptConfig: NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH_P2SH),
				Keypath:      keypath,
			},
			[]byte("message"),
		)
		require.NoError(t, err)
		sigHash := chainhash.DoubleHashB([]byte("\x18Bitcoin Signed Message:\n\x07message"))
		require.True(t, parseECDSASignature(t, result.Signature).Verify(sigHash, pubKey))
	})
}

func TestBTCXPub(t *testing.T) {
	testConfigurations(t, func(t *testing.T, env *testEnv) {
		t.Helper()
		expected := "mocked-xpub"
		xpubType := messages.BTCPubRequest_YPUB
		expectedPubRequest := &messages.BTCPubRequest{
			Coin: messages.BTCCoin_TBTC,
			Keypath: []uint32{
				49 + hardenedKeyStart,
				1 + hardenedKeyStart,
				0 + hardenedKeyStart,
				2,
				10,
			},
			Output: &messages.BTCPubRequest_XpubType{
				XpubType: xpubType,
			},
			Display: true,
		}

		// Unexpected response
		env.onRequest = func(request *messages.Request) *messages.Response {
			return testDeviceResponseOK
		}
		_, err := env.device.BTCXPub(
			expectedPubRequest.Coin,
			expectedPubRequest.Keypath,
			xpubType,
			expectedPubRequest.Display,
		)
		require.Error(t, err)

		// Happy case.
		env.onRequest = func(request *messages.Request) *messages.Response {
			pubRequest, ok := request.Request.(*messages.Request_BtcPub)
			require.True(t, ok)
			require.Equal(t,
				expectedPubRequest,
				pubRequest.BtcPub)
			return &messages.Response{
				Response: &messages.Response_Pub{
					Pub: &messages.PubResponse{
						Pub: expected,
					},
				},
			}
		}
		address, err := env.device.BTCXPub(
			expectedPubRequest.Coin,
			expectedPubRequest.Keypath,
			xpubType,
			expectedPubRequest.Display,
		)
		require.NoError(t, err)
		require.Equal(t, expected, address)

		// Query error.
		expectedErr := errors.New("error")
		env.communication.MockQuery = func(msg []byte) ([]byte, error) {
			return nil, expectedErr
		}
		_, err = env.device.BTCXPub(
			expectedPubRequest.Coin,
			expectedPubRequest.Keypath,
			xpubType,
			expectedPubRequest.Display,
		)
		require.Equal(t, expectedErr, err)
	})
}

func TestBTCAddress(t *testing.T) {
	testConfigurations(t, func(t *testing.T, env *testEnv) {
		t.Helper()
		expected := "mocked-address"
		scriptConfig := NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH_P2SH)
		expectedPubRequest := &messages.BTCPubRequest{
			Coin: messages.BTCCoin_TBTC,
			Keypath: []uint32{
				49 + hardenedKeyStart,
				1 + hardenedKeyStart,
				0 + hardenedKeyStart,
				2,
				10,
			},
			Output: &messages.BTCPubRequest_ScriptConfig{
				ScriptConfig: scriptConfig,
			},
			Display: true,
		}

		// Unexpected response
		env.onRequest = func(request *messages.Request) *messages.Response {
			return testDeviceResponseOK
		}
		_, err := env.device.BTCAddress(
			expectedPubRequest.Coin,
			expectedPubRequest.Keypath,
			scriptConfig,
			expectedPubRequest.Display,
		)
		require.Error(t, err)
		// Happy case.
		env.onRequest = func(request *messages.Request) *messages.Response {
			pubRequest, ok := request.Request.(*messages.Request_BtcPub)
			require.True(t, ok)
			require.True(t, proto.Equal(
				expectedPubRequest,
				pubRequest.BtcPub,
			))
			return &messages.Response{
				Response: &messages.Response_Pub{
					Pub: &messages.PubResponse{
						Pub: expected,
					},
				},
			}
		}
		address, err := env.device.BTCAddress(
			expectedPubRequest.Coin,
			expectedPubRequest.Keypath,
			scriptConfig,
			expectedPubRequest.Display,
		)
		require.NoError(t, err)
		require.Equal(t, expected, address)

		// Query error.
		expectedErr := errors.New("error")
		env.communication.MockQuery = func(msg []byte) ([]byte, error) {
			return nil, expectedErr
		}
		_, err = env.device.BTCAddress(
			expectedPubRequest.Coin,
			expectedPubRequest.Keypath,
			scriptConfig,
			expectedPubRequest.Display,
		)
		require.Equal(t, expectedErr, err)
	})
}

func TestBTCSignMessage(t *testing.T) {
	testConfigurations(t, func(t *testing.T, env *testEnv) {
		t.Helper()
		hostNonce := []byte("\x55\xae\x3b\xbb\x4c\x9e\xc5\x27\xca\xc1\x48\x92\xe9\xd7\x29\x81\x82\xf2\x1d\x5c\xa0\xa5\xf3\xc4\x30\x42\x3e\x52\xfe\x1c\xb9\x10")
		expectedSig := []byte("\xb1\xf8\x62\x29\x55\xc2\x67\xf9\x01\x0b\xd9\x1d\xa8\x46\x93\x67\xb5\xd1\xab\xd1\x95\x72\x1c\xa8\xc1\xd0\xc5\x2a\x37\x73\x84\xbb\x44\xa9\x92\x7e\x42\xaf\xf8\x91\xfa\x8b\xd1\x9e\x77\x86\x62\x1e\x57\xfb\xe4\x14\x79\x9d\x71\x29\x25\xed\xbc\x3b\x5b\x68\xc8\x95\x00")
		env.onRequest = func(request *messages.Request) *messages.Response {
			if req, ok := request.Request.(*messages.Request_Btc).Btc.Request.(*messages.BTCRequest_SignMessage); ok && req.SignMessage.HostNonceCommitment != nil {
				return &messages.Response{
					Response: &messages.Response_Btc{
						Btc: &messages.BTCResponse{
							Response: &messages.BTCResponse_AntikleptoSignerCommitment{
								AntikleptoSignerCommitment: &messages.AntiKleptoSignerCommitment{
									Commitment: []byte("\x02\xed\xee\x9d\x17\x5a\xd5\xcf\x66\xf5\x46\xe0\x72\xfe\x08\x7f\xc1\x5c\x5c\xa8\x4e\x51\xbe\x6e\x72\x5f\x5b\x33\x77\xbf\xfc\x96\x22"),
								},
							},
						},
					},
				}
			}
			return &messages.Response{
				Response: &messages.Response_Btc{
					Btc: &messages.BTCResponse{
						Response: &messages.BTCResponse_SignMessage{
							SignMessage: &messages.BTCSignMessageResponse{
								Signature: expectedSig,
							},
						},
					},
				},
			}
		}
		// Mock host nonce.
		prevGenerateHostNonce := generateHostNonce
		t.Cleanup(func() {
			generateHostNonce = prevGenerateHostNonce
		})
		generateHostNonce = func() ([]byte, error) {
			return hostNonce, nil
		}
		result, err := env.device.BTCSignMessage(
			messages.BTCCoin_BTC,
			&messages.BTCScriptConfigWithKeypath{
				ScriptConfig: NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH_P2SH),
				Keypath:      []uint32{49 + hardenedKeyStart, 0 + hardenedKeyStart, 0 + hardenedKeyStart, 0, 0},
			},
			[]byte("message"),
		)
		if env.version.AtLeast(semver.NewSemVer(9, 5, 0)) {
			require.NoError(t, err)
			require.Equal(t, expectedSig[:64], result.Signature)
			require.Equal(t, byte(0), result.RecID)
			require.Equal(t, result.ElectrumSig65, append([]byte{31}, expectedSig[:64]...))
		} else {
			require.EqualError(t, err, UnsupportedError("9.5.0").Error())
		}
	})
}

func TestIsTaprootScriptConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    *messages.BTCScriptConfig
		isTaproot bool
	}{
		{
			name:      "simple Taproot",
			config:    NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2TR),
			isTaproot: true,
		},
		{
			name:      "Taproot key-spend policy",
			config:    NewBTCScriptConfigPolicy("tr(@0/<0;1>/*)", nil),
			isTaproot: true,
		},
		{
			name:      "Taproot script-spend policy",
			config:    NewBTCScriptConfigPolicy("tr(@0/<0;1>/*,pk(@1/<0;1>/*))", nil),
			isTaproot: true,
		},
		{
			name:      "SegWit policy",
			config:    NewBTCScriptConfigPolicy("wsh(pk(@0/<0;1>/*))", nil),
			isTaproot: false,
		},
		{
			name:      "native SegWit",
			config:    NewBTCScriptConfigSimple(messages.BTCScriptConfig_P2WPKH),
			isTaproot: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := &messages.BTCScriptConfigWithKeypath{ScriptConfig: test.config}
			require.Equal(t, test.isTaproot, isTaproot(config))
			require.Equal(t, !test.isTaproot, BTCSignNeedsPrevTxs(
				[]*messages.BTCScriptConfigWithKeypath{config},
			))
		})
	}
}

// setupMultisigAccount is a helper function that sets up a multisig account for testing.
// It returns a struct containing the account details.
type MultisigAccountSetup struct {
	KeypathAccount []uint32
	ReceiveKeypath []uint32
	ChangeKeypath  []uint32
	ScriptConfig   *messages.BTCScriptConfig
	Xpubs          []string
}

func setupMultisigAccount(t *testing.T, device *Device, coin messages.BTCCoin) *MultisigAccountSetup {
	t.Helper()

	keypathAccount := []uint32{
		48 + hardenedKeyStart,
		0 + hardenedKeyStart,
		0 + hardenedKeyStart,
		2 + hardenedKeyStart,
	}

	receiveKeypath := append(append([]uint32{}, keypathAccount...), 0, 0)
	changeKeypath := append(append([]uint32{}, keypathAccount...), 1, 0)

	ourXPub, err := device.BTCXPub(coin, keypathAccount, messages.BTCPubRequest_XPUB, false)
	require.NoError(t, err)

	xpubs := []string{
		ourXPub,
		"xpub6Esa6esRHkbuXtbdDKqu3uWjQ1GpK39WW2hxbUAN4L3TxrwDyghEwBtUYZ8uK8LZh3tJ3pjWEpxng9tjfo7RT9BaZKV2T3EPvmZ6N1LgSdj",
		"xpub6FJ6FAAFUzuWQAKyT98Ngs6UwsoPfPCdmepqX2aLLPT54M85ARsWzPciFd49foStMwhWgfiHP6PnMgPrWLrBJpUHgqw8vZPd5ov8uSfW2vo",
	}

	ourXPubIndex := uint32(0)
	threshold := 1

	scriptConfig, err := NewBTCScriptConfigMultisig(uint32(threshold), xpubs, ourXPubIndex)
	require.NoError(t, err)

	// The multisig account has to be registered if not already.
	registered, err := device.BTCIsScriptConfigRegistered(coin, scriptConfig, keypathAccount)
	require.NoError(t, err)
	require.False(t, registered)

	err = device.BTCRegisterScriptConfig(coin, scriptConfig, keypathAccount, "My multisig account")
	require.NoError(t, err)

	return &MultisigAccountSetup{
		KeypathAccount: keypathAccount,
		ReceiveKeypath: receiveKeypath,
		ChangeKeypath:  changeKeypath,
		ScriptConfig:   scriptConfig,
		Xpubs:          xpubs,
	}
}

// 1-of-3 multisig registration and address display/verification.
func TestSimulatorBTCAddressMultisig(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *simulatorStdout) {
		t.Helper()

		coin := messages.BTCCoin_BTC
		setup := setupMultisigAccount(t, device, coin)

		address, err := device.BTCAddress(
			coin,
			setup.ReceiveKeypath,
			setup.ScriptConfig,
			true,
		)
		require.NoError(t, err)
		require.Equal(t, "bc1qdhqnu2arm9al7uv687amuesk5det5nxx0k9ed30x2u8zjsfnsfyqzlsrsu", address)
		if device.Version().AtLeast(semver.NewSemVer(9, 20, 0)) {
			displayAddress := address
			if device.Version().AtLeast(semver.NewSemVer(9, 26, 0)) {
				displayAddress = "bc1q dhqn u2ar m9al 7uv6 87am uesk 5det 5nxx 0k9e d30x 2u8z jsfn sfyq zlsr su"
			}

			// Before simulator v9.20, address confirmation data was not written to stdout.
			require.Contains(t,
				stdOut.String(),
				fmt.Sprintf(`TITLE: Register
BODY: 1-of-3
Bitcoin multisig
CONFIRM SCREEN END
CONFIRM SCREEN START
TITLE: Register
BODY: My multisig account
CONFIRM SCREEN END
CONFIRM SCREEN START
TITLE: Register
BODY: p2wsh
at
m/48'/0'/0'/2'
CONFIRM SCREEN END
CONFIRM SCREEN START
TITLE: Register
BODY: Cosigner 1/3 (this device): Zpub74CYNJGx5QwGYeXket9qEbWbEhMNCL1d1Za3eXpABKXMWNVDhTZmovUkzBa74SCrZruMQLGQ6Zce9HzJUaLoF8QPkRU7CVfSSqNZ7Qy2BB5
CONFIRM SCREEN END
CONFIRM SCREEN START
TITLE: Register
BODY: Cosigner 2/3: Zpub75SBqDwhA5FEf49Epht8JA3YTjbyQdp6eXQ55XDgC7ddhF8bFQQeGS4gPg1YsNsJjoBtRMvk3N4PZtjdQR6QC6fT8TzH2GLNMwxFj3Rnnzx
CONFIRM SCREEN END
CONFIRM SCREEN START
TITLE: Register
BODY: Cosigner 3/3: Zpub75rhyjEXMKYqXKsb4XAbw7dJ1c8YkysDv9Wx15deUB3EnjKSS9avKdnv6jvoE3ydQh174CuXBdVPFREkExqA3mxAFzSPVnVbWzKJGVWvYXJ
CONFIRM SCREEN END
STATUS SCREEN START
TITLE: Multisig account
registered
STATUS SCREEN END
CONFIRM SCREEN START
TITLE: Receive to
BODY: 1-of-3
Bitcoin multisig
CONFIRM SCREEN END
CONFIRM SCREEN START
TITLE: Receive to
BODY: My multisig account
CONFIRM SCREEN END
CONFIRM SCREEN START
TITLE: Receive to
BODY: %s
CONFIRM SCREEN END
`, displayAddress))
		}
	})
}
