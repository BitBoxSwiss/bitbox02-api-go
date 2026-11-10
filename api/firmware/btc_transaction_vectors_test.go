// SPDX-License-Identifier: Apache-2.0

package firmware

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/BitBoxSwiss/bitbox02-api-go/util/semver"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/stretchr/testify/require"
)

const (
	btcTransactionTestVectorsFilename = "testdata/btc-transaction-test-vectors.json"
	btcVectorStdoutStableFor          = 50 * time.Millisecond
	btcVectorStdoutTimeout            = 5 * time.Second
)

type btcTestVectorOutcome string

const (
	btcTestVectorOutcomeSuccess      btcTestVectorOutcome = "success"
	btcTestVectorOutcomeUnsupported  btcTestVectorOutcome = "unsupported"
	btcTestVectorOutcomeInvalidInput btcTestVectorOutcome = "invalid_input"
)

type btcTestVectorSignatureKind string

const (
	btcTestVectorSignatureECDSA         btcTestVectorSignatureKind = "ecdsa"
	btcTestVectorSignatureTaprootKey    btcTestVectorSignatureKind = "taproot_key"
	btcTestVectorSignatureTaprootScript btcTestVectorSignatureKind = "taproot_script"
)

type btcTestVectorSighash string

const (
	btcTestVectorSighashAll     btcTestVectorSighash = "all"
	btcTestVectorSighashDefault btcTestVectorSighash = "default"
)

type btcTestVector struct {
	ID                       string                            `json:"id"`
	Description              string                            `json:"description"`
	Coin                     string                            `json:"coin"`
	PSBT                     btcTestVectorPSBT                 `json:"psbt"`
	ExpectedNeedsPrevTxs     bool                              `json:"expected_needs_prevtxs"`
	Expectations             []btcTestVectorVersionExpectation `json:"expectations"`
	Registrations            []btcTestVectorRegistration       `json:"registrations,omitempty"`
	ExpectedSignatures       []btcTestVectorSignature          `json:"expected_signatures,omitempty"`
	ExpectedGeneratedOutputs map[int]string                    `json:"expected_generated_outputs,omitempty"`
}

type btcTestVectorPSBT struct {
	Transaction string                       `json:"transaction"`
	Options     btcTestVectorPSBTSignOptions `json:"options,omitempty"`
}

type btcTestVectorVersionExpectation struct {
	MinVersion          *semver.SemVer       `json:"min_version,omitempty"`
	MaxVersionExclusive *semver.SemVer       `json:"max_version_exclusive,omitempty"`
	Outcome             btcTestVectorOutcome `json:"outcome"`
	UnsupportedVersion  *string              `json:"unsupported_version,omitempty"`
	Screens             []simulatorScreen    `json:"screens"`
}

type btcTestVectorPSBTSignOptions struct {
	ForceScriptConfig *btcTestVectorScriptConfigWithKeypath  `json:"force_script_config,omitempty"`
	Outputs           map[int]btcTestVectorPSBTOutputOptions `json:"outputs,omitempty"`
	PaymentRequests   []btcTestVectorPaymentRequest          `json:"payment_requests,omitempty"`
	FormatUnit        string                                 `json:"format_unit,omitempty"`
}

type btcTestVectorPSBTOutputOptions struct {
	SilentPaymentAddress string  `json:"silent_payment_address,omitempty"`
	PaymentRequestIndex  *uint32 `json:"payment_request_index,omitempty"`
}

type btcTestVectorPaymentRequest struct {
	RecipientName string                            `json:"recipient_name"`
	TotalAmount   uint64                            `json:"total_amount"`
	Nonce         string                            `json:"nonce,omitempty"`
	Memos         []btcTestVectorPaymentRequestMemo `json:"memos"`
	Signature     string                            `json:"signature"`
}

type btcTestVectorPaymentRequestMemo struct {
	Type           string `json:"type"`
	Note           string `json:"note,omitempty"`
	CoinType       uint32 `json:"coin_type,omitempty"`
	Amount         string `json:"amount,omitempty"`
	Address        string `json:"address,omitempty"`
	AddressKeypath string `json:"address_keypath,omitempty"`
}

type btcTestVectorScriptConfigWithKeypath struct {
	ScriptConfig btcTestVectorScriptConfig `json:"script_config"`
	Keypath      string                    `json:"keypath"`
}

type btcTestVectorScriptConfig struct {
	Type         string                       `json:"type"`
	ScriptType   string                       `json:"script_type,omitempty"`
	Threshold    uint32                       `json:"threshold,omitempty"`
	Xpubs        []string                     `json:"xpubs,omitempty"`
	OurXpubIndex uint32                       `json:"our_xpub_index,omitempty"`
	Policy       string                       `json:"policy,omitempty"`
	Keys         []btcTestVectorKeyOriginInfo `json:"keys,omitempty"`
}

type btcTestVectorKeyOriginInfo struct {
	RootFingerprint *string `json:"root_fingerprint,omitempty"`
	Keypath         *string `json:"keypath,omitempty"`
	Xpub            string  `json:"xpub"`
}

type btcTestVectorRegistration struct {
	ScriptConfig btcTestVectorScriptConfig `json:"script_config"`
	Keypath      *string                   `json:"keypath,omitempty"`
	Name         string                    `json:"name"`
}

type btcTestVectorSignature struct {
	InputIndex int                        `json:"input_index"`
	Kind       btcTestVectorSignatureKind `json:"kind"`
	Pubkey     string                     `json:"pubkey,omitempty"`
	LeafHash   string                     `json:"leaf_hash,omitempty"`
	Sighash    btcTestVectorSighash       `json:"sighash"`
}

func loadBTCTransactionTestVectors(t *testing.T) []btcTestVector {
	t.Helper()
	data, err := os.ReadFile(btcTransactionTestVectorsFilename)
	require.NoError(t, err)
	var result struct {
		Vectors []btcTestVector `json:"vectors"`
	}
	require.NoError(t, json.Unmarshal(data, &result))
	return result.Vectors
}

func btcTestVectorExpectation(
	expectations []btcTestVectorVersionExpectation,
	version *semver.SemVer,
) *btcTestVectorVersionExpectation {
	for index := range expectations {
		expectation := &expectations[index]
		if expectation.MinVersion != nil && !version.AtLeast(expectation.MinVersion) {
			continue
		}
		if expectation.MaxVersionExclusive != nil && version.AtLeast(expectation.MaxVersionExclusive) {
			continue
		}
		return expectation
	}
	return nil
}

func parseBTCVectorKeypath(value string) ([]uint32, error) {
	if value == "m" {
		return []uint32{}, nil
	}
	components := strings.Split(strings.TrimPrefix(value, "m/"), "/")
	result := make([]uint32, len(components))
	for index, component := range components {
		hardened := strings.HasSuffix(component, "'")
		if hardened {
			component = strings.TrimSuffix(component, "'")
		}
		child, err := strconv.ParseUint(component, 10, 31)
		if err != nil {
			return nil, err
		}
		result[index] = uint32(child)
		if hardened {
			result[index] |= HARDENED
		}
	}
	return result, nil
}

func btcTestVectorCoin(coin string) (messages.BTCCoin, error) {
	switch coin {
	case "btc":
		return messages.BTCCoin_BTC, nil
	case "tbtc":
		return messages.BTCCoin_TBTC, nil
	case "ltc":
		return messages.BTCCoin_LTC, nil
	default:
		return 0, fmt.Errorf("unknown Bitcoin test vector coin %q", coin)
	}
}

func btcTestVectorFormatUnit(formatUnit string) (messages.BTCSignInitRequest_FormatUnit, error) {
	switch formatUnit {
	case "", "default":
		return messages.BTCSignInitRequest_DEFAULT, nil
	case "sat":
		return messages.BTCSignInitRequest_SAT, nil
	default:
		return 0, fmt.Errorf("unknown Bitcoin test vector format unit %q", formatUnit)
	}
}

func convertBTCVectorScriptConfig(config btcTestVectorScriptConfig) (*messages.BTCScriptConfig, error) {
	switch config.Type {
	case "simple":
		var simpleType messages.BTCScriptConfig_SimpleType
		switch config.ScriptType {
		case "p2wpkh":
			simpleType = messages.BTCScriptConfig_P2WPKH
		case "p2wpkh_p2sh":
			simpleType = messages.BTCScriptConfig_P2WPKH_P2SH
		case "p2tr":
			simpleType = messages.BTCScriptConfig_P2TR
		default:
			return nil, fmt.Errorf("unknown simple script type %q", config.ScriptType)
		}
		return NewBTCScriptConfigSimple(simpleType), nil

	case "multisig":
		converted, err := NewBTCScriptConfigMultisig(
			config.Threshold,
			config.Xpubs,
			config.OurXpubIndex,
		)
		if err != nil {
			return nil, err
		}
		switch config.ScriptType {
		case "p2wsh":
			converted.GetMultisig().ScriptType = messages.BTCScriptConfig_Multisig_P2WSH
		case "p2wsh_p2sh":
			converted.GetMultisig().ScriptType = messages.BTCScriptConfig_Multisig_P2WSH_P2SH
		default:
			return nil, fmt.Errorf("unknown multisig script type %q", config.ScriptType)
		}
		return converted, nil

	case "policy":
		keys := make([]*messages.KeyOriginInfo, len(config.Keys))
		for index, key := range config.Keys {
			xpub, err := NewXPub(key.Xpub)
			if err != nil {
				return nil, err
			}
			var rootFingerprint []byte
			if key.RootFingerprint != nil {
				rootFingerprint, err = hex.DecodeString(*key.RootFingerprint)
				if err != nil {
					return nil, err
				}
			}
			var keypath []uint32
			if key.Keypath != nil {
				keypath, err = parseBTCVectorKeypath(*key.Keypath)
				if err != nil {
					return nil, err
				}
			}
			keys[index] = &messages.KeyOriginInfo{
				RootFingerprint: rootFingerprint,
				Keypath:         keypath,
				Xpub:            xpub,
			}
		}
		return NewBTCScriptConfigPolicy(config.Policy, keys), nil

	default:
		return nil, fmt.Errorf("unknown script config type %q", config.Type)
	}
}

func convertBTCVectorScriptConfigWithKeypath(
	config btcTestVectorScriptConfigWithKeypath,
) (*messages.BTCScriptConfigWithKeypath, error) {
	converted, err := convertBTCVectorScriptConfig(config.ScriptConfig)
	if err != nil {
		return nil, err
	}
	keypath, err := parseBTCVectorKeypath(config.Keypath)
	if err != nil {
		return nil, err
	}
	return &messages.BTCScriptConfigWithKeypath{
		ScriptConfig: converted,
		Keypath:      keypath,
	}, nil
}

func convertBTCVectorPaymentRequest(
	paymentRequest btcTestVectorPaymentRequest,
) (*messages.BTCPaymentRequestRequest, error) {
	nonce, err := hex.DecodeString(paymentRequest.Nonce)
	if err != nil {
		return nil, err
	}
	signature, err := hex.DecodeString(paymentRequest.Signature)
	if err != nil {
		return nil, err
	}

	memos := make([]*messages.BTCPaymentRequestRequest_Memo, len(paymentRequest.Memos))
	for index, memo := range paymentRequest.Memos {
		switch memo.Type {
		case "text":
			memos[index] = &messages.BTCPaymentRequestRequest_Memo{
				Memo: &messages.BTCPaymentRequestRequest_Memo_TextMemo_{
					TextMemo: &messages.BTCPaymentRequestRequest_Memo_TextMemo{Note: memo.Note},
				},
			}
		case "coin_purchase":
			keypath, err := parseBTCVectorKeypath(memo.AddressKeypath)
			if err != nil {
				return nil, err
			}
			memos[index] = &messages.BTCPaymentRequestRequest_Memo{
				Memo: &messages.BTCPaymentRequestRequest_Memo_CoinPurchaseMemo_{
					CoinPurchaseMemo: &messages.BTCPaymentRequestRequest_Memo_CoinPurchaseMemo{
						CoinType: memo.CoinType,
						Amount:   memo.Amount,
						Address:  memo.Address,
						AddressDerivation: &messages.BTCPaymentRequestRequest_Memo_CoinPurchaseMemo_Eth{
							Eth: &messages.BTCPaymentRequestRequest_Memo_CoinPurchaseMemo_EthAddressDerivation{
								Keypath: keypath,
							},
						},
					},
				},
			}
		default:
			return nil, fmt.Errorf("unknown payment request memo type %q", memo.Type)
		}
	}

	return &messages.BTCPaymentRequestRequest{
		RecipientName: paymentRequest.RecipientName,
		Nonce:         nonce,
		TotalAmount:   paymentRequest.TotalAmount,
		Memos:         memos,
		Signature:     signature,
	}, nil
}

func convertBTCVectorPSBTOptions(options btcTestVectorPSBTSignOptions) (*PSBTSignOptions, error) {
	formatUnit, err := btcTestVectorFormatUnit(options.FormatUnit)
	if err != nil {
		return nil, err
	}
	if options.ForceScriptConfig == nil && len(options.Outputs) == 0 &&
		len(options.PaymentRequests) == 0 && formatUnit == messages.BTCSignInitRequest_DEFAULT {
		return nil, nil
	}
	result := &PSBTSignOptions{
		FormatUnit: formatUnit,
		Outputs:    make(map[int]*PSBTSignOutputOptions, len(options.Outputs)),
	}
	if options.ForceScriptConfig != nil {
		result.ForceScriptConfig, err = convertBTCVectorScriptConfigWithKeypath(*options.ForceScriptConfig)
		if err != nil {
			return nil, err
		}
	}
	for index, output := range options.Outputs {
		result.Outputs[index] = &PSBTSignOutputOptions{
			SilentPaymentAddress: output.SilentPaymentAddress,
			PaymentRequestIndex:  output.PaymentRequestIndex,
		}
	}
	result.PaymentRequests = make([]*messages.BTCPaymentRequestRequest, len(options.PaymentRequests))
	for index, paymentRequest := range options.PaymentRequests {
		result.PaymentRequests[index], err = convertBTCVectorPaymentRequest(paymentRequest)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func registerBTCVectorConfigs(
	device *Device,
	coin messages.BTCCoin,
	registrations []btcTestVectorRegistration,
) error {
	for index := range registrations {
		registration := &registrations[index]
		scriptConfig, err := convertBTCVectorScriptConfig(registration.ScriptConfig)
		if err != nil {
			return err
		}
		var keypath []uint32
		if registration.Keypath != nil {
			keypath, err = parseBTCVectorKeypath(*registration.Keypath)
			if err != nil {
				return err
			}
		}
		registered, err := device.BTCIsScriptConfigRegistered(coin, scriptConfig, keypath)
		if err != nil {
			return err
		}
		if registered {
			return fmt.Errorf("script config %q is already registered", registration.Name)
		}
		if err := device.BTCRegisterScriptConfig(coin, scriptConfig, keypath, registration.Name); err != nil {
			return err
		}
	}
	return nil
}

func decodeBTCVectorPSBT(encoded string) (*psbt.Packet, error) {
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return psbt.NewFromRawBytes(bytes.NewReader(decoded), false)
}

func btcTestVectorSighashName(sighash txscript.SigHashType) (btcTestVectorSighash, error) {
	switch sighash {
	case txscript.SigHashAll:
		return btcTestVectorSighashAll, nil
	case txscript.SigHashDefault:
		return btcTestVectorSighashDefault, nil
	default:
		return "", fmt.Errorf("unexpected signature sighash 0x%x", uint32(sighash))
	}
}

func btcTestVectorTaprootSignatureSighash(signature []byte) (btcTestVectorSighash, error) {
	if len(signature) != schnorr.SignatureSize && len(signature) != schnorr.SignatureSize+1 {
		return "", fmt.Errorf("unexpected Taproot signature length %d", len(signature))
	}
	if _, err := schnorr.ParseSignature(signature[:schnorr.SignatureSize]); err != nil {
		return "", err
	}
	if len(signature) == schnorr.SignatureSize {
		return btcTestVectorSighashDefault, nil
	}
	return btcTestVectorSighashName(txscript.SigHashType(signature[schnorr.SignatureSize]))
}

func btcTestVectorObservedSignatureSlots(
	packet *psbt.Packet,
) ([]btcTestVectorSignature, error) {
	result := []btcTestVectorSignature{}
	for inputIndex := range packet.Inputs {
		input := &packet.Inputs[inputIndex]
		for _, partialSignature := range input.PartialSigs {
			if len(partialSignature.Signature) < 2 {
				return nil, fmt.Errorf("input %d contains an empty ECDSA signature", inputIndex)
			}
			if _, err := btcec.ParsePubKey(partialSignature.PubKey); err != nil {
				return nil, err
			}
			if _, err := ecdsa.ParseDERSignature(partialSignature.Signature[:len(partialSignature.Signature)-1]); err != nil {
				return nil, err
			}
			sighash, err := btcTestVectorSighashName(
				txscript.SigHashType(partialSignature.Signature[len(partialSignature.Signature)-1]),
			)
			if err != nil {
				return nil, err
			}
			result = append(result, btcTestVectorSignature{
				InputIndex: inputIndex,
				Kind:       btcTestVectorSignatureECDSA,
				Pubkey:     hex.EncodeToString(partialSignature.PubKey),
				Sighash:    sighash,
			})
		}
		if input.TaprootKeySpendSig != nil {
			sighash, err := btcTestVectorTaprootSignatureSighash(input.TaprootKeySpendSig)
			if err != nil {
				return nil, err
			}
			result = append(result, btcTestVectorSignature{
				InputIndex: inputIndex,
				Kind:       btcTestVectorSignatureTaprootKey,
				Pubkey:     hex.EncodeToString(input.TaprootInternalKey),
				Sighash:    sighash,
			})
		}
		for _, taprootSignature := range input.TaprootScriptSpendSig {
			if _, err := schnorr.ParseSignature(taprootSignature.Signature); err != nil {
				return nil, err
			}
			sighash, err := btcTestVectorSighashName(taprootSignature.SigHash)
			if err != nil {
				return nil, err
			}
			result = append(result, btcTestVectorSignature{
				InputIndex: inputIndex,
				Kind:       btcTestVectorSignatureTaprootScript,
				Pubkey:     hex.EncodeToString(taprootSignature.XOnlyPubKey),
				LeafHash:   hex.EncodeToString(taprootSignature.LeafHash),
				Sighash:    sighash,
			})
		}
	}
	return result, nil
}

func btcTestVectorInsertedSignatureSlots(
	before []btcTestVectorSignature,
	after []btcTestVectorSignature,
) ([]btcTestVectorSignature, error) {
	remaining := make(map[btcTestVectorSignature]int, len(after))
	for _, signature := range after {
		remaining[signature]++
	}
	for _, signature := range before {
		if remaining[signature] == 0 {
			return nil, fmt.Errorf("signing removed or changed signature slot %+v", signature)
		}
		remaining[signature]--
	}

	inserted := make([]btcTestVectorSignature, 0, len(after)-len(before))
	for signature, count := range remaining {
		for range count {
			inserted = append(inserted, signature)
		}
	}
	return inserted, nil
}

func btcTestVectorECDSAScriptCode(input *psbt.PInput, pubkey []byte) ([]byte, error) {
	// Firmware ECDSA inputs are P2WPKH or P2WSH, either native or nested in P2SH.
	if len(input.WitnessScript) > 0 {
		return input.WitnessScript, nil
	}
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_DUP).
		AddOp(txscript.OP_HASH160).
		AddData(address.Hash160(pubkey)).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_CHECKSIG).
		Script()
}

// assertBTCVectorInsertedSignature verifies a signature against its exact PSBT input sighash.
func assertBTCVectorInsertedSignature(
	t *testing.T,
	packet *psbt.Packet,
	slot btcTestVectorSignature,
) {
	t.Helper()
	input := &packet.Inputs[slot.InputIndex]
	tx := packet.UnsignedTx
	prevOutputs := psbtPrevoutFetcher{psbt: packet}
	sigHashes := txscript.NewTxSigHashes(tx, prevOutputs)
	prevOutput := prevOutputs.FetchPrevOutput(tx.TxIn[slot.InputIndex].PreviousOutPoint)

	switch slot.Kind {
	case btcTestVectorSignatureECDSA:
		var partialSignature *psbt.PartialSig
		for _, candidate := range input.PartialSigs {
			if hex.EncodeToString(candidate.PubKey) != slot.Pubkey {
				continue
			}
			partialSignature = candidate
			break
		}
		require.NotNil(t, partialSignature)
		scriptCode, err := btcTestVectorECDSAScriptCode(input, partialSignature.PubKey)
		require.NoError(t, err)
		signatureBytes := partialSignature.Signature
		sighash, err := txscript.CalcWitnessSigHash(
			scriptCode,
			sigHashes,
			txscript.SigHashType(signatureBytes[len(signatureBytes)-1]),
			tx,
			slot.InputIndex,
			prevOutput.Value,
		)
		require.NoError(t, err)
		signature, err := ecdsa.ParseDERSignature(signatureBytes[:len(signatureBytes)-1])
		require.NoError(t, err)
		pubkey, err := btcec.ParsePubKey(partialSignature.PubKey)
		require.NoError(t, err)
		require.True(t, signature.Verify(sighash, pubkey))
	case btcTestVectorSignatureTaprootKey:
		witnessVersion, outputKey, err := txscript.ExtractWitnessProgramInfo(prevOutput.PkScript)
		require.NoError(t, err)
		require.Equal(t, 1, witnessVersion)
		require.NoError(t, txscript.VerifyTaprootKeySpend(
			outputKey,
			input.TaprootKeySpendSig,
			tx,
			slot.InputIndex,
			prevOutputs,
			sigHashes,
			nil,
		))
	case btcTestVectorSignatureTaprootScript:
		var scriptSignature *psbt.TaprootScriptSpendSig
		for _, candidate := range input.TaprootScriptSpendSig {
			if hex.EncodeToString(candidate.XOnlyPubKey) != slot.Pubkey ||
				hex.EncodeToString(candidate.LeafHash) != slot.LeafHash {
				continue
			}
			scriptSignature = candidate
			break
		}
		require.NotNil(t, scriptSignature)
		leafScript, err := psbt.FindLeafScript(input, scriptSignature.LeafHash)
		require.NoError(t, err)
		sighash, err := txscript.CalcTapscriptSignaturehash(
			sigHashes,
			scriptSignature.SigHash,
			tx,
			slot.InputIndex,
			prevOutputs,
			txscript.NewTapLeaf(leafScript.LeafVersion, leafScript.Script),
		)
		require.NoError(t, err)
		signature, err := schnorr.ParseSignature(scriptSignature.Signature)
		require.NoError(t, err)
		pubkey, err := schnorr.ParsePubKey(scriptSignature.XOnlyPubKey)
		require.NoError(t, err)
		require.True(t, signature.Verify(sighash, pubkey))
	default:
		require.Failf(t, "unsupported signature kind", "%q", slot.Kind)
	}
}

func changedBTCVectorPSBTOutputs(before [][]byte, packet *psbt.Packet) map[int]string {
	var result map[int]string
	for index, output := range packet.UnsignedTx.TxOut {
		if !bytes.Equal(before[index], output.PkScript) {
			if result == nil {
				result = map[int]string{}
			}
			result[index] = hex.EncodeToString(output.PkScript)
		}
	}
	return result
}

func assertBTCVectorSignOutcome(
	t *testing.T,
	err error,
	vectorID string,
	expectation *btcTestVectorVersionExpectation,
) bool {
	t.Helper()
	switch expectation.Outcome {
	case btcTestVectorOutcomeSuccess:
		if vectorID == "silent-payment-owned-output" {
			// The shared vectors describe firmware behavior. Older firmware accepts silent
			// payment metadata on owned outputs without returning a generated script, but
			// the Go client requires a verified script for every requested silent payment.
			require.EqualError(t, err, "missing generated silent payment output")
			return false
		}
		require.NoError(t, err)
		return true
	case btcTestVectorOutcomeUnsupported:
		require.NotNil(t, expectation.UnsupportedVersion)
		require.EqualError(t, err, UnsupportedError(*expectation.UnsupportedVersion).Error())
		return false
	case btcTestVectorOutcomeInvalidInput:
		require.Error(t, err)
		require.Truef(
			t,
			isErrorCode(err, ErrInvalidInput),
			"expected invalid input, got %T: %v",
			err,
			err,
		)
		return false
	default:
		require.Failf(t, "unknown Bitcoin test vector outcome", "%q", expectation.Outcome)
		return false
	}
}

func assertBTCVectorSetupOutcome(
	t *testing.T,
	err error,
	expectation *btcTestVectorVersionExpectation,
) {
	t.Helper()
	switch expectation.Outcome {
	case btcTestVectorOutcomeSuccess:
		require.NoError(t, err)
	case btcTestVectorOutcomeUnsupported:
		require.NotNil(t, expectation.UnsupportedVersion)
		require.Error(t, err)
		clientUnsupported := err.Error() == UnsupportedError(*expectation.UnsupportedVersion).Error()
		deviceUnsupported := isErrorCode(err, ErrInvalidInput) ||
			isErrorCode(err, ErrDisabled)
		require.Truef(
			t,
			clientUnsupported || deviceUnsupported,
			"expected unsupported setup error for firmware before %s, got %T: %v",
			*expectation.UnsupportedVersion,
			err,
			err,
		)
	case btcTestVectorOutcomeInvalidInput:
		require.Error(t, err)
		require.Truef(
			t,
			isErrorCode(err, ErrInvalidInput),
			"expected invalid input, got %T: %v",
			err,
			err,
		)
	default:
		require.Failf(t, "unknown Bitcoin test vector outcome", "%q", expectation.Outcome)
	}
}

func runBTCPSBTTestVector(
	t *testing.T,
	device *Device,
	coin messages.BTCCoin,
	vector *btcTestVector,
	expectation *btcTestVectorVersionExpectation,
) {
	t.Helper()
	packet, err := decodeBTCVectorPSBT(vector.PSBT.Transaction)
	require.NoError(t, err)
	options, err := convertBTCVectorPSBTOptions(vector.PSBT.Options)
	require.NoError(t, err)
	beforeSignatures, err := btcTestVectorObservedSignatureSlots(packet)
	require.NoError(t, err)

	needsNonWitnessUTXOs, err := device.BTCSignNeedsNonWitnessUTXOs(packet, options)
	require.NoError(t, err)
	require.Equal(t, vector.ExpectedNeedsPrevTxs, needsNonWitnessUTXOs)

	outputScriptsBefore := make([][]byte, len(packet.UnsignedTx.TxOut))
	for index, output := range packet.UnsignedTx.TxOut {
		outputScriptsBefore[index] = append([]byte(nil), output.PkScript...)
	}
	err = device.BTCSignPSBT(coin, packet, options)
	afterSignatures, signaturesErr := btcTestVectorObservedSignatureSlots(packet)
	require.NoError(t, signaturesErr)
	if !assertBTCVectorSignOutcome(t, err, vector.ID, expectation) {
		require.ElementsMatch(
			t,
			beforeSignatures,
			afterSignatures,
			"failed signing changed PSBT signatures",
		)
		require.Empty(t, changedBTCVectorPSBTOutputs(outputScriptsBefore, packet),
			"failed signing changed PSBT outputs")
		return
	}

	insertedSignatures, err := btcTestVectorInsertedSignatureSlots(beforeSignatures, afterSignatures)
	require.NoError(t, err)
	require.ElementsMatch(t, vector.ExpectedSignatures, insertedSignatures)
	for _, signature := range insertedSignatures {
		assertBTCVectorInsertedSignature(t, packet, signature)
	}

	require.Equal(t, vector.ExpectedGeneratedOutputs, changedBTCVectorPSBTOutputs(outputScriptsBefore, packet))
}

func runBTCTransactionTestVector(
	t *testing.T,
	device *Device,
	stdout *simulatorStdout,
	vector *btcTestVector,
) {
	t.Helper()
	expectation := btcTestVectorExpectation(vector.Expectations, device.Version())
	if expectation == nil {
		if len(vector.Expectations) > 0 {
			minVersion := vector.Expectations[0].MinVersion
			if minVersion != nil && !device.Version().AtLeast(minVersion) {
				t.Skipf("vector is not applicable to firmware %s", device.Version())
			}
		}
		t.Fatalf("no vector expectation matches firmware %s", device.Version())
		return
	}

	coin, err := btcTestVectorCoin(vector.Coin)
	require.NoError(t, err)
	setupErr := registerBTCVectorConfigs(device, coin, vector.Registrations)
	require.NoError(t, stdout.waitUntilStable(btcVectorStdoutStableFor, btcVectorStdoutTimeout))

	screenCapture := newSimulatorScreenCapture(stdout)
	if setupErr != nil {
		assertBTCVectorSetupOutcome(t, setupErr, expectation)
	} else {
		runBTCPSBTTestVector(t, device, coin, vector, expectation)
	}
	var screens []simulatorScreen
	if setupErr == nil && expectation.Outcome == btcTestVectorOutcomeSuccess {
		screens, err = screenCapture.waitForTerminalStatus(btcVectorStdoutStableFor, btcVectorStdoutTimeout)
	} else {
		require.NoError(t, stdout.waitUntilStable(btcVectorStdoutStableFor, btcVectorStdoutTimeout))
		screens, err = screenCapture.screensSinceCheckpoint()
	}
	require.NoError(t, err)
	require.Equal(t, expectation.Screens, screens)
}

func TestSimulatorBTCTransactionVectors(t *testing.T) {
	vectors := loadBTCTransactionTestVectors(t)
	for vectorIndex := range vectors {
		vector := &vectors[vectorIndex]
		t.Run(vector.ID, func(t *testing.T) {
			t.Log(vector.Description)
			testInitializedSimulators(t, func(t *testing.T, device *Device, stdout *simulatorStdout) {
				t.Helper()
				runBTCTransactionTestVector(t, device, stdout, vector)
			})
		})
	}
}

func TestBTCVectorPaymentRequestSighash(t *testing.T) {
	vectors := loadBTCTransactionTestVectors(t)
	var vector *btcTestVector
	for index := range vectors {
		if vectors[index].ID == "payment-request" {
			vector = &vectors[index]
			break
		}
	}
	require.NotNil(t, vector)

	packet, err := decodeBTCVectorPSBT(vector.PSBT.Transaction)
	require.NoError(t, err)
	paymentRequest, err := convertBTCVectorPaymentRequest(vector.PSBT.Options.PaymentRequests[0])
	require.NoError(t, err)

	outputIndex := -1
	for index, output := range vector.PSBT.Options.Outputs {
		if output.PaymentRequestIndex != nil && *output.PaymentRequestIndex == 0 {
			outputIndex = index
			break
		}
	}
	require.NotEqual(t, -1, outputIndex)
	output := packet.UnsignedTx.TxOut[outputIndex]
	_, addresses, _, err := txscript.ExtractPkScriptAddrs(output.PkScript, &chaincfg.TestNet3Params)
	require.NoError(t, err)
	require.Len(t, addresses, 1)

	sighash, err := ComputePaymentRequestSighash(
		paymentRequest,
		1,
		uint64(output.Value),
		addresses[0].EncodeAddress(),
	)
	require.NoError(t, err)
	privateKey, _ := btcec.PrivKeyFromBytes([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	signature := ecdsa.SignCompact(privateKey, sighash, true)
	require.Equal(t, paymentRequest.Signature, signature[1:])
}
