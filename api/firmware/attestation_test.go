// SPDX-License-Identifier: Apache-2.0

package firmware

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/common"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/mocks"
	"github.com/BitBoxSwiss/bitbox02-api-go/util/semver"
	"github.com/btcsuite/btcd/btcec/v2"
	btcec_ecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/stretchr/testify/require"
)

// addAttestationPubkey temporarily modifies the attestation pubkeys list to add a mock entry for
// testing.
func addAttestationPubkey(pubkeyHex string) func() {
	hash := sha256.Sum256(unhex(pubkeyHex))
	identifier := hex.EncodeToString(hash[:])
	attestationPubkeysMap[identifier] = pubkeyHex
	return func() {
		delete(attestationPubkeysMap, identifier)
	}
}

func makeCertificate(rootPrivkey *btcec.PrivateKey, bootloaderHash []byte, devicePubkey []byte) []byte {
	var certMsg bytes.Buffer
	certMsg.Write(bootloaderHash)
	certMsg.Write(devicePubkey)
	sigHash := sha256.Sum256(certMsg.Bytes())
	signature, err := btcec_ecdsa.SignCompact(rootPrivkey, sigHash[:], true)
	if err != nil {
		panic(err)
	}
	return signature[1:]
}

// adapted from ecdsa.GenerateKey()
func p256PrivKeyFromBytes(k []byte) *ecdsa.PrivateKey {
	priv := new(ecdsa.PrivateKey)
	c := elliptic.P256()
	priv.Curve = c
	priv.D = new(big.Int).SetBytes(k)
	priv.X, priv.Y = c.ScalarBaseMult(k)
	return priv
}

func TestAttestation(t *testing.T) {

	// Arbitrary values, they do not have any special meaning.
	// identifier is the sha256 hash of the uncompressed pubkey.
	rootPubkeyIdentifier := unhex("11554d841e74066eebc3556ed6dea4d6ceef3940009222c77c3b966349989de1")
	rootPrivateKey, rootPublicKey := btcec.PrivKeyFromBytes(
		unhex("15608dfed8e876bed1cf2599574ce853f7a2a017d19ba0aabd4bcba033a70880"),
	)
	bootloaderHash := unhex("3fdf2ff2dcbd31d161a525a88cb57641209c7eac2bc014564a03d34a825144f0")
	devicePrivateKey := p256PrivKeyFromBytes(
		unhex("9b1a4d293a6eef1960d8afab5e58dd581b135152ec3399bde9268fa23051321b"),
	)
	devicePublicKey := devicePrivateKey.PublicKey
	devicePubkeyBytes := make([]byte, 64)
	copy(devicePubkeyBytes[:32], devicePublicKey.X.Bytes())
	copy(devicePubkeyBytes[32:], devicePublicKey.Y.Bytes())

	undo := addAttestationPubkey(hex.EncodeToString(rootPublicKey.SerializeUncompressed()))
	defer undo()

	communication := &mocks.Communication{}
	product := common.ProductBitBox02BTCOnly
	device := NewDevice(
		semver.NewSemVer(2, 0, 0),
		&product,
		&mocks.Config{}, communication, &mocks.Logger{},
	)

	// Query error.
	expectedErr := errors.New("error")
	communication.MockQuery = func([]byte) ([]byte, error) {
		return nil, expectedErr
	}
	_, err := device.performAttestation()
	require.Equal(t, expectedErr, err)

	// Invalid response.
	communication.MockQuery = func([]byte) ([]byte, error) {
		return nil, nil
	}
	success, err := device.performAttestation()
	require.NoError(t, err)
	require.False(t, success)

	// Invalid response status code.
	communication.MockQuery = func([]byte) ([]byte, error) {
		response := make([]byte, 1+32+64+64+32+64)
		response[0] = 0x01
		return response, nil
	}
	success, err = device.performAttestation()
	require.NoError(t, err)
	require.False(t, success)

	// Unknown pubkey
	communication.MockQuery = func([]byte) ([]byte, error) {
		var buf bytes.Buffer
		buf.Write(make([]byte, 32)) // bootloaderHash
		buf.Write(make([]byte, 64)) // devicePubkeyBytes
		buf.Write(make([]byte, 64)) // certificate
		buf.Write(make([]byte, 32)) // rootPubkeyIdentifier
		buf.Write(make([]byte, 64)) // challengeSignature
		return buf.Bytes(), nil
	}
	success, err = device.performAttestation()
	require.NoError(t, err)
	require.False(t, success)

	// Known pubkey, wrong bootloader hash
	communication.MockQuery = func([]byte) ([]byte, error) {
		var buf bytes.Buffer
		buf.WriteByte(0x00)             // opSuccess
		buf.Write(make([]byte, 32))     // bootloaderHash
		buf.Write(make([]byte, 64))     // devicePubkeyBytes
		buf.Write(make([]byte, 64))     // certificate
		buf.Write(rootPubkeyIdentifier) // rootPubkeyIdentifier
		buf.Write(make([]byte, 64))     // challengeSignature
		return buf.Bytes(), nil
	}
	success, err = device.performAttestation()
	require.NoError(t, err)
	require.False(t, success)

	// Known pubkey, right bootloader hash, wrong certificate
	communication.MockQuery = func([]byte) ([]byte, error) {
		var buf bytes.Buffer
		buf.WriteByte(0x00)             // opSuccess
		buf.Write(bootloaderHash)       // bootloaderHash
		buf.Write(make([]byte, 64))     // devicePubkeyBytes
		buf.Write(make([]byte, 64))     // certificate
		buf.Write(rootPubkeyIdentifier) // rootPubkeyIdentifier
		buf.Write(make([]byte, 64))     // challengeSignature
		return buf.Bytes(), nil
	}
	success, err = device.performAttestation()
	require.NoError(t, err)
	require.False(t, success)

	// Known pubkey, right bootloader hash, right certificate, invalid challenge sig.
	certificate := makeCertificate(rootPrivateKey, bootloaderHash, devicePubkeyBytes)
	communication.MockQuery = func([]byte) ([]byte, error) {
		var buf bytes.Buffer
		buf.WriteByte(0x00)             // opSuccess
		buf.Write(bootloaderHash)       // bootloaderHash
		buf.Write(devicePubkeyBytes)    // devicePubkeyBytes
		buf.Write(certificate)          // certificate
		buf.Write(rootPubkeyIdentifier) // rootPubkeyIdentifier
		buf.Write(make([]byte, 64))     // challengeSignature
		return buf.Bytes(), nil
	}
	success, err = device.performAttestation()
	require.NoError(t, err)
	require.False(t, success)

	// Known pubkey, right bootloader hash, right certificate, correct challenge sig.
	communication.MockQuery = func(msg []byte) ([]byte, error) {
		challenge := msg[1:]
		sigHash := sha256.Sum256(challenge)
		sigR, sigS, err := ecdsa.Sign(rand.Reader, devicePrivateKey, sigHash[:])
		if err != nil {
			panic(err)
		}

		var buf bytes.Buffer
		buf.WriteByte(0x00)             // opSuccess
		buf.Write(bootloaderHash)       // bootloaderHash
		buf.Write(devicePubkeyBytes)    // devicePubkeyBytes
		buf.Write(certificate)          // certificate
		buf.Write(rootPubkeyIdentifier) // rootPubkeyIdentifier
		// challengeSignature
		buf.Write(sigR.Bytes())
		buf.Write(sigS.Bytes())
		return buf.Bytes(), nil
	}
	success, err = device.performAttestation()
	require.NoError(t, err)
	require.True(t, success)
}
