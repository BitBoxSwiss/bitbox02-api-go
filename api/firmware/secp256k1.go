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

package firmware

import (
	"bytes"
	"crypto/sha256"
	"math/big"

	"github.com/BitBoxSwiss/bitbox02-api-go/util/errp"
	"github.com/btcsuite/btcd/btcec/v2"
)

func taggedSha256(tag []byte, msg []byte) []byte {
	h := sha256.New()
	tagHash := sha256.Sum256(tag)
	h.Write(tagHash[:]) //nolint:errcheck
	h.Write(tagHash[:]) //nolint:errcheck
	h.Write(msg)        //nolint:errcheck
	return h.Sum(nil)
}

func antikleptoHostCommit(hostNonce []byte) []byte {
	return taggedSha256([]byte("s2c/ecdsa/data"), hostNonce)
}

// antikleptoVerify verifies that hostNonce was used to tweak the nonce during signature
// generation according to k' = k + H(clientCommitment, hostNonce) by checking that
// k'*G = signerCommitment + H(signerCommitment, hostNonce)*G.
func antikleptoVerify(hostNonce, signerCommitment, signature []byte) error {
	signerCommitmentPubkey, err := btcec.ParsePubKey(signerCommitment)
	if err != nil {
		return errp.WithStack(err)
	}
	curve := btcec.S256()
	// Compute R = R1 + H(R1, host_nonce)*G.
	tweak := taggedSha256([]byte("s2c/ecdsa/point"), append(signerCommitmentPubkey.SerializeCompressed(), hostNonce...))
	tx, ty := curve.ScalarBaseMult(tweak)
	x, _ := curve.Add(signerCommitmentPubkey.X(), signerCommitmentPubkey.Y(), tx, ty)
	x.Mod(x, curve.Params().N)
	signatureR := big.NewInt(0).SetBytes(signature[:32])
	if x.Cmp(signatureR) != 0 {
		return errp.New("Could not verify that the host nonce was contributed to the signature. " +
			"If this happens repeatedly, the device might be attempting to leak the " +
			"seed through the signature.")
	}
	return nil
}

// Verifies a DLEQ proof.
//
// A DLEQ (discrete log equivalence) proof proves that the discrete log of p1 to the secp256k1 base
// G is the same as the discrete log of p2 to another base gen2.
//
// Same as
// https://github.com/BlockstreamResearch/secp256k1-zkp/blob/6152622613fdf1c5af6f31f74c427c4e9ee120ce/src/modules/ecdsa_adaptor/dleq_impl.h#L129
// with default noncefp and ndata==NULL).
func DLEQVerify(proof []byte, p1, gen2, p2 *btcec.PublicKey) error {
	if len(proof) != 64 {
		return errp.New("proof must be 64 bytes")
	}
	s := proof[:32]
	e := proof[32:]
	curve := btcec.S256()

	// R1 = s*G  - e*P1
	sPubX, sPubY := curve.ScalarBaseMult(s)
	eP1X, eP1Y := curve.ScalarMult(p1.X(), p1.Y(), e)
	// Negate eP1
	eP1Y = new(big.Int).Sub(curve.P, eP1Y)
	r1PubX, r1PubY := curve.Add(sPubX, sPubY, eP1X, eP1Y)

	/* R2 = s*gen2 - e*P2 */
	sGen2X, sGen2Y := curve.ScalarMult(gen2.X(), gen2.Y(), s)
	eP2X, eP2Y := curve.ScalarMult(p2.X(), p2.Y(), e)
	// Negate eP2
	eP2Y = new(big.Int).Sub(curve.P, eP2Y)
	r2PubX, r2PubY := curve.Add(sGen2X, sGen2Y, eP2X, eP2Y)

	toPub := func(x, y *big.Int) *btcec.PublicKey {
		var xx, yy btcec.FieldVal
		xx.SetByteSlice(x.Bytes())
		yy.SetByteSlice(y.Bytes())
		return btcec.NewPublicKey(&xx, &yy)
	}
	challenge := func() *big.Int {
		var b bytes.Buffer
		b.Write(p1.SerializeCompressed())
		b.Write(gen2.SerializeCompressed())
		b.Write(p2.SerializeCompressed())
		b.Write(toPub(r1PubX, r1PubY).SerializeCompressed())
		b.Write(toPub(r2PubX, r2PubY).SerializeCompressed())
		hash := taggedSha256([]byte("DLEQ"), b.Bytes())
		return new(big.Int).SetBytes(hash)
	}
	modEqual := func(x, y, n *big.Int) bool {
		return new(big.Int).Mod(x, n).Cmp(new(big.Int).Mod(y, n)) == 0
	}
	eExpected := challenge()
	eInt := new(big.Int).SetBytes(e)
	if !modEqual(eExpected, eInt, curve.N) {
		return errp.New("DLEQ proof verification failed")
	}
	return nil
}
