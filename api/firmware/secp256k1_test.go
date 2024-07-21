package firmware

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestTaggedSha256(t *testing.T) {
	require.Equal(t,
		unhex("025ee06f5a2db377bd9d7040bae8f6e0ab49784f9c68a1380fba5465d8a99928"),
		taggedSha256([]byte("test tag"), []byte("test message")),
	)
}

func TestAntikleptoHostCommit(t *testing.T) {
	hostNonce := unhex("e8011345fe4851538c30c1fc1a215395e8063fcf6fbdcf8fab9a42e466a74f4a")
	require.Equal(t,
		unhex("70a8934f41a1679b4c715c3e6db17f785b67da4e398107a0a00c828980a4be2f"),
		antikleptoHostCommit(hostNonce),
	)
}

func TestAntikleptoVerify(t *testing.T) {
	// Fixtures made by running the protocol and recording the values.
	// A high-level test is too hard to write in Go, as it does not easily allow to make a
	// signature with a custom nonce.
	for _, test := range []struct {
		hostNonce        []byte
		signerCommitment []byte
		signature        []byte
	}{
		{
			hostNonce:        unhex("8b4c26aa2695a34bdbc34235f6c91be14b93037a063b13f7c814101359561092"),
			signerCommitment: unhex("0236ff92fe02c08d0d04851e0ce1516104085215f05a178307de60ea53e207f971"),
			signature:        unhex("7fd66b48ffea2fe048869880bbb3a1819e262af14980e8885df1e5765750cb8f47e01eca356377870356d54853573a955076228e5044cd3dd3a049abe70d5585"),
		},
		{
			hostNonce:        unhex("9c9471aa529fbad96396b9379938e56195c5aa8e1e22b6e87d226e49d8b1f581"),
			signerCommitment: unhex("034e2979d398ce029996ffe99dc310a0f2cf9a5411b166f57a85fc3a24985f16be"),
			signature:        unhex("48cb61d08c730e36b0285dfd9ece91e88a5ec0898d1c80b93e85b967e0ddcd195ab807640347e8f96e3fad67a971fc52eb4f15b4fa65577bcf4a053e598d057d"),
		},
	} {
		require.NoError(t, antikleptoVerify(test.hostNonce, test.signerCommitment, test.signature))

		// Tweak an input a bit to fail verification.
		test.hostNonce[0]++
		require.Error(t, antikleptoVerify(test.hostNonce, test.signerCommitment, test.signature))
	}
}

func TestDLEQVerify(t *testing.T) {
	// secret key sk=077eb75a52eca24cdedf058c92f1ca8b9d4841771fd6baa3d27885fb5b49fba2
	// is the secret key in pubKey=sk*G and otherPubKey=sk*otherBase.
	//
	// Test fixture created by running dleq_verify() in
	// https://github.com/BlockstreamResearch/secp256k1-zkp/blob/6152622613fdf1c5af6f31f74c427c4e9ee120ce/src/modules/ecdsa_adaptor/dleq_impl.h
	// with the above secret key, p1 being sk*G,
	// 0389140f7bb852f020f154e55908fe3699dc9f65153e681527f0d55aabed937f4b for gen2, and p2=sk*gen2.

	proof := unhex("6c885f825f6ce7565bc6d0bfda90506b11e2682dfe943f5a85badf1c8a96edc5f5e03f5ee2c58bf979646fbada920f9f1c5bd92805fb5b01534b42d26a550f79")
	pubKey, err := btcec.ParsePubKey(unhex("021b8594084a12da837a78f9337e3d29169025a8ddbe9f9933a131607c6e62d21e"))
	require.NoError(t, err)
	otherBase, err := btcec.ParsePubKey(unhex("0389140f7bb852f020f154e55908fe3699dc9f65153e681527f0d55aabed937f4b"))
	require.NoError(t, err)
	otherPubKey, err := btcec.ParsePubKey(unhex("03019807775b92c83d24e3001b55f60373e0bdc7d7cc7bc86befecf5bb987b54ac"))
	require.NoError(t, err)
	require.NoError(t, DLEQVerify(proof, pubKey, otherBase, otherPubKey))
}
