package firmware

import (
	"encoding/hex"
	"testing"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/stretchr/testify/require"
)

// TODO: Add integration test for CoinPurchaseMemo once the firmware UI is implemented.
// potentially in psbt_test.go

func TestComputePaymentRequestSighash_CoinPurchaseMemo(t *testing.T) {
	// This test verifies that our Go sighash computation matches the firmware's Rust implementation.
	// The expected hash comes from a firmware test.
	paymentRequest := &messages.BTCPaymentRequestRequest{
		RecipientName: "Merchant",
		Memos: []*messages.BTCPaymentRequestRequest_Memo{
			{
				Memo: &messages.BTCPaymentRequestRequest_Memo_CoinPurchaseMemo_{
					CoinPurchaseMemo: &messages.BTCPaymentRequestRequest_Memo_CoinPurchaseMemo{
						CoinType: 60, // Ethereum
						Amount:   "0.25 ETH",
						Address:  "0xabc1234567890",
						// address_derivation is intentionally nil, since it's not part of the sighash
					},
				},
			},
		},
		Nonce:       []byte{},
		TotalAmount: 123456,
		Signature:   []byte{},
	}

	sighash, err := ComputePaymentRequestSighash(
		paymentRequest,
		1, // SLIP-44 coin type for Bitcoin Testnet
		123456,
		"tb1q2q0j6gmfxynj40p0kxsr9jkagcvgpuqvqynnup",
	)
	require.NoError(t, err)

	expectedHash := "1806caf7c518aad69eb38f25fd418d507c6a3e01719a7d77be94cd50a2790872"
	actualHash := hex.EncodeToString(sighash)

	require.Equal(t, expectedHash, actualHash, "Sighash mismatch: Go implementation doesn't match firmware")
}
