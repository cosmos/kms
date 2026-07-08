//go:build localstack

package awskms

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	cometsecp "github.com/cometbft/cometbft/crypto/secp256k1"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/stretchr/testify/require"

	"github.com/cosmos/kms/config"
)

// TestLocalStackSecp256k1Roundtrip exercises both secp256k1 algos on the same
// KMS key against real KMS semantics: secp256k1 (RAW message, KMS SHA-256,
// 64-byte r‖s low-S verified by cometbft) and secp256k1eth (DIGEST message,
// 65-byte r‖s‖v that recovers the signing pubkey).
func TestLocalStackSecp256k1Roundtrip(t *testing.T) {
	ctx := context.Background()
	client := localstackClient(t)

	created, err := client.CreateKey(ctx, &kms.CreateKeyInput{
		KeySpec:  types.KeySpecEccSecgP256k1,
		KeyUsage: types.KeyUsageTypeSignVerify,
	})
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "no such host") ||
			strings.Contains(err.Error(), "dial tcp") ||
			strings.Contains(err.Error(), "context deadline exceeded") {
			t.Skipf("LocalStack KMS unreachable at %s: %v", endpoint(), err)
		}
		t.Skipf("LocalStack does not support ECC_SECG_P256K1: %v", err)
	}
	keyID := aws.ToString(created.KeyMetadata.KeyId)

	// Consensus algo: 64-byte r‖s low-S, verified by the cometbft secp pubkey.
	cs, err := open(ctx, client, keyID, algos[config.AlgoSecp256k1])
	require.NoError(t, err)
	require.Equal(t, config.AlgoSecp256k1, cs.Scheme())
	msg := []byte("localstack secp consensus sign-bytes")
	sig, err := cs.Sign(ctx, msg)
	require.NoError(t, err)
	require.Len(t, sig, 64)
	require.True(t, cometsecp.PubKey(cs.PubKey()).VerifySignature(msg, sig))

	// Ethereum algo on the same key: 65-byte recoverable signature over a
	// 32-byte digest.
	gs, err := open(ctx, client, keyID, algos[config.AlgoSecp256k1Eth])
	require.NoError(t, err)
	require.Equal(t, config.AlgoSecp256k1Eth, gs.Scheme())
	require.Len(t, gs.PubKey(), 33)

	digest := sha256.Sum256([]byte("localstack eth digest"))
	rsv, err := gs.Sign(ctx, digest[:])
	require.NoError(t, err)
	require.Len(t, rsv, 65)
	require.LessOrEqual(t, rsv[64], byte(1))

	compact := make([]byte, 65)
	compact[0] = 27 + rsv[64]
	copy(compact[1:], rsv[:64])
	recovered, _, err := ecdsa.RecoverCompact(compact, digest[:])
	require.NoError(t, err)
	require.Equal(t, gs.PubKey(), recovered.SerializeCompressed())
}
