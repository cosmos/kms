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
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/stretchr/testify/require"

	pb "github.com/cosmos/kms/gen/signerservice"
)

// TestLocalStackSecp256k1Roundtrip exercises both secp256k1 paths against real
// KMS semantics: the consensus Backend (RAW message, KMS SHA-256, 64-byte r‖s
// low-S verified by cometbft) and the gRPC Secp256k1Signer (DIGEST message,
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

	be, err := open(ctx, client, keyID, algos[algoSecp256k1])
	require.NoError(t, err)

	// Consensus path: 64-byte r‖s low-S, verified by the cometbft secp pubkey.
	pub, err := be.PubKey(ctx)
	require.NoError(t, err)
	msg := []byte("localstack secp consensus sign-bytes")
	sig, err := be.Sign(ctx, msg)
	require.NoError(t, err)
	require.Len(t, sig, 64)
	require.True(t, pub.VerifySignature(msg, sig))

	// gRPC path: 65-byte recoverable signature over a 32-byte digest.
	gs, err := newSecp256k1Signer(be)
	require.NoError(t, err)
	require.Equal(t, pb.SignatureScheme_ECDSA_SECP256K1, gs.Scheme())
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
