//go:build localstack

// Package awskms LocalStack integration test. Run with:
//
//	KMS_AWSKMS_ENDPOINT=http://localhost:4566 \
//	  go test -tags localstack ./signing/awskms/ -run TestLocalStack -v
//
// Requires a LocalStack instance with KMS. It auto-skips if the endpoint is
// unreachable or if LocalStack does not support the ECC_NIST_EDWARDS25519 key
// spec (AWS shipped Ed25519 KMS keys in Nov 2025; older LocalStack lacks it).
package awskms

import (
	"context"
	"crypto/ed25519"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/require"

	pb "github.com/cosmos/kms/gen/signerservice"
)

func endpoint() string {
	if e := os.Getenv("KMS_AWSKMS_ENDPOINT"); e != "" {
		return e
	}
	return "http://localhost:4566"
}

func localstackClient(t *testing.T) *kms.Client {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
	)
	require.NoError(t, err)
	return kms.NewFromConfig(cfg, func(o *kms.Options) {
		o.BaseEndpoint = aws.String(endpoint())
	})
}

func TestLocalStackSignRoundtrip(t *testing.T) {
	ctx := context.Background()
	client := localstackClient(t)

	created, err := client.CreateKey(ctx, &kms.CreateKeyInput{
		KeySpec:  types.KeySpecEccNistEdwards25519,
		KeyUsage: types.KeyUsageTypeSignVerify,
	})
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "no such host") ||
			strings.Contains(err.Error(), "dial tcp") ||
			strings.Contains(err.Error(), "context deadline exceeded") {
			t.Skipf("LocalStack KMS unreachable at %s: %v", endpoint(), err)
		}
		// Older LocalStack rejects the Ed25519 key spec.
		t.Skipf("LocalStack does not support ECC_NIST_EDWARDS25519: %v", err)
	}
	keyID := aws.ToString(created.KeyMetadata.KeyId)

	s, err := open(ctx, client, keyID, algos[algoEd25519])
	require.NoError(t, err)

	pub, err := s.PubKey(ctx)
	require.NoError(t, err)

	msg := []byte("localstack consensus sign-bytes")
	sig, err := s.Sign(ctx, msg)
	require.NoError(t, err)
	require.True(t, pub.VerifySignature(msg, sig))

	// Same key through the gRPC SignerService adapter: 32-byte pubkey, ED25519
	// scheme, 64-byte signature that the pubkey verifies.
	gs := &Signer{be: s}
	require.Equal(t, pb.SignatureScheme_ED25519, gs.Scheme())
	gpub := gs.PubKey()
	require.Len(t, gpub, ed25519.PublicKeySize)

	gmsg := []byte("localstack signerservice payload")
	gsig, err := gs.Sign(ctx, gmsg)
	require.NoError(t, err)
	require.Len(t, gsig, ed25519.SignatureSize)
	require.True(t, ed25519.Verify(ed25519.PublicKey(gpub), gmsg, gsig))
}
