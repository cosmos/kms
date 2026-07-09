// Package awskms implements a signing key backed by an AWS KMS asymmetric
// key. The private key never leaves KMS: signing is performed by the KMS Sign
// API. Ed25519 (ECC_NIST_EDWARDS25519 + ED25519_SHA_512, PureEdDSA over the
// canonical sign-bytes) and secp256k1 (ECC_SECG_P256K1 + ECDSA_SHA_256) are the
// supported key algorithms; see algo.go for the per-algorithm seam.
package awskms

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/cosmos/kms/config"
)

// Config describes how to reach a signing key in AWS KMS. Credentials are
// resolved by the standard AWS default chain (environment, shared config, SSO,
// container/instance role); no secret material is read from this struct.
type Config struct {
	KeyID     string           // KMS key id, ARN, or alias/<name>
	Region    string           // optional; falls back to the AWS default chain
	Profile   string           // optional shared-config profile
	Endpoint  string           // optional endpoint override (LocalStack / testing)
	Algorithm config.Algorithm // key algorithm; defaults to "ed25519"
}

// kmsAPI is the subset of the AWS KMS client kms uses. *kms.Client
// satisfies it; tests inject a fake.
type kmsAPI interface {
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}

// The concrete AWS KMS client must satisfy the interface we depend on.
var _ kmsAPI = (*kms.Client)(nil)
