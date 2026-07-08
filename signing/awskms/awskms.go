// Package awskms implements a signing key backed by an AWS KMS asymmetric
// key. The private key never leaves KMS: signing is performed by the KMS Sign
// API. Ed25519 (ECC_NIST_EDWARDS25519 + ED25519_SHA_512, PureEdDSA over the
// canonical sign-bytes) and secp256k1 (ECC_SECG_P256K1 + ECDSA_SHA_256) are the
// supported key algorithms; see algo.go for the per-algorithm seam.
package awskms

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/cosmos/kms/config"

	"github.com/cometbft/cometbft/crypto"
	cometed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometsecp "github.com/cometbft/cometbft/crypto/secp256k1"
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

// Backend signs via the AWS KMS Sign API for the consensus (privval) path. It is
// stateless beyond the cached public key and is safe for concurrent use (the
// AWS SDK client is concurrency-safe). The gRPC SignerService uses Signer (see
// signer.go), which wraps a *Backend.
type Backend struct {
	client kmsAPI
	keyID  string
	pub    []byte // canonical public key bytes for the algorithm's scheme
	algo   keyAlgo
}

// Open resolves AWS configuration, builds a KMS client, fetches and caches the
// key's public key, and validates its spec against the configured algorithm. Any
// failure is returned (fatal at startup for the chain). It performs one KMS
// GetPublicKey call.
func Open(ctx context.Context, cfg Config) (*Backend, error) {
	algo, ok := algos[cfg.Algorithm]
	if !ok {
		return nil, fmt.Errorf("awskms: unknown algorithm %s", string(cfg.Algorithm))
	}

	var loadOpts []func(*awsconfig.LoadOptions) error
	if cfg.Region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(cfg.Region))
	}
	if cfg.Profile != "" {
		loadOpts = append(loadOpts, awsconfig.WithSharedConfigProfile(cfg.Profile))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("awskms: load AWS config: %w", err)
	}
	client := kms.NewFromConfig(awsCfg, func(o *kms.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
	})
	return open(ctx, client, cfg.KeyID, algo)
}

// open is the client-injectable core of Open: it fetches the public key,
// verifies the key spec, and decodes the public key. Tests call it with a fake
// kmsAPI.
func open(ctx context.Context, client kmsAPI, keyID string, algo keyAlgo) (*Backend, error) {
	out, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, fmt.Errorf("awskms: get public key for %q: %w", keyID, err)
	}
	if out.KeySpec != algo.keySpec {
		return nil, fmt.Errorf("awskms: key %q has spec %q, expected %q for algorithm %q",
			keyID, out.KeySpec, algo.keySpec, algo.name)
	}
	pub, err := algo.decodePub(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("awskms: decode public key for %q: %w", keyID, err)
	}
	return &Backend{client: client, keyID: keyID, pub: pub, algo: algo}, nil
}

// PubKey returns the validator public key cached at Open.
func (s *Backend) PubKey(context.Context) (crypto.PubKey, error) {
	switch s.algo.name {
	case config.AlgoED25519:
		return cometed25519.PubKey(s.pub), nil
	case config.AlgoSecp256k1:
		return cometsecp.PubKey(s.pub), nil
	default:
		return nil, fmt.Errorf("awskms: no cometbft pubkey type for algorithm %s", string(s.algo.name))
	}
}

// sign calls the KMS Sign API and returns the raw signature untouched.
func (s *Backend) sign(ctx context.Context, msg []byte, msgType types.MessageType) ([]byte, error) {
	out, err := s.client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          msg,
		MessageType:      msgType,
		SigningAlgorithm: s.algo.signAlgo,
	})
	if err != nil {
		return nil, fmt.Errorf("awskms: sign with %q: %w", s.keyID, err)
	}
	return out.Signature, nil
}

// Sign signs the canonical consensus sign-bytes via the KMS Sign API.
func (s *Backend) Sign(ctx context.Context, signBytes []byte) ([]byte, error) {
	sig, err := s.sign(ctx, signBytes, types.MessageTypeRaw)
	if err != nil {
		return nil, err
	}
	return s.algo.fixSig(sig)
}

// Close is a no-op for awskms based signers.
func (s *Backend) Close() error {
	return nil
}
