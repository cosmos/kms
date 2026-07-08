package awskms

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/cosmos/kms/config"
	"github.com/cosmos/kms/signing"
)

// Signer adapts an AWS KMS key to the gRPC SignerService signing.Signer
// interface. The private key never leaves KMS; signing is performed by the KMS
// Sign API.
type Signer struct {
	client kmsAPI
	keyID  string
	pub    []byte // canonical public key bytes for the algorithm's scheme
	algo   keyAlgo
}

// The adapter must satisfy the SignerService signer contract.
var _ signing.Signer = (*Signer)(nil)

// Open resolves a new aws kms signer from an existing aws kms
// Backend. Ed25519 serves the ED25519 scheme (raw message signing); secp256k1
// serves the ECDSA_SECP256K1 (Ethereum) scheme, signing 32-byte digests and
// returning 65-byte r‖s‖v recoverable signatures.
func Open(ctx context.Context, cfg Config) (signing.Signer, error) {
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
	out, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(cfg.KeyID)})
	if err != nil {
		return nil, fmt.Errorf("awskms: get public key for %q: %w", cfg.KeyID, err)
	}
	if out.KeySpec != algo.keySpec {
		return nil, fmt.Errorf("awskms: key %q has spec %q, expected %q for algorithm %q",
			cfg.KeyID, out.KeySpec, algo.keySpec, algo.name)
	}
	pub, err := algo.decodePub(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("awskms: decode public key for %q: %w", cfg.KeyID, err)
	}
	return &Signer{client: client, keyID: cfg.KeyID, pub: pub, algo: algo}, nil
}

// PubKey returns the public key in the scheme's canonical encoding.
func (s *Signer) PubKey() []byte { return s.pub }

// Scheme reports the signers signature scheme.
func (s *Signer) Scheme() config.Algorithm { return s.algo.name }

// Sign signs the payload via the KMS Sign API using the scheme's message type
// and returns the signature in the scheme's wire form.
// In cases where the MessageType is Raw, the payload has not been hashed.
func (s *Signer) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	out, err := s.client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          payload,
		MessageType:      s.algo.msgType,
		SigningAlgorithm: s.algo.signAlgo,
	})
	if err != nil {
		return nil, fmt.Errorf("awskms: Sign with %q: %w", s.keyID, err)
	}
	return s.algo.fixSig(out.Signature, payload, s.pub)
}

// Close closes the backend for the aws kms based signer.
func (s *Signer) Close() error {
	return nil
}
