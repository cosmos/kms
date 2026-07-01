package awskms

import (
	"context"
	"fmt"

	"github.com/cosmos/kms/config"
	pb "github.com/cosmos/kms/gen/signerservice"
	"github.com/cosmos/kms/signing"
)

// Signer adapts an AWS KMS key to the gRPC SignerService signing.Signer
// interface. The private key never leaves KMS; signing is performed by the KMS
// Sign API.
type Signer struct {
	be     *Backend
	scheme pb.SignatureScheme
}

// The adapter must satisfy the SignerService signer contract.
var _ signing.Signer = (*Signer)(nil)

// OpenSigner resolves AWS configuration, builds a KMS client, fetches and
// caches the key's public key. It performs one KMS GetPublicKey call and any
// failure is returned (fatal at startup).
func OpenSigner(ctx context.Context, cfg Config) (*Signer, error) {
	be, err := Open(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("opening backend: %w", err)
	}
	return OpenSignerFromBackend(be, cfg.Algorithm)
}

// OpenSignerFromBackend resolves a new aws kms signer from an existing aws kms
// Backend.
func OpenSignerFromBackend(backend *Backend, algo config.Algorithm) (*Signer, error) {
	var scheme pb.SignatureScheme
	switch algo {
	case config.AlgoED25519:
		scheme = pb.SignatureScheme_ED25519
	case config.AlgoSecp256k1:
		scheme = pb.SignatureScheme_ECDSA_SECP256K1
	default:
		return nil, fmt.Errorf("unsupported algorithm %s", string(algo))
	}

	return &Signer{be: backend, scheme: scheme}, nil
}

// PubKey returns the 32-byte public key.
func (s *Signer) PubKey() []byte { return s.be.pub.Bytes() }

// Scheme reports the signers signature scheme.
func (s *Signer) Scheme() pb.SignatureScheme { return s.scheme }

// Sign signs the payload (the message) via the KMS Sign API and returns the
// raw 64-byte signature.
func (s *Signer) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	return s.be.Sign(ctx, payload)
}

// Close closes the backend for the aws kms based signer.
func (s *Signer) Close() error {
	return s.be.Close()
}
