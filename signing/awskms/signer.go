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
// failure is returned (fatal at startup). Algorithm defaults to ed25519 when
// empty.
func OpenSigner(ctx context.Context, cfg Config) (signing.Signer, error) {
	be, err := Open(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("opening backend: %w", err)
	}
	return OpenSignerFromBackend(be, be.algo.name)
}

// OpenSignerFromBackend resolves a new aws kms signer from an existing aws kms
// Backend. Ed25519 serves the ED25519 scheme (raw message signing); secp256k1
// serves the ECDSA_SECP256K1 (Ethereum) scheme via Secp256k1Signer, which signs
// 32-byte digests and returns recoverable signatures.
func OpenSignerFromBackend(backend *Backend, algo config.Algorithm) (signing.Signer, error) {
	switch algo {
	case config.AlgoED25519:
		return &Signer{be: backend, scheme: pb.SignatureScheme_ED25519}, nil
	case config.AlgoSecp256k1:
		return newSecp256k1Signer(backend)
	default:
		return nil, fmt.Errorf("unsupported algorithm %s", string(algo))
	}
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
