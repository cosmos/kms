package awskms

import (
	"context"
	"fmt"

	pb "github.com/cosmos/kms/gen/signerservice"
	"github.com/cosmos/kms/signing"
)

// Signer adapts an AWS KMS ed25519 key to the gRPC SignerService signing.Signer
// interface. The private key never leaves KMS; signing is performed by the KMS
// Sign API. It wraps a *Backend (the consensus-path KMS signer) and reuses its
// client, cached public key, and Sign path verbatim — KMS ed25519 is PureEd25519
// over the raw message (MessageType=RAW), which is exactly what the gRPC ED25519
// scheme requires. Only ed25519 is supported over gRPC today.
type Signer struct {
	be *Backend
}

// The adapter must satisfy the SignerService signer contract.
var _ signing.Signer = (*Signer)(nil)

// OpenSigner resolves AWS configuration, builds a KMS client, fetches and caches
// the key's public key, and validates its spec against the configured algorithm
// (which must be ed25519). It performs one KMS GetPublicKey call and any failure
// is returned (fatal at startup). Algorithm defaults to ed25519 when empty; a
// non-ed25519 algorithm is rejected since the gRPC SignerService only supports
// ED25519 for KMS keys.
func OpenSigner(ctx context.Context, cfg Config) (*Signer, error) {
	if cfg.Algorithm != "" && cfg.Algorithm != algoEd25519 {
		return nil, fmt.Errorf("awskms: gRPC SignerService supports only %q, got %q", algoEd25519, cfg.Algorithm)
	}
	be, err := Open(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &Signer{be: be}, nil
}

// PubKey returns the 32-byte ed25519 public key, the canonical SignerService
// encoding for ED25519.
func (s *Signer) PubKey() []byte { return s.be.pub.Bytes() }

// Scheme reports ED25519.
func (s *Signer) Scheme() pb.SignatureScheme { return pb.SignatureScheme_ED25519 }

// Sign signs the payload (the message) under ED25519 via the KMS Sign API and
// returns the raw 64-byte signature.
func (s *Signer) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	return s.be.Sign(ctx, payload)
}

// Close closes the backend for the aws kms based signer.
func (s *Signer) Close() error {
	return s.be.Close()
}
