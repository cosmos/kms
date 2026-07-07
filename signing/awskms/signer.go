package awskms

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/cosmos/kms/config"
	pb "github.com/cosmos/kms/gen/signerservice"
	"github.com/cosmos/kms/signing"
	"github.com/cosmos/kms/signing/ecdsasig"
)

// Signer adapts an AWS KMS key to the gRPC SignerService signing.Signer
// interface. The private key never leaves KMS; signing is performed by the KMS
// Sign API.
type Signer struct {
	be      *Backend
	scheme  pb.SignatureScheme
	msgType types.MessageType // RAW: KMS hashes/signs the payload; DIGEST: payload is pre-hashed
	// finalize converts the raw KMS signature into the scheme's wire form; it
	// receives the payload and public key because recoverable ECDSA needs both.
	finalize func(raw, payload, pub []byte) ([]byte, error)
}

// The adapter must satisfy the SignerService signer contract.
var _ signing.Signer = (*Signer)(nil)

// OpenSigner resolves AWS configuration, builds a KMS client, fetches and
// caches the key's public key. It performs one KMS GetPublicKey call and any
// failure is returned (fatal at startup).
func OpenSigner(ctx context.Context, cfg Config) (signing.Signer, error) {
	be, err := Open(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("opening backend: %w", err)
	}
	return OpenSignerFromBackend(be, be.algo.name)
}

// OpenSignerFromBackend resolves a new aws kms signer from an existing aws kms
// Backend. Ed25519 serves the ED25519 scheme (raw message signing); secp256k1
// serves the ECDSA_SECP256K1 (Ethereum) scheme, signing 32-byte digests and
// returning 65-byte r‖s‖v recoverable signatures.
func OpenSignerFromBackend(backend *Backend, algo config.Algorithm) (signing.Signer, error) {
	switch algo {
	case config.AlgoED25519:
		return &Signer{
			be:       backend,
			scheme:   pb.SignatureScheme_ED25519,
			msgType:  types.MessageTypeRaw,
			finalize: func(raw, _, _ []byte) ([]byte, error) { return raw, nil },
		}, nil
	case config.AlgoSecp256k1:
		return &Signer{
			be:       backend,
			scheme:   pb.SignatureScheme_ECDSA_SECP256K1,
			msgType:  types.MessageTypeDigest,
			finalize: recoverableSig,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %s", string(algo))
	}
}

// PubKey returns the public key in the scheme's canonical encoding.
func (s *Signer) PubKey() []byte { return s.be.pub }

// Scheme reports the signers signature scheme.
func (s *Signer) Scheme() pb.SignatureScheme { return s.scheme }

// Sign signs the payload via the KMS Sign API using the scheme's message type
// and returns the signature in the scheme's wire form.
func (s *Signer) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	// DIGEST-mode schemes sign a pre-hashed 32-byte payload as-is.
	if s.msgType == types.MessageTypeDigest && len(payload) != 32 {
		return nil, fmt.Errorf("awskms: %s digest must be 32 bytes, got %d", string(s.be.algo.name), len(payload))
	}
	out, err := s.be.sign(ctx, payload, s.msgType)
	if err != nil {
		return nil, err
	}
	return s.finalize(out, payload, s.be.pub)
}

// recoverableSig converts the DER (r,s) signature KMS returned over digest
// into the 65-byte r‖s‖v recoverable form the ECDSA_SECP256K1 scheme requires.
func recoverableSig(raw, digest, pub []byte) ([]byte, error) {
	dpub, err := secp256k1.ParsePubKey(pub)
	if err != nil {
		return nil, fmt.Errorf("parse secp256k1 public key: %w", err)
	}
	return ecdsasig.RecoverableSig(raw, digest, dpub)
}

// Close closes the backend for the aws kms based signer.
func (s *Signer) Close() error {
	return s.be.Close()
}
