package awskms

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	pb "github.com/cosmos/kms/gen/signerservice"
	"github.com/cosmos/kms/signing"
	"github.com/cosmos/kms/signing/ecdsasig"
)

// Secp256k1Signer adapts an AWS KMS secp256k1 key to the gRPC SignerService
// signing.Signer interface under the ECDSA_SECP256K1 (Ethereum-compatible)
// scheme: it signs a 32-byte digest and returns a 65-byte r‖s‖v recoverable
// signature. It reuses *Backend for the KMS client and cached public key but
// signs with MessageType=DIGEST (the caller pre-hashes, e.g. keccak256) rather
// than the consensus RAW path, and post-processes the DER signature via the
// shared ecdsasig library — KMS returns neither low-S nor the recovery id v.
type Secp256k1Signer struct {
	be  *Backend
	pub *secp256k1.PublicKey // for recovery-id search and canonical encoding
}

// The adapter must satisfy the SignerService signer contract.
var _ signing.Signer = (*Secp256k1Signer)(nil)

// newSecp256k1Signer wraps a secp256k1 Backend, recovering the decred public key
// from the backend's cached (compressed) consensus public key.
func newSecp256k1Signer(be *Backend) (*Secp256k1Signer, error) {
	pub, err := secp256k1.ParsePubKey(be.pub.Bytes())
	if err != nil {
		return nil, fmt.Errorf("awskms: parse secp256k1 public key: %w", err)
	}
	return &Secp256k1Signer{be: be, pub: pub}, nil
}

// PubKey returns the 33-byte compressed secp256k1 public key (the canonical
// SignerService encoding for ECDSA_SECP256K1).
func (s *Secp256k1Signer) PubKey() []byte { return s.pub.SerializeCompressed() }

// Scheme reports ECDSA_SECP256K1.
func (s *Secp256k1Signer) Scheme() pb.SignatureScheme { return pb.SignatureScheme_ECDSA_SECP256K1 }

// Sign signs the 32-byte digest via the KMS Sign API (MessageType=DIGEST, so
// KMS signs the digest as-is without re-hashing) and returns the 65-byte
// r‖s‖v recoverable signature.
func (s *Secp256k1Signer) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("awskms: secp256k1 digest must be 32 bytes, got %d", len(digest))
	}
	out, err := s.be.client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.be.keyID),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: s.be.algo.signAlgo,
	})
	if err != nil {
		return nil, fmt.Errorf("awskms: sign with %q: %w", s.be.keyID, err)
	}
	return ecdsasig.RecoverableSig(out.Signature, digest, s.pub)
}

// Close closes the backend for the aws kms based signer.
func (s *Secp256k1Signer) Close() error {
	return s.be.Close()
}
