package pkcs11

import (
	"context"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/miekg/pkcs11"

	"github.com/cosmos/kms/config"
	pb "github.com/cosmos/kms/gen/signerservice"
	"github.com/cosmos/kms/signing"
	"github.com/cosmos/kms/signing/ecdsasig"
)

// Signer adapts a PKCS#11 key to the gRPC SignerService signing.Signer
// interface. The private key never leaves the token; signing is performed
// on-device via C_Sign. keyAlgo is protocol-neutral, so the per-scheme
// SignerService conventions (scheme constant, token mechanism, signature wire
// form) live here.
type Signer struct {
	be        *Backend
	scheme    pb.SignatureScheme
	mechanism func() []*pkcs11.Mechanism
	digest    bool // payload is a pre-hashed 32-byte digest signed as-is
	// finalize converts the raw token signature into the scheme's wire form; it
	// receives the payload and public key because recoverable ECDSA needs both.
	finalize func(raw, payload, pub []byte) ([]byte, error)
}

// The adapter must satisfy the SignerService signer contract.
var _ signing.Signer = (*Signer)(nil)

// OpenSigner opens the token key and wraps it as a SignerService signer. Any
// failure is returned (fatal at startup).
func OpenSigner(cfg Config) (signing.Signer, error) {
	be, err := Open(cfg)
	if err != nil {
		return nil, fmt.Errorf("opening backend: %w", err)
	}
	return OpenSignerFromBackend(be, be.algo.name)
}

// OpenSignerFromBackend resolves a new pkcs11 signer from an existing pkcs11
// Backend. Ed25519 serves the ED25519 scheme (CKM_EDDSA over the raw message);
// secp256k1 serves the ECDSA_SECP256K1 (Ethereum) scheme, signing 32-byte
// digests with bare CKM_ECDSA and returning 65-byte r‖s‖v recoverable
// signatures.
func OpenSignerFromBackend(backend *Backend, algo config.Algorithm) (signing.Signer, error) {
	switch algo {
	case config.AlgoED25519:
		return &Signer{
			be:        backend,
			scheme:    pb.SignatureScheme_ED25519,
			mechanism: func() []*pkcs11.Mechanism { return []*pkcs11.Mechanism{pkcs11.NewMechanism(ckmEDDSA, nil)} },
			finalize:  func(raw, _, _ []byte) ([]byte, error) { return raw, nil },
		}, nil
	case config.AlgoSecp256k1:
		return &Signer{
			be:        backend,
			scheme:    pb.SignatureScheme_ECDSA_SECP256K1,
			mechanism: func() []*pkcs11.Mechanism { return []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)} },
			digest:    true,
			finalize:  recoverableSig,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %s", string(algo))
	}
}

// PubKey returns the public key in the scheme's canonical encoding.
func (s *Signer) PubKey() []byte { return s.be.pub }

// Scheme reports the signers signature scheme.
func (s *Signer) Scheme() pb.SignatureScheme { return s.scheme }

// Sign signs the payload on the token using the scheme's mechanism and returns
// the signature in the scheme's wire form.
func (s *Signer) Sign(_ context.Context, payload []byte) ([]byte, error) {
	// Digest schemes sign a pre-hashed 32-byte payload as-is.
	if s.digest && len(payload) != 32 {
		return nil, fmt.Errorf("pkcs11: %s digest must be 32 bytes, got %d", string(s.be.algo.name), len(payload))
	}
	raw, err := s.be.sign(s.mechanism(), payload)
	if err != nil {
		return nil, err
	}
	return s.finalize(raw, payload, s.be.pub)
}

// recoverableSig converts the raw r‖s signature the token returned over digest
// into the 65-byte r‖s‖v recoverable form the ECDSA_SECP256K1 scheme requires.
func recoverableSig(raw, digest, pub []byte) ([]byte, error) {
	dpub, err := secp256k1.ParsePubKey(pub)
	if err != nil {
		return nil, fmt.Errorf("parse secp256k1 public key: %w", err)
	}
	return ecdsasig.RecoverableSigRS(raw, digest, dpub)
}

// Close closes the backend for the pkcs11 based signer.
func (s *Signer) Close() error {
	return s.be.Close()
}
