// Package signing defines the public signing contracts for kms: the consensus
// Backend used by the privval path, and the Signer/Key used by the
// SignerService. Concrete custodians live in the file, pkcs11, and awskms
// subpackages.
package signing

import (
	"context"

	"github.com/cometbft/cometbft/crypto"
)

// Backend is the consensus signing-key contract: a key custodian (file, PKCS#11,
// AWS KMS, ...) that signs the canonical CometBFT consensus sign-bytes.
//
// The interface is algorithm-agnostic: the public key carries its own algorithm
// via crypto.PubKey.Type(), and Sign produces a valid signature over the
// sign-bytes using whatever scheme the key requires.
type Backend interface {
	// PubKey returns the validator public key.
	PubKey(ctx context.Context) (crypto.PubKey, error)
	// Sign signs the canonical consensus sign-bytes and returns the signature.
	Sign(ctx context.Context, signBytes []byte) ([]byte, error)
	// Close contains any logic that should be called on cleanup.
	Close() error
}
