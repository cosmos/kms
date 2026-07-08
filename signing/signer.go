package signing

import (
	"context"

	"github.com/cosmos/kms/config"
)

// Signer is the capability every SignerService key provides: it describes itself
// (public key + signature scheme) and signs a payload under that scheme. The
// per-scheme payload/signature conventions (e.g. ECDSA_SECP256K1 takes a
// 32-byte digest and returns 65-byte r‖s‖v) are documented on the
// SignatureScheme enum in the proto.
type Signer interface {
	// PubKey returns the public key in the canonical encoding for Scheme.
	PubKey() []byte
	// Scheme reports the Algorithm this key signs under.
	Scheme() config.Algorithm
	// Sign signs payload under Scheme and returns the raw signature bytes.
	Sign(ctx context.Context, payload []byte) ([]byte, error)
	// Close contains any logic that should be called on cleanup.
	Close() error
}

// Key is a configured SignerService signing identity.
type Key struct {
	ID     string
	Signer Signer
}
