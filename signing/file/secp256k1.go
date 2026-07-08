package file

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/cosmos/kms/config"
	"github.com/cosmos/kms/signing"
)

// Secp256k1EthSigner is an in-memory, file-backed secp256k1 key that produces
// recoverable ECDSA signatures.
// NOT for production custody: the private key is held in process memory.
type Secp256k1EthSigner struct {
	priv *secp256k1.PrivateKey
	pub  *secp256k1.PublicKey
}

var _ signing.Signer = (*Secp256k1EthSigner)(nil)

func LoadSecp256k1EthFromString(str string) (*Secp256k1EthSigner, error) {
	hexKey := strings.TrimPrefix(strings.TrimSpace(str), "0x")
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("file: secp256k1eth key string %q is not hex: %w", str, err)
	}
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("file: secp256k1eth key string %q: expected 32-byte key, got %d", str, len(keyBytes))
	}
	priv := secp256k1.PrivKeyFromBytes(keyBytes)
	return &Secp256k1EthSigner{priv: priv, pub: priv.PubKey()}, nil
}

// LoadSecp256k1EthFromFile reads a file containing the hex-encoded 32-byte secp256k1eth
// private key.
func LoadSecp256k1Eth(path string) (*Secp256k1EthSigner, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("file: read secp256k1eth key file %q: %w", path, err)
	}
	signer, err := LoadSecp256k1EthFromString(string(raw))
	if err != nil {
		return nil, fmt.Errorf("file: secp256k1eth key file %q failed string decoding: %w", path, err)
	}
	return signer, nil
}

// Scheme reports the config.Algorithm.
func (s *Secp256k1EthSigner) Scheme() config.Algorithm { return config.AlgoSecp256k1Eth }

// Sign signs a 32-byte digest and returns a 65-byte recoverable signature laid
// out as r‖s‖v: r and s are 32 bytes each, v is a single 0/1 recovery-id byte.
// decred's SignCompact (signRFC6979) negates s when s > N/2 (BIP-0062 step B),
// so S is always canonical (low-S); no re-normalization is needed. This method
// reorders the <27+recid><R><S> compact form to the r‖s‖v layout the client
// expects and reduces the recovery code to 0/1.
func (s *Secp256k1EthSigner) Sign(_ context.Context, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("file: secp256k1eth digest must be 32 bytes, got %d", len(digest))
	}
	// isCompressedKey=false so the recovery code is 27+recid (no +4 offset).
	compact := ecdsa.SignCompact(s.priv, digest, false)
	if len(compact) != 65 {
		return nil, fmt.Errorf("file: unexpected compact signature length %d", len(compact))
	}
	recid := compact[0] - 27 // pubKeyRecoveryCode (0–3)
	if recid > 1 {
		// recid 2/3 means the X-overflow case (~1-in-2^127 on secp256k1); the
		// SignerService protocol requires a 0/1 recovery id, so reject it. This
		// is unrecoverable for this key+digest: RFC6979 nonces are deterministic,
		// so re-signing the same digest yields the same recid every time.
		return nil, fmt.Errorf("file: recovery id %d (X-overflow point) unsupported; key+digest cannot produce a 0/1 recovery id", recid)
	}
	out := make([]byte, 65)
	copy(out[0:32], compact[1:33])   // r
	copy(out[32:64], compact[33:65]) // s
	out[64] = recid                  // v (0/1)
	return out, nil
}

// PubKey returns the 33-byte compressed secp256k1eth public key (the canonical
// SignerService encoding for secp256k1eth).
func (s *Secp256k1EthSigner) PubKey() []byte { return s.pub.SerializeCompressed() }

// PubKeyUncompressed returns the 65-byte uncompressed secp256k1 public key
// (0x04 || X || Y). Used in tests for recovery comparison.
func (s *Secp256k1EthSigner) PubKeyUncompressed() []byte { return s.pub.SerializeUncompressed() }

// Close is a no-op for file based signers.
func (s *Secp256k1EthSigner) Close() error {
	return nil
}
