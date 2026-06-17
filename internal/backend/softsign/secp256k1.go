package softsign

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// AlgoSecp256k1 is the algorithm identifier reported by Secp256k1Signer. It
// matches the string convention used by the backend algos registries.
const AlgoSecp256k1 = "secp256k1"

// Secp256k1Signer is an in-memory, file-backed secp256k1 key that produces
// recoverable ECDSA signatures.
// NOT for production custody: the private key is held in process memory.
type Secp256k1Signer struct {
	priv *secp256k1.PrivateKey
	pub  *secp256k1.PublicKey
}

// LoadSecp256k1 reads a file containing the hex-encoded 32-byte secp256k1
// private key.
func LoadSecp256k1(path string) (*Secp256k1Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("softsign: read secp256k1 key file %q: %w", path, err)
	}
	keyBytes, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil {
		return nil, fmt.Errorf("softsign: secp256k1 key file %q is not hex: %w", path, err)
	}
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("softsign: secp256k1 key file %q: expected 32-byte key, got %d", path, len(keyBytes))
	}
	priv := secp256k1.PrivKeyFromBytes(keyBytes)
	return &Secp256k1Signer{priv: priv, pub: priv.PubKey()}, nil
}

// SignDigest signs a 32-byte digest and returns the recoverable signature as
// (r, s, v): r and s are 32 bytes each, v is a single 0/1 recovery-id byte.
// decred's SignCompact (signRFC6979) negates s when s > N/2 (BIP-0062 step B),
// so S is always canonical (low-S); no re-normalization is needed. This method
// reorders the <27+recid><R><S> compact form to the r||s||v layout the client
// expects and reduces the recovery code to 0/1.
func (s *Secp256k1Signer) SignDigest(digest []byte) (r, sig, v []byte, err error) {
	if len(digest) != 32 {
		return nil, nil, nil, fmt.Errorf("softsign: secp256k1 digest must be 32 bytes, got %d", len(digest))
	}
	// isCompressedKey=false so the recovery code is 27+recid (no +4 offset).
	compact := ecdsa.SignCompact(s.priv, digest, false)
	if len(compact) != 65 {
		return nil, nil, nil, fmt.Errorf("softsign: unexpected compact signature length %d", len(compact))
	}
	recid := compact[0] - 27 // pubKeyRecoveryCode (0–3)
	if recid > 1 {
		// recid 2/3 means the X-overflow case (~1-in-2^127 on secp256k1); the
		// SignerService protocol requires a 0/1 recovery id, so reject it. This
		// is unrecoverable for this key+digest: RFC6979 nonces are deterministic,
		// so re-signing the same digest yields the same recid every time.
		return nil, nil, nil, fmt.Errorf("softsign: recovery id %d (X-overflow point) unsupported; key+digest cannot produce a 0/1 recovery id", recid)
	}
	r = append([]byte(nil), compact[1:33]...)
	sig = append([]byte(nil), compact[33:65]...)
	v = []byte{recid}
	return r, sig, v, nil
}

// Algo reports the key algorithm identifier.
func (s *Secp256k1Signer) Algo() string { return AlgoSecp256k1 }

// PubKeyCompressed returns the 33-byte compressed secp256k1 public key (the
// canonical SignerService encoding for secp256k1).
func (s *Secp256k1Signer) PubKeyCompressed() []byte { return s.pub.SerializeCompressed() }

// PubKeyUncompressed returns the 65-byte uncompressed secp256k1 public key
// (0x04 || X || Y). Used in tests for recovery comparison.
func (s *Secp256k1Signer) PubKeyUncompressed() []byte { return s.pub.SerializeUncompressed() }
