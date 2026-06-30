// Package ecdsasig converts the DER-encoded secp256k1 ECDSA signatures that
// hardware/managed signers (AWS KMS, PKCS#11 HSMs) return into the wire forms
// this project consumes:
//
//   - ConsensusSig:    64-byte r‖s low-S, the cometbft consensus (privval) form.
//   - RecoverableSig:  65-byte r‖s‖v recoverable, the SignerService
//     ECDSA_SECP256K1 (Ethereum-compatible) form.
//
// It is signer-agnostic (no AWS/PKCS#11 imports) so both the privval backends
// and the gRPC SignerService share one implementation. KMS et al. neither
// guarantee low-S nor return the recovery id v; both are derived here.
package ecdsasig

import (
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// decodeRS parses a canonical DER ECDSA signature into (r, s) as mod-N scalars
// and normalizes s to low-S. ModNScalar reduces mod the curve order, so range
// validation rides on the overflow flag from SetByteSlice.
func decodeRS(der []byte) (r, s secp256k1.ModNScalar, err error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return r, s, fmt.Errorf("ecdsasig: parse DER signature: %w", err)
	}
	if len(rest) != 0 {
		return r, s, fmt.Errorf("ecdsasig: %d trailing bytes after DER signature", len(rest))
	}
	if sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return r, s, fmt.Errorf("ecdsasig: signature r and s must be positive")
	}
	if r.SetByteSlice(sig.R.Bytes()) || s.SetByteSlice(sig.S.Bytes()) {
		return r, s, fmt.Errorf("ecdsasig: signature r or s is >= curve order")
	}
	// Low-S: collapse the malleable high half so the result is canonical.
	if s.IsOverHalfOrder() {
		s.Negate()
	}
	return r, s, nil
}

// ConsensusSig converts a DER (r,s) signature into the 64-byte r‖s low-S form
// cometbft secp256k1 consensus verification requires.
func ConsensusSig(der []byte) ([]byte, error) {
	r, s, err := decodeRS(der)
	if err != nil {
		return nil, err
	}
	rb, sb := r.Bytes(), s.Bytes()
	out := make([]byte, 64)
	copy(out[0:32], rb[:])
	copy(out[32:64], sb[:])
	return out, nil
}

// RecoverableSig converts a DER (r,s) signature over digest into the 65-byte
// r‖s‖v recoverable form, where v is the 0/1 recovery id. Since the underlying
// signer does not return v, it is found by trial-recovering pub from the
// (low-S normalized) signature with each candidate. An error is returned if
// neither candidate recovers pub — including the ~1-in-2^127 X-overflow case
// (recid 2/3), which the SignerService 0/1-recovery-id protocol cannot carry.
func RecoverableSig(der, digest []byte, pub *secp256k1.PublicKey) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("ecdsasig: digest must be 32 bytes, got %d", len(digest))
	}
	r, s, err := decodeRS(der)
	if err != nil {
		return nil, err
	}
	rb, sb := r.Bytes(), s.Bytes()

	// decred compact form is <27+recid>‖R‖S; isCompressedKey=false ⇒ no +4.
	compact := make([]byte, 65)
	copy(compact[1:33], rb[:])
	copy(compact[33:65], sb[:])
	for v := byte(0); v <= 1; v++ {
		compact[0] = 27 + v
		recovered, _, recErr := ecdsa.RecoverCompact(compact, digest)
		if recErr == nil && recovered.IsEqual(pub) {
			out := make([]byte, 65)
			copy(out[0:64], compact[1:65])
			out[64] = v
			return out, nil
		}
	}
	return nil, fmt.Errorf("ecdsasig: no 0/1 recovery id recovers the public key")
}

// ParsePubKeySPKI parses the DER X.509 SubjectPublicKeyInfo that AWS KMS
// GetPublicKey returns for an ECC_SECG_P256K1 key. The standard library's
// x509.ParsePKIXPublicKey rejects secp256k1, so the point is pulled from the
// SubjectPublicKeyInfo BIT STRING directly; ParsePubKey then checks it is a
// valid point on the secp256k1 curve.
func ParsePubKeySPKI(spki []byte) (*secp256k1.PublicKey, error) {
	var info struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.ObjectIdentifier
		}
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &info); err != nil {
		return nil, fmt.Errorf("ecdsasig: parse SubjectPublicKeyInfo: %w", err)
	}
	pub, err := secp256k1.ParsePubKey(info.PublicKey.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ecdsasig: decode secp256k1 public key: %w", err)
	}
	return pub, nil
}
