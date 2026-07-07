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

// decodeRawRS parses a raw fixed-width r‖s signature (2×32 bytes, as PKCS#11
// CKM_ECDSA returns) into (r, s) as mod-N scalars and normalizes s to low-S.
func decodeRawRS(rs []byte) (r, s secp256k1.ModNScalar, err error) {
	if len(rs) != 64 {
		return r, s, fmt.Errorf("ecdsasig: raw signature must be 64 bytes, got %d", len(rs))
	}
	if r.SetByteSlice(rs[:32]) || s.SetByteSlice(rs[32:]) {
		return r, s, fmt.Errorf("ecdsasig: signature r or s is >= curve order")
	}
	if r.IsZero() || s.IsZero() {
		return r, s, fmt.Errorf("ecdsasig: signature r and s must be nonzero")
	}
	// Low-S: collapse the malleable high half so the result is canonical.
	if s.IsOverHalfOrder() {
		s.Negate()
	}
	return r, s, nil
}

// consensusSig serializes low-S normalized scalars as the 64-byte r‖s form
// cometbft secp256k1 consensus verification requires.
func consensusSig(r, s secp256k1.ModNScalar) []byte {
	rb, sb := r.Bytes(), s.Bytes()
	out := make([]byte, 64)
	copy(out[0:32], rb[:])
	copy(out[32:64], sb[:])
	return out
}

// ConsensusSig converts a DER (r,s) signature into the 64-byte r‖s low-S form
// cometbft secp256k1 consensus verification requires.
func ConsensusSig(der []byte) ([]byte, error) {
	r, s, err := decodeRS(der)
	if err != nil {
		return nil, err
	}
	return consensusSig(r, s), nil
}

// ConsensusSigRS is ConsensusSig for a raw 64-byte r‖s signature.
func ConsensusSigRS(rs []byte) ([]byte, error) {
	r, s, err := decodeRawRS(rs)
	if err != nil {
		return nil, err
	}
	return consensusSig(r, s), nil
}

// recoverableSig builds the 65-byte r‖s‖v form from low-S normalized scalars.
// Since the underlying signer does not return v, it is found by
// trial-recovering pub from the signature with each candidate. An error is
// returned if neither candidate recovers pub, including the X-overflow case
// (recid 2/3), which the SignerService 0/1-recovery-id protocol cannot carry.
func recoverableSig(r, s secp256k1.ModNScalar, digest []byte, pub *secp256k1.PublicKey) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("ecdsasig: digest must be 32 bytes, got %d", len(digest))
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

// RecoverableSig converts a DER (r,s) signature into the 65-byte r‖s‖v
// recoverable form.
func RecoverableSig(der, digest []byte, pub *secp256k1.PublicKey) ([]byte, error) {
	r, s, err := decodeRS(der)
	if err != nil {
		return nil, err
	}
	return recoverableSig(r, s, digest, pub)
}

// RecoverableSigRS is RecoverableSig for a raw 64-byte r‖s signature.
func RecoverableSigRS(rs, digest []byte, pub *secp256k1.PublicKey) ([]byte, error) {
	r, s, err := decodeRawRS(rs)
	if err != nil {
		return nil, err
	}
	return recoverableSig(r, s, digest, pub)
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
