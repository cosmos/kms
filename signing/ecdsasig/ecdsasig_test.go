package ecdsasig

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	cometsecp "github.com/cometbft/cometbft/crypto/secp256k1"
)

// testKey returns a deterministic secp256k1 key for tests.
func testKey(t *testing.T) *secp256k1.PrivateKey {
	t.Helper()
	// 32-byte non-zero scalar < N.
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return secp256k1.PrivKeyFromBytes(b)
}

// derSig signs digest with priv and returns the canonical DER (r,s) encoding,
// standing in for what AWS KMS / a PKCS#11 token returns.
func derSig(t *testing.T, priv *secp256k1.PrivateKey, digest []byte) []byte {
	t.Helper()
	return ecdsa.Sign(priv, digest).Serialize()
}

// highSDER re-encodes a DER (r,s) signature with s replaced by N-s, producing a
// non-canonical high-S signature (what KMS may legitimately return).
func highSDER(t *testing.T, der []byte) []byte {
	t.Helper()
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		t.Fatalf("unmarshal der: %v", err)
	}
	// s' = N - s via mod-N negation, yielding the non-canonical high-S form.
	var sc secp256k1.ModNScalar
	sc.SetByteSlice(sig.S.Bytes())
	sc.Negate()
	neg := sc.Bytes()
	sig.S = new(big.Int).SetBytes(neg[:])
	out, err := asn1.Marshal(sig)
	if err != nil {
		t.Fatalf("marshal der: %v", err)
	}
	return out
}

func TestRecoverableSigRecoversPubKey(t *testing.T) {
	priv := testKey(t)
	digest := sha256.Sum256([]byte("eth digest"))
	der := derSig(t, priv, digest[:])

	sig, err := RecoverableSig(der, digest[:], priv.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 65 {
		t.Fatalf("want 65-byte sig, got %d", len(sig))
	}
	// v must be 0 or 1.
	if v := sig[64]; v > 1 {
		t.Fatalf("recovery id %d out of range", v)
	}
	// S must be canonical low-S.
	var s secp256k1.ModNScalar
	s.SetByteSlice(sig[32:64])
	if s.IsOverHalfOrder() {
		t.Fatal("S is not low-S")
	}
	// r‖s‖(27+v) must recover the signing pubkey.
	compact := make([]byte, 65)
	compact[0] = 27 + sig[64]
	copy(compact[1:], sig[:64])
	recovered, _, err := ecdsa.RecoverCompact(compact, digest[:])
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if !recovered.IsEqual(priv.PubKey()) {
		t.Fatal("recovered pubkey mismatch")
	}
}

func TestRecoverableSigNormalizesHighS(t *testing.T) {
	priv := testKey(t)
	digest := sha256.Sum256([]byte("eth digest"))
	low := derSig(t, priv, digest[:])
	high := highSDER(t, low)

	a, err := RecoverableSig(low, digest[:], priv.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	b, err := RecoverableSig(high, digest[:], priv.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	// Same r‖s after low-S normalization (v may flip, so compare the first 64).
	if !bytes.Equal(a[:64], b[:64]) {
		t.Fatal("high-S input did not normalize to the same r‖s")
	}
}

func TestConsensusSigVerifiesWithCometBFT(t *testing.T) {
	priv := testKey(t)
	msg := []byte("consensus sign bytes")
	digest := sha256.Sum256(msg)
	der := derSig(t, priv, digest[:])

	sig, err := ConsensusSig(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 64 {
		t.Fatalf("want 64-byte sig, got %d", len(sig))
	}
	pub := cometsecp.PubKey(priv.PubKey().SerializeCompressed())
	if !pub.VerifySignature(msg, sig) {
		t.Fatal("cometbft rejected the consensus signature")
	}
}

func TestConsensusSigNormalizesHighS(t *testing.T) {
	priv := testKey(t)
	msg := []byte("consensus sign bytes")
	digest := sha256.Sum256(msg)
	low := derSig(t, priv, digest[:])
	high := highSDER(t, low)

	a, err := ConsensusSig(low)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ConsensusSig(high)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("high-S input did not normalize to the same consensus signature")
	}
	pub := cometsecp.PubKey(priv.PubKey().SerializeCompressed())
	if !pub.VerifySignature(msg, b) {
		t.Fatal("cometbft rejected the normalized high-S signature")
	}
}

func TestParsePubKeySPKIRoundTrip(t *testing.T) {
	priv := testKey(t)
	pub := priv.PubKey()

	// Build the DER X.509 SubjectPublicKeyInfo AWS KMS returns for a
	// secp256k1 key: AlgorithmIdentifier{ecPublicKey, secp256k1} + BIT STRING
	// holding the uncompressed point.
	type algID struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.ObjectIdentifier
	}
	type spkiT struct {
		Algorithm algID
		PublicKey asn1.BitString
	}
	point := pub.SerializeUncompressed()
	spki, err := asn1.Marshal(spkiT{
		Algorithm: algID{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, // ecPublicKey
			Parameters: asn1.ObjectIdentifier{1, 3, 132, 0, 10},       // secp256k1
		},
		PublicKey: asn1.BitString{Bytes: point, BitLength: len(point) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := ParsePubKeySPKI(spki)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsEqual(pub) {
		t.Fatal("parsed pubkey mismatch")
	}
}
