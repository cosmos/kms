package awskms

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/cometbft/cometbft/crypto/mldsa65"
	"github.com/cosmos/kms/config"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

// marshalMLDSA65SPKI wraps a packed ML-DSA-65 public key in the DER
// SubjectPublicKeyInfo envelope KMS GetPublicKey returns.
func marshalMLDSA65SPKI(t *testing.T, pub []byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidMLDSA65},
		PublicKey: asn1.BitString{Bytes: pub, BitLength: len(pub) * 8},
	})
	require.NoError(t, err)
	return der
}

// fakeMLDSAKMS is an in-process stand-in for AWS KMS backed by a real
// ML-DSA-65 key, exercising the SPKI decode and sign->verify path offline.
// KMS only sees the 64-byte μ under EXTERNAL_MU, so the fake holds the
// expected pre-μ message: it checks the received μ against one recomputed
// from that message and signs the message in pure mode.
type fakeMLDSAKMS struct {
	t    *testing.T
	priv mldsa65.PrivKey
	msg  []byte
}

func (f *fakeMLDSAKMS) GetPublicKey(_ context.Context, _ *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return &kms.GetPublicKeyOutput{
		PublicKey: marshalMLDSA65SPKI(f.t, f.priv.PubKey().Bytes()),
		KeySpec:   types.KeySpecMlDsa65,
	}, nil
}

func (f *fakeMLDSAKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	if in.MessageType != types.MessageTypeExternalMu {
		return nil, errors.New("fakeMLDSAKMS: unexpected message type")
	}
	if in.SigningAlgorithm != types.SigningAlgorithmSpecMlDsaShake256 {
		return nil, errors.New("fakeMLDSAKMS: unexpected signing algorithm")
	}
	// Recompute the FIPS 204 μ for the expected message (empty context) and
	// require the signer to have sent exactly that.
	tr := make([]byte, 64)
	sha3.ShakeSum256(tr, f.priv.PubKey().Bytes())
	h := sha3.NewShake256()
	h.Write(tr)
	h.Write([]byte{0, 0})
	h.Write(f.msg)
	mu := make([]byte, 64)
	if _, err := h.Read(mu); err != nil {
		return nil, err
	}
	if !bytes.Equal(in.Message, mu) {
		return nil, errors.New("fakeMLDSAKMS: message is not the expected μ")
	}
	// A signature over external μ is indistinguishable from a pure-mode
	// signature over the message, so sign the message directly.
	sig, err := f.priv.Sign(f.msg)
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{Signature: sig}, nil
}

func TestMLDSA65OpenAndSignRoundtrip(t *testing.T) {
	priv, err := mldsa65.GenPrivKey()
	require.NoError(t, err)
	f := &fakeMLDSAKMS{t: t, priv: priv}

	s, err := open(context.Background(), f, "alias/validator-pq", algos[config.AlgoMLDSA65])
	require.NoError(t, err)
	require.Equal(t, config.AlgoMLDSA65, s.Scheme())

	pub, err := mldsa65.NewPubKeyFromBytes(s.PubKey())
	require.NoError(t, err)
	require.True(t, pub.Equals(priv.PubKey()))

	// Larger than the 4096-byte KMS RAW cap: EXTERNAL_MU must not be size-bound.
	msg := bytes.Repeat([]byte("vote-extension sign-bytes "), 200)
	f.msg = msg
	sig, err := s.Sign(context.Background(), msg)
	require.NoError(t, err)
	require.True(t, pub.VerifySignature(msg, sig), "cometbft pubkey must verify the KMS signature")
}

func TestMLDSA65DecodePubRejectsWrongOID(t *testing.T) {
	der, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}},
		PublicKey: asn1.BitString{Bytes: []byte{0x01}, BitLength: 8},
	})
	require.NoError(t, err)
	_, err = decodeMLDSA65Pub(der)
	require.ErrorContains(t, err, "OID")
}

func TestMLDSA65DecodePubRejectsWrongLength(t *testing.T) {
	_, err := decodeMLDSA65Pub(marshalMLDSA65SPKI(t, []byte{0x01, 0x02}))
	require.ErrorContains(t, err, "expected")
}
