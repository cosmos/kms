package awskms

import (
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
type fakeMLDSAKMS struct {
	t    *testing.T
	priv mldsa65.PrivKey
}

func (f *fakeMLDSAKMS) GetPublicKey(_ context.Context, _ *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return &kms.GetPublicKeyOutput{
		PublicKey: marshalMLDSA65SPKI(f.t, f.priv.PubKey().Bytes()),
		KeySpec:   types.KeySpecMlDsa65,
	}, nil
}

func (f *fakeMLDSAKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	if in.MessageType != types.MessageTypeRaw {
		return nil, errors.New("fakeMLDSAKMS: unexpected message type")
	}
	if in.SigningAlgorithm != types.SigningAlgorithmSpecMlDsaShake256 {
		return nil, errors.New("fakeMLDSAKMS: unexpected signing algorithm")
	}
	// Mirror KMS ML_DSA_SHAKE_256 + MessageType=RAW: pure ML-DSA over the
	// message with an empty context.
	sig, err := f.priv.Sign(in.Message)
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

	msg := []byte("canonical consensus sign-bytes")
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
