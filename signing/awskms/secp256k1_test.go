package awskms

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/stretchr/testify/require"

	pb "github.com/cosmos/kms/gen/signerservice"
)

// fakeSecpKMS is an in-process stand-in for AWS KMS backed by a real secp256k1
// key. GetPublicKey returns the X.509 SPKI; Sign mirrors KMS ECDSA_SHA_256 +
// MessageType=DIGEST, signing the supplied digest and returning DER (r,s).
type fakeSecpKMS struct {
	priv    *secp256k1.PrivateKey
	signErr error
}

func newFakeSecpKMS(t *testing.T) *fakeSecpKMS {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	return &fakeSecpKMS{priv: priv}
}

func (f *fakeSecpKMS) GetPublicKey(_ context.Context, _ *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	spki := secp256k1SPKIForTest(nil, f.priv.PubKey())
	return &kms.GetPublicKeyOutput{PublicKey: spki, KeySpec: types.KeySpecEccSecgP256k1}, nil
}

func (f *fakeSecpKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	if f.signErr != nil {
		return nil, f.signErr
	}
	if in.MessageType != types.MessageTypeDigest {
		return nil, errors.New("fakeSecpKMS: expected MessageType=DIGEST")
	}
	if in.SigningAlgorithm != types.SigningAlgorithmSpecEcdsaSha256 {
		return nil, errors.New("fakeSecpKMS: expected ECDSA_SHA_256")
	}
	der := ecdsa.Sign(f.priv, in.Message).Serialize()
	return &kms.SignOutput{Signature: der}, nil
}

func TestGRPCSecp256k1SignerRoundtrip(t *testing.T) {
	f := newFakeSecpKMS(t)
	be, err := open(context.Background(), f, "alias/eth", algos[algoSecp256k1])
	require.NoError(t, err)
	s, err := newSecp256k1Signer(be)
	require.NoError(t, err)

	require.Equal(t, pb.SignatureScheme_ECDSA_SECP256K1, s.Scheme())
	require.Equal(t, f.priv.PubKey().SerializeCompressed(), s.PubKey())

	digest := sha256.Sum256([]byte("ethereum tx hash stand-in"))
	sig, err := s.Sign(context.Background(), digest[:])
	require.NoError(t, err)
	require.Len(t, sig, 65)
	require.LessOrEqual(t, sig[64], byte(1))

	// The 65-byte r‖s‖v must recover the signing pubkey.
	compact := make([]byte, 65)
	compact[0] = 27 + sig[64]
	copy(compact[1:], sig[:64])
	recovered, _, err := ecdsa.RecoverCompact(compact, digest[:])
	require.NoError(t, err)
	require.True(t, recovered.IsEqual(f.priv.PubKey()))
}

func TestGRPCSecp256k1SignerPropagatesSignError(t *testing.T) {
	f := newFakeSecpKMS(t)
	be, err := open(context.Background(), f, "k", algos[algoSecp256k1])
	require.NoError(t, err)
	s, err := newSecp256k1Signer(be)
	require.NoError(t, err)

	f.signErr = errors.New("throttled")
	digest := sha256.Sum256([]byte("m"))
	_, err = s.Sign(context.Background(), digest[:])
	require.ErrorContains(t, err, "throttled")
}

// secp256k1SPKIForTest builds the DER SubjectPublicKeyInfo KMS returns for an
// ECC_SECG_P256K1 key. t may be nil (callers outside *testing.T helpers).
func secp256k1SPKIForTest(t *testing.T, pub *secp256k1.PublicKey) []byte {
	if t != nil {
		t.Helper()
	}
	type spkiT struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.ObjectIdentifier
		}
		PublicKey asn1.BitString
	}
	var s spkiT
	s.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	s.Algorithm.Parameters = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
	point := pub.SerializeUncompressed()
	s.PublicKey = asn1.BitString{Bytes: point, BitLength: len(point) * 8}
	der, err := asn1.Marshal(s)
	if err != nil {
		panic(err)
	}
	return der
}
