package awskms

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/cosmos/kms/config"
	"github.com/stretchr/testify/require"
)

// open builds a Signer over an injected kmsAPI, mirroring Open's
// fetch/spec-check/decode sequence so tests can run against a fake client.
func open(ctx context.Context, client kmsAPI, keyID string, algo keyAlgo) (*Signer, error) {
	out, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, fmt.Errorf("awskms: get public key for %q: %w", keyID, err)
	}
	if out.KeySpec != algo.keySpec {
		return nil, fmt.Errorf("awskms: key %q has spec %q, expected %q for algorithm %q",
			keyID, out.KeySpec, algo.keySpec, algo.name)
	}
	pub, err := algo.decodePub(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("awskms: decode public key for %q: %w", keyID, err)
	}
	return &Signer{client: client, keyID: keyID, pub: pub, algo: algo}, nil
}

// fakeKMS is an in-process stand-in for AWS KMS backed by a real Ed25519 key. It
// lets the public-key-parse and sign->verify path run offline, exercising
// exactly the conversion logic in the signer.
type fakeKMS struct {
	priv      ed25519.PrivateKey
	keySpec   types.KeySpec
	getErr    error
	signErr   error
	badPubDER []byte // when set, GetPublicKey returns this instead of a valid SPKI
}

func newFakeKMS(t *testing.T) *fakeKMS {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return &fakeKMS{priv: priv, keySpec: types.KeySpecEccNistEdwards25519}
}

func (f *fakeKMS) GetPublicKey(_ context.Context, _ *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	der := f.badPubDER
	if der == nil {
		var err error
		der, err = x509.MarshalPKIXPublicKey(f.priv.Public())
		if err != nil {
			return nil, err
		}
	}
	return &kms.GetPublicKeyOutput{PublicKey: der, KeySpec: f.keySpec}, nil
}

func (f *fakeKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	if f.signErr != nil {
		return nil, f.signErr
	}
	if in.MessageType != types.MessageTypeRaw {
		return nil, errors.New("fakeKMS: unexpected message type")
	}
	if in.SigningAlgorithm != types.SigningAlgorithmSpecEd25519Sha512 {
		return nil, errors.New("fakeKMS: unexpected signing algorithm")
	}
	// Mirror KMS ED25519_SHA_512 + MessageType=RAW: PureEd25519 over the message.
	return &kms.SignOutput{Signature: ed25519.Sign(f.priv, in.Message)}, nil
}

func TestOpenAndSignRoundtrip(t *testing.T) {
	f := newFakeKMS(t)
	s, err := open(context.Background(), f, "alias/validator", algos[config.AlgoED25519])
	require.NoError(t, err)

	require.Equal(t, config.AlgoED25519, s.Scheme())
	pub := s.PubKey()
	require.Len(t, pub, ed25519.PublicKeySize)
	require.Equal(t, []byte(f.priv.Public().(ed25519.PublicKey)), pub)

	msg := []byte("canonical consensus sign-bytes")
	sig, err := s.Sign(context.Background(), msg)
	require.NoError(t, err)
	require.Len(t, sig, ed25519.SignatureSize)
	require.True(t, ed25519.Verify(ed25519.PublicKey(pub), msg, sig), "pubkey must verify the KMS signature")
}

func TestOpenRejectsWrongKeySpec(t *testing.T) {
	f := newFakeKMS(t)
	f.keySpec = types.KeySpecEccSecgP256k1
	_, err := open(context.Background(), f, "k", algos[config.AlgoED25519])
	require.ErrorContains(t, err, "spec")
}

func TestOpenPropagatesGetPublicKeyError(t *testing.T) {
	f := newFakeKMS(t)
	f.getErr = errors.New("access denied")
	_, err := open(context.Background(), f, "k", algos[config.AlgoED25519])
	require.ErrorContains(t, err, "access denied")
}

func TestOpenRejectsUndecodablePublicKey(t *testing.T) {
	f := newFakeKMS(t)
	f.badPubDER = []byte("not-a-valid-spki")
	_, err := open(context.Background(), f, "k", algos[config.AlgoED25519])
	require.ErrorContains(t, err, "decode public key")
}

func TestSignPropagatesError(t *testing.T) {
	f := newFakeKMS(t)
	s, err := open(context.Background(), f, "k", algos[config.AlgoED25519])
	require.NoError(t, err)
	f.signErr = errors.New("throttled")
	_, err = s.Sign(context.Background(), []byte("m"))
	require.ErrorContains(t, err, "throttled")
}

func TestSignRejectsOversizedRawPayload(t *testing.T) {
	f := newFakeKMS(t)
	s, err := open(context.Background(), f, "k", algos[config.AlgoED25519])
	require.NoError(t, err)
	_, err = s.Sign(context.Background(), make([]byte, kmsRawMessageLimit+1))
	require.ErrorContains(t, err, "RAW message limit")
}

func TestOpenUnknownAlgorithm(t *testing.T) {
	_, err := Open(context.Background(), Config{KeyID: "k", Algorithm: "rsa-9000"})
	require.ErrorContains(t, err, "unknown algorithm")
}
