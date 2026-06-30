package awskms

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cosmos/kms/config"
	pb "github.com/cosmos/kms/gen/signerservice"
)

// TestGRPCSignerRoundtrip exercises the SignerService adapter end to end against
// the in-process fake KMS: the public key is the 32-byte ed25519 key, the scheme
// is ED25519, and Sign returns a 64-byte signature the same key verifies.
func TestGRPCSignerRoundtrip(t *testing.T) {
	f := newFakeKMS(t)
	be, err := open(context.Background(), f, "alias/attestor", algos[config.AlgoED25519])
	require.NoError(t, err)
	s := &Signer{be: be}

	require.Equal(t, pb.SignatureScheme_ED25519, s.Scheme())

	pub := s.PubKey()
	require.Len(t, pub, ed25519.PublicKeySize)
	require.Equal(t, []byte(f.priv.Public().(ed25519.PublicKey)), pub)

	msg := []byte("attestation payload")
	sig, err := s.Sign(context.Background(), msg)
	require.NoError(t, err)
	require.Len(t, sig, ed25519.SignatureSize)
	require.True(t, ed25519.Verify(ed25519.PublicKey(pub), msg, sig),
		"SignerService pubkey must verify the KMS signature")
}

// TestOpenSignerRejectsNonEd25519Algorithm guards against a future secp256k1
// registry entry being silently served under the ED25519 scheme. The rejection
// happens before any AWS call, so no network/credentials are needed.
func TestOpenSignerRejectsNonEd25519Algorithm(t *testing.T) {
	_, err := OpenSigner(context.Background(), Config{KeyID: "k", Algorithm: config.AlgoSecp256k1})
	require.ErrorContains(t, err, "only")
}
