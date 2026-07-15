package signer

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/mldsa65"
	"github.com/cometbft/cometbft/crypto/secp256k1eth"
	"github.com/stretchr/testify/require"

	"github.com/cosmos/kms/config"
	"github.com/cosmos/kms/signing/file"
)

// stubSigner is a minimal ed25519 signing.Signer for tests.
type stubSigner struct{ priv crypto.PrivKey }

func (s stubSigner) PubKey() []byte                                   { return s.priv.PubKey().Bytes() }
func (s stubSigner) Scheme() config.Algorithm                         { return config.AlgoED25519 }
func (s stubSigner) Sign(_ context.Context, b []byte) ([]byte, error) { return s.priv.Sign(b) }
func (s stubSigner) Close() error                                     { return nil }

func TestAdapterSatisfiesPrivKeyAndSigns(t *testing.T) {
	priv := ed25519.GenPrivKey()
	st := stubSigner{priv: priv}

	pk, err := newSignerPrivKey(context.Background(), st)
	require.NoError(t, err)

	// The compile-time interface assertion lives in privkey_adapter.go
	// (var _ crypto.PrivKey = (*signerPrivKey)(nil)); here we exercise behavior.
	require.True(t, pk.PubKey().Equals(priv.PubKey()))
	require.Equal(t, "ed25519", pk.Type())

	msg := []byte("hello")
	sig, err := pk.Sign(msg)
	require.NoError(t, err)
	require.True(t, pk.PubKey().VerifySignature(msg, sig))
}

// mldsaStub reports the mldsa65 scheme.
type mldsaStub struct{ stubSigner }

func (mldsaStub) Scheme() config.Algorithm { return config.AlgoMLDSA65 }

func TestAdapterMLDSA65(t *testing.T) {
	priv, err := mldsa65.GenPrivKey()
	require.NoError(t, err)
	st := mldsaStub{stubSigner{priv: priv}}

	pk, err := newSignerPrivKey(context.Background(), st)
	require.NoError(t, err)

	require.True(t, pk.PubKey().Equals(priv.PubKey()))
	require.Equal(t, mldsa65.KeyType, pk.Type())

	msg := []byte("hello")
	sig, err := pk.Sign(msg)
	require.NoError(t, err)
	require.True(t, pk.PubKey().VerifySignature(msg, sig))
}

// TestAdapterSecp256k1Eth proves the adapter's Keccak-256 pre-hash matches what
// cometbft secp256k1eth verification applies: a digest-signing eth signer
// wrapped by the adapter must verify against the raw sign-bytes.
func TestAdapterSecp256k1Eth(t *testing.T) {
	fs, err := file.GenerateSecp256k1Eth(rand.Reader)
	require.NoError(t, err)

	pk, err := newSignerPrivKey(context.Background(), fs)
	require.NoError(t, err)
	require.Equal(t, secp256k1eth.KeyType, pk.Type())

	msg := []byte("hello")
	sig, err := pk.Sign(msg)
	require.NoError(t, err)
	require.True(t, pk.PubKey().VerifySignature(msg, sig))
}

// bogusStub reports a scheme with no cometbft pubkey type.
type bogusStub struct{ stubSigner }

func (bogusStub) Scheme() config.Algorithm { return config.Algorithm("bogus") }

func TestAdapterRejectsSchemeWithoutCometPubKey(t *testing.T) {
	st := bogusStub{stubSigner{priv: ed25519.GenPrivKey()}}
	_, err := newSignerPrivKey(context.Background(), st)
	require.ErrorContains(t, err, "no cometbft pubkey type")
}
