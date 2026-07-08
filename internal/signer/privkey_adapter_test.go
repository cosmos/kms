package signer

import (
	"context"
	"testing"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/stretchr/testify/require"

	"github.com/cosmos/kms/config"
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

// ethStub reports the eth scheme, which has no cometbft pubkey type.
type ethStub struct{ stubSigner }

func (ethStub) Scheme() config.Algorithm { return config.AlgoSecp256k1Eth }

func TestAdapterRejectsSchemeWithoutCometPubKey(t *testing.T) {
	st := ethStub{stubSigner{priv: ed25519.GenPrivKey()}}
	_, err := newSignerPrivKey(context.Background(), st)
	require.ErrorContains(t, err, "no cometbft pubkey type")
}
