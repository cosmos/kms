package signer

import (
	"context"
	"testing"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/stretchr/testify/require"

	"github.com/cosmos/kms/config"
)

// stubBackend is a minimal ed25519 signing.Signer for tests.
type stubBackend struct{ priv crypto.PrivKey }

func (s stubBackend) PubKey() []byte                                   { return s.priv.PubKey().Bytes() }
func (s stubBackend) Scheme() config.Algorithm                         { return config.AlgoED25519 }
func (s stubBackend) Sign(_ context.Context, b []byte) ([]byte, error) { return s.priv.Sign(b) }
func (s stubBackend) Close() error                                     { return nil }

func TestAdapterSatisfiesPrivKeyAndSigns(t *testing.T) {
	priv := ed25519.GenPrivKey()
	be := stubBackend{priv: priv}

	pk, err := newBackendPrivKey(context.Background(), be)
	require.NoError(t, err)

	// The compile-time interface assertion lives in privkey_adapter.go
	// (var _ crypto.PrivKey = (*backendPrivKey)(nil)); here we exercise behavior.
	require.True(t, pk.PubKey().Equals(priv.PubKey()))
	require.Equal(t, "ed25519", pk.Type())

	msg := []byte("hello")
	sig, err := pk.Sign(msg)
	require.NoError(t, err)
	require.True(t, pk.PubKey().VerifySignature(msg, sig))
}

// ethStub reports the eth scheme, which has no cometbft pubkey type.
type ethStub struct{ stubBackend }

func (ethStub) Scheme() config.Algorithm { return config.AlgoSecp256k1Eth }

func TestAdapterRejectsSchemeWithoutCometPubKey(t *testing.T) {
	be := ethStub{stubBackend{priv: ed25519.GenPrivKey()}}
	_, err := newBackendPrivKey(context.Background(), be)
	require.ErrorContains(t, err, "no cometbft pubkey type")
}
