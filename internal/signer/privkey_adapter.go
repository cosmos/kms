package signer

import (
	"context"
	"fmt"

	"github.com/cometbft/cometbft/crypto"
	cometed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometsecp "github.com/cometbft/cometbft/crypto/secp256k1"

	"github.com/cosmos/kms/config"
	"github.com/cosmos/kms/signing"
)

// backendPrivKey adapts a signing.Backend to crypto.PrivKey so it can be handed to
// privval.NewFilePV. Only Sign, PubKey, and Type are exercised by the FilePV
// signing path; Bytes and Equals are intentionally unsupported for remote keys.
type backendPrivKey struct {
	ctx context.Context
	be  signing.Signer
	pub crypto.PubKey
}

var _ crypto.PrivKey = (*backendPrivKey)(nil)

// newBackendPrivKey caches the public key (so PubKey is cheap and FilePV's
// address computation works) and returns the adapter.
func newBackendPrivKey(ctx context.Context, be signing.Signer) (crypto.PrivKey, error) {
	var pub crypto.PubKey
	switch be.Scheme() {
	case config.AlgoED25519:
		pub = cometed25519.PubKey(be.PubKey())
	case config.AlgoSecp256k1:
		pub = cometsecp.PubKey(be.PubKey())
	default:
		return nil, fmt.Errorf("awskms: no cometbft pubkey type for algorithm %s", string(be.Scheme()))
	}
	return &backendPrivKey{ctx: ctx, be: be, pub: pub}, nil
}

func (k *backendPrivKey) Sign(msg []byte) ([]byte, error) { return k.be.Sign(k.ctx, msg) }
func (k *backendPrivKey) PubKey() crypto.PubKey           { return k.pub }
func (k *backendPrivKey) Type() string                    { return k.pub.Type() }

// Bytes is unsupported: remote/HSM keys never expose private material. It returns
// nil rather than panicking because crypto.PrivKey requires the method; it is not
// called on the FilePV signing path.
func (k *backendPrivKey) Bytes() []byte { return nil }

// Equals compares by public key (private material is unavailable).
func (k *backendPrivKey) Equals(other crypto.PrivKey) bool {
	return k.pub.Equals(other.PubKey())
}
