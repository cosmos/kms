package signer

import (
	"context"
	"fmt"

	"github.com/cometbft/cometbft/crypto"
	cometed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometmldsa "github.com/cometbft/cometbft/crypto/mldsa65"
	cometsecp "github.com/cometbft/cometbft/crypto/secp256k1"

	"github.com/cosmos/kms/config"
	"github.com/cosmos/kms/signing"
)

// signerPrivKey adapts a signing.Signer to crypto.PrivKey so it can be handed to
// privval.NewFilePV. Only Sign, PubKey, and Type are exercised by the FilePV
// signing path; Bytes and Equals are intentionally unsupported for remote keys.
type signerPrivKey struct {
	ctx context.Context
	s   signing.Signer
	pub crypto.PubKey
}

var _ crypto.PrivKey = (*signerPrivKey)(nil)

// newSignerPrivKey caches the public key (so PubKey is cheap and FilePV's
// address computation works) and returns the adapter.
func newSignerPrivKey(ctx context.Context, s signing.Signer) (crypto.PrivKey, error) {
	var pub crypto.PubKey
	switch s.Scheme() {
	case config.AlgoED25519:
		pub = cometed25519.PubKey(s.PubKey())
	case config.AlgoSecp256k1:
		pub = cometsecp.PubKey(s.PubKey())
	case config.AlgoMLDSA65:
		mpub, err := cometmldsa.NewPubKeyFromBytes(s.PubKey())
		if err != nil {
			return nil, fmt.Errorf("signer: mldsa65 pubkey: %w", err)
		}
		pub = mpub
	default:
		return nil, fmt.Errorf("signer: no cometbft pubkey type for algorithm %s", string(s.Scheme()))
	}
	return &signerPrivKey{ctx: ctx, s: s, pub: pub}, nil
}

func (k *signerPrivKey) Sign(msg []byte) ([]byte, error) { return k.s.Sign(k.ctx, msg) }
func (k *signerPrivKey) PubKey() crypto.PubKey           { return k.pub }
func (k *signerPrivKey) Type() string                    { return k.pub.Type() }

// Bytes is unsupported: remote/HSM keys never expose private material. It returns
// nil rather than panicking because crypto.PrivKey requires the method; it is not
// called on the FilePV signing path.
func (k *signerPrivKey) Bytes() []byte { return nil }

// Equals compares by public key (private material is unavailable).
func (k *signerPrivKey) Equals(other crypto.PrivKey) bool {
	return k.pub.Equals(other.PubKey())
}
