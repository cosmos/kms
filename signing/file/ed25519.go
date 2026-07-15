// Package file implements file-backed signing keys read from disk into process
// memory. NOT for production custody: the private key is held in memory.
package file

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/cometbft/cometbft/crypto"
	cometed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cosmos/kms/config"
	"github.com/cosmos/kms/signing"
	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
)

// Ed25519Signer is a file-backed Ed25519 key held in memory.
type Ed25519Signer struct {
	priv crypto.PrivKey
	pub  crypto.PubKey
}

var _ signing.Signer = (*Ed25519Signer)(nil)

// LoadEd25519 reads a key file. It accepts either a CometBFT priv_validator_key.json
// (typed JSON with a "priv_key" field) or a file containing the base64-encoded
// 64-byte Ed25519 private key.
func LoadEd25519(path string) (*Ed25519Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("file: read key file %q: %w", path, err)
	}

	priv, err := parseEddsaKey(raw)
	if err != nil {
		return nil, fmt.Errorf("file: parse key file %q: %w", path, err)
	}

	return &Ed25519Signer{priv: priv, pub: priv.PubKey()}, nil
}

func NewEd25519(privateKey []byte) (*Ed25519Signer, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519: expected 64-byte key, got %d", len(privateKey))
	}

	pk := cometed25519.PrivKey(privateKey)

	return &Ed25519Signer{
		priv: pk,
		pub:  pk.PubKey(),
	}, nil
}

func GenerateEd25519(rand io.Reader) (*Ed25519Signer, error) {
	_, pk, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, err
	}

	return NewEd25519(pk)
}

func parseEddsaKey(raw []byte) (crypto.PrivKey, error) {
	const size = ed25519.PrivateKeySize

	// Try priv_validator_key.json shape first (both concrete and interface-typed variants).
	pk := parseFilePrivKey(raw)
	if pk != nil {
		if priv, ok := pk.(cometed25519.PrivKey); ok {
			return priv, nil
		}
		return cometed25519.PrivKey{}, fmt.Errorf("priv_validator_key.json key type %T is not ed25519", pk)
	}

	// Fall back to base64 raw 64-byte ed25519 key.
	dec, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil {
		return nil, fmt.Errorf("not priv_validator_key.json and not base64: %w", err)
	}
	if len(dec) != size {
		return nil, fmt.Errorf("expected %d-byte ed25519 key, got %d", size, len(dec))
	}

	return cometed25519.PrivKey(dec), nil
}

// Scheme reports the config.Algorithm.
func (s *Ed25519Signer) Scheme() config.Algorithm { return config.AlgoED25519 }

// PubKey returns the public key.
func (s *Ed25519Signer) PubKey() []byte { return s.pub.Bytes() }

// Sign signs signBytes with the in-memory private key.
func (s *Ed25519Signer) Sign(_ context.Context, signBytes []byte) ([]byte, error) {
	return s.priv.Sign(signBytes)
}

// Close is a no-op for file based signers.
func (s *Ed25519Signer) Close() error {
	return nil
}
