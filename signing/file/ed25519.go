// Package file implements file-backed signing keys read from disk into process
// memory. NOT for production custody: the private key is held in memory.
package file

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cosmos/kms/config"
	"github.com/cosmos/kms/signing"
)

// Backend is a file-backed Ed25519 key held in memory.
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

	priv, err := parseKey(raw)
	if err != nil {
		return nil, fmt.Errorf("file: parse key file %q: %w", path, err)
	}
	return &Ed25519Signer{priv: priv, pub: priv.PubKey()}, nil
}

func parseKey(raw []byte) (crypto.PrivKey, error) {
	// Try priv_validator_key.json shape first (both concrete and interface-typed variants).
	if bytes.Contains(raw, []byte("priv_key")) {
		// Try interface-typed JSON first ({"type":"...","value":"..."} envelope).
		var kfIface struct {
			PrivKey crypto.PrivKey `json:"priv_key"`
		}
		if err := cmtjson.Unmarshal(raw, &kfIface); err == nil && kfIface.PrivKey != nil {
			return kfIface.PrivKey, nil
		}
		// Try concrete ed25519 JSON (plain base64 string value).
		var kfConcrete struct {
			PrivKey ed25519.PrivKey `json:"priv_key"`
		}
		if err := cmtjson.Unmarshal(raw, &kfConcrete); err == nil && len(kfConcrete.PrivKey) == ed25519.PrivateKeySize {
			return kfConcrete.PrivKey, nil
		}
	}
	// Fall back to base64 raw 64-byte ed25519 key.
	dec, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil {
		return nil, fmt.Errorf("not priv_validator_key.json and not base64: %w", err)
	}
	if len(dec) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("expected %d-byte ed25519 key, got %d", ed25519.PrivateKeySize, len(dec))
	}
	return ed25519.PrivKey(dec), nil
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
