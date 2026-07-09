package file

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/mldsa65"
	cmtjson "github.com/cometbft/cometbft/libs/json"

	"github.com/cosmos/kms/config"
	"github.com/cosmos/kms/signing"
)

// MLDSA65Signer is a file-backed ML-DSA-65 (FIPS 204 post-quantum) key held in
// memory.
type MLDSA65Signer struct {
	priv mldsa65.PrivKey
	pub  []byte
}

var _ signing.Signer = (*MLDSA65Signer)(nil)

// LoadMLDSA65 reads a key file. It accepts either a CometBFT
// priv_validator_key.json (typed JSON with a "priv_key" field) or a file
// containing the base64-encoded packed ML-DSA-65 private key.
func LoadMLDSA65(path string) (*MLDSA65Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("file: read key file %q: %w", path, err)
	}
	priv, err := parseMLDSA65Key(raw)
	if err != nil {
		return nil, fmt.Errorf("file: parse key file %q: %w", path, err)
	}
	return &MLDSA65Signer{priv: priv, pub: priv.PubKey().Bytes()}, nil
}

func parseMLDSA65Key(raw []byte) (mldsa65.PrivKey, error) {
	// Try priv_validator_key.json shape first ({"type":"...","value":"..."}
	// envelope on the interface-typed field).
	if bytes.Contains(raw, []byte("priv_key")) {
		var kf struct {
			PrivKey crypto.PrivKey `json:"priv_key"`
		}
		if err := cmtjson.Unmarshal(raw, &kf); err == nil {
			if priv, ok := kf.PrivKey.(mldsa65.PrivKey); ok {
				return priv, nil
			}
			if kf.PrivKey != nil {
				return mldsa65.PrivKey{}, fmt.Errorf("priv_validator_key.json key type %T is not mldsa65", kf.PrivKey)
			}
		}
	}
	// Fall back to base64 packed private key bytes.
	dec, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil {
		return mldsa65.PrivKey{}, fmt.Errorf("not priv_validator_key.json and not base64: %w", err)
	}
	return mldsa65.NewPrivKeyFromBytes(dec)
}

// Scheme reports the config.Algorithm.
func (s *MLDSA65Signer) Scheme() config.Algorithm { return config.AlgoMLDSA65 }

// PubKey returns the packed ML-DSA-65 public key.
func (s *MLDSA65Signer) PubKey() []byte { return s.pub }

// Sign signs signBytes with the in-memory private key.
func (s *MLDSA65Signer) Sign(_ context.Context, signBytes []byte) ([]byte, error) {
	return s.priv.Sign(signBytes)
}

// Close is a no-op for file based signers.
func (s *MLDSA65Signer) Close() error { return nil }
