package file_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/stretchr/testify/require"

	"github.com/cosmos/kms/config"
	"github.com/cosmos/kms/signing/file"
)

func TestLoadBase64AndSign(t *testing.T) {
	priv := ed25519.GenPrivKey()
	dir := t.TempDir()
	path := filepath.Join(dir, "key.b64")
	require.NoError(t, os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(priv.Bytes())), 0o600))

	s, err := file.LoadEd25519(path)
	require.NoError(t, err)

	require.Equal(t, config.AlgoED25519, s.Scheme())
	require.Equal(t, priv.PubKey().Bytes(), s.PubKey())

	msg := []byte("canonical-sign-bytes")
	sig, err := s.Sign(context.Background(), msg)
	require.NoError(t, err)
	require.True(t, priv.PubKey().VerifySignature(msg, sig))
}

func TestLoadPrivValidatorKeyJSON(t *testing.T) {
	priv := ed25519.GenPrivKey()
	raw, err := cmtjson.MarshalIndent(struct {
		PrivKey crypto.PrivKey `json:"priv_key"`
	}{PrivKey: priv}, "", "  ")
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "priv_validator_key.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))

	s, err := file.LoadEd25519(path)
	require.NoError(t, err)
	require.Equal(t, priv.PubKey().Bytes(), s.PubKey())
}

func TestLoadRejectsMissingFile(t *testing.T) {
	_, err := file.LoadEd25519(filepath.Join(t.TempDir(), "nope"))
	require.Error(t, err)
}

func TestGenerateEd25519(t *testing.T) {
	// ACT #1
	acme, err := file.GenerateEd25519(rand.Reader)
	require.NoError(t, err)

	// ASSERT #1
	require.Equal(t, config.AlgoED25519, acme.Scheme())
	require.Len(t, acme.PubKey(), 32)
	require.NotEmpty(t, acme.PubKey())

	// ACT #2
	privBytes, err := file.PrivateKeyFromSigner(acme)
	require.NoError(t, err)
	require.Len(t, privBytes, 64)

	// ACT #3
	reloaded, err := file.NewEd25519(privBytes)
	require.NoError(t, err)

	// ASSERT #2
	require.Equal(t, acme.PubKey(), reloaded.PubKey())

	// ACT #4 — round-trip through base64 file format
	path := filepath.Join(t.TempDir(), "key.b64")
	require.NoError(t, os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(privBytes)), 0o600))
	reloadedFromFile, err := file.LoadEd25519(path)
	require.NoError(t, err)

	// ASSERT #3
	require.Equal(t, acme.PubKey(), reloadedFromFile.PubKey())
}
