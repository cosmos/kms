package file_test

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/mldsa65"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/stretchr/testify/require"

	"github.com/cosmos/kms/config"
	"github.com/cosmos/kms/signing/file"
)

func TestMLDSA65LoadBase64AndSign(t *testing.T) {
	priv, err := mldsa65.GenPrivKey()
	require.NoError(t, err)
	dir := t.TempDir()
	path := filepath.Join(dir, "key.b64")
	require.NoError(t, os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(priv.Bytes())), 0o600))

	s, err := file.LoadMLDSA65(path)
	require.NoError(t, err)

	require.Equal(t, config.AlgoMLDSA65, s.Scheme())
	require.Equal(t, priv.PubKey().Bytes(), s.PubKey())

	msg := []byte("canonical-sign-bytes")
	sig, err := s.Sign(context.Background(), msg)
	require.NoError(t, err)
	require.True(t, priv.PubKey().VerifySignature(msg, sig))
}

func TestMLDSA65LoadPrivValidatorKeyJSON(t *testing.T) {
	priv, err := mldsa65.GenPrivKey()
	require.NoError(t, err)
	// Marshal through the interface-typed field so the JSON carries the
	// {"type","value"} envelope, exactly as privval.FilePVKey writes it.
	raw, err := cmtjson.MarshalIndent(struct {
		PrivKey crypto.PrivKey `json:"priv_key"`
	}{PrivKey: priv}, "", "  ")
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "priv_validator_key.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))

	s, err := file.LoadMLDSA65(path)
	require.NoError(t, err)
	require.Equal(t, priv.PubKey().Bytes(), s.PubKey())
}

func TestMLDSA65LoadRejectsWrongSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.b64")
	require.NoError(t, os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString([]byte("short"))), 0o600))
	_, err := file.LoadMLDSA65(path)
	require.Error(t, err)
}

func TestMLDSA65OpenViaFileConfig(t *testing.T) {
	priv, err := mldsa65.GenPrivKey()
	require.NoError(t, err)
	dir := t.TempDir()
	path := filepath.Join(dir, "key.b64")
	require.NoError(t, os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(priv.Bytes())), 0o600))

	s, err := file.Open(file.Config{Algorithm: config.AlgoMLDSA65, KeyFile: path})
	require.NoError(t, err)
	require.Equal(t, config.AlgoMLDSA65, s.Scheme())
}
