package app_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/stretchr/testify/require"

	"github.com/cosmos/kms/config"
	"github.com/cosmos/kms/internal/app"
)

func TestBuildWiresChainSigners(t *testing.T) {
	home := t.TempDir()

	keyPath := filepath.Join(home, "key.json")
	raw, err := cmtjson.MarshalIndent(struct {
		PrivKey ed25519.PrivKey `json:"priv_key"`
	}{PrivKey: ed25519.GenPrivKey()}, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyPath, raw, 0o600))

	identPath := filepath.Join(home, "identity.json")

	c := &config.Config{
		Chains:     []config.Chain{{ID: "c1"}},
		Validators: []config.Validator{{ChainID: "c1", Addr: "tcp://127.0.0.1:1", IdentityKey: identPath}},
		Keys:       []config.Key{{ChainIDs: []string{"c1"}, Backend: config.BackendFile, FileConfig: config.FileConfig{KeyFile: keyPath}}},
	}
	require.NoError(t, c.Validate(home))

	mgr, cleanup, err := app.Build(c, log.TestingLogger())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	require.NotNil(t, mgr)
}

func TestBuildFailsOnMissingKeyFile(t *testing.T) {
	home := t.TempDir()
	c := &config.Config{
		Chains:     []config.Chain{{ID: "c1"}},
		Validators: []config.Validator{{ChainID: "c1", Addr: "tcp://127.0.0.1:1", IdentityKey: filepath.Join(home, "id.json")}},
		Keys:       []config.Key{{ChainIDs: []string{"c1"}, Backend: config.BackendFile, FileConfig: config.FileConfig{KeyFile: filepath.Join(home, "missing.json")}}},
	}
	require.NoError(t, c.Validate(home))
	_, cleanup, err := app.Build(c, log.TestingLogger())
	t.Cleanup(cleanup)
	require.Error(t, err)
}
