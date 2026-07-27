package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInitCreatesConfigAndIdentity(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, runInit(home))

	_, err := os.Stat(filepath.Join(home, "kms.yaml"))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(home, "identity.json"))
	require.NoError(t, err)
}

func TestStateInitSeedsFloorAndRefusesOverwrite(t *testing.T) {
	home := t.TempDir()
	yaml := "chains:\n  - id: c1\nkeys:\n  - chain_ids: [c1]\n    key_file: key.json\n"
	require.NoError(t, os.WriteFile(filepath.Join(home, "kms.yaml"), []byte(yaml), 0o600))

	root := rootCmd()
	root.SetArgs([]string{"state", "init", "--home", home, "--chain", "c1", "--height", "123"})
	require.NoError(t, root.Execute())

	raw, err := os.ReadFile(filepath.Join(home, "state", "c1.json"))
	require.NoError(t, err)
	require.Contains(t, string(raw), `"123"`) // cmtjson encodes int64 height as a string

	root = rootCmd()
	root.SetArgs([]string{"state", "init", "--home", home, "--chain", "c1", "--height", "5"})
	require.ErrorContains(t, root.Execute(), "refusing to overwrite")
}

func TestPeerIDFromIdentity(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, runInit(home))
	id, err := peerIDFromIdentity(filepath.Join(home, "identity.json"))
	require.NoError(t, err)
	require.NotEmpty(t, id)
}
