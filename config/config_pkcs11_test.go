package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cosmos/kms/config"
)

// writeModule creates a stand-in PKCS#11 module file so readability checks pass.
func writeModule(t *testing.T, home string) string {
	t.Helper()
	p := filepath.Join(home, "libsofthsm2.so")
	require.NoError(t, os.WriteFile(p, []byte("not-a-real-module"), 0o600))
	return p
}

// pkcs11Cfg builds a YAML config with one pkcs11-backend key. extra lines are
// appended under that key's list item and must be indented 4 spaces.
func pkcs11Cfg(module, extra string) string {
	return `
chains:
  - id: c1

validators:
  - chain_id: c1
    addr: tcp://127.0.0.1:1
    identity_key: i

keys:
  - chain_ids: [c1]
    backend: pkcs11
    module: "` + module + `"
` + extra
}

func TestPKCS11Good(t *testing.T) {
	home := t.TempDir()
	mod := writeModule(t, home)
	body := pkcs11Cfg(mod, `    token_label: comet
    key_label: validator
    pin: "1234"
`)
	cfgPath := filepath.Join(home, "kms.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(body), 0o600))

	c, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NoError(t, c.Validate(home))
}

func TestPKCS11SatisfiesBackendRequirement(t *testing.T) {
	// A chain whose only key is pkcs11 must not trip the "no backend" check.
	home := t.TempDir()
	mod := writeModule(t, home)
	body := pkcs11Cfg(mod, `    token_label: comet
    key_id: "01ab"
    pin: "1234"
`)
	cfgPath := filepath.Join(home, "kms.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(body), 0o600))
	c, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NoError(t, c.Validate(home))
}

func validatePKCS11(t *testing.T, extra string) error {
	t.Helper()
	home := t.TempDir()
	mod := writeModule(t, home)
	body := pkcs11Cfg(mod, extra)
	cfgPath := filepath.Join(home, "kms.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(body), 0o600))
	c, err := config.Load(cfgPath)
	require.NoError(t, err)
	return c.Validate(home)
}

func TestPKCS11TokenAndSlotMutuallyExclusive(t *testing.T) {
	err := validatePKCS11(t, `    token_label: comet
    slot: 0
    key_label: validator
    pin: "1234"
`)
	require.ErrorContains(t, err, "token_label")
}

func TestPKCS11RequiresTokenOrSlot(t *testing.T) {
	err := validatePKCS11(t, `    key_label: validator
    pin: "1234"
`)
	require.ErrorContains(t, err, "token_label")
}

func TestPKCS11RequiresKeyLabelOrID(t *testing.T) {
	err := validatePKCS11(t, `    token_label: comet
    pin: "1234"
`)
	require.ErrorContains(t, err, "key_label")
}

func TestPKCS11BadKeyIDHex(t *testing.T) {
	err := validatePKCS11(t, `    token_label: comet
    key_id: "zz"
    pin: "1234"
`)
	require.ErrorContains(t, err, "key_id")
}

func TestPKCS11MultiplePINSources(t *testing.T) {
	err := validatePKCS11(t, `    token_label: comet
    key_label: validator
    pin: "1234"
    pin_env: X
`)
	require.ErrorContains(t, err, "pin")
}

func TestPKCS11NoPINSource(t *testing.T) {
	err := validatePKCS11(t, `    token_label: comet
    key_label: validator
`)
	require.ErrorContains(t, err, "pin")
}

func TestPKCS11UnknownAlgorithm(t *testing.T) {
	err := validatePKCS11(t, `    token_label: comet
    key_label: validator
    pin: "1234"
    algorithm: rsa-9000
`)
	require.ErrorContains(t, err, "algorithm")
}

func TestPKCS11MissingModule(t *testing.T) {
	home := t.TempDir()
	body := pkcs11Cfg(filepath.Join(home, "does-not-exist.so"), `    token_label: comet
    key_label: validator
    pin: "1234"
`)
	cfgPath := filepath.Join(home, "kms.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(body), 0o600))
	c, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.ErrorContains(t, c.Validate(home), "module")
}

func TestPKCS11RelativePathsResolvedAgainstHome(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(home, "mod.so"), []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(home, "pin.txt"), []byte("1234"), 0o600))
	body := `
chains:
  - id: c1

validators:
  - chain_id: c1
    addr: tcp://127.0.0.1:1
    identity_key: i

keys:
  - chain_ids: [c1]
    backend: pkcs11
    module: mod.so
    token_label: comet
    key_label: validator
    pin_file: pin.txt
`
	cfgPath := filepath.Join(home, "kms.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(body), 0o600))
	c, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NoError(t, c.Validate(home))
	require.Equal(t, filepath.Join(home, "mod.so"), c.Keys[0].Module)
	require.Equal(t, filepath.Join(home, "pin.txt"), c.Keys[0].PINFile)
}
