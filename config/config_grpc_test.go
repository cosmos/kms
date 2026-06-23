package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func touch(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
	return p
}

func baseGRPC(t *testing.T) (*Config, string) {
	t.Helper()
	home := t.TempDir()
	cert := touch(t, home, "server.crt")
	key := touch(t, home, "server.key")
	kkey := touch(t, home, "key.hex")
	c := &Config{
		GRPC: &GRPCConfig{
			Listen:  "0.0.0.0:9090",
			TLSCert: cert,
			TLSKey:  key,
			Keys: []GRPCKey{{
				ID:         "attestor-1",
				FileConfig: FileConfig{KeyFile: kkey},
			}},
		},
	}
	return c, home
}

func TestValidateGRPCOK(t *testing.T) {
	c, home := baseGRPC(t)
	require.NoError(t, c.Validate(home))
}

func TestValidateGRPCRequiresKey(t *testing.T) {
	c, home := baseGRPC(t)
	c.GRPC.Keys = nil
	require.Error(t, c.Validate(home))
}

func TestValidateRejectsEmptyConfig(t *testing.T) {
	c := &Config{}
	require.Error(t, c.Validate(t.TempDir()))
}

func TestValidateGRPCMissingTLSFile(t *testing.T) {
	c, home := baseGRPC(t)
	c.GRPC.TLSCert = "does-not-exist.crt"
	require.Error(t, c.Validate(home))
}

func TestValidateGRPCDuplicateKeyID(t *testing.T) {
	c, home := baseGRPC(t)
	dup := c.GRPC.Keys[0]
	c.GRPC.Keys = append(c.GRPC.Keys, dup)
	require.Error(t, c.Validate(home))
}

func TestValidateGRPCAWSKMSOK(t *testing.T) {
	c, home := baseGRPC(t)
	c.GRPC.Keys = []GRPCKey{{ID: "a1", Backend: BackendAWSKMS, KeyID: "alias/attestor", Algorithm: "ed25519"}}
	require.NoError(t, c.Validate(home))
}

func TestValidateGRPCAWSKMSRequiresKeyID(t *testing.T) {
	c, home := baseGRPC(t)
	c.GRPC.Keys = []GRPCKey{{ID: "a1", Backend: BackendAWSKMS}}
	require.ErrorContains(t, c.Validate(home), "key_id")
}

func TestValidateGRPCAWSKMSUnknownAlgorithm(t *testing.T) {
	c, home := baseGRPC(t)
	c.GRPC.Keys = []GRPCKey{{ID: "a1", Backend: BackendAWSKMS, KeyID: "alias/attestor", Algorithm: "rsa-9000"}}
	require.ErrorContains(t, c.Validate(home), "algorithm")
}
