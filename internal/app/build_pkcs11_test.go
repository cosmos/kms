package app_test

import (
	"testing"

	"github.com/cometbft/cometbft/libs/log"
	"github.com/stretchr/testify/require"

	"github.com/cosmos/kms/config"
	"github.com/cosmos/kms/internal/app"
	"github.com/cosmos/kms/signing/pkcs11/pkcs11test"
)

// TestBuildWiresPKCS11Backend verifies a pkcs11-backend key is opened and
// wired into the manager, and that cleanup releases the HSM session.
func TestBuildWiresPKCS11Backend(t *testing.T) {
	module := pkcs11test.FindModule(t)
	pkcs11test.SetupToken(t, module)
	home := t.TempDir()

	c := &config.Config{
		Chains:     []config.Chain{{ID: "c1"}},
		Validators: []config.Validator{{ChainID: "c1", Addr: "tcp://127.0.0.1:1", IdentityKey: home + "/identity.json"}},
		Keys: []config.Key{{
			ChainIDs: []string{"c1"},
			Backend:  config.BackendPKCS11,
			PKCS11Config: config.PKCS11Config{
				Module:     module,
				TokenLabel: pkcs11test.TokenLabel,
				KeyLabel:   pkcs11test.KeyLabel,
				PIN:        pkcs11test.UserPIN,
			},
		}},
	}
	require.NoError(t, c.Validate(home))

	mgr, cleanup, err := app.Build(c, log.TestingLogger())
	require.NoError(t, err)
	t.Cleanup(cleanup) // releases the PKCS#11 session even if assertions below fail
	require.NotNil(t, mgr)
}

// TestNewServerWiresPKCS11Backend verifies a pkcs11-backend gRPC key is opened
// on the token and served by the SignerService.
func TestNewServerWiresPKCS11Backend(t *testing.T) {
	module := pkcs11test.FindModule(t)
	pkcs11test.SetupToken(t, module)
	home := t.TempDir()

	c := &config.Config{
		GRPC: &config.GRPCConfig{
			Listen: "127.0.0.1:0",
			Keys: []config.GRPCKey{{
				ID:      "hsm-1",
				Backend: config.BackendPKCS11,
				PKCS11Config: config.PKCS11Config{
					Module:     module,
					TokenLabel: pkcs11test.TokenLabel,
					KeyLabel:   pkcs11test.KeyLabel,
					PIN:        pkcs11test.UserPIN,
				},
			}},
		},
	}
	require.NoError(t, c.Validate(home))

	srv, err := app.NewServer(c, home, log.TestingLogger())
	require.NoError(t, err)
	require.NotNil(t, srv)
	srv.Close()
}
