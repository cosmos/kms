package app_test

import (
	"path/filepath"
	"testing"

	"github.com/cometbft/cometbft/libs/log"
	"github.com/stretchr/testify/require"

	"github.com/cosmos/kms/config"
	"github.com/cosmos/kms/internal/app"
)

func TestBuildAWSKMSKeyUnreachableErrors(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_MAX_ATTEMPTS", "1")

	home := t.TempDir()

	t.Run("consensus signer", func(t *testing.T) {
		c := &config.Config{
			Chains:     []config.Chain{{ID: "c1"}},
			Validators: []config.Validator{{ChainID: "c1", Addr: "tcp://127.0.0.1:1", IdentityKey: filepath.Join(home, "id.json")}},
			Keys: []config.Key{{
				ChainIDs: []string{"c1"},
				Backend:  config.BackendAWSKMS,
				KeyID:    "alias/validator",
				AWSKMSConfig: config.AWSKMSConfig{
					Region:   "us-east-1",
					Endpoint: "http://127.0.0.1:1", // closed port -> connection refused
				},
			}},
		}
		require.NoError(t, c.Validate(home))

		_, cleanup, err := app.Build(c, log.TestingLogger())
		t.Cleanup(cleanup)
		// The error must come from awskms.Open's GetPublicKey call (connection
		// refused against the closed port), proving the provider was wired in. Before
		// the wiring exists, Build instead errors with "chain has no backend", which
		// does NOT contain this substring — so this assertion is a true red->green.
		require.ErrorContains(t, err, "get public key")
	})

	t.Run("grpc signer", func(t *testing.T) {
		c := &config.Config{
			GRPC: &config.GRPCConfig{
				Listen: "127.0.0.1:0",
				Keys: []config.GRPCKey{{
					ID:      "attestor-1",
					Backend: config.BackendAWSKMS,
					KeyID:   "alias/attestor",
					AWSKMSConfig: config.AWSKMSConfig{
						Region:   "us-east-1",
						Endpoint: "http://127.0.0.1:1", // closed port -> connection refused
					},
				}},
			},
		}

		_, err := app.NewServer(c, home, log.TestingLogger())
		require.ErrorContains(t, err, "get public key")
	})
}
