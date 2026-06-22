// Command kms is an external remote signer.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/lp2p"
	"github.com/spf13/cobra"

	"github.com/cosmos/kms/config"
	"github.com/cosmos/kms/internal/app"
	"github.com/cosmos/kms/internal/identity"
	"github.com/cosmos/kms/internal/version"
)

// home is the home directory of kms
var home string

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{Use: "kms", Short: "External remote signer"}
	root.PersistentFlags().StringVar(&home, "home", ".", "the home directory of kms")
	root.AddCommand(versionCmd(), initCmd(), startCmd(), peerIDCmd())
	return root
}

func peerIDFromIdentity(path string) (string, error) {
	key, err := identity.LoadOrGen(path)
	if err != nil {
		return "", err
	}
	id, err := lp2p.IDFromPrivateKey(key)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func peerIDCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "peer-id",
		Short: "Print the libp2p peer ID of the KMS identity key (for the validator's noise allowlist)",
		RunE: func(_ *cobra.Command, _ []string) error {
			id, err := peerIDFromIdentity(filepath.Join(home, "identity.json"))
			if err != nil {
				return err
			}
			fmt.Println(id)
			return nil
		},
	}
	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the kms version",
		RunE: func(_ *cobra.Command, _ []string) error {
			fmt.Println(version.String())
			return nil
		},
	}
}

func initCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Scaffold a config file and generate an identity key",
		RunE:  func(_ *cobra.Command, _ []string) error { return runInit(home) },
	}
	return cmd
}

func runInit(home string) error {
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	path := cfgPath(home)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.WriteFile(path, []byte(config.DefaultTemplate), 0o600); err != nil {
			return err
		}
	}
	if _, err := identity.LoadOrGen(filepath.Join(home, "identity.json")); err != nil {
		return err
	}
	fmt.Printf("initialized kms in %s\n", home)
	return nil
}

func startCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Connect to validators and serve signing requests",
		RunE: func(_ *cobra.Command, _ []string) error {
			logger := log.NewTMLogger(log.NewSyncWriter(os.Stdout))

			cfg, err := config.Load(cfgPath(home))
			if err != nil {
				return err
			}
			if err := cfg.Validate(home); err != nil {
				return err
			}

			mgr, cleanup, err := app.Build(cfg, logger)
			if err != nil {
				return err
			}
			defer cleanup()
			if err := mgr.Start(); err != nil {
				return err
			}
			defer mgr.Stop()

			grpcErr := make(chan error, 1)
			gs, lis, err := app.BuildGRPC(cfg, home, logger)
			if err != nil {
				return err
			}
			if gs != nil {
				go func() {
					logger.Info("serving signerservice gRPC", "addr", lis.Addr().String())
					if serr := gs.Serve(lis); serr != nil {
						grpcErr <- serr
					}
				}()
				defer gs.GracefulStop()
			}

			logger.Info("kms started; press Ctrl-C to stop")
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
			select {
			case <-sig:
				logger.Info("kms shutting down")
			case serr := <-grpcErr:
				return fmt.Errorf("signerservice gRPC server failed: %w", serr)
			}
			return nil
		},
	}
	return cmd
}

func cfgPath(home string) string {
	return filepath.Join(home, "kms.yaml")
}
