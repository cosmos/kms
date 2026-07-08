package file

import (
	"fmt"

	"github.com/cosmos/kms/config"
	"github.com/cosmos/kms/signing"
)

// Config encompasses the subset of config values relevant for constructing a file signer.
type Config struct {
	Algorithm config.Algorithm
	KeyFile   string
}

func Open(cfg Config) (signing.Signer, error) {
	switch cfg.Algorithm {
	case config.AlgoED25519:
		return LoadEd25519(cfg.KeyFile)
	case config.AlgoSecp256k1Eth:
		return LoadSecp256k1Eth(cfg.KeyFile)
	default:
		return nil, fmt.Errorf("file: unknown key type %s", cfg.Algorithm)
	}
}
