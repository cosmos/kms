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

// PrivateKeyFromSigner returns the private key from the signer.
// Use this only for operational purposes.
func PrivateKeyFromSigner(signer signing.Signer) ([]byte, error) {
	if signer == nil {
		return nil, fmt.Errorf("signer is nil")
	}

	switch signer.Scheme() {
	case config.AlgoED25519:
		return signer.(*Ed25519Signer).priv.Bytes(), nil
	case config.AlgoSecp256k1Eth:
		return signer.(*Secp256k1EthSigner).priv.Serialize(), nil
	default:
		return nil, fmt.Errorf("private key export is not supported for %s", signer.Scheme())
	}
}
