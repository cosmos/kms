package signer

import (
	"context"

	"github.com/cosmos/kms/signing"
)

// ConsensusAddress derives the public consensus address for a signer's key,
// in CometBFT's canonical uppercase-hex encoding.
func ConsensusAddress(s signing.Signer) (string, error) {
	pk, err := newSignerPrivKey(context.Background(), s)
	if err != nil {
		return "", err
	}
	return pk.PubKey().Address().String(), nil
}
