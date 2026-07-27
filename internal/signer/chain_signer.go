package signer

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/cometbft/cometbft/crypto"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/privval"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"

	"github.com/cosmos/kms/signing"
)

// ChainSigner signs consensus messages for one chain, enforcing double-sign
// protection by delegating to a CometBFT *privval.FilePV (identical guard +
// crash-recovery logic). It is safe for concurrent use across multiple validator
// connections for the same chain.
type ChainSigner struct {
	chainID string
	mu      sync.Mutex
	fpv     *privval.FilePV
}

var _ types.PrivValidator = (*ChainSigner)(nil)

// NewChainSigner builds the signer. The key signer is wrapped as a crypto.PrivKey
// and handed to privval.NewFilePV; the sign-state at stateFile is reloaded so
// double-sign protection survives restarts. The directory containing stateFile
// must already exist (config validation guarantees this).
//
// A missing or empty state file is a fatal error, not a fresh start.
// A corrupt (non-empty, unparseable) file is always fatal.
func NewChainSigner(chainID string, s signing.Signer, stateFile string, allowFresh bool) (*ChainSigner, error) {
	adapter, err := newSignerPrivKey(context.Background(), s)
	if err != nil {
		return nil, fmt.Errorf("chain %q: load pubkey: %w", chainID, err)
	}

	fpv := privval.NewFilePV(adapter, "", stateFile)

	if err := reloadState(fpv, stateFile, chainID, allowFresh); err != nil {
		return nil, fmt.Errorf("chain %q: reload sign-state: %w", chainID, err)
	}

	return &ChainSigner{chainID: chainID, fpv: fpv}, nil
}

// reloadState loads persisted FilePVLastSignState JSON into fpv.LastSignState,
// preserving the private filePath set by NewFilePV (JSON has no such field).
// Missing and empty files fail closed unless allowFresh, which instead writes
// the height-0 marker (see NewChainSigner).
func reloadState(fpv *privval.FilePV, stateFile, chainID string, allowFresh bool) error {
	raw, err := os.ReadFile(stateFile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if os.IsNotExist(err) || len(raw) == 0 {
		if !allowFresh {
			return fmt.Errorf("sign-state file %s is missing or empty; refusing to start at height 0. "+
				"If this validator has NEVER signed on chain %s, restart with --allow-fresh-state %s; "+
				"or seed the floor with `kms state init` first",
				stateFile, chainID, chainID)
		}
		return InitState(stateFile, 0, 0, 0)
	}
	return cmtjson.Unmarshal(raw, &fpv.LastSignState)
}

// GetPubKey implements types.PrivValidator.
func (c *ChainSigner) GetPubKey() (crypto.PubKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fpv.GetPubKey()
}

// SignVote implements types.PrivValidator.
//
// State-persistence panics from FilePV (Save failure, corrupt sign state) are
// deliberately NOT recovered: FilePV advances its in-memory floor before
// persisting, so recovering here would let a later same-HRS retry release the
// cached signature with no floor on disk.
func (c *ChainSigner) SignVote(chainID string, vote *cmtproto.Vote) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fpv.SignVote(chainID, vote)
}

// SignProposal implements types.PrivValidator. Persistence panics propagate;
// see SignVote.
func (c *ChainSigner) SignProposal(chainID string, proposal *cmtproto.Proposal) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fpv.SignProposal(chainID, proposal)
}
