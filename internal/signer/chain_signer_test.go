package signer_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"

	"github.com/cosmos/kms/config"
	"github.com/cosmos/kms/internal/signer"
)

type memSigner struct{ priv crypto.PrivKey }

func (m memSigner) PubKey() []byte                                   { return m.priv.PubKey().Bytes() }
func (m memSigner) Scheme() config.Algorithm                         { return config.AlgoED25519 }
func (m memSigner) Sign(_ context.Context, b []byte) ([]byte, error) { return m.priv.Sign(b) }
func (m memSigner) Close() error                                     { return nil }

const chainID = "test-chain-1"

func newSigner(t *testing.T) (*signer.ChainSigner, crypto.PubKey, string) {
	t.Helper()
	priv := ed25519.GenPrivKey()
	state := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, signer.InitState(state, 0, 0, 0))
	cs, err := signer.NewChainSigner(chainID, memSigner{priv: priv}, state, false)
	require.NoError(t, err)
	return cs, priv.PubKey(), state
}

func precommit(h int64, r int32) *cmtproto.Vote {
	return &cmtproto.Vote{Type: cmtproto.PrecommitType, Height: h, Round: r}
}

func TestSignVoteProducesVerifiableSignature(t *testing.T) {
	cs, pub, _ := newSigner(t)
	v := precommit(10, 0)
	require.NoError(t, cs.SignVote(chainID, v))
	require.True(t, pub.VerifySignature(types.VoteSignBytes(chainID, v), v.Signature))
}

func TestDoubleSignRegressionRejected(t *testing.T) {
	cs, _, _ := newSigner(t)
	require.NoError(t, cs.SignVote(chainID, precommit(10, 0)))
	err := cs.SignVote(chainID, precommit(9, 0))
	require.Error(t, err)
}

func TestStatePersistsAcrossReload(t *testing.T) {
	priv := ed25519.GenPrivKey()
	state := filepath.Join(t.TempDir(), "state.json")

	cs1, err := signer.NewChainSigner(chainID, memSigner{priv: priv}, state, true)
	require.NoError(t, err)
	require.NoError(t, cs1.SignVote(chainID, precommit(100, 0)))

	cs2, err := signer.NewChainSigner(chainID, memSigner{priv: priv}, state, false)
	require.NoError(t, err)
	require.Error(t, cs2.SignVote(chainID, precommit(50, 0)))

	_, statErr := os.Stat(state)
	require.NoError(t, statErr)
}

func TestMissingOrEmptyStateFileFailsClosed(t *testing.T) {
	priv := ed25519.GenPrivKey()
	state := filepath.Join(t.TempDir(), "state.json")

	// Missing file: refuse to start.
	_, err := signer.NewChainSigner(chainID, memSigner{priv: priv}, state, false)
	require.ErrorContains(t, err, "missing or empty")

	// Empty file (e.g. disk-full truncation): refuse to start.
	require.NoError(t, os.WriteFile(state, nil, 0o600))
	_, err = signer.NewChainSigner(chainID, memSigner{priv: priv}, state, false)
	require.ErrorContains(t, err, "missing or empty")
}

func TestAllowFreshWritesMarkerImmediately(t *testing.T) {
	priv := ed25519.GenPrivKey()
	state := filepath.Join(t.TempDir(), "state.json")

	_, err := signer.NewChainSigner(chainID, memSigner{priv: priv}, state, true)
	require.NoError(t, err)

	// The never-signed marker exists before any sign, so the waiver is consumed:
	// the next start is guarded without --allow-fresh-state.
	raw, err := os.ReadFile(state)
	require.NoError(t, err)
	require.NotEmpty(t, raw)
	cs, err := signer.NewChainSigner(chainID, memSigner{priv: priv}, state, false)
	require.NoError(t, err)
	require.NoError(t, cs.SignVote(chainID, precommit(1, 0)))
}

func TestCorruptStateFileFatalEvenWithAllowFresh(t *testing.T) {
	priv := ed25519.GenPrivKey()
	state := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, os.WriteFile(state, []byte(`{"height": nope`), 0o600))

	_, err := signer.NewChainSigner(chainID, memSigner{priv: priv}, state, true)
	require.Error(t, err)
}

func TestInitStateSeedsDoubleSignFloor(t *testing.T) {
	priv := ed25519.GenPrivKey()
	state := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, signer.InitState(state, 100, 0, 3))

	cs, err := signer.NewChainSigner(chainID, memSigner{priv: priv}, state, false)
	require.NoError(t, err)

	require.Error(t, cs.SignVote(chainID, precommit(100, 0)), "at the floor")
	require.Error(t, cs.SignVote(chainID, precommit(99, 0)), "below the floor")
	require.NoError(t, cs.SignVote(chainID, precommit(101, 0)), "above the floor")
}

func TestInitStateRefusesOverwrite(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, signer.InitState(state, 42, 0, 3))
	require.ErrorContains(t, signer.InitState(state, 0, 0, 0), "refusing to overwrite")
}

func TestVoteExtensionSignedForNonNilPrecommit(t *testing.T) {
	cs, pub, _ := newSigner(t)
	v := &cmtproto.Vote{
		Type:    cmtproto.PrecommitType,
		Height:  10,
		Round:   0,
		BlockID: cmtproto.BlockID{Hash: []byte("01234567890123456789012345678901")},
	}
	require.NoError(t, cs.SignVote(chainID, v))
	require.NotEmpty(t, v.ExtensionSignature)
	require.True(t, pub.VerifySignature(types.VoteExtensionSignBytes(chainID, v), v.ExtensionSignature))
}

func TestConflictingBlockSameHRSRejected(t *testing.T) {
	cs, _, _ := newSigner(t)

	blockA := &cmtproto.Vote{
		Type:    cmtproto.PrecommitType,
		Height:  10,
		Round:   0,
		BlockID: cmtproto.BlockID{Hash: []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")},
	}
	require.NoError(t, cs.SignVote(chainID, blockA))

	// Same H/R/step, DIFFERENT block -> must be refused (conflicting data).
	blockB := &cmtproto.Vote{
		Type:    cmtproto.PrecommitType,
		Height:  10,
		Round:   0,
		BlockID: cmtproto.BlockID{Hash: []byte("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")},
	}
	require.Error(t, cs.SignVote(chainID, blockB))
}

func TestSignProposalVerifiableAndRegressionRejected(t *testing.T) {
	cs, pub, _ := newSigner(t)

	prop := &cmtproto.Proposal{Type: cmtproto.ProposalType, Height: 20, Round: 0}
	require.NoError(t, cs.SignProposal(chainID, prop))
	require.True(t, pub.VerifySignature(types.ProposalSignBytes(chainID, prop), prop.Signature))

	// Lower height must be refused.
	lower := &cmtproto.Proposal{Type: cmtproto.ProposalType, Height: 19, Round: 0}
	require.Error(t, cs.SignProposal(chainID, lower))
}

func TestStateSaveFailurePanicsFailStop(t *testing.T) {
	priv := ed25519.GenPrivKey()
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	cs, err := signer.NewChainSigner(chainID, memSigner{priv: priv}, statePath, true)
	require.NoError(t, err)

	// Sabotage persistence: remove any state file and create a DIRECTORY at the
	// state path, so the atomic write (temp file + rename onto statePath) fails.
	_ = os.Remove(statePath)
	require.NoError(t, os.Mkdir(statePath, 0o755))

	// A sign-state persistence failure must panic (fail-stop), not be swallowed
	// into an error: FilePV has already advanced its in-memory floor, so
	// continuing could release a signature with no floor on disk.
	require.Panics(t, func() { _ = cs.SignVote(chainID, precommit(30, 0)) })
}
