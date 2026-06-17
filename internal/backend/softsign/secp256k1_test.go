package softsign

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/stretchr/testify/require"
)

func writeKeyFile(t *testing.T, hexKey string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "key.hex")
	require.NoError(t, os.WriteFile(p, []byte(hexKey), 0o600))
	return p
}

func TestLoadSecp256k1AndSignDigestRecovers(t *testing.T) {
	// Deterministic test key (32 bytes).
	const hexKey = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
	path := writeKeyFile(t, hexKey)

	s, err := LoadSecp256k1(path)
	require.NoError(t, err)
	require.Equal(t, "secp256k1", s.Algo())

	digest := sha256.Sum256([]byte("attestation payload"))
	r, sig, v, err := s.SignDigest(digest[:])
	require.NoError(t, err)
	require.Len(t, r, 32)
	require.Len(t, sig, 32)
	require.Len(t, v, 1)
	require.True(t, v[0] == 0 || v[0] == 1, "v must be a 0/1 recovery id")

	// S must be canonical (low-S): s <= N/2.
	sInt := new(big.Int).SetBytes(sig)
	halfN := new(big.Int).Rsh(secp256k1.Params().N, 1)
	require.LessOrEqual(t, sInt.Cmp(halfN), 0, "signature S must be low-S")

	// Reconstruct decred compact form (<27+recid><R><S>) and recover the pubkey.
	compact := make([]byte, 65)
	compact[0] = 27 + v[0]
	copy(compact[1:33], r)
	copy(compact[33:65], sig)
	recovered, _, err := ecdsa.RecoverCompact(compact, digest[:])
	require.NoError(t, err)
	require.Equal(t, s.PubKeyUncompressed(), recovered.SerializeUncompressed())
}

func TestLoadSecp256k1RejectsBadKey(t *testing.T) {
	_, err := LoadSecp256k1(writeKeyFile(t, "not-hex"))
	require.Error(t, err)

	// 31 bytes instead of 32.
	short := hex.EncodeToString(make([]byte, 31))
	_, err = LoadSecp256k1(writeKeyFile(t, short))
	require.Error(t, err)
}

func TestPubKeyShapes(t *testing.T) {
	const hexKey = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
	s, err := LoadSecp256k1(writeKeyFile(t, hexKey))
	require.NoError(t, err)
	require.Len(t, s.PubKey(), 33)
	require.Len(t, s.PubKeyUncompressed(), 65)
	require.Equal(t, byte(0x04), s.PubKeyUncompressed()[0])
	require.IsType(t, &secp256k1.PublicKey{}, s.pub)
}
