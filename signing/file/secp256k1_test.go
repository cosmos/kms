package file

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

	pb "github.com/cosmos/kms/gen/signerservice"
)

const testHexKey = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"

func writeKeyFile(t *testing.T, hexKey string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key.hex")
	require.NoError(t, os.WriteFile(p, []byte(hexKey), 0o600))
	return p
}

func TestLoadSecp256k1FromFileMatchesString(t *testing.T) {
	fromFile, err := LoadSecp256k1FromFile(writeKeyFile(t, testHexKey))
	require.NoError(t, err)
	fromStr, err := LoadSecp256k1FromString(testHexKey)
	require.NoError(t, err)
	require.Equal(t, fromStr.PubKey(), fromFile.PubKey())
}

func TestLoadSecp256k1FromFileMissing(t *testing.T) {
	_, err := LoadSecp256k1FromFile(filepath.Join(t.TempDir(), "nope.hex"))
	require.Error(t, err)
}

func TestSignDigestRecovers(t *testing.T) {
	s, err := LoadSecp256k1FromString(testHexKey)
	require.NoError(t, err)
	require.Equal(t, pb.SignatureScheme_ECDSA_SECP256K1, s.Scheme())

	digest := sha256.Sum256([]byte("attestation payload"))
	out, err := s.Sign(digest[:])
	require.NoError(t, err)
	require.Len(t, out, 65)
	r, sig, v := out[0:32], out[32:64], out[64]
	require.True(t, v == 0 || v == 1, "v must be a 0/1 recovery id")

	// S must be canonical (low-S): s <= N/2.
	sInt := new(big.Int).SetBytes(sig)
	halfN := new(big.Int).Rsh(secp256k1.Params().N, 1)
	require.LessOrEqual(t, sInt.Cmp(halfN), 0, "signature S must be low-S")

	// Reconstruct decred compact form (<27+recid><R><S>) and recover the pubkey.
	compact := make([]byte, 65)
	compact[0] = 27 + v
	copy(compact[1:33], r)
	copy(compact[33:65], sig)
	recovered, _, err := ecdsa.RecoverCompact(compact, digest[:])
	require.NoError(t, err)
	require.Equal(t, s.PubKeyUncompressed(), recovered.SerializeUncompressed())
}

func TestSignRejectsBadDigestLength(t *testing.T) {
	s, err := LoadSecp256k1FromString(testHexKey)
	require.NoError(t, err)
	_, err = s.Sign(make([]byte, 31))
	require.Error(t, err)
}

func TestLoadSecp256k1FromStringRejectsBadKey(t *testing.T) {
	_, err := LoadSecp256k1FromString("not-hex")
	require.Error(t, err)

	// 31 bytes instead of 32.
	_, err = LoadSecp256k1FromString(hex.EncodeToString(make([]byte, 31)))
	require.Error(t, err)
}

func TestLoadSecp256k1Accepts0xPrefix(t *testing.T) {
	// Same key with and without the "0x" prefix (and surrounding whitespace)
	// must yield the same pubkey.
	plain, err := LoadSecp256k1FromString(testHexKey)
	require.NoError(t, err)
	prefixed, err := LoadSecp256k1FromString("  0x" + testHexKey + "\n")
	require.NoError(t, err)
	require.Equal(t, plain.PubKey(), prefixed.PubKey())
}

func TestPubKeyShapes(t *testing.T) {
	s, err := LoadSecp256k1FromString(testHexKey)
	require.NoError(t, err)
	require.Len(t, s.PubKey(), 33)
	require.Len(t, s.PubKeyUncompressed(), 65)
	require.Equal(t, byte(0x04), s.PubKeyUncompressed()[0])
	require.IsType(t, &secp256k1.PublicKey{}, s.pub)
}
