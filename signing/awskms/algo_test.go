package awskms

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	cometed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometsecp "github.com/cometbft/cometbft/crypto/secp256k1"
	"github.com/cosmos/kms/config"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

func TestDecodeSecp256k1PubFromSPKI(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	spki := secp256k1SPKIForTest(t, priv.PubKey())

	got, err := decodeSecp256k1Pub(spki)
	require.NoError(t, err)
	require.Equal(t, string(config.AlgoSecp256k1), got.Type())
	require.Len(t, got.Bytes(), cometsecp.PubKeySize)
	require.Equal(t, priv.PubKey().SerializeCompressed(), got.Bytes())
}

func TestDecodeSecp256k1PubRejectsGarbage(t *testing.T) {
	_, err := decodeSecp256k1Pub([]byte("not-a-spki"))
	require.Error(t, err)
}

func TestSecp256k1AlgoRegistered(t *testing.T) {
	a, ok := algos[config.AlgoSecp256k1]
	require.True(t, ok)
	require.Equal(t, "ECC_SECG_P256K1", string(a.keySpec))
	require.Equal(t, "ECDSA_SHA_256", string(a.signAlgo))
}

func TestDecodeEd25519PubFromSPKI(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_ = priv

	spki, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)

	got, err := decodeEd25519Pub(spki)
	require.NoError(t, err)
	require.Equal(t, string(config.AlgoED25519), got.Type())
	require.Len(t, got.Bytes(), cometed25519.PubKeySize)
	require.Equal(t, []byte(pub), got.Bytes())
}

func TestDecodeEd25519PubRejectsGarbage(t *testing.T) {
	_, err := decodeEd25519Pub([]byte("not-a-spki"))
	require.Error(t, err)
}

func TestDecodeEd25519PubRejectsNonEd25519(t *testing.T) {
	// An RSA SPKI parses fine but is the wrong key type.
	der := rsaSPKIForTest(t)
	_, err := decodeEd25519Pub(der)
	require.ErrorContains(t, err, "expected ed25519")
}

func TestEd25519AlgoRegistered(t *testing.T) {
	a, ok := algos[config.AlgoED25519]
	require.True(t, ok)
	require.Equal(t, "ECC_NIST_EDWARDS25519", string(a.keySpec))
	require.Equal(t, "ED25519_SHA_512", string(a.signAlgo))
	out, err := a.fixSig([]byte{1, 2, 3})
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2, 3}, out) // identity for ed25519
}

func rsaSPKIForTest(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return der
}
