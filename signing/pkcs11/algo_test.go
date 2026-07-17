package pkcs11

import (
	"testing"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

func TestEd25519DecodePub_DERWrapped(t *testing.T) {
	priv := ed25519.GenPrivKey()
	raw := priv.PubKey().Bytes() // 32 bytes
	// PKCS#11 v3.0 returns CKA_EC_POINT as a DER OCTET STRING: 0x04 0x20 <32 bytes>.
	der := append([]byte{0x04, 0x20}, raw...)

	pub, err := algos["ed25519"].decodePub(der)
	require.NoError(t, err)
	require.Equal(t, priv.PubKey().Bytes(), pub)
}

func TestEd25519DecodePub_Raw(t *testing.T) {
	priv := ed25519.GenPrivKey()
	raw := priv.PubKey().Bytes() // some tokens return the raw 32-byte point

	pub, err := algos["ed25519"].decodePub(raw)
	require.NoError(t, err)
	require.Equal(t, priv.PubKey().Bytes(), pub)
}

func TestEd25519DecodePub_BadLength(t *testing.T) {
	_, err := algos["ed25519"].decodePub([]byte{0x01, 0x02, 0x03})
	require.Error(t, err)
}

func TestSecp256k1DecodePub(t *testing.T) {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 1)
	}
	pub := secp256k1.PrivKeyFromBytes(b).PubKey()
	uncompressed := pub.SerializeUncompressed() // 65 bytes
	compressed := pub.SerializeCompressed()     // 33 bytes
	offCurve := pub.SerializeUncompressed()
	offCurve[64] ^= 1 // corrupt Y so the point is off-curve

	testCases := []struct {
		name        string
		key         []byte
		expectedErr string
		expectedPub []byte
	}{
		{"DER-wrapped uncompressed", append([]byte{0x04, 65}, uncompressed...), "", compressed},
		{"DER-wrapped compressed", append([]byte{0x04, 33}, compressed...), "", compressed},
		{"bare compressed", compressed, "", compressed},
		{"bare uncompressed", uncompressed, "", compressed},
		{"garbage", []byte{0x01, 0x02, 0x03}, "invalid length", nil},
		{"empty", []byte{}, "invalid length", nil},
		{"off-curve", offCurve, "", nil},
		{"wrong DER length prefix", append([]byte{0x04, 64}, pub.SerializeUncompressed()...), "", nil},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output, err := decodeSecp256k1Pub(tc.key)
			if tc.expectedErr != "" {
				require.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.Equal(t, tc.expectedPub, output)
			}
		})
	}
}

func TestEd25519FixSig_Identity(t *testing.T) {
	sig := []byte("a-64-byte-ed25519-signature-placeholder-value-for-testing-only!!")
	out, err := algos["ed25519"].fixSig(sig, nil, nil)
	require.NoError(t, err)
	require.Equal(t, sig, out)
}
