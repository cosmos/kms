package pkcs11

import (
	"crypto/ed25519"
	"fmt"

	"github.com/cosmos/kms/config"
	"github.com/cosmos/kms/signing/ecdsasig"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/miekg/pkcs11"
)

// ckmEDDSA is the standard PKCS#11 v3.0 EdDSA signing mechanism. miekg/pkcs11
// v1.1.x does not export it, so it is defined here against the spec value.
const ckmEDDSA = 0x00001057

// keyAlgo describes how one validator key algorithm maps onto PKCS#11: which
// signing mechanism to use, how to turn the token's public-key bytes into a
// crypto.PubKey, and how to normalize the raw signature the token returns.
//
// Adding a new key type (ml-dsa, secp256k1eth, ...) is a single new entry in
// algos: its mechanism, a decodePub, and (for ECDSA-family keys) a fixSig that
// converts the token's DER signature into the consensus wire format.
type keyAlgo struct {
	name      config.Algorithm
	mechanism func() []*pkcs11.Mechanism
	decodePub func(ckaECPoint []byte) ([]byte, error)
	fixSig    func(raw, digest, pub []byte) ([]byte, error)
}

// algos is the registry of supported key algorithms, keyed by the config
// "algorithm" string. Ed25519 is the only entry for now.
var algos = map[config.Algorithm]keyAlgo{
	config.AlgoED25519: {
		name:      config.AlgoED25519,
		mechanism: func() []*pkcs11.Mechanism { return []*pkcs11.Mechanism{pkcs11.NewMechanism(ckmEDDSA, nil)} },
		decodePub: decodeEd25519Pub,
		fixSig:    func(raw, digest, pub []byte) ([]byte, error) { return raw, nil },
	},
	config.AlgoSecp256k1Eth: {
		name:      config.AlgoSecp256k1Eth,
		mechanism: func() []*pkcs11.Mechanism { return []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)} },
		decodePub: decodeSecp256k1Pub,
		fixSig:    recoverSig,
	},
}

func recoverSig(raw, digest, pub []byte) ([]byte, error) {
	dpub, err := secp256k1.ParsePubKey(pub)
	if err != nil {
		return nil, fmt.Errorf("parse secp256k1 public key: %w", err)
	}
	return ecdsasig.RecoverCompact(raw, digest, dpub)
}

// decodeEd25519Pub turns a CKA_EC_POINT value into aa byte array.
// PKCS#11 v3.0 encodes the point as a DER OCTET STRING wrapping the 32-byte key
// (0x04 0x20 <32 bytes>); some tokens return the raw 32 bytes. Both are accepted.
func decodeEd25519Pub(ckaECPoint []byte) ([]byte, error) {
	raw := ckaECPoint
	// DER OCTET STRING (tag 0x04) of length 0x20 (32) wrapping the key.
	if len(ckaECPoint) == ed25519.PublicKeySize+2 && ckaECPoint[0] == 0x04 && ckaECPoint[1] == ed25519.PublicKeySize {
		raw = ckaECPoint[2:]
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519 CKA_EC_POINT: expected %d-byte key, got %d bytes", ed25519.PublicKeySize, len(raw))
	}
	return raw, nil
}

// decodeSecp256k1Pub turns a CKA_EC_POINT value into the 33-byte compressed
// public key. PKCS#11 encodes the point as a DER OCTET STRING wrapping the
// SEC1 point (0x04‖X‖Y) either uncompressed or compressed. Both are accepted.
func decodeSecp256k1Pub(ckaECPoint []byte) ([]byte, error) {
	raw := ckaECPoint
	// DER OCTET STRING (0x04) of length 65 uncompressed, or 33 compressed)
	// wrapping the SEC1 point. A bare uncompressed point also starts with x04
	// but is 65 bytes, never 67 or 35.
	if wrapped := len(raw) - 2; (wrapped == 65 || wrapped == 33) && raw[0] == 0x04 && int(raw[1]) == wrapped {
		raw = raw[2:]
	}
	pub, err := secp256k1.ParsePubKey(raw)
	if err != nil {
		return nil, fmt.Errorf("secp256k1 CKA_EC_POINT: %w", err)
	}
	return pub.SerializeCompressed(), nil
}
