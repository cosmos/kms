package awskms

import (
	"crypto/ed25519"
	"crypto/x509"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/cosmos/kms/config"

	"github.com/cometbft/cometbft/crypto"
	cometed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometsecp "github.com/cometbft/cometbft/crypto/secp256k1"

	"github.com/cosmos/kms/signing/ecdsasig"
)

// keyAlgo describes how one validator key algorithm maps onto AWS KMS: which key
// spec the KMS key must have, which signing algorithm to request, how to turn
// the DER SubjectPublicKeyInfo that GetPublicKey returns into a crypto.PubKey,
// and how to normalize the signature KMS returns.
//
// Adding a new key type (secp256k1, ml-dsa, ...) is a single new entry in algos:
// its key spec, its signing algorithm, a decodePub, and — for ECDSA-family keys
// — a fixSig that DER-decodes the (r,s) signature, normalizes s to low-S, and
// emits the 64-byte r||s consensus wire form.
type keyAlgo struct {
	name      config.Algorithm
	keySpec   types.KeySpec
	signAlgo  types.SigningAlgorithmSpec
	decodePub func(spki []byte) (crypto.PubKey, error)
	// fixSig converts the raw signature KMS returns into the consensus wire
	// format. Ed25519 KMS signatures are already raw 64-byte R||S, so it is the
	// identity; ECDSA-family keys will DER-decode (r,s), apply low-S, and emit
	// 64-byte r||s here.
	fixSig func(raw []byte) ([]byte, error)
}

// algos is the registry of supported key algorithms, keyed by the config
// "algorithm" string.
//
// Ed25519 uses the ECC_NIST_EDWARDS25519 key spec with the ED25519_SHA_512
// signing algorithm and MessageType=RAW, which is standard RFC 8032 PureEd25519
// over the raw message — identical to the file/pkcs11 backends. The
// signature is a fixed raw 64 bytes, so fixSig is the identity.
//
// Secp256k1 uses the ECC_SECG_P256K1 key spec with ECDSA_SHA_256 and
// MessageType=RAW: KMS SHA-256-hashes the consensus sign-bytes and signs,
// matching cometbft secp256k1 consensus. KMS returns a DER (r,s) signature with
// no low-S guarantee, so fixSig normalizes it to the 64-byte r‖s low-S form
// cometbft verification requires. This is the consensus (privval) path; the
// gRPC SignerService uses the recoverable form via Secp256k1Signer (see
// secp256k1.go), which shares the same ecdsasig conversion library.
var algos = map[config.Algorithm]keyAlgo{
	config.AlgoED25519: {
		name:      config.AlgoED25519,
		keySpec:   types.KeySpecEccNistEdwards25519,
		signAlgo:  types.SigningAlgorithmSpecEd25519Sha512,
		decodePub: decodeEd25519Pub,
		fixSig:    func(raw []byte) ([]byte, error) { return raw, nil },
	},
	config.AlgoSecp256k1: {
		name:      config.AlgoSecp256k1,
		keySpec:   types.KeySpecEccSecgP256k1,
		signAlgo:  types.SigningAlgorithmSpecEcdsaSha256,
		decodePub: decodeSecp256k1Pub,
		fixSig:    ecdsasig.ConsensusSig,
	},
}

// decodeSecp256k1Pub turns the DER SubjectPublicKeyInfo returned by KMS
// GetPublicKey into a cometbft secp256k1 crypto.PubKey (33-byte compressed).
func decodeSecp256k1Pub(spki []byte) (crypto.PubKey, error) {
	pub, err := ecdsasig.ParsePubKeySPKI(spki)
	if err != nil {
		return nil, err
	}
	return cometsecp.PubKey(pub.SerializeCompressed()), nil
}

// decodeEd25519Pub turns the DER SubjectPublicKeyInfo returned by KMS
// GetPublicKey into an ed25519 crypto.PubKey.
func decodeEd25519Pub(spki []byte) (crypto.PubKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("parse SubjectPublicKeyInfo: %w", err)
	}
	edPub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected ed25519 public key, got %T", parsed)
	}
	if len(edPub) != cometed25519.PubKeySize {
		return nil, fmt.Errorf("ed25519 public key: expected %d bytes, got %d", cometed25519.PubKeySize, len(edPub))
	}
	pub := make(cometed25519.PubKey, cometed25519.PubKeySize)
	copy(pub, edPub)
	return pub, nil
}
