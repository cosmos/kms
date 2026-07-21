package awskms

import (
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cosmos/kms/config"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"

	"github.com/cosmos/kms/signing/ecdsasig"
)

// keyAlgo describes how one key algorithm maps onto AWS KMS:
//   - which key spec the KMS key must have
//   - which signing algorithm to request
//   - how to turn the DER SubjectPublicKeyInfo that GetPublicKey returns into
//     canonical public key bytes
//   - how to normalize the signature KMS returns
//
// Adding a new key type is a new entry in algos plus, for consensus use, its
// cometbft pubkey mapping in internal/signer.
type keyAlgo struct {
	name     config.Algorithm
	keySpec  types.KeySpec
	msgType  types.MessageType
	signAlgo types.SigningAlgorithmSpec
	// decodePub turns the DER SubjectPublicKeyInfo from GetPublicKey into the
	// scheme's canonical public key bytes (32-byte raw ed25519, 33-byte
	// compressed secp256k1).
	decodePub func(spki []byte) ([]byte, error)
	// fixSig converts the raw signature KMS returns into the consensus wire
	// format.
	//   - Ed25519 KMS signatures are already raw 64-byte R||S, so it is the
	//     identity
	//   - ECDSA-family keys will DER-decode (r,s), apply low-S, and emit
	//     64-byte r||s or 65-byte r||s||v here.
	fixSig func(raw, digest, pub []byte) ([]byte, error)
	// prepare, when set, transforms the payload into the message actually sent
	// to KMS (e.g. the FIPS 204 μ for EXTERNAL_MU). Nil sends the payload as-is.
	prepare func(payload, pub []byte) []byte
}

// algos is the registry of supported key algorithms, keyed by the config
// "algorithm" string.
//
// Ed25519 uses the ECC_NIST_EDWARDS25519 key spec with the ED25519_SHA_512
// signing algorithm and MessageType=RAW, which is standard RFC 8032 PureEd25519
// over the raw message — identical to the file/pkcs11 backends. The
// signature is a fixed raw 64 bytes, so fixSig is the identity.
// KMS caps RAW messages at 4096 bytes and offers no pre-hashed Ed25519 mode
// compatible with cometbft's PureEd25519 verification, so payloads above the
// cap (possible with large vote extensions) are rejected locally in Sign.
//
// Secp256k1 uses the ECC_SECG_P256K1 key spec with ECDSA_SHA_256 and
// MessageType=RAW: KMS SHA-256-hashes the consensus sign-bytes and signs,
// matching cometbft secp256k1 consensus. KMS returns a DER (r,s) signature with
// no low-S guarantee, so fixSig normalizes it to the 64-byte r‖s low-S form
// cometbft verification requires. This is the consensus (privval) path; the
// gRPC SignerService signs pre-hashed digests and uses the recoverable form
// instead (see signer.go), sharing the same ecdsasig conversion library.
var algos = map[config.Algorithm]keyAlgo{
	config.AlgoED25519: {
		name:      config.AlgoED25519,
		keySpec:   types.KeySpecEccNistEdwards25519,
		msgType:   types.MessageTypeRaw,
		signAlgo:  types.SigningAlgorithmSpecEd25519Sha512,
		decodePub: decodeEd25519Pub,
		fixSig:    func(raw, digest, pub []byte) ([]byte, error) { return raw, nil },
	},
	config.AlgoSecp256k1: {
		name:      config.AlgoSecp256k1,
		keySpec:   types.KeySpecEccSecgP256k1,
		msgType:   types.MessageTypeRaw,
		signAlgo:  types.SigningAlgorithmSpecEcdsaSha256,
		decodePub: decodeSecp256k1Pub,
		fixSig:    func(raw, digest, pub []byte) ([]byte, error) { return ecdsasig.ConsensusSig(raw) },
	},
	config.AlgoSecp256k1Eth: {
		name:      config.AlgoSecp256k1Eth,
		keySpec:   types.KeySpecEccSecgP256k1,
		msgType:   types.MessageTypeDigest,
		signAlgo:  types.SigningAlgorithmSpecEcdsaSha256,
		decodePub: decodeSecp256k1Pub,
		fixSig:    recoverableSig,
	},
	// ML-DSA-65 signs via MessageType=EXTERNAL_MU: the FIPS 204 message
	// representative μ is computed locally (empty context string) and KMS signs
	// the fixed 64-byte μ, sidestepping the 4096-byte cap KMS puts on RAW
	// messages — vote-extension sign-bytes can exceed it. The resulting
	// signature verifies as pure ML-DSA, the mode cometbft mldsa65 verification
	// expects, and is the packed FIPS 204 form, so fixSig is the identity.
	config.AlgoMLDSA65: {
		name:      config.AlgoMLDSA65,
		keySpec:   types.KeySpecMlDsa65,
		msgType:   types.MessageTypeExternalMu,
		signAlgo:  types.SigningAlgorithmSpecMlDsaShake256,
		decodePub: decodeMLDSA65Pub,
		fixSig:    func(raw, digest, pub []byte) ([]byte, error) { return raw, nil },
		prepare:   mldsaMu,
	},
}

// decodeSecp256k1Pub turns the DER SubjectPublicKeyInfo returned by KMS
// GetPublicKey into the 33-byte compressed public key.
func decodeSecp256k1Pub(spki []byte) ([]byte, error) {
	pub, err := ecdsasig.ParsePubKeySPKI(spki)
	if err != nil {
		return nil, err
	}
	return pub.SerializeCompressed(), nil
}

// recoverableSig converts the DER (r,s) signature KMS returned over digest
// into the 65-byte r‖s‖v recoverable form the ECDSA_SECP256K1ETH scheme requires.
func recoverableSig(raw, digest, pub []byte) ([]byte, error) {
	dpub, err := secp256k1.ParsePubKey(pub)
	if err != nil {
		return nil, fmt.Errorf("parse secp256k1 public key: %w", err)
	}
	return ecdsasig.RecoverDER(raw, digest, dpub)
}

// mldsaMu computes the FIPS 204 message representative
// μ = SHAKE256(tr ‖ 0x00 ‖ 0x00 ‖ payload, 64) with tr = SHAKE256(pub, 64):
// pure-mode signing with an empty context string, so KMS EXTERNAL_MU
// signatures verify under standard pure ML-DSA verification.
func mldsaMu(payload, pub []byte) []byte {
	tr := make([]byte, 64)
	sha3.ShakeSum256(tr, pub)
	buf := make([]byte, 0, len(tr)+2+len(payload))
	buf = append(buf, tr...)
	buf = append(buf, 0, 0)
	buf = append(buf, payload...)
	mu := make([]byte, 64)
	sha3.ShakeSum256(mu, buf)
	return mu
}

// oidMLDSA65 is id-ml-dsa-65 (2.16.840.1.101.3.4.3.18), the SPKI algorithm
// identifier for ML-DSA-65 public keys.
var oidMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}

// decodeMLDSA65Pub turns the DER SubjectPublicKeyInfo returned by KMS
// GetPublicKey into the packed 1952-byte ML-DSA-65 public key.
// crypto/x509 does not know ML-DSA, so the SPKI envelope is parsed directly.
func decodeMLDSA65Pub(spki []byte) ([]byte, error) {
	var parsed struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(spki, &parsed)
	if err != nil {
		return nil, fmt.Errorf("parse SubjectPublicKeyInfo: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("parse SubjectPublicKeyInfo: %d trailing bytes", len(rest))
	}
	if !parsed.Algorithm.Algorithm.Equal(oidMLDSA65) {
		return nil, fmt.Errorf("expected ml-dsa-65 public key, got OID %v", parsed.Algorithm.Algorithm)
	}
	pub := parsed.PublicKey.RightAlign()
	if len(pub) != mldsa65.PublicKeySize {
		return nil, fmt.Errorf("ml-dsa-65 public key: expected %d bytes, got %d", mldsa65.PublicKeySize, len(pub))
	}
	return pub, nil
}

// decodeEd25519Pub turns the DER SubjectPublicKeyInfo returned by KMS
// GetPublicKey into the raw 32-byte public key.
func decodeEd25519Pub(spki []byte) ([]byte, error) {
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("parse SubjectPublicKeyInfo: %w", err)
	}
	edPub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected ed25519 public key, got %T", parsed)
	}
	if len(edPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519 public key: expected %d bytes, got %d", ed25519.PublicKeySize, len(edPub))
	}
	return edPub, nil
}
