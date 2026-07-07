// Package config defines the kms YAML configuration and its validation.
package config

import (
	_ "embed"
	"fmt"
	"os"
	"strings"

	"github.com/cometbft/cometbft/privval"
	"github.com/libp2p/go-libp2p/core/peer"
	"gopkg.in/yaml.v3"
)

// DefaultTemplate is the commented config scaffold written by `kms init`.
//
//go:embed default.yaml
var DefaultTemplate string

// Config is the top-level kms configuration.
type Config struct {
	Chains     []Chain     `yaml:"chains"`
	Validators []Validator `yaml:"validators"`
	Keys       []Key       `yaml:"keys"`
	GRPC       *GRPCConfig `yaml:"grpc"`
}

// Chain declares a chain and its double-sign state file.
type Chain struct {
	ID        string `yaml:"id"`
	StateFile string `yaml:"state_file"` // optional; defaulted by Validate
}

// Validator declares one outbound connection to a validator's listener.
type Validator struct {
	ChainID     string `yaml:"chain_id"`
	Addr        string `yaml:"addr"`         // tcp://host:port
	IdentityKey string `yaml:"identity_key"` // ed25519 node-key file for SecretConnection
	Reconnect   *bool  `yaml:"reconnect"`    // default true
}

// Backend identifies which key custodian a Key uses.
type Backend string

const (
	BackendFile   Backend = "file"
	BackendPKCS11 Backend = "pkcs11"
	BackendAWSKMS Backend = "awskms"
)

// Algorithm names a signing key algorithm.
type Algorithm string

const (
	AlgoED25519   Algorithm = "ed25519"
	AlgoSecp256k1 Algorithm = "secp256k1"
)

// Key binds one signing key to one or more chains. Backend selects the custodian;
// the matching embedded config block (FileConfig/PKCS11Config/AWSKMSConfig)
// supplies its parameters. Fields belonging to other backends are ignored.
//
// KeyID and Algorithm are shared across backends and so live here rather than in
// the embedded structs: yaml.v3 rejects a duplicate inline key, and both pkcs11
// and awskms would otherwise declare them.
type Key struct {
	ChainIDs  []string  `yaml:"chain_ids"`
	Backend   Backend   `yaml:"backend"`   // "file" (default) | "pkcs11" | "awskms"
	Algorithm Algorithm `yaml:"algorithm"` // key algorithm; defaults to "ed25519"
	KeyID     string    `yaml:"key_id"`    // pkcs11: hex CKA_ID; awskms: KMS id, ARN, or alias/<name>

	FileConfig   `yaml:",inline"`
	PKCS11Config `yaml:",inline"`
	AWSKMSConfig `yaml:",inline"`
}

// FileConfig configures the file backend: a key read from disk into memory.
type FileConfig struct {
	KeyFile string `yaml:"key_file"`
}

// PKCS11Config configures a key on a PKCS#11 token/HSM. Exactly one of
// TokenLabel/Slot selects the token, at least one of KeyLabel/Key.KeyID selects
// the key, and exactly one of PIN/PINEnv/PINFile supplies the user PIN.
type PKCS11Config struct {
	Module     string `yaml:"module"`      // path to the PKCS#11 .so
	TokenLabel string `yaml:"token_label"` // CKA_LABEL of the token (XOR slot)
	Slot       *uint  `yaml:"slot"`        // slot number (XOR token_label)
	KeyLabel   string `yaml:"key_label"`   // CKA_LABEL of the key
	PIN        string `yaml:"pin"`         // inline PIN
	PINEnv     string `yaml:"pin_env"`     // name of env var holding the PIN
	PINFile    string `yaml:"pin_file"`    // path to a file holding the PIN
}

// AWSKMSConfig configures a key stored in AWS KMS. The private key never leaves
// KMS; signing is performed by the KMS Sign API. Credentials are resolved by the
// AWS default credential chain — no secret material is placed here.
type AWSKMSConfig struct {
	Region   string `yaml:"region"`   // optional; AWS default chain otherwise
	Profile  string `yaml:"profile"`  // optional shared-config profile
	Endpoint string `yaml:"endpoint"` // optional endpoint override (LocalStack/testing)
}

// Load parses a YAML config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("config: decode %q: %w", path, err)
	}
	return &c, nil
}

// ReconnectEnabled reports the effective reconnect setting (default true).
func (v Validator) ReconnectEnabled() bool { return v.Reconnect == nil || *v.Reconnect }

// Transport identifies the privval connection transport selected by a validator
// address scheme.
type Transport int

const (
	// TransportTCP is tcp:// with cometbft SecretConnection (the default).
	TransportTCP Transport = iota
	// TransportNoise is noise://<peer-id>@host:port with libp2p Noise.
	TransportNoise
)

// ParsedTransport classifies v.Addr. For TCP it returns the full address
// unchanged (DialTCPFn consumes the tcp:// form) and an empty peer ID. For Noise
// it returns the host:port and the pinned validator peer ID.
func (v Validator) ParsedTransport() (tr Transport, addr string, validatorPeer peer.ID, err error) {
	if strings.HasPrefix(v.Addr, "noise://") {
		pid, hostport, perr := privval.ParseNoiseAddr(v.Addr)
		if perr != nil {
			return TransportNoise, "", "", perr
		}
		return TransportNoise, hostport, pid, nil
	}
	return TransportTCP, v.Addr, "", nil
}

// GRPCConfig configures the SignerService gRPC server (optional). When present,
// kms serves the SignerService alongside any privval dial-out connections.
type GRPCConfig struct {
	Listen  string    `yaml:"listen"`   // host:port to listen on
	TLSCert string    `yaml:"tls_cert"` // server TLS certificate file; empty (with tls_key) serves plaintext
	TLSKey  string    `yaml:"tls_key"`  // server TLS private key file; empty (with tls_cert) serves plaintext
	Keys    []GRPCKey `yaml:"keys"`
}

// GRPCKey binds a signing key to an id (the SignerService key handle clients
// address). Backend selects the custodian and Algorithm the key type. The
// supported combinations are file/secp256k1, awskms/ed25519, and awskms/secp256k1.
// PKCS#11 is not yet supported over gRPC. The server performs no caller
// authorization, so every configured key is usable by any connecting client.
type GRPCKey struct {
	ID        string    `yaml:"id"`
	Backend   Backend   `yaml:"backend"`   // "file" | "awskms"
	Algorithm Algorithm `yaml:"algorithm"` // file: "secp256k1"; awskms: "ed25519" | "secp256k1"
	KeyID     string    `yaml:"key_id"`    // awskms: KMS id, ARN, or alias/<name>

	FileConfig   `yaml:",inline"`
	AWSKMSConfig `yaml:",inline"`
}
