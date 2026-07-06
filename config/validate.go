package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// supportedPKCS11Algorithms mirrors the algo registry in signing/pkcs11. It is
// duplicated here so config validation does not have to import the cgo-backed
// pkcs11 package. Keep the two in sync when adding a key type.
var supportedPKCS11Algorithms = map[Algorithm]bool{AlgoED25519: true}

// supportedAWSKMSAlgorithms mirrors the algo registry in signing/awskms. It is
// duplicated here so config validation does not have to import the awskms
// package. Keep the two in sync when adding a key type.
var supportedAWSKMSAlgorithms = map[Algorithm]bool{AlgoED25519: true, AlgoSecp256k1: true}

// Validate resolves defaults and enforces fail-fast invariants. home is the base
// directory used to resolve relative paths and default state files.
func (c *Config) Validate(home string) error {
	// Chains are required for privval signing (validators/keys). A gRPC-only
	// deployment needs none.
	privvalConfigured := len(c.Validators) > 0 || len(c.Keys) > 0
	grpcOnly := c.GRPC != nil && !privvalConfigured
	if len(c.Chains) == 0 && !grpcOnly {
		return fmt.Errorf("config: no chain entries declared")
	}

	chainIDs := make(map[string]int, len(c.Chains)) // id -> index
	for i, ch := range c.Chains {
		if ch.ID == "" {
			return fmt.Errorf("config: chain entry #%d has empty id", i)
		}
		if _, dup := chainIDs[ch.ID]; dup {
			return fmt.Errorf("config: duplicate chain id %q", ch.ID)
		}
		chainIDs[ch.ID] = i
	}

	// Resolve + ensure writable state files.
	for i := range c.Chains {
		sf := c.Chains[i].StateFile
		if sf == "" {
			sf = filepath.Join(home, "state", c.Chains[i].ID+".json")
		} else {
			sf = AbsPath(home, sf)
		}
		if err := os.MkdirAll(filepath.Dir(sf), 0o700); err != nil {
			return fmt.Errorf("config: state dir for chain %q: %w", c.Chains[i].ID, err)
		}
		if err := checkWritable(filepath.Dir(sf)); err != nil {
			return fmt.Errorf("config: state file for chain %q not writable: %w", c.Chains[i].ID, err)
		}
		c.Chains[i].StateFile = sf
	}

	// Every validator references a known chain.
	for i := range c.Validators {
		v := c.Validators[i]
		if _, ok := chainIDs[v.ChainID]; !ok {
			return fmt.Errorf("config: validator references unknown chain %q", v.ChainID)
		}
		if v.Addr == "" {
			return fmt.Errorf("config: validator for chain %q has empty addr", v.ChainID)
		}
		if v.IdentityKey == "" {
			return fmt.Errorf("config: validator for chain %q has empty identity_key", v.ChainID)
		}
		if _, _, _, perr := v.ParsedTransport(); perr != nil {
			return fmt.Errorf("config: validator for chain %q has invalid addr: %w", v.ChainID, perr)
		}
		// Resolve relative identity_key against home so app.Build consumes the
		// resolved path (CWD-relative resolution would silently mint a new key).
		c.Validators[i].IdentityKey = AbsPath(home, v.IdentityKey)
	}

	// Every key references known chains; collect which chains have a backend.
	hasBackend := make(map[string]bool)
	for i := range c.Keys {
		// Default the backend so the rest of the pipeline can switch on it.
		if c.Keys[i].Backend == "" {
			c.Keys[i].Backend = BackendFile
		}
		if len(c.Keys[i].ChainIDs) == 0 {
			return fmt.Errorf("config: key[%d] (%s) has no chain_ids", i, c.Keys[i].Backend)
		}
		for _, id := range c.Keys[i].ChainIDs {
			if _, ok := chainIDs[id]; !ok {
				return fmt.Errorf("config: key[%d] references unknown chain %q", i, id)
			}
			hasBackend[id] = true
		}
		var err error
		switch c.Keys[i].Backend {
		case BackendFile:
			err = c.validateFileKey(i, home)
		case BackendPKCS11:
			err = c.validatePKCS11Key(i, home)
		case BackendAWSKMS:
			err = c.validateAWSKMSKey(i)
		default:
			err = fmt.Errorf("config: key[%d] has unknown backend %q", i, c.Keys[i].Backend)
		}
		if err != nil {
			return err
		}
	}

	// Every chain must have at least one backend.
	for _, ch := range c.Chains {
		if !hasBackend[ch.ID] {
			return fmt.Errorf("config: chain %q has no backend", ch.ID)
		}
	}

	if c.GRPC != nil {
		if err := c.validateGRPC(home); err != nil {
			return err
		}
	}
	return nil
}

// validateFileKey checks one file-backend key and resolves its key_file against
// home.
func (c *Config) validateFileKey(i int, home string) error {
	k := &c.Keys[i]
	if k.KeyFile == "" {
		return fmt.Errorf("config: key[%d] (file) has empty key_file", i)
	}
	k.KeyFile = AbsPath(home, k.KeyFile)
	return nil
}

// validatePKCS11Key checks one pkcs11-backend key and resolves its relative
// paths against home.
func (c *Config) validatePKCS11Key(i int, home string) error {
	k := &c.Keys[i]

	if k.Module == "" {
		return fmt.Errorf("config: key[%d] (pkcs11) has empty module", i)
	}

	// Token selector: exactly one of token_label / slot.
	switch {
	case k.TokenLabel != "" && k.Slot != nil:
		return fmt.Errorf("config: key[%d] (pkcs11) sets both token_label and slot (use exactly one)", i)
	case k.TokenLabel == "" && k.Slot == nil:
		return fmt.Errorf("config: key[%d] (pkcs11) must set token_label or slot", i)
	}

	// Key selector: at least one of key_label / key_id.
	if k.KeyLabel == "" && k.KeyID == "" {
		return fmt.Errorf("config: key[%d] (pkcs11) must set key_label or key_id", i)
	}
	if k.KeyID != "" {
		if _, err := hex.DecodeString(k.KeyID); err != nil {
			return fmt.Errorf("config: key[%d] (pkcs11) key_id %q is not valid hex: %w", i, k.KeyID, err)
		}
	}

	// PIN source: exactly one of pin / pin_env / pin_file.
	n := 0
	for _, set := range []bool{k.PIN != "", k.PINEnv != "", k.PINFile != ""} {
		if set {
			n++
		}
	}
	if n != 1 {
		return fmt.Errorf("config: key[%d] (pkcs11) must set exactly one of pin, pin_env, pin_file (got %d)", i, n)
	}

	// Algorithm: empty defaults to ed25519; otherwise must be registered.
	if k.Algorithm != "" && !supportedPKCS11Algorithms[k.Algorithm] {
		return fmt.Errorf("config: key[%d] (pkcs11) has unknown algorithm %q", i, k.Algorithm)
	}

	// Resolve relative paths against home before checking the module is readable.
	k.Module = AbsPath(home, k.Module)
	k.PINFile = AbsPath(home, k.PINFile)
	if _, err := os.Stat(k.Module); err != nil {
		return fmt.Errorf("config: key[%d] (pkcs11) module %q not readable: %w", i, k.Module, err)
	}
	return nil
}

// validateAWSKMSKey checks one awskms-backend key. There is no path resolution
// or local readability check: credentials and reachability are an AWS concern
// surfaced at Open (startup).
func (c *Config) validateAWSKMSKey(i int) error {
	k := &c.Keys[i]

	if k.KeyID == "" {
		return fmt.Errorf("config: key[%d] (awskms) has empty key_id", i)
	}
	if k.Algorithm != "" && !supportedAWSKMSAlgorithms[k.Algorithm] {
		return fmt.Errorf("config: key[%d] (awskms) has unknown algorithm %q", i, k.Algorithm)
	}
	return nil
}

func checkWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".writecheck-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

func (c *Config) validateGRPC(home string) error {
	g := c.GRPC
	if g.Listen == "" {
		return fmt.Errorf("config: grpc.listen is required")
	}
	// TLS is optional: both empty means an insecure (plaintext) listener for
	// local/testing use. Setting one without the other is a misconfiguration.
	switch {
	case g.TLSCert == "" && g.TLSKey == "":
		// insecure; access must be constrained by network controls.
	case g.TLSCert == "" || g.TLSKey == "":
		return fmt.Errorf("config: grpc.tls_cert and grpc.tls_key must be set together")
	default:
		if _, err := os.Stat(AbsPath(home, g.TLSCert)); err != nil {
			return fmt.Errorf("config: grpc.tls_cert %q: %w", g.TLSCert, err)
		}
		if _, err := os.Stat(AbsPath(home, g.TLSKey)); err != nil {
			return fmt.Errorf("config: grpc.tls_key %q: %w", g.TLSKey, err)
		}
	}
	if len(g.Keys) == 0 {
		return fmt.Errorf("config: grpc requires at least one grpc.key entry")
	}
	seen := map[string]bool{}
	for i := range g.Keys {
		k := &g.Keys[i]
		if k.ID == "" {
			return fmt.Errorf("config: grpc.key[%d].id is required", i)
		}
		if seen[k.ID] {
			return fmt.Errorf("config: duplicate grpc.key id %q", k.ID)
		}
		seen[k.ID] = true

		// gRPC keys carry their own (small) backend validation rather than sharing
		// the consensus per-backend validators: only file and awskms are supported
		// here, and a gRPC key is bound by id, not chain_ids.
		switch k.Backend {
		case BackendFile:
			if k.KeyFile == "" {
				return fmt.Errorf("config: grpc.key[%d] (file) requires key_file", i)
			}
			if _, err := os.Stat(AbsPath(home, k.KeyFile)); err != nil {
				return fmt.Errorf("config: grpc.key[%d].key_file %q: %w", i, k.KeyFile, err)
			}
			k.KeyFile = AbsPath(home, k.KeyFile)
		case BackendAWSKMS:
			if k.KeyID == "" {
				return fmt.Errorf("config: grpc.key[%d] (awskms) requires key_id", i)
			}
			if k.Algorithm != "" && !supportedAWSKMSAlgorithms[k.Algorithm] {
				return fmt.Errorf("config: grpc.key[%d] (awskms) has unknown algorithm %q", i, k.Algorithm)
			}
		default:
			return fmt.Errorf("config: grpc.key[%d] has unsupported backend %q", i, k.Backend)
		}
	}
	return nil
}
