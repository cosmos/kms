package pkcs11

import (
	"context"
	"fmt"
	"sync"

	"github.com/cosmos/kms/config"
	"github.com/cosmos/kms/signing"
	"github.com/miekg/pkcs11"
)

// Signer signs on a PKCS#11 token. It owns a single
// long-lived session; the mutex serializes signing (PKCS#11 sessions are not
// safe for concurrent use) and guards Close.
type Signer struct {
	mod    *pkcs11.Ctx
	module string // module path, used to release the shared context on Close
	// session is a handle used to access data for the signer session within the HSM
	session pkcs11.SessionHandle
	// privH is a uint that corresponds to the specific signing privKey within the HSM
	privH pkcs11.ObjectHandle
	pub   []byte
	algo  keyAlgo

	mu     sync.Mutex
	closed bool
}

var _ signing.Signer = (*Signer)(nil)

// Open loads the PKCS#11 module, logs into the selected token, locates the key,
// and caches its public key. Any failure is returned (fatal at startup for the
// chain). On success the returned Signer holds an open, logged-in session that
// must be released with Close.
func Open(cfg Config) (s *Signer, err error) {
	algoName := cfg.Algorithm
	if algoName == "" {
		algoName = config.AlgoED25519
	}
	algo, ok := algos[algoName]
	if !ok {
		return nil, fmt.Errorf("pkcs11: unknown algorithm %q", algoName)
	}

	pin, err := resolvePIN(cfg)
	if err != nil {
		return nil, err
	}

	mod, err := acquireModule(cfg.Module)
	if err != nil {
		return nil, err
	}
	// Release our module reference on any error past this point.
	defer func() {
		if err != nil {
			releaseModule(cfg.Module)
		}
	}()

	slot, err := selectSlot(mod, cfg)
	if err != nil {
		return nil, err
	}

	session, err := mod.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: open session on slot %d: %w", slot, err)
	}
	defer func() {
		if err != nil {
			_ = mod.CloseSession(session)
		}
	}()

	// Login is per-application (shared across sessions on a slot): a concurrent
	// signer on the same token may already hold the login, which is fine.
	if err = mod.Login(session, pkcs11.CKU_USER, pin); err != nil {
		if ce, ok := err.(pkcs11.Error); !ok || ce != pkcs11.CKR_USER_ALREADY_LOGGED_IN {
			return nil, fmt.Errorf("pkcs11: login: %w", err)
		}
		err = nil
	}

	privH, err := findObject(mod, session, pkcs11.CKO_PRIVATE_KEY, cfg)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: find private key: %w", err)
	}
	pubH, err := findObject(mod, session, pkcs11.CKO_PUBLIC_KEY, cfg)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: find public key: %w", err)
	}

	attrs, err := mod.GetAttributeValue(session, pubH, []*pkcs11.Attribute{
		pkcs11.NewAttribute(algo.pubAttr, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("pkcs11: read public key: %w", err)
	}
	if len(attrs) == 0 {
		return nil, fmt.Errorf("pkcs11: public key has no attribute 0x%x", algo.pubAttr)
	}
	pub, err := algo.decodePub(attrs[0].Value)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: decode public key: %w", err)
	}

	return &Signer{mod: mod, module: cfg.Module, session: session, privH: privH, pub: pub, algo: algo}, nil
}

// PubKey returns the public key cached at Open.
func (s *Signer) PubKey() []byte { return s.pub }

// Scheme returns the config.Algorithm.
func (s *Signer) Scheme() config.Algorithm { return s.algo.name }

// Sign signs the canonical consensus sign-bytes on the token.
func (s *Signer) Sign(_ context.Context, signBytes []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("pkcs11: signer is closed")
	}
	if err := s.mod.SignInit(s.session, s.algo.mechanism(), s.privH); err != nil {
		return nil, fmt.Errorf("pkcs11: sign init: %w", err)
	}
	raw, err := s.mod.Sign(s.session, signBytes)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: sign: %w", err)
	}
	return s.algo.fixSig(raw, signBytes, s.pub)
}

// Close logs out, closes the session, and tears down the module. It is
// idempotent.
func (s *Signer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	_ = s.mod.CloseSession(s.session)
	// releaseModule finalizes and unloads the module once the last signer using
	// it has closed (Finalize tears down login state and sessions).
	releaseModule(s.module)
	return nil
}
