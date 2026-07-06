// Package app wires a validated config into a runnable manager.
package app

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"

	"github.com/cometbft/cometbft/libs/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/cosmos/kms/config"
	gensignerservice "github.com/cosmos/kms/gen/signerservice"
	"github.com/cosmos/kms/internal/identity"
	"github.com/cosmos/kms/internal/manager"
	"github.com/cosmos/kms/internal/signer"
	"github.com/cosmos/kms/internal/signerservice"
	"github.com/cosmos/kms/internal/transport"
	"github.com/cosmos/kms/signing"
	"github.com/cosmos/kms/signing/awskms"
	"github.com/cosmos/kms/signing/file"
	"github.com/cosmos/kms/signing/pkcs11"
)

// Build constructs a Manager from a validated config. The returned cleanup
// function releases backend resources (e.g. PKCS#11 sessions) and must be called
// on shutdown. cleanup is non-nil even when an error is returned, so callers can
// always defer it.
func Build(c *config.Config, logger log.Logger) (mgr *manager.Manager, cleanup func(), err error) {
	// Backends that hold OS/HSM resources are closed by cleanup.
	var closers []io.Closer
	cleanup = func() {
		for _, cl := range closers {
			_ = cl.Close()
		}
	}
	// On error, release anything already opened before returning.
	defer func() {
		if err != nil {
			cleanup()
		}
	}()

	// chainID -> backend (one backend per chain).
	backends := map[string]signing.Backend{}
	for _, k := range c.Keys {
		s, berr := newPrivvalBackend(k)
		if berr != nil {
			return nil, cleanup, berr
		}
		closers = append(closers, s)
		for _, id := range k.ChainIDs {
			if _, dup := backends[id]; dup {
				return nil, cleanup, fmt.Errorf("app: multiple backends bound to chain %q", id)
			}
			backends[id] = s
		}
	}

	// chainID -> state file.
	stateFiles := map[string]string{}
	for _, ch := range c.Chains {
		stateFiles[ch.ID] = ch.StateFile
	}

	// chainID -> *ChainSigner.
	signers := map[string]*signer.ChainSigner{}
	for id, be := range backends {
		cs, cerr := signer.NewChainSigner(id, be, stateFiles[id])
		if cerr != nil {
			return nil, cleanup, cerr
		}
		signers[id] = cs
	}

	// One ValidatorConn per validator entry; validators of a chain share its signer.
	var conns []manager.ValidatorConn
	for _, v := range c.Validators {
		cs, ok := signers[v.ChainID]
		if !ok {
			return nil, cleanup, fmt.Errorf("app: chain %q has no backend", v.ChainID)
		}
		idKey, lerr := identity.LoadOrGen(v.IdentityKey)
		if lerr != nil {
			return nil, cleanup, lerr
		}
		tr, addr, validatorPeer, perr := v.ParsedTransport()
		if perr != nil {
			return nil, cleanup, perr
		}
		vc := manager.ValidatorConn{
			ChainID:     v.ChainID,
			Addr:        v.Addr,
			IdentityKey: idKey,
			Signer:      cs,
			Reconnect:   v.ReconnectEnabled(),
		}
		if tr == config.TransportNoise {
			d, derr := transport.NoiseDialer(addr, idKey, validatorPeer, manager.DefaultDialTimeout)
			if derr != nil {
				return nil, cleanup, derr
			}
			vc.Dialer = d
		}
		conns = append(conns, vc)
	}

	return manager.New(logger, conns), cleanup, nil
}

// newPrivvalBackend constructs the signing backend for one config key. The
// returned io.Closer is non-nil only for backends that hold OS resources
// (pkcs11) and must be closed on shutdown.
func newPrivvalBackend(k config.Key) (signing.Backend, error) {
	switch k.Backend {
	case config.BackendFile:
		s, err := file.LoadEd25519(k.KeyFile)
		if err != nil {
			return nil, err
		}
		return s, nil
	case config.BackendPKCS11:
		var keyID []byte
		if k.KeyID != "" {
			var derr error
			if keyID, derr = hex.DecodeString(k.KeyID); derr != nil {
				return nil, fmt.Errorf("app: pkcs11 key_id %q: %w", k.KeyID, derr)
			}
		}
		s, err := pkcs11.Open(pkcs11.Config{
			Module:     k.Module,
			TokenLabel: k.TokenLabel,
			Slot:       k.Slot,
			KeyLabel:   k.KeyLabel,
			KeyID:      keyID,
			PIN:        k.PIN,
			PINEnv:     k.PINEnv,
			PINFile:    k.PINFile,
			Algorithm:  k.Algorithm,
		})
		if err != nil {
			return nil, err
		}
		return s, nil
	case config.BackendAWSKMS:
		s, err := awskms.Open(context.Background(), awskms.Config{
			KeyID:     k.KeyID,
			Region:    k.Region,
			Profile:   k.Profile,
			Endpoint:  k.Endpoint,
			Algorithm: k.Algorithm,
		})
		if err != nil {
			return nil, err
		}
		return s, nil
	default:
		return nil, fmt.Errorf("app: key for chains %v has unknown backend %q", k.ChainIDs, k.Backend)
	}
}

// Server is a signing service GRPC server.
type Server struct {
	gs       *grpc.Server
	listener net.Listener
	logger   log.Logger
	cleanup  func()
}

// Serve blocks and allows the server to listen for and accept new GRPC
// connections.
func (s *Server) Serve() error {
	s.logger.Info("serving signerservice gRPC", "addr", s.listener.Addr().String())
	return s.gs.Serve(s.listener)
}

// Close releases a servers resources.
func (s *Server) Close() {
	s.gs.GracefulStop()
	s.cleanup()
}

// NewServer constructs a new signing service server from the given config.
// Returns (nil, nil) when no grpc block is configured. The caller owns
// starting/stopping the server and closing the server.
func NewServer(c *config.Config, home string, logger log.Logger) (srv *Server, err error) {
	if c.GRPC == nil {
		return nil, nil
	}
	g := c.GRPC

	var closers []io.Closer
	cleanup := func() {
		for _, cl := range closers {
			_ = cl.Close()
		}
	}
	// On error, release anything already opened before returning.
	defer func() {
		if err != nil {
			cleanup()
		}
	}()

	// keyID -> signing.Signer. The server performs no caller auth: any client
	// reaching the listener may use any key (see signerservice.Server).
	keys := map[string]signing.Key{}
	for _, k := range g.Keys {
		s, err := newGRPCSigner(home, k)
		if err != nil {
			return nil, err
		}
		closers = append(closers, s)
		keys[k.ID] = signing.Key{ID: k.ID, Signer: s}
	}

	// TLS is optional (validated together): empty cert+key serves plaintext for
	// local/testing, where access is constrained by network controls instead.
	var gs *grpc.Server
	if g.TLSCert == "" && g.TLSKey == "" {
		logger.Info("signerservice gRPC serving WITHOUT TLS (plaintext)", "listen", g.Listen)
		gs = grpc.NewServer()
	} else {
		creds, err := credentials.NewServerTLSFromFile(config.AbsPath(home, g.TLSCert), config.AbsPath(home, g.TLSKey))
		if err != nil {
			return nil, fmt.Errorf("app: grpc tls: %w", err)
		}
		gs = grpc.NewServer(grpc.Creds(creds))
	}
	gensignerservice.RegisterSignerServiceServer(gs, signerservice.NewServer(keys))

	lis, err := net.Listen("tcp", g.Listen)
	if err != nil {
		return nil, fmt.Errorf("app: grpc listen %q: %w", g.Listen, err)
	}
	logger.Info("signerservice gRPC server configured", "listen", g.Listen, "keys", len(keys))
	return &Server{gs: gs, listener: lis, logger: logger, cleanup: cleanup}, nil
}

// newGRPCSigner constructs the signing.Signer for one grpc.key entry from its
// backend/algorithm. The algorithm default depends on the backend: file defaults
// to secp256k1, awskms to ed25519. Supported combinations are file/secp256k1,
// awskms/ed25519, and awskms/secp256k1 (Ethereum-compatible recoverable signing).
func newGRPCSigner(home string, k config.GRPCKey) (signing.Signer, error) {
	be, algo := k.Backend, k.Algorithm
	if be == "" {
		be = config.BackendFile
	}
	if algo == "" {
		switch be {
		case config.BackendAWSKMS:
			algo = config.AlgoED25519
		default:
			algo = config.AlgoSecp256k1
		}
	}
	switch {
	case be == config.BackendFile && algo == config.AlgoSecp256k1:
		return file.LoadSecp256k1(k.KeyFile)
	case be == config.BackendAWSKMS && (algo == config.AlgoED25519 || algo == config.AlgoSecp256k1):
		return awskms.OpenSigner(context.Background(), awskms.Config{
			KeyID:     k.KeyID,
			Region:    k.Region,
			Profile:   k.Profile,
			Endpoint:  k.Endpoint,
			Algorithm: algo,
		})
	default:
		return nil, fmt.Errorf("app: grpc key %q: unsupported backend/algorithm %q/%q", k.ID, be, algo)
	}
}
