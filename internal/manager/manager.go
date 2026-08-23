package manager

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/libs/protoio"
	"github.com/cometbft/cometbft/privval"
	privvalproto "github.com/cometbft/cometbft/proto/tendermint/privval"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"

	"github.com/cometbft/cometbft/types"
	"github.com/cosmos/kms/internal/metrics"
)

const (
	defaultDialTimeout    = 5 * time.Second
	defaultReadTimeout    = 10 * time.Second // must exceed the validator's ping interval (~3.3s at default)
	defaultWriteTimeout   = 5 * time.Second
	defaultBackoffInitial = 200 * time.Millisecond
	defaultBackoffMax     = 10 * time.Second
)

// maxRemoteSignerMsgSize mirrors privval's framing cap.
var maxRemoteSignerMsgSize = types.MaxVoteExtensionSize + 2*types.MaxSignatureSize + 1024

// DefaultDialTimeout is the per-dial timeout used for validator connections.
const DefaultDialTimeout = defaultDialTimeout

// ValidatorConn describes one outbound signer connection.
type ValidatorConn struct {
	ChainID     string
	Addr        string
	IdentityKey crypto.PrivKey
	Signer      types.PrivValidator
	// Reconnect controls whether the manager re-dials after an established
	// connection drops. The initial connect always uses backoff regardless.
	Reconnect bool
	// Dialer is the base (already transport-specific) SocketDialer. If nil, the
	// manager builds the default tcp:// SecretConnection dialer from Addr.
	Dialer privval.SocketDialer
}

// Manager supervises one validator connection per ValidatorConn, dialing out and
// re-dialing with backoff across outages (including graceful validator restarts).
type Manager struct {
	logger   log.Logger
	conns    []ValidatorConn
	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// New builds a Manager.
func New(logger log.Logger, conns []ValidatorConn) *Manager {
	return &Manager{logger: logger, conns: conns, stop: make(chan struct{})}
}

// Start launches one supervised goroutine per connection. It never returns an
// error (kept in the signature for API stability and future validation).
func (m *Manager) Start() error {
	for _, c := range m.conns {
		m.wg.Add(1)
		go m.run(c)
	}
	return nil
}

// Stop signals all connections to close and waits for their goroutines to exit.
// Safe to call multiple times.
func (m *Manager) Stop() {
	m.stopOnce.Do(func() { close(m.stop) })
	m.wg.Wait()
}

// run maintains one validator connection: dial (blocking, with backoff), serve
// until the connection breaks (EOF or timeout), then redial — until Stop.
func (m *Manager) run(c ValidatorConn) {
	defer m.wg.Done()

	logger := m.logger.With("chain", c.ChainID, "addr", c.Addr)

	// Materialize the per-connection series up front so a validator that is
	// unreachable from startup reports connected == 0 rather than no data.
	metrics.ValidatorConnected.WithLabelValues(c.ChainID, c.Addr).Set(0)
	metrics.ValidatorDials.WithLabelValues(c.ChainID, c.Addr, "ok").Add(0)
	metrics.ValidatorDials.WithLabelValues(c.ChainID, c.Addr, "error").Add(0)

	base := c.Dialer
	if base == nil {
		base = privval.DialTCPFn(c.Addr, defaultDialTimeout, c.IdentityKey)
	}
	base = instrumentDialer(base, c.ChainID, c.Addr)
	dialer := backoffDialer(base, m.stop, logger, defaultBackoffInitial, defaultBackoffMax)

	for {
		select {
		case <-m.stop:
			return
		default:
		}

		conn, err := dialer()
		if err != nil {
			return // errDialerStopped: shutting down
		}
		logger.Info("kms: connected")
		metrics.ValidatorConnected.WithLabelValues(c.ChainID, c.Addr).Set(1)
		metrics.ValidatorConnectedSince.WithLabelValues(c.ChainID, c.Addr).Set(float64(time.Now().Unix()))

		m.handleConnection(conn, c, logger)
		metrics.ValidatorConnected.WithLabelValues(c.ChainID, c.Addr).Set(0)

		if !c.Reconnect {
			logger.Info("kms: reconnect disabled; connection closed")
			return
		}
		logger.Info("kms: connection closed; will redial")
	}
}

// handleConnection serves a single established connection until it breaks or the
// manager stops. It owns the connection lifecycle: a monitor goroutine closes the
// conn on shutdown (unblocking a pending read), and deferred cleanup guarantees
// both the conn and the monitor goroutine are released when this returns. Scoping
// this to its own function (rather than deferring inside run's loop) keeps the
// defers per-connection and ensures they still run if serveConn panics mid-unwind.
func (m *Manager) handleConnection(conn net.Conn, c ValidatorConn, logger log.Logger) {
	closed := make(chan struct{})
	defer close(closed)
	defer func() { _ = conn.Close() }()

	go func() {
		select {
		case <-m.stop:
			_ = conn.Close()
		case <-closed:
		}
	}()

	m.serveConn(conn, c.ChainID, c.Signer, logger)
}

// serveConn reads validation requests off conn and answers them with the reused
// privval.DefaultValidationRequestHandler, until any read/write error (EOF on a
// graceful restart, or a read-deadline timeout on a silently dead peer) or until
// stop. Returning signals the caller to redial.
func (m *Manager) serveConn(conn net.Conn, chainID string, signer types.PrivValidator, logger log.Logger) {
	reader := protoio.NewDelimitedReader(conn, maxRemoteSignerMsgSize)
	writer := protoio.NewDelimitedWriter(conn)

	for {
		select {
		case <-m.stop:
			return
		default:
		}

		if err := conn.SetReadDeadline(time.Now().Add(defaultReadTimeout)); err != nil {
			logger.Error("kms: set read deadline", "err", err)
			return
		}
		var req privvalproto.Message
		if _, err := reader.ReadMsg(&req); err != nil {
			logger.Info("kms: read failed; dropping connection", "err", err)
			return
		}

		start := time.Now()
		resp, err := privval.DefaultValidationRequestHandler(signer, req, chainID)
		kind, kv, ping := describeRequest(req)
		mkind := requestKind(req)
		metrics.Requests.WithLabelValues(chainID, mkind, classifyResult(err)).Inc()
		switch mkind {
		case kindProposal, kindPrevote, kindPrecommit:
			metrics.SignDuration.WithLabelValues(chainID, mkind).Observe(time.Since(start).Seconds())
			if err == nil {
				h, r := requestHeightRound(req)
				metrics.LastSignedHeight.WithLabelValues(chainID, mkind).Set(float64(h))
				metrics.LastSignedRound.WithLabelValues(chainID, mkind).Set(float64(r))
				metrics.LastSignedTimestamp.WithLabelValues(chainID, mkind).Set(float64(time.Now().Unix()))
				metrics.SignStateHeight.WithLabelValues(chainID).Set(float64(h))
				metrics.SignStateRound.WithLabelValues(chainID).Set(float64(r))
				metrics.SignStateStep.WithLabelValues(chainID).Set(signStep(mkind))
			}
		}
		switch {
		case err != nil:
			// resp already carries an embedded RemoteSignerError; log loudly and still send it.
			logger.Error("kms: "+kind+" request rejected", append(kv, "err", err)...)
		case ping:
			logger.Debug("kms: ping")
		case kind == "pubkey":
			logger.Info("kms: served pubkey request")
		default:
			logger.Info("kms: signed "+kind, kv...)
		}

		if err := conn.SetWriteDeadline(time.Now().Add(defaultWriteTimeout)); err != nil {
			logger.Error("kms: set write deadline", "err", err)
			return
		}
		if _, err := writer.WriteMsg(&resp); err != nil {
			logger.Error("kms: write failed; dropping connection", "err", err)
			return
		}
	}
}

// describeRequest returns a short kind, structured log keyvals, and whether the
// request is a ping (which is logged at debug to avoid flooding the log every
// few seconds). It is used to emit one log line per served request.
func describeRequest(req privvalproto.Message) (kind string, kv []any, ping bool) {
	switch r := req.Sum.(type) {
	case *privvalproto.Message_SignVoteRequest:
		if v := r.SignVoteRequest.GetVote(); v != nil {
			return "vote", []any{"height", v.Height, "round", v.Round, "type", v.Type}, false
		}
		return "vote", nil, false
	case *privvalproto.Message_SignProposalRequest:
		if p := r.SignProposalRequest.GetProposal(); p != nil {
			return "proposal", []any{"height", p.Height, "round", p.Round}, false
		}
		return "proposal", nil, false
	case *privvalproto.Message_PubKeyRequest:
		return "pubkey", nil, false
	case *privvalproto.Message_PingRequest:
		return "ping", nil, true
	default:
		return "unknown", nil, false
	}
}

// Metric label values for privval request kinds.
const (
	kindProposal  = "proposal"
	kindPrevote   = "prevote"
	kindPrecommit = "precommit"
	kindPubkey    = "pubkey"
	kindPing      = "ping"
)

// instrumentDialer wraps a SocketDialer so every dial attempt is counted.
func instrumentDialer(base privval.SocketDialer, chainID, addr string) privval.SocketDialer {
	return func() (net.Conn, error) {
		conn, err := base()
		if err != nil {
			metrics.ValidatorDials.WithLabelValues(chainID, addr, "error").Inc()
			return nil, err
		}
		metrics.ValidatorDials.WithLabelValues(chainID, addr, "ok").Inc()
		return conn, nil
	}
}

// requestKind maps a privval request onto the metrics type label.
func requestKind(req privvalproto.Message) string {
	switch r := req.Sum.(type) {
	case *privvalproto.Message_SignVoteRequest:
		if v := r.SignVoteRequest.GetVote(); v != nil && v.Type == cmtproto.PrecommitType {
			return kindPrecommit
		}
		return kindPrevote
	case *privvalproto.Message_SignProposalRequest:
		return kindProposal
	case *privvalproto.Message_PubKeyRequest:
		return kindPubkey
	case *privvalproto.Message_PingRequest:
		return kindPing
	default:
		return "unknown"
	}
}

// classifyResult maps a request-handler error onto the metrics result label.
// FilePV double-sign refusals surface as height/round/step regression or
// conflicting-data errors; everything else is an error.
func classifyResult(err error) string {
	if err == nil {
		return "ok"
	}
	msg := err.Error()
	if strings.Contains(msg, "regression") || strings.Contains(msg, "conflicting data") {
		return "refused"
	}
	return "error"
}

// requestHeightRound extracts the height and round from a signing request.
func requestHeightRound(req privvalproto.Message) (int64, int32) {
	switch r := req.Sum.(type) {
	case *privvalproto.Message_SignVoteRequest:
		if v := r.SignVoteRequest.GetVote(); v != nil {
			return v.Height, v.Round
		}
	case *privvalproto.Message_SignProposalRequest:
		if p := r.SignProposalRequest.GetProposal(); p != nil {
			return p.Height, p.Round
		}
	}
	return 0, 0
}

// signStep maps a signed message type onto the FilePV step it advances the
// double-sign floor to (1 proposal, 2 prevote, 3 precommit).
func signStep(kind string) float64 {
	switch kind {
	case kindProposal:
		return 1
	case kindPrevote:
		return 2
	case kindPrecommit:
		return 3
	}
	return 0
}
