// Package metrics defines the kms Prometheus registry, collectors, and the
// optional HTTP endpoint that serves them.
//
// Collection is always on; serving is opt-in via the `metrics` config block.
// Naming follows the Prometheus conventions: counters end in _total, durations
// are _seconds histograms in base units, timestamps are _timestamp_seconds
// gauges, and one-value metadata series end in _info.
package metrics

import (
	"context"
	"net"
	"net/http"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/cosmos/kms/internal/version"
	"github.com/cosmos/kms/signing"
)

// Registry holds every kms collector plus the standard Go runtime and process
// collectors.
var Registry = prometheus.NewRegistry()

func newCounterVec(name, help string, labels ...string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, labels)
	Registry.MustRegister(c)
	return c
}

func newGaugeVec(name, help string, labels ...string) *prometheus.GaugeVec {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: name, Help: help}, labels)
	Registry.MustRegister(g)
	return g
}

func newHistogramVec(name, help string, buckets []float64, labels ...string) *prometheus.HistogramVec {
	h := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: name, Help: help, Buckets: buckets}, labels)
	Registry.MustRegister(h)
	return h
}

// signBuckets spans sub-millisecond in-memory signing through multi-second
// HSM or cloud-API latency.
var signBuckets = []float64{.0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5}

var (
	// BuildInfo is the standard build-information series with a constant value of 1.
	BuildInfo = newGaugeVec("kms_build_info",
		"Build information for the running kms binary; always 1.",
		"version", "go_version")

	// KeyInfo describes each configured consensus key with a constant value of 1.
	// The address label is the public consensus address derived from the key.
	KeyInfo = newGaugeVec("kms_key_info",
		"Configured signing key per chain; always 1. Labels carry the custodian backend, algorithm, and public consensus address.",
		"chain_id", "backend", "algorithm", "address")

	// ValidatorConnected reports whether the outbound privval connection is up.
	ValidatorConnected = newGaugeVec("kms_validator_connected",
		"Whether the privval connection to this validator endpoint is currently established (1) or not (0).",
		"chain_id", "addr")

	// ValidatorConnectedSince is the Unix time the current connection was established.
	ValidatorConnectedSince = newGaugeVec("kms_validator_connected_since_timestamp_seconds",
		"Unix time at which the current privval connection was established.",
		"chain_id", "addr")

	// ValidatorDials counts dial attempts by result.
	ValidatorDials = newCounterVec("kms_validator_dials_total",
		"Privval dial attempts by result. A burst of ok results usually means the validator is restarting.",
		"chain_id", "addr", "result")

	// Requests counts every privval request served, by type and result.
	// result is ok, refused (the double-sign guard declined to sign), or error.
	Requests = newCounterVec("kms_requests_total",
		"Privval requests served, by request type and result. result=refused means the double-sign protection declined the request.",
		"chain_id", "type", "result")

	// SignDuration measures whole-request signing latency as seen by the validator.
	SignDuration = newHistogramVec("kms_sign_duration_seconds",
		"Time to serve a signing request, including double-sign checks, backend signing, and state persistence.",
		signBuckets, "chain_id", "type")

	// LastSignedHeight/Round/Timestamp record the most recent successful signature.
	LastSignedHeight = newGaugeVec("kms_last_signed_height",
		"Height of the most recent successfully signed message of this type.",
		"chain_id", "type")
	LastSignedRound = newGaugeVec("kms_last_signed_round",
		"Round of the most recent successfully signed message of this type.",
		"chain_id", "type")
	LastSignedTimestamp = newGaugeVec("kms_last_signed_timestamp_seconds",
		"Unix time of the most recent successful signature of this type. Alert on time() minus this value.",
		"chain_id", "type")

	// SignState mirrors the persisted double-sign high-water mark.
	SignStateHeight = newGaugeVec("kms_sign_state_height",
		"Height of the persisted double-sign protection state; the signer refuses to sign at or below it.",
		"chain_id")
	SignStateRound = newGaugeVec("kms_sign_state_round",
		"Round of the persisted double-sign protection state.",
		"chain_id")
	SignStateStep = newGaugeVec("kms_sign_state_step",
		"Step of the persisted double-sign protection state (1 proposal, 2 prevote, 3 precommit).",
		"chain_id")

	// BackendSignDuration and BackendErrors observe the raw key-custodian call.
	BackendSignDuration = newHistogramVec("kms_backend_sign_duration_seconds",
		"Raw Sign call latency of the key backend, excluding privval handling.",
		signBuckets, "backend", "algorithm")
	BackendErrors = newCounterVec("kms_backend_errors_total",
		"Errors returned by the key backend's Sign call.",
		"backend", "algorithm")
)

func init() {
	Registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	BuildInfo.WithLabelValues(version.String(), runtime.Version()).Set(1)
}

// Server serves the registry over HTTP at /metrics.
type Server struct {
	srv *http.Server
	ln  net.Listener
}

// NewServer binds the listener. The endpoint carries no authentication;
// restrict access by network policy, exactly as with the gRPC signer service.
func NewServer(listen string) (*Server, error) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(Registry, promhttp.HandlerOpts{}))
	return &Server{srv: &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}, ln: ln}, nil
}

// Serve blocks serving the endpoint until Close.
func (s *Server) Serve() error { return s.srv.Serve(s.ln) }

// Close shuts the server down.
func (s *Server) Close() { _ = s.srv.Close() }

// wrappedSigner instruments a signing.Signer's Sign call.
type wrappedSigner struct {
	signing.Signer
	backend   string
	algorithm string
}

// WrapSigner returns s with Sign latency and error instrumentation attached.
func WrapSigner(backend, algorithm string, s signing.Signer) signing.Signer {
	return &wrappedSigner{Signer: s, backend: backend, algorithm: algorithm}
}

func (w *wrappedSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	start := time.Now()
	sig, err := w.Signer.Sign(ctx, payload)
	BackendSignDuration.WithLabelValues(w.backend, w.algorithm).Observe(time.Since(start).Seconds())
	if err != nil {
		BackendErrors.WithLabelValues(w.backend, w.algorithm).Inc()
	}
	return sig, err
}
