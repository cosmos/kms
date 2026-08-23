# Metrics

kms can serve Prometheus metrics over HTTP. Collection is always on; the
endpoint is opt-in:

```yaml
metrics:
  listen: 0.0.0.0:8545   # GET /metrics; omit the block to disable
```

The listener carries no authentication, the same trade as the gRPC signer
service: restrict access with network controls.

Naming follows the Prometheus conventions: counters end in `_total`,
durations are `_seconds` histograms in base units, timestamps are
`_timestamp_seconds` gauges (alert on `time()` minus the value), and
constant metadata series end in `_info` with a value of 1. All series are
prefixed `kms_`, and every signer series carries `chain_id` because one
process can sign for several chains.

## Connection

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `kms_validator_connected` | gauge | chain_id, addr | 1 while the dial-out privval connection is established |
| `kms_validator_connected_since_timestamp_seconds` | gauge | chain_id, addr | Unix time the current connection was established |
| `kms_validator_dials_total` | counter | chain_id, addr, result=`ok`\|`error` | Dial attempts; a burst of `ok` means the validator is restarting |

## Signing

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `kms_requests_total` | counter | chain_id, type=`proposal`\|`prevote`\|`precommit`\|`pubkey`\|`ping`, result=`ok`\|`refused`\|`error` | Every privval request served. `refused` is the double-sign guard declining a height/round/step regression or conflicting data |
| `kms_sign_duration_seconds` | histogram | chain_id, type | Whole-request latency: double-sign checks, backend signing, state persistence |
| `kms_last_signed_height` / `_round` | gauge | chain_id, type | Most recent successful signature per message type |
| `kms_last_signed_timestamp_seconds` | gauge | chain_id, type | Unix time of that signature |

## Double-sign protection state

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `kms_sign_state_height` / `_round` / `_step` | gauge | chain_id | The persisted high-water mark the signer refuses to cross (step: 1 proposal, 2 prevote, 3 precommit) |

## Key backend

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `kms_backend_sign_duration_seconds` | histogram | backend, algorithm | Raw `Sign` latency of the custodian (file, pkcs11, awskms). The pkcs11 and awskms backends put an HSM or a network API in the hot path, so this is where their health shows |
| `kms_backend_errors_total` | counter | backend, algorithm | Errors returned by the custodian's `Sign` |

## Metadata

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `kms_build_info` | gauge (1) | version, go_version | Running build |
| `kms_key_info` | gauge (1) | chain_id, backend, algorithm, address | Configured key per chain; `address` is the public consensus address, so dashboards can assert the signer holds the expected key |

The standard `go_*` and `process_*` collectors (heap, GC, goroutines, file
descriptors, RSS) are served from the same registry.

## Dashboard

A ready-to-import Grafana dashboard covering these metrics ships at
[`docs/grafana-dashboard.json`](grafana-dashboard.json). Importing it prompts
for a Prometheus datasource; thresholds on the board match the starter alerts
below.

## Starter alerts

```yaml
- alert: SignerDisconnected
  expr: kms_validator_connected == 0
  for: 1m
- alert: SignerNotSigning
  expr: time() - max by (chain_id) (kms_last_signed_timestamp_seconds) > 60
  for: 2m
- alert: SignerRefusedRequest
  expr: increase(kms_requests_total{result="refused"}[5m]) > 0
- alert: BackendErrors
  expr: increase(kms_backend_errors_total[5m]) > 0
- alert: SignLatencyHigh
  expr: histogram_quantile(0.99, sum by (le) (rate(kms_sign_duration_seconds_bucket[5m]))) > 0.1
  for: 15m
```

`SignerDisconnected` only works while the process is alive to report 0; pair
it with scrape-absence alerting (`up == 0` / `absent(up{job=...})`) for the
process-death case.

