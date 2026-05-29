# MS022 — SSE subscriber quota operator guide

Selfdef enforces per-token + global concurrency caps on the SSE event
stream (`GET /v1/events/stream`). The caps protect the daemon from
runaway client behavior — leaked SSE connections, misbehaving test
loops, or a single token monopolizing the subscriber pool. This guide
documents the **producer-side** surface (the IPS half of the chain);
the consumer-side observability (Prometheus alerts, Grafana panels,
sovereign-os master-dashboard banner) is documented separately in
[`sovereign-os/docs/operator/m060-deployment-guide.md`](https://github.com/cyberpunk042/sovereign-os/blob/main/docs/operator/m060-deployment-guide.md#ms022sseglobalquotaapproaching-warning)
under the `MS022Sse*` runbook sections.

Per the operator's standing rule (2026-05-19):

> *"if I talk about an IPS feature it's obviously not in Sovereign-OS"*

The cap enforcement + the metric emission are selfdef IPS surfaces;
sovereign-os only renders them READ-ONLY (R10212).

---

## TL;DR — what an operator does

```bash
# 1. (Optional) Raise the default caps in /etc/selfdef/selfdef.toml.
sudo tee -a /etc/selfdef/selfdef.toml > /dev/null <<'EOF'

[api]
max_sse_subscribers           = 128   # default 64
max_sse_subscribers_per_token = 16    # default 8
EOF

# 2. Reload the daemon to pick up the new caps.
sudo systemctl restart selfdefd

# 3. Verify the 6 SSE quota gauges are surfacing at /metrics.
curl -s --unix-socket /run/selfdef.sock http://localhost/metrics \
  | grep selfdef_sse_subscribers_
```

---

## The 6 published gauges

Exposed at `GET /metrics` in the Prometheus exposition format. The
producer crate is
[`crates/selfdef-api/src/sse_quota_metrics.rs`](../../crates/selfdef-api/src/sse_quota_metrics.rs)
(shipped selfdef commit `77b4499`).

| Metric | Type | Semantics |
|---|---|---|
| `selfdef_sse_subscribers_global_active` | gauge | Live count across all tokens. Bumped by `SubscriberGuard::try_acquire` on each `/v1/events/stream` connect; decremented when the `SubscriberGuard` drops. |
| `selfdef_sse_subscribers_global_cap` | gauge | Effective global cap (operator override `[api].max_sse_subscribers` or compiled default 64). |
| `selfdef_sse_subscribers_global_saturation` | gauge | `active / cap` ratio in `[0.0, 1.0]`. The single gauge alert rules typically threshold on (e.g. `> 0.85 for 5m`). |
| `selfdef_sse_subscribers_per_token_cap` | gauge | Effective per-token cap (operator override `[api].max_sse_subscribers_per_token` or compiled default 8). |
| `selfdef_sse_subscribers_per_token{token_fp="<8-hex>"}` | gauge | Live count per token fingerprint. The label is the privacy-preserving 8-hex-char prefix of `SHA-256(bearer_token)` — matches the Debug impl on `TokenFingerprint`. |
| `selfdef_sse_subscribers_per_token_saturated` | gauge | Count of tokens currently at-or-above the per-token cap. The fast alert-trigger signal that someone is being throttled right now. |

### Privacy posture on the per-token label

The `token_fp` label is **deliberately not the full SHA-256 hash**. The
8-hex-char prefix gives operators a stable identifier they can
cross-reference with the daemon's tracing output (which uses the same
prefix shape via `TokenFingerprint::Debug`), while leaving 28 bytes of
entropy unrevealed. An attacker who later steals the bearer token can
brute-force the matching against past log lines only by SHA-256-ing
~2^32 candidate tokens — far below the security level the bearer
token's full 256 bits provides, but enough that the metric isn't a
new oracle.

### Determinism

The per-token rows are emitted in **sorted fingerprint order** so
successive Prometheus scrapes diff cleanly. The producer samples the
counter map under the lock then drops the lock before formatting —
the lock window is bounded by the size of the active token set
(small in practice — operator + 0..N admin tools).

---

## Configuration

The caps live in `/etc/selfdef/selfdef.toml` under `[api]`:

```toml
[api]
# Global cap on concurrent SSE subscribers. None / 0 / unset →
# compiled default 64.
max_sse_subscribers = 128

# Per-token cap. None / 0 / unset → compiled default 8.
max_sse_subscribers_per_token = 16
```

The config schema is
[`crates/selfdef-config/src/lib.rs::ApiConfig`](../../crates/selfdef-config/src/lib.rs)
(`max_sse_subscribers` + `max_sse_subscribers_per_token` fields). The
daemon reads them at startup and threads them into `ApiState` via
`with_sse_caps`; the running daemon does not re-read the file on
SIGHUP — config changes require a `systemctl restart selfdefd`.

### Defaults rationale

| Knob | Default | Rationale |
|---|---|---|
| `max_sse_subscribers` | 64 | The bus broadcast channel sizes itself around tens of subscribers; 64 covers a single operator + browser refreshes + a handful of admin tools simultaneously. Above 64 the operator should profile bus-publish latency before scaling further. |
| `max_sse_subscribers_per_token` | 8 | A single operator's typical fan-out (master-dashboard + 1-2 drill-down dashboards + maybe a CLI tail) is < 5; 8 leaves headroom for the operator's own browser refreshes without giving any one token enough headroom to monopolize the global pool. |

### When to raise them

| Symptom | Knob to raise |
|---|---|
| Multiple operators sharing one token (anti-pattern; rotate to per-operator tokens) | `max_sse_subscribers_per_token` |
| Single operator with many browser tabs + admin tools open | `max_sse_subscribers_per_token` |
| Fleet of read-only dashboards (each with its own token) polling the same selfdefd | `max_sse_subscribers` |
| `MS022SseGlobalQuotaApproaching` Prometheus alert firing during normal operation (not during a leak) | `max_sse_subscribers` |

### When raising is the wrong answer

| Symptom | Real fix |
|---|---|
| Browser tabs orphaning SSE connections (slot leak) | Browser-side fix — close tabs OR set a TTL on the SSE proxy |
| Runaway test loop subscribing in a tight loop | Kill the loop; the count drops within seconds |
| `selfdef_sse_subscribers_per_token_saturated > 0` for ONE specific token | Identify that token's owner via the daemon journal + rotate them — raising the cap masks the root cause |

---

## Cap-enforcement semantics

The cap is enforced by
[`SubscriberGuard::try_acquire`](../../crates/selfdef-api/src/handlers.rs)
on each `/v1/events/stream` connect:

1. **Per-token check first**: looks up the token's atomic counter; if
   it's at-or-above the per-token cap, returns
   `AcquireError::PerTokenCap` → HTTP 429 with body `"per-token sse
   cap reached"`. Per SDD-007 D-6 the per-token signal surfaces
   FIRST so the operator gets the more-specific reason in their logs.

2. **Global cap second** (CAS loop): if the per-token check passes,
   the global counter is incremented via a CAS loop. If the global
   would exceed the cap, the per-token counter is decremented (so
   the next request under the same token still gets its full slice)
   and `AcquireError::GlobalCap` returns → HTTP 429 with body
   `"global sse cap reached"`.

3. **Both pass** → returns a `SubscriberGuard` that the SSE handler
   holds until the client disconnects; `Drop` decrements both
   counters atomically.

When the per-token map's entry hits zero subscribers, the entry is
NOT removed from the map (avoids a lock-free CAS race against entry
removal during Drop). Empty entries are GC'd on the next operator-
issued `[api] sse-caps reload` (a future hook; today the map grows
unbounded by distinct token-fp set size — bounded in practice by
the active token set, which is small).

The compiled defaults — `MAX_SSE_SUBSCRIBERS = 64` and
`MAX_SSE_SUBSCRIBERS_PER_TOKEN = 8` — live in
[`crates/selfdef-api/src/handlers.rs`](../../crates/selfdef-api/src/handlers.rs).

---

## Verification recipes

```bash
# 1. All 6 gauges present at /metrics.
curl -s --unix-socket /run/selfdef.sock http://localhost/metrics \
  | grep -E "^selfdef_sse_subscribers_"

# 2. Live saturation %.
curl -s --unix-socket /run/selfdef.sock http://localhost/metrics \
  | awk '/^selfdef_sse_subscribers_global_saturation /
         {printf "saturation: %.1f%%\n", $2*100}'

# 3. Operator-readable per-token table sorted by count desc.
curl -s --unix-socket /run/selfdef.sock http://localhost/metrics \
  | awk '/^selfdef_sse_subscribers_per_token\{/ {print}' \
  | sort -t' ' -k2 -nr | head -10

# 4. End-to-end via the sovereign-os proxy (when running on the
#    same host).
curl -s http://localhost:7711/api/ms022/sse-quota | jq .state
```

---

## Failure-mode → log-line crib sheet

| Symptom | Daemon log line | Fix |
|---|---|---|
| `MS022SseGlobalQuotaApproaching` firing | (none — pre-saturation) | Raise `[api].max_sse_subscribers` or identify the heaviest token via the per-token map + rotate. |
| `MS022SseGlobalQuotaSaturated` firing | `WARN sse cap reached: global` (per connection refused) | Restart selfdefd to clear leaked subscribers; identify the leak source via the per-token saturated count. |
| `MS022SsePerTokenQuotaSaturated` firing | `WARN sse cap reached: per-token fp=<8-hex>` | Identify the token-owner via the fingerprint cross-reference. Most common: browser tab orphan. |
| 6 gauges missing from `/metrics` | (none) | `selfdef-api` was built without the `sse_quota_metrics` module wired — verify the build is post-commit `77b4499`. |
| Per-token map growing unbounded | (none — by design until a `reload` hook ships) | Restart selfdefd to drop the dead entries. The map size is bounded by the distinct token-fingerprint set, which is operator-controlled. |

---

## Project boundary (R10212 — sacrosanct)

- Cap enforcement (the 429 rejection) lives in **selfdefd**.
- Metric emission (`/metrics` exposition) lives in **selfdef-api**.
- sovereign-os renders the gauges **READ-ONLY** in:
  - 3 Prometheus alert rules (`config/prometheus/alerts/ms022-sse-quota.rules.yml`)
  - 1 Grafana dashboard (`docs/observability/dashboards/sovereign-os-ms022-sse-quota.json`)
  - 1 master-dashboard banner (`webapp/master-dashboard/index.html` `#ms022-sse-quota-banner`)
  - 1 proxy API daemon (`scripts/operator/ms022-sse-quota-api.py` + `systemd/system/sovereign-ms022-sse-quota-api.service`)
- The sovereign-os surfaces never POST to selfdef — every operator
  remediation (raise cap, rotate token, restart daemon) is an
  `ssh <selfdef-host> sudo ...` command the dashboard COPIES to
  clipboard, never an HTTP mutation.

Drift on either side fails contract tests on **BOTH sides**:
- selfdef-side: `crates/selfdef-api/src/sse_quota_metrics.rs` 9 unit tests
- sovereign-os side: `tests/lint/test_ms022_sse_quota_alerts_contract.py` (12 tests) + `test_ms022_sse_quota_dashboard_contract.py` (10 tests) + `test_ms022_sse_quota_api_contract.py` (15 tests) + `test_ms022_sse_quota_api_systemd_contract.py` (13 tests) = 50 contract tests total

---

## Operator runbook references

- **Setup**: this document (selfdef side) +
  `sovereign-os/docs/operator/m060-deployment-guide.md` § "MS022Sse*"
  (consumer side, with per-alert diagnosis + fix commands).
- **Alert runbook**: see the `MS022Sse{GlobalQuotaApproaching,
  GlobalQuotaSaturated,PerTokenQuotaSaturated}` sections of the
  sovereign-os deployment guide.
- **CLI**: `curl --unix-socket /run/selfdef.sock /metrics` (no
  dedicated `selfdefctl` verb today — the metric surface is a
  Prometheus pull-only contract; a future `selfdefctl m060-metrics
  --artifact sse-quota` could surface it through the daemon api,
  but that's an additive enhancement, not a regression on the
  current state).
