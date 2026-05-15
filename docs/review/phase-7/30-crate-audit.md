# Phase 7 — crate audit

Audit pass over the **4 new Q-G channel crates** shipped by
the post-Phase-6 cycle: `selfdef-integration-pagerduty`,
`-loki`, `-opensearch`, `-thehive`. Closes **F-2032-004**
(client-builder duplication in PagerDuty) in-place.

## Methodology

For each crate: read `Cargo.toml`, top-level lib docs, every
public type and trait impl, every error variant, every
secret-bearing field's `Debug` shape, every test. Spot-check
the `docs/dev/integrations.md` contract:

- HTTPS-only endpoint guard.
- Secret-elision Debug.
- `from_config` validation surface.
- Notifier + Channel ABI parity.
- Severity-mapping consistency.
- Workspace-managed deps (no per-crate version pins).

Look for **drift** between the four — they all
pattern-instance the same template, so deviations are
signal.

## Per-crate audit notes

### `selfdef-integration-pagerduty` (559 LOC, 12 tests)

- `PagerDutyNotifier { client, endpoint, routing_key, source }`.
  Custom `Debug` elides `routing_key`; shows the 8-char prefix.
- `from_config(routing_key_file, endpoint, source)`.
  - `endpoint = ""` → use the default global US endpoint
    (`https://events.pagerduty.com/v2/enqueue`).
  - Non-`https://` endpoint → `EndpointNotHttps` error.
  - Empty `source` → defaults to `"selfdef"`.
- Severity map (`map_severity` OCSF 6 → PD 4):
  `Unknown / Other / Informational / Low → Info`,
  `Medium → Warning`, `High → Error`, `Critical / Fatal →
  Critical`. **Consistent with TheHive's collapse buckets.**
- Dedup model: per-fire dedup_key (PayloadId on engine path,
  Event id on legacy chain). Documented in module rustdoc.
- One drift on entry: `from_config` previously built the
  `reqwest::Client::builder()` inline instead of routing
  through `Self::new`. The 3 other Q-G adapters all route
  through their `new`. **Closed in this PR**: F-2032-004
  fix — `from_config` now returns `Self::new(routing_key,
  source).with_endpoint(endpoint)`.

### `selfdef-integration-loki` (600 LOC, 16 tests)

- `LokiNotifier { client, endpoint, tenant_id, token, source }`.
  Custom `Debug` redacts `token` (shows `<redacted>` /
  `None`); tenant_id + endpoint shown freely.
- `from_config(endpoint, tenant_id, auth_token_file, source)`.
  - `endpoint = ""` → `EmptyEndpoint`.
  - Non-`https://` → `EndpointNotHttps`.
  - Empty `tenant_id` → `None`.
  - `auth_token_file = Some(p)` → reads file, trims; empty
    → `EmptyTokenFile`; unreadable → `TokenFileUnreadable`.
  - Empty `source` → `"selfdef"`.
- Severity label (`severity_label` returns `&'static str`):
  6-level stable lowercase. **Consistent with OpenSearch's
  pass-through.**
- Line rendering collapses `\n` and `\r` to ` · ` so multi-
  line bodies stay one logical Loki entry.
- Three-mode auth via the `tenant_id` × `token` combination
  matrix.

**No drift.**

### `selfdef-integration-opensearch` (792 LOC, 22 tests)

- `OpenSearchNotifier { client, endpoint, index, auth_kind,
  username, token, source }`. Custom `Debug` redacts token.
- `from_config(endpoint, index, auth_kind, username,
  auth_token_file, source)`. The largest validation surface
  of the four:
  - `endpoint = ""` → `EmptyEndpoint`.
  - Non-`https://` → `EndpointNotHttps`.
  - Trailing slash stripped at parse time.
  - `index = ""` → `EmptyIndex`.
  - `auth_kind` parsed via `AuthKind::from_str_ci`:
    `"none"`/`""` / `"basic"` / `"apikey"` / `"api_key"` /
    `"api-key"`. Unknown strings → `UnknownAuthKind` (refuses
    rather than silently downgrading to None).
  - `auth_kind = "basic"` enforces both `username` non-empty
    + `auth_token_file = Some`.
  - `auth_kind = "apikey"` enforces `auth_token_file = Some`,
    ignores username.
  - `auth_kind = "none"` ignores both.
- Severity label: 6-level pass-through, matches Loki's.
- Wire shape: ECS-compatible (`@timestamp`, `service`,
  `host`, `severity`, `kind`, …). RFC-3339 timestamp via
  `time::OffsetDateTime`.
- 22 tests reflect the auth-mode complexity — verified
  legitimate coverage, not test-style padding (see Phase 7
  recent-PRs audit's pattern-uniformity table).

**No drift.**

### `selfdef-integration-thehive` (578 LOC, 16 tests)

- `TheHiveNotifier { client, endpoint, api_key, source,
  alert_type }`. Custom `Debug` elides `api_key`; shows the
  8-char prefix.
- `from_config(endpoint, api_key_file, source, alert_type)`.
  - `endpoint = ""` → `EmptyEndpoint`.
  - Non-`https://` → `EndpointNotHttps`.
  - Trailing slash stripped.
  - `api_key_file` required; unreadable → `ApiKeyFileUnreadable`;
    empty → `EmptyApiKeyFile`.
  - Empty `source` → `"selfdef"`.
  - Empty `alert_type` → `"selfdef"`.
- Severity map: OCSF 6 → TheHive 4, **same bucket-collapse
  as PagerDuty's** (`Unknown/Other/Informational/Low → 1`,
  `Medium → 2`, `High → 3`, `Critical/Fatal → 4`).
- TLP defaults to **Amber (2)** per the module rustdoc.
- Tag composition: `["selfdef", "selfdef:<severity>",
  "kind:<class_uid>"]`. `kind` tag omitted when
  `payload.event_kind.is_none()`.

**No drift.**

## Findings

### F-2032-004 (nice, closed-in-place)

**Surface**:
`selfdef-integration-pagerduty/src/lib.rs::from_config`.

Pre-fix code (lines 166-174):

```rust
Ok(Self {
    client: reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default(),
    endpoint,
    routing_key,
    source,
})
```

This duplicates the `Client::builder().timeout(10s).build()
.unwrap_or_default()` block that `Self::new` already
contains. The 3 other Q-G adapters route their `from_config`
through their `Self::new`; PagerDuty was the outlier.

**Concrete impact**: low at the behavior level — both code
paths produce identical clients. The real cost is **future-
edit fragility**: any change to the canonical client setup
(timeouts, TLS profile, connection pooling, redirect policy)
now has to be applied twice in PagerDuty, vs. once
elsewhere.

**Severity = nice**. Matches the secret-elision drift
pattern Phase 6 caught with ntfy in F-2031-005 (one channel
out-of-step with the others on a contract that's
operator-invisible until something regresses).

**Closed in this PR**: `from_config` rewritten as
`Ok(Self::new(routing_key, source).with_endpoint(endpoint))`.
The 12 existing tests still pass.

## Cross-crate consistency observations (no findings)

### Severity-mapping coherence

The four Q-G adapters split cleanly between two patterns:

- **4-level destinations** (PagerDuty, TheHive) use
  identical OCSF→4 collapse:

  | OCSF | PagerDuty | TheHive |
  | --- | --- | --- |
  | Unknown / Other / Informational / Low | Info | 1 (Low) |
  | Medium | Warning | 2 (Medium) |
  | High | Error | 3 (High) |
  | Critical / Fatal | Critical | 4 (Critical) |

- **6-level destinations** (Loki, OpenSearch) use identical
  stable lowercase labels (`informational` / `low` /
  `medium` / `high` / `critical` / `fatal` / `unknown` for
  the Unknown+Other catch-all).

Both groups are internally consistent and reflect the
destination's native severity vocabulary. **No drift.**

### Timeout posture

All four adapters use `Duration::from_secs(10)`. Twilio /
Slack / Discord from the SDD-008 main cycle use 10s as
well. **Consistent.** The ntfy crate uses 5s — historical
artifact from the legacy chain; not a Phase 7 concern.

### HTTPS-only guard

All four reject `http://` endpoints in `from_config` with
explicit `EndpointNotHttps`. PagerDuty's check is gated on
`endpoint.is_empty() == false` (since empty means "use the
default global US endpoint, which IS https"). Loki +
OpenSearch + TheHive require `endpoint` non-empty before
checking the scheme. **Consistent.**

### Secret-elision Debug

All four custom-impl `Debug` to redact the bearer / api key
/ routing key / password. Two patterns:

- **8-char prefix shown** (PagerDuty `routing_key_prefix`,
  TheHive `api_key_prefix`): operator can disambiguate
  multiple service instances in logs.
- **`<redacted>` marker** (Loki `token`, OpenSearch `token`):
  presence-but-not-value.

Both are defensible postures; the prefix approach is
slightly more operator-friendly for triage. Worth a future
cross-channel polish PR if the team wants uniform shape,
but **not a Phase 7 finding** — both posture variants
satisfy the secret-elision contract.

## Test surface analysis

The 12 / 16 / 22 / 16 test counts across the four Q-G
adapters reflect real auth-mode complexity (already
covered in the recent-PRs audit pattern-uniformity table).
Spot-checked the tests themselves against the contract:

- Every adapter has positive + negative `from_config` paths
  for every error variant.
- Every adapter has at least 2 wiremock tests (Notifier
  happy + Channel happy) + a non-success-status test.
- Every adapter has a `name_parity` test pinning that the
  legacy and orchestrator trait both return the same string.
- Every adapter has at least one `debug_elides_*` test.

**Coverage parity is real and proportional to surface
area.**

## Status

- F-2032-004 closed in-place (PagerDuty `from_config` now
  routes through `Self::new`).
- 4 Q-G crates audit **clean** at the crate level. The
  severity-mapping coherence, timeout posture, HTTPS-only
  guard, and secret-elision Debug shape all pass cross-crate
  review.

## Hand-off

- **Module explorer (next)**: walk the D-4 HTTP ack flow
  end-to-end (DispatcherAdapter mint → engine persist →
  channel send → handler ack).
- **Security explorer**: pick up F-2032-002 (token-IS-auth
  re-audit). The Q-G channel layer feeds the ack-URL out of
  band; the secret-elision posture above keeps the URL
  bearer-credential out of the daemon's local logs but the
  URL itself rides through Slack / SMTP / PagerDuty / etc.
- **Tests explorer**: no Q-G test concerns; pick up the
  `EngineHarness` pattern review and the schema-migration
  test coverage gap (do v2 + v3 migrations have tests at
  all? Initial scan suggests no — but that's the tests
  explorer's job).
