# Phase 7 — security audit

Final Phase 7 explorer. Audits the security-relevant
surface added by the post-Phase-6 cycle: the first
unauthenticated API route (`/notify/ack/:token`), 4 new
channel-credential surfaces, schema v2 + v3 migration
safety, and the third-party-log-leakage surface that
`ack_link` opens. Closes **F-2032-002** (referral → audit
complete + SECURITY.md addendum).

## Methodology

For each security-relevant surface added by the post-Phase-6
cycle:

1. Trace operator-controlled or attacker-controlled inputs
   to where they could be observed (log, on-disk file,
   third-party service).
2. Enumerate the principals with access at each step.
3. Identify the integrity boundary and the failure mode.

Cross-check against shipped fixes from the rest of Phase 7
(F-2032-001 schema transactions, F-2032-005 token stability,
F-2032-006 migration upgrade tests).

## Findings

### F-2032-002 (referral, **closed**)

Raised by Phase 7 recent-PRs explorer: PR #142 introduced
`GET /notify/ack/:token` — the first unauthenticated API
route selfdef ships. The PR documents the "token IS the
auth" model upfront. Phase 7 security explorer was tasked
with the end-to-end re-audit.

#### Brute-force feasibility

UUIDv7 wire shape: 128 bits total = 48-bit Unix-ms timestamp
+ 4-bit version + 12-bit random + 2-bit variant + 62-bit
random. The **post-timestamp entropy is ~74 bits** (random
fields). An attacker observing one URL learns the daemon's
local clock at one moment; they can predict the timestamp
prefix of future tokens but not the random suffix.

Brute-force search space against a known-time window
(say, last 24h of issuance = ~86.4M valid timestamp ms):

```
2^74 / 86.4M ≈ 2^48 ≈ 281 × 10^12 guesses
```

At 10K req/s online (a daemon doing nothing else): 893
years. **Not online-brute-forceable.** Token space is well
above the threshold where the operator's TLS / proxy
rate-limiting would have to do the work.

#### Third-party-log-leakage map

The realistic attack surface. Walked all 11 channels and
classified by whether they put the `ack_link` URL into
their outbound wire body:

| Channel | Includes ack_link? | Where the URL ends up |
| --- | --- | --- |
| ntfy | no | — |
| signal | no | — |
| smtp | **yes** (line 269) | SMTP relay logs, mail spools, recipient inboxes |
| twilio | **yes** (line 303) | Twilio dashboard SMS history, recipient phone |
| slack | **yes** (line 210) | Slack workspace search, audit log |
| discord | **yes** (line 204) | Discord channel history, audit log |
| wall | **yes** (line 287) | TTYs of every logged-in user |
| pagerduty | no | — |
| loki | no | — |
| opensearch | no | — |
| thehive | no | — |

**5 of 11 channels** include the URL in their wire body —
all 5 are human-facing channels. The 4 Q-G adapters
shipped this cycle (PD / Loki / OS / TheHive) deliberately
do NOT include the URL in their wire body (they're
SIEM/incident-management ingestion targets, not
human-clickable).

**Concrete attack surfaces**:

- Operator in a shared Slack channel with non-SOC members:
  every URL is search-indexable + clickable by anyone with
  channel access.
- Operator's SMTP relay is third-party (e.g. Mailgun /
  SendGrid): provider sees every URL.
- Twilio dashboard access for billing / non-SOC roles:
  full SMS history including URLs.
- wall(1) broadcasts to every logged-in user on the host:
  anyone with a TTY session learns the URL.
- Discord audit log retains URLs even after message
  deletion.

**After Phase 7 F-2032-005**: a leaked token stays valid
for the full lifetime of the unacked row, including across
rung re-fires. This is **the post-fix posture** —
before F-2032-005, a leaked token T1 was implicitly
invalidated by the adapter's next mint (T2 would have
shipped to the next rung's channel send, although that
URL would have been 404 too). Operators should be aware
that the token-stability fix prioritized correctness over
"automatic invalidation via mint refresh".

**Mitigation recommendations** (now documented in
SECURITY.md):

1. Prefer **machine-only Q-G channels** (PagerDuty / Loki /
   OpenSearch / TheHive) for routing — they don't include
   the URL.
2. Restrict human-facing channel delivery destinations to
   SOC-only audiences (private SMTP destinations,
   SOC-internal Slack channels, etc.).
3. Don't configure `ack_link_base` if the operator's
   channel topology can't keep the URL inside the trust
   boundary; CLI ack via `selfdefctl notify ack <id>`
   still works fine.

#### Closure

This PR adds a new SECURITY.md row documenting the URL-
leakage surface with the per-channel inclusion map, the
brute-force math, and the post-F-2032-005 stability note.
F-2032-002 closes with no code change; the docs delta is
the audit artifact.

## Other surfaces re-audited (no new findings)

### Schema v2 + v3 migration safety

Phase 7 integration explorer (F-2032-001 closure) wrapped
each migration block in `unchecked_transaction()`. Phase 7
tests explorer (F-2032-006 closure) added explicit v1 → v3
+ v2 → v3 upgrade-path tests.

**Re-audited from the security angle**:

- An attacker with write access to `escalations.sqlite`
  can set `user_version` to a future value (e.g. 999) and
  cause `SchemaTooNew` on next daemon open. **This is DoS
  via DB-file tampering** — not new; the daemon's working
  assumption is operator-owned filesystem (mode 0600,
  daemon-user-owned).
- The `randomblob(16)` back-fill uses SQLite's PRNG. On
  upgrade from v2, existing rows get fresh tokens. The
  PRNG is seeded from `/dev/urandom` per the SQLite docs —
  not attacker-controllable.
- Transaction rollback semantics ensure mid-migration
  failure (e.g. attacker pulls the rug on the DB file)
  leaves the schema at the prior version. **Recoverable.**

**Clean.**

### 4 new channel credential surfaces

Phase 7 crate explorer verified secret-elision Debug for
all four:

| Channel | Secret | Elision posture |
| --- | --- | --- |
| pagerduty | routing_key | 8-char prefix shown, rest elided |
| loki | bearer token | `<redacted>` marker |
| opensearch | basic password OR API key | `<redacted>` marker |
| thehive | API key | 8-char prefix shown, rest elided |

All four HTTPS-only endpoint guards present. All four
reject `http://` at `from_config`. None of the four logs
the secret in `tracing` calls.

**Clean.** Re-confirmed at security level.

### Race conditions

Phase 7 module explorer audited `record_ack_by_token` and
the wake_task's `dispatch_payload_for_rung` interaction.
The handler's `unchecked_transaction` prevents
`close_event` racing with the UPDATE+SELECT.

Re-walked from the security angle:

- An attacker who has the ack URL races with the wake
  task: the wake task's `take_due` queries
  `WHERE acked_at IS NULL AND deadline_at <= ?`. The
  handler's UPDATE sets `acked_at = ?` first. If the
  handler's transaction commits before the wake task's
  `take_due`, the wake task sees the acked row as
  acked and skips. If the wake task's `take_due` runs
  first, it pulls the row but the subsequent
  `advance_rung` fails the `acked_at IS NULL` guard
  and the rung doesn't advance. **Either order is safe.**
- `lookup_or_mint_token` is the responder-side
  pre-submit lookup. No security implication; an attacker
  controlling event input can already trigger any
  channel-send the responder configures.

**Clean.** No new findings.

### Token-stability + ack_token persistence (F-2032-005 closure)

The fix shipped in Phase 7's module explorer: adapter
calls `engine.lookup_or_mint_token(event_id)` before
constructing the Payload, so re-submits use the canonical
stored token rather than minting fresh.

**Security implication**: a leaked token stays valid for
the full lifetime of the unacked row, **including across
rung re-fires** and **including across responder
re-submits**. Pre-fix, the token would have been
implicitly rotated by the adapter on every re-submit
(though the URL the operator clicked would still 404 —
the bug F-2032-005 closed).

This **strengthens the third-party-log-leakage threat**:
a token-bearing URL that ends up in a Slack message stays
clickable until the operator acks (or the row's deadline
expires). Documented in the SECURITY.md addendum.

## Status

- F-2032-002 closed by re-audit + SECURITY.md addendum.
- Schema v2 + v3 migration safety: clean (F-2032-001 +
  F-2032-006 closures).
- 4 new channel credential surfaces: clean (Phase 7 crate
  explorer + this re-audit).
- Race conditions: clean.
- All 6 findings from Phase 7 now closed.

## All 7 Phase 7 explorers complete

| Explorer | Findings raised | Findings closed |
| --- | --- | --- |
| inventory + recent-PRs | F-2032-001, -002, -003 | (raises) |
| crate | F-2032-004 | -004 |
| module | F-2032-005 | -005 |
| integration | (closes -001) | -001 |
| docs | (closes -003) | -003 |
| tests | F-2032-006 | -006 |
| security | (closes -002) | -002 |
| **Totals** | **6 raised** | **6 closed** |

Phase 7 ready to wrap — separate PR will flip the ledger
Status to `wrapped`.

## Hand-off

- **Phase 7 wrap PR (next, last)**: flip ledger Status
  line `open` → `wrapped`; document the cumulative
  trajectory and the 6-of-6 closure rate.
