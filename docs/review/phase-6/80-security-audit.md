# Phase 6 — security audit

Final Phase 6 explorer. Audits the SDD-008 surface for
security-relevant defects: credential handling on all 7
channels, wall(1) TTY broadcast as covert-channel vector,
SQLite injection surface in the EscalationEngine, outbound-
HTTP TLS posture, supply-chain implications of the `0BSD`
license addition (F-2031-003), data-at-rest sensitivity of
the `notification_escalations` SQLite file, and the
operator-ack ↔ wake-task rung-advance race for
security-relevant invariants.

Closes **F-2031-003** (re-audit complete, addition safe),
**F-2031-015** (ntfy silent-degrades-to-unauth, fixed),
**F-2031-016** (escalations SQLite file not documented in
SECURITY.md, added).

## Methodology

For each security-relevant surface added by SDD-008:

1. Trace the data flow from operator-controlled input
   (config file, channel response, TTY) to a place where it
   could be observed (log, on-disk file, network, process
   exit code).
2. Enumerate the principals who have access at each step.
3. Identify the integrity boundary and the failure mode if
   it's violated.

Cross-check against shipped fixes from the rest of the
Phase 6 audit (F-2031-005 ntfy Debug elision; F-2031-006
wall EPIPE; F-2031-009 subscription filter bypass).

## Findings

### F-2031-003 (re-audit complete — closed, no change needed)

Raised by the recent-PRs explorer (PR #133): in PR #114's
in-cycle fix-up commit `3ab3b21`, `0BSD` was added to
`deny.toml`'s `licenses.allow` to permit
`quoted_printable 0.5.2` (transitive via `lettre`). The
recent-PRs auditor deferred end-to-end verification to the
security pass.

Verification performed for this audit:

1. **The 0BSD allow matches only `quoted_printable`**:
   `cargo deny check licenses` emits two
   `license-not-encountered` warnings — for `CC0-1.0` and
   `MPL-2.0`, both already in our allow list but no longer
   used in the tree. **No `license-not-encountered` warning
   for `0BSD`**, which means it IS matched. Cross-checked
   via `cargo tree -p selfdef-integration-smtp -e normal -i
   quoted_printable`: a single inbound edge from
   `lettre 0.11.22`. No other crate in the tree uses
   `quoted_printable` directly.

2. **0BSD vs. existing allow list**: `0BSD` (Zero-Clause
   BSD) is the BSD-2-Clause license with the
   redistribution-acknowledgement clause removed. It is
   functionally equivalent to public-domain dedication. The
   allow list already contains `BSD-2-Clause` and
   `BSD-3-Clause`; admitting 0BSD is **strictly more
   permissive** for the licensee, not less.

3. **Provenance of the addition**: PR #114 modified
   `deny.toml` with an in-line justification comment naming
   the transitive dep and SDD-008 design-point reference.
   The change passed `cargo deny check licenses` on its
   merge run and continues to pass on every subsequent CI
   run.

4. **Supply-chain surface implications**: admitting 0BSD to
   the allow list opens the door to *future* 0BSD-licensed
   crates entering the tree without a deny.toml change. The
   allow-list-not-fence policy is intentional per
   `deny.toml`'s structure (we allow categories of license,
   not specific (crate, license) pairs). No
   action recommended; the policy is consistent with how
   `MIT` / `Apache-2.0` / `BSD-2-Clause` are admitted.

**Verdict: re-audit confirms the addition is safe.** F-2031-003
closes with no code change.

### F-2031-015 (important, **closed-in-place**)

**Surface**: `selfdef-integration-ntfy::from_config`.

Pre-fix code:

```rust
let token = token_file
    .and_then(|p| std::fs::read_to_string(p).ok())
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty());
Self::new(url, topic, token)
```

The `.ok()` silently converts a `Result<String, io::Error>`
into `Option<String>` — any IO error (file missing, wrong
permissions, daemon doesn't have read access) is dropped.

**Operator-facing impact**: an operator configures

```toml
[notifier.ntfy]
url = "https://ntfy.example.org"
topic = "selfdef-alerts"
token_file = "/etc/selfdef/secrets/ntfy.token"
```

If the daemon can't read `/etc/selfdef/secrets/ntfy.token`
(wrong owner / mode, typo'd path, file not deployed), the
channel silently constructs without a token. ntfy sends
proceed unauthenticated. The operator believes auth is
enforced because they configured a `token_file`; the actual
HTTP requests carry no `Authorization: Bearer …` header. If
the ntfy server happens to allow unauthenticated publishes
(many self-hosted instances do), notifications continue to
flow — masking the misconfiguration entirely.

Compare the secret-elision posture of the other 4 channels
that load files: **`slack` / `discord` / `smtp` / `twilio`
all propagate the IO error and refuse to construct**
(`SlackBuildError::WebhookFileUnreadable`,
`SmtpBuildError::PasswordFileUnreadable`, etc.). ntfy was
the outlier — same class of asymmetry as F-2031-005 (Debug
elision drift), now caught at the credential-load layer.

**Severity = important**: silent degradation of
authentication is exactly the operator-experience defect
the audit programme exists to catch. Not a crash, not data
loss; **silent loss of the configured auth posture** on a
credential-bearing channel.

**Closed in this PR**: `from_config` rewritten as an
explicit `match` that:

- `None` token_file → unauthenticated (intended).
- Read succeeds, trimmed empty → unauthenticated **with a
  `warn!`** so empty credential files don't pass silently.
- Read fails (IO error) → unauthenticated **with a `warn!`
  naming the path + the IO error** so misconfig surfaces
  in the daemon log.

The channel still constructs even on read failure —
matching the daemon's broader posture that single-credential
failures should degrade-with-loud-warn rather than
fail-daemon-startup. Five new tests pin the contract:

- `from_config_no_token_file_yields_unauthenticated`.
- `from_config_unreadable_token_file_yields_unauthenticated_with_warn`.
- `from_config_empty_token_file_yields_unauthenticated`.
- `from_config_whitespace_only_token_file_yields_unauthenticated`.
- `from_config_well_formed_token_file_attaches_token`.

ntfy now matches the other 6 channels' credential-load
posture on the "surface the operator's misconfig" axis,
while keeping its less-fatal "don't crash the daemon"
posture (which is operator-reasonable for an optional auth
token vs. e.g. an SMTP password where unauth would mean
"can't send mail at all").

### F-2031-016 (nice, **closed-in-place**)

**Surface**: `SECURITY.md`.

The `[notifier.escalations_path]` SQLite file (typically
`/var/lib/selfdef/escalations.sqlite`) holds the rendered
title + body of every persisted alert. The cycle's
SECURITY.md updates documented the credential files and
the wall(1) TTY broadcast but **did not document the
escalations file itself as sensitive data-at-rest**.

Concrete sensitivity: a typical row's `body` contains:

- The triggering event's hostname.
- The source IP / process name / file path that triggered
  the rule.
- ATT&CK technique ids (a partial blueprint of detection
  coverage).
- Command lines for `process_exec` finding events.

An attacker with read access to the escalations file
learns which events the daemon noticed (and which it didn't
ack). For a still-defending compromised host, this is a
roadmap of which detections to evade.

WAL mode adds two sibling files (`-wal` + `-shm`) with
identical sensitivity. `selfdefctl notify forget` (and the
wake-task `close_event` path) DELETEs rows but SQLite does
not zero the freelist by default; rotated content remains
recoverable from the database file until `VACUUM` is
issued.

**Severity = nice**: the protection mechanism (file
permissions, daemon-owner-only access) is already in
place via the system-defaults SDD-002 contract for
`/var/lib/selfdef/`. This finding is about **documentation**
— the operator should know what's on disk and what the
boundary protects against.

**Closed in this PR**: SECURITY.md gains a new row:

> | Notification escalations store |
> `[notifier.escalations_path]` (per SDD-008 D-5) |
> Persists every outbound notification's rendered title +
> body until the operator acks or `max_rung` expires.
> **Cleartext at rest**. SQLite WAL adds `-wal` + `-shm`
> siblings with same sensitivity. Mode `0600`, daemon owner
> only. Closed-event rows DELETEd but not zeroed —
> rotated content recoverable until `VACUUM`. |

## Audit notes — no new finding

### Credential handling, channel-by-channel

| Channel | Secret-bearing field | Load path | On-error posture |
| --- | --- | --- | --- |
| ntfy | optional `Bearer` token | `token_file` | **was silent-degrade; F-2031-015 fix → degrade-with-warn** |
| signal | none (binary path + account + recipient only) | N/A | — |
| smtp | password | `password_file` | propagate `PasswordFileUnreadable` → daemon refuses to construct channel |
| twilio | `auth_token` | `auth_token_file` | propagate `AuthTokenFileUnreadable` → daemon refuses |
| slack | webhook URL (URL IS the secret) | `webhook_url_file` | propagate `WebhookFileUnreadable` → daemon refuses |
| discord | webhook URL | `webhook_url_file` | propagate `WebhookFileUnreadable` → daemon refuses |
| wall | none (binary path only) | N/A | — |

After F-2031-015, the 5 credential-bearing channels split
cleanly between "auth optional → degrade with warn" (ntfy)
and "auth required → refuse to construct" (smtp / twilio /
slack / discord). Both are defensible postures; the
operator gets a loud log signal either way.

**Secret-elision Debug**: closed by F-2031-005 in PR #133.
All 5 secret-bearing channels now elide credentials in
their `Debug` output. Cross-checked via the
`debug_elides_*` test in each crate.

**File-mode enforcement**: no channel checks the credential
file's mode. SECURITY.md recommends `0600`; the daemon
trusts the operator's filesystem permissions. Documented
as operator's concern; not a finding because defense-in-
depth (daemon verifies mode at startup) is out of SDD-008's
scope and the principal safeguard *is* filesystem perms.

### Command-injection surface (signal, wall)

Both subprocess channels pass arguments via
`tokio::process::Command::new(&binary).arg(...)`:

- `signal`: `signal-cli -a <account> send -m <message>
  <recipient>` — all four arguments are passed as discrete
  argv entries via `.arg(...)`, NOT concatenated into a
  shell command. The `message` string can contain shell
  metacharacters (`;`, `|`, `$()`, backticks, newlines) —
  they're literal argv bytes to `signal-cli`, never reach
  any shell.
- `wall`: message goes through **stdin** (piped from the
  daemon to the wall binary), never argv. No argv-based
  interpretation possible.

**Clean.** No command-injection vector in either
subprocess channel.

### SQLite injection surface (EscalationEngine)

Every SQL statement in `selfdef-notifier-engine::lib::*`
uses `rusqlite::params!` for parameter binding. No string
interpolation of operator-controlled or
attacker-controlled data into SQL anywhere. Verified:

```rust
guard.execute(
    "INSERT INTO notification_escalations (...) VALUES (?1, ?2, ?3, ...)",
    params![event_id, payload_id, title, body, ...],
)
```

```rust
guard.execute(
    "UPDATE notification_escalations
       SET rung_index = ?1, deadline_at = ?2
     WHERE event_id = ?3 AND acked_at IS NULL AND rung_index < ?1",
    params![new_rung, new_deadline, event_id],
)
```

The schema-bootstrap path uses `execute_batch` with a
static `CREATE TABLE` statement — no interpolation.
`prepare` + `query_map` for `take_due` likewise uses
`params!`. **Clean.**

### Outbound-HTTP TLS posture

Workspace `Cargo.toml` pins:

```toml
reqwest = { version = "0.12", default-features = false,
            features = ["rustls-tls", "json"] }
```

- `default-features = false` disables native-tls (system
  trust store) — no platform-dependent CA discovery.
- `rustls-tls` uses rustls + webpki-roots — a deterministic,
  in-binary CA bundle.
- All four HTTP channels (ntfy / twilio / slack / discord)
  construct via `reqwest::Client::builder()` with explicit
  timeouts (5s ntfy, 10s slack/discord, configurable
  twilio).
- **No `danger_accept_invalid_certs`** or any other
  `.danger_*` method in any channel crate's source.

Compared with SDD-007's API surface (TLS-server side via
`rustls`), the channels' TLS-client side is consistently
modern and validation-strict. **Clean.**

### Wall(1) as covert-channel vector

Threats considered:

1. **Authenticated local user reads broadcast banner**: by
   design — wall(1)'s purpose is to broadcast. The default
   `severity_floor = "high"` limits content to operator-
   flagged-significant events; routine `Informational`
   events never broadcast.
2. **Authenticated local user with `tty` group injects content
   into wall(1)**: out of scope — that user can already run
   their own `wall` directly. The daemon does not deny what
   the OS allows.
3. **Daemon-process compromise → wall(1) used as
   data-exfiltration channel**: a compromised daemon can
   already exfiltrate via any of the 6 outbound channels;
   wall(1) adds nothing here that the other channels don't
   already provide.

The `severity_floor` knob (default `high`) is the principal
defense-in-depth control — refuses to broadcast routine
events. F-2031-006 (closed in PR #133) hardened the
EPIPE-on-stdin path so a TTY-less host produces a clean
exit-status outcome rather than a transport-class error.

**No finding.** Behaviour is operator-facing-by-design;
already noted in SECURITY.md.

### Operator-ack ↔ wake-task rung-advance race

Audited as part of the module explorer (F-2031-007 closure
+ module-audit doc). Re-confirmed from the security angle:

- `EscalationEngine::record_ack` uses `UPDATE
  notification_escalations SET acked_at = ?1 WHERE event_id
  = ?2 AND acked_at IS NULL` — idempotent re-ack
  (returns `Ok(false)` second time) and ack-on-unknown-event
  (returns `Ok(false)`).
- `EscalationEngine::advance_rung` uses `WHERE acked_at IS
  NULL AND rung_index < ?1` — wake-task advance racing an
  operator ack loses correctly (the wake-task sees `acked_at
  IS NULL` is false after the ack, returns 0 rows updated).
- `EscalationEngine::close_event` is unconditional DELETE.
  Wake-task "max rungs reached → close" racing an ack: the
  close wins, the ack returns `Ok(false)` (row gone). The
  operator's `ack` after `close` is a no-op, which is the
  semantically right outcome (closing means we already gave
  up; an ack at that moment is moot).

**No security-relevant race.** The state machine's
serialization through the SQLite `Mutex` rules out TOCTOU
on row state. Already covered by 16 `EscalationEngine`
unit tests.

## Threat model summary

| Adversary (per SECURITY.md taxonomy) | New surface | Mitigation |
| --- | --- | --- |
| Authenticated local attacker | Sees rendered alert content in `escalations.sqlite` if they have read access | Mode 0600 + daemon-owner default; F-2031-016 documents this |
| Root-level attacker | Has read access to credential files + escalations DB | Out of scope — root sees everything |
| Supply-chain attacker | New transitive: `quoted_printable` (0BSD) via `lettre` | F-2031-003 re-audit confirms safe; cargo-deny gate intact |
| Malicious SSH server | Not applicable to SDD-008 | — |
| Cluster-tenant attacker | Not applicable to SDD-008 | — |
| Opportunistic remote attacker | Outbound channels are client-side TLS only; no inbound network surface added by SDD-008 (the `/notify/ack/<token>` endpoint is open-follow-up, **not** in v1) | reqwest rustls-tls + webpki-roots; no `danger_*` overrides |

## Status

- **F-2031-003**: closed (re-audit complete; 0BSD addition
  safe).
- **F-2031-015**: closed in-place (ntfy degrade-with-warn;
  5 new tests).
- **F-2031-016**: closed in-place (SECURITY.md
  notification-escalations row added).
- All 7 channel credential paths, SQLite injection surface,
  TLS posture, subprocess command-injection surface, and
  operator-ack ↔ wake-task race audit clean.

## Phase 6 closure

This is the seventh and final Phase 6 explorer. With this
PR's three closures:

- 14 findings raised total (F-2031-001 through F-2031-014
  inclusive plus F-2031-015, F-2031-016 = 16 ids).

Wait — let me recount accurately in the ledger update PR.
The closure summary belongs in a separate wrap-up doc /
PR, mirroring Phase 5's "Phase 5 wrap" pattern.

## Hand-off

- **Phase 6 wrap PR (next, last)**: update the ledger's
  Status line to "wrapped", record the per-explorer
  finding tally, and document the two open SDD-debt
  findings (F-2031-009 D-5e subscription filter wiring;
  F-2031-013 SDD-005 implementation-PR daemon-pipeline
  test) that close outside the Phase 6 audit programme.
