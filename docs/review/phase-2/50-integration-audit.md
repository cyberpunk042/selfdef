# Phase 2 — Integration audit

> Scope (per the Phase 2 charter): the four new post-Phase-1
> seams. Per-area ids prefix `I2-` and roll up to the ledger as
> `F-2027-NNN`.
>
> What this audit doesn't re-litigate: Phase 1's six integration
> flows (every `F-2026-NNN` integration finding closed during
> the previous cycle). If a Phase 1 fix is broken, that's a new
> `F-2027-NNN` with a back-reference.

## Headlines

- **1 important finding, 8 nice findings**. The important one
  (I2-008) is a TOCTOU + symlink-follow gap in the
  eventstream collector's integrity check that, on its own,
  defeats the opt-in `integrity_check = true` contract. Every
  other observation is documentation, log clarity, or test-
  coverage shaped.
- The three closed-explorer backlogs (recent-PRs, crate,
  module) total 27 findings — all closed except F-2027-010
  (SDD-debt). The integration explorer adds 9 more.

## Seam-by-seam notes

### Seam 1 — SSE writer (`/events/stream`) ↔ CLI follow consumer

Writer: `crates/selfdef-api/src/handlers.rs::events_stream` —
Axum SSE handler over UNIX socket. Reader:
`crates/selfdef-cli/src/follow.rs` — hand-rolled HTTP/1.1 +
chunked transfer + SSE-frame parser over `UnixStream`. Both
sides have ~50 lines of test coverage on their own; the *seam*
between them is exercised by one integration test
(`crates/selfdef-cli/tests/cli_events_follow.rs`) plus the
hand-crafted lagged-event test corpus.

Observations:

- `crates/selfdef-cli/src/follow.rs:120-124` (reader) silently
  ignores non-`data:` lines. The writer emits `:ping` keep-alive
  comments (SSE spec, fine) at
  `crates/selfdef-api/src/handlers.rs:138-142`, but the reader
  has no way to distinguish a routine keep-alive from a malformed
  comment (`:error something-terrible`) — they're both no-ops.
  A future protocol extension that uses comment payloads would
  need to add a "must-recognise" check. **(I2-001)**
- No explicit end-of-stream marker on the wire
  (`crates/selfdef-api/src/handlers.rs:110-112` vs.
  `crates/selfdef-cli/src/follow.rs:81-82`). The reader exits on
  `read_line` returning 0 bytes; the writer's task exits on
  `tx.send(...).is_err()`. From the reader's vantage, "the
  daemon crashed mid-stream" looks identical to "the daemon
  closed the stream cleanly because shutdown fired". An
  `event: shutdown` frame would let the CLI distinguish the
  two and exit with a different code. **(I2-002)**
- The lagged-event seam (writer's `Lagged(n)` → SSE
  `event: lagged` frame → CLI parse) is tested with hand-
  crafted bytes in `crates/selfdef-cli/tests/cli_events_follow.rs:162-197`
  but never against the real daemon under a synthetic burst.
  When the writer's 64-event mpsc channel
  (`crates/selfdef-api/src/handlers.rs:102`) overflows in
  practice, no test asserts the resulting frame parses. **(I2-003)**

### Seam 2 — SIGUSR2 token-reload (CLI rotate-token ↔ daemon SIGUSR2 handler)

Writer: `crates/selfdef-cli/src/main.rs::api_rotate_token`
(lines 1013-1110). Reader: `crates/selfdef-daemon/src/main.rs::wait_for_shutdown_or_reload`
SIGUSR2 branch (lines 677-725).

Order of operations on the writer:

```
tempfile + fsync → atomic rename → chmod → signal SIGUSR2
```

The atomic rename happens *before* the signal, so a mid-flight
auth check that races with the signal sees either the old token
or the new one — never a half-written file. Good. Two
follow-ups:

- `crates/selfdef-api/src/transport.rs::TokenReloader::reload`
  (~line 150) re-reads the token files but doesn't re-validate
  the mode-0600 invariant the writer asserts at
  `crates/selfdef-cli/src/main.rs:1083`. An operator who
  `chmod 0644 /etc/selfdef/api.token` would silently weaken the
  bearer-token surface — `reload()` succeeds, the daemon logs
  "api tokens reloaded from disk", and the token file is now
  world-readable. Either reject the reload on `mode & 0o077 != 0`
  or emit a `warn!` line surfacing the loose mode. **(I2-004)**
- `crates/selfdef-daemon/src/main.rs::wait_for_shutdown_or_reload`
  SIGUSR2 branch runs the three reload paths (api-token,
  verifier, rules) independently. If `rel.reload()` fails but
  `corr.reload_verifier()` succeeds, the operator sees two
  separate log lines and has to correlate them mentally: bearer-
  token failures will start hitting at the API layer (stale
  tokens), but a finding fired by a new rule signed by the
  rotated key will be visible in the store — so a quick
  "rotation worked!" check via `/findings` would be misleading.
  A summary line at the end of the SIGUSR2 handler ("reloaded:
  tokens=ok, verifier=ok, rules=N") would close the gap. **(I2-005)**

### Seam 3 — minisign verify ↔ correlator load_dir_verified

Writer: operator's offline `minisign -S` + scp of rule files
into `[correlator].rules_dir`. Reader:
`crates/selfdef-correlator/src/sigma.rs::Engine::load_dir_verified`
(lines 524-562) iterates `walk_yaml` (line 649) and calls
`Verifier::verify_detached_file` per entry.

- `walk_yaml` (lines 649-674) uses `std::fs::read_dir` whose
  iteration order is undefined per the standard library docs.
  Two rules with the same `level: high` priority that match the
  same event fire in whichever order `read_dir` yields them —
  a kernel-version / filesystem-version dependent ordering.
  Per-rule UUID-based deduplication later in the pipeline
  protects against double-emission, but a tie-break on
  "which rule's `detection.condition` short-circuits first" is
  effectively random. Add a `paths.sort()` before the loop in
  `walk_yaml`. **(I2-006)**
- `crates/selfdef-correlator/src/sigma.rs:545-557` checks the
  signature *before* the YAML parse. If a rule file is syntactically
  malformed but signed, the operator gets `SigmaError::Signature`
  instead of `SigmaError::Yaml` — counter-intuitive because the
  signature *was* valid (over the malformed bytes). Either swap
  the order (parse first, then verify) or augment the
  `SigmaError::Signature` variant to include a yaml-parse hint
  when the underlying file fails both checks. **(I2-007)**
- `crates/selfdef-correlator/tests/signed_rules.rs` covers the
  happy-path matrix (signed / unsigned / tampered / wrong-key)
  but not "mixed directory with one signed and one unsigned
  rule under `require_signed_rules = true`". The expected
  behaviour — the whole load fails, the prior ruleset stays
  loaded — is the most operator-relevant case (a half-deployed
  rotation looks like this). Add the case. (No new finding;
  this is a follow-up under I2-006.)

### Seam 4 — integrity check ↔ eventstream open

Writer: operator sets `[collectors.eventstream].paths` and
`integrity_check = true`. Reader:
`crates/selfdef-collector-eventstream/src/lib.rs::check_path_integrity`
(line 136) is called once at startup before
`tokio::fs::File::open` (line 100).

This seam carries the **only important finding** in the audit:

- **I2-008 — TOCTOU + symlink-follow** in
  `check_path_integrity`. The check uses `std::fs::metadata`
  (line 138) which is `stat()`, not `lstat()` — symlinks are
  silently followed. The collector then opens the path via
  `tokio::fs::File::open` (line 100) which also follows
  symlinks. Two attack vectors:
  1. **Symlink**: a non-root operator who can write `path` to
     point at a symlink targeting a file with `selfdef`-uid
     ownership passes the check; the collector then reads from
     a target the operator controls. Mitigation: re-stat with
     `symlink_metadata` (lstat) and refuse on `is_symlink()`.
  2. **TOCTOU rename**: between the stat (line 138) and the
     open (line 100), a malicious local user can replace the
     file with a symlink (via `rename`, which is atomic for
     symlinks). The opened FD then reads attacker-controlled
     data. Mitigation: open with `O_NOFOLLOW`, then fstat the
     returned FD to validate, instead of stat-then-open.
  3. **Post-startup drift**: even after a correct check + open,
     the FD is held for the daemon's lifetime
     (`BufReader::new(file)` at line 104). Nothing re-validates
     ownership / mode if the operator's daily `logrotate`
     replaces the file or chmods it. The collector keeps reading
     the now-invalid FD. (lower severity — this is a usage
     pattern bug, not an attack — but warrants a doc warning.)

  This is **important** rather than blocker because the
  integrity check is **opt-in** (`integrity_check = true` is
  off by default — see
  `crates/selfdef-config/src/lib.rs::CollectorsEventstreamConfig`).
  Operators who opt in are explicitly trusting the check, and
  the check has a defeatable gap. Fix shape: rewrite the check
  to lstat-then-(O_NOFOLLOW)open-then-fstat in a single
  syscall sequence; document the `logrotate` pattern in the
  collector's README. **(I2-008)**

## Triage

| ID | Severity | Surface | Closing-PR cluster |
| --- | --- | --- | --- |
| I2-001 | nice | SSE: `:ping` vs. malformed comment | seam-1 |
| I2-002 | nice | SSE: no end-of-stream marker | seam-1 |
| I2-003 | nice | SSE: lagged-event seam test gap | seam-1 |
| I2-004 | nice | TokenReloader doesn't validate file mode | seam-2 |
| I2-005 | nice | SIGUSR2 handler: per-reload logs, no summary | seam-2 |
| I2-006 | nice | walk_yaml: unsorted enumeration | seam-3 |
| I2-007 | nice | SigmaError: signature check before YAML parse | seam-3 |
| **I2-008** | **important** | eventstream integrity check: TOCTOU + symlink | seam-4 |

Closing-PR candidates (one per seam):

- **seam-1 docs + tests** — I2-001 + I2-002 + I2-003. Wire an
  end-of-stream frame; tighten reader's comment-payload
  handling; add a real-bus lagged-event seam test.
- **seam-2 token-mode + summary log** — I2-004 + I2-005. Reject
  loose-mode token files on reload; emit a one-line summary
  after the SIGUSR2 fan-out.
- **seam-3 deterministic load + error priority** — I2-006 +
  I2-007. Sort `walk_yaml`; swap (or augment) the
  signature-vs-yaml error priority.
- **seam-4 lstat-O_NOFOLLOW-fstat rewrite** — I2-008. The only
  important entry; ship its own PR with the explicit
  symlink-and-TOCTOU regression tests.

All 9 entries land in the Phase 2 findings ledger as
F-2027-028 through F-2027-036.
