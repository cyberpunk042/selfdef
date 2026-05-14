# Phase 3 — Security audit

> Scope (per the Phase 3 charter): new attack surfaces introduced by the
> Phase 2 closure cycle (commits `2d918ac` → `ee0e1a9`). Per-area ids
> are `F-2028-NNN` and roll up to the ledger.
>
> This audit re-verifies the closures that hardened security surfaces
> (F-2027-031/-032 token-file mode check, F-2027-035 eventstream TOCTOU,
> F-2027-061/-062 SSE subscriber cap + timeout) and surfaces new findings
> in the TCP-follow client, API error logging, and daemon architecture.

## Headlines

- **No blockers, 1 important finding.** One real exposure in the SSE
  subscriber cap design: a single malicious bearer-token holder can
  saturate the global cap and DoS legitimate operators. The TCP-follow
  client's URL handling is safe by reqwest design (http/https only);
  no scheme-validation gap exists.
- **2 nice findings** (CLI UX gaps, missing test coverage).
- **1 SDD-debt finding** (per-token quota design).
- **Re-audit of F-2027-031/-032, F-2027-035, F-2027-061/-062** shows
  all closures holding correctly — token mode checks mirror, eventstream
  TOCTOU is eliminated, SSE cap is enforced. No regressions detected.

## Per-area observations

### Area 1 — TCP-follow client URL parsing (audit of F-2027-010)

#### F-2028-036 — **demoted** — `events_follow_tcp` URL scheme validation

`crates/selfdef-cli/src/follow.rs:321-327` constructs the SSE endpoint URL
via `format!("{}/events/stream", base_url.trim_end_matches('/'))` without
validating the `base_url` scheme. However, reqwest's default configuration
restricts the client to `http://` and `https://` schemes only — attempting
to construct a request with any other scheme (e.g., `file://`, `ftp://`)
fails inside `client.get(&url)` before any network access occurs.

**Evidence:**
- `/crates/selfdef-cli/src/follow.rs:328-334` — `reqwest::Client::builder()`
  with no custom scheme handling
- Reqwest documentation: default client only supports http/https

**Cross-check result:** Not a finding. Reqwest's built-in scheme restriction
provides the defense automatically. An operator passing `--url file:///etc/passwd`
gets an error from reqwest ("unsupported scheme"), which is appropriate.

(This was flagged during crate-explorer as F-2028-009 demoted; re-verified
in security pass as indeed safe-by-design.)

---

### Area 2 — SSE subscriber cap architecture

#### F-2028-037 — **important** — SSE subscriber cap is global, not per-token; one malicious bearer-holder can DoS legitimate operators

`crates/selfdef-api/src/handlers.rs:156-161` enforces a global
`MAX_SSE_SUBSCRIBERS = 64` cap via a per-process atomic counter. When
multiple operators hold different read-only bearer tokens (issued via
separate `selfdefctl api rotate-token` calls), a single token holder can
saturate the cap by opening 64 concurrent `/events/stream` connections,
preventing any other token holder from connecting until the attacker
drops their connections. The cap is per-process-global, not per-token,
so authenticated DoS is possible and impacts the availability of the
API for legitimate operators.

**Evidence:**
- `/crates/selfdef-api/src/state.rs:31` — `sse_subscribers: Arc<AtomicUsize>`
  is per-`ApiState`, shared across all requests (no per-token tracking)
- `/crates/selfdef-api/src/handlers.rs:120-140` — `SubscriberGuard::try_acquire`
  checks against global cap, not a per-token quota
- `/crates/selfdef-api/tests/m12_api.rs:792-861` — `events_stream_rejects_over_cap_with_503`
  test saturates the global cap; no per-token quota test exists

**Scenario:**
1. Operator A holds token `A` (read-only); Operator B holds token `B` (read-only).
2. An attacker with access to token `A` opens 64 concurrent `/events/stream`
   connections via the TCP transport.
3. All 64 slots are consumed; the cap is exhausted.
4. Operator B tries to open a connection with token `B` → HTTP 503 `sse subscriber cap reached`.
5. Operator A cannot use the API until the attacker closes their connections.

**Mitigation:** Either implement a per-token (or per-source-IP) quota
beneath the global cap, or document the authenticated DoS risk in
`SECURITY.md` and recommend operators run multiple daemon instances
behind a load balancer if distributing tokens to untrusted consumers.
This is a design question (see F-2028-039 below).

---

#### F-2028-038 — **nice** — TCP-follow 503 error message doesn't surface the cap-reached detail to operator

`crates/selfdef-cli/src/follow.rs:339-347` routes the daemon's HTTP 503
response (with body `{"error":"sse subscriber cap reached"}`) through a
generic error handler that prints `"daemon refused /events/stream: HTTP 503 ..."`.
An operator seeing the 503 has to check Prometheus metrics or inspect the
raw response body to learn the cap is exhausted rather than a transient
daemon issue. The daemon-side message is already specific; the CLI should
extract and surface it.

**Evidence:**
- `/crates/selfdef-cli/src/follow.rs:342-347` — error handling calls `resp.text()`
  but doesn't attempt to parse the JSON body for an error field
- `/crates/selfdef-cli/tests/cli_events_follow_tcp.rs` — no test case for 503
  with specific error-message extraction

**Mitigation:** When status is not 2xx, attempt to parse the response body
as JSON and extract an `"error"` field if present; surface it in the error
message (e.g., "daemon refused /events/stream: HTTP 503 (sse subscriber cap reached)").

---

### Area 3 — Bearer-token file read path (re-audit of F-2027-031 + F-2027-032)

`crates/selfdef-api/src/transport.rs::read_token` and
`crates/selfdef-cli/src/follow.rs::read_token_file` both validate the file's
mode (`mode & 0o077 == 0`) and trim the content using `str::trim()`. The
Phase 2 closures that shipped these checks are verified holding:

1. **Mode check parity** — both sides refuse files with `group` or `other`
   bits set. CLI mirrors daemon; operator sees the same error regardless
   of which side hits the loose file first. (F-2028-004 + F-2028-005
   closures already pinned this contract via test
   `events_follow_token_file_refuses_world_readable_mode`.)

2. **TOCTOU between stat and read** — the CLI calls `std::fs::metadata()`
   then `std::fs::read_to_string()` without `O_NOFOLLOW`. If the file is
   a symlink, the stat follows the symlink, validates the *target* file's
   mode, then opens the *link* itself (if the link is readable). This is
   a lower-severity TOCTOU than the eventstream case (F-2027-035) — the
   attack requires the operator to provision a symlink in their own config
   directory, which is already a trust boundary. Not flagged as a finding.

3. **Null-byte handling** — both sides call `str::trim()` on the result of
   `read_to_string()`. Rust's `String` cannot contain internal `\0` bytes
   in meaningful ways; `read_to_string()` includes them in the string, but
   `trim()` only removes leading/trailing whitespace. A token file with an
   embedded `\0` byte (e.g., `abc\0def\n`) would be read as `"abc\0def"`
   after trim and passed to the Authorization header as-is. The bearer-auth
   middleware in `selfdef-api/src/transport.rs` compares the token via `==`
   string equality, so a `\0`-containing token would fail to match (safe by
   construction). Low risk; an operator would have to craft such a file
   explicitly.

### Area 4 — `validate_rbac_subject` charset (re-audit of F-2028-009)

`crates/selfdef-cli/src/main.rs:1480-1495` validates RBAC subject names
against the regex `[A-Za-z0-9:._/@-]` and a 253-byte cap. Re-audit confirms
no new gaps:

1. **Charset correctness** — the validator accepts Kubernetes built-in
   subjects (`system:authenticated`, `system:masters`, etc.), ServiceAccount
   forms (`system:serviceaccount:ns:name`), and email addresses (`user@domain`).
   The charset forbids whitespace, shell metacharacters, ANSI escapes, and
   non-ASCII characters. Appropriate for defense-in-depth on a command that
   passes untrusted input to `kubectl` (already safe by construction — no shell).

2. **Length cap** — 253 bytes matches Kubernetes's DNS-name cap. ServiceAccount
   subjects are capped at ~127 bytes by Kubernetes API validation, so the
   253-byte cap is not tight, but safe (no overflow).

3. **Test coverage** — 7 unit tests + 1 integration test exercise the validator's
   happy path and error cases (empty, shell-meta, ANSI, whitespace, over-length).
   Coverage is adequate.

### Area 5 — `ApiError::store` log line for sensitive-error leaks (re-audit of F-2027-063)

`crates/selfdef-api/src/handlers.rs:265-281` logs store errors at WARN
level and returns a generic `"store unavailable"` body. Re-audit confirms
the closure F-2027-063 is holding:

1. **Sensitive-error content** — if a future store-error message includes
   a path (e.g., `sqlite: open /var/lib/selfdef/state.sqlite: EACCES`),
   the path is now logged server-side at WARN, not sent to the client. The
   path is already discoverable from the daemon config, so the leak is
   small, but best practice was applied.

2. **Log level** — WARN is appropriate: it indicates an API problem (caller
   gets 500), and the operator sees the reason in structured logs. An
   alternative would be DEBUG (excluded from default logs), but WARN is
   correct for indicating API availability issues.

---

### Area 6 — `SubscriberGuard` cap enforcement (re-audit of F-2027-061 + F-2027-062)

`crates/selfdef-api/src/handlers.rs:111-147` implements an RAII
`SubscriberGuard` that atomically increments and decrements the per-process
SSE subscriber counter. Re-audit confirms the closures are sound:

1. **Atomics memory ordering** — `Ordering::Acquire` on load,
   `Ordering::AcqRel` on compare-exchange (line 129), and `Ordering::AcqRel`
   on fetch_sub (line 145). The ordering is correct: Acquire synchronizes
   with prior release-stores; AcqRel ensures the increment/decrement is
   atomic and synchronizes with paired operations. The cap cannot be bypassed
   via a race.

2. **Guard lifetime** — the guard is moved into the spawned `tokio::spawn`
   task (line 171) and held for the task's lifetime. When the writer task
   exits (client disconnect, bus closed, send timeout), the guard drops and
   the counter decrements. The pattern is sound.

3. **Slow-client timeout** — every `tx.send()` is wrapped in
   `tokio::time::timeout(30s, ...)` (lines 194-203). On timeout the task
   logs and returns, freeing the guard slot. The deadline is reasonable for
   an SSE stream.

---

### Area 7 — Eventstream TOCTOU + symlink check (re-audit of F-2027-035)

`crates/selfdef-collector-eventstream/src/lib.rs:179-228` implements
`open_with_integrity_check` using `O_NOFOLLOW | O_NONBLOCK` open followed
by fstat on the returned FD. Re-audit confirms the closure is holding:

1. **Symlink rejection** — `O_NOFOLLOW` causes open to return ELOOP (errno 40)
   if the path is a symlink. The code maps this to `EventstreamError::IntegritySymlink`
   with operator-facing message directing them to the real file.

2. **Post-open TOCTOU closure** — fstat on the returned FD (line 217) is
   locked to the inode opened, so a post-open rename/replace on disk doesn't
   affect validation.

3. **File-type validation** — `is_file()` refusal rejects fifos, sockets,
   devices, and directories. `O_NONBLOCK` prevents the open call from
   blocking on a fifo.

The mitigation is complete and verified.

---

### Area 8 — F-2027-014 `with_full_capability` feature-gate (re-audit)

`crates/selfdef-api/src/lib.rs:50-61` wraps the router in a test-helper
capability grant, gated on the `test-helpers` Cargo feature. Re-verified:

```rust
#[cfg(feature = "test-helpers")]
pub fn with_full_capability(router: Router) -> Router {
    with_capability(router, Capability::Full)
}
```

The feature gate is present; production code cannot call the function.
The closure is verified holding.

---

## Appendix — Design questions and deferred findings

### F-2028-039 — **SDD-debt** — Per-token SSE subscriber quota design

The global SSE cap (F-2027-061) bounds worst-case memory per process, but
a single malicious token holder can fill the cap and DoS others (F-2028-037).
Future phases should scope whether to:

1. Implement a per-token quota (e.g., 8 connections per token, 64 global).
2. Implement a per-source-IP quota for TCP clients.
3. Document the authenticated DoS risk and recommend operators run
   multiple daemon instances behind a load balancer.

This is a design question; the immediate fix for F-2028-037 is out of scope
for Phase 3 (important severity but design-shaped). Recommend creating
SDD-007 to scope the options.

---

## Triage

| ID | Severity | Surface | Closing-PR cluster |
| --- | --- | --- | --- |
| F-2028-036 | demoted | TCP-follow URL scheme validation | none (safe by design) |
| F-2028-037 | important | SSE cap is global not per-token | (open) |
| F-2028-038 | nice | TCP-follow 503 error-message detail | (open) |
| F-2028-039 | SDD-debt | Per-token SSE quota design | (SDD-007) |

---

## Summary

The Phase 2 closure cycle introduced the TCP-follow client (F-2027-010)
with safe defaults: reqwest restricts the scheme to http/https by design,
so no scheme-validation gap exists. The SSE subscriber cap (F-2027-061)
correctly enforces a per-process limit, but the lack of a per-token quota
creates an authenticated DoS surface (F-2028-037) that should be addressed
via a design question (SDD-007). One nice UX finding (F-2028-038) improves
operator visibility into cap-reached errors.

The security closures from Phase 2 (token-file mode checks, eventstream
TOCTOU, SSE backpressure) are verified holding with no regressions. The
RBAC validator is well-scoped and well-tested.

**Immediate action:** F-2028-037 is important and should be designed
(SDD-007). F-2028-038 is a nice-to-have (deferred is acceptable).
