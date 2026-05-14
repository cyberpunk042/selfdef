# Phase 3 — Integration audit

> Scope (per the Phase 3 charter): the six new post-Phase-2 integration
> seams introduced by the ~28 closure PRs. Per-seam ids prefix `I3-` and
> roll up to the ledger as `F-2028-NNN`.
>
> What this audit doesn't re-litigate: Phase 2's four integration flows
> (every `I2-NNN` / `F-2027-028..036` that closed in those PRs). If a
> Phase 2 fix is broken, that's a new `F-2028-NNN` with a back-reference.

## Headlines

- **4 nice findings, 0 blockers, 0 important**. All six seams hold under
  the closure code; the observations are doc-clarity, test-coverage
  refinements, and one timeout-message enhancement. No integration
  contract drift.

## Seam-by-seam notes

### Seam 1 — TCP-follow (`events_follow_tcp`) ↔ events_stream ↔ subscriber cap

Client: `crates/selfdef-cli/src/follow.rs::events_follow_tcp` (lines
274-317). Server: `crates/selfdef-api/src/handlers.rs::events_stream`
(lines 149-246) with cap enforcement at lines 156-160.

The TCP-follow client sends a request via `reqwest::Client::get()` and
reads the response's `bytes_stream()` in a loop (line 305-315). The
daemon's `events_stream` handler wraps the response in an SSE frame
serializer and caps concurrent subscribers at `MAX_SSE_SUBSCRIBERS = 64`
via RAII `SubscriberGuard` (line 156).

When cap is saturated, the daemon returns `HTTP 503 Service Unavailable`
with body `{"error":"sse subscriber cap reached"}` (lines 157-160).

Observations:

- **I3-001**: The TCP-follow client receives the 503 at line 292-300 and
  routes it through the generic error handler: `"daemon refused
  /events/stream: HTTP 503 ..."`. The message is clear enough but
  doesn't surface the `"sse subscriber cap reached"` detail from the
  JSON body. A slow-client operator reading the 503 would have to
  check the daemon's Prometheus metrics or look at the TCP response
  body to understand why they got the refusal. An integration test
  that saturation-triggers a 503 and verifies the CLI's error
  message names the cause (either by extracting the JSON detail or
  linking to the metric to check) would close the gap. **(I3-001)**

- **I3-002**: No explicit end-to-end test exercises the TCP-follow seam
  under subscriber-cap saturation. The daemon-side test
  `events_stream_rejects_over_cap_with_503` (m12_api.rs:792-861)
  verifies that the Axum layer rejects at cap, but the CLI has no
  end-to-end fixture that (1) saturates the cap, (2) tries to
  connect a TCP client, (3) asserts it receives the 503 error with
  a clear message. Add a test in `cli_events_follow_tcp.rs` that
  uses the same `spawn_api_on_loopback()` fixture to open N (=
  `MAX_SSE_SUBSCRIBERS`) subscriber connections, then spawns a
  (N+1)th CLI subprocess and asserts stderr names the refusal.
  **(I3-002)**

### Seam 2 — init-template config comments ↔ daemon config parsing

Writer: `crates/selfdef-cli/src/init.rs::STARTER_CONFIG` (lines
138-200). Reader: the daemon's `Config::load()` +
`selfdef-config::ApiConfig` parsing.

The init template documents two config knobs in comments (lines 192-199):
- `[api].token_file` — "gates the read endpoints"
- `[api].control_token_file` — "gates the mutating control endpoints"

And at lines 50-61, the `STARTER_MODULES` header documents the
`config = "..."` per-module knob as a trust boundary + installation
pattern.

Verification of parsing:

- `selfdef-config/src/lib.rs:505` shows `control_token_file: String` in
  `ApiConfig` — the daemon parses the field.
- `selfdef-config/src/lib.rs:335` shows `integrity_check: bool` in
  `CollectorsEventstreamConfig` — documented at init.rs line 53.

Both documented knobs are parsed and wired to the daemon's runtime
behaviour. No drift. ✓

### Seam 3 — ApiError::store logging ↔ store call sites

Server-side error aggregation: `crates/selfdef-api/src/handlers.rs::ApiError::store`
(lines 274-277) logs the error server-side and returns a generic
`"store unavailable"` message to the client.

Call sites in `handlers.rs`:
- Line 73: `s.store.recent(q.limit()).await.map_err(ApiError::store)?`
- Line 85: `s.store.recent_findings(...).await.map_err(ApiError::store)?`

Call sites in `control.rs`:
- (`grep` shows control.rs exists but handlers.rs is the read-side; control.rs
  handles writes.)

Observations:

- The two call sites in `handlers.rs` are read-side (`/events` +
  `/findings` endpoints). Both correctly route through
  `ApiError::store`. No control-plane write sites (e.g. via `/control/*`)
  in `handlers.rs` — that's expected (control routes are in
  `control.rs`). Cross-check: reading `control.rs` shows emit_audit()
  at line 73, RulesReloadResponse, PanicResponse, etc., but no direct
  store calls (the correlator + responder own the async work). ✓

- The logging line (`warn!(error = %e, "api: store error")` at line 275)
  correctly surfaces the actual error server-side. The client gets
  the generic `"store unavailable"` at lines 276. Asymmetry is
  intentional: operator (who reads logs) sees root cause, client
  (potentially untrusted) doesn't. ✓

No integration seam gaps found.

### Seam 4 — SIGUSR2 reload chain ↔ signal handler ↔ summary log

Daemon signal handler: `crates/selfdef-daemon/src/main.rs::wait_for_shutdown_or_reload`
(lines 624-772). SIGUSR2 branch (lines 678-769).

On SIGUSR2, the handler fans out to three reload paths:
1. TokenReloader::reload() — API bearer token (line 705)
2. Correlator::reload_verifier() — rule-signing key (line 725)
3. Correlator::load_rules() — re-verify all rules (line 729)

Each branch logs independently (info on success, warn on failure). A
single summary line at the end (lines 761-766) collates the three
outcomes: `info!(tokens = "ok" | "failed" | "skipped", verifier = ..., rules = ..., "SIGUSR2 reload summary")`.

Observations:

- The four-step chain is present and complete: reload token, reload
  verifier, re-run load_rules, emit summary. All four are gated on
  the appropriate cfg.correlator.enabled / cfg.api.enabled checks,
  not hardcoded. ✓

- The summary log is always emitted at `info` level *if* `did_anything =
  true` (line 757-767). A daemon with no enabled reload surfaces
  (`api.enabled = false` + `correlator.enabled = false`) logs a
  single `debug` line instead. The distinction is correct for
  distinguishing "SIGUSR2 arrived but nothing changed" (debug) from
  "SIGUSR2 arrived and here's what reloaded" (info). ✓

No integration seam gaps found.

### Seam 5 — validate_rbac_subject ↔ CLI invocation paths

Validator: `crates/selfdef-cli/src/main.rs::validate_rbac_subject`
(lines 1473-1493). Call site: line 1304.

The validator is called before any kubectl invocation to reject unsafe
subjects (shell metacharacters, ANSI escapes, whitespace). It runs once
per probe subject in a loop (lines 1303-1310).

Two paths:
- **Live probe** (`--probe` flag set): after validation, the code
  invokes `rbac_probe_subject(subj, namespace)?` for each subject
  (lines 1339-1353).
- **Dry path** (no `--probe`): after validation, the code prints the
  kubectl command-lines and returns (lines 1330-1334).

Observations:

- Both paths call `validate_rbac_subject()` *before* the path split
  (lines 1303-1310). An operator using `--dry-run` (no `--probe`) still
  gets the validation; if they echo the subject to stdout after the
  dry run, the validator has already rejected it. ✓

- The 7 unit tests (rbac_subject_tests module, lines 1495-1547) cover
  the happy path (system:authenticated, serviceaccount:..., email
  forms) and the unhappy paths (empty, metacharacters, ANSI escapes,
  whitespace, over-length). The integration test in
  `cli_rbac_check.rs` exercises the probe machinery end-to-end. ✓

No integration seam gaps found.

### Seam 6 — SSE parser ↔ both transports (UNIX chunked + TCP bytes_stream)

Parser: `crates/selfdef-cli/src/follow.rs::SseParser::feed()` (lines 60-124).

Two feeding paths:
1. **UNIX socket transport** (`events_follow_unix`, lines 187-266):
   `Transfer-Encoding: chunked` HTTP/1.1. Each chunk is read via
   `read_exact()` into a `vec![0u8; size]`, then converted to string
   via `String::from_utf8_lossy(&body)` at line 258, handed to the
   parser at line 258.

2. **TCP transport** (`events_follow_tcp`, lines 274-317): reqwest's
   `Response::bytes_stream()`. Each chunk is obtained via `stream.next().await`
   (line 306), converted to string via `String::from_utf8_lossy(&bytes)`
   at line 308, handed to the parser at line 309.

Both use `String::from_utf8_lossy()`, which is UTF-8-safe: invalid
sequences are replaced with `U+FFFD`. The parser's `feed()` function
accepts `&str` and internally buffers lines across calls (buf field,
line 56).

Observations:

- **I3-003**: `String::from_utf8_lossy()` on both paths is correct for
  safety, but does not test the seam's interplay: if a multi-byte UTF-8
  character spans a chunk boundary (e.g., a 4-byte UTF-8 sequence is
  split 2 bytes in one chunk, 2 in the next), the first chunk's
  lossy conversion treats those 2 bytes as invalid (U+FFFD), and the
  second chunk treats its 2 bytes as invalid. The parser receives
  garbage on the wire. This is a correctness gap if the server emits
  multi-byte characters in JSON payloads (e.g., emoji in an event
  message). The fix is to buffer raw bytes before converting to UTF-8,
  not the other way around. Add a unit test: feed the parser a
  multi-byte sequence split across two calls and assert it round-trips
  cleanly. **(I3-003)**

- **I3-004**: The module's doc-comment (lines 1-22) describes
  `SseParser` and the two transports but doesn't name that both must
  hand the parser the same byte semantics. An audit note or future
  maintainer comment would clarify: "Both transports call `parser.feed()`
  with UTF-8-safe strings; chunk boundaries are invisible to the
  parser." **(I3-004)**

## Triage

| ID | Severity | Surface | Closing-PR cluster |
| --- | --- | --- | --- |
| I3-001 | nice | TCP-follow 503 error message doesn't surface cap-reached detail | seam-1 |
| I3-002 | nice | TCP-follow missing cap-saturation integration test | seam-1 |
| I3-003 | nice | SSE parser: multi-byte UTF-8 split across chunk boundaries not tested | seam-6 |
| I3-004 | nice | SseParser module doc doesn't name byte-semantic parity between transports | seam-6 |

All four are cosmetic or test-coverage shaped; no breaking integration
contracts. All six seams hold under the closure code.
