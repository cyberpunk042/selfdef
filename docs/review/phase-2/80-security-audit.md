# Phase 2 — Security audit

> Scope (per the Phase 2 charter): new attack surfaces added
> during the post-Phase-1 cycle. Per-area ids prefix `S2-`
> and roll up to the ledger as `F-2027-NNN`.
>
> Last of the seven Phase 2 explorers. What this audit doesn't
> re-litigate: Phase 1's security audit (every `F-2026-NNN`
> security finding closed during the previous cycle) and the
> two Phase 2 closures that hardened the post-Phase-1 surface
> (F-2027-014 `with_full_capability` feature-gate, F-2027-035
> eventstream TOCTOU/symlink). Both are verified holding in the
> appendix.

## Headlines

- **No blockers, no important findings.** Every new attack
  surface Phase 2 introduced (`/events/stream`, init config
  templates, `rbac check --probe`) has either explicit
  defense (bearer-token middleware on TCP, `safe_name`
  validators in shell scripts) or is gated behind opt-in
  config (TCP transport, integrity_check, etc.). The two
  high-impact Phase 2 closures verified by re-audit.
- **8 nice findings** clustered into four themes:
  - **Init-template hygiene** — three doc gaps where the
    starter `selfdef.toml` / `modules.toml` doesn't warn an
    operator about a known footgun (eventstream
    integrity_check pairing, module-config file mode,
    control_token_file knob).
  - **Defense-in-depth input validation** — `rbac check
    --probe` passes operator-supplied `--as <subject>`
    strings to `kubectl` via `Command::new` (safe by
    construction — no shell), but the strings aren't
    validated against a safe-charset regex before going to
    kubectl or being echoed back through error paths.
  - **SSE backpressure / DoS** — `/events/stream` lacks
    per-client connection caps and slow-client inactivity
    timeouts. Authenticated TCP DoS only, but the TCP
    transport is the opt-in operator-facing surface where
    this matters.
  - **Information disclosure surface** — `ApiError::store`
    flattens store errors verbatim into the JSON response;
    a future store error message that names an internal
    path would leak it.

## Per-area observations

### Area 1 — Init config templates (`crates/selfdef-cli/src/init.rs`)

- `init.rs:203-209` STARTER_CONFIG `[collectors.eventstream]`
  block tells operators to flip `integrity_check = true` and
  set the dir to 0750, but doesn't explicitly mention the
  symlink + TOCTOU attack vectors that F-2027-035 closed.
  Operators who enable the collector without reading
  SECURITY.md may not realise that pointing `paths` at a
  symlinked location bypasses the integrity check entirely.
  Add a single-line comment naming the attack class.
  **(S2-001)**
- `init.rs:187-191` `[api]` section lists `token_file` but
  doesn't mention `control_token_file` (the read-vs-control
  token split). Operators who enable the API and then need
  control endpoints discover the second knob only by reading
  the full example. Asymmetric documentation. **(S2-002)**
- `init.rs:225-275` STARTER_MODULES module-config example
  paths (`config = "/etc/selfdef/modules/<slug>.toml"`)
  don't warn that the config file should be 0640
  `root:selfdef` — a config file at 0644 with TOML the
  daemon evaluates is a trust-boundary footgun. Add a
  one-line "see `chown root:selfdef && chmod 0640`" comment
  in the section's header. **(S2-003)**

### Area 2 — `rbac check --probe` input validation

- `crates/selfdef-cli/src/main.rs::rbac_probe_subject` passes
  the operator-supplied `--as <subject>` string directly to
  `kubectl` via `Command::new(...).args(...)`. Safe from
  shell injection (no shell), but the string isn't validated
  against a Kubernetes-safe-charset regex (e.g.
  `^[a-z0-9:._/@-]+$`). An operator passing
  `--as "system:masters$(whoami)"` or an ANSI-escape-laden
  string would have the literal bytes appear in kubectl's
  error output and the daemon's `error!` logs. Defense-in-
  depth: validate `--as` against a strict regex up front and
  refuse non-conforming subjects with a typed error. Not a
  command-injection vector (no shell); a log-pollution /
  log-confusion vector. **(S2-004)**

### Area 3 — SSE backpressure / DoS

- `crates/selfdef-api/src/handlers.rs::events_stream:99`
  opens a new bus subscriber + spawns a tokio task per
  request. No per-client connection cap, no per-IP rate
  limit. An authenticated TCP client (bearer-token holder)
  can open hundreds of concurrent `/events/stream`
  connections, each holding a 64-slot mpsc channel + a
  tokio task — exhausts memory + CPU under load. The TCP
  transport is opt-in, and bearer tokens are operator-
  provisioned, so "authenticated DoS" only; but operators
  exposing the TCP port via a reverse proxy without
  rate-limiting are exposed. **(S2-005)**
- `crates/selfdef-api/src/handlers.rs:127-130` SSE
  forwarder does `tx.send(frame).await` (line 129) — a
  client that opens the connection and stops reading
  causes the channel's 64-slot buffer to fill, after which
  the task blocks indefinitely on send. No per-client
  inactivity timeout. Same authenticated-DoS profile as
  S2-005. Combine with a `tokio::time::timeout` of, say,
  30s on each `tx.send().await`; on timeout drop the
  client. **(S2-006)**

### Area 4 — Information disclosure

- `crates/selfdef-api/src/handlers.rs::ApiError::store`
  (~line 182) formats arbitrary store errors via
  `format!("store: {e}")` and ships the result inside the
  JSON 500 response body. If a future store-error message
  includes a path (`sqlite: open
  /var/lib/selfdef/state.sqlite: permission denied`), that
  path leaks to the (authenticated) caller. The path is
  already discoverable from the daemon config so the leak
  is small, but best practice would be to log the detail
  server-side and return a generic `"store unavailable"`
  to clients. **(S2-007)**

### Area 5 — Test-fixture posture

- `crates/selfdef-cli/tests/cli_api_rotate_token.rs:64-70`
  the `rotate_token_writes_url_safe_token_at_0600` test
  asserts that stdout includes the generated token value
  (via `--print`). The test correctly validates the
  `--print` contract, but the token value lands in CI's
  job-log output. The tokens are ephemeral (tempfile-scoped,
  never used against a real daemon), so this is **very**
  low risk. Best practice would be to assert format
  (length + url-safe-base64 charset regex) rather than
  echoing the value. Skip until the test framework needs a
  separate change pass — too small to ship in isolation.
  **(S2-008)**

## Appendix — Re-audit of two Phase 2 closures

These were the security-tier closures from earlier Phase 2
explorers. Re-verified during this audit:

### F-2027-035 — eventstream TOCTOU + symlink (PR #67)

`crates/selfdef-collector-eventstream/src/lib.rs:201-215`'s
`open_with_integrity_check` opens with `O_NOFOLLOW |
O_NONBLOCK` (symlinks → `ELOOP` → typed `IntegritySymlink`),
fstats the returned FD (not a fresh path stat, so post-open
swap can't change what's validated), refuses non-regular
files via `is_file()`, drops the FD on refusal. The full
mitigation holds — no remaining gaps.

### F-2027-014 — `with_full_capability` feature-gate (PR #61)

`crates/selfdef-api/src/lib.rs:50-61` is `#[cfg(feature =
"test-helpers")]`. `cargo build --release -p selfdef-api`
produces no symbol for the function — verified at the time
of the PR. Downstream consumers without the feature can't
link to it. The integration tests' circular dev-dep
(`selfdef-api = { path = ".", features = ["test-helpers"] }`)
enables it for the test build only.

## Triage

| ID | Severity | Surface | Closing-PR cluster |
| --- | --- | --- | --- |
| S2-001 | nice | init STARTER_CONFIG eventstream block | init-template hygiene |
| S2-002 | nice | init STARTER_CONFIG control_token_file | init-template hygiene |
| S2-003 | nice | init STARTER_MODULES file-mode hint | init-template hygiene |
| S2-004 | nice | rbac check --as subject validator | rbac-input-validation |
| S2-005 | nice | SSE per-client connection cap | SSE-backpressure |
| S2-006 | nice | SSE slow-client inactivity timeout | SSE-backpressure |
| S2-007 | nice | ApiError::store path leak | info-disclosure |
| S2-008 | nice | cli_api_rotate_token test value-vs-format | (deferred) |

All 8 entries land in the Phase 2 findings ledger as
F-2027-057 through F-2027-064 with `nice` severity. Three
clean closing-PR clusters:

- **Init-template hygiene** — S2-001 + S2-002 + S2-003. One PR
  refreshing comments in `STARTER_CONFIG` + `STARTER_MODULES`.
- **rbac input validation** — S2-004. Single-file change in
  `selfdef-cli/src/main.rs`.
- **SSE backpressure** — S2-005 + S2-006. One PR in
  `selfdef-api/src/handlers.rs::events_stream` adds a
  global atomic subscriber counter + per-send `tokio::time::
  timeout`.

S2-007 + S2-008 are smaller and can fold in opportunistically.
