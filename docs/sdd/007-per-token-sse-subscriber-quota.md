# SDD-007 — Per-token SSE subscriber quota

> Status: design
> Owner: audit team
> Last updated: 2026-05-14
> Closes findings: F-2028-039 (SDD-debt parent), F-2028-037
> (important — implementation will close this when the design
> ships).

## Why now

Phase 2 closed F-2027-061 with a process-global subscriber
cap (`MAX_SSE_SUBSCRIBERS = 64`) implemented via an
`Arc<AtomicUsize>` + RAII `SubscriberGuard`. The Phase 3
security explorer (PR #91) raised **F-2028-037 (important)**:
the cap is process-global, but the bearer-token model treats
every token as equivalent. One bearer-holder who opens 64
concurrent `/events/stream` connections from a single process
saturates the cap and denies service to every other
authenticated client. Authenticated-only DoS, but real for
operators who hand out tokens with the same audience as their
read endpoints.

F-2028-039 is the design counterpart: scope the per-token
quota mechanism, then implement against it.

## Goals

1. **Bound abuse from a single token** — a token holder can
   exhaust at most a per-token slice of the global cap, not
   the whole cap.
2. **Preserve revocation timeliness** — when an operator
   rotates / revokes a token, every connection that was
   counting against that token's quota frees its slot
   *immediately*, not at next bus message.
3. **No regression in the legitimate single-operator case** —
   an operator with one rotated token running one `selfdefctl
   events follow --url` shouldn't hit the per-token cap.

## Design

### D-1 — Token identity

The cap counter needs to key on something that uniquely
identifies a token-holder. Options:

| Identity | Pros | Cons |
| --- | --- | --- |
| **Raw token bytes** | Trivial; what the wire carries. | Stores secrets in memory's hash table; revocation needs a token-list pull. |
| **Token fingerprint** (SHA-256 of the bytes) | Doesn't keep the secret in maps; fingerprint is a stable handle. | One extra hash per request. |
| **Token role / audience** | Allows per-audience quotas. | Doesn't address the "one role holder, many connections" abuse case. |
| **Source IP** | No token lookup. | Doesn't compose with token rotation; NAT collapses many holders into one. |

**Decision**: token fingerprint (SHA-256). Computed once per
request inside the bearer-auth middleware that already inspects
the token bytes. The fingerprint is a 32-byte handle stored in
`request.extensions()` so the `events_stream` handler reads it
without re-hashing.

### D-2 — Quota mechanism

`ApiState::sse_subscribers` becomes
`Arc<RwLock<HashMap<Fingerprint, AtomicUsize>>>` (or
`Arc<DashMap<Fingerprint, AtomicUsize>>` if we want
lock-free).

For each request:

1. Read the fingerprint from `request.extensions()`.
2. Acquire / create the per-fingerprint counter under a brief
   write lock.
3. CAS-increment the per-fingerprint counter against the
   per-token quota (`MAX_SSE_SUBSCRIBERS_PER_TOKEN`,
   default 8).
4. If the per-token counter is at quota → 503 with a typed
   reason "per-token sse cap reached"
   (distinguishable from the existing "sse subscriber cap
   reached" so operators can tell which limit they hit).
5. Otherwise, increment a **global** counter too — the
   process-wide cap stays in place as a backstop for the
   case where many tokens each fit under per-token but
   collectively exhaust process resources.

The `SubscriberGuard` decrements both counters on drop and
opportunistically removes the per-fingerprint entry from the
map when the per-token counter hits zero (so a rotating
operator doesn't leak HashMap entries).

### D-3 — Revocation interaction

When a token is rotated, the bearer-auth middleware starts
rejecting requests bearing the old token. Existing connections
under the old token are *not* terminated by the middleware —
they keep their `SubscriberGuard` alive and continue draining.

For F-2028-037's threat model, that's adequate: the abusive
token-holder loses the ability to open *new* connections at the
moment of rotation, and the existing ones drain through normal
client-disconnect / slow-client-timeout paths.

For a stricter model (revoke = terminate-all-existing), the
fingerprint map gains a `drained_at: Option<Instant>` and the
writer task checks it on every send. **Out of scope for D-2's
first cut.** Mark as D-3 "future hardening" and revisit only
if operator demand surfaces.

### D-4 — Config surface

`[api]` block in `selfdef.toml` gains two optional knobs (both
default to the constants below if unset):

```toml
[api]
# F-2028-037: per-token cap on concurrent /events/stream
# subscribers. Backstop for malicious / leaked tokens; the
# global cap below is a defence-in-depth backstop.
max_sse_subscribers_per_token = 8

# F-2027-061: global cap. Unchanged from prior behaviour;
# kept as a second-line defence for the case where many
# distinct tokens each fit under the per-token cap but
# the process can't hold them all.
max_sse_subscribers = 64
```

The new init-template (closes F-2027-059's cousin in this
cycle) ships these commented out at the defaults so operators
can tune by uncommenting.

### D-5 — Test coverage

New integration tests:

1. **Per-token cap reached** — open
   `MAX_SSE_SUBSCRIBERS_PER_TOKEN + 1` connections all bearing
   the same token; assert the last one gets 503 "per-token sse
   cap reached".
2. **Per-token cap is per-token** — open
   `MAX_SSE_SUBSCRIBERS_PER_TOKEN` connections with token A,
   then 1 with token B; assert B succeeds (A's cap doesn't
   affect B).
3. **Global cap still applies** — open enough connections
   across enough distinct tokens to hit `MAX_SSE_SUBSCRIBERS`
   without any single token hitting its per-token cap; assert
   the next request gets 503 "sse subscriber cap reached"
   (the existing global-cap message).
4. **Rotation frees slots eventually** — open the per-token
   cap, rotate the token, close the old connections, open one
   new connection with the new token, assert it succeeds.
5. **Per-token counter drops to zero** — open then close N
   connections; assert the HashMap is empty (no leak).

The existing `events_stream_rejects_over_cap_with_503` test
upgrades to also exercise the per-token path (or splits into
`global_cap` + `per_token_cap` test cases).

### D-6 — Status-code semantics

Both cap exhaustion modes return `503 Service Unavailable`.
The body distinguishes:

- `{"error": "sse subscriber cap reached"}` — global
  (`MAX_SSE_SUBSCRIBERS` exhausted; no single token to blame).
- `{"error": "per-token sse cap reached"}` — this token's
  per-token slice is full; rotate the abusive token or wait
  for connections to drain.

Both surface through the CLI's `events_follow_tcp` (F-2028-016
closure) via the same JSON-extraction path.

## Out of scope (deferred to future SDD)

- **Per-IP quota** — would need to coexist with the
  token-quota path. The audit didn't surface a use case
  (NATted operators would suffer).
- **Quota-exhaustion metric** — emit a Prometheus counter so
  operators can detect abusive tokens. Mentioned here for
  awareness; not blocking the implementation PR.
- **Token-issuer-time quota** — the daemon currently doesn't
  know which `audience` / `scope` a token was issued for;
  the bearer-auth middleware treats every token equivalently.
  Per-audience quotas would need the rotation tool to thread
  audience metadata through the token file, which is a
  separate redesign.

## Phasing

- **Phase A** — D-1 + D-2 + D-3 + D-4 implementation (single PR).
  Closes F-2028-037 and F-2028-039.
- **Phase B** — D-5 test coverage (paired with Phase A or
  immediate follow-up).
- **Phase C** — D-6 status-code semantics (already implicit in
  D-2 but called out as an explicit contract).

The phasing assumes one operator-time-bounded PR for the
implementation + one for tests; both can ship in the same
chunk if test-fixture work doesn't bloat the diff.

## Status

Design phase. Implementation lands in the SDD-007 closure PR,
which will close F-2028-037 + F-2028-039 + the SDD-007 entry
on the `implemented` status line.
