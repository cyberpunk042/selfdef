# SDD-059 — Auditd collector record-type catalog + dispatch doctrine

> Status: **implemented** — Stage-1 doctrine + Stage-2 dispatch table
> ratified post-implementation. Shipped 2026-05-21 across commits
> 5a421c0 (AVC) + 061c7c8 (SECCOMP + ANOM_ABEND + ANOM_PROMISCUOUS),
> growing the auditd collector from the M3 baseline (3 USER_* auth
> types) to 7 first-class record types (USER_AUTH / USER_LOGIN /
> USER_ACCT / AVC / SECCOMP / ANOM_ABEND / ANOM_PROMISCUOUS) plus
> a back-compat fallback for every other type the kernel emits.
> All 12 parser tests pass.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestone: MS002 (catalog row "collector fabric");
> closes the MS002 evidence row from "auditd collector with AVC
> support" → "auditd collector with AVC + SECCOMP + ANOM_ABEND +
> ANOM_PROMISCUOUS support".
> Builds on: SDD-006 (shared module-script lib — not directly
> consumed but the dispatch-table pattern echoes it); MS002 entry
> in `backlog/milestones/INDEX.md`.

## Problem

`selfdef-collector-auditd` originally shipped (cycle-3 era) at M3
scope: a generic parser + 3 typed handlers (USER_AUTH, USER_LOGIN,
USER_ACCT) for password-auth events, plus a fallback that emits
unknown types as `ClassUid::new(0)` generic events with the raw
payload preserved. Every additional record type came at the cost
of:

1. ad-hoc severity / class / attack-tag choices invented per type
2. no documented place to look up what's-supported-when
3. no contract for the operator-facing message-string format
4. drift risk: the next person to add a type might choose a
   different severity scale or skip the attack tag

The auditd subsystem emits ~150 record types. We won't ship typed
handlers for all of them, but the 5-10 most security-relevant
types need first-class treatment so the correlator + responder +
notifier surfaces receive well-typed events.

## Catalog (as of 2026-05-21)

The dispatch table in `crates/selfdef-collector-auditd/src/lib.rs`
`build_event()` maps record kind → handler. Adding a type is:

1. Add a `match record.kind.as_str()` arm
2. Implement `fn build_<type>_event(...)` returning `Event`
3. Author a parser unit test using a real kernel-emitted line shape
4. Update this catalog table

| Audit kind | ClassUid | Activity | Severity (failure case) | Attack tag | Tactic |
|---|---|---|---|---|---|
| `USER_AUTH` | AUTHENTICATION | Logon | Medium (failed auth) / Informational (success) | T1110 Brute Force (on failure) | CredentialAccess |
| `USER_LOGIN` | AUTHENTICATION | Logon | Same as USER_AUTH | Same | Same |
| `USER_ACCT` | AUTHENTICATION | Logon | Same | Same | Same |
| `AVC` | PROCESS_ACTIVITY | Open | High (denied) / Informational (granted) | T1083 File and Directory Discovery | Discovery |
| `SECCOMP` | PROCESS_ACTIVITY | Other | High | T1562 Impair Defenses | DefenseEvasion |
| `ANOM_ABEND` | PROCESS_ACTIVITY | Terminate | Medium | (none — correlator adds context) | n/a |
| `ANOM_PROMISCUOUS` | PROCESS_ACTIVITY | Other | High | T1040 Network Sniffing | Discovery |
| _(everything else)_ | `0` (generic) | `0` | Informational | (none) | n/a |

## Contract

### C-1 — Severity ladder

Per-type severity at the event-emission layer follows a 4-level
ladder; the correlator + responder may further escalate based on
context (e.g. ABEND on a SUID binary, repeated SECCOMP from the
same comm).

| Level | Use | Examples |
|---|---|---|
| Informational | Successful authoritative action | USER_AUTH res=success, AVC granted |
| Medium | Operator-actionable but ambiguous | USER_AUTH res=failed, ANOM_ABEND |
| High | High-signal hostile-or-broken | AVC denied, SECCOMP trip, ANOM_PROMISCUOUS |
| Critical | RESERVED — not currently emitted by any auditd handler; the correlator can escalate to Critical based on multi-event patterns |

### C-2 — Attack tag policy

Each handler MAY tag the event with one MITRE ATT&CK TechniqueRef
when the kernel-emitted record itself is a clear technique signal.
DO NOT tag ambiguous events at this layer — let the correlator add
context-aware tags.

Concretely: AVC denied + SECCOMP trip + ANOM_PROMISCUOUS each tag
with a single technique because the record type IS the technique.
ANOM_ABEND does NOT tag because abnormal termination is too broad
without context.

### C-3 — Message-string format

Every typed handler emits a message string starting with the audit
kind (or the kind + decision for AVC) followed by `key=value` pairs
in record order. Operator-readable by tail -f.

Examples:
- `USER_AUTH: failed for alice (PAM:authentication)`
- `AVC denied: comm=sshd target=shadow tclass=file scontext=... tcontext=... permissive=0`
- `SECCOMP trip: pid=4242 comm=badapp exe=/usr/bin/badapp syscall=42 arch=c000003e sig=31 filter_code=0x0`
- `ANOM_ABEND: pid=4244 comm=crashy exe=/usr/bin/crashy sig=11`
- `ANOM_PROMISCUOUS: dev=eth0 old_prom=0 prom=256 auid=0`

The raw `record.fields` HashMap goes through `with_raw()` unchanged
so downstream consumers can re-derive any field.

### C-4 — Fallback contract

Unknown kinds MUST NOT be silently dropped. `build_other_event()`
emits `ClassUid::new(0)` + `SeverityId::Informational` + a message
`"auditd record: <KIND>"` + the raw payload. The correlator can
upgrade unknown records based on rules; the responder can ignore
them by default.

### C-5 — Multi-line records (shipped)

The kernel emits SYSCALL + EXECVE pairs across two lines correlated
by `msg=audit(<ts>:<serial>)`. Originally marked "explicitly out of
scope" in the first SDD-059 ratification; **shipped 2026-05-21**
with a single-slot buffer pattern instead of the full timeout-based
correlation map originally envisioned:

- `AuditdCollector::run()` carries a `pending_syscall:
  Option<(AuditRecord, String)>` local to its tokio task.
- On SYSCALL: flush any previously-pending SYSCALL as a lone
  generic event, then buffer the new SYSCALL.
- On EXECVE: if serial matches the pending SYSCALL, emit a
  combined `build_syscall_execve_event` event with the argv
  vector + executable path + exit code + raw payload of BOTH
  records. Status mapping: exit_code "0" → Success; "?" →
  Unknown; non-zero → Failure. Attack tag: T1059 Command and
  Scripting Interpreter (Tactic::Execution).
- On any other kind: flush pending then handle the new record
  normally.
- On shutdown: flush pending before returning.

The argv extraction lives in `parser::parse_execve_argv(record)`
— sorts the record's `aN` fields by numeric index (NOT
lexicographic — `a10` must come AFTER `a9`, not after `a1`).
4 new parser unit tests verify in-order extraction + gap
preservation + empty-on-non-EXECVE + double-digit-index sort.

Per the operator's standing "tractable + production" preference,
the single-slot buffer is sufficient: auditd kernel writes
contiguous record blocks per audit_log_msg() call so the SYSCALL
+ EXECVE for one exec() ARE adjacent in the log. The original
timeout-map design handled interleaved records from concurrent
audit_log_msg calls — a hypothetical edge case that hasn't
materialized in production traffic; deferred until a real
divergence is observed.

## Decisions

### D-1 — ClassUid: AUTHENTICATION for user-* / PROCESS_ACTIVITY otherwise

The OCSF schema is the cross-repo source of truth (per SDD-023
cross-repo model taxonomy mirror). USER_AUTH / USER_LOGIN / USER_ACCT
are unambiguously authentication events. The other 4 typed handlers
fire at process-level kernel hooks (LSM denials, seccomp filters,
abnormal terminations, promiscuous mode changes) so they all map
to PROCESS_ACTIVITY even when "Activity::Other" is the only fit.

**Tradeoff**: ANOM_PROMISCUOUS arguably belongs in NETWORK_ACTIVITY,
but the schema has no "interface mode change" activity variant. The
operator-readable message + raw payload preserves the network
context for downstream consumers.

### D-2 — Severity High on AVC denied, not Medium

The AVC subsystem is fail-closed by design — a denied event means
SELinux ALREADY blocked the action. The cost of overconservatively
flagging an authorized policy gap is operator-readable; the cost of
underflagging an exploit attempt is breach. Default High; let the
operator tune via configurable per-comm allowlist in a future SDD.

### D-3 — Severity High on SECCOMP, T1562 attack tag

SECCOMP filters are explicit operator-installed policy. A trip
means a program tried a syscall its filter forbids. Either the
program has a benign portability bug (Medium would be fine) OR
this is attempted defense-evasion / sandbox escape (High is
required). We can't distinguish; default High.

T1562 (Impair Defenses) is the canonical MITRE technique for
seccomp-evasion attempts. Tactic DefenseEvasion.

### D-4 — Severity Medium on ANOM_ABEND, no attack tag

Abnormal program termination is too broad to tag at this layer.
A SIGSEGV in a daemon could be a benign crash, an OOM kill, a
corrupted SUID binary, or successful exploit fallout. Severity
Medium so the correlator can route the event AND decide whether
to upgrade based on context (target is SUID? recent network
activity? unusual exe path?).

### D-5 — High on ANOM_PROMISCUOUS, T1040 attack tag

Network interface entering promiscuous mode is a high-signal event
even when the operator-initiated cause is legitimate (tcpdump for
debugging). The operator KNOWS they ran tcpdump; they want the
event in the audit trail anyway so unauthorized sniffer activation
is detectable. Severity High + T1040 Network Sniffing tag.

### D-6 — Raw payload always preserved via with_raw()

Every typed handler invokes `with_raw(record.fields)` so downstream
consumers can re-derive any field the typed event didn't carry.
The message string is convenience; the raw payload is the source
of truth.

## Test plan

12 unit tests in `crates/selfdef-collector-auditd/src/parser.rs::tests`
exercise the parser side:

- USER_AUTH failure (5 fields including PAM op nested)
- USER_LOGIN success (acct + res field extraction)
- Non-audit lines rejected (3 cases)
- Unknown record type still parses (ANOM_PROMISCUOUS structural)
- AVC denied with full field set (pid + comm + name + tclass +
  permissive + decision)
- AVC granted decision
- AVC decision missing returns None
- AVC partial-word non-match (`deniedfoo` ≠ `denied`)
- SECCOMP record fields (pid + comm + exe + syscall + arch + sig +
  code)
- ANOM_ABEND record fields (pid + comm + sig)
- ANOM_PROMISCUOUS record fields (dev + prom + old_prom)

The lib.rs event-emission side is type-checked by `cargo build` +
the dispatch arms — adding a new arm without implementing the
handler is a compile error. Integration tests at the
event-emission layer are deferred per the existing M3-era pattern
(tests would need a live Publisher mock).

## Migration

None. Existing handlers unchanged. New handlers add new arms to
the `match record.kind.as_str()` dispatch + new functions in
`lib.rs`. The fallback path stays the same.

## Risk + benefit

**Risk**: minimal. Each new handler is self-contained; the parser
+ fallback path are unchanged. Severity-tier choices documented
+ tradeoffs articulated.

**Benefit**: closes 4 high-signal kernel-emitted record types
end-to-end through the existing bus → store → correlator →
responder pipeline. The catalog table makes future additions
self-service for any operator reading this SDD.

## Out-of-scope (future SDDs)

- **Full timeout-based serial-keyed buffering** for the
  multi-line C-5 case (concurrent audit_log_msg calls
  producing interleaved records). The single-slot buffer
  shipped 2026-05-21 covers the contiguous-block reality;
  the timeout-map design is deferred until a real divergence
  is observed in production traffic.
- **Per-comm allowlist for AVC denied** (D-2). Operator config
  to skip known-benign denials (e.g. `dhclient` denied on
  /etc/resolv.conf write that's correctly rerouted).
- **Severity escalation rules** in the correlator (e.g. multiple
  SECCOMP trips from same pid in 1s → Critical). The correlator
  surface, not the collector.
- **Add more record types**: USER_CHAUTHTOK, USER_END, CRED_ACQ,
  CRYPTO_KEY_USER, CONFIG_CHANGE, MAC_POLICY_LOAD. Each is one
  build_*_event + 1 parser test; this catalog is the doctrine for
  doing so.

## Closure

MS002 catalog row "collector fabric" evidence updated from
"auditd collector with AVC support" → "auditd collector with AVC
+ SECCOMP + ANOM_ABEND + ANOM_PROMISCUOUS support". Doctrine for
ALL future auditd record-type additions now lives in this SDD.
