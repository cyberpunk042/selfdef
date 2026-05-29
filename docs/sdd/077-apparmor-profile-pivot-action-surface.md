# SDD-077 — AppArmor live profile-pivot action surface (selfdef enforcement layer)

**Status:** draft / architectural spec
**Author:** selfdef IPS authority chain
**Stems from:** IPS duodectet (SDD-065..076) → tridectet expansion.
The duodectet covers network perimeter + single-process boundary +
shell session + API/web token + MFA grant + kernel-namespace
containment + filesystem-binding + process-graph + per-connection
severance + in-memory secret-residency + per-process privilege
set + kernel-keyring eviction. SDD-077 adds the **MAC (Mandatory
Access Control) policy axis** — pivot a running process from its
current AppArmor profile (or `unconfined`) into a stricter
"selfdef-quarantine" profile via the kernel's live
profile-change mechanism, without killing the process.
**Pairs with:** SDD-075 (POSIX caps) at the privilege-axis
family. SDD-075 drops kernel capabilities; SDD-077 narrows the
MAC profile that gates path/network/cap usage. Together they
form a two-layer privilege/policy containment: caps decide
"what kernel ops the process may invoke at all", AppArmor
decides "which paths/sockets/caps the process may exercise
within that allowed set". SDD-077 is the policy-narrowing
companion to SDD-075's privilege-narrowing.

## Purpose

The duodectet's missing thirteenth axis: **live MAC policy
narrowing**. Existing primitives don't cover the AppArmor
profile layer:

- SDD-066 quarantine (single-pid freeze) is process-state
  containment (stop the process), not policy narrowing of a
  still-running process.
- SDD-070 netns-isolation puts the process in a network
  namespace; orthogonal to MAC, doesn't restrict path access.
- SDD-071 mount-binding-unbind detaches mount points but
  doesn't change what paths the process *may attempt*.
- SDD-075 capability-drops removes POSIX caps; AppArmor profile
  rules can still narrow further (e.g., a process retaining
  `CAP_NET_BIND_SERVICE` can be forbidden by AppArmor from
  `bind()` on specific ports).

SDD-077 fills the gap: target a running pid + the name of a
pre-loaded AppArmor profile (e.g., `selfdef-quarantine-strict`),
write `changeprofile <profile>\n` to `/proc/<pid>/attr/current`,
and the kernel atomically pivots the process into the new MAC
profile. All subsequent syscalls are evaluated against the new
profile's rules. The pivot is one-way at the kernel level —
the process cannot un-pivot itself without the new profile
permitting `aa_change_profile()`; the operator-restore action
is documented as queue-clear + audit only (operator must
restart the process under the original profile via init system
to recover).

Operator decides per incident:

- Attacker exploited a path-traversal in a daemon → SDD-077
  pivot into `selfdef-quarantine-strict` (no `/etc` writes, no
  arbitrary `bind()`, no `ptrace`)
- Attacker dropped a malicious dynamic library into the
  process's load path → SDD-077 pivot + SDD-074 env-scrub
  (clear `LD_PRELOAD` etc.) + SDD-066 freeze (stop forks)
- Suspicious process is still nominally trusted but needs
  containment for forensic capture → SDD-077 pivot into
  `selfdef-observe-only` (read-only filesystem view, no
  egress sockets) while the operator triages

## Non-goals

- Not a profile authoring tool. The pivot target must be a
  pre-loaded profile name; the profile itself is authored
  out-of-band (`/etc/apparmor.d/`) and loaded via
  `apparmor_parser` at provisioning time.
- Not a profile loader/unloader. SDD-077 pivots between
  already-loaded profiles; loading new profiles is admin-time
  work and not part of the live-enforcement action surface.
- Not for SELinux hosts. SDD-077 is specifically AppArmor
  (`/sys/kernel/security/apparmor/` present). SELinux uses
  different mechanisms (`setexeccon`) and is out of scope —
  the AppArmor-vs-SELinux split is detected at start-up and
  selfdef raises a clear error if SDD-077 is invoked on a
  SELinux host.
- Not for kernel threads or pid 1 — sacrosanct (same as
  SDD-072 / SDD-074 / SDD-075 / SDD-076).
- Not for profiles with `aa_change_profile` denied. If the
  current profile of the target pid denies `change_profile ->
  <new-profile>`, the pivot fails with `EACCES`; selfdef
  reports the constraint and the operator must either pre-load
  a profile that permits the pivot or use a different
  enforcement primitive.

## Surface

### 1. CLI verbs

```
selfdefctl pivot-profile <pid> --to <profile-name> --reason <text>
                                [--duration <human>]    # default 30m; max 4h
                                [--authority <tier>]
                                [--scope <hat|profile>] # default profile
                                [--dry-run]

selfdefctl restore-profile <handle> [--force]
```

`<profile-name>` is the AppArmor profile to pivot into (e.g.,
`selfdef-quarantine-strict`, `selfdef-observe-only`). Must be
present in the kernel-loaded profile set (verified by reading
`/sys/kernel/security/apparmor/profiles`).

`--scope hat` performs a hat-change (`changehat`) within the
current profile rather than a full profile change; useful for
profiles authored with sub-hats for graduated containment.

`restore-profile` does NOT re-pivot the process to its
original profile (impossible — the kernel does not retain
the pre-pivot profile reference and the new profile may forbid
`change_profile`). Clears the operator queue + audit record.
The process must be restarted under its original profile by
the init system to recover.

### 2. Library — `selfdef-responder::ApparmorProfilePivotAction`

Action type appended to the responder enum:

```rust
pub struct ApparmorProfilePivotAction {
    pub pid: u32,
    pub target_profile: String,
    pub scope: PivotScope,
    pub authority: AuthorityTier,
    pub reason: String,
    pub max_duration: Duration,
}

pub enum PivotScope {
    Profile,  // full aa_change_profile()
    Hat,      // aa_change_hat() within current profile
}
```

Stable name: `apparmor.profile_pivot`.

### 3. Backend — `selfdef-apparmor-profile-pivot-backend`

Trait `ApparmorProfilePivotBackend`:

```rust
async fn pivot(&self, req: PivotRequest) -> Result<PivotHandle>;
async fn restore(&self, handle: PivotHandle) -> Result<RestoreOutcome>;
async fn list_active(&self) -> Result<Vec<PivotHandle>>;
```

`PivotHandle` variants:

- `Active { pid, target_profile, scope, original_profile, expires_at }`
- `Stale { pid, target_profile, scope, original_profile, observed_dead_at }`
- `NoTarget { pid, attempted_profile, reason }` — profile
  not loaded in kernel
- `Denied { pid, attempted_profile, current_profile, reason }`
  — current profile forbids the pivot

Production impl `LiveBackend`:

- Verifies `/sys/kernel/security/apparmor/` mounted (errors
  with `EnforcementOffline` otherwise).
- Verifies `<target-profile>` in
  `/sys/kernel/security/apparmor/profiles` (returns `NoTarget`
  if absent).
- Reads `/proc/<pid>/attr/current` to capture
  `original_profile` for audit.
- Writes `"changeprofile <profile>\n"` (or
  `"changehat <hat>\n"` for `Hat` scope) to
  `/proc/<pid>/attr/current` via opened-as-writer fd (NOT
  via `echo >` to avoid shell escapability + idempotency
  races).
- Reports `EACCES` from kernel as `Denied` variant (current
  profile lacks `change_profile -> <new>` permission).
- Reports `ESRCH` from kernel as `Stale` (process died
  between observation and pivot).

In-memory mock `InMemoryBackend` for tests + MS5a fs-journaled
`FsBackend` paralleling SDD-076 (atomic
`<name>.tmp.<pid>.<nanos>` writes + `rename(2)`,
`active.json` + `pending-restores.json` under
`/var/lib/selfdef/apparmor-profile-pivots/`).

### 4. State-journal (MS5a)

Same separation-of-concerns pattern as SDD-068..076 (see
[ms5a-state-journal-vs-enforcement-layer-separation]
pattern doc): the FsBackend persists handles + pending
restore decisions; the LiveBackend performs the
`aa_change_profile()` syscalls; the cockpit reads the
pending queue and surfaces the irreversibility caveat.

### 5. Observer (MS4a — 31st sibling, OnBootSec=930s)

`packaging/scripts/selfdef-apparmor-profile-pivots-textfile.sh`
emits:

```
selfdef_apparmor_profile_pivots_state_dir_present       (gauge)
selfdef_apparmor_profile_pivots_active_count            (gauge)
selfdef_apparmor_profile_pivots_denied_count            (gauge)
selfdef_apparmor_profile_pivots_no_target_count         (gauge)
selfdef_apparmor_profile_pivots_by_target_profile{profile="..."} (labeled)
selfdef_apparmor_profile_pivots_by_scope{scope="profile|hat"}    (labeled)
selfdef_apparmor_profile_pivots_pending_restores        (gauge)
selfdef_apparmor_profile_pivots_oldest_expiry_unix      (gauge)
selfdef_apparmor_profile_pivots_last_run_unix           (gauge)
selfdef_apparmor_profile_pivots_textfile_emit_failed    (sentinel 0/1)
```

R171 12-clause hardening on the .service unit;
OnBootSec=930s on the .timer (distinct from 30 prior
siblings 60s..900s).

### 6. Consumer (sovereign-os MS4b + MS5b — vertical 31,
dashboard #51, cockpit card 38)

- `config/prometheus/alerts/selfdef-apparmor-profile-pivots.rules.yml`
  with 6 rules (TextfileEmitFailed/ObserverSilent/StateDirMissing
  critical; PendingBacklog/DeniedHigh/QuarantineStrictHigh
  warnings).
- `docs/observability/dashboards/sovereign-os-selfdef-apparmor-profile-pivots.json`
  with 8 panels matching the duodectet siblings.
- `scripts/cockpit/apparmor-profile-pivots-queue.py` 13th
  paired-decision queue surfacing the
  "profile pivot is one-way at kernel level" caveat.
- `scripts/dashboard/serve.py` card 38 registration.
- `scripts/diagnostics/observability-status.py` probe_*
  vertical 31, VERTICALS tuple → 31, header "31 verticals".
- `docs/observability/dashboards/sovereign-os-ips-host-overview.json`
  duodectet → tridectet rollup (12 → 13 in PromQL unions,
  max thresholds 12 → 13, per-primitive timeseries +1).

## Authority tiers

| Tier | max_duration | Permitted profile targets |
|---|---|---|
| Autonomous | 5m | Only `selfdef-observe-only` (read-only, no egress) |
| Responder | 30m | `selfdef-observe-only`, `selfdef-quarantine-strict` |
| Operator | 4h | All loaded profiles except `unconfined` |
| OperatorOverridden | 24h | All loaded profiles, including `unconfined` (un-pivot) |

The `OperatorOverridden` tier is the only path that can pivot
INTO `unconfined` (effectively a controlled un-confining of a
strictly-profiled process — rare; reserved for forensic-capture
workflows where the original strictness is interfering).

## Locked contracts (C-1..C-5)

- **C-1:** Pivot is one-way at the kernel level. Restore
  endpoint clears queue + audit only; it does NOT re-pivot.
- **C-2:** Pivot must verify target profile is in the
  kernel-loaded set BEFORE writing to `/proc/<pid>/attr/current`
  (else returns `NoTarget`, no syscall attempted, audit records
  the attempt + the missing profile).
- **C-3:** Pid 1 (init), kernel threads (pid in `/proc/<pid>/`
  with empty `cmdline`), and the selfdefd pid itself are
  sacrosanct — pivot returns `EnforcementRefused` without
  attempting the syscall.
- **C-4:** Idempotency key shape:
  `apparmor_profile_pivot:{pid}:{target_profile}:{scope:?}:{event_id}:{tier:?}`
  — repeated requests with the same key are coalesced
  into one handle.
- **C-5:** Honest-offline: if `/sys/kernel/security/apparmor/`
  is not mounted, the observer emits `state_dir_present=0`
  AND the LiveBackend returns `EnforcementOffline` for all
  pivot attempts (no syscall, audit records the refusal).

## Decisions (D-1..D-13)

- **D-1:** Use `/proc/<pid>/attr/current` write (the documented
  AppArmor user-space interface), not the lower-level
  `aa_change_profile()` libapparmor call — keeps the dep
  surface minimal (no `libapparmor` link) and matches the
  pattern of the kernel docs.
- **D-2:** Open the attr file as a fresh fd per pivot (don't
  cache fds across pids) — `/proc/<pid>/attr/current` is
  per-task; caching would race against task exit.
- **D-3:** Read original profile BEFORE pivot (for audit), even
  though restore can't use it — operator forensics need to know
  what the process was confined as before.
- **D-4:** `Hat` scope uses `changehat <hat>\n` not
  `changeprofile <hat>\n` — kernel rejects the wrong verb.
- **D-5:** Profile names are validated against
  `^[a-zA-Z0-9_./-]{1,256}$` before writing — prevents
  injection of `\n` or other control chars into the write
  payload (kernel would reject but we want to fail fast).
- **D-6:** `EACCES` from the kernel maps to `Denied` variant
  (not `Error`) — it's an expected outcome when the current
  profile lacks the necessary `change_profile` permission;
  audit, don't error.
- **D-7:** `ESRCH` maps to `Stale` (matches SDD-072 / SDD-073
  / SDD-075 stale-handle conventions).
- **D-8:** Profile breakdown (`by_target_profile` labeled
  gauge) is bounded by the kernel-loaded profile set;
  cardinality is operator-controlled (typically <20 profiles
  on a hardened host).
- **D-9:** Scope breakdown (`by_scope`) is binary
  (profile|hat) — fixed cardinality.
- **D-10:** Pivots into `unconfined` require the
  `OperatorOverridden` tier (D-1 implies one-wayness, so
  un-confining a process is a serious operator decision).
- **D-11:** `--dry-run` reads
  `/sys/kernel/security/apparmor/profiles` + verifies target
  is loaded + reads current profile, but does NOT write to
  `/proc/<pid>/attr/current` (returns the would-be transition
  + the audit record).
- **D-12:** No fallback to SELinux. On a SELinux host, SDD-077
  fails-closed with `WrongMacBackend` — operator must use a
  different primitive (none yet for SELinux; future SDD-078
  could fill the SELinux-side).
- **D-13:** Pending-restores queue includes a
  `requires_process_restart: true` field by default — the
  cockpit + operator-facing CLI surface this prominently so
  the operator doesn't expect a one-step restore.

## Cross-repo bridge

`selfdef-cli-mirror` exports the new CLI verbs as typed mirror
stubs for sovereign-os to consume without depending on
selfdef-cli directly. Same pattern as SDD-068..076.

## End-to-end milestone slots

- **MS1** — `selfdef-apparmor-profile-pivot-backend` crate
  (trait + InMemoryBackend + contract tests)
- **MS2** — `ApparmorProfilePivotAction` in selfdef-responder
- **MS3** — `selfdefctl pivot-profile` / `restore-profile`
  CLI verbs
- **MS5a-enforcement** — `LiveBackend` impl (real
  `/proc/<pid>/attr/current` writes)
- **MS5a-state-journal** — `FsBackend` adapter (active.json +
  pending-restores.json under
  `/var/lib/selfdef/apparmor-profile-pivots/`)
- **MS4a** — packaging textfile observer (31st sibling)
- **MS4b** — sovereign-os alerts file + dashboard #51 +
  observability-status vertical 31 + IPS-host-overview
  tridectet extension
- **MS5b** — sovereign-os cockpit queue + serve.py card 38

We do not minimize anything.
