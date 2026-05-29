# SDD-078 — BPF map element clear action surface (selfdef enforcement layer)

**Status:** draft / architectural spec
**Author:** selfdef IPS authority chain
**Stems from:** IPS tridectet (SDD-065..077) → quattuordectet
expansion. The tridectet covers network perimeter + single-process
boundary + shell session + API/web token + MFA grant + kernel-
namespace containment + filesystem-binding + process-graph +
per-connection severance + in-memory secret-residency + per-process
privilege set + kernel-keyring eviction + MAC profile pivot.
SDD-078 adds the **eBPF map state axis** — clear / delete
specific elements (or entire maps) from kernel-side eBPF maps
that hold security-relevant state.
**Pairs with:** SDD-076 (kernel-keyring eviction) at the
kernel-state-eviction family. SDD-076 evicts cached
credentials via keyctl; SDD-078 evicts BPF map state via
the `bpf()` syscall. Different syscall surface, different
state-store semantics, different attacker-leverage models
(keyctl caches credentials; BPF maps cache policy + counters
+ allow-lists held by BPF programs).

## Purpose

The tridectet's missing fourteenth axis: **kernel-side BPF
map state eviction**. Existing primitives don't reach the
BPF map layer:

- SDD-076 keyctl-evict: kernel keyring credential cache.
  Doesn't touch BPF map state.
- SDD-070 netns-isolation: network namespace boundary. Doesn't
  reach the BPF programs/maps attached to network hooks.
- SDD-075 capability-drop: POSIX caps. Doesn't invalidate
  cached BPF policy state.
- SDD-067/068/069 token/session/MFA revoke: app-layer
  credential layers. Doesn't touch BPF-tracked grant maps.

Attacker scenarios SDD-078 closes:

- Attacker pinned a malicious entry into a BPF allow-list map
  (e.g. ip_allow_list, pid_allow_list) used by a BPF-LSM
  program → SDD-078 delete-elem
- BPF program counting per-pid syscall budget is poisoned
  (pid mapped to 0 budget left, so future syscalls fall
  through to default-allow) → SDD-078 delete-elem to reset
- A pinned BPF map at `/sys/fs/bpf/<name>` is suspected
  tampered with → SDD-078 clear-all (delete every element,
  preserving the map pin so the BPF program still works)

Operator decides per incident:

- Suspicious entry in known allow-list map → SDD-078 with
  `--key <hex>` (single-element delete)
- Suspected wholesale poisoning → SDD-078 with `--scope all`
  (iterate + delete every element)
- BPF map itself should be unloaded (program assumed
  compromised) → out-of-scope for SDD-078 (use `bpftool prog
  unload` operator-side or future SDD-079); SDD-078 only
  touches elements within a map, not the map itself

## Non-goals

- **Not a BPF program loader/unloader.** SDD-078 only touches
  map elements; loading/unloading BPF programs is admin-time
  work and not part of the live-enforcement action surface.
- **Not for kernel-internal BPF maps** (BPF iter, BPF stats,
  scheduler maps). Those are read-only or selfdef-side
  not-our-business. SDD-078 only targets maps in
  `/sys/fs/bpf/` or referenced by name + ID from
  `bpftool map list`.
- **Not for maps owned by pid 1.** Sacrosanct (same as
  SDD-072 / SDD-074 / SDD-075 / SDD-076 / SDD-077). If a
  BPF program loaded by pid 1 owns the map, SDD-078 refuses.
- **Not a `bpftool` replacement.** SDD-078 wraps a specific
  syscall surface (`BPF_MAP_DELETE_ELEM`,
  `BPF_MAP_GET_NEXT_KEY` for iteration). Operator-side
  arbitrary BPF debugging remains `bpftool`'s job.

## Surface

### 1. CLI verbs

```
selfdefctl clear-bpf-map <map-spec> --reason <text>
                          [--scope element|all]   # default element
                          [--key <hex>]            # required if scope=element
                          [--duration <human>]    # default 30m; max 4h
                          [--authority <tier>]
                          [--dry-run]

selfdefctl restore-bpf-map <handle> [--force]
```

`<map-spec>` is one of:

- **By pinned path:** `/sys/fs/bpf/<name>` (most stable
  reference; BPF map IDs change across kernel reboots)
- **By id:** `id:<u32>` (matches `bpftool map list` ID
  column; volatile across reboots)
- **By name:** `name:<map-name>` (matches the map's
  in-program name; ambiguous if multiple maps share the
  name — selfdef refuses with `AmbiguousName`)

`--key <hex>` is the map key encoded as hex bytes
(e.g. `0a000001` for IPv4 `10.0.0.1` in a key-size-4
ip_allow_list map). Key size must match the map's
`key_size` field (verified before syscall, returns
`KeySizeMismatch` if wrong).

`restore-bpf-map` does NOT re-add the cleared elements
(impossible — selfdef did not snapshot the prior values,
and even if it had, the BPF program may have evolved
its data shape). Clears the operator queue + audit record.
The owning BPF program will re-populate the map through
its normal control plane (operator must restart that plane
or wait for natural re-population).

### 2. Library — `selfdef-responder::BpfMapElementClearAction`

```rust
pub struct BpfMapElementClearAction {
    pub map_spec: String,
    pub scope: ClearScope,
    pub key_hex: Option<String>,
    pub authority: AuthorityTier,
    pub reason: String,
    pub max_duration: Duration,
}

pub enum ClearScope {
    Element,  // BPF_MAP_DELETE_ELEM for a single key
    All,      // iterate via BPF_MAP_GET_NEXT_KEY then DELETE
}
```

Stable name: `bpf_map_element_clear`.

### 3. Backend — `selfdef-bpf-map-element-clear-backend`

Trait `BpfMapElementClearBackend`:

```rust
async fn clear(&self, req: ClearRequest) -> Result<ClearReceipt>;
async fn restore(&self, handle: ClearHandle) -> Result<RestoreOutcome>;
async fn list_active(&self) -> Result<Vec<ClearHandle>>;
```

`ClearHandle` variants:

- `Active { map_spec, scope, elements_cleared, expires_at }`
- `MapNotFound { map_spec, reason }` — map_spec didn't
  resolve to a loaded BPF map
- `AmbiguousName { name, candidates }` — `name:<x>`
  resolved to >1 map
- `KeySizeMismatch { expected, got }` — `--key` byte length
  ≠ map's `key_size`
- `KeyNotFound { map_spec, key }` — element-scope clear
  but key wasn't in the map (race or stale spec; not an error,
  audit only)
- `BpfMapAccessDenied { map_spec, reason }` — kernel returned
  `EPERM` (map_flags forbid delete, or selfdef lacks
  `CAP_BPF`/`CAP_SYS_ADMIN`)

Production impl `LiveBackend`:

- Verifies `/sys/fs/bpf/` mounted (else
  `EnforcementOffline`)
- Resolves `<map-spec>` to (map_fd, key_size) via
  `bpf(BPF_OBJ_GET)` (pinned path) or
  `bpf(BPF_MAP_GET_FD_BY_ID)` (id) or `bpftool` JSON
  parsing (name) — same fallback chain `bpftool` itself
  uses internally
- Validates `--key` byte length matches `key_size` before
  attempting `BPF_MAP_DELETE_ELEM`
- For `--scope all`: iterates via
  `BPF_MAP_GET_NEXT_KEY` + `BPF_MAP_DELETE_ELEM` in a
  bounded loop (max 1M iterations to defeat pathological
  maps); reports `elements_cleared` count
- Reports `EPERM`/`EACCES` as `BpfMapAccessDenied`
  variant
- Reports `ENOENT` from `DELETE_ELEM` as `KeyNotFound`
  (audit-only, not an error)

In-memory mock `InMemoryBackend` for L1 tests + MS5a
fs-journaled `FsBackend` paralleling SDD-076/077 (atomic
`<name>.tmp.<pid>.<nanos>` writes + `rename(2)`,
`active.json` + `pending-restores.json` under
`/var/lib/selfdef/bpf-map-element-clears/`).

### 4. State-journal (MS5a)

Same separation-of-concerns pattern as SDD-068..077 (see
[ms5a-state-journal-vs-enforcement-layer-separation]
pattern doc, 13th application). The FsBackend persists
handles + pending restore decisions; the LiveBackend
performs the `bpf()` syscalls; the cockpit reads the
pending queue and surfaces the irreversibility caveat
("selfdef did not snapshot prior values; restore is
queue-clear + audit only").

### 5. Observer (MS4a — 32nd sibling, OnBootSec=960s)

`packaging/scripts/selfdef-bpf-map-element-clears-textfile.sh`
emits:

```
selfdef_bpf_map_element_clears_state_dir_present                  (gauge)
selfdef_bpf_map_element_clears_active_count                       (gauge)
selfdef_bpf_map_element_clears_map_not_found_count                (gauge)
selfdef_bpf_map_element_clears_ambiguous_name_count               (gauge)
selfdef_bpf_map_element_clears_access_denied_count                (gauge)
selfdef_bpf_map_element_clears_elements_cleared_total             (gauge)
selfdef_bpf_map_element_clears_by_scope{scope="element|all"}      (labeled)
selfdef_bpf_map_element_clears_by_map_name{map="..."}             (labeled)
selfdef_bpf_map_element_clears_pending_restores                   (gauge)
selfdef_bpf_map_element_clears_oldest_expiry_unix                 (gauge)
selfdef_bpf_map_element_clears_last_run_unix                      (gauge)
selfdef_bpf_map_element_clears_textfile_emit_failed               (sentinel 0/1)
```

R171 12-clause hardening on the .service unit;
OnBootSec=960s on the .timer (distinct from 31 prior
siblings 60s..930s).

### 6. Consumer (sovereign-os MS4b + MS5b — vertical 32,
dashboard #52, cockpit card 39)

- `config/prometheus/alerts/selfdef-bpf-map-element-clears.rules.yml`
  with 7 rules (TextfileEmitFailed/ObserverSilent/StateDirMissing
  critical; PendingBacklog/AccessDeniedHigh/ElementsClearedHigh/
  AmbiguousNameAny warnings — AmbiguousNameAny fires on any
  occurrence because it indicates rule-config error).
- `docs/observability/dashboards/sovereign-os-selfdef-bpf-map-element-clears.json`
  with 8 panels matching the tridectet siblings.
- `scripts/cockpit/bpf-map-element-clears-queue.py` 14th
  paired-decision queue surfacing the
  "selfdef did not snapshot prior values" caveat.
- `scripts/dashboard/serve.py` card 39 registration.
- `scripts/diagnostics/observability-status.py` probe_*
  vertical 32, VERTICALS tuple → 32, header "32 verticals".
- `docs/observability/dashboards/sovereign-os-ips-host-overview.json`
  tridectet → quattuordectet rollup (13 → 14 in PromQL unions,
  max thresholds 13 → 14, per-primitive timeseries +1).

## Authority tiers

| Tier | max_duration | Permitted scope |
|---|---|---|
| Autonomous | 2m | Element-scope only, `--key` required |
| Responder | 15m | Element-scope only, `--key` required |
| Operator | 1h | Element + All scope |
| OperatorOverridden | 4h | Element + All scope |

The All-scope (wipe every element) is restricted to Operator+
because it has the highest blast radius — wiping a BPF map
could effectively disable the BPF program that depends on it
(if the program treats empty-map as default-deny, traffic
breaks; if default-allow, security collapses). Tier matrix
forces operator awareness.

## Locked contracts (C-1..C-5)

- **C-1:** Clear is one-way. Restore endpoint clears queue +
  audit only; it does NOT re-add the prior elements.
- **C-2:** Element-scope clears must verify `--key` byte
  length matches the map's `key_size` BEFORE the syscall
  (returns `KeySizeMismatch`, no syscall attempted).
- **C-3:** Pid 1 / kernel threads / selfdefd sacrosanct —
  if the map is owned by a sacrosanct pid (verified via
  `bpf(BPF_MAP_GET_INFO_BY_FD)` `btf_owner_prog_id`), the
  clear is refused.
- **C-4:** Idempotency key shape:
  `bpf_map_element_clear:{map_spec}:{scope:?}:{key_hex:?}:{event_id}:{tier:?}`
  — repeated requests with the same key are coalesced.
- **C-5:** Honest-offline: if `/sys/fs/bpf/` is not mounted,
  observer emits `state_dir_present=0` AND LiveBackend
  returns `EnforcementOffline` for all clear attempts
  (no syscall, audit records the refusal).

## Decisions (D-1..D-13)

- **D-1:** Use raw `bpf()` syscall (libc::syscall(SYS_bpf,
  ...)) rather than depending on `libbpf-sys` to keep the
  dep surface minimal. Same philosophy as SDD-077 D-1.
- **D-2:** Three resolver paths (pinned path / id / name)
  match `bpftool map list`'s shorthand semantics, so
  operator muscle memory transfers.
- **D-3:** `--key` is hex-bytes (not e.g. decimal int) to
  handle arbitrary key sizes uniformly (BPF maps can have
  any `key_size`; some are 4B for IPv4, some 16B for
  IPv6, some 24B for 5-tuple).
- **D-4:** All-scope iteration bounded at 1M elements
  defeats pathological maps without preventing legitimate
  large-map clears.
- **D-5:** `ENOENT` on `DELETE_ELEM` maps to
  `KeyNotFound` variant (audit, not error) — same
  philosophy as SDD-076 `NotFound`.
- **D-6:** `EPERM`/`EACCES` from kernel map to
  `BpfMapAccessDenied` (expected outcome when map_flags
  set `BPF_F_RDONLY` or selfdef lacks the cap; audit).
- **D-7:** Ambiguous `name:<x>` resolution refuses
  (returns `AmbiguousName` with candidates list); operator
  must use id: or path: to disambiguate.
- **D-8:** by_map_name labeled gauge bounded by the loaded
  BPF map set (typically <50 maps on a hardened host);
  cardinality stays bounded.
- **D-9:** by_scope gauge is binary (element|all) — fixed
  cardinality.
- **D-10:** All-scope requires Operator+ tier (D-1 implies
  one-wayness, so wiping a whole map is a serious operator
  decision).
- **D-11:** `--dry-run` resolves map_spec + verifies key
  size + reads the map's current element count, but does
  NOT attempt `DELETE_ELEM` (returns the would-be transition).
- **D-12:** No snapshot before clear. The kernel BPF
  subsystem doesn't expose a transactional clear, and
  snapshotting + restoring large maps is operationally
  expensive — the design accepts one-wayness explicitly.
- **D-13:** Pending-restores queue includes a
  `requires_owning_program_repopulation: true` field by
  default — the cockpit surfaces this so the operator knows
  the owning BPF program's control plane must re-add elements.

## Cross-repo bridge

`selfdef-cli-mirror` exports the new CLI verbs as typed
mirror stubs for sovereign-os consumption. Same pattern as
SDD-068..077.

## End-to-end milestone slots

- **MS1** — `selfdef-bpf-map-element-clear-backend` crate
  (trait + InMemoryBackend + contract tests)
- **MS2** — `BpfMapElementClearAction` in selfdef-responder
- **MS3** — `selfdefctl clear-bpf-map` / `restore-bpf-map`
  CLI verbs
- **MS5a-enforcement** — `LiveBackend` impl (real
  `bpf()` syscalls via libc::syscall)
- **MS5a-state-journal** — `FsBackend` adapter (active.json
  + pending-restores.json under
  `/var/lib/selfdef/bpf-map-element-clears/`)
- **MS4a** — packaging textfile observer (32nd sibling)
- **MS4b** — sovereign-os alerts file + dashboard #52 +
  observability-status vertical 32 + IPS-host-overview
  quattuordectet extension
- **MS5b** — sovereign-os cockpit queue + serve.py card 39

We do not minimize anything.
