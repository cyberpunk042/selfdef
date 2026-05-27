# SDD-064 — Tool observed-discipline: quarantine archive + trust-score tracker (MS042)

> Status: **active** — extends SDD-050 (tool-authority declaration/authorization
> half) with the MS042 **observed/enforcement half**: the declaration-vs-observed
> comparator, the block+quarantine+trace mismatch response, the quarantine
> archive, and the per-tool trust-score tracker. Ships the two read-only
> schema-discovery surfaces (`/v1/quarantine`, `/v1/trust-scores`) that the IPS
> dashboard quarantine + trust-scores panels — and the sovereign-os D-17/D-18
> mirror dashboards (M060, via MS007 typed mirror) — consume.

**Source**: `backlog/milestones/MS042-tool-authority-declaration-vs-observed-discipline.md`
(dump `2026-05-18-...-AVX-plus-plus.md` lines 17422-17445) + SDD-050 (the
authorization half already implemented).

**Project boundary** (operator-sacrosanct): this is an **IPS feature** — it lives
in selfdef. Tool-execution semantics live in sovereign-os (M054 Tool typed
interface + M058 scheduler). selfdef is the **observed-behavior arbiter**;
sovereign-os only *mirrors* the quarantine archive + trust scores read-only via
the MS007 typed-mirror crate (per MS042 F05034 + F05027). No IPS enforcement
logic is authored in sovereign-os.

## Doctrine (verbatim from MS042)

> "If declaration and observed behavior differ, the runtime should flag it."
> (dump 17434-17435)
> "Example: declared: read-only / observed: opened socket / result: block +
> quarantine + trace" (dump 17437-17445)

Every tool call enters with a **7-field signed declaration** (E0421-E0427):

| # | field | what the caller declares | observed by |
|---|---|---|---|
| 1 | `read_paths` | filesystem paths it will read | fanotify (MS037) |
| 2 | `write_paths` | filesystem paths it will modify | fanotify (MS037) |
| 3 | `network_domains` | domains it will connect to | eBPF connect()/sendmsg() (MS024+MS038) |
| 4 | `environment_variables` | env vars it will read | ptrace+seccomp getenv() |
| 5 | `secret_access` | secrets it will touch | kernel keyring keyctl() |
| 6 | `expected_side_effects` | side-effect class | MS036 sandbox introspector |
| 7 | `rollback` | rollback availability | cross-ref MS041 commit authority |

The IPS **observes actual behavior** through 5 monitors (E0428, M01080-M01084):
fanotify · eBPF · ptrace/seccomp · kernel-keyring · MS036 sandbox introspector.
A **comparator** (E0429, M01085-M01087) diffs declared vs observed per field. On
mismatch, the **3-step response** (E0430, M01088-M01090, dump 17444):

1. **block** — `selfdef-tool-response-blocker` halts the tool mid-flight.
2. **quarantine** — `selfdef-tool-response-quarantiner` freezes the offending
   call + its artifacts into the quarantine archive (M01094).
3. **trace** — `selfdef-tool-response-tracer` emits the OCSF 2004 detection
   finding into the audit chain (cross-ref MS026 + MS009).

## Surface 1 — quarantine archive (`/v1/quarantine`, M01094)

Read-only schema-discovery of the quarantine-archive contract. The archive
(F05027-F05029) supports: operator **review** via dashboard, operator **restore**
on false-positive (MS003-signed CLI only), forensic **export**. Quarantine
records persist under `/var/lib/selfdef/tool-quarantine/`.

Quarantine record schema (per archive entry):
`quarantine_id` · `tool_id` · `declaration` (7-field) · `observed` (per-field) ·
`mismatch_field` · `mismatch_detail` · `response` (block/quarantine/trace) ·
`trace_id` (OCSF 2004 link) · `quarantined_at` · `status`
(quarantined / restored / exported / purged).

Mutation (restore / purge / export) is **CLI-only**, MS003-signed
(`selfdefctl tool-authority quarantine {review,restore,export}`) — the HTTP
surface is read-only per the sovereignty boundary (SDD-050 D-4 lineage).

## Surface 2 — trust-score tracker (`/v1/trust-scores`, M01095)

Read-only schema-discovery of the per-tool trust-score model (F05030-F05034):

- **accumulates** trust from declaration-fidelity over time (clean call → small
  credit; mismatch → larger debit).
- **decays** on mismatch history (a tool with recent mismatches loses trust
  faster than it regains it — asymmetric, per F05033).
- **persisted** under `/var/lib/selfdef/tool-trust/` (F05031).
- **factored** into MS040 profile evaluation (F05032) — low-trust tools face
  stricter gates in Careful/Production profiles.
- **exposed** via the MS007 typed mirror (F05034) for the sovereign-os D-18
  mirror dashboard.

Trust-score model: score ∈ [0.0, 1.0], 4 bands
(`trusted` ≥ 0.85 / `watched` 0.6-0.85 / `suspect` 0.3-0.6 / `quarantined` < 0.3),
seeded at `0.5` (neutral) for a newly-declared tool.

## Decisions locked

- D-064.1 — Both surfaces are **read-only schema-discovery** (static doctrine
  JSON), mirroring the SDD-050 D-2 `/v1/tool-authority` pattern. Live archive
  contents + live scores are served by the existing instrumented runtime, not
  invented here; this surface publishes the *contract*.
- D-064.2 — Mutation (restore/purge/export, score reset) is MS003-signed
  CLI-only. The HTTP + dashboard surfaces never mutate (MS043 R10212 lineage).
- D-064.3 — Trust-score decay is **asymmetric** (mismatch debits faster than
  clean-call credits) per F05033 — a deliberately conservative posture.
- D-064.4 — sovereign-os consumes both via the MS007 typed mirror ONLY
  (D-040.6/.8); no IPS logic crosses into sovereign-os.

## Surfaces (§1g 8-surface ladder)

| surface | artifact |
|---|---|
| core | the existing tool-* observed-monitor crates (M01080-M01095) |
| api | `crates/selfdef-api/src/quarantine.rs` + `trust_scores.rs` (this SDD) |
| cli | `selfdefctl tool-authority {quarantine,trust-scores}` (read) + signed mutations |
| dashboard | selfdef PWA `quarantine` + `trust-scores` panels |
| mirror | MS007 typed-mirror crate → sovereign-os D-17/D-18 |

## Open questions (Q-064)

- **Q-064.1** — Should the trust-score band thresholds (0.85/0.6/0.3) be
  operator-tunable per `/etc/selfdef/tool-trust-policy.toml`? Recommendation:
  yes, but ship fixed defaults first (this SDD), make tunable in a follow-up.
- **Q-064.2** — Quarantine retention: auto-purge after N days, or operator-only
  purge? Recommendation: operator-only purge + a forensic-export-before-purge
  guard (quarantine is evidence).
