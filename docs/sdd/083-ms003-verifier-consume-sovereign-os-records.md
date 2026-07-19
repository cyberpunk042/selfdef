# SDD-083 — MS003 verifier: consume + verify sovereign-os's ed25519 mutation records

**Status:** implemented (core) — operator chose **Option 1** (shell to system `openssl`, zero new crypto dependency; 2026-07-19). The verify core landed in `crates/selfdef-signing/src/ms003.rs`: envelope parse, `keyid`, `canonical_bytes` (recursive sorted-key form, robust to `preserve_order`), inline base64url, a selfdef-owned `TrustAnchors` store, and `verify_record` → the 5 `VerifyStatus` variants, all `openssl`-backed. 20 crate tests pass incl. a **cross-implementation golden** (a record signed by the real sovereign-os `scripts/lib/ms003.py` verifies here). **Remaining follow-up** (own increment): the `selfdefctl ms003 {anchor-add,anchor-list,verify,sweep}` surface + folding a ledger sweep into selfdef's audit/observability surface — that consumer wiring is what finally closes F-2026-034.
**Author:** selfdef IPS authority chain
**Closes:** the **selfdef half** of sovereign-os finding **F-2026-034** (MS003 commit-authority). sovereign-os chose **Option B** (it mints ed25519 locally; *selfdef verifies* — sovereign-os decision D-025, SDD-984) and shipped the producer + a *local* self-audit verifier (sovereign-os SDD-989 + SDD-990 + its 2026-07-17 trust-anchor store). F-2026-034 stays open until **selfdef** — the audit-chain authority — verifies those records too. This SDD scopes that verifier.
**Owner:** `crates/selfdef-signing` (today minisign detached-file, verify-only) + the store/audit-ledger consumer path.
**Last updated:** 2026-07-19.

## Problem

sovereign-os now stamps a **real ed25519 signature** into every durable mutation / decision record it authors (the writers swept in sovereign-os SDD-990). Per the operator-chosen model, sovereign-os is the **producer** and **selfdef is the verifier** — selfdef owns the authoritative audit chain, so a sovereign-os signature only becomes *trustworthy across the boundary* once selfdef checks it against the operator's public trust anchor.

Today selfdef **cannot** do that. `crates/selfdef-signing` is **minisign-only**: it verifies detached `.minisig` sidecars over rule/policy files under a configured minisign public key (`minisign_verify::PublicKey`). sovereign-os's records use a **different, inline** envelope (`ms003:ed25519:<keyid>:<sig>` in the record's `signature` field) with a **raw ed25519** signature — not minisign framing. No raw-ed25519 verification path exists in the selfdef workspace (only `minisign` / `minisign-verify` in `Cargo.lock`). So the cross-boundary half of MS003 is unbuilt.

## The contract selfdef must verify (source-traced from `sovereign-os/scripts/lib/ms003.py`)

Verbatim from the producer — the verifier MUST agree byte-for-byte:

- **Wire format** (the `signature` field value): `ms003:ed25519:<keyid>:<sig>`
  - `keyid` — `base64url(pub_raw)[:16]`, i.e. the first 16 chars of the unpadded base64url of the **raw 32-byte** ed25519 public key. Selects which trust anchor to verify under.
  - `sig` — unpadded base64url of the **64-byte** ed25519 signature.
- **Signed bytes** — `canonical_bytes(record)`:
  ```
  json.dumps({record without its "signature" key},
             sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
  ```
  i.e. the record **minus** its `signature` field, compact (no spaces), keys sorted, UTF-8, non-ASCII preserved. Producer and verifier must serialize identically.
- **Public trust anchor** — the operator's raw 32-byte ed25519 public key. sovereign-os exports it as unpadded base64url (its `sovereign-osctl ms003 pubkey`), and stores anchors as `<keyid>.pub` files (sovereign-os default `/etc/sovereign-os/ms003-trust-anchors/`).
- **Placeholder** — an unsigned record carries the literal `signature: "unsigned-pending-MS003"` (nodes without a key). Not an error — a distinct status.

### Verification classifications (adopt sovereign-os `VERIFY_STATUSES` verbatim)

sovereign-os's SDD-984 note is explicit: *"the store layout + status enum are the reusable contract the selfdef-side verifier can adopt verbatim."* The five stable statuses:

| Status | Meaning |
|---|---|
| `verified` | real signature, anchor found for `keyid`, ed25519 verify OK |
| `unsigned-placeholder` | `signature == "unsigned-pending-MS003"` (keyless producer node) |
| `no-signature-field` | record has no `signature` field at all |
| `unknown-keyid` | signed, but selfdef holds no trust anchor for that `keyid` |
| `invalid-signature` | signed, anchor found, but the signature does **not** verify (tamper / wrong key) |

`invalid-signature` on a record that claims to be a committed sovereign-os mutation is a **security event** — it is exactly what selfdef exists to surface.

## Current selfdef reality (what exists / what's missing)

| Piece | Today | Gap |
|---|---|---|
| `selfdef-signing` | minisign detached-file `Verifier` (`verify_detached_file`) | no raw-ed25519 inline-envelope verify; no `keyid`→anchor selection |
| crypto deps | `minisign-verify` only | no `ed25519-dalek` / `ring` in the workspace |
| trust anchors | minisign `.pub` for rule signing | no store of operator **ed25519** anchors keyed by `keyid` |
| consumer path | selfdef mirrors sovereign-os state read-only | nothing verifies sovereign-os's `signature` field |

## The design decision (operator) — crypto approach

To ed25519-verify a raw signature over `canonical_bytes`, selfdef needs an ed25519 verify primitive. Two coherent options:

### Option 1 — shell to system `openssl` (zero new dependency) — *recommended*
Mirror the producer exactly: `openssl pkeyutl -verify -pubin` over the recomputed canonical bytes, as sovereign-os's `ms003.py` already does. openssl is already present on the target (SecureBoot uses it) and already ed25519-capable.
- **+** No new crypto dependency in a security IPS (smallest attack/audit surface); **byte-identical** to the producer's own verify path (removes format-drift risk); trivially matches the reference `ms003.py`.
- **−** subprocess per record (fine for batch audit sweeps; not a hot path); depends on an `openssl` with ed25519.

### Option 2 — add a pure-Rust ed25519 verifier (`ed25519-dalek` or `ring`)
Verify in-process, no subprocess.
- **+** no external process; fast per-record; idiomatic Rust.
- **−** a **new crypto dependency** in the IPS — a real supply-chain + audit-surface decision for a security daemon; must re-implement `keyid`/base64url/canonical-bytes to match the producer exactly (drift risk the operator must weigh).

**Recommendation: Option 1** — it adds zero dependencies, is byte-identical to the audited producer path, and the verifier's job is **batch audit** of a durable ledger (not per-request latency), where a subprocess is immaterial. Option 2 is the upgrade path if in-process verification is later required.

### Secondary decisions
- **Home**: extend `crates/selfdef-signing` with an `ms003` module (keeps all signature verification in one crate) vs a new crate. *Recommend: extend `selfdef-signing`* — it is already "the verify authority."
- **Anchor store location**: a selfdef-owned path (e.g. `/etc/selfdef/ms003-trust-anchors/<keyid>.pub`) populated from the operator's exported sovereign-os public key. *Recommend: selfdef-owned path* (selfdef must not trust a path sovereign-os writes).
- **Surface**: a `selfdefctl` verb (`ms003 verify <ledger>` / `anchor-add` / `anchor-list`) + a sweep classification into the store's audit surface, mirroring sovereign-os's `sovereign-osctl ms003` shape.

## Proposed integration (pending the decision above)

1. **`selfdef-signing::ms003`** — parse the envelope, select the anchor by `keyid`, recompute `canonical_bytes`, verify (via the chosen primitive), return one of the 5 `VerifyStatus` variants. Verify-only; no key material minted here.
2. **Anchor store** — read `<keyid>.pub` (unpadded base64url raw 32 bytes) from the selfdef-owned anchor dir; `anchor-add` imports the operator's exported sovereign-os public key.
3. **Ledger sweep** — classify every record in a consumed sovereign-os mutation/decision ledger; emit counts + raise a security-audit event on `invalid-signature` / `unknown-keyid` (the operationally-meaningful cases), consistent with selfdef's existing action-ledger + observability surfaces.
4. **`selfdefctl` surface** — `ms003 {anchor-add, anchor-list, verify, sweep}` (verify-only; read-only on sovereign-os state, honoring the R10212 producer/consumer boundary).

## Verification / test plan (for the implementation follow-up)

Real-crypto end-to-end, mirroring sovereign-os's `test_ms003_verify_store.py`:
- **verified** — sign a fixture record with a test ed25519 key (via openssl), import its anchor, assert `verified`.
- **invalid-signature** — flip one byte of the record body (or the sig) → `invalid-signature`.
- **unknown-keyid** — verify with the anchor absent → `unknown-keyid`.
- **unsigned-placeholder / no-signature-field** — the two non-signed shapes classify correctly (never `invalid`).
- **canonical-bytes agreement** — a golden record signed by sovereign-os's `ms003.py` verifies under this crate (cross-implementation fixture — the real drift guard).

## Non-goals

- Minting signatures (sovereign-os is the producer; selfdef is verify-only — unchanged).
- Changing sovereign-os's producer or wire format (this consumes the pinned contract).
- Implementing before the crypto-approach decision (Option 1 vs 2) is made — this SDD is `scoping`.
- selfdef's own rule/policy minisign signing (`selfdef-signing` today) — orthogonal; untouched.

## Safety invariants

Verify-only; no key material handled beyond public anchors. selfdef trusts anchors from its **own** path, never a sovereign-os-writable one. R10212 producer/consumer boundary preserved (selfdef reads sovereign-os records, never mutates them). No change to selfdef's existing minisign path.

## Cross-references

- sovereign-os producer + local verifier: `sovereign-os/scripts/lib/ms003.py` (the source-traced contract) · `sovereign-os/docs/sdd/989-ms003-signing-primitive.md` + `990-ms003-writer-sweep.md`
- sovereign-os decision: `sovereign-os/docs/decisions.md` D-025 (Option B) · `sovereign-os/docs/sdd/984-ms003-commit-authority-decision-package.md`
- sovereign-os finding: `sovereign-os/docs/review/phase-1/99-findings-ledger.md` F-2026-034 (open on this selfdef half)
- selfdef existing signing: `crates/selfdef-signing/src/lib.rs` (minisign detached-file verify) · MS003 milestone `backlog/milestones/MS003-correlator-store-responder-signing.md` (E0024/E0028 signing)
