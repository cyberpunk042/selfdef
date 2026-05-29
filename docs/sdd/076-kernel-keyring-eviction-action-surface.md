# SDD-076 — Kernel-keyring eviction action surface (selfdef enforcement layer)

**Status:** draft / architectural spec
**Author:** selfdef IPS authority chain
**Stems from:** IPS undectet (SDD-065..075) → duodectet expansion.
The undectet covers network perimeter + single-process boundary +
shell session + API/web token + MFA grant + kernel-namespace
containment + filesystem-binding + process-graph + per-connection
severance + in-memory secret-residency + per-process privilege
set. SDD-076 adds the **kernel-keyring axis** — evict / invalidate
specific keys from the Linux kernel keyring (kerberos TGTs, NFS
sec credentials, dm-crypt master keys, `request_key()` upcall
cache entries) without killing the process.
**Pairs with:** SDD-068 (API/web token revoke) + SDD-069 (MFA
grant) + SDD-074 (in-memory env scrub) + SDD-075 (POSIX caps) at
the credential-axis family. SDD-076 covers a distinct surface —
the kernel-side keyctl-managed cache — that none of those four
touch.

## Purpose

The undectet's missing twelfth axis: **kernel-side cached
credential eviction**. Existing primitives don't cover the
keyctl cache:
- SDD-068 token-revoke: HTTP auth bearers at the API layer.
  Doesn't touch kernel keys.
- SDD-069 MFA-grant revoke: PAM-side cached grants. Doesn't
  reach kernel keys.
- SDD-074 env-scrub: process-environ secrets. Doesn't touch
  keyctl.
- SDD-075 capability-drop: POSIX caps. Doesn't invalidate
  cached crypto material.

SDD-076 fills the gap: identify a key by serial (numeric) or
description ("krb5cc/uid=1000", "dm-crypt:luks-<uuid>", etc.),
then invalidate it via `keyctl_invalidate(KEYCTL_INVALIDATE)`
syscall (kernel ≥ 3.5). The key remains addressable for in-
flight operations holding a reference, but any new lookup
(`request_key()`, `keyctl_get`, etc.) fails with `EKEYREVOKED`
forcing re-acquisition through the proper authentication path.

Operator decides per incident:
- Attacker has compromised kerberos TGT in `/proc/keys` → SDD-076
- Attacker holds dm-crypt master key in keyring → SDD-076 +
  SDD-066 freeze (drop the cap before they can fork-encrypt)
- Attacker's NFS sec cred was leaked → SDD-076 + SDD-073 close
  the active NFS socket

## Non-goals

- Not a key-store reissuer. We invalidate; the operator (or the
  upstream KDC/NFS server) re-issues through normal flow.
- Not for kernel-internal keyrings (system keyring, builtin
  trusted keys). Those require kernel rebuild to modify.
- Not for keyrings owned by pid 1 (init) — sacrosanct (same as
  SDD-072 / SDD-074 / SDD-075).

## Surface

### 1. CLI verbs

```
selfdefctl evict-key <key-spec> --reason <text>
                    [--duration <human>]    # default 30m; max 4h
                    [--authority <tier>]
                    [--scope <invalidate|unlink|both>]  # default invalidate
                    [--dry-run]

selfdefctl restore-key <handle> [--force]
```

`<key-spec>` is either a numeric serial (`0x12345678`) or a
type:description tuple (`keyring:_uid.1000`,
`user:krb5cc/uid=1000`, `logon:dm-crypt:luks-<uuid>`).

`restore-key` does NOT re-fetch the key (impossible — the kernel
discarded it). Clears the operator queue + audit record. The
process must re-acquire via the upstream auth flow.

### 2. Library — `selfdef-responder::KernelKeyringEvictionAction`

Standard Action pattern. Reads `<key-spec>` from
`event.metadata.profiles["evict_key:<spec>"]` (custom). Returns
`Skipped` when no key spec is present.

### 3. Backend trait

```rust
pub enum EvictionScope {
    /// keyctl_invalidate — marks key dead, in-flight refs still
    /// valid, new lookups fail with EKEYREVOKED.
    Invalidate,
    /// keyctl_unlink — removes the key from one keyring. If it's
    /// in other keyrings or held by other refs, still alive there.
    Unlink,
    /// Both invalidate AND unlink from the default keyring.
    Both,
}

#[async_trait]
pub trait KernelKeyringEvictionBackend: Send + Sync {
    async fn evict_key(
        &self, req: EvictKeyRequest,
    ) -> Result<EvictKeyReceipt, KernelKeyringEvictionError>;
    async fn restore_key(
        &self, handle: KernelKeyringHandle,
    ) -> Result<RestoreReceipt, KernelKeyringEvictionError>;
    async fn pending_restores(&self) -> Vec<PendingKeyRestore> { Vec::new() }
    async fn mark_restore_decided(&self, _: &KernelKeyringHandle) -> bool { false }
}
```

### 4. Authority + TTL matrix

| Authority tier        | Max eviction window |
|-----------------------|---------------------|
| `autonomous`          | 2 min               |
| `responder`           | 15 min              |
| `operator`            | 1 hour              |
| `operator-overridden` | 4 hours             |

Shortest of the IPS spine — kernel-keyring evictions are
irreversible at the kernel level; long handle TTLs only
accumulate operator-decision queue noise.

### 5. Audit + observability

30th sibling textfile observer
`selfdef-kernel-keyring-evictions-textfile.sh` (OnBootSec=900s).
Same 6 canonical gauges as the prior undectet observers plus:
- `selfdef_kernel_keyring_evictions_by_type{type="user|logon|keyring|big_key|..."}` (labeled gauge for key-type incident-pattern detection)

### 6. Operator UX

MS5b cockpit card `card_kernel_keyring_evictions_queue` adjacent
to the eleven undectet cards — completes the **duodectet-paired-
handle row**.

## Implementation order — same 5-MS pattern (now duodecuply-validated)

- **MS1** — backend trait + `InMemoryBackend` substrate
- **MS2** — `KernelKeyringEvictionAction` in selfdef-responder
- **MS3** — `selfdefctl evict-key` / `restore-key` verbs
- **MS4a** — 30th sibling textfile observer (selfdef) with extra
  by-type labeled gauge
- **MS4b** — sovereign-os consumer surface (alerts + dashboard #50
  + observability-status vertical 30)
- **MS5a-state-journal** — FsBackend pattern (see info-hub wiki/
  patterns/01_drafts/ms5a-state-journal-vs-enforcement-layer-separation.md)
- **MS5a-enforcement** — `keyctl(KEYCTL_INVALIDATE, …)` adapter
  (CAP_SYS_ADMIN required for keyrings outside the caller's
  session) — deferred until L3 nspawn substrate
- **MS5b** — cockpit `kernel-keyring-evictions-queue.py` +
  duodectet-paired-handle row

## Open questions

- **Key-spec syntax.** Numeric serial is unambiguous;
  `<type>:<desc>` is what `keyctl describe` outputs. Validator
  accepts both; canonical-form is numeric serial post-MS5a-
  enforcement resolution.
- **Cross-session keyrings.** Some keys live in
  `_uid.<UID>` session keyring not visible to the daemon's
  session. Production adapter needs `KEYCTL_JOIN_SESSION_KEYRING`
  + CAP_SYS_ADMIN. Documented as MS5a-enforcement substrate.
- **Untyped numeric serial collision.** Two different keys with
  similar serials at different times. Mitigation: validator
  requires `0x`-prefix or `keyring:`/`user:`/`logon:` prefix.
- **Invalidate-vs-unlink semantic.** Operator may want to keep
  the key alive for in-flight forensics but break new lookups
  (Invalidate), OR fully detach from a specific keyring
  (Unlink), OR both. Default is Invalidate (least surprising).

## Standing-rule alignment

R10212 read-only doctrine: SDD-076 IS the enforcement primitive
(selfdef). Sovereign-os consumes via observer + cockpit +
vertical 30. Same as SDD-065..075.
