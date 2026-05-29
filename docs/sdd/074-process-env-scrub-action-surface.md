# SDD-074 — Process-env scrub action surface (selfdef enforcement layer)

**Status:** draft / architectural spec
**Author:** selfdef IPS authority chain
**Stems from:** IPS nonet (SDD-065..073) → dectet expansion. The
nonet covers network perimeter + single-process boundary + shell
session + API token + MFA grant + kernel-namespace containment +
filesystem-binding + process-graph + per-connection severance.
SDD-074 adds the **in-memory secret-residency axis** — scrub
sensitive environment variables from a live process's
`/proc/<pid>/environ` view AND ask the process (via prearranged
signal-trigger) to re-fetch from a secret broker, so post-
rotation secrets propagate without restart.
**Pairs with:** SDD-068 (token-revocation) at the credential-axis
family. SDD-068 revokes the credential server-side; SDD-074
scrubs the client-side cached copy.

## Purpose

The nonet's missing tenth axis: **in-memory cached-secret
revocation**. Existing options leave the secret in the process's
RAM:
- SDD-068 token-revoke makes the API reject the old token, but
  the process still has the old token cached in `getenv()` /
  `os.environ` and may keep retrying.
- SDD-066 process-freeze stops the process — but operator may
  not want to interrupt long-running work (e.g. a model training
  loop).
- SDD-073 per-fd close kills the active connection but the
  in-memory token is still there for the next attempt.

SDD-074 fills the gap: writes zeros into the matching environ
slots in `/proc/<pid>/environ` (via `process_vm_writev` on
kernels ≥ 3.2, or ptrace fallback), then SIGUSR2 (or a
process-defined signal) to wake the process so it re-reads from
the cooperating secret broker (Vault, AWS SM, local-broker
socket). Process keeps running, picks up the new secret.

Operator decides per incident:
- Long-running process + rotated secret → SDD-074 (cleanest)
- Secret rotation isn't an option, attacker has the token →
  SDD-068 + SDD-074 (revoke + scrub)
- Process is the attacker → SDD-066 freeze, not SDD-074

## Non-goals

- Not a memory-corruption tool. We only write to the named
  environ slots, never anywhere else in process memory.
- Not for processes without cooperative signal-handlers. If the
  process doesn't refetch on SIGUSR2, SDD-074 only scrubs the
  cached value — the process keeps using whatever it has in
  local variables. Document this in the operator-facing message.
- Not for hardcoded secrets (those that aren't env-sourced).
  Hardcoded credentials require SDD-066 freeze + redeploy.

## Surface

### 1. CLI verbs

```
selfdefctl scrub-env <pid> --vars <VAR1[,VAR2,...]> --reason <text>
                    [--duration <human>]   # default 30m; max 6h
                    [--authority <tier>]
                    [--signal <SIGUSR2|SIGUSR1|SIGHUP|none>]  # default SIGUSR2
                    [--dry-run]

selfdefctl restore-env <handle> [--force]
```

`restore-env` cannot recover the scrubbed value (it's literally
zeroed in process memory). It clears the operator queue + audit
record only; if the operator wants the secret back, they must
re-trigger the process's secret-broker fetch by other means.

### 2. Library — `selfdef-responder::ProcessEnvScrubAction`

Standard Action pattern. Reads `(pid, vars)` from
`event.metadata.profiles["env_scrub:VAR1,VAR2"]` (custom). Returns
`Skipped` if no pid or no vars.

### 3. Backend trait

```rust
pub enum ScrubSignal {
    Sigusr1,
    Sigusr2,
    Sighup,
    None,  // scrub only, do not signal
}

#[async_trait]
pub trait ProcessEnvScrubBackend: Send + Sync {
    async fn scrub_env(
        &self, req: ScrubEnvRequest,
    ) -> Result<ScrubEnvReceipt, ProcessEnvScrubError>;
    async fn restore_env(
        &self, handle: ProcessEnvScrubHandle,
    ) -> Result<RestoreReceipt, ProcessEnvScrubError>;
    async fn pending_restores(&self) -> Vec<PendingEnvRestore> { Vec::new() }
    async fn mark_restore_decided(&self, _: &ProcessEnvScrubHandle) -> bool { false }
}
```

### 4. Authority + TTL matrix

| Authority tier        | Max scrub window |
|-----------------------|------------------|
| `autonomous`          | 5 min            |
| `responder`           | 30 min           |
| `operator`            | 2 hours          |
| `operator-overridden` | 6 hours          |

Medium tier-cap because scrubs are sticky (you can't un-scrub a
value out of zeroed memory) but the recorded handle is what
limits operator-queue accumulation, not actual scrub lifetime.

### 5. Audit + observability

28th sibling textfile observer
`selfdef-env-scrubs-textfile.sh` (OnBootSec=840s). Six canonical
gauges + extra `selfdef_env_scrubs_vars_scrubbed_total` (sum
across all active handles).

### 6. Operator UX

MS5b cockpit card `card_env_scrubs_queue` adjacent to the nine
nonet cards — completes the **dectet-paired-handle row**.

## Implementation order — same 5-MS pattern (now decuply-validated)

- **MS1** — backend trait + `InMemoryBackend` substrate
- **MS2** — `ProcessEnvScrubAction` in selfdef-responder
- **MS3** — `selfdefctl scrub-env` / `restore-env` verbs
- **MS4a** — 28th sibling textfile observer
- **MS4b** — sovereign-os consumer surface
- **MS5a** — production adapter (process_vm_writev + signal) — deferred
- **MS5b** — cockpit queue + dectet-paired-handle row

## Open questions

- **Variable-name leak risk.** The scrub request must name the
  variable — that name itself is sometimes sensitive ("DB_PROD_PASSWORD"
  reveals the system has prod DB credentials). Mitigation: redact
  variable names in the cockpit queue display unless operator clicks
  "show names"; full names always in audit log.
- **Process refetch races.** Between scrub and signal, the process
  may re-read the variable from its (now-zeroed) cache and get an
  empty string. Documented behavior; processes should treat
  empty-cred as "refetch immediately".
- **PID-reuse hazard.** Same as SDD-072 — use start_time tuple in
  handle.
- **Variable list audit.** Always record the variable NAMES in
  audit, never the prior values (we don't know them; we just
  zero-fill).

## Standing-rule alignment

R10212 read-only doctrine: SDD-074 IS the enforcement primitive
(selfdef). Sovereign-os consumes observer + cockpit + vertical 28.
Same as SDD-065..073.
