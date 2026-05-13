# Security audit

> Scope: cross-reference `SECURITY.md` (and its mirror at
> `docs/src/security.md`) against the attack surfaces introduced
> by recent PRs and the modules they ship. Per-area finding ids
> prefix `S-`.

`SECURITY.md` is well-structured for the daemon as it stood at
M15. The post-M15 work (PRs #19–#25) introduced new attack
surfaces that the threat model does not acknowledge. None of
these are exploitable today *by remote attackers* in a default
install (the daemon defaults to "everything disabled"), but they
are real surfaces the operator must understand once they enable
the relevant features.

This audit doesn't propose fixes — that's Phase 2. It catalogues
gaps.

---

## Existing threat model

The Assets table in `SECURITY.md:9-17` lists:

- Daemon binary
- Daemon config (`/etc/selfdef/`)
- Detection rules
- Hot event store
- Cold archive
- Notification credentials
- eBPF programs

The Adversaries (`SECURITY.md:19-30`) cover four classes from
opportunistic remote attackers to root-level attackers, plus
SSH-server and supply-chain. The Mitigations sections enumerate
build, process, config, storage, notification, and tamper
detection.

The Tetragon TracingPolicy at `SECURITY.md:86-88` watches the
daemon's own paths — a known-good policy, but only for
*self-watch*. The threat model treats Tetragon as a tamper
detector, not as itself a system with attack surface.

---

## New surfaces not in the threat model

### S-001 — Tetragon TracingPolicy drop directory

`tetragon` module creates `/etc/tetragon/tetragon.tp.d/` and
peer modules (`agent-guard`) write YAML files into it. Tetragon
loads every YAML in that directory as kernel-level eBPF policy.

An attacker who gains write access to that directory can:

- Inject a policy with `action: Sigkill` to terminate arbitrary
  processes (denial of service).
- Inject a policy with `action: Override` to short-circuit
  syscalls (privilege escalation surface depending on which
  syscalls are overridden).
- Inject a policy that masks legitimate detection (replace
  agent-guard's etc-write-guard with a wildcard rule that fires
  Post-only and lets writes through unflagged).

Severity: **important**. The default directory mode (0755) is
operator-default; selfdef does not set or verify it. The threat
model doesn't acknowledge this directory at all.

Recommended treatment (out of scope for this phase):
- Document `/etc/tetragon/tetragon.tp.d/` as an asset.
- Add an `integrity-sentinel` paths entry for the directory by
  default (it's already supported via `paths_file`, but a
  default seed would help operators discover it).
- Phase-2 design: signed policy YAMLs, similar to the
  "rule signing" gap already in `SECURITY.md:95`.

### S-002 — `/metrics` exposure

The new `/metrics` endpoint (PR #23) renders process-wide
counters: events / second by class, findings / second by
severity, hot-store size, daemon uptime. Lower-sensitivity than
raw events but a fingerprint of host activity.

- On UNIX socket: filesystem-permissions gated — fine.
- On TCP: bearer-token gated (the integration audit confirmed
  `/metrics` follows the same middleware as the other read
  endpoints). Still:
  - If the operator binds `0.0.0.0:8443` (not the default but
    documented as a knob), the endpoint is reachable from the
    network. Tokens stop credential-less scrapes but a leaked
    token reads metrics indefinitely.
  - Token rotation is not in the threat model. Today the daemon
    loads tokens once at startup; rotating requires a daemon
    restart.

Severity: **important**.

### S-003 — Pod-label scope label-trust

`agent-guard` v0.3.0 introduces `scope = "pod-label"`. The
policy matches pods carrying `pod_label_key: pod_label_value`
(default `selfdef.io/agent: "true"`).

In a Kubernetes cluster the threat surface is:

- Anyone with `PATCH` on a Pod's labels (RBAC default for some
  service-account configurations) can either *opt into* the
  agent-guard policies (set the label on an arbitrary pod) or
  *opt out* (remove the label from a real agent pod) — moving
  the policy boundary.
- The pod-label scope is *narrower* than the namespace scope,
  so it's strictly safer in audit mode. In enforce mode it
  becomes a privilege boundary that depends on the cluster's
  label RBAC.

Severity: **important** in k8s environments; **n/a** on
non-k8s hosts.

### S-004 — Eventstream JSONL ingestion trust

The eventstream collector reads JSON lines from any path it's
configured to tail. A peer module emits events via
`selfdefctl events emit --out <path>`. An attacker with write
access to such a path can:

- Inject fake events to mask real ones.
- Inject finding-shaped events that trip the notifier chain
  (denial-of-service-of-attention).
- Inject events with crafted `host_tag` values to pollute the
  multi-host NATS bridge (the bridge filters by host_tag for
  loop avoidance, but a malicious local writer can claim to be
  a different host).

The default `event_log_path` for integrity-sentinel is
`/var/lib/selfdef/eventstream/integrity-sentinel.jsonl`. The
daemon mode of this directory and the modes of its files are
not specified anywhere in the threat model. The eventstream
collector does not check file ownership or integrity before
parsing.

Severity: **important**. The mitigation is straightforward
(daemon-owned, mode-0600 directories, verify ownership at
parse-time) but neither is implemented.

### S-005 — selfdefctl events emit auth

`selfdefctl events emit` is invokable by any user who can
execute the binary. The binary defaults to system PATH (root-
owned). The append path is operator-chosen via `--out`. So:

- Module scripts run as root via systemd → safe.
- Anyone who can run `selfdefctl events emit --out
  <eventstream-path>` and has write access to that path can
  inject events.

In practice this collapses to S-004: it's a write-access
problem on the JSONL files. But the threat model should
acknowledge `selfdefctl events emit` as an event-injection
primitive.

Severity: **nice** (sub-component of S-004).

### S-006 — Notifier credential lifecycle

`SECURITY.md:75-78` says notification credentials are loaded on
start and never re-read. That mitigation is correct for the
documented threat (attacker editing the credentials file without
restarting the daemon).

The new GET `/metrics` endpoint reveals daemon uptime, so an
attacker who can poll `/metrics` can detect a daemon restart
and time their credential-file edit. This is a chained-attack
observation, not a defect, but worth listing in the threat
model as a side-channel.

Severity: **nice**.

### S-007 — vpn-bridge multi-instance state corruption (security implication of M-008)

M-008 is documented as a correctness defect (instances clobber
shared paths). It is also a *security* defect: an operator who
configures two `vpn-bridge` instances ends up with one of them
in undefined state. If that's a relay-via-server profile, the
"failed" instance may silently fall back to a permissive
firewall ruleset. Cross-referenced here so the threat model
acknowledges the surface.

Severity: **important** (already a blocker in M-008).

---

## Findings raised in this section

| Id | Severity | Surface | Summary |
| --- | --- | --- | --- |
| S-001 | important | `SECURITY.md` Assets table | Tetragon policy drop directory (`/etc/tetragon/tetragon.tp.d/`) not in the threat model. eBPF injection surface. |
| S-002 | important | `SECURITY.md` | `/metrics` endpoint not in the threat model. Token rotation lifecycle unspecified. |
| S-003 | important | `SECURITY.md` | Pod-label scope's reliance on k8s label RBAC not in the threat model. |
| S-004 | important | `SECURITY.md` | Eventstream JSONL paths are a write-access-controlled trust boundary; no documented permissions / ownership requirements. |
| S-005 | nice | `SECURITY.md` | `selfdefctl events emit` is an event-injection primitive; sub-case of S-004. |
| S-006 | nice | `SECURITY.md` notification credentials section | `/metrics` daemon-uptime gauge enables an attacker to time credential-file edits to a daemon restart. Chained-attack side-channel worth noting. |
| S-007 | important (cross-listed M-008) | `SECURITY.md` | vpn-bridge multi-instance corruption can leave one instance with permissive firewall state. |
