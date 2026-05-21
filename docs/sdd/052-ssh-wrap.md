# SDD-052 — SSH-wrap — client-side defense when YOU are the client (MS014)

> Status: **implemented** — `selfdef-ssh-wrap` crate shipped as a
> drop-in `ssh` replacement that enforces per-host policy + emits
> OCSF events for every session. Stage-2 SDD authored retroactively.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestone: MS014 (catalogued in
> `backlog/milestones/MS014-ssh-wrap-client-side-defense.md`)
> Builds on: SDD-004 (security threat model — adversary 4 "malicious
> SSH server"), SDD-007 (audit chain — session events join the chain).

## Problem

When YOU are the SSH client connecting to remote hosts, the
operator's host is exposed to "malicious SSH server" attacks
(adversary 4 in SDD-004 threat model). Standard `ssh` has no
client-side policy enforcement:

1. **No per-host policy** — operator can't say "for host X, never
   forward agent + always disable X11 + always require known host
   key match".
2. **No audit trail** — `ssh` doesn't log session metadata in
   operator-readable OCSF form.
3. **No policy-load defense** — `ssh` reads `~/.ssh/config` but
   any compromised process can rewrite it.
4. **No drop-in replacement** — even if operator authors a policy,
   forgetting to invoke the wrapped binary defeats it.

## Goals

1. Drop-in `ssh` replacement that operators install via PATH-shadow
   pattern:
   ```bash
   sudo install -m 0755 target/release/selfdef-ssh-wrap /usr/local/bin/
   ln -sf /usr/local/bin/selfdef-ssh-wrap ~/.local/bin/ssh
   ```
   `~/.local/bin/` precedes `/usr/bin/` → every `ssh` invocation
   transparently routes through the wrapper.
2. Per-host policy enforcement loaded at wrapper startup.
3. OCSF event emission for every session (`~/.local/share/selfdef/
   ssh-wrap.jsonl`; operator override via env).
4. Pass-through to real `ssh` after policy gate (default
   `/usr/bin/ssh`, override via `SELFDEF_SSH_PATH`).
5. Refuse-to-connect on policy violation with operator-readable
   error citing the rule.

## Non-goals

- This SDD does NOT cover server-side SSH hardening (that's
  per-host OS configuration; out-of-scope for selfdef).
- It does NOT cover SSH agent-forwarding cryptographic implementation
  (the wrapper enforces policy ABOUT forwarding; the cryptography
  is `ssh`'s job).

## Recommended design

### Crate layout

- `src/main.rs` — entrypoint; parses argv, loads policy, applies
  gate, execs real ssh
- `src/argv.rs` — argv parser
- `src/policy.rs` — per-host policy types + load
- `src/events.rs` — OCSF event emission

### Caller contract (operator install)

```bash
# Build + install
cargo build --release -p selfdef-ssh-wrap
sudo install -m 0755 target/release/selfdef-ssh-wrap /usr/local/bin/
mkdir -p ~/.local/bin
ln -sf /usr/local/bin/selfdef-ssh-wrap ~/.local/bin/ssh

# Author policy
cat > ~/.config/selfdef/ssh-wrap.toml <<'EOF'
[hosts."bastion.example.com"]
forward_agent = false
forward_x11   = false
require_known_host = true

[hosts."*"]    # default; lowest priority
forward_agent = false
EOF

# Verify PATH precedence
which ssh   # should print ~/.local/bin/ssh
```

## Implementation status

**Crate**: shipped under `crates/selfdef-ssh-wrap/`. Module structure
covers argv parsing + policy + event emission + main entry.

**Caller integration**: operator-driven install per the docs above.

**Sain-01 integration**: deferred — the SSH-wrap currently runs as
the operator's user; integration with sain-01 friction-audit's
SSH-binary signature verification + sain-01 boot-time gate is a
follow-up arc.

## Open questions

- **D-1**: `selfdefctl ssh-wrap {policy, install, test <host>}` CLI
  surface? **Recommendation: yes** — `policy` prints loaded rules,
  `install` automates the PATH-shadow install, `test <host>`
  dry-runs the policy gate without connecting.
- **D-2**: `GET /v1/ssh-wrap/policy` HTTP discovery returning the
  active policy as JSON? **Recommendation: defer** — the wrapper
  is a per-operator-user tool, not daemon-owned; HTTP surface would
  cross the operator-isolation boundary.
- **D-3**: Sain-01 integration — wire SSH-wrap event emission into
  the friction-audit OCSF chain? **Recommendation**: defer; needs
  the operator-user → daemon-user audit-log bridge.
