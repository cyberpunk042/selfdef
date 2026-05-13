# Rule + policy signing (operator runbook)

selfdef can refuse to load unsigned detection rules. The
verification uses [minisign](https://jedisct1.github.io/minisign/),
a small audited ed25519-based detached-signature format. This
runbook walks through key generation, signing rules, configuring
the daemon, and operational rotation. It also previews the
forthcoming TracingPolicy signing (SDD-004 F-2026-024 follow-up)
which will use the same machinery.

## What gets signed

| Surface | Status | Mechanism |
| --- | --- | --- |
| Detection rules (`/etc/selfdef/rules/*.yml`) | **opt-in shipped** | `[security].require_signed_rules = true` in selfdef.toml |
| Tetragon TracingPolicies (`/etc/tetragon/tetragon.tp.d/*.yml`) | tracked follow-up | will reuse the same verifier |
| Module manifests | not scoped | manifests aren't a kernel-level surface |

The selfdef daemon's verification is **verify-only** — no signing
happens on the host. Signing is performed offline on the
operator's signing machine, where the secret key is protected
by a passphrase and (recommended) a hardware token.

## Install the minisign CLI

```sh
# Debian-derived
apt install minisign

# macOS
brew install minisign

# From source: https://github.com/jedisct1/minisign
```

selfdef ships verification only — it does not require the
`minisign` CLI on the daemon host.

## Generate the signing key pair (once, on the signing machine)

```sh
# Protect the secret key with a passphrase. Store the
# resulting `policy.key` on the signing machine ONLY (e.g.
# a YubiKey-backed slot, a luks-encrypted USB, an air-gapped
# laptop).
minisign -G -p ./policy.pub -s ./policy.key
```

Two files are produced:

- `policy.pub` — small ASCII file with a comment header + base64
  body. Ship this to every daemon host (mode `0644`; it's a
  public key, not a secret).
- `policy.key` — the encrypted secret key. Never leaves the
  signing machine.

## Sign a rule

```sh
# Each rule YAML gets a sibling .minisig file with the
# detached signature.
minisign -S -m /etc/selfdef/rules/my-rule.yml -s ./policy.key
```

After signing, the rules directory should look like:

```
/etc/selfdef/rules/
├── my-rule.yml
├── my-rule.yml.minisig    ← detached signature
└── another-rule.yml
└── another-rule.yml.minisig
```

To sign every rule under a directory in one go:

```sh
find /etc/selfdef/rules -name '*.yml' -print0 |
  xargs -0 -I{} minisign -S -m {} -s ./policy.key
```

## Deploy the public key

Ship `policy.pub` to every host that runs the daemon. The
canonical location is `/etc/selfdef/keys/policy.pub` with mode
`0644 root:root`:

```sh
sudo install -D -m 0644 ./policy.pub /etc/selfdef/keys/policy.pub
```

## Turn on enforcement in `selfdef.toml`

```toml
[security]
require_signed_rules = true
signing_public_key_file = "/etc/selfdef/keys/policy.pub"
```

Restart the daemon to apply the new configuration.

After startup you have two hot-reload signals at your disposal:

- **SIGHUP** — reload rules from disk. Re-uses the verifier that
  was constructed at startup. Picks up newly-signed rules but
  *not* a changed public-key file (path or contents).
- **SIGUSR2** — fan-outs to *every* hot-reloadable surface the
  daemon owns. As of the current cycle that's three branches:
  1. **API tokens** — re-reads `[api].token_file` and
     `[api].control_token_file`, enforces mode-0600
     (F-2027-031). Paired with `selfdefctl api rotate-token`.
  2. **Rule-signing verifier** — re-reads
     `signing_public_key_file` and swaps the in-memory
     verifier (F-2027-005).
  3. **Rule re-verify** — automatically follows the verifier
     reload; any rule whose signature was rejected under the
     previous public key gets a fresh attempt.

  After the fan-out the daemon emits a single summary line so
  operators can answer "did the rotation overall succeed?" in
  one glance (F-2027-032):

  ```
  INFO tokens=ok verifier=ok rules=ok SIGUSR2 reload summary
  ```

  Each branch's outcome is one of `ok` / `failed` / `skipped`
  (the latter when the feature isn't enabled). A failed branch
  doesn't block the others — partial reloads are valid.

Both signals are no-ops if no hot-reloadable surface is enabled
(SIGHUP without a correlator-enabled config; SIGUSR2 without
api / signing) — they log a `debug:` line and continue.

When enforcement is on:

- Every `*.yml` rule file in the rules directory must carry a
  valid `<file>.yml.minisig` sidecar signed by the configured
  public key.
- Rules that fail verification are **refused** with a typed
  `SigmaError::Signature` — the prior ruleset stays loaded, the
  daemon stays up, and the warning is logged at `WARN`.
- An unsigned drop never affects the running rule set.

## Verify a signature manually

The CLI ships a debug helper:

```sh
selfdefctl keys verify /etc/selfdef/rules/my-rule.yml
# uses [security].signing_public_key_file from selfdef.toml

# Override:
selfdefctl keys verify /etc/selfdef/rules/my-rule.yml \
    --public-key /tmp/scratch.pub
```

Returns `ok: <target> verifies against <pubkey>` on success;
a typed error otherwise. Useful when an operator is investigating
"did this rule really get signed by the key I think it did?"
without involving the daemon.

## Rotating the signing key

There's no automatic rotation — a key rotation is operator-driven:

1. Generate a new key pair on the signing machine.
2. Re-sign every rule with the new key.
3. Atomically replace `/etc/selfdef/keys/policy.pub` on every
   host (`install -D -m 0644 new.pub /etc/selfdef/keys/policy.pub`).
4. Replace every `.minisig` sidecar in the rules directory.
5. Hot-rotate the daemon's verifier without a restart:
   `pkill -USR2 selfdefd`. The SIGUSR2 handler re-loads the
   public-key file at the configured
   `[security].signing_public_key_file` path and immediately
   re-runs `load_rules` against the fresh verifier; both steps
   log at `info`. On reload failure (corrupt key file) the
   previous verifier stays in place and a `warn` line surfaces
   the cause. (Before F-2027-005, this step required a full
   daemon restart.)

The signing key's compromise impact is "an attacker can have the
daemon load malicious rules"; revoke by replacing the public key
and re-signing, exactly as above.

## Threat model (what this doesn't fix)

- A signing-key compromise lets the attacker sign anything the
  operator would have signed. Hold the key on a YubiKey or
  air-gapped host.
- Verification happens at rule-load time. A previously-loaded
  malicious rule already in memory continues to fire until the
  daemon restarts. Mitigation: integrity-sentinel watches the
  rules directory and surfaces unsigned modifications as
  Detection Findings.
- The verifier doesn't bind a key to a hostname / cluster — any
  host with the public key trusts any rule signed by the
  corresponding secret key. Operators wanting per-cluster
  signing keys ship per-cluster `policy.pub` files.

## Tests

- `selfdef-signing` unit tests (`crates/selfdef-signing/src/lib.rs`):
  9 tests covering public-key parsing (raw + .pub format),
  signed/unsigned/wrong-key/tampered/malformed paths.
- `selfdef-correlator` integration tests
  (`crates/selfdef-correlator/tests/signed_rules.rs`): 6 tests
  covering the full correlator `load_rules` path under a
  configured verifier, including the "keep prior ruleset on
  failure" contract.

## TracingPolicy signing (SDD-004 F-2026-024 follow-up — shipped)

The same verifier gates Tetragon TracingPolicy YAMLs in
`/etc/tetragon/tetragon.tp.d/`. The `tetragon` module's
`apply.sh` and `check.sh` re-use `selfdefctl keys verify` to
check every policy file's sibling `.minisig` before allowing
tetragon to (re)start.

### Turning it on

In the tetragon module's per-host config
(`/etc/selfdef/modules/tetragon.toml`):

```toml
profile = "default"
require_signed_policies = true
# (other knobs — event_log_path, policy_dir, etc — unchanged)
```

The verifier reads `[security].signing_public_key_file` from
the daemon config — operators don't configure the key twice.

### Apply behaviour

When `require_signed_policies = true`:

- `selfdefctl modules apply` runs the tetragon module's
  `apply.sh`, which iterates every `*.yml`/`*.yaml` in
  `policy_dir` and runs `selfdefctl keys verify` on each.
- If any policy is unsigned or its `.minisig` fails to verify,
  apply.sh emits a `failed` structured-status line and exits
  non-zero **before** invoking `systemctl restart tetragon`.
  The previously-running tetragon stays up with whatever
  policies were already loaded; the operator fixes the
  unsigned policy and re-applies.
- Dry-run (`SELFDEF_DRY_RUN=1`) logs "DRY-RUN: would verify
  ..." for each policy but does **not** fail — dry-runs report
  what would happen, never enforce.

### Check behaviour

`selfdefctl modules check` runs `check.sh`, which reports an
unsigned-policy count as a `failed` structured status with the
detail line:

```
"<N> of <M> policy file(s) in /etc/tetragon/tetragon.tp.d failed signature verification"
```

This is non-fatal to the running tetragon (it never invokes
systemctl) — the check is purely a state report.

### Caveats

- `agent-guard` renders its policies at runtime from operator
  config (severity, scope, allow-lists). The rendered output
  is **not** pre-signed. If you opt every module into signing,
  you'll either need to sign agent-guard's rendered output
  on each apply (defeating the offline-signing model — secret
  key has to live on the host) or exempt agent-guard's
  rendered files. The current shipped approach: operators turn
  on `require_signed_policies` for hosts where they don't run
  agent-guard, or where the agent-guard render output is
  trusted via package signatures + integrity-sentinel
  baselining.
- The check is at apply-time, not load-time. Tetragon itself
  has no signature gate; a policy that gets dropped into
  `policy_dir` between applies will be loaded by tetragon
  unverified. Mitigation: `integrity-sentinel` watches the
  policy directory and surfaces unsigned additions as
  Detection Findings.
