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

Restart the daemon (or SIGHUP — rule loads happen on every
SIGHUP and the verifier is constructed at startup, so a SIGHUP
picks up newly-signed rules but not a changed public-key
configuration).

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
5. SIGHUP the daemon (rules reload with the new verifier picked
   up by the new key configuration on next daemon restart;
   SIGHUP-only rotation requires the public key path to stay
   the same and the SIGHUP code path to call `Verifier::load`
   each time — TODO: a future enhancement).

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

## Coming soon (SDD-004 F-2026-024 follow-up)

The same verifier infrastructure will gate the Tetragon
TracingPolicy directory (`/etc/tetragon/tetragon.tp.d/`). A
future patch adds `[security].require_signed_tetragon_policies`
and wires the verifier into the `tetragon` module's `apply.sh`
so unsigned policies are refused before they reach the kernel.
