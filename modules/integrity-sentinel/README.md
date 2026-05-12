# integrity-sentinel

Records a SHA256 baseline of selfdef's policy artifacts and verifies
the host still matches. Fail-closed by default: any drift in a
baselined file (modified, removed, or a new file matching a tracked
glob) makes `selfdefctl modules apply` exit non-zero.

This is the answer to "did anyone tamper with my rules / configs /
module install scripts since I sealed the host?" — not as a
crypto-anchored attestation (no signing, no remote attestation), but
as a tripwire the operator owns the keys to.

## What gets baselined

The set of paths to track is **operator-defined**, in a plain text
file (one absolute path per line, globs and `**` are expanded). The
default set, shipped at `paths.txt.default`, covers the artifacts
that matter for selfdef's own integrity:

- `/etc/selfdef/selfdef.toml` — daemon config
- `/etc/selfdef/modules.toml` — host modules list
- `/etc/selfdef/modules/*.toml` — per-module configs
- `/etc/selfdef/rules.d/**/*.yml` — correlator rules
- `/usr/share/selfdef/modules/*/module.toml` — module manifests
- `/usr/share/selfdef/modules/*/install/*.sh` + `install/profiles/*.sh`
  — every executable selfdef's runner can `bash <script>` against

Copy the default to `/etc/selfdef/integrity-sentinel/paths.txt` and
edit. The module deliberately does not install the file to that path
automatically — picking what to baseline is a security decision the
operator makes.

## Profiles

| Profile | Drift behaviour | When to use |
| --- | --- | --- |
| `strict` (default) | Exit non-zero on any drift. `selfdefctl modules apply` halts. | Production. The whole point of the module. |
| `warn-only` | Report `ok` with `DRIFT detected (warn-only: not blocking)` in the status message. | Bring-up — while you stabilise what's in the baseline. Flip to `strict` once the noise is gone. |

In both modes the full diff (`diff -u <baseline> <current>`) is
written to stderr so the operator can triage immediately.

## Lifecycle

```
# 1. Set up the paths file once.
sudo mkdir -p /etc/selfdef/integrity-sentinel
sudo cp /usr/share/selfdef/modules/integrity-sentinel/paths.txt.default \
        /etc/selfdef/integrity-sentinel/paths.txt
sudo nano /etc/selfdef/integrity-sentinel/paths.txt   # edit to taste

# 2. Activate the module in /etc/selfdef/modules.toml.
sudo sh -c 'echo "[modules.integrity-sentinel]" >> /etc/selfdef/modules.toml'

# 3. First apply seals the baseline.
sudo selfdefctl modules apply --only integrity-sentinel
# → "ok: baseline created (N entries) at /var/lib/selfdef/integrity-sentinel/baseline.sha256"

# 4. Subsequent applies verify it.
sudo selfdefctl modules apply
# → "ok: baseline matches (N entries)"
```

## Re-sealing after intentional changes

When you legitimately update a config / rule / module script, the
existing baseline is now stale and `apply` will start refusing. To
re-seal:

```
sudo selfdefctl modules uninstall  # removes the baseline file only
sudo selfdefctl modules apply --only integrity-sentinel
```

This is intentional friction: re-sealing is a deliberate act, never a
silent side-effect of a routine apply.

For a one-shot operator who wants to flip without uninstall:

```
sudo rm /var/lib/selfdef/integrity-sentinel/baseline.sha256
sudo selfdefctl modules apply --only integrity-sentinel
```

(Equivalent to the uninstall+apply pair.)

## Baseline format

The baseline file is in `sha256sum(1)` format — one
`<sha256-hex>  <abs-path>` record per line, sorted by path. Both
because it's the standard format on Linux and because it's directly
verifiable without going through selfdef:

```
sha256sum -c /var/lib/selfdef/integrity-sentinel/baseline.sha256
```

That gives operators a useful out-of-band path if `selfdefctl` itself
is in doubt.

## Config

```toml
profile       = "strict"                                           # strict | warn-only
paths_file    = "/etc/selfdef/integrity-sentinel/paths.txt"
baseline_path = "/var/lib/selfdef/integrity-sentinel/baseline.sha256"
on_missing    = "create"                                           # create | fail

# Optional notifier wiring — see "Notifying on drift" below.
# event_stream_path     = "/var/lib/selfdef/eventstream/integrity-sentinel.jsonl"
# event_severity_strict = "high"
# event_severity_warn   = "low"
```

## Notifying on drift

Out of the box, drift only surfaces in the structured-status JSON
that `selfdefctl modules apply` / `check` aggregates. To wire drift
into the existing notifier chain (ntfy / Signal), set
`event_stream_path` to a JSONL file the selfdef daemon's
`eventstream` collector is configured to tail:

```toml
# /etc/selfdef/integrity-sentinel.toml
event_stream_path     = "/var/lib/selfdef/eventstream/integrity-sentinel.jsonl"
event_severity_strict = "high"   # default — strict drift is operator-actionable
event_severity_warn   = "low"    # default — warn-only drift is informational

# /etc/selfdef/selfdef.toml
[collectors.eventstream]
enabled  = true
paths    = ["/var/lib/selfdef/eventstream/integrity-sentinel.jsonl"]
read_from = "end"
```

When drift is detected, the module appends a Detection Finding
(OCSF class 2004) to the JSONL via `selfdefctl events emit`. The
daemon picks it up, the responder routes any `Findings`-category
event through the notifier chain, and the operator gets a Signal /
ntfy ping.

Leave `event_stream_path` unset to suppress emission entirely — the
structured-status surface is unaffected.

`on_missing = "fail"` is the right answer once you've sealed the
initial baseline through an out-of-band channel (e.g. a configuration
management tool laying down the baseline file ahead of selfdef's
first apply). It refuses to silently create a new baseline if the
expected one is missing — which would otherwise be an exploitable
race: an attacker who deleted the baseline file and triggered an
apply could re-baseline a host they'd already tampered with.

## Scope of this module

Owns:

1. The baseline file at `baseline_path` (default
   `/var/lib/selfdef/integrity-sentinel/baseline.sha256`).
2. Reading `paths_file` and computing the current view of every
   matched regular file.

Does NOT own:

- The paths file itself (`paths_file`) — operator-managed.
- The integrity of the baseline file (operator should 0600 it; the
  module sets that on creation but doesn't enforce it on each apply).
- Cryptographic signing of the baseline. SHA256 is integrity, not
  authenticity — if an attacker has write access to both the tracked
  files AND the baseline, this module can't help. Pair with
  filesystem-level immutability (`chattr +i`) or out-of-band
  baseline storage if you need stronger guarantees.

## Caveats

- **Symlinks**: the module follows symlinks (sha256sum's default).
  If a tracked path is a symlink, the *target's* hash is what's
  baselined. Replacing the symlink to point elsewhere is **detected**;
  replacing the target's content is **detected**; replacing the
  symlink with a copy of the target is **not** detected (same hash).
- **Globs**: `*` and `**` are expanded with bash globstar+nullglob.
  Patterns that don't match anything contribute zero entries (rather
  than failing).
- **Directories and special files** are skipped — only regular files
  are hashed.
- **Ordering vs the rest of `modules apply`**: this module's manifest
  declares `phase = "pre"`, so `selfdefctl modules apply` runs it
  before any `main`-phase module. A drift detection in `strict` mode
  halts the apply before anything else mutates host state — the
  intended security posture.
