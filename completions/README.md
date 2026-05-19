# selfdefctl shell completions

Per MS043 R10134 — bash + fish + zsh completions, installed by the
selfdef `.deb` package alongside the daemon binary.

## Installation paths

| Shell | Path |
|---|---|
| bash | `/usr/share/bash-completion/completions/selfdefctl` |
| fish | `/usr/share/fish/vendor_completions.d/selfdefctl.fish` |
| zsh  | `/usr/share/zsh/vendor-completions/_selfdefctl` |

The `.deb` `postinst` script copies these files into place; no
operator-side action required.

## Coverage

All three completion files mirror the `selfdef-cli-mirror` schema:

- **13 top-level namespaces**: `grant token rule sandbox quarantine
  trust audit rollback snapshot commit notify config status` + meta
  (`help`, `version`).
- **Per-namespace subcommands** (e.g. `grant list / request / approve
  / deny / revoke / inspect`).
- **Flag-value enumerations** for closed-set arguments:
  - `--ring` → ring0..ring4 (MS039)
  - `--tier` → A/B/C/D (MS036)
  - `--kind` → filesystem/network/capability/communication/sandbox
  - `--verdict` → allow/deny/log
  - `--authority` → l0_observe..l6_persist (MS039)
  - `--profile` → private/fast/careful/autonomous/experimental/production (MS040)
  - `--band` → trusted/watched/suspect/untrusted (D-18)
  - `--severity` → informational/minor/major/critical (D-17)
  - `--output|-o` → json/yaml/text
- **Generic flags**: `--help --json --yaml --watch --quiet --verbose
  --dry-run --confirm --signed-by --reason --ttl --since --until`.

## Verification

The MS045 UX coherence harness L1 layer asserts that the completion
files exist + match `selfdef-cli-mirror` schema. Run:

```
/usr/bin/selfdef-ux-harness --layer L1
```

CI: schema drift between completion files and `selfdef-cli-mirror`
fails the harness with non-zero exit per MS045 R10570.
