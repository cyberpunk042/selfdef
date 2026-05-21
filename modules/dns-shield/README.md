# dns-shield

DNS-level malicious-domain sinkhole via `/etc/hosts`. Renders a
bracketed `# === selfdef dns-shield BEGIN/END ===` block in the
host's `/etc/hosts` with `0.0.0.0 <domain>` + `0.0.0.0
www.<domain>` entries for every blocked domain in the operator's
chosen profile + operator-additions − allowlist.

## Profiles

| Profile | Sources | Use |
|---|---|---|
| `base` (default) | `blocklists/base.txt` | Known C2 + phishing + cryptominer pools. Conservative. |
| `strict` | `blocklists/base.txt` + `blocklists/strict.txt` | Adds tracker/analytics + URL shorteners + high-risk file-hosting. Privacy + tighter operational stance. |

## Operator extension

Two operator-owned files in `/etc/selfdef/dns-shield/`:

| File | Purpose |
|---|---|
| `operator.txt` | Additional domains the operator wants blocked. Same format (bare domain per line; comments `#`). Auto-merged at apply. |
| `allowlist.txt` | Domains to REMOVE from the merged set even if shipped blocklists list them. Operator can opt out of any shipped entry. |

Apply order: profile blocklists → operator.txt → allowlist
subtraction → dedup → sort → render.

## Why /etc/hosts (not a real DNS resolver)

- `/etc/hosts` is honored by EVERY Linux resolver (libc nsswitch
  `hosts: files dns ...` puts `files` first by default). The
  operator's choice of unbound / dnsmasq / systemd-resolved /
  external DNS keeps working — the block is at the libc layer
  BELOW the resolver.
- Zero new daemons / ports / listeners. Pure data.
- The blocklist is operator-readable + grep-able in one file.

Tradeoffs:
- `/etc/hosts` has no wildcard semantics. `*.evil.example` is NOT
  supported; the operator must list specific subdomains. For
  wildcard support, an upstream module like `unbound` or
  `dnsmasq` is the right tier. `dns-shield` is the simple-first
  module.
- Very large lists (100k+ entries) bloat `/etc/hosts` (libc
  resolver does an O(n) scan per lookup). The shipped lists are
  intentionally short; operator-supplied additions are at their
  discretion.

## Install

```bash
selfdefctl modules apply dns-shield
```

Default profile is `base`. Switch via the config file's
`profile = "strict"` setting.

## Coexistence with operator-edited /etc/hosts

The module ONLY touches the region between
`# === selfdef dns-shield BEGIN ===` and
`# === selfdef dns-shield END ===` markers. Operator-edited
entries above or below the block are preserved byte-for-byte
across apply / uninstall / re-apply cycles.

## Coverage relative to MITRE ATT&CK

- **T1071.004** Application Layer Protocol: DNS — sinkholes the
  resolution step before any TCP/UDP traffic is generated.
- **T1568** Dynamic Resolution — partial; DGA-style algorithm
  domains aren't blocked unless seeded into operator.txt.
- **T1583.001** Acquire Infrastructure: Domains — blocking the
  domain renders an actor-acquired domain useless until they
  acquire a new one.
