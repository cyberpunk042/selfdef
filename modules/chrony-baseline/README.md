# chrony-baseline

NTP integrity baseline via [chrony](https://chrony.tuxfamily.org/).
Drops a `/etc/chrony/conf.d/50-selfdef.conf` that composes with the
OS-shipped `/etc/chrony/chrony.conf` to enforce:

- Multi-source NTP from diverse pools (community + commercial
  fallbacks).
- Maximum step clamp: 1 hour. Beyond that, chrony LOGS but does
  not step the clock (operator must intervene).
- Localhost-only `chronyc` command access.
- Drift file + tracking/measurements/statistics journaling.
- (NTS profile) Network Time Security (RFC 8915) — HMAC-signed
  packets, refuse plain-NTP fallback.

## Profiles

| Profile | Source set | Cryptographic auth | When to use |
|---|---|---|---|
| `pool` (default) | pool.ntp.org + Cloudflare + Google | None (plain NTP) | Most operator workflows; community-uptime guarantees |
| `nts` | Cloudflare + Netnod + PTB + NL Labs (NTS-only) | HMAC per RFC 8915 | Network-attacker threat model; chrony ≥ 4.0 + outbound 4460/tcp |

## MITRE coverage

- **T1029** Scheduled Transfer — a malicious scheduled task that
  relies on system time to execute at a specific moment can be
  derailed by clock manipulation; NTS prevents undetected
  manipulation.
- **T1070.006** Indicator Removal: Timestomp — without trusted
  time, tamper-evident logs lose meaning. Trustworthy clock is
  the foundation.
- **T1565.001** Stored Data Manipulation — clock-dependent log
  rotation / certificate expiry checks are useless if the clock
  is wrong.

## Why chrony over systemd-timesyncd / ntpd?

- chrony handles network discontinuities better (laptops sleep,
  bridged networks) than ntpd.
- chrony supports NTS (the modern authenticated NTP) natively;
  systemd-timesyncd does not as of mid-2026.
- chrony's `makestep` + `maxchange` directives express "step the
  clock only if it's sane" semantics that the threat model
  requires.

## Coexistence

Operator-shipped `/etc/chrony/chrony.conf` is UNTOUCHED. Our
50-selfdef.conf in conf.d composes with it. Operator-added
files at e.g. `99-operator.conf` LOAD AFTER ours and can
override individual directives if needed.

## Operator extension

The shipped drop-in has no operator-extension hook beyond
profile selection. Operators wanting custom servers, peer
configs, or NTP server (allow-from) directives drop a sibling
file at `/etc/chrony/conf.d/60-operator.conf` (lex-order after
ours). selfdef NEVER touches operator-prefixed files.
