# nscd-disable

Masks `nscd.service` (Name Service Cache Daemon) on
hosts that don't need it. nscd was the standard NSS
cache layer in pre-systemd Linux; modern hosts use
`systemd-resolved` for DNS + `sssd` for user/group
lookups, leaving nscd as either dead code or a
liability.

## Why this matters

nscd has a long history of security CVEs:

- **CVE-2024-33599** (April 2024): nscd stack-buffer
  overflow via crafted netgroup lookup — exploitable
  by any local client.
- **CVE-2024-33600**: NULL deref + DoS in nscd
  netgroup cache.
- **CVE-2024-33601 / CVE-2024-33602**: same NSCD
  netgroup component.
- **CVE-2021-3326** (iconv assertion failure
  triggerable via nscd queries).
- **CVE-2013-0288** historical stack overflow.

The pattern: nscd parses untrusted local-client input
(NSS query) in a high-privilege long-running daemon.
Every time a CVE drops, every host with nscd installed
is vulnerable. For hosts not actively benefiting from
the NSS cache, the simple defense is: turn it off.

## Profiles

| Profile | Effect |
|---|---|
| `mask` (default) | stop + disable + mask nscd.service + nscd.socket. Defeats package re-install auto-enable. |
| `stop` | stop + disable only. Operator-pull re-enable is one systemctl-start away. |

apply.sh probes for unit existence first — no-op on
hosts where nscd isn't installed (most modern distros).

## When NOT to use

- Hosts on **NIS / YP** with high lookup volume from
  many local processes — nscd is the canonical cache.
- Hosts using LDAP-NSS WITHOUT sssd — nscd may be
  caching for performance reasons; switch to sssd
  before disabling nscd.
- Hosts with custom NSS modules that explicitly
  benefit from nscd's cache (rare).

For most modern systemd-resolved + sssd hosts, nscd
is unnecessary.

## MITRE coverage

- **T1190** Exploit Public-Facing Application — narrowly;
  nscd's socket is local-AF_UNIX, not network, but it
  is reachable from any local user including
  unprivileged web-app contexts.
- **T1068** Exploitation for Privilege Escalation —
  primary; nscd CVEs (2024 family) elevate from local
  unprivileged to root.
- **T1499** Endpoint Denial of Service — CVE-2024-33600
  triggers nscd crash → NSS lookups fail → daemons
  hang or refuse connections.

## Operator workflow

```bash
# Verify nscd is silent
systemctl status nscd 2>/dev/null | grep -E 'Loaded:|Active:'
ss -lx | grep -E 'nscd|/var/run/nscd'        # expect: empty

# Verify NSS still resolves (systemd-resolved / files)
getent hosts example.com
getent passwd root

# Switch to stop profile (allows operator-pull restart)
sudo sed -i 's/^profile.*/profile = "stop"/' \
    /etc/selfdef/modules/nscd-disable.toml
sudo selfdefctl modules apply nscd-disable

# Re-enable for one-shot use (if package re-installs nscd)
sudo systemctl unmask nscd nscd.socket
sudo systemctl enable --now nscd
```

## Caveats

- **Package upgrade may re-enable** without mask
  profile. mask profile defeats this; stop profile
  does not.
- **Some older sssd configurations chain through
  nscd**. Modern sssd does not. Check `/etc/sssd/
  sssd.conf` for any nscd-routed lookups.
- **glibc still ships nscd binary** even if the
  service is masked. Vulnerable CVE class is in the
  daemon — masked = unreachable.

## Coexistence

- **dns-shield + loopback-only-dns**: complementary;
  those handle DNS-layer hardening, this handles NSS-
  cache daemon.
- **services-disable-printing + bluetooth-disable**:
  same pattern — service-mask family. All apply
  together with no conflict.
- **fail2ban-bridge + ssh-hardening**: orthogonal
  network-layer defense.
- **sysctl-network-baseline + kernel-yama-baseline**:
  orthogonal kernel-feature hardening.
