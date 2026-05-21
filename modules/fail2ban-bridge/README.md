# fail2ban-bridge

Configures [fail2ban](https://www.fail2ban.org/) for network-side
IP-level brute-force defense. Pairs with `pam-faillock` (local-auth
account lockout) and `ssh-hardening` (sshd protocol config) as the
**IP-layer of the auth-defense triad**:

| Layer | Module | Blocks |
|---|---|---|
| Network protocol | `ssh-hardening` | Weak crypto + password auth + N-fail in sshd |
| IP (network) | `fail2ban-bridge` | Repeat-offender IPs at the firewall level (entire host) |
| Local PAM | `pam-faillock` | Local brute force (sudo, su, login, passwd) |

When all three are active, an attacker faces:
1. ssh-hardening's `MaxAuthTries=4` → 4 in-connection retries
2. fail2ban's `maxretry=5 findtime=600` → IP banned after 5 auth
   failures within 10 min, blocked at the firewall for 1h+
3. (Even if attacker rotates IPs) pam-faillock's `deny=10
   fail_interval=900` → account locked after 10 failures, regardless
   of source IP

## Profiles

| Profile | sshd jail | sshd-ddos | recidive | Ban duration |
|---|---|---|---|---|
| `standard` (default) | 5 fails / 10min | — | — | 1h |
| `broad` | 3 fails / 10min | enabled (5 connection-floods / 2min → 10min ban) | enabled (5 prior bans in 24h → 7d allports ban) | sshd: 2h, recidive: 7d |

Both profiles share:
- `backend = systemd` — reads from journald (no rsyslog required)
- `ignoreip` — loopback + IPv6-loopback + RFC1918 (operator's LAN
  is never banned)
- `banaction = nftables-multiport` — modern firewall backend
  (firewalld-compatible)

## Operator extension

`/etc/fail2ban/jail.d/60-operator-allow.conf` — additional ignoreip
entries (lex-order AFTER ours → overrides):

```
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 1.2.3.4 5.6.7.0/24
```

`/etc/fail2ban/jail.d/99-operator-*.conf` — custom operator jails
(nginx-noscript, postfix-sasl, etc.). selfdef NEVER touches
operator-prefixed files.

## MITRE coverage

- **T1110** Brute Force — primary; IP-level lockout supplements
  the per-account lockout in pam-faillock.
- **T1110.001** Brute Force: Password Guessing — same.
- **T1499** Endpoint Denial of Service — sshd-ddos jail catches
  connection-flood patterns BELOW the per-IP auth-failure threshold.
- **T1078** Valid Accounts — recidive jail (broad profile) bans
  IPs that demonstrate repeated brute-force intent across multiple
  jails over 24h.

## Operator workflow

```bash
# See current jail status + banned IPs
sudo fail2ban-client status
sudo fail2ban-client status sshd

# Inspect a specific IP's history
sudo fail2ban-client get sshd banip <IP>

# Manually unban an IP (operator-error legitimate user blocked)
sudo fail2ban-client unban <IP>

# Manually ban an IP for the current bantime
sudo fail2ban-client set sshd banip <IP>

# Clear ALL bans (rare; usually only at infrastructure rotation)
sudo fail2ban-client unban --all
```

## Coexistence with the auth-defense triad

| Failure scenario | ssh-hardening | fail2ban-bridge | pam-faillock |
|---|---|---|---|
| 10000 distributed attackers, 1 try each from unique IPs | MaxAuthTries=4 limits each connection; PasswordAuth=no forces key-only (no online guess possible) | Doesn't trigger (no single IP exceeds threshold) | pam-faillock would trigger per-account after 10 fails |
| 1 attacker, 1000 attempts from 1 IP | MaxAuthTries=4 per connection (250 reconnects) | Bans at 5 fails / 10min → blocked at firewall | Caught earlier by fail2ban |
| 1 attacker rotating IPs (botnet, ~50 IPs) | per-connection limit | Each IP burns its 5-strike → all 50 IPs banned over a few hours | pam-faillock catches after 10 fails per account total |

The defenses are complementary, not redundant. Each blocks a
different attack shape.

## When to enable broad profile

Indicators:
- `fail2ban-client status sshd` shows hundreds of bans/day → expected
  on internet-facing hosts; broad's tighter `maxretry=3` reduces
  attacker dwell time
- A specific IP / netblock keeps coming back after standard ban
  expires → recidive jail's 7-day allports ban breaks the cycle
- sshd's auth.log shows connection floods that DON'T trip the
  auth-failure filter → sshd-ddos jail catches that pattern

## Caveats

- **Backend choice**: `backend = systemd` requires
  `python3-systemd` (Debian) or `python3-systemd-journal` (RHEL).
  fail2ban falls back to `backend = auto` (which usually picks the
  right thing) if systemd lib isn't available.
- **IPv6**: nftables-multiport supports both v4 + v6; explicit IPv6
  ignoreip entries (`::1`, fd00::/8 for ULA) recommended in the
  operator-allow drop-in.
- **firewall coexistence**: nftables-multiport injects rules into
  fail2ban's own nftables table; doesn't conflict with operator
  firewall rules in separate tables (bridge-l2's selfdef-bridge
  table, etc.).
