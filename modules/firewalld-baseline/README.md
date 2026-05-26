# firewalld-baseline

Default-deny firewalld zone baseline for RHEL / Fedora /
Rocky / AlmaLinux. The RHEL-side parallel of
`nftables-baseline` — on firewalld hosts, firewalld OWNS
the nftables ruleset, so you configure the firewall
through `firewall-cmd`, not by writing nft rules directly.
Built so it can never lock the operator out of SSH.

## Why this matters

Same rationale as nftables-baseline: a host without a
default-deny firewall exposes every listening port to the
network. On RHEL-family hosts firewalld is the default
firewall manager; fighting it by writing raw nftables
rules (as nftables-baseline does) causes conflicts. So on
those hosts, this module is the right tool — it creates a
`selfdef` zone with `target=DROP`, allows only SSH +
operator-declared services, and makes it the default zone.

`conflicts = ["nftables-baseline"]` — pick one firewall
manager per host (mirrors the apparmor/selinux mutex).

## Profiles

| Profile | Default-zone target | Allowed |
|---|---|---|
| `baseline` (default) | DROP (silent) | ssh + operator `allow_services`/`allow_ports` |
| `web` | DROP | baseline + http + https |
| `block` | %%REJECT%% (ICMP reject, more polite) | ssh + operator extras |

Operator extras in the profile TOML:
```toml
profile = "baseline"
allow_services = "cockpit,dhcpv6-client"
allow_ports = "8443/tcp,51820/udp"
```

## Anti-lockout (refuse-to-brick)

- **SSH added to the zone BEFORE it becomes default** —
  apply.sh adds `--add-service=ssh` to the `selfdef` zone,
  then sets the zone as default + reloads. The accept is
  in place before the deny takes effect.
- **check.sh verifies** the zone allows ssh and flags
  lockout risk if not.
- **Prior default zone backed up** to
  `/var/lib/selfdef/firewalld-default-zone.bak`; uninstall
  restores it (restore-then-remove, no zoneless window).

13th-gate-family anti-lockout (shared design with
nftables-baseline).

## DROP vs %%REJECT%%

- `DROP` (baseline/web) — packets silently discarded; a
  scanner sees filtered/no-response (stealthier).
- `%%REJECT%%` (block) — sends ICMP port-unreachable;
  more "polite" (apps fail fast instead of timing out) but
  confirms the host exists.

## MITRE coverage

- **T1190** Exploit Public-Facing Application — default-
  deny shrinks the reachable surface.
- **T1133** External Remote Services — only ssh +
  declared services reachable.
- **T1046** Network Service Scanning — DROP target makes
  the host quiet to scans.
- **T1571** Non-Standard Port — backdoor inbound dropped.

## Operator workflow

```bash
# Inspect
firewall-cmd --get-default-zone           # expect: selfdef
firewall-cmd --zone=selfdef --list-all

# Allow a service
sudo sed -i 's/^allow_services.*/allow_services = "cockpit"/' \
    /etc/selfdef/modules/firewalld-baseline.toml
sudo selfdefctl modules apply firewalld-baseline

# Allow a raw port
sudo firewall-cmd --permanent --zone=selfdef --add-port=8080/tcp
sudo firewall-cmd --reload

# Emergency revert (restore prior zone)
sudo selfdefctl modules uninstall firewalld-baseline
```

## Caveats

- **firewalld must be installed + running** for live
  effect; permanent config is written regardless, takes
  effect on firewalld start + reload. apply.sh warns if
  firewalld isn't running.
- **Interface zone binding**: the default zone applies to
  interfaces not explicitly bound elsewhere. If the
  operator has interfaces pinned to other zones, those
  keep their zone — review `firewall-cmd --get-active-
  zones` after apply.
- **conflicts with nftables-baseline** — running both
  means two managers fighting over nftables. Pick one.
- **Cloud images** sometimes ship firewalld disabled in
  favor of security-group filtering; on those, the
  permanent config waits until firewalld is enabled.

## Coexistence

- **nftables-baseline**: the mutually-exclusive parallel
  (declared via conflicts). firewalld-baseline on RHEL-
  family + firewalld; nftables-baseline on Debian/Ubuntu
  or firewalld-less hosts.
- **fail2ban-bridge**: complementary — fail2ban integrates
  with firewalld (its firewallcmd-* actions) to add
  dynamic bans atop this static default-deny.
- **sysctl-network-baseline**: complementary IP-layer
  sysctl hardening beneath the firewall.
- **listening-ports-watchdog + mta-loopback-detect**:
  detection complements — they flag exposed listeners;
  this drops inbound to undeclared services.
