# services-disable-printing

Masks the print + scan service set (cups, cups-browsed, saned)
on hosts that don't print or scan. Removes a class of network-
reachable attack surfaces (CUPS RCE, mDNS-leaked-printer
discovery, SANE network protocol).

## Why this matters

CUPS has a long history of security CVEs:
- **CVE-2024-47175** (September 2024): chained RCE via cups-
  browsed listening on UDP 631 — accepted attacker-supplied
  PPD which executed arbitrary commands at next print job
- **CVE-2024-47176**: cups-browsed accepts any IPP server
  announce → silently adds the attacker's printer
- Multiple earlier IPP parsing CVEs going back ~2010

Most server + IPS hosts NEVER print. Operator workstations
typically print 1-2 times per quarter. Disabling cups + cups-
browsed when unneeded eliminates the entire CVE chain without
operator-workflow impact.

saned (the SANE scanner network daemon) is similar: optional
on hosts without scanners.

## Profiles

| Profile | atd-style mask | Use |
|---|---|---|
| `mask` (default) | stop + disable + mask | Strongest; defeats package re-install Wants= auto-re-enable |
| `stop` | stop + disable only | Operator-pull occasional re-enable via systemctl start |

## Units covered

| Unit | Purpose |
|---|---|
| `cups.service` | CUPS print daemon |
| `cups.socket` | Socket activation for CUPS |
| `cups.path` | path-activation hook (.cups-something file change) |
| `cups-browsed.service` | CUPS network discovery + auto-printer-install (CVE-2024-47175 source) |
| `saned.service` | SANE network scanner daemon |
| `saned.socket` | Socket activation for SANE |
| `printer.target` | systemd umbrella target for printing |

apply.sh probes each via `systemctl list-unit-files` and only
acts on those that exist (no-op on hosts where cups + saned
are not installed).

## MITRE coverage

- **T1190** Exploit Public-Facing Application — CUPS on UDP/TCP
  631 is reachable on broadcast networks; mask removes the
  service entirely.
- **T1133** External Remote Services — cups-browsed accepts
  unauthenticated printer-share announcements from the network;
  mask removes this attack channel.
- **T1046** Network Service Scanning — defender side; the host
  no longer responds to printer discovery probes.

## Operator workflow

```bash
# Verify nothing is listening on print/scan ports
sudo ss -lntu | grep -E ':(631|6566) '
# Expected: empty output

# Verify services are masked
systemctl status cups cups-browsed saned 2>/dev/null | grep -E 'Loaded:|Active:'

# To re-enable for one-shot printing (operator-pull):
sudo systemctl unmask cups cups.socket
sudo systemctl enable --now cups
# After printing, re-disable:
sudo selfdefctl modules apply services-disable-printing
```

## Caveats

- **Operator who needs to print occasionally**: this module's
  re-enable-then-re-disable workflow is 4 commands. For
  frequent printing, skip this module + rely on fail2ban-
  bridge + ssh-hardening + audit-rules for the CUPS attack
  surface monitoring.
- **AppSocket printers** (HP JetDirect, etc.) bypass cups
  entirely and talk to printers via the printer's own TCP
  9100 port. Operators using these aren't affected by
  cups+cups-browsed disable.
- **LPD (port 515)** is a separate legacy protocol; not handled
  by this module. Most modern distros don't install lpd.

## Coexistence

- **fail2ban-bridge**: would catch network-side CUPS brute-
  force if cups WERE running. With cups masked, fail2ban has
  nothing to catch on port 631.
- **kernel-lockdown**: orthogonal to service-level disable.
- **package-trust-baseline**: ensures CUPS itself (when
  installed) ships only signed packages. Defense-in-depth even
  on hosts that ARE using printing.
