# polkit-rules-watchdog

Boot + daily delta of the admin/local polkit authorization rules
(modern JS `.rules` + legacy `.pkla`) against a learned baseline,
plus an ownership + grant scan. Catches a rogue rule that grants
privilege escalation. MITRE **T1548** (Abuse Elevation Control
Mechanism).

## Why this matters

`polkitd` evaluates these rules **as root** to decide whether a
subject may perform a privileged action (mount, install
packages, manage units, reboot, …). A rogue rule grants privilege
escalation to an unprivileged user:

```javascript
// /etc/polkit-1/rules.d/99-evil.rules  (modern JS)
polkit.addRule(function(action, subject) {
    return polkit.Result.YES;          // any action, any subject
});
```

```ini
# /etc/polkit-1/localauthority/50-local.d/evil.pkla  (legacy)
[allow]
Identity=unix-user:*
Action=*
ResultActive=yes
```

Both let any local user run any polkit action as root — quiet
privilege-escalation persistence. These admin dirs are sparsely
populated, so a new rule is high-signal.

## Watched directories

| Directory | Watched | Why |
|---|---|---|
| `/etc/polkit-1/rules.d/*.rules` | **yes** | admin JS rules |
| `/usr/local/share/polkit-1/rules.d/*.rules` | **yes** | local JS rules |
| `/run/polkit-1/rules.d/*.rules` | **yes** | runtime |
| `/etc/polkit-1/localauthority/{50-local,90-mandatory}.d/*.pkla` | **yes** | legacy local authority |
| `/var/lib/polkit-1/localauthority/.../*.pkla` | **yes** | legacy local authority |
| `/usr/share/polkit-1/rules.d` | **no** | package-managed; integrity-sentinel covers it |

No-ops cleanly if none exist (`event:no_polkit_rules`).

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any polkit-rules change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No polkit rule dirs present | `ok` | `no_polkit_rules` |
| No delta | `ok` | `polkit_rules_intact` |
| A rule changed or removed | `warn` | `polkit_rules_changed` |
| A NEW rule file, or a NEW grant (Result.YES / ResultActive=yes) | `alert` | `polkit_rules_new` |
| A rule world-writable / non-root-owned | `alert` | `polkit_rules_suspicious` |

"New" is computed on file PATHS (a content edit of an existing
rule is `warn`, not `new`).

## What's recorded

- `file:<path>:<sha12>` — hash of each `.rules` / `.pkla` file.
- `own:<path>:<owner:mode>` — owner + mode (world-writable /
  non-root = hijackable).
- `grant:<path>:YES` — the file grants authorization
  (`polkit.Result.YES` or a `.pkla` `Result*=yes`); a NEW grant
  is alert-grade.

## Cadence

`OnBootSec=23min` + `OnCalendar=*-*-* 08:00:00` — extends the
staggered ladder after limits-conf (07:55). polkitd reloads
rules dynamically, so a dropped rule is live immediately; the
boot catch confirms the set after a restart.

## MITRE coverage

- **T1548** Abuse Elevation Control Mechanism — PRIMARY; a
  permissive polkit rule is an elevation-control abuse.
- **T1098** Account Manipulation (adjacent) — granting a user
  blanket privileged-action authority.
- **T1543** Create or Modify System Process — many polkit
  actions manage systemd units / services.

## Operator workflow

```bash
journalctl -t selfdef-polkit-rules -n 1 --no-pager
journalctl -t selfdef-polkit-rules-detail --since "1 day ago"

# Inventory
ls -la /etc/polkit-1/rules.d/ \
       /etc/polkit-1/localauthority/*/ 2>/dev/null
grep -rnE 'Result\.YES|ResultActive|ResultAny' \
     /etc/polkit-1/rules.d/ /etc/polkit-1/localauthority/ 2>/dev/null

# Investigate a new/suspicious rule
cat <rule>            # does it grant YES without a real guard?
sudo rm <rule>
sudo rm /var/lib/selfdef/polkit-rules-baseline.tsv
sudo systemctl start selfdef-polkit-rules.service
```

## Caveats

- **Legit admin polkit rules exist** (e.g. allowing a sysadmin
  group to manage units). A new such rule fires `alert` (new)
  once; re-baseline after vetting. The grant scan is informational
  for the operator to confirm the GUARD is real (`isInGroup`,
  `subject.active`, a specific `action.id`), not blanket.
- **The grant heuristic flags presence of YES, not whether it is
  guarded** — a YES inside a proper `isInGroup` check is legit;
  the alert is the prompt to verify the guard, and the delta
  (warn on any change) is the backstop.
- **Daily+boot cadence** misses an inject-act-revert within the
  window; an audit-rules watch on the polkit dirs' writes is the
  real-time complement.

## Coexistence

- **sudoers-integrity-watchdog**: the sudo privilege-grant
  surface; polkit is the parallel D-Bus/desktop-service authority
  (pkexec, systemctl-via-polkit, package managers). Both elevation
  paths worth watching.
- **account-watchdog / group-integrity-watchdog**: who exists +
  group membership (which polkit rules often key on); this watches
  the authorization rules themselves.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the rule files; this adds the new-file + ownership + grant
  semantic view.
