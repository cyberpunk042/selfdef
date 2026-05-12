# ATT&CK coverage

The Sigma rule set in `rules/sigma/` is tagged with [MITRE
ATT&CK](https://attack.mitre.org/) tactic and technique IDs. This page is a
human-readable summary; the canonical, machine-checked report is the
`attack_coverage_report` test in `crates/selfdef-correlator`, which prints
the live count on every CI run.

## Snapshot (auto-summarised from current rule set)

| Tactic                | Rules |
| --------------------- | ----: |
| Execution             | 1 |
| Persistence           | 7 |
| Privilege Escalation  | 7 |
| Defense Evasion       | 6 |
| Credential Access     | 3 |
| Command & Control     | 1 |
| Impact                | 3 |

**Techniques covered:** 20 (across 7 tactics).

## Technique → rule map

| Technique | Name | Rule file |
| --- | --- | --- |
| T1053.003 | Scheduled Task/Job: Cron | `persistence/cron_tamper.yml` |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | `execution/webshell_pattern.yml` |
| T1070.004 | Indicator Removal: File Deletion | `defense_evasion/selfdef_state_tamper.yml` |
| T1071.001 | Application Layer Protocol: Web Protocols | `command_and_control/suricata_alert.yml` |
| T1078.003 | Valid Accounts: Local Accounts | `discovery/sshd_publickey_accepted.yml` |
| T1098     | Account Manipulation | `persistence/sudoers_tamper.yml`, `defense_evasion/ssh_wrap_policy_strip.yml` |
| T1110     | Brute Force | `credential_access/ssh_bruteforce.yml` |
| T1136.001 | Create Account: Local Account | `persistence/new_local_account.yml` |
| T1485     | Data Destruction | `impact/destructive_dd.yml` |
| T1489     | Service Stop | `impact/security_service_stop.yml` |
| T1505.003 | Server Software Component: Web Shell | `execution/webshell_pattern.yml` |
| T1543.002 | Create or Modify System Process: Systemd Service | `persistence/systemd_service_install.yml` |
| T1548.001 | Abuse Elevation Control Mechanism: Setuid/Setgid | `persistence/setuid_binary.yml` |
| T1548.003 | Abuse Elevation Control Mechanism: Sudo | `privilege_escalation/sudo_failure.yml` |
| T1552.001 | Unsecured Credentials: Credentials in Files | `credential_access/sensitive_file_access.yml`, `credential_access/canary_access.yml` |
| T1561.001 | Disk Wipe: Disk Content Wipe | `impact/destructive_disk_tools.yml` |
| T1561.002 | Disk Wipe: Disk Structure Wipe | `impact/destructive_disk_tools.yml` |
| T1562.001 | Impair Defenses: Disable or Modify Tools | `defense_evasion/audit_rules_tamper.yml` |
| T1562.006 | Impair Defenses: Indicator Blocking | `defense_evasion/audit_rules_tamper.yml` |
| T1574.006 | Hijack Execution Flow: Dynamic Linker Hijacking | `persistence/ld_preload_tamper.yml` |

## Collectors and what they unlock

Different ATT&CK techniques require different telemetry. The matrix below
shows which collectors back the current rule set — when a rule cites a
collector, that telemetry is what makes the rule fire.

| Collector       | Powers techniques |
| --------------- | ----------------- |
| `auditd`        | T1053.003, T1098, T1110, T1136.001, T1543.002, T1548.001, T1548.003, T1562.001, T1562.006, T1574.006 |
| `journald`      | T1078.003 |
| `tetragon`      | T1059.004, T1485, T1489, T1505.003, T1552.001, T1561.001, T1561.002 |
| `selfdef.ebpf`  | T1070.004 |
| `selfdef.canary`| T1552.001 |
| `selfdef.ssh-wrap` | T1098 |
| `suricata`      | T1071.001 |

## Known gaps

The rule set deliberately stays narrow — it's better to ship 20 high-precision
techniques than 50 noisy ones. The largest open gaps are:

- **Discovery** — no rules yet for host/network enumeration patterns
  (`whoami`, `id`, `netstat`, `ss`, `arp -a`, `getent`). These are very
  noisy on multi-user hosts; needs grouping/aggregation work before it's
  worth shipping.
- **Lateral Movement** — outbound SSH from non-shell parents would be a
  good fit but needs the eventstream collector to expose process trees.
- **Exfiltration** — Suricata covers some network egress patterns via
  T1071.001 today; dedicated DNS-tunneling / large-flow rules want
  flow-aggregation in the correlator.
- **Impact** — `destructive_dd`, `destructive_disk_tools`, and
  `security_service_stop` cover the most common wiper / ransomware
  primitives (T1485, T1489, T1561.001, T1561.002). Mass file *rewrite*
  patterns (e.g. ransomware encrypting in place) need a rate-of-write
  rule against eBPF telemetry — not yet shipped.

The roadmap in `docs/src/intro.md` tracks rule-set growth.
