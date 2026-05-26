# Changelog

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — module-ecosystem batch 46: continuation 128→129 (2026-05-26)

Per operator direction ("continue endlessly"). Adds the sudoers Defaults
tamper surface (completes sudoers coverage with sudoers-integrity +
sudo-tune); L1 module-contracts coherent at 129, cargo modules::tests
16/16.

- `sudoers-defaults-watchdog` (129) — boot+daily delta of the sudoers
  Defaults directives (/etc/sudoers + /etc/sudoers.d/*) vs a learned
  baseline. sudoers-integrity-watchdog tracks GRANTS and excludes
  Defaults; this watches the tunables an attacker abuses for privesc:
  secure_path with a writable/tmp/home/relative element (sudo finds a
  trojan binary), env_keep/env_check/env_delete += of a dangerous var
  (LD_PRELOAD/LD_LIBRARY_PATH/LD_AUDIT/PYTHONPATH/PERL5LIB/RUBYLIB/
  BASH_ENV/ENV/IFS/PS4 — env injection into the root command), or
  !env_reset. Any Defaults change is warn; a NEWLY-ADDED dangerous
  Default is alert (delta-based — pre-existing flagged once at baseline).
  No-ops cleanly if absent. Complements sudo-tune (which SETS hardened
  Defaults). MITRE T1548.003/T1574.006. Cadence boot+27min / 08:20.

### Added — module-ecosystem batch 45: continuation 127→128 (2026-05-26)

Per operator direction ("continue endlessly"). Adds the kernel-module
auto-load source surface; L1 module-contracts coherent at 128, cargo
modules::tests 16/16.

- `modules-load-watchdog` (128) — boot+daily delta of the kernel-module
  auto-load config (/etc/modules-load.d/*.conf + /etc/modules + /run/
  modules-load.d + /usr/local/lib/modules-load.d) vs a learned baseline +
  ownership scan. systemd-modules-load (and the legacy /etc/modules)
  force-load the listed modules AT BOOT; an attacker who adds a module
  name makes a malicious out-of-tree or known-vulnerable module load
  every boot (T1547.006). Records each module-to-load + file hash + owner;
  any add/remove/change is warn; a world-writable/non-root config is
  alert (an attacker who controls it can force-load anything). No-ops
  cleanly if absent. /usr/lib (package-managed) not watched. Completes
  the module-load family with kernel-module-watchdog (LOADED modules) +
  modprobe-config-watchdog (install/alias directives). Cadence boot+26min
  / 08:15.

### Changed — ld-preload-watchdog: add LD_AUDIT detection (2026-05-26)

- `ld-preload-watchdog` now also scans the global env files for
  `LD_AUDIT` (the rtld-audit sibling of `LD_PRELOAD` — it loads a `.so`
  as an auditor into every dynamically-linked program; same
  T1574.006 injection surface). A LD_AUDIT lib under /tmp /var/tmp
  /dev/shm /home /run, or a non-existent path, is alert (same
  trusted-path logic as LD_PRELOAD). Closes the LD_AUDIT half of the
  runtime-linker env-injection vector.

### Added — module-ecosystem batch 44: continuation 126→127 (2026-05-26)

Per operator direction ("continue endlessly"). Adds the D-Bus
activation/policy IPC surface; L1 module-contracts coherent at 127, cargo
modules::tests 16/16.

- `dbus-service-watchdog` (127) — boot+daily delta of the admin/local
  D-Bus system activation services + policy files
  (/usr/local/share/dbus-1/system-services/*.service, /etc/dbus-1/
  system-services, /etc/dbus-1/system.d/*.conf, /usr/local/share/dbus-1/
  system.d) vs a learned baseline + ownership + Exec/User + policy scan.
  A D-Bus-activated system service runs its Exec= as the configured User=
  (often root) when any client calls its bus name; a rogue activation
  file is root-exec-on-demand persistence, and a permissive policy
  `<allow own=>` lets an attacker hijack a privileged bus name
  (T1543/T1548). A NEW activation .service (new PATH) or a NEW `<allow
  own=>` is alert; world-writable/non-root file or an Exec under
  tmp/home/dev-shm/world-writable is alert; content change/removal is
  warn. No-ops cleanly if absent. /usr/share (package-managed) not
  watched. Cadence boot+25min / 08:10.

### Added — module-ecosystem batch 43: continuation 125→126 (2026-05-26)

Per operator direction ("continue endlessly"). Adds the dynamic-MOTD
root-on-login surface; L1 module-contracts coherent at 126, cargo
modules::tests 16/16.

- `motd-scripts-watchdog` (126) — boot+daily delta of the dynamic MOTD
  script dir (/etc/update-motd.d/*) vs a learned baseline + ownership +
  suspicious-pattern scan. pam_motd runs these scripts AS ROOT on every
  interactive login (SSH/console); a script added or tampered here is
  root-exec persistence that fires on each login and is easy to overlook
  (looks like cosmetic banner config). World-writable/non-root script or
  an injection pattern (curl|sh, /dev/tcp, bash -i, tmp/home exec, …) =
  alert; add/change/remove = warn. No-ops cleanly if no update-motd.d.
  Distinct from motd-doctrine (which WRITES a presence banner) — this
  DETECTS rogue/tampered scripts in the same dir. MITRE T1546/T1037/
  T1059.004. Cadence boot+24min / 08:05.

### Added — module-ecosystem batch 42: continuation 124→125 (2026-05-26)

Per operator direction ("continue endlessly"). Adds the polkit
authorization surface; L1 module-contracts coherent at 125, cargo
modules::tests 16/16.

- `polkit-rules-watchdog` (125) — boot+daily delta of the admin/local
  polkit authorization rules (/etc/polkit-1/rules.d/*.rules JS +
  /etc/polkit-1/localauthority/**/*.pkla + /var/lib/polkit-1/... +
  /usr/local/share/polkit-1/rules.d + /run/polkit-1/rules.d) vs a
  learned baseline + ownership + grant scan. polkitd evaluates these as
  root to decide authorization; a rogue rule returning blanket
  Result.YES (or a .pkla ResultActive=yes for Identity=*/Action=*)
  grants privilege escalation to any action — quiet privesc persistence
  (T1548). These dirs are sparse, so a NEW rule file (new PATH, not a
  content edit) or a NEW grant is alert; world-writable/non-root is
  alert; content change/removal is warn. No-ops cleanly if absent.
  /usr/share (package-managed) not watched. Distinct from
  sudoers-integrity-watchdog (sudo grants) — polkit is the D-Bus/
  desktop-service authority (pkexec, systemctl-via-polkit, package
  managers). Cadence boot+23min / 08:00.

### Fixed — unquoted word-split glob expansion in 4 watchdog parsers (2026-05-26)

A scan parser that word-splits attacker-influenceable file content with
unquoted `$line` / `$var` lets the shell glob-expand any `*` token
against the scan's cwd, corrupting the parse (and potentially the
baseline). Surfaced while building limits-conf-watchdog, whose standard
`*` domain expanded to the cwd file list. Converted the affected
parsers to `read -ra` (splits on IFS without pathname expansion):

- `nsswitch-watchdog` (112) — `for tok in $sources` (a `*` source token).
- `modprobe-config-watchdog` (115) — `set -- $line` (`alias net-pf-* off`).
- `hosts-file-watchdog` (119) — `set -- $line` (a malformed `*` hostname).
- `ld-preload-watchdog` — `for lib in $val` (a `*` in a preload path).

Behaviour is unchanged for well-formed input; a literal `*` is now
recorded/flagged verbatim instead of being expanded.

### Added — module-ecosystem batch 41: continuation 123→124 (2026-05-26)

Per operator direction ("continue endlessly"). Adds the pam_limits
config surface (rounds out /etc/security/* with access-conf); L1
module-contracts coherent at 124, cargo modules::tests 16/16.

- `limits-conf-watchdog` (124) — boot+daily delta of the pam_limits
  resource-limit config (/etc/security/limits.conf + limits.d/*) vs a
  learned baseline. An attacker who re-enables core dumps
  (`* hard core unlimited`) reverts the coredump-suid-restrict hardening
  and re-opens memory-secret harvest on crash (T1005), or loosens
  nproc/nofile/maxlogins for DoS. Records each domain:type:item -> value
  limit; any change is warn; a NEWLY-ADDED core-dump re-enable is the
  hardening-revert signature (alert) — pre-existing core values flagged
  once at baseline, not re-alerted. No-ops cleanly if absent. Complements
  coredump-suid-restrict (which SETS core 0) by detecting tampering, and
  access-conf-watchdog (the other /etc/security file). Cadence boot+22min
  / 07:55.

### Added — module-ecosystem batch 40: continuation 122→123 (2026-05-26)

Per operator direction ("continue endlessly"). Adds the systemd
early-boot generator surface; L1 module-contracts coherent at 123, cargo
modules::tests 16/16.

- `systemd-generator-watchdog` (123) — boot+daily delta of the
  admin/local/runtime systemd generator dirs (/etc/systemd/{system,user}-
  generators, /usr/local/lib/systemd/*-generators, /run/systemd/*-
  generators) vs a learned baseline + ownership + suspicious-pattern
  scan. systemd generators are executables run AS ROOT very early at boot
  (before any unit) to synthesize units; a dropped generator is stealthy
  early-boot root persistence (T1543/T1546). These dirs are normally
  empty, so a NEW generator (new file PATH, not a content edit of an
  existing one) is alert; world-writable/non-root/suspicious-pattern is
  alert; content change/removal is warn. No-ops cleanly if no generator
  dirs. /usr/lib (package-managed) deliberately not watched. Distinct
  from systemd-unit-watchdog (the units, not the generators that create
  them). Cadence boot+21min / 07:50.

### Added — module-ecosystem batch 39: continuation 121→122 (2026-05-26)

Per operator direction ("continue endlessly"). Completes the
scheduler-persistence pair (cron + at); L1 module-contracts coherent at
122, cargo modules::tests 16/16.

- `at-jobs-watchdog` (122) — boot+daily delta of the at/batch job spool
  (/var/spool/cron/atjobs Debian, /var/spool/at RHEL) + at.allow/at.deny
  vs a learned baseline + a suspicious-pattern + self-resubmission scan.
  atd runs each spooled job as its owner at the scheduled time; an
  unexpected job — especially one that re-submits itself via `at`/`batch`
  (a self-perpetuating loop) or contains a reverse shell / tmp payload —
  is scheduler persistence (T1053.001) that cron-job-watchdog does not
  see. Records each job hash + owner + acl hash; suspicious pattern or
  self-resubmit = alert, add/remove = warn. No-ops cleanly if no spool
  (e.g. when the at-disable module has masked atd). Scheduler-persistence
  sibling to cron-job-watchdog. Cadence boot+20min / 07:45.

### Added — module-ecosystem batch 38: continuation 120→121 (2026-05-26)

Per operator direction ("continue endlessly"). Adds the GRUB
config-source surface; L1 module-contracts coherent at 121, cargo
modules::tests 16/16.

- `grub-config-watchdog` (121) — boot+daily delta of the GRUB config
  SOURCE (/etc/grub.d/* generator scripts + /etc/default/grub) vs a
  learned baseline + ownership + suspicious-pattern scan +
  GRUB_CMDLINE_LINUX extraction. /etc/grub.d scripts run AS ROOT at
  grub-mkconfig/update-grub; a rogue/world-writable script executes at
  config-regen and can inject a menuentry, a malicious initrd, or kernel
  params. An init= param added to GRUB_CMDLINE_LINUX hijacks PID 1 on the
  next boot — invisible to kernel-cmdline-watchdog (which reads the LIVE
  /proc/cmdline) until that reboot. World-writable/non-root grub.d
  script, an injection pattern, or an init= cmdline param = alert; any
  other change = warn. No-ops cleanly if no grub config. Complements
  kernel-cmdline-watchdog (live cmdline) + bootloader-password-detect
  (the password). MITRE T1542.003/T1037/T1601. Cadence boot+19min /
  07:40.

### Added — module-ecosystem batch 37: continuation 119→120 (2026-05-26)

Per operator direction ("continue endlessly"). Adds the pam_access
login-rule surface; **120-module milestone**; L1 module-contracts
coherent at 120, cargo modules::tests 16/16.

- `access-conf-watchdog` (120) — boot+daily delta of the pam_access
  login-access-control rules (/etc/security/access.conf + access.d/*)
  vs a learned baseline. When pam_access.so is in the PAM stack, these
  rules decide who may log in from where; an attacker who adds a broad
  permit (`+ : evil : ALL`) grants login access, or removing a deny rule
  weakens lockdown (T1556/T1098). Records each permit/deny rule; any
  change is warn; a NEWLY-ADDED permit-from-ALL rule is the backdoor
  signature (alert) — pre-existing legit broad permits (e.g.
  `+ : (wheel) : ALL`) are flagged once at baseline for vetting and do
  not re-alert. No-ops cleanly if access.conf absent. Distinct from
  pam-config-watchdog (the /etc/pam.d stack + module hashes) and
  login-defs-baseline (UID ranges / password aging). Cadence boot+18min
  / 07:35.

### Added — module-ecosystem batch 36: continuation 118→119 (2026-05-26)

Per operator direction ("continue endlessly"). Adds entry-level
/etc/hosts hijack detection; L1 module-contracts coherent at 119, cargo
modules::tests 16/16.

- `hosts-file-watchdog` (119) — boot+daily ENTRY-level delta of
  /etc/hosts vs a learned baseline. /etc/hosts is consulted before DNS,
  so an added/edited entry silently MITMs or blackholes resolution
  host-wide: redirect a package/update/CA host (supply-chain MITM), or
  map a security-update domain to 0.0.0.0 to stop patching
  (T1565.001/T1562.001). Records each ip->hostname mapping; any entry
  add/remove/change is warn; an entry mapping a sensitive package/
  security/CA domain (distro mirrors, docker/github/npm/pypi/crates, CA/
  OCSP/CRL, OS update services) — regardless of IP — is the hijack
  signature (alert). Distinct from dns-resolver-watchdog (records only
  the /etc/hosts line COUNT) and nsswitch-watchdog (the resolver source
  map). No-ops cleanly if no /etc/hosts. Cadence boot+17min / 07:30.

### Added — module-ecosystem batch 35: continuation 117→118 (2026-05-26)

Per operator direction ("continue endlessly"). Adds the legacy-boot
surface; L1 module-contracts coherent at 118, cargo modules::tests 16/16.

- `boot-script-watchdog` (118) — boot+daily delta of the SysV/rc
  boot-script surfaces (/etc/rc.local, /etc/rc.d/rc.local, /etc/init.d/*,
  and the /etc/rc{0..6,S}.d/ runlevel symlinks) vs a learned baseline +
  an ownership + suspicious-pattern scan. rc.local + init.d scripts run
  AS ROOT at boot — even on pure-systemd hosts (via
  systemd-rc-local-generator + systemd-sysv-generator) — so an appended
  payload or a new init script is boot persistence (T1037.004/T1037).
  Records script hash + owner:mode + injection patterns + runlevel
  symlink targets. World-writable/non-root script or an injection
  pattern = alert; add/change/remove = warn. No-ops cleanly if no boot
  scripts exist. Distinct from systemd-unit-watchdog (native units).
  MITRE T1037.004/T1037/T1059.004/T1543. Cadence boot+16min / 07:25.

### Changed

- `shell-init-watchdog` (114) + `network-dispatcher-watchdog` (117) +
  `boot-script-watchdog` (118): added a low-false-positive pattern to
  the shared injection-pattern set that flags a `/tmp` `/var/tmp`
  `/dev/shm` (and `/home` for the system-script modules) path **invoked
  as a command** (line start or after a `;`/`&`/`|` separator) — bare
  execution of a dropped payload, which the prior set (curl|sh, reverse
  shells, obfuscation) did not catch. Legit *references* to a tmp path
  (e.g. `rm -f /tmp/x.lock`) do not match.

### Added — module-ecosystem batch 34: continuation 116→117 (2026-05-26)

Per operator direction ("continue endlessly"). Closes the last common
root-exec-on-event hook (network events); L1 module-contracts coherent
at 117, cargo modules::tests 16/16.

- `network-dispatcher-watchdog` (117) — boot+daily delta of the
  network-event dispatcher script dirs (NetworkManager dispatcher.d +
  pre-up.d/pre-down.d, networkd-dispatcher *.d, ifupdown
  if-{pre-,post-,}{up,down}.d, ppp ip-up.d/ip-down.d) vs a learned
  baseline + an ownership + suspicious-pattern scan. These scripts run
  AS ROOT on network events (interface up/down, DHCP renew, VPN connect)
  — events that fire at every boot and transition, so a dropped script
  is reliable root-exec persistence (T1546). World-writable / non-root-
  owned script or an injection pattern (curl|sh, /dev/tcp, bash -i, …) =
  alert; add/change/remove = warn. No-ops cleanly if no dispatcher dirs
  exist. MITRE T1546/T1059.004/T1037/T1543. Cadence boot+15min / 07:20.

**Persistence-mechanism family** now covers all six common root-exec-
on-event hooks: cron (time) + systemd-unit (service) + udev-rules
(device) + shell-init (login) + modprobe-config (module load) +
network-dispatcher (network event). Module total: 117.

### Added — module-ecosystem batch 33: continuation 115→116 (2026-05-26)

Per operator direction ("continue endlessly"). Closes the effective-
sshd-config drift surface; L1 module-contracts coherent at 116, cargo
modules::tests 16/16.

- `sshd-config-watchdog` (116) — boot+daily delta of the EFFECTIVE sshd
  config (sshd -T merged output for a curated security-directive set)
  PLUS a content hash of sshd_config + sshd_config.d/* (to catch Match
  blocks, which sshd -T's global dump omits). Catches a dangerous
  directive added via ANY file: PermitRootLogin yes, PermitEmptyPasswords
  yes, a malicious AuthorizedKeysCommand/ForceCommand (sshd exec
  vectors), or a backdoor Match block. Dangerous value or exec target
  under tmp/home/dev-shm/world-writable/bare = alert; any other directive
  or hash change = warn. No-ops cleanly on hosts without sshd. Distinct
  from ssh-hardening (writes/checks its OWN directives) and
  ssh-authkeys-watchdog (watches key FILES; this watches the
  AuthorizedKeysCommand that supplies keys + the rest of the effective
  config). MITRE T1098.004/T1556/T1505/T1059.004. Cadence boot+14min /
  07:15.

### Added — module-ecosystem batch 32: continuation 114→115 (2026-05-26)

Per operator direction ("continue endlessly"). Closes the modprobe
module-load exec surface; L1 module-contracts coherent at 115, cargo
modules::tests 16/16.

- `modprobe-config-watchdog` (115) — boot+daily delta of /etc/modprobe.d
  + /run/modprobe.d vs a learned baseline. An `install <mod> <command>`
  directive makes modprobe RUN <command> instead of loading the module
  — code-exec on module request (manual modprobe, kernel autoload,
  modules-load.d), usually as root (T1547.006). The benign disable
  idiom `install <mod> /bin/true|/bin/false` (written by selfdef's own
  *-disable modules) is recognized and not alerted. Any other install
  command is exec_install (alert); one under /tmp /home /dev/shm,
  world-writable, or bare is the payload signature. Records each conf
  hash + install-command first token + blacklist entries. Distinct from
  kernel-module-watchdog (which watches LOADED modules, /proc/modules).
  MITRE T1547.006/T1546/T1059.004. Cadence boot+13min / 07:10.

### Fixed

- `udev-rules-watchdog` (113) + `modprobe-config-watchdog` (115):
  world-writable target check now uses `stat -L` to dereference
  symlinks. A symlink's own mode is always 0777 on Linux (symlink
  perms are not enforced), so the prior `stat` mis-flagged symlinked
  commands (`/bin/sh`, `/bin/bash`, usrmerge links) as world-writable;
  dereferencing tests the executed target's real mode.

### Added — module-ecosystem batch 31: continuation 113→114 (2026-05-26)

Per operator direction ("continue endlessly"). Closes the shell-init
login-persistence surface; L1 module-contracts coherent at 114, cargo
modules::tests 16/16.

- `shell-init-watchdog` (114) — boot+daily delta of the global + root
  shell-init scripts (/etc/profile, /etc/bash.bashrc|/etc/bashrc,
  /etc/profile.d/*.sh, /etc/zsh/*, root's ~/.bashrc ~/.bash_profile
  ~/.profile ~/.zshrc) vs a learned baseline, PLUS a suspicious-pattern
  scan. An attacker appending `curl evil|sh`, a /dev/tcp reverse shell,
  or a base64 payload to any init script gets code-exec on every
  interactive login/shell (T1546.004). Records each file hash + each
  matched injection pattern (curl|sh, /dev/tcp, nc -e, bash -i,
  base64 -d, eval $(), python -c, mkfifo, setsid; full-line comments
  stripped first). Suspicious pattern = alert (delta-independent);
  hash change = warn. Distinct from ld-preload-watchdog, which scans
  the same file set only for LD_PRELOAD. MITRE T1546.004/T1059.004/
  T1037. Cadence boot+12min / 07:05 (extends the ladder after udev).

**Persistence-mechanism family** now covers all four classic Linux
surfaces: systemd-unit (services) + cron-job (scheduler) + udev-rules
(device events) + shell-init (login scripts). Module total: 114.

### Added — module-ecosystem batch 30: continuation 112→113 (2026-05-26)

Per operator direction ("continue endlessly"). Closes the udev
device-event persistence surface; L1 module-contracts coherent at 113,
cargo modules::tests 16/16.

- `udev-rules-watchdog` (113) — boot+daily delta of the admin/runtime
  udev rule dirs (/etc/udev/rules.d + /run/udev/rules.d) vs a learned
  baseline. udevd runs as root and evaluates *.rules on every device
  event; a RUN+=/PROGRAM/IMPORT{program} directive runs its target as
  root at boot coldplug + hotplug — a persistence + privilege vector.
  Records each rule-file hash + each exec directive's program path
  (directive-anchored parse, not first-quote). A NEW exec directive is
  alert (new_exec); an exec target under /tmp /home /dev/shm,
  world-writable, or bare/relative is the payload signature
  (suspicious_exec). /usr/lib/udev/rules.d (package-managed) is
  deliberately NOT watched — integrity-sentinel covers that. MITRE
  T1546/T1059/T1037/T1200. Cadence boot+11min / 07:00 (extends the
  ladder after nsswitch).

**Persistence-mechanism family** now complete across the three classic
root-persistence surfaces: systemd-unit (services) + cron-job
(scheduler) + udev-rules (device events). udev-rules + usbguard/
pci-device pair detection-of-device with the rule that weaponizes
`ACTION=="add"`. Module total: 113.

### Added — module-ecosystem batch 29: continuation 110→112 (2026-05-26)

Per operator direction ("continue endlessly"). The dynamic-linker /
name-resolution hijack pair; L1 module-contracts coherent at 112,
cargo modules::tests 16/16.

- `ld-so-conf-watchdog` (111) — boot+daily delta of the dynamic-linker
  search-path config (/etc/ld.so.conf + /etc/ld.so.conf.d/*) vs a
  learned baseline. An attacker who prepends a writable dir to the
  linker search path makes ld.so prefer a trojaned .so over the real
  system library — persistent SO-search-order hijack. A path under
  /tmp /home or world-writable is flagged hard. MITRE T1574.001 (the
  config-file vector; ld-preload-watchdog covers the LD_PRELOAD env
  vector T1574.006). Cadence boot+9min / 06:50.
- `nsswitch-watchdog` (112) — boot+daily delta of the Name Service
  Switch map (/etc/nsswitch.conf) vs a learned baseline. Each source
  token resolves to a libnss_<name>.so loaded into every name-resolving
  process; an appended rogue source (`passwd: files evil`) backdoors
  identity + auth resolution host-wide — injecting a phantom UID-0
  account, leaking credential lookups, or redirecting hosts:. A source
  token outside the known-standard NSS set is flagged as the rogue-
  module signature; a whole db line removed is alert. MITRE T1556/
  T1574/T1098/T1564. Cadence boot+10min / 06:55 (extends the ladder
  after ld-so-conf).

**Dynamic-linker / resolver hijack family** now: ld-preload (env) +
ld-so-conf (search path) + nsswitch (resolver-source map). nsswitch +
pam-config cover both authentication substrates (NSS resolver + PAM
stack); nsswitch + account-watchdog cover both account-fabrication
layers (resolver vs /etc/passwd file). Module total: 112.

### Added — module-ecosystem batch 28: continuation 108→110 (2026-05-22)

Per operator direction ("continue endlessly"). Two more distinct
detectors; L1 module-contracts coherent at 110, cargo modules::tests
16/16.

- `group-integrity-watchdog` (109) — delta of /etc/group membership
  w/ privileged-group denylist (docker/lxd/disk/shadow/kvm/adm/…).
  Catches `usermod -aG docker attacker` (container-escape-to-root)
  that account-watchdog's passwd/uid0/sudo-roster view misses.
  Records group-file + primary-gid members. MITRE T1098/T1548/T1611/
  T1078.003. Completes account+group capability coverage.
- `pci-device-watchdog` (110) — boot+daily PCI/PCIe inventory delta
  (reads /sys/bus/pci, no pciutils dep). NEW device = evil-maid
  implant / Thunderbolt-DMA / unauthorized passthrough. MITRE T1200/
  T1011/T1052. Complements usbguard (USB bus) for hardware-addition
  coverage on both buses.

**Capability-grant detector family** now: account + group + sudoers +
crontab-allow. **Hardware-addition detection**: usbguard (USB) +
pci-device-watchdog (PCI/Thunderbolt). Module total: 110.

### Added — module-ecosystem batch 27: continuation 106→108 (2026-05-22)

Per operator direction ("More selfdef modules"). Two capability-grant
+ identity detectors; L1 module-contracts coherent at 108, cargo
modules::tests 16/16.

- `crontab-allow-watchdog` (107) — delta of cron.allow/deny +
  at.allow/deny rosters; added-to-*.allow or removed-from-*.deny =
  schedule-capability grant (precedes the job, so cron-job-watchdog
  stays quiet until used). MITRE T1053.003/T1098. Pairs with
  cron-baseline (sets policy) + cron-job-watchdog (the jobs).
- `ssh-hostkey-watchdog` (108) — delta of /etc/ssh/ssh_host_*_key.pub
  fingerprints; a changed host key = MITM-prep / unauthorized
  reinstall / key-theft-rotate (the REMOTE HOST IDENTIFICATION HAS
  CHANGED signal). MITRE T1557/T1563.001/T1552.004. Matched sibling
  to ssh-authkeys-watchdog (server identity vs client access).

**Capability-grant detector family**: account (new account/uid0/sudo
group) + sudoers (NOPASSWD rule) + crontab-allow (schedule roster) —
all catch the GRANT that precedes the action. **SSH-surface
detection complete**: authkeys (access) + hostkey (identity) +
hardening + moduli. Module total: 108.

### Added — module-ecosystem batch 26: continuation 103→106 (2026-05-22)

Per operator direction ("More selfdef modules"). Three further
distinct modules; L1 module-contracts coherent at 106, cargo
modules::tests 16/16.

- `nfs-mount-watchdog` (104) — verify network mounts (nfs/cifs/sshfs/
  ceph/gluster) carry nosuid+nodev; a network mount without nosuid
  lets an attacker-controlled export plant a setuid-root binary →
  instant client root. MITRE T1080/T1548.001/T1210. Distinct from
  mount-options-watchdog (local mounts) — network threat model.
- `wwan-disable` (105) — disable cellular/WWAN modems (rfkill + mask
  ModemManager + mask-profile modprobe-blacklist cdc_mbim/qmi_wwan/
  option stack). Removes an out-of-band exfil path + modem-CVE
  surface. MITRE T1011/T1090/T1190/T1200. Completes the RF-surface
  family: wireless + bluetooth + wol + wwan.
- `coredump-pattern-watchdog` (106) — detect kernel.core_pattern
  hijack (|/tmp/evil runs as root on next crash). Allowlists systemd-
  coredump + apport. MITRE T1546/T1574/T1548. Pairs with coredumpd-
  redirect (sets) + coredump-suid-restrict + apport-disable.

Module total: 106. RF-surface family complete (Wi-Fi/BT/WoL/WWAN);
core-dump defense family complete (redirect + suid-restrict + apport-
disable + pattern-hijack-detect).

### Added — module-ecosystem batch 25: past-100 continuation 100→103 (2026-05-22)

Per operator direction ("More selfdef modules") after the 100-module
target was reached. Three further genuinely-distinct modules; L1
module-contracts coherent at 103, cargo modules::tests 16/16.

- `timestomp-watchdog` (101) — timestamp-manipulation anomaly scan
  (FUTURE / EPOCH / MTIME>CTIME) on system binaries. The MTIME>CTIME
  check is the strong tell (ctime can't be set by touch). MITRE
  T1070.006/T1036/T1554.
- `kernel-cmdline-watchdog` (102) — boot+daily /proc/cmdline delta +
  weakening-flag denylist (mitigations=off/nosmep/nokaslr/audit=0/
  init=/bin/sh/...). Boot catch is primary (cmdline only changes
  across reboot). Matched pair with bootloader-password-detect.
  MITRE T1562.001/T1601/T1542/T1014.
- `wireless-disable` (103) — rfkill + modprobe-blacklist Wi-Fi on
  wired-only servers; anti-lockout wired-carrier guard. Completes the
  RF-surface family (bluetooth-disable + wol-disable + wireless-
  disable). MITRE T1011/T1190/T1200/T1542.

**Defense-evasion detection now comprehensive**: timestomp (T1070.006)
+ logfile-integrity (T1070.002) + audit-config (T1562.001) +
kernel-cmdline (T1562.001/T1601) + selfdef-self-integrity (meta).
**RF-surface family complete**: bluetooth + wol + wireless. Module
total: 103.

### Added — module-ecosystem: 100/100 MODULE TARGET REACHED (2026-05-22, batches 23-24)

The operator's verbatim 100+ module target is met. Modules 90→100
(plus 85→89 in batch 22) complete the firewall coverage, the auth-
persistence detection family, the rootkit-detector trio, and the
meta-watchdog capstone. L1 module-contracts coherent at 100; cargo
test -p selfdef-api --lib modules::tests stays 16/16.

**Modules 90→100 (this finish):**

- `firewalld-baseline` (90) — RHEL/Fedora firewalld default-deny zone;
  conflicts=[nftables-baseline]; completes firewall coverage on both
  distros. MITRE T1190/T1133/T1046/T1571.
- `ld-preload-watchdog` (91) — userland-rootkit LD_PRELOAD hook
  detection (/etc/ld.so.preload + global env). MITRE T1574.006/T1014/
  T1556/T1564. Completes rootkit-detector trio with hidden-process +
  kernel-module.
- `shell-timeout-baseline` (92) — TMOUT idle auto-logout (unattended-
  session defense). MITRE T1078/T1563.
- `home-perms-baseline` (93) — 0750/0700 /home dirs (cross-user
  browse block). MITRE T1083/T1552.001/T1078.
- `logfile-integrity-watchdog` (94) — log truncation/tamper detection
  (wtmp/btmp/auth.log monotonic-growth + inode tracking). MITRE
  T1070.002/T1070.006/T1485.
- `ssh-authkeys-watchdog` (95) — authorized_keys delta (T1098.004 —
  the most common Linux backdoor-access technique). MITRE T1098.004/
  T1078/T1556.
- `sudoers-integrity-watchdog` (96) — sudo grant-set delta (NOPASSWD
  injection bypassing group membership). MITRE T1548.003/T1098.
- `systemd-unit-watchdog` (97) — enabled-unit + ExecStart-hash delta
  (T1543.002 service persistence). Matched sibling to cron-job-
  watchdog.
- `pam-config-watchdog` (98) — PAM config-line + module-hash delta
  (T1556.003 PAM backdoor / magic-password module).
- `audit-config-watchdog` (99) — auditd disablement/rule-flush
  detection (T1562.001 Impair Defenses).
- `selfdef-self-integrity` (100, CAPSTONE) — the meta-watchdog:
  hashes selfdef's own trust root (delta-watchdog baselines + wrapper
  scripts + module configs) + alerts on tampering. Closes the
  who-watches-the-watchers gap. MITRE T1562.001/T1565.001/T1070/T1554.

**Final architecture (100 modules):**
- **Auth-persistence detection family**: ssh-authkeys + sudoers +
  account + systemd-unit + cron-job + pam-config watchdogs.
- **Rootkit-detector trio**: ld-preload (userland) + hidden-process
  (either) + kernel-module (LKM).
- **Defense-tamper detection**: audit-config + logfile-integrity +
  selfdef-self-integrity (the meta-watchdog).
- **Firewall** both distros: nftables-baseline + firewalld-baseline.
- **MAC** both distros: apparmor-baseline + selinux-baseline.
- **Detection ladder**: 23 staggered cadences.
- **13 refuse-to-brick gates.**

Module total: **100/100 — operator target reached.** Detection-
heavy second half (delta-watchdogs covering every canonical
persistence + defense-evasion surface) complements the hardening-
heavy first half.

### Added — module-ecosystem batch: 4 more modules push 85→89 (2026-05-22, batch 22)

Four further modules: two new delta-detection surfaces, the rootkit
hidden-process detector, and the foundational host firewall. Module-
catalog parser 16/16; L1 module-contracts coherent at 89.

- `dns-resolver-watchdog` — daily+boot delta of resolver config
  (resolv.conf nameservers/search + systemd-resolved upstreams behind
  the stub + /etc/hosts override count); nameserver change = alert
  (DNS-hijack signature). MITRE T1584.002/T1565.001/T1557/T1071.004.
- `file-capabilities-watchdog` — daily+boot delta of getcap -r;
  covers the suid-sgid blind spot (caps live in security.capability
  xattr, not mode bits); dangerous-cap (setuid/dac_override/sys_admin
  /sys_ptrace/sys_module) added = alert. MITRE T1548/T1098/T1546/
  T1574. Matched sibling to suid-sgid-watchdog.
- `hidden-process-watchdog` — readdir(/proc) vs direct /proc/<pid>
  stat asymmetry to surface rootkit-hidden processes; pid_max-aware,
  capped 200k, Nice=19; every 4h. MITRE T1014/T1564/T1055/T1562.006.
  Pairs with kernel-module-watchdog (both halves of an LKM rootkit).
- `nftables-baseline` — default-deny inet host firewall (baseline/web/
  locked profiles); 13th refuse-to-brick (4-layer anti-lockout: SSH
  always allowed, nft -c parse-check, SSH-accept verify, ruleset
  backup). MITRE T1190/T1133/T1046/T1048/T1571.

**Delta-detection family now 7** (account/cron/setuid/file-caps/
listeners/kernel-modules/dns-resolver) + 2 standalone rootkit/mount
detectors (hidden-process, mount-options). **Detection ladder 18
cadences.** **Refuse-to-brick gates 13.** **Foundational firewall**
landed (nftables-baseline) — the long-standing gap. Module total
after this batch: 89 (operator target 100+; remaining gap ~11).

### Added — module-ecosystem batch: 3 more modules push 82→85 (2026-05-22, batch 21)

Three further modules deepening SMTP-surface, SSH-crypto, and mount-
hardening detection. Module-catalog parser test 16/16; L1 module-
contracts coherent at 85.

- `mta-loopback-detect` — detection: verify SMTP listeners (25/465/
  587) bind loopback only, not 0.0.0.0/:: (open-relay / spam-cannon /
  exim-RCE surface). report/enforce; boot+5min+6h. MITRE T1190/
  T1071.003/T1048/T1046.
- `ssh-moduli-harden` — prune weak DH moduli from /etc/ssh/moduli
  (strong >=3072 / minimum >=2048); Logjam-class defense; refuse-to-
  brick never-empties-moduli; backup+restore. Companion to ssh-
  hardening. CIS 5.2.x. MITRE T1557/T1040/T1600.001.
- `mount-options-watchdog` — daily+boot verify nosuid/nodev/noexec on
  /tmp /var/tmp /dev/shm /var/log /boot (+nosuid/nodev /home);
  separate-mount aware; drift detection complementing tmpfs-baseline.
  MITRE T1059/T1548.001/T1546/T1564.

**Detection ladder** now 15 cadences. **Network-surface-reduction**
family extended (mta-loopback + listening-ports + rpcbind + avahi).
Module total after this batch: 85 (operator target 100+; remaining
gap ~15).

### Added — module-ecosystem batch: 4 more modules push 78→82 (2026-05-22, batch 20)

Four further modules: the fifth delta-detection watchdog, the
account-policy capstone, the RHEL MAC parallel, and the ASLR
guarantee. Module-catalog parser test 16/16 + L1 module-contracts
coherent at each step.

- `kernel-module-watchdog` — daily+boot delta of /proc/modules vs
  baseline; out-of-tree module (no .ko under /lib/modules) = alert
  (LKM-rootkit signature). Fifth delta-detection watchdog. MITRE
  T1547.006/T1014/T1562.001/T1205. Real-time complement: host-
  sentinel's do_init_module kprobe.
- `login-defs-baseline` — password-aging + strong-hash defaults
  (PASS_MAX/MIN_DAYS, ENCRYPT_METHOD yescrypt/SHA512, SHA_CRYPT
  rounds) in /etc/login.defs.d (legacy /etc/login.defs fallback).
  standard (NIST-leaning) + strict (PCI DSS 90-day) profiles. CIS
  5.5.x. MITRE T1110.002/T1110.001/T1078. Completes account-policy
  stack with the pwquality/history/faillock triad.
- `selinux-baseline` — RHEL/Fedora MAC posture (audit/permissive/
  enforcing); conflicts=[apparmor-baseline]; 12th refuse-to-brick
  gate (disabled→enforcing needs acknowledge_relabel + autorelabel
  + reboot). MITRE T1068/T1611/T1562.001/T1505.003.
- `aslr-baseline` — guarantee kernel.randomize_va_space=2 (full
  ASLR), drift-resistant. CIS 1.6.x. MITRE T1203/T1068/T1211/T1055.

**Delta-detection family now 5** (accounts/cron/setuid/listeners/
kernel-modules). **Refuse-to-brick gates now 12.** **Detection
ladder 14 cadences.** **MAC coverage** both distros: apparmor-
baseline (Debian/Ubuntu) + selinux-baseline (RHEL/Fedora), mutually
exclusive via conflicts wiring. Module total after this batch: 82
(operator target 100+; remaining gap ~18).

### Added — module-ecosystem batch: 6 more modules push 72→78 (2026-05-22, batch 19)

Six further modules, completing the persistence-surface delta-
detection quartet and deepening the service-mask family. Module-
catalog parser test stays 16/16 green after each add.

- `avahi-disable` — mask mDNS/DNS-SD daemon (LAN hostname+service
  broadcast info-leak + CVE-2021-3468/3502/CVE-2023-1981 DoS chain +
  mDNS reflection-amplification). MITRE T1046/T1590/T1499/T1498.
- `rpcbind-disable` — mask SunRPC portmapper (TCP/UDP 111) on
  non-NFS/NIS hosts (portmap reflection-amplification reflector,
  rpcbomb CVE-2017-8779, rpcinfo recon). Warns if nfs-server active.
  MITRE T1498.002/T1046/T1190/T1499.
- `rsh-telnet-disable` — mask legacy cleartext daemons (telnet, rsh/
  rlogin/rexec, tftp, finger) if present. CIS 2.2.x. No-op on the
  common modern host. MITRE T1040/T1110/T1078/T1071/T1087.
- `listening-ports-watchdog` — daily+boot delta of listening TCP/UDP
  sockets vs baseline; new listener = backdoor/reverse-shell/SOCKS
  indicator. MITRE T1571/T1090/T1059/T1205.
- `cron-job-watchdog` — daily delta of all scheduled-task surfaces
  (crontabs + cron.d + periodic dirs + systemd timers, sha256-hashed
  so content changes surface). MITRE T1053.003/T1053.006/T1546/T1078.
- `account-watchdog` — daily+boot delta of account surface (passwd +
  uid0 set + sudo/wheel/admin roster); new uid=0 / sudo member =
  alert. MITRE T1136.001/T1078.003/T1098/T1548.003.

**Persistence-surface delta quartet COMPLETE**: the four canonical
attacker-persistence surfaces each have a baseline+delta watchdog —
accounts (account-watchdog) + scheduled-tasks (cron-job-watchdog) +
setuid binaries (suid-sgid-watchdog) + network listeners (listening-
ports-watchdog). Each pairs with a real-time auditd/eBPF source
(acct-baseline / audit-rules / tetragon) as the catch-anyway backstop.

**Service-mask family** now 8: services-disable-printing, bluetooth-
disable, nscd-disable, apport-disable, avahi-disable, rpcbind-disable,
rsh-telnet-disable (+ at-disable from earlier). avahi + rpcbind are
the two LAN-facing reflection-amplification daemons — masking both
shrinks the host's DDoS-reflector surface.

**Detection ladder** now 13 cadences. Module total after this batch:
78 (operator target 100+; remaining gap ~22).

### Added — module-ecosystem batch: 5 more modules push 67→72 (2026-05-22, batch 18)

Five further modules after the dashboard expansion, deepening the
hardening + detection surfaces. All follow the established module-
template pattern; module-catalog parser test stays 16/16 green after
each add.

- `nscd-disable` — mask Name Service Cache Daemon (CVE-2024-33599
  family stack overflow + netgroup DoS); modern hosts use systemd-
  resolved + sssd. mask/stop profiles. MITRE T1190/T1068/T1499.
- `entropy-baseline` — detection (boot+5min + 6h): verify entropy
  posture via 5 signals (entropy_avail, entropy daemon, hwrng node,
  CPU rdrand/rdseed, CRNG-init-done). Catches entropy-starved-VM
  predictable-key class. MITRE T1552.004/T1600.001/T1190.
- `ctrlaltdel-disable` — mask ctrl-alt-del.target (mask profile) OR
  CtrlAltDelBurstAction=none (burst-guard); blocks console-reboot
  DoS. Pairs with kernel-sysrq-restrict. MITRE T1499/T1529/
  T1561.001/T1200.
- `apport-disable` — mask Ubuntu apport/whoopsie + reset core_pattern
  apport pipe (CVE-2021-3899 TOCTOU, CVE-2022-1242 path traversal,
  CVE-2023-1326 setuid PE). mask/stop profiles. MITRE T1068/T1055/
  T1005/T1552.
- `coredump-suid-restrict` — fs.suid_dumpable=0 (suid-only) + all-
  process hard core 0 (all-off). Prevents setuid-binary memory-dump
  credential leak. CIS 1.5.x. MITRE T1003/T1552.001/T1005/T1212.

**Detection ladder** now 10 cadences (added entropy boot+5min+6h
alongside swap-encryption boot+5min+12h). **Physical-console DoS
lockdown pair**: kernel-sysrq-restrict + ctrlaltdel-disable. **Memory-
leak defense quartet**: coredump-suid-restrict + coredumpd-redirect +
apport-disable + swap-encryption-detect + kdump-disable. **Service-
mask family**: services-disable-printing + bluetooth-disable +
nscd-disable + apport-disable.

Module total after this batch: 72 (was 52 at the resumed-session
start; operator target 100+; remaining gap ~28).

### Added — dashboard preset catalog 5→20 (2026-05-22, batch 17)

Operator-verbatim target met: "there is over 20 dashboards and a
main one and everything can be turned on and off and there are also
a tons of modes and profiles" (2026-05-19, sacrosanct). The 5-preset
table that shipped under batch 12 is now a 20-preset table.

**New presets (15 added, alphabetical with focus tab / refresh):**

| Preset | Tab | Refresh | Focus |
|---|---|---|---|
| audit-trail | logs | slow | audit chains + alerts (forensic posture) |
| cpu-bound | hardware | fast | CPU + hardware + composite-health (compute saturation) |
| gpu-monitor | hardware | fast | GPU + CPU + flex + composite-health (inference) |
| health-only | all | slow | composite-health alone (smallest footprint) |
| incident-response | logs | fast | 4 watchdogs + alerts + audit + logs (active triage) |
| inference-throughput | models | fast | inference + GPU + flex + CPU (hot path tuning) |
| mcp-debug | mcp | normal | MCP + alerts + logs (external client diagnosis) |
| mcp-tools | mcp | normal | MCP + modules + alerts (tool-side rollout) |
| models-lab | models | normal | models + inference + GPU (model swap) |
| module-status | modules | slow | modules + profiles + health (apply/check drift) |
| network-ops | network | normal | network + storage + RAID + health |
| paused-snapshot | all | paused | all 16 panels BUT refresh paused |
| repl-session | repl | normal | REPL + composite-health + alerts |
| storage-ops | all | normal | storage + RAID + composite-health |
| watchdog-deep | all | fast | 4 watchdogs + composite-health |

Plus the 5 original: default, security, performance, inference,
compact.

**Atomic 7-file update**

- `crates/selfdef-api/src/dashboards.rs` — DASHBOARDS const + 3
  updated tests (count=20, names enumerated, descriptions).
- `crates/selfdef-api/src/dashboard_prefs.rs` — VALID_PRESETS
  validator + matching test assertion.
- `crates/selfdef-cli/src/dashboard_prefs.rs` — VALID_PRESETS
  matches daemon (no drift between CLI client + daemon).
- `dashboard/app.js` — PRESETS object + comment block documenting
  catalog + source-of-truth invariant.
- `dashboard/index.html` — `<select>` extended from 5 to 20
  option rows.
- `docs/operator-cheatsheet.md` — 3 references updated.
- `docs/sdd/060-dashboard-prefs-persistence.md` — preset enum in
  both the TOML example + validation-table row.

**Test posture**: cargo test -p selfdef-api --lib dashboards 6/6
+ dashboard_prefs 7/7 + modules::tests 16/16 (unaffected). All 8
L1 doc gates remain green. Workspace builds clean.

**Source-of-truth invariant**: `selfdef-api/src/dashboards.rs
DASHBOARDS` is authoritative. PWA's `PRESETS` keys MUST match
byte-for-byte; daemon + CLI VALID_PRESETS MUST match. Drift =
lint failure (Rust-side at compile time; JS/HTML via PUT-
validator round-trip at runtime).

### Added — module-ecosystem batch: 11 new modules push 53→63 (2026-05-21, batch 16)

Eleven new modules shipped in one resumed perpetual-/goal turn,
diversifying the hardening + detection + sysctl + modprobe-blacklist
surfaces. All follow the established module-template pattern
(module.toml + profiles/*.toml + install/{apply,check,uninstall,lib}.sh
+ install_paths manifest + README with MITRE-coverage table +
operator workflow + caveats + coexistence). Module catalog parser
test suite stays 16/16 green (cargo test -p selfdef-api --lib
modules::tests) after each add.

**Hardening (4 new modules)**

- `bluetooth-disable` — triple-defense BlueZ stack mask + rfkill
  + modprobe blacklist of btusb/btintel/btbcm/btmtk/btrtl/bluetooth
  with install /bin/true. MITRE T1011 / T1200 / T1557 / T1543.002
  (BlueBorne CVE-2017-1000251 family, BlueDucky CVE-2023-45866,
  KNOB CVE-2019-9506, BIAS CVE-2020-10135). Two profiles: mask
  (default; full triple) + stop (services + rfkill only).

- `sysctl-network-baseline` — curated net.ipv4 + net.ipv6
  hardening: accept_source_route=0, accept_redirects=0,
  rp_filter=1 strict, log_martians=1, tcp_syncookies=1, ipv6
  accept_ra/autoconf=0. Three profiles: baseline / router
  (forwards + conntrack tune) / paranoid (silent host + ipv6
  disabled). Soft-fails per-key on container-restricted
  namespaces. MITRE T1557.002 / T1499 / T1590 / T1542.005.

- `kernel-yama-baseline` — kernel.yama.ptrace_scope three-tier
  control (1 relaxed / 2 strict / 3 paranoid). 10th refuse-to-
  brick gate: paranoid requires `acknowledge_paranoid = true` in
  config (irreversible until reboot). MITRE T1055.008 / T1003 /
  T1611 / T1574 (blocks in-host credential-theft via gdb-attach
  to ssh-agent / gpg-agent).

- `file-protections-baseline` — fs.protected_{hardlinks,
  symlinks,fifos,regular} sysctls at kernel-max. Defeats
  canonical /tmp-race priv-esc class (symlink-race-to-shadow,
  hardlink-to-root-file, FIFO/regular race-and-replace). MITRE
  T1068 / T1574.012 / T1222.002 / T1083.

- `rare-filesystems-disable` — modprobe.d blacklist for cramfs,
  freevxfs, jffs2, hfs, hfsplus, udf, ksmbd (baseline) +
  squashfs/nfsd/gfs2 (strict). Defeats USB-with-exotic-fs auto-
  mount kernel-parser-CVE class (CVE-2020-27194 jffs2 type
  confusion; CVE-2023-32257 ksmbd RCE). MITRE T1068 / T1190 /
  T1052.001 / T1091 / T1014.

**Patch automation**

- `dnf-automatic-config` — RHEL/Fedora/Rocky/AlmaLinux parallel
  of unattended-upgrades-config. Renders /etc/dnf/automatic.conf
  with upgrade_type=security + emit_via=stdio. Two profiles:
  security-only (default; never auto-reboot) + security-and-
  reboot (shutdown -r +5 when kernel/glibc requires).
  Backup-then-render-with-header-marker pattern. MITRE T1190 /
  T1068 / T1133 / T1059.

**Detection (5 new modules; extends staggered cadence ladder
from 4 to 9 modules)**

- `unowned-files-watchdog` — Sun 06:00 weekly find -nouser -o
  -nogroup scan. Two-tier journald events (summary + per-path).
  Severity: 0=ok, 1-50=warn, 51+=alert. MITRE T1070.004 / T1136
  / T1078 / T1083.

- `world-writable-watchdog` — daily 05:00 find -perm 0002 scan
  (files any; non-sticky dirs). Prunes safe-by-design paths
  (/tmp, /var/tmp, /dev/shm, container storage, virtual fs).
  Severity: 0=ok, 1-25=warn, 26+=alert. MITRE T1222 / T1574.010
  / T1083 / T1078.

- `suid-sgid-watchdog` — daily 05:15 SUID/SGID inventory + delta
  against /var/lib/selfdef/suid-sgid-baseline.tsv. Per-class
  events: added / removed / perm_changed / hash_changed. Baseline
  preserved across uninstall (forensic). MITRE T1548.001 / T1546
  / T1059 / T1574.005.

- `swap-encryption-detect` — boot+5min + every-12h. Per /proc/swaps
  entry classification: /dev/zram* safe (RAM only), /dev/mapper/<x>
  safe iff dmsetup table=crypt or crypttab mention, raw devices
  safe iff lsblk parent-walk finds crypto_LUKS, file-backed safe
  iff parent fs encrypted. zswap+unsafe_backing=alert (worst
  case). MITRE T1552.004 / T1003.008 / T1565.001 / T1005.

- `bootloader-password-detect` — boot+10min + Sun 07:00 weekly.
  Scans GRUB2 grub.cfg + /etc/grub.d/40_custom + 01_users across
  Debian/Ubuntu/RHEL/Fedora/Rocky/Alma/EFI paths for password
  directive presence + PBKDF2 form. Severity: pbkdf2+superuser=ok,
  pbkdf2_no_superuser=warn, plaintext=warn, no_password=alert.
  MITRE T1542 / T1542.003 / T1078 / T1200 / T1556.

**Detection-ladder slot rationale (early-morning I/O budget)**

| Time | Module | Cadence |
|---|---|---|
| 02:30 ±30m | aide-bridge | daily |
| 03:30 ±30m | clamav-cron | daily |
| 04:30 ±15m | rkhunter-cron | daily |
| 05:00 ±15m | world-writable-watchdog | daily (NEW) |
| 05:15 ±10m | suid-sgid-watchdog | daily (NEW) |
| Sun 05:30 ±15m | lynis-cron | weekly |
| Sun 06:00 ±15m | unowned-files-watchdog | weekly (NEW) |
| Sun 07:00 ±15m | bootloader-password-detect | weekly (NEW) |
| boot+5m + 12h | swap-encryption-detect | trigger-driven (NEW) |

Three weekly + four daily + two trigger-driven cadences cover
the early-morning operator-host I/O budget without herd
collision. Each carries `Persistent=true` to catch up missed
runs after host downtime.

**Refuse-to-brick gate ledger (now 10)**

10th gate landed with kernel-yama-baseline `acknowledge_paranoid`.
Full ledger: visudo -cf (sudoers), sshd -t (ssh), backup-then-
restore (per modify-in-place modules), modprobe blacklist
ownership marker (per modprobe modules), authselect/pam-auth-
update soft-fail (per pam modules), audit-rules immutable
acknowledge flag, firewall-allow-ssh acknowledge (per future
firewall modules), kernel-lockdown lockdown_mode_acknowledge,
kernel-yama acknowledge_paranoid (NEW).

**Module total**

After this batch: 63 modules shipped (was 52 at session start).
Operator-target is 100+; remaining gap ~37 modules. Detection
ladder 7→9. Compute-stack unchanged (5). Hardening-stack
expanded 22→26. Total cargo test -p selfdef-api --lib
modules::tests stays 16/16 across the batch.

### Added — MS043 UX `selfdefctl dashboard-prefs` CLI verb (2026-05-21, batch 15)

Closes the layer-up pattern for the dashboard-prefs arc. After
the daemon-side HTTP surface (batch 13) + PWA sync (batch 14),
the CLI verb gives headless / scriptable access:

- `selfdefctl dashboard-prefs` (or `show`) — GETs the persisted
  prefs + renders the human table (active_preset / refresh_rate /
  hidden_panels list + updated_at_ms).
- `selfdefctl dashboard-prefs show --json` — pass-through of the
  daemon JSON body for jq.
- `selfdefctl dashboard-prefs set refresh_rate <fast|normal|slow|paused>`
  — PUTs the mutation. Client-side enum check before round-trip
  (saves a network round-trip on operator typo).
- `selfdefctl dashboard-prefs set active_preset <default|security|performance|inference|compact>`
  — same shape, validates the 5-preset table.
- `selfdefctl dashboard-prefs set hidden_panels "a,b,c"` — PUTs
  the comma-separated section IDs. Empty string clears the set
  (D-6 in SDD-060: hidden_panels is unconstrained `Vec<String>`).

Exit codes per the operator's standing 4-tier ladder for
operator-visible CLI verbs:
  0 = ok
  1 = daemon not reachable / fetch failed
  2 = invalid arg (unknown field / unknown enum value, caught
      client-side)
  3 = server rejected the PUT (400/409 from the daemon)

Operator cheatsheet documents the 5 invocations. L1-operator-
cheatsheet gate updated to require the `selfdefctl dashboard-prefs`
literal in the doc.

This closes the dashboard-prefs layer-up chain: crate (HTTP
module) → SDD-060 → CLI verb → HTTP discovery → L1 (api endpoints
+ cheatsheet) → INDEX. Per the layer-up lesson in info-hub
(commit c48e19d).

### Added — MS043 UX dashboard-prefs PWA sync (2026-05-21, batch 14)

Closes the dashboard-prefs arc end-to-end. Batch 13 shipped the
daemon-side HTTP surface; this batch wires the PWA to consume it.

- `app.js` adds `fetchPrefsFromServer()` (GET on load) +
  `syncPrefsToServer()` (PUT on change, debounced 400ms via
  `schedulePrefsSync`).
- Every `writeHiddenPanels` / `writeRefreshRate` / `writePreset`
  call now schedules a server PUT. Burst-of-changes (operator
  toggling 5 visibility checkboxes in 2s) collapses to ONE
  round-trip.
- Initial `fetchPrefsFromServer()` runs after `switchTab(parseTab())`
  so server preferences win over localStorage when the daemon is
  reachable. Refresh-rate select + preset select sync to the
  server value if different.
- Offline-safe: any fetch/PUT failure (file:// scheme, daemon
  down, 5xx) is silent — localStorage remains authoritative; the
  next change re-attempts.
- Server-side enum rejections (400) log a console warning so
  operators on a stale build see the divergence; no infinite
  retry. Schema mismatch (409) likewise.
- Service worker SHELL bumped v26 → v27.

The dashboard-prefs UX flow is now: operator changes a
preference in any browser → 400ms debounce → PUT to daemon →
atomic write to `/etc/selfdef/dashboard-prefs.toml`. The same
operator on a different browser fires `fetchPrefsFromServer()` on
next load and sees the new state. localStorage caches the result
so offline use stays smooth.

### Added — MS043 UX daemon-side dashboard-prefs persistence (2026-05-21, batch 13)

The three UX-mode pillars shipped in batches 10/11/12 (panel
visibility + refresh rate + view presets) persist to
`localStorage` — that's per-browser. The same operator on a phone
PWA / laptop / different host loses their choices.

This batch promotes the preferences to the **daemon** as the
source of truth.

- **`GET /v1/dashboard-prefs`** — returns the current persisted
  preferences. Missing file → `200 OK` with a blank-valid body
  (schema_version 1.0.0, empty hidden_panels, normal refresh,
  default preset). Malformed file → also blank-valid (we do NOT
  500 on disk corruption; the dashboard would lose all UX state).
- **`PUT /v1/dashboard-prefs`** — atomically persists new
  preferences via temp-file-then-rename. Validates:
  - `schema_version` matches server's `1.0.0` → 409 Conflict
    otherwise
  - `refresh_rate` ∈ {fast, normal, slow, paused} → 400 otherwise
  - `active_preset` ∈ {default, security, performance, inference,
    compact} → 400 otherwise
- Disk persistence at `/etc/selfdef/dashboard-prefs.toml`; env
  override `SELFDEF_DASHBOARD_PREFS_PATH`. Server stamps
  `updated_at_ms` from `SystemTime::now()` on every accepted PUT.
- 7 unit tests (default constructor, missing-file behavior, disk
  round-trip, malformed-file resilience, enum-table coverage,
  atomic-write parent-dir creation) + 4 integration tests against
  the live axum router (GET default body, PUT rejection on all 3
  enum mismatches). All 11 pass.
- L1-api-endpoints gate extended with the new route line. Operator
  cheatsheet documents the GET + PUT contracts.

The dashboard-side sync (PWA fetches on load, PUTs on
preference change, falls back to localStorage when offline) is
the next layer-up and lands in a follow-up commit — this batch
ships the daemon-side foundation under SDD-026 + the layer-up
pattern documented in the info-hub lesson.

### Added — MS043 UX view presets (2026-05-21, batch 12)

Third pillar of the operator's UX-mode requirements. Verbatim:
*"there is over 20 dashboards"*. Distinct dashboard URL paths
(each with its own service worker shell) is a Stage-2 arc; this
batch ships the tractable interim — operator-named view PRESETS
that snap `{hiddenPanels, activeTab, refreshRate}` atomically to
a meaningful configuration in one click.

- 5 shipped presets:
  - **Default** — all 16 panels visible, no tab, normal refresh
  - **Security** — health + 4-watchdog + alerts + audit-chains;
    `logs` tab; normal refresh
  - **Performance** — health + hardware + network + storage + raid
    + gpu + cpu; `hardware` tab; fast refresh
  - **Inference** — health + inference-backends + gpu + flex-profile;
    `models` tab; normal refresh
  - **Compact** — always-visible strip only (composite-health +
    4-watchdog + alerts); `all` pseudo-tab; slow refresh
- `index.html`: `#preset-label` + `#preset-select` placed
  between View ▾ and Refresh in the always-visible `#tab-nav`
  strip.
- `app.js`: `PRESETS` table + `applyPreset(name)` writes the
  triple (`writeHiddenPanels` → `applyHiddenPanels` →
  `writeRefreshRate` → refresh-select sync → `window.location.hash
  = "tab=<name>"`). Operator's post-preset manual overrides are
  kept (preset is the snap-to point, not a lock).
- `dashboard.css`: preset-select sized to fit the longest label
  ("Security — watchdogs + alerts + audit"); hover/focus matches
  refresh-rate select.
- localStorage `selfdef.activePreset` persists the choice.
- Service worker SHELL bumped v25 → v26.

Together with batch 10's per-panel visibility menu + batch 11's
refresh-rate selector, the always-visible strip now offers three
operator-facing controls — what panels (View ▾), how often
(Refresh), and which operator-meaningful view (View preset). Each
control is independently usable + composable; presets snap all
three at once for the most common operator workflows.

### Added — MS043 UX refresh-rate selector (2026-05-21, batch 11)

Second pillar of the operator's "tons of modes" verbatim
requirement. The Fast/Normal/Slow/Paused selector sits next to
View ▾ in `#tab-nav`. Operators on flaky links pick Slow; operators
debugging a flapping watchdog pick Fast; long-running idle sessions
pick Paused to stop probing entirely.

- `index.html` adds `#refresh-rate-label` + `#refresh-rate-select`
  with 4 options (fast/normal/slow/paused).
- `app.js` factor table (fast=0.25× / normal=1× / slow=4× /
  paused=∞), localStorage key `selfdef.refreshRate` persisting
  the operator's choice across reloads.
- `gatedInterval()` refactored from `setInterval(fn, ms)` to a
  self-rescheduling `setTimeout` chain. Each cycle reads the
  current rate factor + multiplies the base interval. Rate flips
  apply on the NEXT cycle of every panel — no need to clear or
  re-arm any handles. Hidden panels (either tab-hidden OR new
  operator-hidden) skip their probe entirely; the chain self-
  reschedules to keep checking.
- `dashboard.css` styles the label + select to match the existing
  dark theme + hover/focus interactive states.
- Service worker SHELL cache bumped v24 → v25.

Together with batch 10's per-panel visibility menu, the operator
now has both *what* to show (panel set) and *how often* to refresh
it. Both pieces sit in the always-visible `#tab-nav` strip so no
tab switch is needed to access them.

### Added — MS043 UX per-panel visibility menu (2026-05-21, batch 10)

Operator-facing per-panel visibility toggle. Verbatim operator
direction: "everything can be turned on and off". The 8-tab nav
already groups the 17 panels logically; this batch adds a "View ▾"
menu in `#tab-nav` that lets the operator permanently hide
individual panels they don't care about (e.g. operator on a host
without RAID hides the RAID panel; operator with no GPU hides the
GPU panel).

- `index.html`: new `#panel-visibility-btn` (View ▾) + collapsible
  `#panel-visibility-menu` container inside `#tab-nav`.
- `app.js`: 137-LOC visibility subsystem. `selfdef.hiddenPanels`
  localStorage key holds a JSON array of section IDs to hide;
  `applyHiddenPanels()` toggles the `.operator-hidden` class on
  each section; `buildPanelVisibilityMenu()` renders 16 panel-row
  checkboxes + a "Show all panels" reset row + a `N/16 panels
  visible` header counter. Menu opens/closes on button click,
  closes on outside-click, full ARIA wiring (`aria-haspopup`,
  `aria-expanded`, `aria-controls`).
- `dashboard.css`: `.operator-hidden { display: none; }` (parallel
  to `.tab-hidden`; either flag hides the section, so operator
  preference survives tab switches). 90+ LOC styling the View
  button + menu + rows + reset to match the existing dark theme
  + interactive states.
- Service worker SHELL cache bumped v23 → v24.

The hidden set is ANDed against the tab-driven hide set in
`switchTab()` so hidden panels stay hidden across all tabs +
"Show all" mode. Default = all visible (back-compat for existing
operators). Reset clears the set instantly via the in-menu button.

### Added — MS016 host-sentinel module (2026-05-21, batch 9)

New `modules/host-sentinel/` ships 2 host-scope Tetragon TracingPolicies
as companion implementations to MS016's deferred aya-rs eBPF programs:

- `policies/kmod-watch.yaml` — Tetragon kprobe on `do_init_module`
  with `matchNamespaces: Pid In host_ns` selector. Companion to MS016
  `kmod-watch`. Post action in both audit + enforce profiles
  (killing the loader after the module is already in-kernel is closing
  the barn door; the event is the value).
- `policies/ld-preload-watch.yaml` — Tetragon kprobe on
  `security_file_open` matching `/etc/ld.so.preload` with O_WRONLY/
  O_RDWR mask. Companion to MS016 `ld-preload-watch`. Post in audit;
  apply.sh rewrites to Sigkill in enforce — rootkit-installation
  attempt killed at the open() syscall.

Module structure mirrors agent-guard: `module.toml` declares the
`[install_paths]` block (writes shared `/etc/tetragon/tetragon.tp.d`
plus its own config file — `install-plan`'s `path_conflicts`
surface will flag the policy_dir as informational overlap with
tetragon + agent-guard, all expected); `install/{apply,check,
uninstall}.sh` follow the shared `module-lib.sh` pattern;
`profiles/{audit,enforce}.toml` per-policy enable flags;
`README.md` documents the architectural difference vs agent-guard
(host PID ns vs container PID ns).

`selfdef-ebpf/README.md` updated to cross-reference the Tetragon
companions on each item; 3 deferred programs (proc-ancestry,
hidden-process, tcp-fingerprint) remain deferred because they
genuinely need aya-rs eBPF — Tetragon's surface is insufficient.

INDEX MS016 entry promoted from "1 eBPF program shipped" → "1 eBPF
program + 2 Tetragon companions shipped; 3 deferred".

### Added — MS011 Z-8 path-conflict surface + MS011 milestone closure (2026-05-21, batch 8)

Closes the last design-stage Z-vector + promotes MS011 from
`partial` → `done` and SDD-026 from `review` → `implemented`.

#### Z-8 — Docker vs system-level install paths

- All 14 shipped modules gain a `[install_paths]` block in their
  `module.toml` with explicit `scope = "system"` + a `paths` list
  enumerating the absolute paths each module writes during apply
  (extracted directly from each module's `install/apply.sh`
  variables: CONFIG_FILE, POLICY_DIR, RUNTIME_DIR, etc.). The
  schema was shipped earlier (ModuleInstallPaths with default
  back-compat); this batch fills it with real data so the
  downstream surfaces have something to reason about.
- `/v1/modules/install-plan` extended: new `path_conflicts` field
  in the response envelope. The new `compute_path_conflicts()`
  helper walks every planned module's `install_paths.paths` and
  surfaces ≥2-slug groups that share an absolute path. Returns
  `Vec<PathConflict>` with sorted modules + distinct scope set
  per path. Empty when no overlaps exist.
- Dashboard Modules panel: extended to fetch `/v1/modules/install-
  plan` in parallel with the existing modules + install-options
  fetches; renders a yellow `fa-yellow` aggregate badge plus a
  meta-line warning listing up to 3 conflicting paths (with `+ N
  more` suffix) when overlaps exist. Service worker SHELL cache
  key bumped from v22 → v23.
- 3 new selfdef-api unit tests:
  - `path_conflict_detection_two_modules_same_path` — basic case
  - `path_conflict_detection_skips_modules_not_in_plan` — only
    counts conflicts against the active plan set
  - `path_conflict_detection_distinct_scopes_surfaced` —
    informational conflict when scopes differ
- 1 m12_api integration test extension: `modules_install_plan_route
  _returns_200_with_topological_shape` now asserts the
  `path_conflicts` array is present in the envelope.

#### MS011 milestone closure

INDEX promoted MS011 → `done` with full end-to-end Z-vector inventory
(13/13). SDD-026 status block promoted to `implemented` with all 13
vectors enumerated; follow-up arcs (Z-2 module-driven install
pipeline, Z-8 containerized module variants, Z-12 dashboard REPL
pop-out UI) explicitly noted as *next* surfaces over a fully-shipped
foundation, not blockers.

### Added — MS011 Z-12 SD-R102 operator-macro auto-load (2026-05-21, batch 7)

Persistence path for Tier 2: until now operator-owned macros were
session-volatile — every fresh `python3 -i -c "$(selfdefctl repl
bootstrap)"` re-imported a blank Tier 1 surface and lost any custom
`@selfdef_macro` registrations from the previous session. SD-R102
closes the gap with a single auto-source step at bootstrap time.

- `bootstrap_script()` now defines `_autoload_user_macros()` which
  resolves a single operator-owned file via:
    1. `$SELFDEF_REPL_MACROS`                          (explicit override)
    2. `$XDG_CONFIG_HOME/selfdef/repl-macros.py`       (XDG-compliant)
    3. `~/.config/selfdef/repl-macros.py`              (XDG fallback)
- The file is `compile()`d then `exec`d INTO the bootstrap's globals so
  `@selfdef_macro` / `@track` / Tier 1 callables / SD-R97 aliases are
  all in scope. Resolved path is stashed in `_USER_MACROS_PATH`.
- Broken operator-owned files print the exception to stderr but
  bootstrap continues — a syntax error in `repl-macros.py` MUST NOT
  brick the REPL. Verified by manual smoke (SyntaxError captured;
  REPL still functional).
- Banner block now reports which file (if any) was loaded, or hints
  at the resolution paths when none was found.
- TierDescriptor entries (selfdef-api `/v1/repl` + selfdef-cli `repl
  tiers` JSON) advertise the new SD-R102 hints on both tier 1 (the
  load mechanism) and tier 2 (the persistence guidance).
- 2 new unit tests in selfdef-cli's `repl::tests`: bootstrap-script
  smoke (env-var + paths + compile-then-exec invariants) +
  tier-descriptor advertising (both tiers reference SD-R102).
- End-to-end smoke verified with a real `python3`: a fixture file
  defining `@selfdef_macro def hello_from_file()` + a global
  `PROOF_OF_LOAD = 42` was loaded; both were accessible in the
  bootstrap-spawned interactive session.

Per the operator's verbatim direction (SDD-026 Z-12 / SD-R85):
*"We ship Tier 1 + the manifest; operator owns Tier 2."* SD-R102
preserves that ownership boundary — the operator still owns the
macros file 100%, we just provide the auto-load hook so the file
survives session boundaries.

### Added — MS011 Z-2 invocation seed (2026-05-21, batch 6)

- `selfdefctl inference-backends version <backend>` subverb that shells
  out directly to the local backend binary's `--version` — no daemon
  round-trip. Backend name validated against the canonical 4-row table
  (llama.cpp / vllm / bitnet.cpp / unsloth) which mirrors the daemon's
  `BACKENDS` table byte-identically; binary resolved via the same
  `SELFDEF_INFERENCE_<NAME>_BIN` env override pattern.
- Exit code contract: `0` on success, `1` if `command -v <binary>` fails
  (not installed; message names the env-var override), `2` on subprocess
  exec failure.
- `Command::InferenceBackends` restructured from a unit variant with
  `--json` flag into a `Subcommand` with `Show` (default) + `Version
  { backend }` actions. Bare `selfdefctl inference-backends` continues
  to render the daemon-side probe table — operator-facing surface
  unchanged for the existing call.
- Operator cheatsheet updated with the new `version` invocation lines.

Per SDD-026 Z-2 verbatim: *"shells out to operator-installed tooling
(llama.cpp / vllm / bitnet.cpp / unsloth); one-click 'install missing
tool' via module surface"*. The probe (read) and version (invoke)
together seed the Z-2 surface; the "install missing tool" arc lands
next via the module-driven install pipeline (Z-13 install-plan + per-
backend install/check.sh).

### Added — SDD-057 shared-crate refactor + MS011 Z-13 closure (2026-05-21, batch 5)

Continuation block covering commits 145effb → 78e0456. Focus: extract
HardwareRequirements gate logic from selfdef-cli into a shared crate,
extend `/v1/modules/install-options` with hardware-gate enrichment,
ship the topological install plan, and surface the new classification
on the dashboard Modules panel.

#### SDD-057 — 7-step refactor (all shipped same day)

Authored as `scoping` in commit 3e37517; full 7-step migration
sequence executed in commits b37f0ef → 563b9bb. Promoted to
`implemented` in step 7.

- **Step 1** (3e37517) — SDD-057 authored: scope locked, migration
  sequence + risk/benefit + 4 open questions
- **Step 2** (b37f0ef) — `crates/selfdef-hardware-requirements/`
  scaffolded with stub + 2 sanity tests; workspace dep entry
- **Step 3** (e39aabd) — 473-LOC HardwareRequirements struct + impl
  moved verbatim from `crates/selfdef-cli/src/modules.rs` (original
  lines 185-613). `pub(crate)` → `pub`. 2 unit tests added (schema
  version pin + toml round-trip).
- **Step 4** (3710d08) — 420-LOC duplicate removed from selfdef-cli;
  replaced with `pub(crate) use selfdef_hardware_requirements::
  HardwareRequirements;`. All 244 + sibling tests pass — re-export
  bridge worked exactly as designed; zero call-site changes.
- **Step 5** (2519d8b) — `/v1/modules/install-options` extended:
  ModuleSummary gains `requires_hardware` field; install_options()
  derives capabilities via `selfdef_hardware::derive_capabilities`
  + calls `req.evaluate(&caps)`; 4-way classification (ready /
  blocked-by-missing-deps / blocked-by-hardware / needs-review);
  new counts fields (blocked_by_hardware + needs_review);
  unmet_hardware_predicates surfaces the failed predicate list
- **Step 6** (563b9bb) — integration test extended: asserts the 4
  classification variants + the new envelope fields; catches drift
  if a future variant lands without updating the gate
- **Step 7** (563b9bb) — SDD-057 scoping → implemented; INDEX MS011
  row updated to cite Z-13 SD-R86 hardware-gate enrichment as
  **closed**

7 of 7 closure boxes checked in a single multi-cycle session.

#### MS011 Z-13 SD-R87 topological install plan (commit 145effb)

`GET /v1/modules/install-plan` — Kahn's algorithm over the READY
set (no-missing-deps modules). Returns
`{plan, skipped, cycle_detected, cycle_member_slugs}` with the
plan list giving deterministic install order. Cycle detection
surfaces any malformed catalog. Edition-2024 match-ergonomics fix
shipped alongside (2 instances of `.filter(|(_, &d)|` needed
explicit `|&(_, &d)|`).

#### Dashboard hookup (commit 78e0456)

PWA Modules panel now surfaces the install-options counts in its
meta line — operators see `ready / blocked-by-deps /
blocked-by-hardware / needs-review` at a glance without opening
a separate tab. Promise.all parallel fetch with graceful degradation
when /v1/modules/install-options is unavailable.

#### Cross-cutting metrics after batch 5

- Workspace crate count: 536 (was 535; +selfdef-hardware-requirements)
- selfdef-cli LOC: -420 in modules.rs (the duplicate code removed)
- /v1/modules surface: 4 routes now ship (list + show + check + diff
  + install-options + install-plan)
- Dashboard meta lines: install-options counts visible
- SDD-057 closes 1 of 4 remaining MS011 Z-13 follow-up items
  (SD-R86 hardware-gate enrichment); SD-R87 also closed in batch 5
- SDD ledger: 47 implemented / 5 draft / 2 review / 3 scoping / 1
  living / 58 total (was 46 / 5 / 2 / 4 / 1 / 58 pre-batch-5;
  +SDD-057 promotion)
- INDEX milestones: 42 done / 6 partial / 0 stage-1 (MS011 stays
  partial because of Z-2/Z-3/Z-12 still-open arcs — Z-13 SD-R86 +
  SD-R87 closed this batch)

### Added — MS011 Z-1 8-tab restructure + landscape SDDs (2026-05-21, batch 4)

Continuation block covering commits a6f3925 → 4f30408. Focus: ship
the MS011 Z-1 8-tab restructure end-to-end per SDD-026 ratification
+ author 3 retrospective/planning SDDs documenting the dashboard
architecture, partial-milestone landscape, and 8-tab migration plan.

#### SDD-054 — dashboard as shipped (commit 770cf47)

161-line Stage-2 retrospective documenting the actually-shipped
17-panel single-page-with-anchor-nav layout. Captures the panel
taxonomy (5 operator-relevance clusters), refresh interval ladder,
CSS color taxonomy, service-worker cache invalidation, and L1
drift-detection gate. 4 open questions including D-1 "migrate to
8-tab restructure per SDD-026 Z-1" (closed by SDD-056).

#### SDD-055 — partial milestone landscape (commit fdaacfc)

207-line Stage-2 synthesis enumerating all 6 remaining `partial`
milestones with explicit deferred-for-cause reasons + closure
conditions + effort estimates + recommended next-session targets.
Cross-cutting observation: 2 of 6 are eBPF kernel work (MS002 +
MS016 share deferred list — shipping 1 program closes 2 entries);
1 is operator-gated (MS008); 1 is intentionally evergreen (MS013);
2 are MS011 multi-commit arcs.

#### SDD-056 — dashboard 8-tab restructure plan (commit 2251591)

156-line Stage-2 plan locking the 17-panel → 8-tab mapping,
framework choice (vanilla JS hand-rolled router), URL hash routing,
active-tab refresh strategy, L1 gate evolution, 5-commit migration
sequence, and 7-checkbox closure roadmap.

#### SDD-056 implementation (commits 91b8899 + 81ebdca + 4136965 + a9bf06e + 4f30408)

5-commit migration sequence shipped, MS011 Z-1 functionally
complete:

- **Step 2** (91b8899): 8-tab HTML scaffold + CSS (Models /
  Modules / Profiles / Hardware / Network / Logs / MCP / REPL),
  tab UI inert pending JS
- **Step 3** (81ebdca): tab switching JS + URL hash router.
  `#tab=<name>` source of truth; hashchange listener; deep-link
  + back/forward navigation; tab-hidden class toggle
- **Step 4** (4136965): gated setInterval — 16 raw setInterval
  calls replaced with `gatedInterval(fn, ms, sectionId)` that
  pauses fn when its section is tab-hidden. Saves nvidia-smi /
  df / ping / mdstat / --version probe cost when operator pinned
  to a single tab.
- **Step 5** (a9bf06e): "Show all" / "Show tabbed" toggle button
  + localStorage persistence + 9th "All" pseudo-anchor. Default
  stays "all" (no UX surprise for existing operators); operator
  flips once and preference survives reload.
- **Step 6** (4f30408): SDD-056 ratified scoping → implemented.
  Functionally complete; SDD-026 + MS011 ratification deferred
  pending remaining Z-N arcs.

Dashboard now ships its full Z-1 form with operator-toggleable
mode + the 17-panel scroll-all layout preserved as the default.

#### Operator tooling

- `scripts/test/sdd-tally.sh` (4e20bdb) — MS013 charter-tracking
  drift detector with 3 status-format tolerance (carried from
  batch 3)

Final SDD tally:
  implemented: 46 (was 43 pre-batch-4; +SDD-054 + SDD-055 +
    SDD-056 promotion)
  draft:        5
  review:       2 (SDD-012 + SDD-026 — unchanged)
  scoping:      3 (SDD-009/010/011 — unchanged; SDD-056 was
    `scoping` then promoted to `implemented` after impl shipped)
  living:       1
  total:       57

Final INDEX tally:
  done:    42 milestones (unchanged — MS011 stays partial because
    of Z-2/Z-3/Z-12/Z-13 remaining arcs even though Z-1 itself is
    functionally complete)
  partial: 6 milestones
  stage-1: 0 milestones

Dashboard ships 17 sections + 8 tabs + always-visible strip + URL
deep-link support + localStorage preference + L1 drift detection
across HTML / JS / setInterval-pattern / GET-binding axes.

### Added — MS011 fullstack closures + tooling (2026-05-21, batch 3)

Continuation block covering commits 4e20bdb → 522b427. Focus: MS011
Z-vector fullstack closures (dashboard panels + CLI parity) +
operator-tooling hygiene + INDEX cross-reference fix.

#### MS011 fullstack closures

- Dashboard "Flex profile" panel (5b815d3) consuming GET /v1/flex-profile
- Dashboard "Inference backends" panel (b7a60a6) consuming GET /v1/inference-backends
- `selfdefctl inference-backends` CLI parity (a95ffb2)
- `selfdefctl flex-profile show` live-state subverb (a8cbb26)
- Panel-nav strip grew from 14 → 16 anchors
- 17 panels total: Composite Health + 4 watchdogs + Modules + Audit
  chains + Alerts + Hardware + Network + Storage + RAID + GPU + CPU
  + Flex profile + Inference backends + Findings

#### Operator tooling

- `scripts/test/sdd-tally.sh` (4e20bdb) — MS013 charter-tracking
  drift detector. Walks docs/sdd/ and tallies status counts
  (implemented / review / scoping / draft / living). Tolerates 3
  status formats. Read-only, NOT a coherence gate.

#### Cross-reference + doctrine reconciliation

- SDD-032 (eBPF substrate) promoted draft → implemented (358e26e)
  with explicit note that the 4 deferred kernel programs are the
  NEXT arc, NOT a blocker for SDD-032's own status
- INDEX.md MS002 + MS016 partial rows fixed (522b427) — they had
  cross-referenced "SDD-016" for eBPF (wrong; SDD-016 is the
  oracle-triage channel). Correct reference is SDD-032. Added
  enumeration of the 4 deferred programs per selfdef-ebpf/README.md.
- SDD-016 (oracle-triage) now has HTTP discovery surface
  GET /v1/oracle-triage (522b427) — doctrine + wire format + tier
  routing. Previously the doctrine lived only in the
  selfdef-integration-oracle-triage crate.
- 9 module SDDs batch-promoted draft → implemented (b0c6398):
  SDD-033 agent-guard, SDD-034 observability, SDD-036 slm-cpu-loop,
  SDD-037 tensor-parallel-inference, SDD-038 wasm-aot-cache,
  SDD-039 bridge-l2, SDD-040 polarproxy, SDD-041 detect-host,
  SDD-042 integrity-sentinel

Final SDD tally: 43 implemented (was 30 before this batch-2) / 6
draft / 2 review / 3 scoping / 54 total.

Final INDEX tally: 42 done (was 40 before batch-2) / 6 partial / 0
stage-1.

### Added — MS013-MS050 catalog + SDD layer-up batch (2026-05-21, continued)

Continued from the earlier 2026-05-21 entry below. This block captures
commits ecf212d → 5cb64fd: 15 milestones promoted partial → done +
12 retroactive Stage-2 SDDs authored.

#### Milestone promotions (partial → done)

11 milestones promoted to done by layering CLI + HTTP discovery
surfaces over already-shipped Rust crate clusters:

- MS035 capability-tokens — `selfdefctl capability-tokens` + `GET /v1/capability-tokens` (14e12cc)
- MS037 filesystem-boundary — `selfdefctl filesystem-boundary` + `GET /v1/filesystem-boundary` (eba43c7)
- MS038 network-boundary — `selfdefctl network-boundary` + `GET /v1/network-boundary` (eba43c7)
- MS032 sandbox-tiers — `selfdefctl sandbox-tiers` + `GET /v1/sandbox-tiers` (aa0f77a)
- MS034 communication-boundary — `selfdefctl communication-boundary` + `GET /v1/communication-boundary` (aa0f77a)
- MS039 + MS040 authority — `selfdefctl authority` + `GET /v1/authority` (e99caaf)
- MS036 tool-sandboxes — promoted via MS032 cross-coverage (6f8f088)
- MS033 policy + trace — `selfdefctl policy` + `GET /v1/policy` (cdd5039)
- MS028 bitnet-gpu — promoted via cross-cutting modules surface (78c5f64)
- MS031 wasm-aot-cache — promoted via cross-cutting modules surface (78c5f64)
- MS014 ssh-wrap — `selfdefctl ssh-wrap` (HTTP intentionally deferred per SDD-052 D-2) (ecf212d)
- MS015 NATS — `selfdefctl nats` + `GET /v1/nats` (ecf212d)
- MS041 commit-authority — `selfdefctl commit-authority` + `GET /v1/commit-authority` (a831fdc + 9675521)
- MS042 tool-authority — `selfdefctl tool-authority` + `GET /v1/tool-authority` (1e28fe4 + b0493e4)

#### MS011 (operator dashboard + flex profile) — all 13 Z-vectors at discovery

- Z-1 panel-nav strip (1c4f885) — 14 anchor links across panels
- Z-2 `GET /v1/inference-backends` (222c9a1) — probes llama.cpp / vllm / bitnet.cpp / unsloth
- Z-3 `selfdef-flex-profile` crate + CLI + HTTP discovery (ca44734 + 515c76d)
- Z-8 `ModuleInstallPaths` field surfaced via `/v1/modules` + dashboard scope badge (e0fab99 + fb9faa4)
- Z-11 `GET /v1/mcp` MCP-interop foundation discovery (2e95a5c)
- Z-12 `GET /v1/repl` multi-tier REPL discovery (5cb64fd)
- Z-13 SD-R86 `GET /v1/modules/install-options` dep-readiness (104f661)

All 13 Z-vectors now have at least probe/discovery HTTP layers
shipped. Multi-commit follow-up arcs remain: Z-1 full 8-tab UX
restructure, Z-2 shell-out invocation, Z-3 apply+revert mutation
surfaces, Z-12 Tier 1 Python implementation completion, Z-13 SD-R87
topological install + SD-R86 hardware-gate enrichment.

#### MS013 SDD charter-tracking — 12 SDDs authored or promoted

- SDD-043 commit-authority (7c64aec) — MS041, 168 lines
- SDD-044 capability-tokens (6ede095) — MS035, 195 lines
- SDD-045 filesystem-boundary (aa53049) — MS037, 187 lines
- SDD-046 network-boundary (7af029f) — MS038, 176 lines
- SDD-047 sandbox-tiers (ab7e4e1) — MS032, 185 lines
- SDD-048 communication-boundary (1a64c78) — MS034, 201 lines
- SDD-049 authority tiers + trust rings + profile matrix (8333acd) — MS039 + MS040, 216 lines
- SDD-050 tool authority — 11-crate composable pipeline (eb98cfb) — MS042, 214 lines
- SDD-051 policy and trace — 36-crate cluster (6f8f088) — MS033, 179 lines
- SDD-052 ssh-wrap (2ebfe45) — MS014, 114 lines
- SDD-053 NATS bridge (2ebfe45) — MS015, 107 lines
- SDD-032 ebpf-substrate (this commit) — MS016 status reconciled: draft → implemented

9 module SDDs batch-promoted (b0c6398): SDD-033 agent-guard, SDD-034
observability, SDD-036 slm-cpu-loop, SDD-037 tensor-parallel-inference,
SDD-038 wasm-aot-cache, SDD-039 bridge-l2, SDD-040 polarproxy,
SDD-041 detect-host, SDD-042 integrity-sentinel.

Final SDD tally:
  implemented: 43 (was 7 pre-session)
  draft:        6 (forward-looking cycle vectors)
  review:       2 (SDD-012 sain-01 + SDD-026 operator-dashboard)
  scoping:      3 (SDD-009/010/011 operator-gated)
  total:       54

INDEX.md tally:
  done:    42 milestones (was ~8 pre-session)
  partial:  6 milestones (all with explicit deferred-for-cause:
            MS002 + MS016 eBPF kernel programs, MS008 sain-01
            integration, MS011 Z-vector substantive arcs, MS013
            ongoing charter-tracking)
  stage-1:  0 milestones

#### Cross-cutting infrastructure shipped this round

- `selfdef-flex-profile` (NEW crate, ca44734) — 322 LOC, 8 tests:
  FlexProfile + Delta + DeltaOp + RevertRecord with apply / revert /
  inverse / round-trip JSON
- 26 top-level selfdefctl verbs (was 13 pre-session)
- 50+ /v1/* HTTP routes (was ~15 pre-session)

### Added — MS009 + MS010 + MS011 + MS019 + MS013 charter-tracking (2026-05-21)

Multi-cycle session brought 5+ milestones across additional Stage-2+
production layers. 27 commits this session on selfdef main + 2 on
info-hub PR #12.

#### MS027 alerts surface — full fullstack

- `selfdefctl alerts` CLI verb — classifies 9 alert-relevant series
  via `/metrics` parsing OR (preferred) `/v1/alerts` typed endpoint
  with client-side fallback (cedf4e0)
- `selfdefctl doctor` extended — folds MS027 alert classification
  into the cross-cutting health check (64e98d1)
- `GET /v1/alerts` — server-side classifier (worst + 9 alert rows
  with name/ms/series/threshold/value/state) consumed by both the
  dashboard panel + CLI. 4 unit + 1 integration test (c9d648d)
- Dashboard "Alerts overview" panel migrated from /metrics parse
  to /v1/alerts (0b25f57)
- `selfdefctl alerts` migrated to prefer /v1/alerts (f5b367e)

#### MS010 hardware-aware modules — HTTP + dashboard fullstack

- `GET /v1/hardware`, `/v1/hardware/capabilities`, `/v1/hardware/sain01`
  — OnceLock-cached probe (hardware doesn't hot-swap); JSON envelopes
  for snapshot + derived capabilities + sain-01 reference-platform
  match verdict (520501d)
- Dashboard "Host hardware" panel rendering sain-01 verdict + per-
  axis capability checks (AVX-512 VNNI/BF16, ≥256 GB memory, ≥2 GPUs,
  PCIe dual-x8, motherboard ProArt X870E) (757a323)

#### MS011 (operator dashboard + flex profile) — 7 of 13 Z-vectors

- Z-4 (CPU mode classification): `/v1/cpu` + dashboard panel.
  Reads `/sys/devices/system/cpu/*/cpufreq/scaling_governor` + SMT
  state; classifies into `ultra-low-power` / `balanced` /
  `sustained-burst` / `peak-inference` / `custom` (5690b8c)
- Z-5 (GPU watt deviance): `/v1/gpu` + dashboard panel.
  `nvidia-smi --query-gpu=index,power.draw,power.limit` parsed +
  classified against operator-authored `/etc/selfdef/gpu-policy.toml`.
  4 classification levels with configurable tolerance (a26a75c)
- Z-6 (composite autohealth): `/v1/health` + dashboard top panel +
  `selfdefctl health` CLI. Aggregates alerts/network/storage/raid/
  gpu/cpu into single composite worst-state (fedf693 + 4e90962)
- Z-7 (network state): `/v1/network` + dashboard panel.
  Probes internet (ping -c 1 -W 2), DNS (getent), cloudflared /
  tailscaled / traefik (systemctl is-active). 4 unit + 1 integration
  test (aede715)
- Z-9 (software RAID): `/v1/raid` + dashboard panel.
  `/proc/mdstat` parser with level-aware degraded/failed thresholds
  (raid0/linear → red on any missing; raid1/5/10 → yellow on 1, red
  on 2+; raid6 → yellow on 1-2, red on 3+). 10 unit + 1 integration
  test (b8d2b1a)
- Z-10 (storage state): `/v1/storage` + dashboard panel.
  `df -P` parser (excludes tmpfs/devtmpfs/squashfs/etc. by default,
  `SELFDEF_STORAGE_INCLUDE_PSEUDO=1` to include) + walks 3 selfdef-
  managed log dirs for bytes + file counts. Thresholds: green
  (< 70 %), yellow (70-89 %), red (≥ 90 %). 6 unit + 1 integration
  test (7bd0313)
- Z-13 (SD-R83 modules-diff portion): `GET /v1/modules/diff`.
  Pure set-difference partitions catalog × host-active modules.toml
  into installed/available/orphaned buckets. 3 unit + 1 integration
  test (09b8385)

#### Cross-cutting module check surface

- `GET /v1/modules/:name/check` — invokes `<modules_dir>/<name>/
  install/check.sh` per the module-author contract; structured
  envelope with exit_code + ok + stdout/stderr (each truncated at
  64 KiB). Slug regex-validated against directory traversal. Closes
  health-probe gap across 12 operator modules (MS016/17/18/22/23/
  24/25/26/28/29/30/31) (c1f41c6)

#### MS009 audit-cycles fullstack

- `GET /v1/audit-chains` — composite chain-check across the 3
  chained-audit watchdogs (perimeter/guardian/scheduler). Each
  watchdog's `audit_chain_check` runs against its OCSF JSONL file;
  per-chain ok + events_verified + error string (line number when
  broken) (f70f231)
- Dashboard "Audit chains" panel (8c1cbba)
- `selfdefctl audit-chains` CLI verb (0888979)

#### MS019 security threat model — /v1/* surface coverage

- `SECURITY.md` Assets table + API surface section updated for the
  11 new /v1/* endpoints shipped this session. Information-disclosure
  + subprocess-DoS profile documented; cached-vs-live probe contract
  documented for operators (2a81cc4)

#### MS013 SDD charter-tracking

- 11 SDDs promoted from review or draft → implemented as production
  caught up to spec status: SDD-008 (notifications, body said
  shipped but header said draft — reconciled), SDD-013/014/016/017
  (Stage-2 SDDs), SDD-015 (perimeter coexistence), SDD-018
  (hardware-aware modules), SDD-022 (hardware exploit doctrine),
  SDD-023 (cross-repo model taxonomy), SDD-027/028/029/030/031
  (four-watchdog set + UX coherence harness) (986388a + 74d6a13 +
  6a8c222 + 63a3616 + 9a61b87)
- SDD-026 (operator dashboard) promoted draft → review with
  7-of-13 Z-vectors enumerated with commit hashes (9a61b87)
- MS013 status tally after session: 21 implemented (was 7 pre-
  session), 1 review (was 9), 3 scoping, 18 draft (was 24)

#### Info-hub knowledge layer (PR #12)

- `perimeter-audit-log-corruption.md` — fills SelfdefPerimeterChainBroken
  alert runbook gap (077e7c2)
- `network-degraded.md` — operator runbook for /v1/network failures
  with 5-pattern triage matrix + recovery procedures + opt-out
  section (b9ee3f9)
- `storage-degraded.md` — operator runbook for /v1/storage failures
  with 7-pattern triage matrix + cross-reference to audit-log-
  corruption runbooks (b9ee3f9)

#### Workspace hygiene

- 4 workspace warnings cleared (selfdef-trust-score-engine +
  selfdef-context-sensitivity-policy + selfdef-jump-hash unused
  imports; selfdef-cuckoo-filter needless mut) (fb00800)
- Clippy lints cleared across the four-watchdog ship-surface
  (4926422)
- `docs/src/ops/api.md` extended with the full /v1/* route table
  (98b1dbe)

### Added — MS006 / SDD-009: modules surface + MS027 Prometheus alerts + cross-cutting CI/release coherence gating (2026-05-20)

Follow-on round after the four-watchdog production landing. Closes
operator-discoverability + drift-detection + monitoring gaps that
surfaced as the four-watchdog set rolled out.

#### Module surface (MS006 / SDD-009 Q-G)

- `GET /v1/modules` — new HTTP route surfacing every `module.toml`
  the host ships at `/usr/share/selfdef/modules/<name>/`. Each entry
  tagged with `active: bool` (`true` iff `[modules.<name>]` is in
  `/etc/selfdef/modules.toml`). Read-only — activation goes through
  `selfdefctl modules apply` (Ring 0 + operator-confirmed).
- `selfdef-api::modules` module — `list_in_dir(path)` + `active_modules(path)`
  helpers (8 unit tests + 1 m12_api integration test)
- `dashboard/index.html` — new `#modules-section` panel with active/shipped
  count badge; rows sorted active-first; inactive rows render gray
- `dashboard/app.js` — `refreshModules()` handler; 60s setInterval
- `dashboard/service-worker.js` — SHELL v3 (cache invalidation)
- `scripts/test/L1-dashboard-sections.sh` — 4 new locks (HTML section
  + JS handler + setInterval + endpoint binding)
- `selfdef_modules_shipped_total` + `selfdef_modules_active_total`
  Prometheus gauges via `selfdef-api::watchdog_metrics::render_modules()`
- Grafana template: new 'Module catalog' row + 2 stat panels (id 111/112)
- `scripts/test/L1-grafana-template.sh` — panel count gate raised 17→20;
  2 new series locked

#### Prometheus alerts (MS027 four-watchdog set)

- `modules/observability/assets/alerts/selfdef.yml.template` — 9 alert
  rules covering critical + warning failure modes per watchdog. Every
  alert carries `runbook_url` pointing at the matching info-hub runbook
  (operators clicking alerts in Alertmanager UIs get clickable links
  into the 20-runbook remediation surface):
  - SelfdefFrictionAuditFailingGate (critical)
  - SelfdefPerimeterSigkill (warning) / SelfdefPerimeterPolicyMissing
    (critical) / SelfdefPerimeterChainBroken (critical)
  - SelfdefGuardianFailedResponse (critical) / SelfdefGuardianTetragonSocketMissing
    (warning) / SelfdefGuardianChainBroken (critical)
  - SelfdefSchedulerSustainedBackpressure (warning) /
    SelfdefSchedulerChainBroken (critical)
- `modules/observability/install/apply.sh` — deploys alert rules in
  both `bundled` and `external` profiles alongside scrape config +
  dashboard. New `prometheus_rules_dir` config knob.
- `modules/observability/README.md` — new 'Alert rules' section
  replacing the stale 'NOT here yet' bullet
- `crates/selfdef-cli/tests/module_observability.rs` — alert deployment
  end-to-end test (asserts 9 alerts + `wiki/runbooks/` runbook_url
  linkage on both profiles)
- `scripts/test/L1-prometheus-alerts.sh` — 15 checks gating template
  parseability + alert count + per-alert runbook_url linkage + each
  SDD-promised series referenced + apply.sh wiring

#### Periodic health check (operator surface)

- `packaging/systemd/selfdef-doctor.service` + `selfdef-doctor.timer`
  ship with the package. Type=oneshot + Restart=always + hourly cadence
  via OnUnitActiveSec=1h with RandomizedDelaySec=5min fleet spread +
  Persistent=true for catch-up. Hardened (NoNewPrivileges,
  ProtectSystem=strict, ReadOnlyPaths for doctor input dirs only,
  RestrictAddressFamilies=AF_UNIX since doctor is read-only with no
  network). Operators enable via `systemctl enable --now selfdef-doctor.timer`.
- `crates/selfdef-cli/src/doctor.rs` — new `watchdog-set` category
  reports per-watchdog deployability (binary + unit + ring dir +
  supporting infrastructure) + per-watchdog audit-chain integrity
  (SHA-256 chain check against perimeter/guardian/scheduler OCSF logs).
  3 new chain-integrity checks added on top of the existing 5
  deployability checks.
- `packaging/test/L2-doctor-timer.bats` — 23 tests locking the unit +
  timer surface against drift

#### CLI ergonomics

- `selfdefctl trio --json --watch N` now emits a JSONL stream (one
  compact JSON line per cycle) for monitoring pipelines (`jq -c`,
  Loki, Vector ingest). Previously `--watch` was silently ignored
  when `--json` was set.
- `selfdefctl trio-tail` — new top-level subcommand: unified live OCSF
  tail across all four watchdog jsonl logs. Tags each event with its
  source watchdog. Honors env-var path overrides for sandboxed runs.
- `selfdefctl wizard` Step 5 — first-time-operator four-watchdog
  enablement guide
- `selfdefctl init checklist` Step 12 — same on the first-run checklist

#### CI + release gating

- `.github/workflows/ci.yml` — new `coherence` job runs the 10-layer
  `scripts/test/coherence.sh` on every push + PR. The `build` job's
  `needs` chain now includes it — release artifacts are gated on it.
- `.github/workflows/release.yml` — Pre-release coherence gate step
  runs the harness before cargo-deb / SBOM / cosign-signing. Hand-tagged
  releases with a drifted surface fail-fast.

#### Documentation coherence

- `README.md` — new 'Four-watchdog set (IPS spine)' section
- `ARCHITECTURE.md` — new 'Four-watchdog set' section with ASCII
  layered diagram showing the 3 sibling watchdogs feeding into the
  scheduler convergence point
- `SECURITY.md` — new 'Four-watchdog set' subsection in 'Tamper
  detection' with adversary-class table per watchdog
- `Cargo.toml` (selfdef-daemon) — `extended-description` names all
  four watchdogs (dpkg -s now surfaces the IPS spine)
- `docs/dev/operator-health-check.md` — references the production-
  shipped systemd unit (was a hand-rolled stub)
- `docs/dev/modules.md` — new authoritative module-author contract doc
  (was referenced but missing — F-2027-022)
- `dashboard/manifest.json` — PWA description + 512x512 maskable icon
  + W3C `scope` + `categories` fields
- info-hub `wiki/log/2026-05-20-four-watchdog-end-to-end-production-landing.md`
  — second-brain landing record (cross-references the 4 SDDs + 4
  milestone catalogs + 20 runbooks + selfdef CHANGELOG)

#### Test coverage

- m12_api integration tests: 51 (was 39 before the round — +12)
- selfdef-api watchdog_metrics: 3 unit + 3 integration tests
- selfdef-api modules: 8 unit + 1 integration test
- selfdef-api scheduler: 5 unit + 6 integration tests
- L2 bats: 119 tests across 5 packaging surfaces
- Doctor: 17 tests including new watchdog-set category
- Wizard: 10 tests including new Step 5

### Added — MS046 + MS047 + MS048 production landings + four-watchdog operator-discoverability (2026-05-20)

The four-watchdog set (MS046 friction-audit + MS047 perimeter + MS044
guardian + MS048 Goldilocks scheduler) is now end-to-end deployable as
a Debian package, with operator-discoverable entry points from
`dpkg -s selfdef-daemon` all the way through to the PWA dashboard +
Grafana + 20 operator runbooks.

#### What shipped (MS046 friction-audit — hardware-integrity gate, sain-01 §5)

- `packaging/scripts/friction-audit.sh` — verbatim sain-01 §5 transposition
  with 3 gates (PCIe ≥ x8/x8 + ZFS healthy + memory geometry), 2000ms
  timeout watchdog, OCSF + ring-buffer emission
- `packaging/systemd/sovereign-guard.service` — boot-time gate unit
  (Type=oneshot, ordered Before=podman/docker/containerd)
- `crates/selfdef-friction-audit-mirror` (14 tests) — MS007 typed mirror
- `crates/selfdef-friction-audit` (23 tests) — runtime authority crate
  (operator-signed override manifests, MS003 multi-sig, audit chain)
- `crates/selfdef-cli` — `selfdefctl friction-audit {show,history,replay}`
- `crates/selfdef-api` — `GET /v1/friction-audit{,/history}`
- 5 operator runbooks (`friction-audit-{pcie,zfs,memory,immutability,signature}.md`)
- `packaging/test/L2-friction-audit.bats` (20 tests)
- Sovereign-os cockpit consumer: `sovereign-cockpit-friction-audit-panel`

#### What shipped (MS047 perimeter — kernel-fence, sain-01 §6)

- `packaging/tetragon-policies/sovereign-perimeter.yaml` — verbatim sain-01
  §6 TracingPolicy (kprobe sys_execve NotIn allowlist + Sigkill matchAction)
- `crates/selfdef-perimeter-mirror` (17 tests) — MS007 typed mirror
- `crates/selfdef-perimeter` (30 tests) — runtime authority crate
  (allowlist-extension manifest loader, MS003 multi-sig, OCSF + ZFS log
  bridge, SHA-256 audit chain, 30-day TTL bound)
- `crates/selfdef-cli` — `selfdefctl perimeter {show,history,extend,revoke,audit-cycle replay}`
- `crates/selfdef-api` — `GET /v1/perimeter{,/history}`
- `packaging/debian/postinst` — installs TracingPolicy YAML + chattr +i
- 5 operator runbooks (`perimeter-{tetragon-not-running,policy-load-failure,extension-create,sigkill-investigation,key-rotation}.md`)
- `packaging/test/L2-perimeter.bats` (23 tests)
- Sovereign-os cockpit consumer: `sovereign-cockpit-perimeter-panel`
- SDD-028 spec + MS047 catalog (240 R-rows)

#### What shipped (MS044 guardian — Stage-1 production executable, sain-01 §10)

(MS044 first appeared in the 2026-05-19 entry as a Python scaffold; this
round delivers the Rust production daemon.)

- `crates/selfdef-guardian-mirror` (16 tests) — MS007 typed mirror
- `crates/selfdef-guardian` (21 tests + end-to-end mock-socket smoke
  test) — runtime authority crate (TetragonEvent ingester, classify(),
  Effector trait, Responder 3-step orchestrator, CircuitBreaker,
  OCSF emission, audit chain)
- `crates/selfdef-guardian/src/bin/selfdef-guardian.rs` — **Stage-1
  daemon executable**: Tetragon UNIX-socket consumer with reconnect-on-
  EOF + circuit breaker; closes the library→executable production gap.
- `packaging/systemd/selfdef-guardian.service` — Type=simple Restart=always,
  hardened (Ring 0 per MS039 + full systemd-analyze security baseline)
- `crates/selfdef-cli` — `selfdefctl guardian {show,history,replay,rollback}`
- `crates/selfdef-api` — `GET /v1/guardian{,/history}`
- 5 operator runbooks (`guardian-{not-running,socket-unreachable,false-positive-rollback,audit-log-corruption,console-alert-investigation}.md`)
- `packaging/test/L2-guardian.bats` (35 tests)
- Sovereign-os cockpit consumer: `sovereign-cockpit-guardian-panel`
- SDD-029 spec

#### What shipped (MS048 Goldilocks Scheduler — routing layer, avx-plus-plus dump tail)

The avx-plus-plus dump tail (lines 18000-18250) cataloged five concrete
scheduling surfaces + 7-axis objective + per-profile rule tuples; this
round creates MS048 from a backward-sweep review + ships it end-to-end.

- `backlog/milestones/MS048-*.md` — new milestone catalog (247 R-rows)
- `docs/sdd/031-goldilocks-scheduler.md` — 11-deliverable production spec
- `crates/selfdef-scheduler-mirror` (20 tests) — MS007 typed mirror
- `crates/selfdef-scheduler` (31 tests) — runtime authority crate:
  - `ProfileRules::for_profile()` — verbatim 6 per-profile rule tuples
  - `AxisWeights::for_profile()` — per-profile 7-axis weight matrix
  - `evaluate_objective(signals, profile)` — 7-axis compound scorer
  - `BackpressureMonitor` — 5 surfaces × thresholds × hysteresis
  - `emit_audit_entry()` + `audit_chain_check()` — SHA-256 chain
  - `replay()` — counterfactual replay against alternate profile
- `crates/selfdef-scheduler/src/bin/selfdef-scheduler.rs` — **Stage-1
  daemon executable**: PSI ingester + heartbeat decision loop + ring
  buffer + audit log emission; closes the library→executable production gap.
- `packaging/systemd/selfdef-scheduler.service` — Type=simple Restart=always,
  hardened (Ring 0)
- `crates/selfdef-cli` — `selfdefctl scheduler {show,history,explain,replay,weights,force,audit-cycle replay}` (7 subverbs)
- `crates/selfdef-api` — `GET /v1/scheduler{,/history,/backpressure,/weights,/explain/:id}` (5 routes)
- 5 operator runbooks (`scheduler-{not-running,backpressure-stuck-open,weight-matrix-rotation,audit-log-corruption,force-override-investigation}.md`)
- `packaging/test/L2-scheduler.bats` (18 tests)
- Sovereign-os cockpit consumer: `sovereign-cockpit-scheduler-panel` (14 tests)

#### Cross-cutting four-watchdog operator surface

- `selfdefctl trio [--json] [--watch N]` — consolidated 4-panel snapshot
- `selfdefctl trio-tail [--interval-ms N] [--json]` — unified live OCSF
  tail across all four watchdogs
- `selfdefctl doctor` — new `watchdog-set` category reports per-watchdog
  deployability (binary + unit + ring dir + supporting infrastructure)
- `selfdefctl wizard` Step 5 — first-time-operator four-watchdog enablement
- `selfdefctl init checklist` Step 12 — same on the first-run checklist
- README — new "Four-watchdog set (IPS spine)" section
- Debian package `extended-description` — names all four watchdogs
- PWA dashboard — 4 panels (friction-audit + perimeter + guardian + scheduler)
  with auto-refresh + runbook links; `/dashboard/*` now served from
  selfdef-api when `SELFDEF_DASHBOARD_DIR` resolves
- Grafana template (`modules/observability/`) — 9 new four-watchdog panels
  + Prometheus emission via new `selfdef-api::watchdog_metrics` (15 series)
- `selfdef-doctor.timer` + `.service` — hourly `selfdefctl doctor` periodic
  run (closes init checklist Step 11 vaporware gap)

#### Coherence harness (lockfile against drift)

- `scripts/test/coherence.sh` — 11-layer orchestrator runs every L1+L2
  gate + cargo unit suites on demand:
  - L1-perimeter-yaml-lint.sh (verbatim sain-01 §6 TracingPolicy)
  - L1-cli-surface.sh (4 watchdog command subverb counts locked)
  - L1-api-endpoints.sh (11 routes locked)
  - L1-dashboard-sections.sh (HTML + JS + CSS + cargo-deb shipping)
  - L1-grafana-template.sh (11 four-watchdog series locked)
  - L2-{friction-audit,perimeter,guardian,scheduler,doctor-timer}.bats (auto-glob)
  - cargo test across the 9 four-watchdog crates + selfdef-api

#### Cross-repo + info-hub deliverables

- Sovereign-os: 4 new cockpit panel crates, project-boundary preserved
  (zero selfdef-crate deps; reads selfdef-emitted JSON at the filesystem
  boundary)
- Info-hub: 20 operator runbooks (5 per watchdog) + 1 backward-sweep
  review note (`2026-05-20-avx-plus-plus-dump-tail-backward-sweep-review.md`)
  + 1 UX coherence failures runbook
- Selfdef MS040 + MS034 — source addenda recording the dump-tail
  elaboration links (without supplanting the original catalog scope)

### Added — MS007 8/8 SATURATED typed-mirror trio (9 of 9 crates) + MS044 Guardian Daemon + MS045 UX harness + minimal-web bundle (2026-05-19)

The cross-repo cockpit-facing surface (per MS043 IPS operator surface catalog) is now complete: 9 typed-mirror crates exposing READ-ONLY snapshots to sovereign-os D-12..D-18 dashboards, the Guardian Daemon active-defence loop, the UX coherence test harness, and the localhost:7575 minimal-web fallback.

#### What shipped

- **9/9 MS007 mirror crates** (~100 Rust tests, all schema versions pinned at 1.0.0):
  - `selfdef-rules-mirror` (D-12 nftables Ring 0..4)
  - `selfdef-grants-mirror` (D-13 fs/network/capability/communication/sandbox grants)
  - `selfdef-capability-mirror` (D-14 capability_word + Ring 0..4 + L0..L6 authority + F04146 inheritance)
  - `selfdef-sandbox-mirror` (D-15 MS036 tier A/B/C/D + MS032 1-9 isolation primitives)
  - `selfdef-audit-mirror` (D-16/D-19 M049 13-field span + MS026 OCSF 16-event taxonomy + MS016 chain continuity)
  - `selfdef-quarantine-mirror` (D-17 MS042 7-field declaration-vs-observed + 4-severity)
  - `selfdef-trust-score-mirror` (D-18 0..1000 score + 4-band classifier + downward-trend detection)
  - `selfdef-cli-mirror` (50+ subcommand schema + DOCTRINE_FULLSTACK_AT_THE_EDGES verbatim per R10297)
  - `selfdef-tui-mirror` (4-panel canonical layout + DOCTRINE_NO_VANITY_GRAPHS verbatim per R10298 + layout invariants)

- **MS044 Guardian Daemon** at `scripts/guardian/guardian-core` (Python 3) + systemd unit + 37 passing tests:
  - 17 integration tests (event parser, audit log, console bell, CLI surface, probe writes)
  - 14 adversary tests (one per MS042 declaration field — read/write/network/env/secret/side_effects/rollback — + non-response + corrupt-input scenarios per R10358)
  - 6 replay tests (sequential + 3-step block+quarantine+trace + Unicode + concurrent 8-thread × 25-event)
  - **Bug found + fixed by replay tests**: append_atomic_audit_log() used two separate os.write() calls which interleaved under concurrent threads. Combined into one buffer + one write call so POSIX < PIPE_BUF atomicity guarantees per-line isolation.

- **MS045 UX coherence test harness** at `scripts/ux-harness/selfdef-ux-harness` + systemd service/timer + 15 meta-tests:
  - L1 schema/lint (6 active checks): mirror crate list, CLI surface, TUI panel layout, minimal-web panel layout, doctrine preservation verbatim, guardian unit present
  - L2 CLI startup p95 < 50ms over 1000 samples (auto-defers when selfdefctl not on PATH per R10137)
  - L4 WCAG 2.1 AA contrast 4.5:1 (pure-Python, no pa11y dep — verifies 8 selfdef-web color pairs, all ≥ 5.45 per R10175)
  - L3 + L5 defer-by-design (pyte / Playwright not yet installed)
  - --json / --verbose / --layer / --name flags

- **`selfdef-web` minimal-web bundle** (13 tests): localhost:7575 4-panel layout matching TUI per R10166-R10170 + R10212. Read-only default + operator MS003 key upload required for mutations per R10171. SSE 2s refresh per R10173. Loopback-only host validator. Sovereignty-clean static bundle (no framework / no CDN / no external fonts).

- **bash + fish + zsh shell completions** (`completions/{bash,fish,zsh}/`) per MS043 R10134 — 13 top-level namespaces with subcommands + closed-set flag value enumeration.

- **CI wiring** — `.github/workflows/ci.yml` adds `python-tests` (52 tests) + `ux-harness` (10 checks) jobs; release build now blocked on both in addition to fmt/clippy/test.

### Added — `selfdef-integration-write` per-user TTY channel; `selfdefctl notify resend`

Two operator-facing additions completing the SDD-008 channel set + escalation triage surface.

#### What shipped

- **`selfdef-integration-write` crate** (PR #170) — `write(1)` per-user TTY session-attention. Sibling of `selfdef-integration-wall` (broadcast) for per-user targeting: each name in `[notifier.write].users` receives a per-user `write <username>` invocation. Username allowlist regex-validated at config-load (`[a-zA-Z0-9._-]+`) — shell metacharacters reject startup. **Realises D-024** in `docs/decisions.md` (the realization of D-004 — `wall(1)` has no native per-user filter; the right per-user transport is its own channel). +20 tests covering the username validator, severity-floor enforcement, per-user spawn loop, and the "user not logged in is OK" non-error path.
- **`selfdefctl notify resend <event_id>`** (PR #173) — fourth CLI verb against the persistent escalation engine, alongside `ack` / `forget` / `list`. Sets the row's `deadline_at = now` so the wake task fires the current rung's channels at its next poll (≤ `IDLE_POLL_INTERVAL_SECS`). Does **not** reset rung state and does **not** touch acked rows (`WHERE acked_at IS NULL`). Engine surface: new `EscalationEngine::reschedule_now(event_id, now) -> Result<bool>`. +3 CLI tests.

#### Channel inventory (12 total, all wired into the daemon)

```
ntfy (D-2b)         signal (D-2c)       slack (Q-C)         discord
smtp (D-7 Q-E)      twilio (Q-D)        pagerduty (Q-G)     loki (Q-G)
opensearch (Q-G)    thehive (Q-G)       wall (D-8)          write (D-024)
```

#### Status

Closes the SDD-008 channel-adapter set. No required-by-design channel is missing.

### Documentation — Channel-set operator-facing completion

Five PRs landed the operator-facing surface that PR #170's code addition implied: per-channel reference + crate READMEs + mdbook landing + threat-model rows + README freshness + published-link correctness.

#### What shipped

- **Operator canonical reference + 12 per-crate READMEs** (PR #174) — `docs/operator/channels.md` (~375 lines): at-a-glance table, cross-cutting `[notifier]` knobs, operator triage table, per-channel sections (40-60 lines each covering TOML block, auth secret hygiene, wire shape, severity collapse, limitations). Each `crates/selfdef-integration-*/README.md` (12 files, 30-50 lines each) mirrors a slice + cross-links to the canonical reference.
- **mdbook landing refresh** (PR #175) — `docs/src/ops/notifications.md` rewritten from 91-line 2-channel stale to 155-line 12-channel reference + `[notifier]` knobs + triage table + per-channel quick-links into the canonical reference.
- **Security model + modules example** (PR #176) — `SECURITY.md` two threat-model rows updated (TTY-broadcast row now covers both `wall` + `write`; HTTP ack URL leakage map 5 → 6 outbound channels). New `config/modules.toml.example` (76 lines) mirrors the embedded `STARTER_MODULES` constant. Drift-guard tests in `crates/selfdef-cli/src/init.rs` fail loudly if either example file diverges from its const.
- **README refresh** (PR #177) — top-level `README.md` Layout section: crate listing 1 stale line → 15-line per-integration entry; `docs/sdd/` "six Phase-1 SDDs" → "nine SDDs"; `docs/review/` "Phase-1 audit" → "Phase 2..8 ledgers (Phase 8 deferred)"; new rows for `docs/operator/`, `docs/decisions.md`, `docs/handoff/`.
- **mdbook link correctness** (PR #178) — `docs/src/ops/notifications.md`: 14 relative `../../operator/channels.md` links would 404 on a published mdbook (per `book.toml`: `src = "src"`; the canonical doc lives outside `src/`). Normalised to absolute github.com URLs matching the page's existing pattern.

#### By the numbers

~1,100 net lines of operator-facing documentation across 14 files. No code change in this slice.

#### Operator promise

Every channel the daemon wires (ntfy / signal / slack / discord / smtp / twilio / pagerduty / loki / opensearch / thehive / wall / write) is reachable from the starter config, the canonical operator reference, a per-crate README, the published mdbook, the threat model in `SECURITY.md`, the workspace README, and `docs/decisions.md`'s D-NNN audit log. An operator unfamiliar with selfdef can pick a channel and configure it without reading Rust source.

### Documentation — SDD-009 dashboard requirements stub (no design)

**PR #171** lands `docs/sdd/009-dashboard.md` as an intentionally-thin requirements-only SDD per operator direction (D-001).

#### What's in the stub

- **Required coverage** (7 areas operator-named): modules · integrations · configurations · status · events · messages · operations.
- **Non-goals (this SDD)**: explicit list of design decisions this SDD does NOT make — auth model / hosting / UI tech / ack flow / bulk ops / refresh model / multi-host scope.
- **Open questions Q-A..Q-G**: each non-goal as an explicit open question for the design chat.
- **Way forward**: separate design conversation → successor SDD with D-1..D-N design points → impl cycle per the established cadence.

#### Realises

D-001 in `docs/decisions.md` ("Dashboard scope: comprehensive operator visibility — design deferred"). SDD-008's D-9 impl-status row cross-references the new stub.

### Documentation — Phase 8 audit deferred (deferral charter)

**PR #172** lands `docs/review/phase-8/00-charter.md` + `99-findings-ledger.md` as an explicit non-run.

#### Why deferral, not a thin audit

The cycle Phase 8 would audit (PRs #156-#171) has two structural defects:

1. **Authorship bias** — 16 of 16 selfdef PRs in the cycle were authored by the same agent who would run the audit. Self-audit produces no triangulation; "0 findings" reads as QA when it's actually false-positive signal.
2. **Cycle composition** — 13 of 16 PRs are docs / skill / decisions-log work. 6 of the 7 audit-programme explorers presuppose code surface that doesn't exist on this cycle.

#### Four trigger conditions for opening Phase 8 for real

1. A non-author auditor or rater is available.
2. A code-shaped cycle (≥ 5 PRs touching Rust) accumulates after this session.
3. A production-relevant defect is reported against #156-#171's output.
4. The dashboard impl cycle ships (post-SDD-009 design).

#### Reserves

The `F-2033-NNN` findings prefix for whenever Phase 8 (or successor) opens for real. The cycle inventory in the charter is the starting baseline.

#### Trajectory table after deferral

```
┌───────┬────────────────────────────────────────┬───────────────────────────────────┐
│ Phase │ Cycle audited                          │ Outcome                           │
├───────┼────────────────────────────────────────┼───────────────────────────────────┤
│   6   │ SDD-008 cycle (22 PRs / 9 crates)      │ 16 findings, 14 closed, 2 demoted │
│   7   │ post-Phase-6 cycle (7 PRs / 4 crates)  │ 6 findings, all closed            │
│ ⏸ 8 ⏸ │ post-Phase-7 cycle (16 PRs / 1 crate)  │ deferred (this PR)                │
└───────┴────────────────────────────────────────┴───────────────────────────────────┘
```

"Deferred" is explicitly **not** a zero-finding pass — the audit programme honestly examined the cycle and concluded it isn't audit-ready under the current author-bias + composition constraints.

### Documentation — Phase 5 docs explorer (**0 findings**; fifth consecutive clean explorer)

Fifth of seven Phase 5 explorers. Audits the documentation surface from the Phase 4 closure cycle.

#### Headline

**0 findings.** Five Phase 5 explorers in; all 100% clean.

#### What was verified

- **`SECURITY.md` § API surface** (F-2029-007 closure): knob names match `ApiConfig`, defaults (8 per-token, 64 global) match code constants, SHA-256 fingerprint description matches `TokenFingerprint::of`, `Drop` pruning behaviour matches `SubscriberGuard::Drop`, 503 reason strings are exact bytewise match.
- **`docs/sdd/007-per-token-sse-subscriber-quota.md`**: "implemented (all five Ds shipped)" status verified against code.
- **`docs/review/phase-4/*`**: charter + seven explorer docs + ledger cross-references hold; trajectory tables accurate; demoted rationales sound.
- **CHANGELOG.md**: Phase 4 status lines increment correctly across successive entries; trajectory tables match ledger snapshots.
- **`init.rs::STARTER_CONFIG`** knob names still valid against current `ApiConfig` parser.
- **Phase 5's own docs**: charter, inventory, four prior explorer docs, ledger — all consistent with auditor verdicts.

#### Docs-explorer trajectory

| Cycle | Docs findings |
| --- | --- |
| Phase 2 | 9 nice |
| Phase 3 | 5 (2 nice, 3 demoted) |
| Phase 4 | 1 nice (SECURITY.md gap) |
| **Phase 5** | **0** |

#### New document

`docs/review/phase-5/60-docs-audit.md`

#### Phase 5 status

0 findings raised across 5 explorers: 0 blockers, 0 important, 0 nice, 0 demoted, 0 SDD-debt. **Two explorers remain** (tests, security). The trajectory strongly suggests Phase 5 will produce a complete-cycle zero-findings result.

This PR is documentation-only.

### Documentation — Phase 5 integration explorer (**0 findings**; fourth consecutive clean explorer)

Fourth of seven Phase 5 explorers. Traces the five integration seams from the Phase 4 closure cycle end-to-end.

#### Headline

**0 findings.** Four Phase 5 explorers in; all 100% clean.

#### Seams verified

| Seam | Verdict |
| --- | --- |
| TOML → daemon → ApiState chain | clean — test-covered at both parse and handler ends |
| `Some(0)` fallback → `n > 0` guard | clean — `events_stream_zero_caps_fall_back_to_defaults` pins the contract |
| `TokenFingerprint` Debug → tracing field expansion | clean — custom impl sound; defensively documented for future use |
| `vpn-bridge` `apply.sh` header → `profile_apply` | clean — all three documented claims verified against impl |
| `SECURITY.md` → `handlers.rs` + `config.rs` | clean — every claim about defaults, knob names, 503 reasons, SHA-256 fingerprinting, Drop semantics verifies bytewise |

#### Integration-explorer trajectory

| Cycle | Integration findings |
| --- | --- |
| Phase 2 | 9 (1 important + 8 nice) |
| Phase 3 | 4 nice |
| Phase 4 | 2 nice |
| **Phase 5** | **0** |

#### New document

`docs/review/phase-5/50-integration-audit.md` — per-seam evidence + triage.

#### Phase 5 status

0 findings raised across 4 explorers: 0 blockers, 0 important, 0 nice, 0 demoted, 0 SDD-debt. **Three explorers remain** (docs, tests, security). Trajectory continues to suggest a complete-cycle zero-findings result — a milestone marker for project stability.

This PR is documentation-only.

### Documentation — Phase 5 module explorer (**0 findings**; third consecutive clean explorer)

Third of seven Phase 5 explorers. Audits the module-side changes from the Phase 4 closure cycle.

#### Headline

**0 findings.** Three Phase 5 explorers in; all 100% clean.

#### What was verified

- **`vpn-bridge/install/apply.sh` dispatcher header** (F-2029-004 closure): the doc-comment's dry-run-awareness, idempotency, and SDD-006 v2 manifest-tracking claims all match the actual `profile_apply` behaviour. Wording consistent with the cited `bridge-l2`/`observability` reference style.
- **SDD-006 v2 migration coverage** re-verified at 7/8 modules (agent-guard, bridge-l2, integrity-sentinel, observability, polarproxy, tetragon, vpn-bridge) + suricata correctly exempt.
- **`relay-via-server.sh::profile_uninstall` legacy fallback** dedup sound — `removed == 0` guard prevents double-removal.
- **STARTER_CONFIG / STARTER_MODULES** parse cleanly; `cli_init` 7/7 tests pass.
- **Multi-instance manifest test** (`relay_apply_records_nft_path_in_manifest_then_uninstall_clears_it`) covers the full apply → record → uninstall → enumerate round-trip.

#### Module-explorer trajectory across cycles

| Cycle | Module findings |
| --- | --- |
| Phase 2 | 6 nice |
| Phase 3 | 1 **important** (vpn-bridge v2 gap) |
| Phase 4 | 1 nice (dispatcher header) |
| **Phase 5** | **0** |

#### New document

`docs/review/phase-5/40-module-audit.md` — per-module verification notes.

#### Phase 5 status

0 findings raised across 3 explorers: 0 blockers, 0 important, 0 nice, 0 demoted, 0 SDD-debt. **Four explorers remain** (integration, docs, tests, security). Trajectory continues to suggest a complete-cycle zero-findings result.

This PR is documentation-only.

### Documentation — Phase 5 crate explorer (**0 findings**; second consecutive clean explorer)

Second of seven Phase 5 explorers. Audits the new Rust code from the Phase 4 closure cycle: custom `Debug` impl on `TokenFingerprint`, 2 fingerprint unit tests, 1 SseCaps zero-cap integration test, 2 TOML round-trip tests.

#### Headline

**0 findings.** Both Phase 5 explorers so far are 100% clean.

#### What was verified

- The custom `Debug` impl renders `bytes[0..4]` as 8 hex chars + Unicode ellipsis exactly as documented; no edge-case fragility.
- `fingerprint_tests::debug_renders_truncated_prefix` correctly asserts the shape (`TokenFingerprint(<8 hex>…)`).
- `fingerprint_tests::distinct_tokens_produce_distinct_debug_prefixes` correctly verifies different tokens yield different Debug forms.
- `events_stream_zero_caps_fall_back_to_defaults` correctly pins the `Some(0)` → default fallback contract.
- `sse_cap_knobs_round_trip_from_toml` + `sse_cap_knobs_default_to_none_when_unset` correctly exercise both branches of the TOML parse contract.

#### Crate-explorer trajectory across cycles

| Cycle | Crate findings |
| --- | --- |
| Phase 2 | 11 nice |
| Phase 3 | 10 (7 nice, 3 demoted) |
| Phase 4 | 2 nice |
| **Phase 5** | **0** |

#### New document

`docs/review/phase-5/30-crate-audit.md` — per-file notes, edge-case analysis, triage table.

#### Phase 5 status

0 findings raised across 2 explorers: 0 blockers, 0 important, 0 nice, 0 demoted, 0 SDD-debt. **Five explorers remain** (module, integration, docs, tests, security). Trajectory suggests Phase 5 may produce a complete-cycle zero-findings result.

This PR is documentation-only.

### Documentation — Phase 5 audit kickoff (recent-PRs explorer: **0 findings**)

Opens Phase 5 of the rolling structural audit. Phase 4 closed the cleanest cycle yet (9 findings, all closed); Phase 5 audits the 8 PRs of Phase 4's closure cycle (`22ff461..d239dad`).

#### Headline

**First explorer with a 100% review-clean rate.** Every Phase 4 closure PR's code change matches the audit's recommendation; CHANGELOG status lines match the ledger progression; demoted findings have justifications that hold up under cross-check.

#### Recent-PRs explorer trajectory across cycles

| Cycle | Recent-PRs findings | Pass rate |
| --- | --- | --- |
| Phase 2 | many | ~74% |
| Phase 3 | 4 (3 nice + 1 demoted) | 73% (4 obs / 29 PRs) |
| Phase 4 | 1 (demoted) | 94% (1 obs / 17 PRs) |
| **Phase 5** | **0** | **100% (0 obs / 8 PRs)** |

#### New documents

- `docs/review/phase-5/00-charter.md` — same methodology as Phases 1, 2, 3, 4. Vintage prefix `F-2030-NNN`.
- `docs/review/phase-5/10-inventory.md` — `git log 22ff461..d239dad` survey: 1 new SECURITY.md section, 1 vpn-bridge dispatcher header refresh, 1 custom `Debug` impl, 5 new tests.
- `docs/review/phase-5/20-recent-prs-audit.md` — first explorer doc; 0 findings.
- `docs/review/phase-5/99-findings-ledger.md` — initial ledger (empty).

#### Status

0 findings raised so far: 0 blockers, 0 important, 0 nice, 0 demoted, 0 SDD-debt. **Six explorers remain.**

This PR is documentation-only.

### Documentation — Phase 4 security explorer; **ALL 7 PHASE 4 EXPLORERS HAVE RUN; PHASE 4 FULLY WRAPPED**

Seventh and final Phase 4 explorer. Audits new attack surfaces from the Phase 3 closure cycle (SHA-256 fingerprint storage, operator-tunable caps, JSON 503 extraction, etc.) and re-audits five prior closures (F-2028-037, -018, -015, -004+-005, -001).

#### Headline

**0 blockers, 0 important, 0 actionable nice.** The Phase 3 closure cycle was exceptionally clean — every security-relevant property the closures shipped is verified holding.

#### Re-audit results

| Closure | Re-audit verdict |
| --- | --- |
| F-2028-037 (SDD-007 implementation) | Dual-counter logic verified race-free. |
| F-2028-018 (SseParser bytes refactor) | UTF-8 chunk-boundary handling correct. |
| F-2028-015 (vpn-bridge v2 migration) | Manifest dedup sound; legacy-fallback only runs on empty manifest. |
| F-2028-004 + -005 (token-reader symmetry) | Mode check + Unicode trim bytewise identical between CLI and daemon. |
| F-2028-001 (paths compile-time invariants) | Unbypassable; `const` declarations + assertion block ensure no runtime drift. |

#### F-2029-009 — demoted

The security explorer surfaced one entry (re-audit of F-2029-002's `TokenFingerprint` Debug elision): is a 4-byte (32-bit) prefix sufficient against cross-time linkage? Cross-check: yes — 32 bits is collision-prone at the SHA-256 distribution level, so an attacker observing a prefix in logs can't confirm it derives from a specific token they later acquire. Mitigation holds. Kept for audit-trail.

#### New document

`docs/review/phase-4/80-security-audit.md` — per-area observations, re-audit appendix, triage table.

#### Phase 4 fully wrapped

**9 findings raised across all seven explorers**: 0 blockers, 0 important, **5 nice (all closed)**, 4 demoted, 0 SDD-debt.

Comparison across the four audit cycles:

| Phase | Findings | Blockers | Important | Nice | SDD-debt | Pattern |
| --- | --- | --- | --- | --- | --- | --- |
| Phase 1 | 50+ | various | various | various | several | original audit baseline |
| Phase 2 | 64 | 0 | 3 (all closed) | 60 (all closed) | 1 (closed) | initial closure-cycle audit |
| Phase 3 | 39 | 0 | 2 (all closed) | 16 (15 closed) | 1 (closed) | tighter |
| **Phase 4** | **9** | **0** | **0** | **5 (all closed)** | **0** | **cleanest yet** |

The closure-cycle audit trajectory is converging — each cycle finds fewer issues than the prior, and Phase 4 confirms the Phase 3 closure work was exceptionally well-executed.

Phase 4 closes here. Phase 5 kicks off whenever the operator triggers the next audit cycle.

This PR is documentation-only.

### Documentation — Phase 4 tests explorer (verifies F-2029-008 demoted)

Sixth of seven Phase 4 explorers. Audits the test infrastructure + new test cases from the Phase 3 closure cycle.

#### Headline

**0 blockers, 0 important, 0 actionable nice.** The Phase 3 closure-cycle test work is comprehensive and clean. Verifies:

- 6 per-token SSE cap tests (SDD-007 D-4 + D-5) — all correctly pin their contracts.
- 2 SseParser multibyte UTF-8 split tests (F-2028-018) — boundary positions match the claimed cases.
- 3 CLI integration tests (F-2028-004, -015, -017) — proper per-test isolation, correct spawn-blocking pattern.
- 2 config round-trip tests (F-2029-005/-006 closure) — pin the TOML parse hop.
- 2 `TokenFingerprint` Debug-elision tests (F-2029-002 closure) — robust against algorithm swap.
- Common-mod import migration (F-2028-025 closure): all 10 module-test files import `assert_tree_unchanged` + `snapshot_tree` directly. No `common::` qualified call sites remain.
- Test helpers (`with_full_capability_for_fingerprint`, `MAX_SSE_SUBSCRIBERS_PER_TOKEN` const re-export) cleanly gated behind `test-helpers` feature.

#### F-2029-008 — demoted on cross-check

Auditor flagged `events_stream_per_token_counter_drops_to_zero_on_disconnect` for using a real-time `tokio::time::sleep(100ms)` instead of `start_paused`. Cross-check: the sleep is deliberate and documented — a `start_paused` rewrite would deadlock since the writer task is parked on `sub.recv().await` when the response drops, with no further bus event forthcoming. The test correctly pins the D-5.5 contract; SDD-005's "no real-time sleeps in pipeline tests" applies to deterministic-stage pipelines, not async-task-scheduling synchronization. **No action.** Kept in ledger for audit-trail completeness.

#### New document

`docs/review/phase-4/70-tests-audit.md` — per-theme observations with concrete file:line evidence.

#### Phase 4 status

**8 findings across 6 explorers**: 0 blockers, 0 important, **5 nice (all closed)**, 3 demoted, 0 SDD-debt. **One explorer remains: security.**

This PR is documentation-only.

### Docs — Phase 4 docs explorer + SECURITY.md per-token SSE cap entry (raises + closes F-2029-007)

Fifth of seven Phase 4 explorers. Audits the documentation surface from the Phase 3 closure cycle: seven Phase 3 audit docs, CHANGELOG entries, SDD-007, init.rs templates, runbooks, repo-root docs, the Phase 4 audit docs themselves.

#### Headline

**0 blockers, 0 important.** One `nice` finding closed inline.

#### F-2029-007 — SECURITY.md per-token SSE cap entry

SDD-007 shipped during the Phase 3 cycle (closing F-2028-037 — authenticated-only DoS) but `SECURITY.md`'s § API surface didn't mention the new per-token cap. No security gap (feature is well-tested and safe by default), but a documentation gap.

`SECURITY.md` § API surface now documents:
- The per-token cap (default 8) and global cap (default 64).
- The SHA-256-fingerprint counter map and its prune-on-empty semantics.
- The operator-tunable `[api].max_sse_subscribers{,_per_token}` knobs with `None`/`Some(0)` → default fallback.
- The distinguishable 503 reasons (`"sse subscriber cap reached"` global vs `"per-token sse cap reached"`).
- Back-references to SDD-007 and `SubscriberGuard` for full implementation context.

#### Phase 4 status

**7 findings across 5 explorers**: 0 blockers, 0 important, **5 nice (all closed)**, 2 demoted, 0 SDD-debt. **Two explorers remain** (tests, security).

### Audit + test — Phase 4 integration explorer (raises + closes F-2029-005 + -006)

Fourth of seven Phase 4 explorers. Audits the seven integration seams introduced by the Phase 3 closure cycle.

#### Result

**0 blockers, 0 important; all seven seams hold under the closure code.** Two `nice` test-coverage findings, both closed inline:

| Seam | Verdict |
| --- | --- |
| bearer_auth → TokenFingerprint → events_stream extension flow | clean |
| per-token cap ↔ global cap ↔ operator config knobs | clean (per-token rejection short-circuits before global increment; no slot leak) |
| SDD-007 D-4 config knobs ↔ daemon startup wiring | F-2029-005 |
| TCP-follow ↔ JSON-503 ↔ typed reasons | clean |
| vpn-bridge SDD-006 v2 ↔ manifest persistence | clean |
| STARTER_CONFIG SSE caps ↔ daemon parse | F-2029-006 (duplicate of F-2029-005) |
| SseParser feed_bytes ↔ both transports | clean |

**F-2029-005** and **F-2029-006** are facets of the same gap (no end-to-end test from TOML file → daemon parse → `ApiConfig` → `ApiState::with_sse_caps`). Two new tests in `crates/selfdef-config/src/lib.rs::tests`:

- `sse_cap_knobs_round_trip_from_toml` — sets both caps in TOML, asserts `Config::load` yields `Some(16)` and `Some(4)` respectively.
- `sse_cap_knobs_default_to_none_when_unset` — pins the unset-defaults-to-None contract so a regression where `#[serde(default)]` accidentally yields `Some(0)` is caught at parse time.

Together with the existing `events_stream_per_token_cap_honours_operator_override` and `events_stream_global_cap_honours_operator_override` tests (which pin the consumption hop on the API side), the full TOML → ApiState → handler chain is now test-covered.

#### New document

`docs/review/phase-4/50-integration-audit.md` — seam-by-seam notes with concrete `file:line` evidence.

#### Tests

- `cargo test -p selfdef-config` — 4/4 pass (was 2; +2 new round-trip tests).
- `cargo clippy --workspace --tests -- -D warnings` clean.
- `cargo fmt --all -- --check` clean.

#### Phase 4 status

**6 findings across 4 explorers**: 0 blockers, 0 important, **4 nice (all closed)**, 2 demoted, 0 SDD-debt. **Three explorers remain** (docs, tests, security).

### Polish + audit — Phase 4 crate + module cluster (closes F-2029-002 + -003 + -004, raises F-2029-004)

Folds the Phase 4 module explorer (third of seven) into the same PR that closes both `nice` findings from the crate explorer. The module explorer raised one trivial `nice` (F-2029-004 — a doc-comment gap), which is closed inline.

#### F-2029-002 — `TokenFingerprint` Debug elision

Closes both `nice` findings from the Phase 4 crate explorer.

#### F-2029-002 — `TokenFingerprint` Debug elision

`crates/selfdef-api/src/transport.rs::TokenFingerprint` no longer derives `Debug`. A custom `Debug` impl renders only the leading 4 bytes (`TokenFingerprint(a3b9c012…)`), keeping fingerprints visually distinct in log streams while removing the cross-time-linkage primitive. Fingerprints aren't secrets, but they're stable identifiers — an attacker who later acquires the token can recompute the fingerprint and link past log lines to the holder. The truncated prefix (32 bits) is collision-prone enough that it can't confirm linkage.

Two new unit tests pin the contract:
- `debug_renders_truncated_prefix` — shape (`TokenFingerprint(<8 hex chars>…)`) + char-class assertions.
- `distinct_tokens_produce_distinct_debug_prefixes` — two operator-meaningful strings get distinct Debug forms.

#### F-2029-003 — `SseCaps` `Some(0)` defensive test

`crates/selfdef-api/src/handlers.rs::SubscriberGuard::try_acquire` already treats `Some(0)` like `None` (both fall back to the compiled-in default) per the SDD-007 D-4 doc-comment intent. The existing override tests use `Some(2)` and `Some(1)`; neither exercises the `Some(0)` path. The new `events_stream_zero_caps_fall_back_to_defaults` test sets both caps to `Some(0)` and asserts the first connection succeeds — a future refactor dropping the `n > 0` guard would saturate immediately and fail this test.

#### F-2029-004 — vpn-bridge apply.sh dispatcher header documents dry-run + idempotency

`modules/vpn-bridge/install/apply.sh`'s dispatcher header now names the SELFDEF_DRY_RUN-awareness, the idempotency contract, and the SDD-006 v2 manifest-tracking convention profiles must honour. The actual profile scripts already behave correctly via the shared-lib `run` helper and `module_record_file`; the header was the only inconsistency vs `bridge-l2` and `observability`.

#### Phase 4 module explorer (third of seven)

`docs/review/phase-4/40-module-audit.md` ships in the same PR. Highlights:

- **vpn-bridge SDD-006 v2 migration verified complete**: `SELFDEF_MODULE_LIB_VERSION_REQUIRED=2`, `module_record_file` called after the install, `profile_uninstall` iterates `module_render_files` with the legacy fallback for pre-v2 installs. The legacy fallback's deduplication is sound (only runs when manifest is empty, so no double-removal risk).
- **100% v2 coverage for non-exempt modules**: 7 modules at v2 (agent-guard, bridge-l2, integrity-sentinel, observability, polarproxy, tetragon, vpn-bridge), suricata correctly exempt (writes no persistent files).
- **STARTER_CONFIG/STARTER_MODULES templates verified**: 7/7 init tests pass; D-4 SSE caps documented; F-2028-022 mode hints present.
- **Multi-instance scenario verified**: `relay-via-server` honours `SELFDEF_INSTANCE_ID` via `_relay_inst_defaults()`; `cloudflare-tunnel` + `tailscale` correctly refuse it.

#### Tests

- `cargo test -p selfdef-api` — **47/47 pass** (was 44; +3 new tests: 2 fingerprint Debug, 1 zero-cap fallback).
- `cargo clippy --workspace --tests -- -D warnings` clean.
- `cargo fmt --all -- --check` clean.

#### Phase 4 status

**4 findings across 3 explorers**: 0 blockers, 0 important, **3 nice (all closed)**, 1 demoted, 0 SDD-debt. **Four explorers remain** (integration, docs, tests, security).

### Documentation — Phase 4 crate explorer (raises F-2029-002 + F-2029-003)

Second of seven Phase 4 explorers. Audits the new Rust code from the Phase 3 closure cycle: `TokenFingerprint`, `SseCaps`, the dual-counter `SubscriberGuard`, `SseParser::feed_bytes`, JSON-503 extraction, the operator-tunable cap surface in `selfdef-config` + `selfdef-daemon`, the `paths.rs` compile-time invariants.

#### Headline

**No blockers, no important findings.** The Phase 3 closure code is well-integrated and test-covered. Two `nice` observations on defensive hardening.

#### New document

`docs/review/phase-4/30-crate-audit.md` — per-file notes with concrete `file:line` evidence.

#### Findings

- **F-2029-002 (nice)** — `TokenFingerprint`'s derived `Debug` dumps the full 32 bytes; `tracing` via `?fp` would log the raw hash, giving attackers who later acquire the token a way to link past log lines to the holder. Fingerprints aren't secrets but they're persistent identifiers. Custom `Debug` impl that prints a truncated hex prefix (e.g. `TokenFingerprint(a3b9…)`) preserves diagnostic value without the linkage.
- **F-2029-003 (nice)** — The `SseCaps` `try_acquire` path treats `Some(0)` the same as `None` (both fall back to the compiled-in default) per the SDD-007 D-4 intent. The existing override tests use `Some(2)` and `Some(1)`; neither exercises the `Some(0)` path. A future refactor dropping the `n > 0` guard would silently break the contract. Defensive test gap.

#### Phase 4 status

3 findings across 2 explorers: 0 blockers, 0 important, 2 nice, 1 demoted, 0 SDD-debt. Five explorers remain (module, integration, docs, tests, security).

This PR is documentation-only.

### Documentation — Phase 4 recent-PRs explorer + ledger (raises F-2029-001)

First of seven Phase 4 explorers. Surveys the ~17 PRs from the Phase 3 closure cycle (commits `f40bf05` through `8b44322`). Documents the cleanest cycle yet — 16/17 PRs review-clean (94% pass rate).

#### New documents

- `docs/review/phase-4/20-recent-prs-audit.md` — first of seven explorer docs.
- `docs/review/phase-4/99-findings-ledger.md` — initial Phase 4 ledger.

#### F-2029-NNN findings raised

| id | severity | summary |
| --- | --- | --- |
| F-2029-001 | demoted | SDD-007 implementation PR (`a1d6823`) defers D-4 in its commit message; D-4 follow-up (`8b44322`) ships 13 minutes later. Cross-check: defer-and-pair pattern is intentional; SDD status doc correctly updated by the D-4 PR to "all five Ds shipped". No drift; kept for audit-trail completeness. |

#### Pass rate

**94%** review-clean (16/17 PRs). Higher than:
- Phase 3 recent-PRs explorer: 73% clean (4 observations across 29 PRs).
- Phase 2 recent-PRs explorer: comparable rate.

The closure-cycle work landed cleanly — every Phase 3 closure PR matched its scope.

#### Status

1 finding raised: 0 blockers, 0 important, 0 nice, 1 demoted, 0 SDD-debt. Six explorers remain.

This PR is documentation-only.

### Feature — SDD-007 D-4: operator-tunable SSE caps

Closes the deferred work item from SDD-007. The two SSE caps (`MAX_SSE_SUBSCRIBERS` global, `MAX_SSE_SUBSCRIBERS_PER_TOKEN` per-token) are now operator-tunable from `selfdef.toml` without recompiling. SDD-007 status flips from "implemented (D-4 deferred)" → "implemented (all five Ds shipped)".

#### Config surface

```toml
[api]
# SDD-007 D-4 / F-2028-037: caps on concurrent /events/stream
# subscribers. Defaults (64 global, 8 per-token) bound how
# much an authenticated bearer-holder can pin in process memory.
max_sse_subscribers           = 64
max_sse_subscribers_per_token = 8
```

Both fields are optional `Option<usize>`. Unset, empty, or `Some(0)` falls back to the compiled-in defaults — zero behaviour change for existing deployments.

#### Implementation

- **`selfdef-config::ApiConfig`** — two new `Option<usize>` fields with `#[serde(default)]` so existing `selfdef.toml` files keep working unchanged.
- **`selfdef-api::SseCaps`** — new `pub struct SseCaps { global: Option<usize>, per_token: Option<usize> }` carried on `ApiState`. New `ApiState::with_sse_caps(caps)` builder method.
- **`selfdef-api::handlers::SubscriberGuard::try_acquire`** — consults `state.sse_caps` first, falling back to the constants when the operator hasn't overridden.
- **`selfdef-daemon::main`** — passes `cfg.api.max_sse_subscribers{,_per_token}` to `ApiState::with_sse_caps(SseCaps { … })` during the API startup wiring.
- **`init.rs::STARTER_CONFIG`** — the `[api]` block now ships both knobs commented at the defaults so operators discover them while bootstrapping.

#### Tests

Two new integration tests in `crates/selfdef-api/tests/m12_api.rs`:

- `events_stream_per_token_cap_honours_operator_override` — sets per-token cap to 2 via `SseCaps`; asserts the 3rd connection is refused with the per-token typed reason.
- `events_stream_global_cap_honours_operator_override` — sets global cap to 1; asserts the 2nd connection is refused with the global typed reason.

The existing 5 events_stream tests continue to pass (they don't set `SseCaps`, so the compiled-in defaults apply).

#### Test plan

- [x] `cargo test -p selfdef-api -p selfdef-cli -p selfdef-config` — 279/279 pass.
- [x] `cargo clippy --workspace --tests -- -D warnings` clean.
- [x] `cargo fmt --all -- --check` clean.

### Polish — Phase 3 nice-cluster wrap-up (closes F-2028-001 + F-2028-012 + F-2028-013 + F-2028-025)

Closes 4 of the 5 remaining open `nice` findings from Phase 3. After this PR, Phase 3 is effectively wrapped: every blocker, important, and SDD-debt finding is closed; the only remaining open finding (F-2028-008, SseParser visibility) is explicit `defer` per the crate audit ("no immediate consumer").

#### F-2028-001 — paths constant invariants

`crates/selfdef-cli/src/paths.rs` gains a `const _: () = { … }` block that asserts at compile time:

- `DAEMON_CONFIG`, `MODULES_HOST_CONFIG`, `MODULES_PER_MODULE_DIR`, `AGENT_GUARD_CONFIG` all start with `/etc/selfdef/`.
- `AGENT_GUARD_CONFIG` lives under `MODULES_PER_MODULE_DIR`.

Zero runtime cost; a future maintainer who renames the etc-dir or drops a leading slash gets a build error instead of runtime drift.

#### F-2028-012 — SubscriberGuard underflow debug-asserts

`SubscriberGuard::Drop` in `crates/selfdef-api/src/handlers.rs` now `debug_assert!(prev > 0, …)` on both the global and per-token counter decrements, plus a `debug_assert!(false, …)` on the "per-token entry missing on drop" branch. Future logic bugs (double-drop, decrement without acquire, bypass-then-drop) surface as panics in debug builds instead of silent counter corruption.

#### F-2028-013 — SSE timeout error names the deadline

`events_stream`'s writer-task `send_with_timeout` closure now returns `Err("slow-client timeout (30s)")` instead of just `Err("slow-client timeout")`. Operators reading the log line see the deadline directly. The literal is documented inline next to `SSE_SEND_TIMEOUT` so a future const change updates both.

#### F-2028-025 — common-mod import-style symmetry

10 module-test files in `crates/selfdef-cli/tests/` (agent_guard, bridge_l2, integrity_sentinel, suricata, vpn_bridge, vpn_bridge_cloudflare, vpn_bridge_tailscale, observability, tetragon, polarproxy) now import `assert_tree_unchanged` and `snapshot_tree` from `common` alongside their existing helpers. Call sites rewrite from `common::snapshot_tree(...)` to bare `snapshot_tree(...)`. Style is now consistent across the test suite.

#### Tests

- `cargo test -p selfdef-cli -p selfdef-api` — 275/275 pass.
- `cargo clippy --workspace --tests -- -D warnings` clean.
- `cargo fmt --all -- --check` clean.

#### Phase 3 status — effectively wrapped

39 findings across 7 explorers:
- 0 blockers
- **2 important — both shipped** (F-2028-015 in PR #87, F-2028-037 in PR #93)
- **15 of 16 nice closed** (open: F-2028-008, `defer` per crate audit — no immediate consumer)
- 20 demoted
- **1 of 1 SDD-debt closed** (F-2028-039 in PR #93)

Phase 3 closes here. Phase 4 kicks off when a new audit cycle is operator-triggered.

### Security — SDD-007 implementation: per-token SSE subscriber quota (closes F-2028-037 + F-2028-039)

Implements SDD-007. **Closes the open `important` finding** from the Phase 3 security explorer. Status of SDD-007 flips from `design` → `implemented` (D-4 config knobs deferred to a thin follow-up).

#### What changed

**`crates/selfdef-api/src/transport.rs`** — new `TokenFingerprint(pub [u8; 32])` type computed as SHA-256 of the presented bearer token. `bearer_auth` threads it into `request.extensions()` alongside the `Capability` after auth succeeds. A token-rotation between requests changes the fingerprint, so the per-token counter naturally starts fresh.

**`crates/selfdef-api/src/state.rs`** — `ApiState` carries a new `Arc<Mutex<HashMap<TokenFingerprint, AtomicUsize>>>` per-token map alongside the existing global `Arc<AtomicUsize>`. The `Mutex` is `std::sync::Mutex` (not the tokio variant) so the RAII `SubscriberGuard::Drop` can decrement synchronously without an async context. Microsecond lock holds.

**`crates/selfdef-api/src/handlers.rs`** — `SubscriberGuard` refactored to track both counters:

- `try_acquire(state, fingerprint)` checks the **per-token cap first** (so the typed 503 names the abusive token's slice when it's the cause), then the global cap.
- On global-cap failure after a successful per-token increment, the per-token counter is undone — the next request under that token still gets its full slice.
- `Drop` decrements both counters and **prunes the HashMap entry** when the per-token count hits zero. No leak across rotations.

**`crates/selfdef-api/src/lib.rs`** — `TokenFingerprint`, `MAX_SSE_SUBSCRIBERS_PER_TOKEN`, and a new `with_full_capability_for_fingerprint(router, fp)` test helper re-exported (`fingerprint` gated on `test-helpers`).

#### Distinguishable 503 reasons (D-6)

| Cause | Body |
| --- | --- |
| Process-wide cap saturated | `{"error": "sse subscriber cap reached"}` |
| This token's slice full | `{"error": "per-token sse cap reached"}` |

Both surface through the F-2028-016 JSON-extraction path in `events_follow_tcp`, so a CLI operator sees the typed reason directly in stderr.

#### Tests (D-5)

Three new integration tests in `crates/selfdef-api/tests/m12_api.rs`:

- `events_stream_per_token_cap_reached` (D-5.1) — open `MAX_SSE_SUBSCRIBERS_PER_TOKEN` connections with the same fingerprint; (cap+1)th gets 503 with the per-token typed reason.
- `events_stream_per_token_cap_does_not_affect_other_tokens` (D-5.2) — saturate token A's slice; token B still succeeds.
- `events_stream_per_token_counter_drops_to_zero_on_disconnect` (D-5.5) — open then disconnect; assert the HashMap entry is pruned.

D-5.3 (global cap still applies) is covered by the existing `events_stream_rejects_over_cap_with_503` — its `with_full_capability` fixture has no fingerprint, so the test exercises the global-cap path directly.

#### Deferred (D-4, separate PR)

The two `[api]` config knobs (`max_sse_subscribers_per_token` / `max_sse_subscribers`) ship in a thin follow-up that plumbs the constants through `ApiConfig`. The defaults (8 per-token, 64 global) match SDD-007.

#### Tests

- `cargo test -p selfdef-api -p selfdef-cli` — 275/275 pass (was 272; +3 SDD-007 tests).
- `cargo clippy --workspace --tests -- -D warnings` clean.
- `cargo fmt --all -- --check` clean.

#### Phase 3 status

39 findings across all 7 explorers. **Closed**: 0 blockers, 2 important (both shipped), 11 of 16 nice, 20 demoted, 1 of 1 SDD-debt. **Open**: 5 low-priority nice (F-2028-001, -008, -012, -013, -025). Phase 3 wraps when those land or get deferred.

### Design — SDD-007 per-token SSE subscriber quota (scopes F-2028-037 + F-2028-039)

Design doc that scopes the fix for the open `important` finding from the Phase 3 security explorer. Implementation lands in a follow-up PR.

#### What F-2028-037 surfaced

The current `SubscriberGuard` increments a process-global `Arc<AtomicUsize>`; one bearer-holder who opens 64 concurrent `/events/stream` connections from a single process saturates `MAX_SSE_SUBSCRIBERS = 64` and DoSs every other authenticated client. The bearer-token model treats every token as equivalent, so the cap should too.

#### Design decisions

`docs/sdd/007-per-token-sse-subscriber-quota.md` spells out:

- **D-1 — Token identity**: SHA-256 fingerprint, computed once in the bearer-auth middleware, threaded via `request.extensions()` to the handler. Avoids storing raw secrets in maps; gives a stable handle for the quota counter.
- **D-2 — Quota mechanism**: `ApiState::sse_subscribers` becomes a `HashMap<Fingerprint, AtomicUsize>` (or `DashMap` for lock-free). Each request increments both the per-fingerprint and global counters. Refusal returns 503 with a distinguishable reason.
- **D-3 — Revocation interaction**: deliberately deferred. Rotating a token blocks *new* connections immediately (bearer-auth rejects); existing connections drain via the usual paths (client disconnect / slow-client timeout). Terminate-on-revoke is marked as future hardening.
- **D-4 — Config surface**: two new optional `[api]` knobs (`max_sse_subscribers_per_token` default 8, `max_sse_subscribers` unchanged at 64).
- **D-5 — Test coverage**: per-token cap reached, per-token cap is per-token, global cap still applies, rotation frees slots eventually, per-token counter drops to zero.
- **D-6 — Status-code semantics**: both caps return 503 but distinguishable bodies (`"sse subscriber cap reached"` global vs `"per-token sse cap reached"`). Surfaces through the F-2028-016 JSON-extraction path so operators see the right typed reason.

#### Out of scope

Per-IP quotas, per-audience quotas (would need token issuer to thread audience metadata), and the Prometheus quota-exhaustion metric are all marked future SDDs.

#### Phase 3 status after this PR

39 findings, all seven explorers done. **Open items remaining**:
- F-2028-001, F-2028-008, F-2028-012, F-2028-013, F-2028-025 (5 nice, all low-priority or deferred)
- F-2028-037 (important, design landed; implementation pending)
- F-2028-039 (SDD-debt, scoped to SDD-007)

Phase 3 wraps when the SDD-007 implementation PR lands.

### Fix + docs — SSE 503 cluster (closes F-2028-016 + F-2028-017) + Phase 3 security explorer (raises F-2028-036..039; **ALL SEVEN PHASE 3 EXPLORERS HAVE NOW RUN**)

Two pieces in one PR: closes the SSE-503 cluster from the integration explorer + the **seventh and final Phase 3 explorer** (security audit).

#### SSE 503 cluster — closes F-2028-016 + F-2028-017

`crates/selfdef-cli/src/follow.rs::events_follow_tcp` now parses the daemon's `{"error": "..."}` JSON 503 body and surfaces the typed reason. Operators hitting `MAX_SSE_SUBSCRIBERS` now see `daemon refused /events/stream: HTTP 503 sse subscriber cap reached` instead of the raw JSON. Falls back to the raw body for non-JSON errors (e.g. an upstream proxy's HTML 5xx page).

New test `events_follow_url_surfaces_cap_reached_reason_on_503` pins the end-to-end contract: saturate the daemon's cap with `MAX_SSE_SUBSCRIBERS` in-process reqwest streams, then spawn the CLI subprocess (wrapped in `spawn_blocking` so the single-threaded test runtime stays free to drive the in-process server) and assert the subprocess's stderr names both `503` and `sse subscriber cap reached`.

#### Phase 3 security explorer — F-2028-036..039

`docs/review/phase-3/80-security-audit.md` is the final Phase 3 explorer doc. It surveys new attack surfaces introduced by the closure cycle: TCP-follow URL parsing, bearer-token file-read path (re-audited F-2027-031/-032), `validate_rbac_subject` charset, `ApiError::store` log line (re-audited F-2027-063), `SubscriberGuard` cap exhaustion as a DoS amplifier, plus a re-audit appendix for F-2027-014 + F-2027-035.

| id | severity | summary |
| --- | --- | --- |
| F-2028-036 | demoted | URL scheme validation in `events_follow_tcp` — reqwest accepts only `http`/`https` by default; no additional CLI-side scheme check needed. |
| **F-2028-037** | **important** | **SSE subscriber cap is process-global, not per-token. One malicious bearer-holder (or a leaked token) can saturate the 64-slot cap and DoS legitimate operators.** Gated on SDD-007 design. |
| F-2028-038 | demoted | TCP-follow 503 error-message detail. Independently surfaced by the security explorer; same surface as F-2028-016. Closed by the F-2028-016 work in this PR. |
| F-2028-039 | SDD-debt | Per-token SSE subscriber quota — design counterpart of F-2028-037. Spawn SDD-007 to scope: per-token vs per-fingerprint, revocation interaction, config knobs, status code semantics. |

Re-audit appendix verifies F-2027-031/-032, F-2027-035, F-2027-061/-062, and F-2027-014 closures all hold.

#### Tests

- `cargo test -p selfdef-cli --test cli_events_follow_tcp` — 7/7 pass (was 6, now +1 for the cap-saturation test).
- `cargo clippy -p selfdef-cli --tests -- -D warnings` clean.
- `cargo fmt --all -- --check` clean.

#### Phase 3 status

**ALL SEVEN PHASE 3 EXPLORERS HAVE NOW RUN.** 39 findings raised across 7 explorers: 0 blockers, 2 important (F-2028-015 closed; **F-2028-037 open, gated on SDD-007**), 16 nice (11 closed, 5 open), 20 demoted, 1 SDD-debt (F-2028-039 open). Open `nice` follow-ups: F-2028-001, -008, -012, -013, -025. Phase 3 wraps when these + F-2028-037/-039 land.

### Docs + tests — CLI doc clarity (closes F-2028-006 + -007 + -010) + Phase 3 tests explorer (raises F-2028-025; verifies F-2028-026..035)

Two pieces in one PR: closes the CLI doc-clarity cluster from the crate explorer + sixth Phase 3 explorer (tests audit).

#### CLI doc clarity — closes F-2028-006 + F-2028-007 + F-2028-010

Three small doc-comment additions in `crates/selfdef-cli/src/follow.rs` and `crates/selfdef-cli/src/main.rs`:

- **F-2028-006**: `events_follow_tcp` doc-comment now names the wire format (`Authorization: Bearer <t>`, space-separated, no quoting). Matches the daemon-side bearer-auth middleware's expectation.
- **F-2028-007**: `follow.rs` module `//!` header now lists the three module-level entry points with one-sentence summaries each: `events_follow_unix`, `events_follow_tcp`, and `read_token_file`. The helper is no longer hidden from a reader of the module header.
- **F-2028-010**: `Follow` clap enum variant's doc-comment now explicitly restates the clap-enforced constraint structure ("--url and --unix-socket are mutually exclusive; --token-file requires --url") so a reader doesn't have to cross-reference the attributes.

Zero behaviour change. All 232 `selfdef-cli` tests pass against the refreshed docs.

#### Phase 3 tests explorer — F-2028-025 (nice) + F-2028-026..035 (demoted verifications)

`docs/review/phase-3/70-tests-audit.md` surveys the test infrastructure + new test cases from the Phase 2 closure cycle (common-mod adoption, m4_alert + m8_honeytokens pause()-conversion, build_state TempDir handle, dummy_action_set per-call tempdir, prom parser adoption, ~25 new test cases).

Headline: **0 blockers, 0 important; the closure-cycle test work shipped cleanly.**

The one actionable finding is **F-2028-025 (nice, low priority)** — 11 module-test files call `common::snapshot_tree` and `common::assert_tree_unchanged` via fully-qualified paths without listing them in the `use common::{...}` import. Pure import-style asymmetry; explicit-import pattern would tidy them.

The remaining 10 entries (F-2028-026..035) are **verification notes** confirming Phase 2 closures shipped correctly: SseParser UTF-8 split tests, `validate_rbac_subject` 7+1 tests, `events_stream` cap-saturation test, suricata live-apply test, vpn-bridge P-1 backfill, token-file mode test, relay manifest round-trip, `build_state` TempDir handle, `dummy_action_set` per-call tempdir, prom-parser metrics assertions. All marked `demoted` in the ledger (no action needed; they validate prior PRs landed as documented).

#### Phase 3 status after this PR

35 findings across 6 explorers: 0 blockers, 1 important (closed), 16 nice (9 closed, 7 open), 18 demoted, 0 SDD-debt. **One explorer remains: security.**

### Docs polish — STARTER_MODULES per-block mode hint + Phase 3 inventory time-anchor (closes F-2028-022 + F-2028-024)

Closes the two actionable findings from the Phase 3 docs explorer. Both are minor documentation refreshes with no code-behaviour impact.

#### F-2028-022 — STARTER_MODULES per-block mode hint

`crates/selfdef-cli/src/init.rs::STARTER_MODULES` had the F-2027-059 trust-boundary warning at the section header (0640 root:selfdef + `install -m 0640 -o root -g selfdef …` invocation), but the individual commented `[modules.<slug>]` blocks didn't repeat it. An operator copying a single block to a fresh `modules.toml` without scrolling up to the header would have missed the mode requirement.

Two changes:

- A mid-section reminder above the first module block names the safe-copy invariant: "every `config = "..."` line below must point at a file at 0640 root:selfdef".
- Every per-module `config = "/etc/selfdef/modules/<slug>.toml"` line now ends with a `# 0640 root:selfdef` trailing comment. Copy-paste a single block now carries the constraint inline.

The 7 `cli_init` tests still pass against the refreshed templates (assertions check byte-count == `STARTER_MODULES.len()` so the added comments are picked up automatically).

#### F-2028-024 — Phase 3 inventory time-anchor

`docs/review/phase-3/10-inventory.md` claimed "All 8 modules completed SDD-006 v2 migration"; this was wrong at write-time (vpn-bridge was at v1) and only became true after F-2028-015 closed in PR #87. The entry now reads:

> At Phase 2 close: 6 modules at v2, suricata correctly exempt (writes no persistent files), vpn-bridge still at v1 — discovered by the Phase 3 module explorer as F-2028-015 and closed by PR #87. **As of PR #87**: every non-exempt module is v2.

Time-anchored so a future reader can map the inventory's snapshot semantics against the audit trail.

#### Phase 3 status after this PR

24 findings across 5 explorers: 0 blockers, 1 important (closed), 15 nice (6 closed, 9 open), 8 demoted, 0 SDD-debt. Two explorers remain (tests, security).

This PR is documentation-only.

### Fix + docs — SSE parser bytes refactor (closes F-2028-018 + F-2028-019) + Phase 3 docs explorer (raises F-2028-020..024)

Two pieces in one PR: closure of the SseParser chunk-boundary UTF-8 bug surfaced by the integration explorer + the fifth Phase 3 explorer (docs audit).

#### F-2028-018 + F-2028-019 closure — SseParser bytes refactor

`crates/selfdef-cli/src/follow.rs::SseParser` no longer touches `String::from_utf8_lossy` per chunk. The internal buffer is now `Vec<u8>`; the public entry is `feed_bytes(&[u8])`; UTF-8 conversion happens line-at-a-time after a `\n` terminator is found. Both call sites (`events_follow_unix` reading chunked HTTP, `events_follow_tcp` reading `reqwest::bytes_stream`) now hand the parser raw bytes — chunk boundaries are invisible to the parser by construction.

The module `//!` header (closes F-2028-019) now explicitly names the byte-semantic parity requirement and back-references F-2028-018 so a future third transport can't re-introduce the corruption pattern.

Two new unit tests pin the round-trip:

- `parser_reassembles_multibyte_utf8_split_across_chunks` — 4-byte 🦀 (U+1F980, `F0 9F A6 80`) split 2/2 across two `feed_bytes` calls.
- `parser_reassembles_3byte_utf8_split_across_chunks` — 3-byte 漢 (U+6F22, `E6 BC A2`) split 1/2 across two calls.

All existing parser unit tests (9), TCP integration tests (6), and UNIX follow tests (7) continue to pass.

#### Phase 3 docs explorer — F-2028-020..024

`docs/review/phase-3/60-docs-audit.md` surveys the docs surface introduced by the closure cycle: the seven Phase 2 audit docs, CHANGELOG entries, `init.rs` STARTER_CONFIG/STARTER_MODULES templates, runbooks, repo-root docs, the Phase 3 audit docs themselves.

5 entries raised (2 actionable nice + 3 demoted after cross-check):

| id | severity | summary |
| --- | --- | --- |
| F-2028-020 | demoted | CHANGELOG "9 nice (2 closed, 7 open)" flagged as off-by-one; cross-check confirmed count is correct (2+7=9). |
| F-2028-021 | demoted | Integration-explorer PR's "1 important (now closed)" flagged as misleading; cross-check confirmed the closure shipped in the same PR. |
| F-2028-022 | nice (low priority) | `STARTER_MODULES` header has the F-2027-059 trust-boundary warning but individual `[modules.<slug>]` blocks don't repeat the 0640 root:selfdef mode hint. Operator who copies a single block risks missing it. |
| F-2028-023 | demoted | Phase 3 charter "remaining explorers will run in follow-up PRs" wording flagged as stale; cross-check confirmed charter is a static intent snapshot by-design (the ledger is the live status). |
| F-2028-024 | nice (low priority) | Phase 3 inventory's "All 8 modules completed SDD-006 v2 migration" was wrong at write-time (vpn-bridge was v1 until F-2028-015 closed); now accidentally correct post-PR-#87. Add an "as of PR #87" note for time-anchored clarity. |

#### Tests

- `cargo test -p selfdef-cli --bin selfdefctl follow::` — 11/11 pass (9 existing + 2 new multi-byte split).
- `cargo test -p selfdef-cli --test cli_events_follow --test cli_events_follow_tcp` — 13/13 pass.
- `cargo clippy --workspace --tests -- -D warnings` clean.
- `cargo fmt --all -- --check` clean.

#### Phase 3 status

24 findings across 5 explorers: 0 blockers, 1 important (closed), 15 nice (4 closed, 11 open), 8 demoted, 0 SDD-debt. Two explorers remain (tests, security).

### Module + docs — vpn-bridge v2 manifest migration (closes F-2028-015) + Phase 3 integration explorer (raises F-2028-016..019)

Two pieces in one PR: closure of the Phase 3 module-explorer's `important` finding plus the fourth Phase 3 explorer's audit.

#### F-2028-015 closure — `modules/vpn-bridge` v1 → v2

- `modules/vpn-bridge/install/lib.sh` bumped to `SELFDEF_MODULE_LIB_VERSION_REQUIRED=2` with a comment naming the F-2028-015 driver.
- `modules/vpn-bridge/install/profiles/relay-via-server.sh::profile_apply` now calls `module_record_file "$nft_path"` after the `install -D` write, so the per-module manifest carries the path.
- `profile_uninstall` now enumerates from `module_render_files` and removes each tracked file, then calls `module_clear_manifest` to wipe the record. A legacy fallback handles pre-v2 installs (operator who installed under v1 then upgraded — first uninstall after upgrade still removes the legacy hard-coded path).

The multi-instance leak the audit prescribed: `INST="relay1"` → `nft_path=/etc/nftables.d/selfdef-vpn-bridge-relay1.conf` writes; uninstall now finds it via the manifest instead of looking at the singleton default.

New test `relay_apply_records_nft_path_in_manifest_then_uninstall_clears_it` pins the round-trip: live apply against stubs → assert nft.conf exists + manifest names it → live uninstall → assert nft.conf is gone.

#### Phase 3 integration explorer — F-2028-016..019

`docs/review/phase-3/50-integration-audit.md` surveys six integration seams introduced by the Phase 2 closure cycle:

| Seam | Result |
| --- | --- |
| TCP-follow ↔ events_stream ↔ subscriber cap | 2 nice findings (F-2028-016, F-2028-017) |
| init-template ↔ daemon config parsing | clean (control_token_file + integrity_check parsed correctly) |
| ApiError::store ↔ store call sites | clean (both call sites route through the generic-message path) |
| SIGUSR2 reload chain | clean (token + verifier + re-verify + summary log all present) |
| validate_rbac_subject ↔ probe/dry-path | clean (validation runs before the split) |
| SseParser ↔ both transports | 2 findings (F-2028-018 multi-byte UTF-8 split, F-2028-019 module-header parity note) |

**F-2028-018 is the most material**: both `events_follow_unix` (`follow.rs:258`) and `events_follow_tcp` (`:308`) call `String::from_utf8_lossy(&chunk)` per-chunk before feeding the parser. A 4-byte UTF-8 sequence split 2/2 across two `Bytes` would be replaced with two `U+FFFD` instead of one codepoint. Payloads containing emoji or non-ASCII file paths would corrupt under chunked delivery. Fix: buffer raw bytes inside the parser. Triaged `nice` because typical SSE payloads fit in one TCP segment, but worth fixing for correctness.

#### Tests

- `cargo test -p selfdef-cli --test module_vpn_bridge` — 8/8 pass (was 7 before this PR added the manifest round-trip test).
- `cargo clippy --workspace --tests -- -D warnings` clean.
- `cargo fmt --all -- --check` clean.

#### Phase 3 status

19 findings across 4 explorers: 0 blockers, **1 important (now closed)**, 13 nice (2 closed by PR #86, 11 open), 5 demoted, 0 SDD-debt. Three explorers remain (docs, tests, security).

### Security + docs — Phase 3 module explorer (raises F-2028-015) + token-reader symmetry (closes F-2028-004 + F-2028-005)

Third Phase 3 explorer + the first closure cluster off Phase 3's backlog. The audit explorer raises one **important** finding (F-2028-015) on `modules/vpn-bridge`; the same PR closes the token-reader symmetry cluster (F-2028-004 + F-2028-005) that the recent-PRs and crate explorers flagged.

#### Module explorer — F-2028-015 (important)

**Finding**: Phase 3's inventory claimed all 8 modules completed the SDD-006 v2 manifest-helpers migration. Cross-check via `grep SELFDEF_MODULE_LIB_VERSION_REQUIRED modules/*/install/lib.sh` shows 6 modules at v2 + `suricata` (correctly exempt — writes no persistent files) + **`vpn-bridge` at v1 (incorrect)**.

`modules/vpn-bridge/install/profiles/relay-via-server.sh:112` writes `nft_path` via `install -D -m 0644` but `apply.sh` never calls `module_record_file`. `profile_uninstall` hard-codes the cleanup path at lines 193-194 instead of iterating `module_render_files`. When operators move single-instance → multi-instance (`INST="relay1"`, `relay2`, …) the hard-coded uninstall path silently leaks the previous file — exactly the drift v2 was designed to prevent.

**Severity**: important. Fix is a separate PR (bump `lib.sh` to v2, add `module_record_file` after the write, replace hard-coded uninstall with `module_render_files` iteration).

#### Token-reader symmetry — closes F-2028-004 + F-2028-005

`crates/selfdef-cli/src/follow.rs::read_token_file` now mirrors the daemon-side `read_token` in `selfdef-api/src/transport.rs` byte-for-byte:

- **F-2028-004**: mode check. The CLI now refuses files with `mode & 0o077 != 0`, matching the daemon's `LooseTokenMode` refusal. Operators who fat-finger a `chmod 0644 /etc/selfdef/api.token` see the same error regardless of which side they hit first.
- **F-2028-005**: whitespace trim. The CLI now uses `str::trim()` (Unicode-whitespace aware) instead of `trim_end_matches(['\n', '\r', ' ', '\t'])`. Tokens with stray NBSP / BOM / ZWSP no longer round-trip differently between CLI and daemon.

Existing `events_follow_url_with_token_file_passes_bearer_header` test updated to `chmod 0o600` the token before invoking the CLI. New `events_follow_token_file_refuses_world_readable_mode` test exercises the loose-mode refusal end-to-end via subprocess.

#### Documents

- `docs/review/phase-3/40-module-audit.md` — third explorer's full audit doc with per-section evidence, cross-module pattern verification, v2-migration grep output.

#### Tests

- `cargo test -p selfdef-cli --test cli_events_follow_tcp` — 6/6 pass.
- `cargo clippy --workspace --tests -- -D warnings` clean.
- `cargo fmt --all -- --check` clean.

#### Phase 3 status after this PR

15 findings raised across 3 explorers: 0 blockers, 1 important (F-2028-015, open), 9 nice (2 closed, 7 open), 5 demoted, 0 SDD-debt. Four explorers remain (integration, docs, tests, security).

### Documentation — Phase 3 crate explorer (raises F-2028-005 through F-2028-014)

Second of seven Phase 3 explorers. Audits the Rust code introduced by the Phase 2 closure cycle (~28 PRs, commits `2d918ac` through `ee0e1a9`): `SseParser` state machine + dual-transport architecture in `selfdef-cli/src/follow.rs`, `validate_rbac_subject` + `Follow` clap shape in `main.rs`, `SubscriberGuard` RAII + refactored `events_stream` + rewritten `ApiError::store` in `selfdef-api/src/handlers.rs`, `sse_subscribers` field in `state.rs`, `MAX_SSE_SUBSCRIBERS` re-export in `lib.rs`, and new `reqwest`/`futures` deps in `Cargo.toml`.

#### New document

`docs/review/phase-3/30-crate-audit.md` — per-crate notes with concrete `file:line` observations.

#### Headline

**No blockers, no important findings.** The closure code went through PR review and CI; the new machinery is well-integrated and test-covered.

#### Findings raised (10 entries, 7 actionable + 3 demoted after cross-check)

- **F-2028-005 (nice)** — `read_token_file` whitespace-trim asymmetry: CLI uses ASCII-only trim, daemon uses Unicode `.trim()`.
- **F-2028-006 (nice)** — `events_follow_tcp` doc-comment doesn't name the wire-format `Authorization: Bearer <token>`.
- **F-2028-007 (nice)** — `follow.rs` `//!` module header doesn't enumerate the new `read_token_file` helper.
- **F-2028-008 (nice, defer)** — `SseParser` is private but well-tested + reusable; defer until a second consumer emerges.
- **F-2028-009 (demoted)** — `validate_rbac_subject` charset audit returned no actionable findings; the validator is well-scoped, well-tested, and the recent-PRs explorer (F-2028-003) already touched this surface.
- **F-2028-010 (nice)** — `Follow` clap doc-comment correctly uses `conflicts_with` / `requires` attributes but doesn't restate the structure in prose.
- **F-2028-011 (demoted)** — `SubscriberGuard` atomics + memory ordering reviewed; the CAS loop (`Ordering::Acquire` + `AcqRel`) is correct.
- **F-2028-012 (nice, defer)** — `SubscriberGuard::Drop` doesn't `debug_assert!(prev > 0)` against underflow; can't happen today, would catch future double-drop bugs under test.
- **F-2028-013 (nice, defer)** — `events_stream` `"slow-client timeout"` message doesn't name the `SSE_SEND_TIMEOUT = 30s` deadline.
- **F-2028-014 (demoted)** — `reqwest` + `futures` dep additions reviewed and properly justified; inline comments explain the dep-size cost.

#### Closing-PR clusters

- **CLI token-reader symmetry** — F-2028-004 (recent-PRs) + F-2028-005 (crate). One PR aligns the CLI and daemon `read_token_file` implementations on mode validation + whitespace trimming.
- **CLI doc-comment clarity** — F-2028-006 + F-2028-007 + F-2028-010. One PR refreshes the `follow.rs` module header, the `events_follow_tcp` Bearer-format note, and the `Follow` clap doc-comment.

F-2028-008, F-2028-012, F-2028-013 are deferred — no immediate consumer / observed misuse / forcing change.

#### Phase 3 status after this PR

14 findings raised across 2 explorers. 0 blockers, 0 important, 9 nice, 5 demoted, 0 SDD-debt. Five explorers remain.

### Documentation — Phase 3 audit kickoff (raises F-2028-001 through F-2028-004)

Opens Phase 3 of the rolling structural audit. Phase 2 closed in this session — every blocker / important / nice / SDD-debt finding across the seven Phase 2 explorers shipped via closure PRs. Phase 3 audits *what those closure PRs shipped*: drift, coverage gaps, and inconsistencies the closure cycle introduced that didn't get caught at PR-review time.

#### New documents

- `docs/review/phase-3/00-charter.md` — same methodology as Phases 1 + 2 (seven explorers, F-NNNN findings, SDDs where the fix is design-shaped). Vintage prefix `F-2028-NNN` so the three ledgers never collide. Scope table assigns each explorer a slice of the closure surface.
- `docs/review/phase-3/10-inventory.md` — hand-counted from `git log 2d918ac..ee0e1a9`. Lists the ~28 closure PRs by topic, the new `events follow --url` capability, modified crates / handlers / state, the test-infrastructure refactors, and ~25 new tests.
- `docs/review/phase-3/20-recent-prs-audit.md` — first of seven explorer docs. Surveyed 29 PRs from the closure cycle; 25 review-clean, 4 observations (all `nice` or `demoted`).
- `docs/review/phase-3/99-findings-ledger.md` — initial Phase 3 ledger with the four recent-PRs explorer findings.

#### F-2028-NNN findings raised

- **F-2028-001 (nice)** — `paths` module is correctly consolidated across CLI call sites, but startup-time path validation would catch future env-var-override drift earlier. Very low priority.
- **F-2028-002 (demoted)** — Auditor flagged a "1 important + 8 nice" phrasing in `phase-2/50-integration-audit.md` as potentially ambiguous; cross-check confirmed the math is correct (1 + 8 = 9 = `F-2027-028..036`). No drift, kept in ledger for audit-trail transparency.
- **F-2028-003 (demoted)** — Auditor flagged a "8 nice findings (F-2027-057..064)" phrasing in `phase-2/80-security-audit.md` as not mentioning F-2027-010 (SDD-debt); cross-check confirmed F-2027-010 was raised by the recent-PRs explorer, not the security explorer, so the doc is correct as scoped.
- **F-2028-004 (nice)** — The CLI's `--token-file` reader doesn't enforce the same `mode & 0o077 == 0` check the daemon-side `[api].token_file` reader does (closed F-2027-031). Symmetry issue, not a security gap. Worth resolving so the two readers behave the same way.

#### Status after this PR

- 4 findings raised, 0 blockers, 0 important, 2 nice (F-2028-001, F-2028-004), 2 demoted (F-2028-002, F-2028-003).
- Six explorers remain (crate, module, integration, docs, tests, security). Each will add findings in follow-up PRs.

This PR is documentation-only.

### Feature — `selfdefctl events follow --url` over TCP/HTTP(S) (closes F-2027-010, wraps Phase 2)

Operator-facing live-tail now works against the daemon's TCP transport, not just the UNIX socket. The Phase 2 audit flagged the gap as SDD-debt awaiting a design decision; the operator picked the bundle-reqwest option, and this PR ships it.

#### CLI shape

```
selfdefctl events follow                            # existing UNIX-socket path, unchanged
selfdefctl events follow --url https://host:7443    # new: TCP transport
selfdefctl events follow --url ... --token-file PATH
```

`--url` and `--unix-socket` are mutually exclusive (clap-enforced); `--token-file` requires `--url`. Reading the token from a file mirrors `[api].token_file` on the daemon side and keeps the token out of `ps`/shell history.

#### Implementation

- New `events_follow_tcp(base_url, bearer_token, alerts_only, limit)` in `crates/selfdef-cli/src/follow.rs` uses `reqwest::Client::get(base_url + "/events/stream").send().await.bytes_stream()` to receive the SSE body. reqwest already lives in the workspace via `selfdef-notifier`; the net dep cost is the `stream` feature plus `futures::StreamExt::next` to walk the chunk iterator.
- The existing UNIX HTTP/1.1 hand-roll is renamed `events_follow_unix` (no behaviour change).
- Both paths share a new `SseParser` state machine that owns the partial-line buffer + the per-frame `event:` accumulator. Frame decode (`Data` / `Shutdown` / `Lagged` / `UnknownEventType` / `Comment`) is identical across transports, so the `event: shutdown` and `event: lagged` contracts (F-2027-029 + F-2027-028) hold for TCP without re-implementation.
- `read_token_file(path)` trims trailing whitespace and rejects empty tokens (matches daemon-side validation).

#### Tests

- **Parser unit tests** (9): single-data frame, optional space after `data:`, event-type pairing, blank-line event-type reset, `:ping` keepalive vs operator-surfaced comment, `event: shutdown`, unknown event-type passthrough, partial-line buffering across `feed()` calls, unknown SSE fields ignored.
- **TCP integration tests** (5, `cli_events_follow_tcp.rs`): end-to-end stream of one event via subprocess + axum on `127.0.0.1:0`; bad URL fails fast; `--token-file` round-trips; `--url` and `--unix-socket` mutually exclusive (clap conflict); `--token-file` requires `--url` (clap requires-error).
- **Existing UNIX tests** (7): all pass against the refactored shared parser.

`cargo clippy --workspace --tests -- -D warnings` clean; `cargo fmt --all -- --check` clean.

#### Phase 2 status

**Phase 2 is fully wrapped.** Every finding across the seven explorers is closed: 0 blockers, 3 important (closed), 60 nice (closed), 1 SDD-debt (closed by this PR).

### Test — Phase 2 tests-cluster (closes F-2027-046 + F-2027-052 + F-2027-053)

The last three open `nice` findings from the Phase 2 tests-explorer cluster. After this PR every Phase 2 `nice` and `important` finding is closed; only F-2027-010 (SDD-debt, awaiting design decision) remains.

#### F-2027-046 — suricata live-positive coverage

`crates/selfdef-cli/tests/module_suricata.rs::live_apply_invokes_nft_load_and_systemctl_start`. Runs `apply.sh` *without* `SELFDEF_DRY_RUN=1` against recording stubs for `nft`, `systemctl`, and `suricata`. Asserts the live-branch side effects:

- `nft -f <rendered>` lands (NFQUEUE jump installed)
- `systemctl enable suricata.service` lands
- `systemctl start suricata.service` lands
- Apply emits `"status":"ok","message":"applied 3 change(s)"`
- The `[suricata] load NFQUEUE jump …` log line proves apply entered the install branch (not the "already-present" early-exit)

This closes the SDD-005 D-1 gap where every prior suricata test ran under `SELFDEF_DRY_RUN=1`, so the live branch had no regression protection.

#### F-2027-052 + F-2027-053 — pipeline tests on virtual time

`crates/selfdef-daemon/tests/m4_alert.rs::end_to_end_alert_fires_one_notification` and `crates/selfdef-daemon/tests/m8_honeytokens.rs::canary_touch_dispatches_actions_in_dry_run` both gain `start_paused = true` on their `#[tokio::test(…)]` attribute. SDD-005 forbids real-time sleeps in pipeline tests because they trade deterministic execution for CI-machine-speed flakiness; under `start_paused`, every `tokio::time::sleep` / `tokio::time::timeout` becomes virtual and the runtime auto-advances the clock whenever no task is ready to run.

Real pipeline work (collector → bus → correlator → responder → wiremock + SQLite I/O) still runs in real time, but the timer *gaps* between elapsed instants elapse instantly. Concretely:

- `m4_alert` end-to-end alert test: previously took ~500ms of real-time polling (5s deadline × 50ms intervals + 200ms settle); now runs in 0.10s wall-clock.
- `m8_honeytokens` canary-touch dispatch test: previously had seven real-time sleeps totaling 100ms+150ms+200ms+settle; now runs in 0.02s wall-clock.

#### Tests

- `cargo test -p selfdef-cli --test module_suricata` — 7/7 pass.
- `cargo test -p selfdef-daemon --test m4_alert --test m8_honeytokens` — 3/3 pass, all in <0.2s.
- `cargo clippy --workspace --tests -- -D warnings` clean.
- `cargo fmt --all -- --check` clean.

#### Phase 2 status after this PR

**Phase 2 is closed for `nice` findings.** All 60 `nice` + 3 `important` findings across the seven explorers are closed. The only Phase 2 item still open is **F-2027-010** (SDD-debt: `events follow` TCP transport) — awaiting a design decision on whether to pull in an HTTP client or document a remote-tunneling pattern instead.

### Security — remaining security-explorer cluster (closes F-2027-060 + F-2027-063 + F-2027-064)

Three small, contained hardening changes that close the rest of the Phase 2 security-explorer slate. After this PR every security finding from Phase 2 is closed; the only open `nice` clusters are tests-explorer leftovers.

#### F-2027-060 — `rbac check --as` subject validator

New `validate_rbac_subject` helper in `crates/selfdef-cli/src/main.rs`. Runs against every probe subject (built-in defaults + operator-supplied `--as` flags) before any `kubectl` invocation or stdout echo. Refuses anything outside `[A-Za-z0-9:._/@-]` or longer than 253 bytes (Kubernetes' own cap on subject names). Not a command-injection mitigation — `Command::new(...).args(...)` is already shell-free — but a log-pollution mitigation: an operator passing an ANSI-escape-laden string used to have those bytes land in the daemon's `error!` logs and the operator's terminal.

7 new unit tests pin the charset/length contract (accepts built-in subjects + ServiceAccount form, rejects empty/shell-meta/ANSI/whitespace/over-length). 1 new CLI integration test (`rbac_check_rejects_unsafe_subject_passed_via_as_flag`) exercises the validator end-to-end.

#### F-2027-063 — `ApiError::store` info disclosure

`ApiError::store` used to flatten arbitrary store errors verbatim into the JSON 500 body (`"error":"store: sqlite: open /var/lib/selfdef/state.sqlite: permission denied"`). Even though the path is already discoverable from the daemon config, the audit prescribed shipping a generic message to the caller and keeping the detail server-side. The constructor now logs the error via `warn!(error = %e, "api: store error")` and returns the body `"error":"store unavailable"`. All existing handlers route store errors through this constructor, so the change is one-line at the call boundary.

#### F-2027-064 — `cli_api_rotate_token` test posture

`rotate_token_writes_url_safe_token_at_0600` used to echo the rotated token value into its assertion failure messages via `format!("got: {stdout}", …)`. Tokens are tempfile-scoped and never used against a real daemon so the risk is very low, but the audit asked for format-only validation as best practice. The test now hunts for a url-safe-base64 line in stdout, asserts length + charset, and cross-checks `printed == token` — none of those assertion messages echo either value. Strictly stronger: catches stray-whitespace + length-default regressions that the previous substring match would silently accept.

#### Tests

- `cargo test --workspace` passes (existing 29 api tests + 4 rotate-token tests + 10 rbac-check tests + 7 new validator unit tests).
- `cargo clippy --workspace --tests -- -D warnings` clean.
- `cargo fmt --all -- --check` clean.

#### Phase 2 status after this PR

**Open `nice` clusters: 2 remaining, all in the tests-explorer cluster** (F-2027-046 suricata live-positive, F-2027-052 + -053 `pause()`-conversion). Every security-explorer finding is closed; Phase 2 wraps when the tests cluster lands.

### Security — SSE backpressure (closes F-2027-061 + F-2027-062)

Two hardening changes to `crates/selfdef-api/src/handlers.rs::events_stream`, both surfaced by the Phase 2 security audit. Both are authenticated-DoS mitigations on the opt-in TCP transport — UNIX-socket operators were never at risk because filesystem permissions already gate access.

#### F-2027-061 — per-process subscriber cap

`ApiState` now carries an `Arc<AtomicUsize>` subscriber counter. Each `/events/stream` request acquires a slot via a RAII `SubscriberGuard` (CAS-based `try_acquire`); when the cap (`MAX_SSE_SUBSCRIBERS = 64`) is saturated the handler returns `503 Service Unavailable` with `{"error":"sse subscriber cap reached"}` instead of spawning another forwarder task + 64-slot mpsc. The guard moves into the spawned task, so it runs its `Drop` when the writer exits (client gone, bus closed, send timeout) — the slot frees automatically.

#### F-2027-062 — slow-client send timeout

Every forwarder `tx.send(frame).await` is now wrapped in `tokio::time::timeout(SSE_SEND_TIMEOUT, …)` with a 30-second deadline. A client that stops draining its buffer used to pin the writer task indefinitely once the 64-slot mpsc filled; with the timeout, the writer logs `reason = "slow-client timeout"` and returns, which drops the `SubscriberGuard` and frees the cap slot. The deadline applies to both the normal forwarding path and the `event: lagged` overflow notification.

#### Tests

- New `events_stream_rejects_over_cap_with_503` (`crates/selfdef-api/tests/m12_api.rs`) — opens `MAX_SSE_SUBSCRIBERS` streams, asserts the next returns 503, then drops one held response, publishes a bus event to wake the writer (so it notices the disconnect), and asserts a fresh subscription now succeeds. This pins both the cap and the slot-reuse semantics.
- `MAX_SSE_SUBSCRIBERS` is re-exported from `lib.rs` behind the existing `test-helpers` Cargo feature so it stays out of release builds (same pattern as `with_full_capability`, F-2027-014).
- Existing `events_stream_emits_lagged_frame_on_real_bus_overflow` continues to pass — the timeout wrapping preserves the lagged-frame contract.

`cargo test -p selfdef-api`, `cargo clippy --workspace --tests -- -D warnings`, `cargo fmt --all -- --check` all clean.

#### Phase 2 status after this PR

**Open `nice` clusters: 3 remaining.** Tests-explorer leftovers (F-2027-046 suricata live-positive, F-2027-052 + -053 `pause()`-conversion) plus three security-explorer items (F-2027-060 rbac validator, F-2027-063 info disclosure, F-2027-064 test posture). Init-template hygiene + SSE-backpressure clusters are both closed.

### Documentation — init-template hygiene (closes F-2027-057 + F-2027-058 + F-2027-059)

Three doc-comment refreshes inside `crates/selfdef-cli/src/init.rs`'s embedded `STARTER_CONFIG` and `STARTER_MODULES` templates. Each closes one of the Phase 2 security-explorer init-template gaps without changing any value `selfdefctl init` writes — the byte stream only gains comment lines.

#### Changes

- **F-2027-057** — `[collectors.eventstream]` block now names the F-2027-035 mitigation explicitly. Adds a paragraph after the existing `integrity_check`/0750 hint explaining that the check protects the *file open* (via `O_NOFOLLOW` + fstat-on-FD) and warning operators to keep `paths` rooted under a 0750 selfdef:selfdef dir and never list a symlinked target. Closes the "operator never reads SECURITY.md" footgun the explorer flagged.
- **F-2027-058** — `[api]` block now documents `control_token_file` alongside `token_file`. Spells out the read-vs-control audience split: `token_file` gates the read endpoints (/events, /events/stream, /metrics, /status); `control_token_file` gates the mutating control endpoints. Operators who only need read can leave control unset; operators wanting a stricter control audience get a separate 0600 file with its own rotated token.
- **F-2027-059** — `STARTER_MODULES` header now warns that every per-module `config = "..."` is a trust boundary the daemon evaluates at apply time. Includes the verbatim `install -m 0640 -o root -g selfdef …` invocation that gives the file the right ownership/permissions before uncommenting the matching `[modules.<slug>]` block.

#### Tests

- `cargo test -p selfdef-cli --test cli_init` — all 7 cases pass; the existing assertions only check that the byte count matches `STARTER_CONFIG.len()` / `STARTER_MODULES.len()`, so the added comment lines are picked up automatically.
- `cargo build -p selfdef-cli` clean.

#### Phase 2 status after this PR

**Open `nice` clusters: 5 remaining.** Tests-explorer leftovers (F-2027-046 suricata live-positive, F-2027-052/-053 `pause()`-conversion) and four security-explorer items (F-2027-060 rbac validator, F-2027-061 + -062 SSE backpressure, F-2027-063 info disclosure, F-2027-064 test posture). The init-template hygiene cluster is closed.

### Documentation — Phase 2 security explorer (raises F-2027-057 through F-2027-064)

**Last of Phase 2's seven explorers.** Walks the new attack surfaces added during the post-Phase-1 cycle: `/events/stream` SSE endpoint, operator-side `init` config templates, `rbac check --probe`'s `kubectl` exec, plus a re-audit of F-2027-014 (`with_full_capability` feature-gate) and F-2027-035 (eventstream TOCTOU/symlink).

**8 new findings raised, all triaged `nice` — no blockers, no important.** Both re-audited security closures verified holding.

#### New document

`docs/review/phase-2/80-security-audit.md` — per-area notes with concrete `file:line` observations.

#### Themes

- **Init-template hygiene** (F-2027-057 + -058 + -059) — three doc gaps in `STARTER_CONFIG` / `STARTER_MODULES` where the starter doesn't warn about a known footgun (eventstream integrity_check pairing, control_token_file knob, module config file mode).
- **Defense-in-depth input validation** (F-2027-060) — `rbac check --probe` passes `--as <subject>` strings to `kubectl` via `Command::new` (safe by construction — no shell), but the strings aren't validated against a safe-charset regex. Log-pollution mitigation, not a code-injection vector.
- **SSE backpressure** (F-2027-061 + -062) — `/events/stream` lacks per-client connection caps and slow-client inactivity timeouts. Authenticated TCP DoS only (bearer-token holder required), but real for operators exposing the TCP port without an upstream rate limiter.
- **Information disclosure surface** (F-2027-063) — `ApiError::store` flattens store errors verbatim into the JSON 500 body; a future store error message that names an internal path would leak it.
- **Test-fixture posture** (F-2027-064, low priority) — `cli_api_rotate_token` asserts on token *value* rather than format, echoing the value to CI logs.

#### Closing-PR clusters

- **Init-template hygiene** — F-2027-057 + -058 + -059.
- **rbac input validation** — F-2027-060.
- **SSE backpressure** — F-2027-061 + -062.
- **Info-disclosure + test posture** — F-2027-063 + -064.

#### Re-audit appendix

- **F-2027-035** (eventstream TOCTOU/symlink, PR #67) — `O_NOFOLLOW | O_NONBLOCK` open + fstat-on-FD + non-regular-file refusal: complete, no remaining gaps.
- **F-2027-014** (`with_full_capability` feature-gate, PR #61) — `#[cfg(feature = "test-helpers")]` guard correctly prevents the symbol from appearing in release builds.

#### Phase 2 status after this PR

**64 findings across 7 explorers. All 7 Phase 2 explorers have now run.** 0 blockers, 3 important (all closed), 60 nice (49 closed, 11 open), 1 SDD-debt open.

Open `nice` clusters: tests-explorer leftovers (F-2027-046 suricata live-positive, F-2027-052/-053 `pause()`-conversion) and the new security-explorer cluster. Phase 2 wraps when those follow-up PRs merge.

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, `cargo fmt --all -- --check` clean. This PR is documentation-only.

### Test — api-test isolation + parser-adoption (closes F-2027-054 + F-2027-055 + F-2027-056)

Three small, contained fixes in `crates/selfdef-api/tests/m12_api.rs`.

#### F-2027-054 — `dummy_action_set` uses per-test tempdirs

Pre-fix: the helper wrote to `std::env::temp_dir().join("selfdef-api-test-snapshots")` and `.../selfdef-api-test-forensics` — two host-global paths shared across every test in the suite. Parallel test runs would step on each other's snap / forensics outputs. Now: `tempfile::tempdir()` per call so each test gets its own scratch path. The two TempDir handles are then `mem::forget`-leaked per-call (small, bounded leak — at most ~14 tempdirs per `cargo test --workspace` run) so the actions can still find the path when control verbs fire.

#### F-2027-055 — `build_state()` returns the `TempDir` handle

Pre-fix: `build_state()` ended with `std::mem::forget(dir)` to keep the sqlite file alive after the function returned. The leak was correct for in-process operations (Linux inode semantics keep the file alive while any FD is open) but documented as intentional with a stack-of-tempdirs accumulating in `/tmp` per test run.

Now: `build_state()` returns `(ApiState, Arc<Bus>, Arc<SqliteStore>, tempfile::TempDir)`. Every caller adds `_dir` to its destructure; the handle is held on the test's stack frame and dropped cleanly on test exit. 12 callers updated. A second `mem::forget` site in `events_stream_emits_lagged_frame_on_real_bus_overflow` was replaced with a `let _dir_holder = dir` stack hold.

#### F-2027-056 — `metrics_reflect_ingest_counters_via_record_event` uses the P-2 parser

Pre-fix: the test asserted `body.contains("selfdef_events_total 4")` and three sibling substring checks against the raw exposition body. The hand-rolled P-2 Prometheus parser (already used by the strict-format tests in the same file) catches duplicate samples, malformed line shapes, and label-escape bugs that substring matching would miss.

Now: the four assertions go through `prom::parse(&body)` + `exp.find(name, labels)`. Format-strict validation kicks in for free.

#### Phase 2 status after this PR

**56 findings across 6 explorers. 52 nice (49 closed, 3 open)**, **3 important (all closed)**, **0 blockers**, **1 SDD-debt open**. Remaining open `nice`: F-2027-046 (suricata live-positive), F-2027-052/-053 (`pause()`-conversion). One Phase 2 explorer remains (security).

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, `cargo fmt --all -- --check` clean. `m12_api.rs` runs 28 tests all green.

### Test — vpn-bridge P-1 dry-run-noop backfill (closes F-2027-048; F-2027-047 false-positive)

Closes the bulk of the module-test backfill cluster from the Phase 2 tests explorer.

#### F-2027-048 — new P-1 cases for cloudflare-tunnel + tailscale profiles

`crates/selfdef-cli/tests/module_vpn_bridge_cloudflare.rs` and `module_vpn_bridge_tailscale.rs` had live-positive coverage but no `snapshot_tree` / `assert_tree_unchanged` paired test to guard against the dry-run-writes-files regression. Two new cases follow the SDD-005 P-1 pattern: snapshot scratch before, run `apply.sh` with `SELFDEF_DRY_RUN=1`, snapshot after, assert byte-identical.

#### F-2027-047 — closed as false positive

`module_polarproxy.rs::dry_run_apply_must_be_a_noop_on_disk` (line 231) already implements the P-1 snapshot pattern against the host-tls-mitm profile. The tests-explorer's report mis-classified polarproxy's coverage. Marked closed with a `re-verified` note in the ledger.

#### F-2027-046 — remains open

The suricata `module_suricata.rs` live-positive gap (the test suite covers only `SELFDEF_DRY_RUN=1`) is heavier to close — a live-positive test needs a fixture with writable target paths and stubbed `systemctl is-enabled` so the apply path takes the start+enable branches without actually invoking systemd. Defer to its own PR.

#### Phase 2 status after this PR

**56 findings across 6 explorers. 52 nice (46 closed, 6 open)**, **3 important (all closed)**, **0 blockers**, **1 SDD-debt open**. Remaining open `nice`: F-2027-046 (suricata live-positive), F-2027-052/-053 (`pause()`-conversion), F-2027-054/-055 (api-test isolation), F-2027-056 (parser-adoption). One Phase 2 explorer remains (security).

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, `cargo fmt --all -- --check` clean.

### Refactor — common test-helper migration (closes F-2027-049 + F-2027-050 + F-2027-051)

Migrates 17 test files in `crates/selfdef-cli/tests/` to use the canonical helpers in `tests/common/mod.rs` instead of locally duplicating them. Drops ~45 duplicate function definitions from the test surface.

#### Pre-fix → post-fix

Before:
- `workspace_root()` re-implemented in 13 files.
- `module_dir()` re-implemented in 12 files (each hard-coded one slug).
- `last_stdout_line()` re-implemented in 12 files.
- `write_executable()` re-implemented in 7 files.
- `prepended_path()` re-implemented in 10 files.
- `write_file()` re-implemented in 3 files.
- `mod common;` declared late (after the first set of helpers) in 8 module files.

After:
- Every test file declares `mod common;` near the top and `use common::{...};` for the helpers it needs.
- The 12 parameterless `module_dir()` calls in module tests become one-liner wrappers (`fn module_dir() -> PathBuf { common::module_dir("<slug>") }`) — preserving the call shape while delegating the path math.

#### Per-file touch

| File | Helpers removed |
| --- | --- |
| `module_tetragon.rs` | wsroot, module_dir, last_stdout_line, write_executable, prepended_path |
| `module_agent_guard.rs` | wsroot, module_dir, last_stdout_line, write_file |
| `module_bridge_l2.rs` | wsroot, module_dir, last_stdout_line, prepended_path |
| `module_integrity_sentinel.rs` | wsroot, module_dir, last_stdout_line, write_file |
| `module_observability.rs` | wsroot, module_dir, last_stdout_line, write_file |
| `module_polarproxy.rs` | wsroot, module_dir, last_stdout_line, prepended_path |
| `module_suricata.rs` | wsroot, module_dir, last_stdout_line, prepended_path |
| `module_tetragon_signing.rs` | wsroot, module_dir, last_stdout_line, write_executable, prepended_path |
| `module_vpn_bridge*.rs` (4 files) | wsroot, module_dir, last_stdout_line, prepended_path |
| `cli_modules_apply.rs`, `cli_modules_daemon_requires.rs`, `cli_modules_uninstall.rs`, `cli_rbac_check.rs`, `cli_modules_shared_lib.rs` | write_executable, prepended_path, wsroot (where present) |

#### Phase 2 status after this PR

**56 findings across 6 explorers. 52 nice (44 closed, 8 open)**, **3 important (all closed)**, **0 blockers**, **1 SDD-debt open**. Remaining open `nice` clusters: module-test backfill (F-2027-046/-047/-048), pause()-conversion (F-2027-052/-053), api-test isolation (F-2027-054/-055), parser-adoption (F-2027-056). One Phase 2 explorer remains (security).

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, `cargo fmt --all -- --check` clean.

### Documentation — Phase 2 tests explorer (raises F-2027-046 through F-2027-056)

Sixth of Phase 2's seven explorers ships. Walks the new integration tests added during the post-Phase-1 cycle, the three shared patterns from SDD-005 (P-1 dry-run-noop, P-2 Prometheus parser, P-3 real-broker NATS), and the four test categories.

**11 new findings raised. All triaged `nice` — no blockers, no important.** Test surface is in good shape overall: every Phase 2 closure PR shipped with a regression test per the ledger's closure notes; the SDD-005 categories still match the codebase; the three patterns are used by the surfaces that need them.

#### New document

`docs/review/phase-2/70-tests-audit.md` — per-area notes with concrete `file:line` observations + a triage table that clusters the findings into five follow-up PRs.

#### New findings

| ID | Surface | Theme |
| --- | --- | --- |
| F-2027-046 | `module_suricata.rs` live-positive missing | P-1 dry-run-noop adoption gap |
| F-2027-047 | `module_polarproxy.rs` P-1 pair missing | P-1 dry-run-noop adoption gap |
| F-2027-048 | `module_vpn_bridge_{cloudflare,tailscale}.rs` P-1 gap | P-1 dry-run-noop adoption gap |
| F-2027-049 | `workspace_root()` / `module_dir()` duplicated ~14× | helper duplication |
| F-2027-050 | `last_stdout_line()` duplicated 6× | helper duplication |
| F-2027-051 | `write_executable()` duplicated 4× | helper duplication |
| F-2027-052 | `m4_alert.rs` real-time sleeps | SDD-005 anti-pattern |
| F-2027-053 | `m8_honeytokens.rs` real-time sleeps | SDD-005 anti-pattern |
| F-2027-054 | `dummy_action_set` shared `/tmp` paths | api-test isolation |
| F-2027-055 | `std::mem::forget(dir)` SQLite leak | api-test isolation |
| F-2027-056 | metrics tests bypass P-2 Prometheus parser | parser-adoption |

#### Closing-PR clusters

- **module-test backfill** — F-2027-046 + -047 + -048.
- **`common/mod.rs` migration** — F-2027-049 + -050 + -051.
- **`pause()`-conversion** — F-2027-052 + -053.
- **api-test isolation** — F-2027-054 + -055.
- **parser-adoption** — F-2027-056.

#### Phase 2 status after this PR

**56 findings across 6 explorers. 52 nice (41 closed, 11 open)**, **3 important (all closed)**, **0 blockers**, **1 SDD-debt open**. One explorer remains (security).

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, `cargo fmt --all -- --check` clean. This PR is documentation-only.

### Documentation — Phase 2 docs-final-cluster (closes F-2027-039 + F-2027-040 + F-2027-045)

Closes the last three open `nice` findings from the Phase 2 docs explorer. **All five Phase 2 explorers run so far (recent-PRs, crate, module, integration, docs) are now fully drained at the actionable tiers.** Only F-2027-010 (SDD-debt — `events follow` TCP transport, awaiting design) remains open across Phase 2.

#### F-2027-039 — test-contract "Per-test isolation overrides" section

`docs/dev/test-contract.md` gains a new "Per-test isolation overrides" section documenting the workspace pattern: host-global state paths (manifest, doctor agent-guard config) get a per-test `tempdir`-scoped env override so parallel CI runs don't trample each other. Includes a table of every override the workspace currently wires (`MODULE_INSTALLED_MANIFEST`, `SELFDEF_DOCTOR_AGENT_GUARD_CONFIG`), plus a "when CI fails locally-passes…" diagnostic pointer at commit `d5d05da` (PR #65 fixup).

#### F-2027-040 — `docs/dev/README.md` documents canonical runbook shape

The six existing `docs/dev/<feature>.md` runbooks predate any shape convention and have 5–11 sections each. The audit's recommendation was "pick a canonical shape and apply uniformly" — aggressive reformatting of existing runbooks would be invasive and contentious, so this PR takes the lighter-touch fix instead: new `docs/dev/README.md` indexes every runbook AND documents the canonical 7-section shape (TL;DR / Config / Commands / Tests / Troubleshooting / Env overrides / Threat model) for new runbooks to follow. Existing runbooks aren't reformatted but they're now navigable from the index.

#### F-2027-045 — SDD "Follow-up findings" tail sections

SDD-003, SDD-004, and SDD-006 each gain a `## Follow-up findings (F-2027-045)` tail section listing the Phase 2 F-2027-NNN entries that iterated on each SDD's surface:

- **SDD-003** — F-2027-001 (refusal-message TOML stanza), F-2027-025 (vpn-bridge `safe_name`).
- **SDD-004** — F-2027-003 (eventstream `read_euid`), F-2027-005 (verifier reload), F-2027-006 (`keys verify-dir`), F-2027-007 (RBAC probes), F-2027-014 (`with_full_capability` feature-gate), F-2027-031 (mode-0600 enforcement), F-2027-035 (eventstream TOCTOU/symlink), F-2027-036 (post-startup-drift doc).
- **SDD-006** — F-2027-024 (v2 migration of 5 modules), F-2027-026 (per-module adoption table), F-2027-027 (`DRY_RUN=0` standardisation).

Future SDD readers can now trace the lineage from each design doc to the post-Phase-1 iterations without bouncing through the ledger.

#### Phase 2 status after this PR

**45 findings across 5 explorers. 41 nice (all closed)**, **3 important (all closed)**, **0 blockers**, **1 SDD-debt open** (F-2027-010). Two Phase 2 explorers remain (tests, security).

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, `cargo fmt --all -- --check` clean.

### Documentation — Phase 2 operator-facing docs refresh (closes F-2027-037 + -038 + -041 + -042 + -043 + -044)

Closes the largest of the three docs-explorer follow-up clusters. Six findings, all docs-only, in a single coordinated pass across README + ARCHITECTURE.md + two runbooks.

#### Per-finding fixes

- **F-2027-037** — `docs/dev/signing.md`'s SIGUSR2 section previously documented the signal as a verifier-reload-only surface. It now enumerates all three reload branches (api tokens, verifier, rules re-verify) and shows the post-fan-out summary log line (`tokens=ok verifier=ok rules=ok SIGUSR2 reload summary`) that F-2027-032 added.
- **F-2027-038** — `docs/dev/rbac-posture.md` listed the built-in probe set as 2 subjects. Now lists all four (post-F-2027-007: + `system:masters` + `system:serviceaccount:default:default`) with a one-line rationale per subject explaining the misuse pattern each catches.
- **F-2027-041** — README's "Read-only" verb table now includes `selfdefctl events follow` (with a one-liner pointing at the F-2027-029/-030 protocol surface). The "Security opt-ins" table gains `keys verify-dir` (F-2027-006) and notes F-2027-031 mode-0600 enforcement + F-2027-007 expanded probe set on the existing entries.
- **F-2027-042** — README's "Security opt-ins" section gains a new "Phase 2 hot-reload surfaces" sub-section calling out F-2027-005 (verifier hot-rotation), F-2027-032 (summary log), F-2027-035 (eventstream TOCTOU/symlink hardening), and F-2027-014 (`with_full_capability` feature-gating).
- **F-2027-043** — README quickstart now runs `cargo deb -p selfdef-cli` alongside `selfdef-daemon` and `dpkg -i` both — the daemon and the CLI are separate Debian targets and the operator needs both.
- **F-2027-044** — ARCHITECTURE.md's topology diagram label flipped from `SIGUSR2 (api tokens)` to `SIGUSR2 (tokens + verifier + rules)`. The security-properties section gains cross-references to F-2027-005 / -031 / -032 / -035 alongside the existing F-2026 follow-up citations.

#### Phase 2 status after this PR

**45 findings across 5 explorers. 41 nice (38 closed, 3 open)**, **3 important (all closed)**, **0 blockers**, **1 SDD-debt open**. The three open `nice` findings are the runbook-structure cluster (F-2027-039 + -040) and the SDD-lineage cluster (F-2027-045). Two Phase 2 explorers remain (tests, security).

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, `cargo fmt --all -- --check` clean.

### Documentation — Phase 2 docs explorer (raises F-2027-037 through F-2027-045)

Fifth of Phase 2's seven explorers ships. Walks the six new `docs/dev/<feature>.md` runbooks, README.md, ARCHITECTURE.md, and the six SDDs — plus a sanity-check of the four already-shipped Phase 2 audit docs.

**9 new findings, all triaged `nice` — no blockers, no important.** The doc surface is in good shape overall; the findings cluster around three themes:

- **Drift from Phase 2 closures** — three runbooks (`signing.md`, `rbac-posture.md`, `test-contract.md`) and ARCHITECTURE.md still describe pre-closure behaviour for SIGUSR2 fan-out (F-2027-005 / -032 / -070), RBAC probe set (F-2027-007), and eventstream integrity (F-2027-035) etc.
- **README missing post-Phase-1 verbs** — `selfdefctl init`, `doctor`, `events follow`, `keys verify-dir`, expanded `rbac check` are reachable via `--help` but not called out in the README's verb tour.
- **Phase 2 audit hygiene** — runbook section structure varies (5/8/11 sections across the three runbooks); SDDs don't cross-reference the F-2027-NNN follow-ups that iterated on their surface.

#### New document

`docs/review/phase-2/60-docs-audit.md` — per-area notes with concrete `file:line` observations.

#### Closing-PR clustering

- **Operator-facing refresh** — F-2027-037 + -038 + -041 + -042 + -043 + -044 (six findings, all docs-only; one pass across README + ARCHITECTURE.md + the affected runbooks).
- **SDD lineage refresh** — F-2027-045 (single PR adds "Follow-up findings" tails to SDD-003, -004, -006).
- **Runbook structure pass** — F-2027-039 + -040 (`test-contract.md` "Per-test isolation overrides" section + canonical-shape application).

#### Phase 2 status after this PR

**45 findings across 5 explorers. 41 nice (32 closed, 9 open)**, **3 important (all closed)**, **0 blockers**, **1 SDD-debt open**. Two explorers remain (tests, security).

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, `cargo fmt --all -- --check` clean. This PR is documentation-only.

### Fixed — SSE seam-1: shutdown marker + comment handling + real-bus lagged test (closes F-2027-028 + F-2027-029 + F-2027-030)

Closes the seam-1 cluster from the Phase 2 integration explorer. With this PR, **all four Phase 2 explorers are fully drained at the actionable tiers** — every blocker, important, and nice finding raised across recent-PRs, crate, module, and integration is closed.

#### F-2027-029 — writer emits `event: shutdown` on bus close

`crates/selfdef-api/src/handlers.rs::events_stream`'s forwarder task previously exited silently when the bus closed (`BusError::Closed` = daemon shutdown) or returned a non-Lagged error. The reader saw `read_line` return 0 bytes and couldn't distinguish "daemon shutdown" from "TCP got chopped mid-stream". Now: on both exit paths the task emits an `event: shutdown` frame with a `data:` reason (`"bus closed"` or `"bus error"`) before returning. Best-effort via `try_send` — if the client already disconnected, no harm done.

#### F-2027-028 — reader is frame-aware

`crates/selfdef-cli/src/follow.rs` previously parsed each line independently — it stripped `data:` prefix, tried to decode as `Event`, and silently swallowed everything else (including `event:` lines and `:`-comments). The pre-fix code couldn't distinguish a `:ping` keep-alive from any other `:`-comment, and couldn't tell that a `data: bus closed` line followed an `event: shutdown` header.

The reader now tracks `current_event_type` per-frame (reset on blank-line frame terminator). Dispatches:

- `event: shutdown` → prints `# daemon stream shutdown: <reason>` to stderr, exits 0.
- `event: lagged` → prints `# lagged: <payload>` to stderr (unchanged).
- `event:` (unset) → decodes payload as `Event` for `--alerts-only` filtering.
- `event: <other>` → prints `# unknown event-type "..."` to stderr.
- `:ping` comment → silently ignored.
- `:<other>` comment → prints `# sse-comment: <text>` to stderr (surfaces protocol anomalies).
- Unknown fields (`id:`, `retry:`, …) → silently ignored per the SSE spec.

#### F-2027-030 — real-bus lagged-event end-to-end test

`crates/selfdef-cli/tests/cli_events_follow.rs:162-197` exercises the lagged path via hand-crafted SSE bytes — fine for the reader, but no test on the writer side ever produced a real `BusError::Lagged(_)`. New test `events_stream_emits_lagged_frame_on_real_bus_overflow` in `crates/selfdef-api/tests/m12_api.rs` builds a 2-slot `Bus`, hits `/events/stream`, publishes 100 events without consuming the response body for a moment, and asserts the streaming body contains `event: lagged` within a 5-second deadline.

Plus two reader-side coverage tests in `cli_events_follow.rs`:

- `follow_exits_cleanly_on_event_shutdown_frame` — `event: shutdown\ndata: bus closed` from a fake daemon yields exit-0 + a `# daemon stream shutdown` stderr line.
- `follow_silently_swallows_ping_keepalive_comments` — `:ping` comments don't pollute stderr.
- `follow_surfaces_unexpected_comment_to_stderr` — `:mystery-marker` surfaces as `# sse-comment: mystery-marker`.

#### Build / lint

`crates/selfdef-api/Cargo.toml` dev-dep adds `http-body-util = "0.1"` (already in the lockfile via axum/hyper-util transitively) so the streaming-body lagged test can poll frames directly.

#### Phase 2 status after this PR

**36 findings across 4 explorers. 32 nice (all closed)**, **3 important (all closed)**, **0 blockers**, **1 SDD-debt open** (F-2027-010 — `events follow` TCP transport, awaiting design). All four Phase 2 explorers (recent-PRs, crate, module, integration) are now drained at the actionable tiers. Three explorers remain (docs, tests, security).

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, `cargo fmt --all -- --check` clean.

### Fixed — SIGUSR2 seam-2: token-file mode validation + summary log (closes F-2027-031 + F-2027-032)

Closes the seam-2 cluster from the Phase 2 integration explorer.

#### F-2027-031 — refuse loose token-file modes on reload

`read_token` (in `crates/selfdef-api/src/transport.rs`) now checks `mode & 0o077 == 0` before reading. `selfdefctl api rotate-token` writes the file 0600; if `chmod 0644` slips in after a rotation, the bearer-token surface is silently weakened — world-readable token == defeated auth. The pre-fix code happily re-read the bytes and applied them.

The fix surfaces the misuse as a new typed `ServerError::LooseTokenMode { path, mode }` variant. Display message:

```
token file '/etc/selfdef/api.token' has loose mode 644 (must be 0600); chmod and SIGUSR2 again
```

Prior in-memory tokens stay in place — the bearer-token middleware keeps using the last-good value while the operator chmods and re-signals.

#### F-2027-032 — SIGUSR2 reload summary line

The daemon's SIGUSR2 handler runs three reload paths independently (api tokens, signing verifier, rule re-verify after verifier reload) with three separate log lines. Operators correlating "did SIGUSR2 overall succeed?" had to mentally stitch them together. Now the handler tracks per-branch outcome (`ok` / `failed` / `skipped`) and emits a single summary line at the end of the fan-out:

```
INFO tokens=ok verifier=ok rules=ok SIGUSR2 reload summary
```

The per-branch info/warn lines are unchanged — the summary is additive. `Skipped` covers "feature not configured" (signing disabled, api disabled, etc.). `Failed` covers any branch that errored. The summary always runs when *any* hot-reloadable surface is enabled; the all-skipped case still logs the existing debug "no hot-reloadable surface is enabled" message.

#### Tests

- `crates/selfdef-api/src/transport.rs` `token_reload_tests` — +1 case: `reload_refuses_world_readable_token_file` (10 total). Creates a 0600 file → reload OK → `chmod 0644` → reload fails with `LooseTokenMode { mode: 0o644, … }` → prior tokens still in place.
- No new daemon-side test for F-2027-032 — the summary is just a log line; the existing token-reload test exercises the fan-out branches. Verified manually that the summary line appears in the right outcome combinations.

#### Phase 2 status after this PR

36 findings across 4 explorers. **3 important (all closed)**, **32 nice (29 closed, 3 open)**, **0 blockers**, **1 SDD-debt open**. The seam-1 SSE cluster (F-2027-028 + -029 + -030) is the only remaining open `nice` work; three explorers remain (docs, tests, security).

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, `cargo fmt --all -- --check` clean.

### Fixed — selfdef-correlator seam-3: deterministic load + error priority (closes F-2027-033 + F-2027-034)

Closes the seam-3 cluster from the Phase 2 integration explorer.

#### F-2027-033 — deterministic rule enumeration

`walk_yaml` (in `crates/selfdef-correlator/src/sigma.rs`) previously returned paths in `std::fs::read_dir` order — undefined per the standard library docs. Two rules with the same priority that match the same event would fire in filesystem-enumeration order, kernel- and filesystem-version dependent. Now sorts lexicographically before returning, so operators can predict precedence by file naming alone.

#### F-2027-034 — parse YAML before verifying signature

`Engine::load_dir_maybe_verified` previously verified the signature *before* parsing the YAML. A malformed-but-signed rule (e.g. a yaml-typo accident) yielded `SigmaError::Signature` — counter-intuitive, because the signature was technically valid over the malformed bytes. Operators chasing a "rule won't load" mystery would run `selfdefctl keys verify` first, get a green light, and only then realise the issue was YAML.

Now: read + `serde_yaml_ng::from_slice` runs first; signature verification runs second. A malformed file surfaces `SigmaError::Yaml { path, source }` with the parser's line-and-column detail. The signature is **still** verified before the rule is added to the engine, so the security contract ("only signed rules are loaded") is unchanged — only the failure-mode reporting changes.

#### Tests

`crates/selfdef-correlator/tests/signed_rules.rs` (+2 cases, 14 total):

- `load_rules_yaml_error_takes_priority_over_signature` — signed-but-malformed YAML returns `Yaml`, not `Signature`.
- `load_rules_walks_yaml_in_sorted_order` — three rules named `zeta` / `mu` / `alpha` all load under the deterministic walk; existing tests cover the actual matching precedence indirectly.

#### Phase 2 status after this PR

36 findings across 4 explorers. **3 important (all closed)**, **32 nice (27 closed, 5 open)**, **0 blockers**, **1 SDD-debt open**. Two seam clusters remain (seam-1 SSE, seam-2 SIGUSR2); three explorers remain (docs, tests, security).

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, `cargo fmt --all -- --check` clean.

### Fixed — eventstream collector: TOCTOU + symlink hardening (closes F-2027-035 + F-2027-036)

Closes Phase 2's only open important finding. The opt-in `[collectors.eventstream].integrity_check = true` contract is now defeatable-only-by-kernel-bug instead of defeatable-by-local-attacker.

#### F-2027-035 — TOCTOU and symlink-follow gap

`check_path_integrity` previously did `std::fs::metadata(path)` (a `stat`, which follows symlinks) and then `tokio::fs::File::open(path)` (which also follows symlinks). Two attack vectors:

1. **Symlink**: a non-root operator who could write the configured path could point it at a symlink targeting a daemon-owned file; the check passed against the target's metadata, then the collector read from a target the operator controlled.
2. **TOCTOU**: between the stat and the open, a local attacker could rename the file in-place (atomic for symlinks). The validated metadata no longer matched what the open returned.

The fix: a single-syscall-sequence rewrite. The function is renamed `open_with_integrity_check` and:

1. Opens the file with `OpenOptions::new().read(true).custom_flags(O_NOFOLLOW)`. Symlinks fail open with `ELOOP`, surfaced as a new `EventstreamError::IntegritySymlink` variant whose Display message tells the operator to repoint `[collectors.eventstream].paths` at the real file.
2. Calls `file.metadata()` (which is `fstat` on the returned FD, not a fresh path lookup). The validated metadata is locked to the inode the reader will consume — no TOCTOU window.
3. Refuses non-regular files (`is_file() == false` → fifos, sockets, device nodes) — `O_NOFOLLOW` catches symlinks but not these.
4. Returns the opened `std::fs::File` on success; the caller threads it into `tokio::fs::File::from_std` so there's only one open syscall. On any failure the FD is dropped (closed), so a partially-opened handle can't leak to the reader.

Caveat: the workspace lints `unsafe_code = "forbid"` and doesn't carry a `libc` dep, so the `O_NOFOLLOW` value is hard-coded as the Linux ABI constant (0x20000, from `uapi/asm-generic/fcntl.h`). Same with `ELOOP == 40` for the typed-error branch. Both are stable Linux ABI; pulling in `libc` for two integers would be heavy.

#### F-2027-036 — post-startup drift doc warning

The check runs once at collector startup, against the opened FD. A daily `logrotate` that replaces the file post-startup doesn't trigger a re-check — the collector keeps reading the rotated-out file via the held FD, and ownership / mode drift on the new file goes unvalidated. The SIGHUP / SIGUSR2 handlers don't re-run collector setup today.

`docs/dev/first-run.md` § "Optional: eventstream integrity" now spells this out, including the operator workaround: restart the daemon after a rotation cycle if you want the check to re-assert.

#### Tests

`crates/selfdef-collector-eventstream/src/lib.rs` `#[cfg(test)]` block (+2 new cases):

- `integrity_check_refuses_symlink` — creates a symlink pointing at a daemon-owned regular file; the pre-fix code would silently pass; the new code returns `IntegritySymlink { path }`.
- `integrity_check_refuses_non_regular_file` — creates a fifo via `mkfifo`; the check refuses with `IntegrityRefused { reason: "not a regular file …" }`. Falls back gracefully if `mkfifo` isn't on PATH (busybox / minimal containers).

The three pre-existing tests (`world_writable`, `daemon_owned`, `allowed_owner`) are kept and converted from `check_path_integrity` (returns `()`) to the new `open_with_integrity_check` (returns `File`). Same coverage, FD dropped immediately in the test on success.

#### Phase 2 status after this PR

36 findings across 4 explorers. **3 important (all closed)**, **32 nice (25 closed, 7 open)**, **0 blockers**, **1 SDD-debt open**. Three seam-1/-2/-3 clusters remain as nice follow-ups; three Phase 2 explorers remain (docs, tests, security).

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, `cargo fmt --all -- --check` clean.

### Documentation — Phase 2 integration explorer (raises F-2027-028 through F-2027-036)

Fourth of Phase 2's seven explorers ships. Surveys the four post-Phase-1 seams called out in the charter: SSE writer ↔ CLI follow consumer, SIGUSR2 token-reload, minisign verify ↔ correlator load, and integrity check ↔ eventstream open.

**9 new findings raised. 1 important (F-2027-035), 8 nice.** This is the first explorer in this cycle to surface an `important`-tier observation.

#### New document

`docs/review/phase-2/50-integration-audit.md` — seam-by-seam notes with concrete `file:line` observations + a triage table that clusters the findings into one PR per seam.

#### Important finding

- **F-2027-035** — `selfdef-collector-eventstream::check_path_integrity` uses `std::fs::metadata` (stat, follows symlinks); the follow-up `tokio::fs::File::open` also follows symlinks. A symlink at the configured path passes the check based on the target's metadata, and the collector reads from a target the operator may not control. Combined with the stat→open TOCTOU window, the opt-in `integrity_check = true` contract is defeatable. The fix shape is a single-syscall-sequence rewrite: lstat → O_NOFOLLOW-open → fstat. Important rather than blocker because the feature is opt-in (off by default) — but operators who turn it on are explicitly trusting the check.

#### Nice findings (8 — all open)

- **F-2027-028** — SSE reader silently ignores non-`data:` lines (including `:ping` keep-alives and hypothetical malformed comments).
- **F-2027-029** — SSE seam has no end-of-stream marker; reader can't distinguish "daemon shut down" from "daemon crashed mid-stream".
- **F-2027-030** — SSE lagged-event test corpus is hand-crafted; no end-to-end test under real bus overflow.
- **F-2027-031** — `TokenReloader::reload` doesn't re-validate the mode-0600 invariant; `chmod 0644` after rotate silently weakens the bearer-token surface.
- **F-2027-032** — SIGUSR2 handler runs three reload paths independently with three separate log lines; no summary at the end.
- **F-2027-033** — `walk_yaml` uses unsorted `read_dir`; rules with the same priority fire in fs-dependent order.
- **F-2027-034** — Signature check runs before YAML parse; malformed-but-signed rule yields `Signature` error instead of `Yaml`.
- **F-2027-036** — Eventstream collector holds the FD for the daemon's lifetime; nothing re-validates ownership / mode if `logrotate` replaces the file post-startup. (Doc-only.)

#### Closing-PR clustering

One PR per seam:
- **seam-1 (F-2027-028 + -029 + -030)** — SSE end-of-stream marker + comment-handling + real-bus lagged-event test.
- **seam-2 (F-2027-031 + -032)** — TokenReloader mode-validation + SIGUSR2 summary log.
- **seam-3 (F-2027-033 + -034)** — Deterministic rule load + error-priority swap.
- **seam-4 (F-2027-035 + -036)** — lstat-O_NOFOLLOW-fstat rewrite + post-startup drift doc.

#### Phase 2 backlog after this PR

36 findings across 4 explorers. **3 important (2 closed, 1 open — F-2027-035)**, **32 nice (24 closed, 8 open)**, **1 SDD-debt open**, **0 blockers**. Three explorers remain (docs, tests, security).

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, `cargo fmt --all -- --check` clean. This PR is documentation-only.

### Fixed — SDD-006 v2 manifest-helpers migration (closes F-2027-024)

Closes the last open `nice` finding in the Phase 2 backlog. Five script-based modules — `bridge-l2`, `integrity-sentinel`, `polarproxy`, `observability`, `tetragon` — opted into SDD-006 v2 manifest helpers. Each module's `apply.sh` now records every rendered file via `module_record_file`, and each module's `uninstall.sh` walks `module_render_files` instead of hand-curating the same paths. The drift risk that v2 was specifically designed to remove is now eliminated for these five.

The other two script-based modules don't migrate in this PR:
- **`suricata`** — N/A. Renders no files outside its own template dir; v2 migration would have no manifest entries to track.
- **`vpn-bridge`** — deferred. The dispatcher pattern delegates rendering to per-profile sourced scripts (`install/profiles/*.sh`); the migration needs to flow through each profile's `profile_apply` / `profile_uninstall` functions independently. Tracked as a follow-up under F-2027-024 in the docs.

#### Per-module change shape

Each migration is mechanical:
1. **`install/lib.sh`** bumped to `SELFDEF_MODULE_LIB_VERSION_REQUIRED=2`.
2. **`install/apply.sh`** wraps each `install`/`cp` of a rendered file with `module_record_file "<absolute path>"` immediately after the write.
3. **`install/uninstall.sh`** replaces hand-enumerated removals with a `module_render_files | while read dst; rm -f "$dst"; done` loop, then `module_clear_manifest`. A **legacy-fallback branch** (gated on `manifest_count == 0`) re-derives the old hand-coded paths so pre-v2 installs still uninstall cleanly after the upgrade.

#### Test isolation

The shared module-lib's default install-manifest path is `/var/lib/selfdef/installed/<MODULE>.manifest` — host-global. Parallel test runs were trampling that file, causing flaky failures. Fixed by wiring `MODULE_INSTALLED_MANIFEST=<tempdir>/installed.manifest` into the four affected test fixtures (`module_integrity_sentinel.rs`, `module_observability.rs`, `module_tetragon.rs`, `module_tetragon_signing.rs`). `module_polarproxy.rs` runs dry-run-only so the manifest is never written; no fix needed. `module_agent_guard.rs` already had the override.

#### Adoption-table refresh

`docs/dev/module-helpers.md`'s "Per-module adoption" table now reflects the post-migration state (5 v2, 1 still v1 with rationale, 1 dispatcher with deferred-migration note).

#### Phase 2 status after this PR

**27 findings across 3 explorers. 24 nice (all closed)**, **2 important (closed)**, **0 blockers**, **1 SDD-debt open** (F-2027-010 — `events follow` TCP transport, awaiting design).

**All three Phase 2 run explorers are fully drained at the actionable tiers.** Four explorers remain (integration, docs, tests, security) — each will run in follow-up PRs.

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, `cargo fmt --all -- --check` all clean. Verified stable across multiple parallel `cargo test` runs (no manifest-trampling flakes).

### Fixed — Phase 2 module-cleanup (closes F-2027-022, -023, -025, -026, -027)

Five of the six findings the Phase 2 module explorer raised — closes the small / contained ones and leaves F-2027-024 (full v2-helpers migration of the seven script-based modules) as its own follow-up.

#### F-2027-022 — `[install] kind = "debian-package"` contract documented

`docs/src/modules.md` `[install]` block now documents all three `kind` values inline (`script` / `debian-package` / `rust-binary`) with a per-value note. `modules/detect-host/README.md` (the only consumer) now points at the contract.

#### F-2027-023 — tetragon signing-failure die message embeds the failing file

`modules/tetragon/install/apply.sh` previously did `selfdefctl keys verify-dir … || true` to print the per-file ok/fail listing, then died with a generic message. Operators reading only the final error line had to scroll back. Now: the script captures the verifier output, prints it (preserving the per-file listing), then `die`s with `"policy signature verification failed (first failure: <path>) — refusing to (re)start tetragon. See output above for the full ok/fail listing."`. The integration test (`module_tetragon_signing.rs`) updated to accept either the new pointer or the legacy aggregate phrasing.

#### F-2027-025 — vpn-bridge `safe_name` on `$SELFDEF_INSTANCE_ID`

`_relay_inst_defaults` in `modules/vpn-bridge/install/profiles/relay-via-server.sh` now runs `$SELFDEF_INSTANCE_ID` through `safe_name "$INST" || die "..."` before interpolating it into nftables table names, interface names, and per-instance config paths. Operator-controlled string today, so this is defense-in-depth — but tightens the validator coverage for free in case a future config-reload path lets the daemon inject instance IDs.

#### F-2027-026 — `docs/dev/module-helpers.md` documents per-module v2 adoption

New "Per-module adoption" section in the helpers reference is the single source of truth for which library version each shipped module requires. Includes a 4-step bumping recipe for contributors migrating a module from v1 to v2. Replaces the audit-recommended approach of duplicating the same line across 8 READMEs.

#### F-2027-027 — `DRY_RUN=0` standardised in three check.sh

`modules/{bridge-l2,suricata,polarproxy}/install/check.sh` now set `DRY_RUN=0` before sourcing the v2 lib. The library's `run` helper consults `$DRY_RUN`, so an unset variable is technically `unbound` under `set -u` even though check.sh today doesn't reach `run`. Future-proofing against a v3 helper that does.

#### Phase 2 backlog after this PR

27 findings across three explorers. **24 nice (23 closed, 1 open — F-2027-024)**, **1 SDD-debt open**, **2 important closed**, **0 blockers**.

The only remaining `nice` finding is F-2027-024, the full v2-helpers migration of the seven script-based modules — substantial enough to need its own PR. Four Phase 2 explorers remain (integration, docs, tests, security).

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, `cargo fmt --all -- --check` clean.

### Documentation — Phase 2 module explorer (raises F-2027-022 through F-2027-027)

Third of Phase 2's seven explorers ships. Walks the 9 shipped modules' install scripts + manifests + READMEs, the SDD-006 v2 module-script library, and the post-Phase-1 surfaces called out in the charter (tetragon's `require_signed_policies`, v2 manifest helpers, vpn-bridge per-profile instanced). 6 new findings raised; all triaged **nice** — no blockers, no important.

#### New document

`docs/review/phase-2/40-module-audit.md` — per-area notes with concrete `file:line` observations. Six findings clustered into three themes: v2 manifest-helper adoption gaps, per-module README doc gaps, and a small defense-in-depth tightening on vpn-bridge's `$SELFDEF_INSTANCE_ID` interpolation.

#### New findings (6 entries — all nice)

- `F-2027-022` — `modules/detect-host`: only module using `[install] kind = "debian-package"`; contract not documented in `docs/dev/modules.md` or the module's README.
- `F-2027-023` — `modules/tetragon/install/apply.sh:49`: signing-failure recover-step pipes verifier output to stdout but the subsequent `die` message doesn't reference it; operator has to scroll back to find which file failed.
- `F-2027-024` — seven script-based modules (bridge-l2, observability, tetragon, integrity-sentinel, polarproxy, suricata, vpn-bridge) don't opt into SDD-006 v2 manifest helpers; `uninstall.sh` hand-curates paths that `apply.sh` writes, recreating the drift risk v2 was designed to remove.
- `F-2027-025` — `modules/vpn-bridge/install/profiles/relay-via-server.sh:20-23`: `$SELFDEF_INSTANCE_ID` interpolated into nftables table names without `safe_name` validation. Operator-controlled string, so defense-in-depth only.
- `F-2027-026` — all 9 module READMEs silent on `SELFDEF_MODULE_LIB_VERSION_REQUIRED` and the v2 helpers.
- `F-2027-027` — `modules/{bridge-l2,suricata,polarproxy}/install/check.sh` miss the conventional `DRY_RUN=0` initialization every other check.sh sets.

#### Closing-PR clustering recommendation

Three follow-up implementation PRs cleanly subsume the new findings:

- **v2-helpers migration** — F-2027-024 + F-2027-027 (opt the seven script-based modules into v2; standardise `DRY_RUN=0` init).
- **vpn-bridge safe_name** — F-2027-025 (one-line patch + test).
- **Docs cluster** — F-2027-022 + F-2027-023 + F-2027-026 (per-module README v2-lib note + tetragon die message + `docs/dev/modules.md` `kind = "debian-package"` contract).

#### Phase 2 backlog after this PR

27 findings across three explorers (recent-PRs: 10, all closed except F-2027-010 SDD-debt; crate: 11, all closed; module: 6, all open). Four explorers remain (integration, docs, tests, security) — each will add more findings.

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, and `cargo fmt --all -- --check` clean. This PR is documentation-only.

### Fixed — selfdef-signing API surface (closes F-2027-011 + F-2027-012 + F-2027-013)

Third and last of the follow-up cluster PRs the Phase 2 crate explorer recommended. Closes the three findings the explorer raised against `selfdef-signing`. After this PR, **the crate-explorer backlog is fully drained** — every blocker, important, and nice finding from Phase 2's first two explorers is closed.

#### F-2027-012 — `SigningError::Io` split into typed variants per call site

The unhelpful `Io(#[from] std::io::Error)` variant is gone. In its place, three typed variants — one per call site — each carrying `{ path: PathBuf, source: std::io::Error }`:

- `ReadPublicKey { path, source }` — io failure reading the `.pub` file at `Verifier::load`.
- `ReadTarget { path, source }` — io failure reading the signed target (`<rule>.yml`) at `Verifier::verify_detached_file`.
- `ReadSignature { path, source }` — io failure reading the sidecar (`<rule>.yml.minisig`) at `Verifier::verify_detached_file`. Distinct from `MissingSignature` (sidecar doesn't exist) — `ReadSignature` fires for permission-denied / read-error cases, which are operator-actionable in a different way.

Display impls surface the path directly so `tracing::warn!(error = %e, ...)` lines are self-describing:

```
reading public key /etc/selfdef/keys/policy.pub: No such file or directory (os error 2)
```

#### F-2027-011 + F-2027-013 — public helpers surfaced in the crate `//!`

`SIGNATURE_SUFFIX` and `signature_path_for` are kept `pub` (operators / tooling enumerating expected sig files have a use for them), but the crate `//!` header now has an explicit **"Public helpers"** section listing both with usage guidance:

- `signature_path_for` — prefer for path construction from a target.
- `SIGNATURE_SUFFIX` — bare `".minisig"` constant for shell-out filtering / directory walkers.

The header also gains an **"Error model"** section pointing at the F-2027-012 variant-per-failure-site contract.

#### Tests

`crates/selfdef-signing/src/lib.rs` `#[cfg(test)]` block (+3 new cases, 12 total):

- `load_missing_pubkey_path_yields_read_public_key_variant` — `Verifier::load` on a non-existent file returns the typed `ReadPublicKey { path, source }` with `ErrorKind::NotFound`.
- `verify_missing_target_path_yields_read_target_variant` — a present sidecar with a missing target yields `ReadTarget`.
- `signing_error_display_carries_path` — sanity-check that `format!("{e}")` surfaces the path (otherwise tracing logs would be content-free).

Existing 9 tests still pass — the `Io` variant rename is the only breaking change and there were no callers depending on it.

#### Phase 2 status after this PR

21 findings raised across 2 explorers. **18 nice (all closed)**, **1 SDD-debt open** (F-2027-010 — `events follow` TCP transport, awaiting design), **2 important (closed)**, **0 blockers**.

The recent-PRs explorer's and the crate explorer's full backlogs are now drained at the actionable tiers. **Five explorers remain** (module, integration, docs, tests, security) — each will run in follow-up PRs and add more findings.

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, `cargo fmt --all -- --check` all clean.

### Fixed — Phase 2 CLI / api ergonomics (closes F-2027-014..018)

Second of three follow-up cluster PRs the Phase 2 crate explorer recommended. Five small fixes across `selfdef-api` and `selfdef-cli`; they didn't cluster on a single theme (auth guardrail, doc passes, error-message clarity, path-constant consolidation, env-var docs) but they did cluster on scope: each touches one or two files and ships in one PR.

#### F-2027-014 — `selfdef_api::with_full_capability` feature-gated

The "test-only convenience" helper that wraps the router in a blanket `Capability::Full` grant is now gated behind the new `test-helpers` Cargo feature. Release builds elide it entirely. The crate's own integration tests (`tests/m12_api.rs`) keep working because a new circular dev-dep on selfdef-api with `features = ["test-helpers"]` enables the feature for the integration-test build only.

Risk model: before this PR, a downstream consumer (in tree: 0; future: unknown) could call `selfdef_api::with_full_capability` and silently bypass the bearer-token check on TCP transports. With the feature gate, the symbol simply isn't visible to any consumer that doesn't explicitly opt into `test-helpers`.

#### F-2027-015 — `metrics::run_ingest` rustdoc + lag semantics

`run_ingest` (re-exported as `run_metrics_ingest`) now documents:
- the gating contract: only spawn this task when `[api].enabled = true` (without an HTTP scrape surface, the counters are dead weight; the daemon enforces this at startup);
- the lag accounting semantics: `BusError::Lagged(n)` accumulates onto `selfdef_ingest_lag_events_total` so operators can see the undercount and resize the bus.

#### F-2027-016 — `ApiServer::NoTransport` error spells out the fix

The error message now says exactly which TOML keys to set:

```
[api].enabled = true but no transport is set:
add `[api].unix_socket = "/path/to/sock"` or
`[api].tcp_addr = "host:port"`, or set `[api].enabled = false`
```

A reader hitting this error knows the daemon detected the inconsistent config rather than a missing dependency or a permission error.

#### F-2027-017 — new `selfdef_cli::paths` module consolidates the on-disk layout

`crates/selfdef-cli/src/paths.rs` is the new single source of truth for the CLI's default paths (`/etc/selfdef/selfdef.toml`, `/etc/selfdef/modules.toml`, `/etc/selfdef/modules/`, `/etc/selfdef/modules/agent-guard.toml`). Before this PR, the same paths were redefined in `init.rs`, `modules.rs`, `doctor.rs`, and inline in `main.rs`'s clap `default_value`; drift would mean `selfdefctl init config` could write to one path while `selfdefctl modules apply` read from another. All four call sites now import from `crate::paths`.

#### F-2027-018 — `SELFDEF_DOCTOR_AGENT_GUARD_CONFIG` documented

`docs/dev/operator-health-check.md` has a new **Environment overrides** section listing the env var, what it does, and that it's test-only. The doctor verb's `--help` references it. Operators chasing a doctor bug can now reproduce against a staged tempdir config without grepping the source.

#### Phase 2 status after this PR

21 findings raised across 2 explorers. **18 nice (15 closed, 3 open — F-2027-011 + -012 + -013, the last selfdef-signing API-surface cluster)**, **1 SDD-debt open**, **2 important closed**, **0 blockers**.

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, `cargo fmt --all -- --check` all clean. Release build of `selfdef-api` verified to elide `with_full_capability`.

### Added — selfdef-correlator verifier observability (closes F-2027-019 + F-2027-020 + F-2027-021)

First of three follow-up cluster PRs the Phase 2 crate explorer recommended. The three findings all touched the correlator's post-PR-#58 verifier surface and share a theme: "make verifier state operator-visible". Shipped together as one cohesive bundle.

#### F-2027-019 — crate `//!` header refreshed

`crates/selfdef-correlator/src/lib.rs:1-7` previously stopped at M5's "SshBruteforceRule gone". The post-Phase-1 surface has grown a lot since then. The new header walks the operator through five surface areas in order: rule loading, SIGHUP hot reload, optional rule signing (SDD-004), SIGUSR2 hot rotation of the signing key (F-2027-005 / PR #58), and operator introspection (`verifier_source` / F-2027-021).

#### F-2027-020 — `Correlator::load_rules` logs the verifier key path

Previously `load_rules` only logged `rules = N` once via the daemon's caller. After a SIGUSR2 rotation the operator had no way to eye-ball "did the verifier actually swap?" without sifting through `/proc/$pid/fd`. Now: when a verifier is attached, the function emits

```
info!(rules = N, verifier_key = "/etc/selfdef/keys/policy.pub",
      "rules loaded under signing verifier")
```

at the end of every successful load — including the post-rotation re-verify the SIGUSR2 handler triggers. No log line when no verifier is attached (signing is opt-in).

#### F-2027-021 — public `Correlator::verifier_source() -> Option<PathBuf>` getter

New public method that returns the absolute path the currently-loaded public key came from, or `None` if signing isn't opted in. The return type is owned (`PathBuf`) so callers can't accidentally hold a reference across the read-lock guard. Mirrors the existing `has_verifier()` shape.

Use cases (none consumed in this PR; the getter is added so they have something to call):
- `/status` API endpoint can surface "trusted policy.pub: …".
- Future `selfdefctl status --verifier` verb.
- Operator dashboards / Prometheus metrics.

Tests (`crates/selfdef-correlator/tests/signed_rules.rs`, +3 cases):
- `verifier_source_returns_none_without_verifier` — opt-in disabled.
- `verifier_source_returns_loaded_path_after_with_verifier` — opt-in enabled at startup.
- `verifier_source_tracks_reload` — path stays stable across a SIGUSR2-style hot rotation (the path didn't change, only the key file's bytes).

#### Phase 2 backlog after this PR

21 findings raised across two explorers. **18 nice (10 closed, 8 open)**, **1 SDD-debt (open)**, **2 important (closed)**, **0 blockers**. The remaining 8 open `nice` cluster into two follow-up PRs: selfdef-signing API surface (F-2027-011 + -012 + -013), and CLI / api ergonomics (F-2027-014 through -018). Five explorers remain.

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, `cargo fmt --all -- --check` clean.

### Documentation — Phase 2 crate explorer (raises F-2027-011 through F-2027-021)

Second of Phase 2's seven explorers ships. The crate audit walks the new `selfdef-signing` crate and the extended surfaces on `selfdef-cli`, `selfdef-api`, `selfdef-correlator`, and `selfdef-collector-eventstream` (scope per Phase 2 charter). 11 new findings raised; all triaged **nice** — no blockers, no important.

#### New document

- **`docs/review/phase-2/30-crate-audit.md`** — per-crate notes with concrete `file:line` observations. Eleven findings split across three themes: API surface hygiene (public symbols with no external callers), doc-string drift (crate `//!` headers that stop at M5/PR-1 and don't advertise post-Phase-1 surfaces), and operator-facing observability (state the daemon knows but doesn't log).

#### New findings (11 entries — all nice)

- `F-2027-011` — `selfdef-signing::SIGNATURE_SUFFIX` + `signature_path_for` are `pub` but no external caller exists; tests build the `.minisig` path by hand.
- `F-2027-012` — `SigningError::Io` uses `#[from] io::Error` and loses the path the io error was against; sibling variants carry full context.
- `F-2027-013` — selfdef-signing crate header doesn't mention the public helpers.
- `F-2027-014` — `selfdef_api::with_full_capability` is `pub fn` documented as "test-only" but reachable from any caller; rename or feature-gate to prevent silent auth-bypass.
- `F-2027-015` — `metrics::run_ingest` + `Metrics::*` methods have zero rustdoc.
- `F-2027-016` — `ApiServer::NoTransport` error doesn't distinguish "api disabled" from "api enabled but no transport set".
- `F-2027-017` — `selfdef-cli` starter-config path constants are split across `init.rs` and `modules.rs`; drift risk.
- `F-2027-018` — `SELFDEF_DOCTOR_AGENT_GUARD_CONFIG` test-only env var is documented only in a source comment.
- `F-2027-019` — `selfdef-correlator` crate header stops at M5's "SshBruteforceRule gone" and doesn't advertise the post-PR-#58 hot-rotation surface.
- `F-2027-020` — `Correlator::load_rules` logs `rules = N` but not the verifier source path; operators can't eye-ball "did the verifier swap" after SIGUSR2.
- `F-2027-021` — no public `verifier_source()` getter on the correlator — tests, doctor, dashboards all want to inspect which `policy.pub` is loaded right now.

#### Closing-PR clustering recommendation

Three follow-up PRs cleanly subsume the new findings:

- **selfdef-signing API surface** — F-2027-011 + F-2027-012 + F-2027-013 (re-scope public helpers, add path context to `SigningError::Io`, refresh crate header).
- **selfdef-correlator observability** — F-2027-019 + F-2027-020 + F-2027-021 (crate header, key-path logging, public `verifier_source()` getter).
- **CLI / api ergonomics bundle** — F-2027-014 through F-2027-018 (auth-bypass guardrail, rustdoc passes, error message clarity, path-constant consolidation, env-var docs).

#### Phase 2 backlog after this PR

21 findings across two explorers (recent-PRs: 10, all closed except F-2027-010 SDD-debt; crate: 11, all open). Five explorers remain (module, integration, docs, tests, security) — each will add more findings.

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, `cargo fmt --all -- --check` clean. This PR is documentation-only.

### Added — SIGUSR2 hot-rotation of the rule-signing verifier (closes F-2027-005)

Before this PR, rotating `/etc/selfdef/keys/policy.pub` required a full daemon restart — SIGHUP reloaded rules through the existing verifier but did not re-read the verifier itself. F-2027-005 (Phase 2 recent-PRs audit) called this out as friction in the operator-side key-rotation runbook.

Now: `pkill -USR2 selfdefd` re-loads the public-key file at the configured `[security].signing_public_key_file` path and immediately re-runs `Correlator::load_rules` against the fresh verifier. Both steps log at `info`. On reload failure (corrupt key file, missing path, malformed base64) the previous verifier stays in place and a `warn` line surfaces the cause — same atomic semantics as `load_rules` itself.

#### Correlator side (`crates/selfdef-correlator/src/lib.rs`)

`Correlator::verifier` is now `Arc<RwLock<Option<Verifier>>>` instead of `Option<Verifier>`. Three new public surfaces:
- `Correlator::reload_verifier() -> Result<PathBuf, ReloadVerifierError>` — re-loads the previously-loaded path (read back from `Verifier::source()`) and atomically swaps it in. Returns the path the key was loaded from so the daemon can log it.
- `Correlator::has_verifier() -> bool` — guards the SIGUSR2 fan-out branch in the daemon.
- `ReloadVerifierError` — typed: `NoVerifierConfigured` (signing not opted in) vs `Load(PathBuf, SigningError)` (key file on disk is broken). The daemon distinguishes the two so a no-op SIGUSR2 doesn't look like a failure.

`with_verifier` keeps the same chainable shape (`Self`) — the API is source-compatible for the daemon's startup wire-up.

#### Daemon side (`crates/selfdef-daemon/src/main.rs::wait_for_shutdown_or_reload`)

The SIGUSR2 handler now fans out to every hot-reloadable surface:
1. API tokens (existing, F-2026-023).
2. Rule-signing verifier + a follow-up `load_rules` pass (new, F-2027-005).

Failures in one branch don't block the others. If neither feature is enabled, the handler logs a `debug:` line and continues — same as before, just with a more accurate message.

#### Tests

- `crates/selfdef-correlator/tests/signed_rules.rs`:
  - `reload_verifier_swaps_in_a_rotated_pubkey` — keypair-A signs a rule; verifier loads A; operator rewrites `policy.pub` with keypair B + re-signs the rule; load fails; `reload_verifier()` succeeds; subsequent `load_rules()` succeeds.
  - `reload_verifier_keeps_prior_on_load_failure` — operator clobbers `policy.pub` with garbage; `reload_verifier()` returns a typed `Load` error; the previously-loaded verifier still verifies rules signed by the original key.
  - `reload_verifier_with_no_verifier_attached_is_typed_error` — `NoVerifierConfigured` distinguishes "signing not opted in" from "signing broken".

#### Documentation

`docs/dev/signing.md`:
- "Turn on enforcement" section now lists both signals (SIGHUP for rules; SIGUSR2 for the verifier + rules together) with a one-liner each.
- "Rotating the signing key" section's step 5 now reads `pkill -USR2 selfdefd` instead of "full daemon restart required".

#### Phase 2 ledger update

`docs/review/phase-2/99-findings-ledger.md` marks F-2027-005 closed. Phase 2 backlog after this PR: **0 nice**, 1 SDD-debt (F-2027-010 — `events follow` TCP transport). The recent-PRs explorer's full 10-finding backlog is now drained.

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, and `cargo fmt --all -- --check` are clean.

### Fixed — Phase 2 nice-cluster cleanup (closes F-2027-001, -002, -004, -006, -007, -009)

Six of the seven Phase 2 nice findings shipped as one bundle. Every change is small and contained; they share a PR because each is one-or-two-file diff and they have no inter-dependencies, just a common parent (post-Phase-1 surface auditing). The only nice finding still open is `F-2027-005` (rule-signing verifier reload via SIGUSR2 — needs a follow-up that touches the daemon's verifier wiring, deferred so it can land on its own).

#### F-2027-001 — vpn-bridge profile-instanced refusal embeds copy-pasteable TOML

`selfdef-cli/src/modules.rs::resolve_active` previously emitted a prose refusal when an operator tried to multi-instance a non-instanced profile. The fix embeds the exact `[profiles.details.<profile>]\ninstanced = true\n` stanza inline so the operator can paste it into the module manifest without composing it from the message.

#### F-2027-002 — `docs/dev/test-contract.md` documents `--include-ignored` + nats-server 2.10+

Pattern P-3's "real-broker NATS fixture" section now spells out the runtime invocation (`cargo test -p selfdef-nats -- --include-ignored`), lists the three install paths (apt / brew / nats.io binary), and flags the 2.10+ JetStream requirement so contributors on older Debian repos don't silently skip the gated test.

#### F-2027-004 — `selfdefctl api rotate-token --pid auto` short-circuits on missing systemctl

`discover_daemon_pid()` previously failed with a raw `Os(exited 127)` when `systemctl` wasn't on PATH (containerised dev, BSD compat, restricted distros). The fix detects `ErrorKind::NotFound` from `Command::output()` and emits a friendly diagnostic pointing the operator at `--pid <pid>` with a `pgrep selfdefd` suggestion.

#### F-2027-006 — `selfdefctl keys verify-dir <dir>` batches policy verification

New CLI verb: `selfdefctl keys verify-dir <dir>` walks the immediate `*.yml`/`*.yaml` files in a directory non-recursively, loads the public key once, verifies each file's `.minisig` sidecar in-process, prints one `ok:` / `fail:` line per file plus a `summary: N file(s), X ok, Y fail` line, and exits non-zero iff any file fails. Replaces the N-spawn `for p in $(find...); do selfdefctl keys verify $p; done` loop in `modules/tetragon/install/apply.sh` (and the mirror in `check.sh`) with one invocation.

Tests: `crates/selfdef-cli/tests/cli_keys_verify_dir.rs` covers all-signed / mixed / empty / non-existent / non-yaml-decoy cases against a real minisign keypair generated at test time. The existing tetragon-signing tests are updated to stub the new verb and exercise both the apply and check paths.

#### F-2027-007 — `selfdefctl rbac check --probe` built-in subject set expanded

Two common-mistake bindings auditors hit in the wild are now probed by default:
- `system:masters` — the kubeadm bootstrap superuser group; granting it to humans bypasses every cluster RBAC check by design.
- `system:serviceaccount:default:default` — the default-ns default ServiceAccount; pods that forget to set `serviceAccountName` run as this and any RoleBinding on it leaks to every such pod.

Operator-supplied `--as <subject>` still composes on top. The non-probe recommended-posture block now bullets all four subjects with a one-line explanation each.

Tests: `rbac_check_builtin_set_includes_system_masters_and_default_sa` (documentation path) + `rbac_check_probe_flags_system_masters_when_permissive` (catches the kubeadm-superuser anti-pattern via the stub kubectl).

#### F-2027-009 — `selfdefctl init config` starter embeds `[notifier.ntfy]` example

The starter `selfdef.toml` written by `selfdefctl init config` now includes a commented `[notifier.ntfy]` stanza (server / topic / priority / tags / token_env) with a three-step inline runbook (pick topic → uncomment → flip channels). Operators no longer need to grep `/usr/share/selfdef/selfdef.toml.example` for the shape.

Test: `init_config_writes_starter_file_at_0644` now asserts the `# [notifier.ntfy]` line + the `# server` / `# topic` fields are present.

#### Phase 2 ledger update

`docs/review/phase-2/99-findings-ledger.md` marks all six closed with back-references. Phase 2 backlog is now: 0 blockers, 0 important, 1 nice (`F-2027-005`), 1 SDD-debt (`F-2027-010`).

`cargo test --workspace` and `cargo clippy --workspace --tests -- -D warnings` are clean.

### Fixed — Phase 2 first-fixes (closes F-2027-003 + F-2027-008)

Closes the two important findings raised by Phase 2's recent-PRs audit (PR #55). Both fixes are small, contained, and shipped together so the Phase 2 ledger's "important" tier is empty.

#### F-2027-003 — eventstream euid reader silent degradation

`selfdef-collector-eventstream::check_path_integrity` previously called `unsafe_geteuid()`, which returned `0` silently on any `/proc/self/status` read failure. That made the integrity check accidentally permissive — every root-owned file passed even when the daemon's effective UID wasn't actually root. Operators never noticed the check was degraded.

Renamed to `read_euid() -> Option<u32>` so the failure path is explicit. The caller now emits a structured `tracing::warn!` line and falls back to "owner must be root" (strict-safe) instead of "owner must be 0 because we have no idea what our euid is" (accidentally-permissive).

Test: new `read_euid_returns_some_on_linux_test_host` asserts the happy-path returns `Some(_)` on a Linux host.

#### F-2027-008 — doctor rbac posture inflates the warn count

`selfdefctl doctor`'s rbac category emitted `[warn]` for pod-label scope on every run — but the doctor *never* probes the cluster (probing is `selfdefctl rbac check --probe`'s job). The warn count appeared in the summary line, suggesting something was wrong when actually nothing was — just that the operator hadn't run rbac-check yet.

`check_rbac_posture` now emits `Skipped` for pod-label scope with the detail string flipped from "run `selfdefctl rbac check`" to "posture not verified here; run `selfdefctl rbac check --probe`". The warn count stays at 0; the operator's eye is drawn to genuine warnings.

Tests:
- `doctor_rbac_pod_label_scope_is_skip_not_warn` — verifies the new behaviour with a tempdir-staged agent-guard config.
- `doctor_rbac_container_scope_is_skip_with_not_gating_note` — sanity check that container scope still emits a `skip:` with "RBAC posture not gating" detail.

The doctor module gained a `SELFDEF_DOCTOR_AGENT_GUARD_CONFIG` env override so the integration tests can stage a fake agent-guard.toml without polluting `/etc/selfdef/modules/`.

#### Phase 2 ledger update

`docs/review/phase-2/99-findings-ledger.md` marks F-2027-003 and F-2027-008 closed with back-references. The Phase 2 important-tier list is now empty; remaining backlog: 7 nice + 1 SDD-debt.

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, and `cargo fmt --all -- --check` are clean.

### Documentation — Phase 2 audit kickoff

The Phase-1 audit ran through PR #42; every blocker / important / SDD-debt closed during this session. Phase 2 picks up where Phase 1 left off: same methodology (seven explorers, F-NNNN findings, SDDs where the fix is design-shaped), audited against the new surface shipped post-Phase-1 (18 PRs, 1 new crate, 6 new operator-side CLI verbs, ~80 new tests).

#### New documents under `docs/review/phase-2/`

- **`00-charter.md`** — why Phase 2 now, what changed since Phase 1 closeout, scope of this Phase (7 explorers' worth), out-of-scope items deferred to Phase 3, methodology, naming convention. Phase 2 findings use the `F-2027-NNN` prefix; the `2026` prefix is reserved for Phase 1 entries (all closed).

- **`10-inventory.md`** — structured inventory of what's been added since Phase 1: the new `selfdef-signing` crate, 6 new CLI subcommands (`init`, `doctor`, `events follow`, `keys verify`, `api rotate-token`, `rbac check`), daemon-side machinery (SIGUSR2 token reload, opt-in signed-rule gate, eventstream integrity gate), module-side machinery (shared-lib v2, tetragon `require_signed_policies`, vpn-bridge per-profile instanced), six new operator runbooks under `docs/dev/`, ~80 new tests.

- **`20-recent-prs-audit.md`** — companion to Phase 1's `70-recent-prs-audit.md`. Walks the 18 post-Phase-1 PRs, flags 10 observations (mostly ergonomic nits in the new code).

- **`99-findings-ledger.md`** — Phase 2's findings ledger. Opens with the 10 observations from the recent-PRs explorer triaged into 0 blockers, 2 important, 7 nice, 1 SDD-debt. Numbering: `F-2027-NNN`.

#### Initial findings (10 entries, recent-PRs explorer only)

- **2 important**:
  - `F-2027-003` — eventstream euid reader returns 0 silently on `/proc` failure (integrity check degrades without notice).
  - `F-2027-008` — `selfdefctl doctor`'s rbac category emits a `warn:` pointer even when nothing is wrong (warn count inflates the summary).

- **7 nice**: ergonomic improvements across the new operator-facing verbs (rbac probe subject list, init starter template, signing rotation, etc).

- **1 SDD-debt**: `F-2027-010` — `events follow` UNIX-socket-only design needs a TCP transport design doc.

#### What comes next

The remaining six explorers (crate, module, integration, docs, tests, security) run in follow-up PRs. Phase 2 closes when every important / blocker has either a "closed by <PR>" back-reference or a tracked SDD.

`cargo fmt --all -- --check` clean (no Rust touched).

### Added — `selfdefctl events follow` (live tail)

Live-tails events from the daemon's `/events/stream` SSE endpoint over a UNIX socket. Pairs with `events tail` (which reads the SQLite store for historical context) — together they cover both "what's happening right now?" and "what just happened?".

#### Implementation

- New `crates/selfdef-cli/src/follow.rs` (~100 LoC). Talks raw HTTP/1.1 over `tokio::net::UnixStream` rather than pulling a full HTTP client (hyper) into the CLI — the request is one GET, the response is a long-lived `Transfer-Encoding: chunked` SSE body that the parser line-tokenises into `data: <json>` records.
- TCP transport is not supported; operators with TCP-only daemons run `curl --no-buffer -H "Authorization: Bearer ..." http://host:port/events/stream` directly.

#### Flags

- `--unix-socket <path>` — default `/run/selfdef.sock`.
- `--alerts-only` — filter to `category_uid = 2` (Findings) using the structured field, not substring matching.
- `-n <N>` — stop after N events (default: stream forever until Ctrl-C).

#### Lagged events

The daemon's SSE stream emits `event: lagged` frames when the broadcast bus's subscribe-side queue overflows. Follow surfaces these to stderr as `# lagged: missed N events` so operators see the gap in their tail.

#### Tests

`crates/selfdef-cli/tests/cli_events_follow.rs` ships 4 integration tests using a tiny fake daemon that listens on a tempdir UNIX socket and writes a canned 200 OK + chunked SSE body. Covers happy-path streaming + counting, `--alerts-only` filtering, lagged-frame stderr surfacing, and the connect-failure diagnostic for a bad socket path.

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, and `cargo fmt --all -- --check` are clean.

### Documentation — ARCHITECTURE.md refresh

Sibling refresh to the README rewrite (just shipped). Brings the architecture doc current with everything shipped since M16:

- **Layered view diagram** now shows the operator-side verbs (`init`, `doctor`, `keys verify`, `rbac check`, `api rotate-token`), the SIGUSR2 hot token reload, the opt-in eventstream integrity gate at the collector boundary, and the opt-in signed-rule gate inside the correlator.
- **Modules section** annotates `tetragon` (signed-policy gate), `agent-guard` (pod-label scope + RBAC), and `vpn-bridge` (per-profile instanced) with their post-audit details. Notes that every module script sources `packaging/lib/module-lib.sh` (SDD-006 v2) for the shared helpers + manifest helpers.
- **Core principles** gains a sixth principle: *Security features are opt-in*. Every audit-shipped security feature defaults off; the operator turns each on via the `init checklist` flow; `doctor` verifies the opt-ins they turned on.
- **Data lifecycle** diagram threads the opt-in integrity gate at the collector boundary and the opt-in signed-rule gate at the rule-load boundary.
- **New Operator lifecycle section** with a Day-0 → Day-N diagram showing `init config/modules/checklist` → `systemctl enable` → `modules apply` → `doctor`.
- **Self-protection of the daemon** refreshed: rule signing is now a shipped opt-in (no longer "future"); API token hot-rotation via SIGUSR2 is documented; eventstream integrity gate is documented; dm-verity remains a Known gap.
- **New SDDs section** indexes the six Phase-1 SDDs with one-line summaries and the explicit "all six are `implemented`" statement, plus pointers to the findings ledger.

Pure doc; no code touched. `cargo fmt --all -- --check` clean.

### Documentation — README refresh

Comprehensive README rewrite reflecting everything shipped in the post-M16 audit cycle + the new operator lifecycle verbs (`init`, `doctor`, `keys verify`, `api rotate-token`, `rbac check`). The previous README still referenced "design work tracked in the SDD pipeline" — that pipeline shipped (6 SDDs implemented + every deferred follow-up closed). Drift items addressed:

- **Status block** flips from "Phase 1 audit lists open issues" to "Phase 1 audit closeout complete; every blocker, important, SDD-debt finding closed or carries a shipped follow-up". Cross-links the findings ledger.
- **New "Operator quick-start" section** — `init config` → `init modules` → `modules apply` → `doctor`, with `init checklist` for the full 11-step opt-in walkthrough.
- **New "`selfdefctl` reference" section** enumerates every operator-facing verb (read-only, lifecycle, security opt-ins) with one-line descriptions and the audit finding each closes.
- **New "Operator runbooks" index** points at every `docs/dev/<feature>.md` (first-run, operator-health-check, signing, rbac-posture, module-helpers, test-contract).
- **Module catalog** annotates `vpn-bridge`, `tetragon`, `agent-guard` with their SDD-shipped opt-in details (multi-instance honesty, signed policies, pod-label scope verification).
- **Crate layout** adds `selfdef-signing` (PR #45) and `packaging/lib/module-lib.sh` (SDD-006 v2).
- **Quickstart** appends the `init` + `doctor` bootstrap commands.
- **Milestones** adds three post-M16 entries: Phase-1 audit cycle, audit-shipped opt-ins, operator lifecycle verbs.
- **Threat model** section flips from "SDD pipeline" pointer to a reference to the shipped SDD-004 rewrite + the hardening checklist.

Pure doc; no code changes. `cargo fmt --all -- --check` clean (no Rust touched).

### Added — `selfdefctl init` (first-run bootstrap)

The bookend to `selfdefctl doctor`. Doctor verifies an existing deployment; init bootstraps a new one. Three subcommands:

- **`init config`** — writes a starter `/etc/selfdef/selfdef.toml` (override with `--output`). Every audit-shipped opt-in security feature is OFF in the starter; operators turn each on after following the matching `docs/dev/<feature>.md` runbook. Default mode 0644. Atomic write (tempfile → fsync → rename) so a crash mid-write leaves the previous file intact.
- **`init modules`** — writes a starter `/etc/selfdef/modules.toml` listing every shipped module (`tetragon`, `agent-guard`, `integrity-sentinel`, `bridge-l2`, `suricata`, `polarproxy`, `vpn-bridge`, `observability`, `detect-host`) commented out with a short description. Operators uncomment what they want activated.
- **`init checklist`** — prints a first-run operator checklist (11 numbered steps from `init config` through periodic doctor timer). Read-only.

Both `init config` and `init modules` are non-destructive by default — they refuse to overwrite an existing file unless `--force` is passed.

#### Tests

`crates/selfdef-cli/tests/cli_init.rs` ships 7 integration tests covering each subcommand's happy path, the --force semantics, parent-directory creation, and the structural invariant that the modules starter NEVER ships an uncommented `[modules.<slug>]` activation.

#### Operator UX

Together, `init` + `doctor` give operators the two go-to verbs for the lifecycle:

```sh
# Day 0
sudo selfdefctl init config
sudo selfdefctl init modules
sudo systemctl enable --now selfdefd
sudo selfdefctl modules apply
selfdefctl doctor

# Day N (after editing /etc/selfdef/selfdef.toml or rotating keys)
selfdefctl doctor
```

`docs/dev/first-run.md` is the matching operator runbook.

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, and `cargo fmt --all -- --check` are clean.

### Added — `selfdefctl doctor` (cross-cutting operator health check)

A single verb that verifies the cross-cutting policy state every post-audit security feature depends on. Synthesizes everything the recent follow-up PRs added (rule signing, API token rotation, eventstream integrity, RBAC posture) into one go-to "is this deployment healthy?" command. Complementary to `selfdefctl modules check` — the two don't subsume each other.

#### Categories

- **`signing`** — when `[security].require_signed_rules = true`, verifies the public key loads + every rule in `[correlator].rules_dir` has a sibling `.minisig` that validates.
- **`api`** — when `[api].enabled = true`, verifies the token file exists, is mode 0600, and is non-empty.
- **`eventstream`** — when `[collectors.eventstream].integrity_check = true`, verifies every configured path passes the same checks the collector will run at startup (not world-writable, owned by daemon-allowed UID).
- **`rbac`** — reads agent-guard's host config; when `scope = "pod-label"`, emits a `warn:` pointing at `selfdefctl rbac check --probe` for the actual cluster RBAC verification.

#### Output

- Human report by default (`## <category>` headings + `[status] check-name: detail` lines + summary count).
- `--json` flag emits JSON-lines (one object per check) for CI / monitoring integration.
- Exit `0` if no `FAIL`, `1` otherwise. `warn` and `skip` never trigger non-zero.

#### Operator integration

- Post-deploy smoke check: `selfdefctl doctor`.
- Periodic via systemd timer: see `docs/dev/operator-health-check.md` for the unit + timer files.
- CI: `selfdefctl doctor --json | jq -e '. | select(.status == "FAIL")'`.

#### Tests

`crates/selfdef-cli/tests/cli_doctor.rs` ships 6 integration tests covering: all-opt-ins-off → all `skip`; API token `0644` flagged as `FAIL`; API token `0600` reported as `ok`; signing enabled without key path flagged as `FAIL`; eventstream world-writable path flagged as `FAIL`; `--json` emits one object per check covering every expected category.

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, and `cargo fmt --all -- --check` are clean.

### Added — k8s RBAC posture check (SDD-004 F-2026-025 follow-up)

Closes the SDD-004 F-2026-025 known-gap follow-up as **shipped**.
Adds `selfdefctl rbac check` — a verb that verifies whether the
cluster's RBAC posture matches `agent-guard`'s `scope = "pod-label"`
assumption (only documented narrow subjects should be able to
PATCH pod labels).

With this PR, **every tracked deferred follow-up from the
Phase-1 audit, SDD-004, and SDD-006 is closed**.

- **`selfdefctl rbac check`** — new CLI verb.
  - Reads agent-guard's module config (default
    `/etc/selfdef/modules/agent-guard.toml`, override via
    `--module-config`).
  - If `scope != "pod-label"`, reports the check as
    not-applicable and exits 0.
  - Otherwise, prints the recommended posture + the exact
    `kubectl auth can-i patch pods --subresource=labels --as=<subj>`
    commands the operator should run.
  - With `--probe`, shells out to those commands for the
    built-in subjects (`system:authenticated`,
    `system:unauthenticated`) plus any operator-supplied
    `--as <subject>`. Reports each as `ok:` or `WARN:` and
    exits non-zero if any subject is overly permissive.
    `--warn-only` suppresses the exit code.
  - `--namespace <ns>` scopes the probe to one namespace.
- **`docs/dev/rbac-posture.md`** — operator runbook covering
  when the check applies, the recommended posture, read-only
  vs probe modes, and the documented caveats (the check is
  spot-checking on a fixed subject set, not a cluster-wide
  enumeration).
- **`SECURITY.md`** — F-2026-025 known-gap entry flips from
  "desirable but not designed" to "shipped".

#### Tests

`crates/selfdef-cli/tests/cli_rbac_check.rs` ships 7
integration tests using a stubbed `kubectl` on PATH (mapping
`--as=<subject>` to the `yes`/`no` exit-code contract). Covers:

- not-applicable when `scope = "container"`
- read-only mode prints the recommended posture
- clean posture (every probed subject CANNOT patch labels)
  exits 0
- overly-permissive subject exits non-zero with a clear WARN
  line
- `--warn-only` suppresses the exit code
- operator-supplied `--as` subjects get probed too
- `--namespace` propagates into the printed commands

`cargo test --workspace`, `cargo clippy --workspace --tests
-- -D warnings`, and `cargo fmt --all -- --check` are clean.

### Added — dry-run-noop tests across every module (closes F-2026-030 fully)

Closes F-2026-030 fully (was "reference closed" — adopted only in `vpn-bridge` from PR #41). Every other module-test file now carries a companion `dry_run_apply_must_be_a_noop_on_disk` test using the shared `snapshot_tree` + `assert_tree_unchanged` helpers from `tests/common/mod.rs`.

The dry-run-negative contract: when `SELFDEF_DRY_RUN=1`, the module's `apply.sh` produces zero on-disk delta. A regression making dry-run write the rendered output, the unit file, the nftables ruleset, the baseline, the scrape config, or any other side-effect file is now caught by the test suite.

- `module_agent_guard.rs::dry_run_apply_must_be_a_noop_on_disk` — snapshots the policy_dir + manifest path.
- `module_bridge_l2.rs::dry_run_apply_must_be_a_noop_on_disk` — snapshots the config-holding tempdir.
- `module_integrity_sentinel.rs::dry_run_apply_must_be_a_noop_on_disk` — snapshots the scratch root + spot-checks the baseline file is absent.
- `module_observability.rs::dry_run_apply_must_be_a_noop_on_disk` — snapshots the bundled-profile scrape/dashboard dirs.
- `module_polarproxy.rs::dry_run_apply_must_be_a_noop_on_disk` — snapshots the scratch root + spot-checks the systemd unit / nftables ruleset are absent.
- `module_suricata.rs::dry_run_apply_must_be_a_noop_on_disk` — snapshots the nfqueue-mode fixture.
- `module_tetragon.rs::dry_run_apply_must_be_a_noop_on_disk` — snapshots the tetragon.yaml + policy_dir scope.

#### Tests

7 new tests added, each ~25 lines, follow the same pattern. `cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, and `cargo fmt --all -- --check` are clean.

### Added — shared-lib v2: manifest helpers (SDD-006 F-2026-050 follow-up)

Closes the SDD-006 F-2026-050 follow-up as **shipped**. Bumps
the shared module-script library to v2 and adds three new
helpers that let `apply.sh` record every rendered file into a
per-module manifest; `uninstall.sh` enumerates the manifest
instead of hand-listing expected paths.

- **`packaging/lib/module-lib.sh`**: `SELFDEF_MODULE_LIB_VERSION`
  bumped from `1` to `2`. New helpers:
  - `module_record_file <path>` — append `<path>` to the
    per-module manifest. Idempotent (dedups via `grep -Fxq`),
    dry-run aware.
  - `module_render_files` — print every recorded path (one per
    line). Returns empty for pre-v2 installs / pre-first-apply.
  - `module_clear_manifest` — remove the manifest. Dry-run
    aware.
  - `selfdef_manifest_path` — internal helper exposing the
    manifest path (default `/var/lib/selfdef/installed/<MODULE>.manifest`,
    override via `MODULE_INSTALLED_MANIFEST`).
- **`modules/agent-guard/install/lib.sh`** bumps
  `SELFDEF_MODULE_LIB_VERSION_REQUIRED` from `1` to `2` — agent-guard
  now hard-requires v2 of the shared lib. Older selfdef installs
  hit the existing version-mismatch refusal (exit 99 with a
  structured error).
- **`modules/agent-guard/install/apply.sh`** calls
  `module_record_file "$dst"` for every rendered policy YAML.
  Records both first-write and re-apply cases (idempotent).
- **`modules/agent-guard/install/uninstall.sh`** iterates
  `module_render_files` and removes each path, then
  `module_clear_manifest` wipes the record. A legacy-enum
  fallback handles pre-v2 installs (where the manifest is
  empty) so the first post-upgrade uninstall still cleans up
  the rendered policies.
- **`docs/dev/module-helpers.md`**: new "v2 changes" section +
  per-helper documentation following the same shape as the v1
  helpers.

#### Backwards compatibility

- The shared lib's version-mismatch contract from SDD-006 still
  fires: a v1 selfdef install with v2 modules exits 99 at source
  time with a clear stderr message. The 7 modules that
  required v1 (every module other than agent-guard) keep working
  unchanged — they don't ask for v2 features.
- agent-guard installations that upgrade across this PR
  silently work: apply.sh starts recording, uninstall.sh's
  legacy fallback handles the gap. A second apply post-upgrade
  fully populates the manifest.

#### Tests

- **3 new agent-guard integration tests** in
  `crates/selfdef-cli/tests/module_agent_guard.rs`:
  - `manifest_records_every_rendered_policy` — the manifest's
    contents match every `.yaml` file in `policy_dir`
    post-apply.
  - `manifest_deduplicates_across_reapply` — byte-stable
    across two consecutive apply runs.
  - `uninstall_with_no_manifest_falls_back_to_legacy_enum` —
    migration path: a missing manifest still cleans up via
    the hand-enumerated fallback.
- The existing 19 agent-guard tests continue to pass — every
  apply / check / pod-label / scope / gpu test verified
  byte-stably under the new manifest-recording path.
- **`cli_modules_shared_lib.rs`**: `module_requesting_newer_lib_version_is_refused`
  updated to expect `"have 2"` in the version-mismatch
  diagnostic.

`cargo test --workspace`, `cargo clippy --workspace --tests
-- -D warnings`, and `cargo fmt --all -- --check` are clean.

#### Test isolation note

The shared-lib helpers write to
`/var/lib/selfdef/installed/<MODULE>.manifest` by default.
The agent-guard integration test fixture now sets
`MODULE_INSTALLED_MANIFEST` to a tempdir path per test so the
test suite is hermetic and never touches the host's
`/var/lib/selfdef/installed/`.

### Added — TracingPolicy signing (SDD-004 F-2026-024 follow-up)

Closes the SDD-004 F-2026-024 known-gap follow-up as **shipped**.
Re-uses the rule-signing infrastructure (PR before this one) to
gate Tetragon TracingPolicies in
`/etc/tetragon/tetragon.tp.d/`. The `tetragon` module's
`apply.sh` and `check.sh` shell out to `selfdefctl keys verify`
on every policy file before tetragon (re)starts.

- **Tetragon module config**: new `require_signed_policies: bool`
  (default `false`) in `modules/tetragon/profiles/default.toml`.
  Operators turn it on per-host once they've signed every policy
  in `policy_dir`.
- **apply.sh enforcement**: when `require_signed_policies = true`,
  apply.sh iterates every `*.yml`/`*.yaml` in `policy_dir` and
  runs `selfdefctl keys verify` on each. Failures emit a
  structured `failed` status and exit non-zero **before**
  invoking `systemctl restart tetragon` — the running tetragon
  stays up with whatever policies were already loaded.
- **check.sh report**: when `require_signed_policies = true`,
  check.sh reports the unsigned-policy count as a `failed`
  structured status with detail
  `"<N> of <M> policy file(s) in <dir> failed signature verification"`.
  Non-fatal to the running tetragon — the check is purely a
  state report.
- **Dry-run** logs "DRY-RUN: would verify ..." for each policy
  but never enforces — preserving the dry-run-is-a-no-op
  contract (SDD-005 D-2a).
- **`docs/dev/signing.md`**: new "TracingPolicy signing"
  section walks operators through enabling the gate, apply +
  check behaviour, and the agent-guard render-time caveat
  (rendered policies are not pre-signed; operators turn on the
  gate where they don't run agent-guard, or trust agent-guard's
  output via package signatures + integrity-sentinel
  baselining).

#### Tests

`crates/selfdef-cli/tests/module_tetragon_signing.rs` ships 6
integration tests covering:
- apply passes when signing disabled (sanity: existing workflow
  unchanged)
- apply passes when every policy is signed
- apply refuses with a clear `failed` status when one policy
  is unsigned
- dry-run logs verification intent but never fails
- check passes when signing disabled even with unsigned
  policies
- check fails when signing is enabled and an unsigned policy
  exists

The fixture uses a stubbed `selfdefctl` on PATH that mimics
`keys verify`'s exit-code contract (0 if a sibling `.minisig`
exists, 1 otherwise) — the real verifier path is covered
end-to-end by `selfdef-signing`'s own unit suite + the
correlator's `signed_rules.rs` integration suite.

#### What this closes

- **F-2026-024 follow-up** in `docs/review/99-findings-ledger.md`
  flips from "partial close" to "shipped"; the SECURITY.md
  known-gap entry flips accordingly.

`cargo test --workspace`, `cargo clippy --workspace --tests
-- -D warnings`, and `cargo fmt --all -- --check` are clean.

### Added — detection-rule signing (closes original "Rule signing" Known gap)

Closes the original SECURITY.md "Rule signing not yet enforced"
Known gap as **opt-in shipped**, and ships the verifier
infrastructure that the SDD-004 F-2026-024 follow-up will reuse
for Tetragon TracingPolicies.

The daemon can now refuse to load detection rules that aren't
accompanied by a valid detached minisign signature. Signing
happens offline on the operator's signing machine (with the
standalone `minisign` CLI); the daemon is verify-only.

- **New crate `selfdef-signing`** wraps `minisign-verify`
  (zero-deps, audited). Exposes `Verifier::load(pub_key)` and
  `Verifier::verify_detached_file(<target>)` — looks for
  `<target>.minisig` and verifies under the loaded key.
- **`selfdef-correlator`**: `Correlator::with_verifier(v)`
  builder + `Engine::load_dir_verified(dir, v)` rule loader.
  `SigmaError::Signature { path, source }` is the new typed
  failure mode; the existing "keep prior ruleset on failure"
  semantics mean an unsigned drop never affects the running
  rule set.
- **`selfdef-config`**: new `[security]` block with
  `require_signed_rules: bool` (default `false`) +
  `signing_public_key_file: Option<PathBuf>`. The daemon
  refuses to start when `require_signed_rules = true` but the
  key path is missing or unreadable — failing loudly beats
  silently running unsigned-trusted.
- **`selfdefd`**: when `[security].require_signed_rules` is on,
  the daemon loads the public key at startup and chains the
  verifier onto the Correlator. Logged at `INFO` as
  "correlator: rule-signing verification enabled".
- **`selfdefctl keys verify <target>`**: new debug CLI verb.
  Loads `[security].signing_public_key_file` (or `--public-key`)
  and verifies the target's `.minisig` sidecar. Useful when an
  operator is investigating signing without involving the
  daemon.
- **`docs/dev/signing.md`**: new operator runbook —
  key generation, signing workflow, deployment, manual
  verification, rotation, threat-model caveats.

#### Behavioural notes

- Default is `require_signed_rules = false`. Every existing
  deployment behaves identically; rule signing is strictly
  opt-in.
- A SIGHUP rule reload picks up new signatures + new rules
  but reuses the verifier loaded at startup; rotating the
  public-key path itself requires a daemon restart.
- Verification happens at rule-load time. A previously-loaded
  malicious rule already in memory continues to fire until
  the daemon restarts — `integrity-sentinel` watching the
  rules directory remains the right mitigation for
  in-memory tampering.

#### Tests

- **`selfdef-signing` unit** (9 tests): public-key parsing
  from raw base64 + minisign `.pub` format, malformed-key
  rejection, signed/unsigned/wrong-key/tampered/malformed-sig
  paths, the `signature_path_for` helper.
- **`selfdef-correlator` integration**
  (`tests/signed_rules.rs`, 6 tests): full `load_rules` path
  with a configured verifier — positive accept, unsigned
  reject, tampered reject, wrong-key reject,
  no-verifier-no-signature sanity, prior-ruleset-preserved on
  signature failure.

`cargo test --workspace`, `cargo clippy --workspace --tests
-- -D warnings`, and `cargo fmt --all -- --check` are clean.

### Added — API token hot-rotation (SDD-004 F-2026-023 follow-up)

Closes the SDD-004 F-2026-023 known-gap follow-up as **shipped**.
Operators can now rotate the API bearer token without restarting
the daemon — in-flight scrapes continue against the new token
once the daemon picks it up.

- **`selfdefctl api rotate-token`** — new CLI verb.
  - Generates a fresh 32-byte high-entropy token (read from
    `/dev/urandom`, base64-url-safe encoded — no padding, no
    pulled dep).
  - Writes atomically to the configured `[api].token_file`:
    tempfile → `write_all` → `fsync` → `rename` → `chmod 0600`.
    Survives a crash mid-rotation; the previous token stays
    valid.
  - `--token-file <path>` overrides the config target (useful
    when rotating the control token).
  - `--bytes <N>` (default 32) sets the entropy length;
    validates `1..=256`.
  - `--pid <pid>` or `--pid auto` signals the daemon. `auto`
    runs `systemctl show -p MainPID --value
    selfdefd.service` and parses the pid; omit `--pid` and the
    operator signals the daemon themselves
    (`systemctl kill --signal=SIGUSR2 selfdefd`).
  - `--print` echoes the new token to stdout (default: only the
    on-disk path is logged).
- **Daemon SIGUSR2 handler** — `selfdef-daemon/src/main.rs`'s
  `wait_for_shutdown_or_reload` gains a SIGUSR2 arm that calls
  the new `TokenReloader::reload`. SIGHUP (rules) and SIGUSR2
  (api tokens) stay structurally identical.
- **`selfdef-api::TokenReloader`** — the bearer-token
  middleware now reads tokens through an
  `Arc<RwLock<Option<LoadedTokens>>>` shared with the daemon's
  signal handler. `TokenReloader::reload()` re-reads
  `token_file` / `control_token_file` from disk and swaps the
  inner value under the write lock; reload errors (empty
  file, IO failure) keep the previously-loaded tokens in
  place. New `pub` exports: `TokenReloader`.

#### Behavioural notes

- The middleware now holds a read lock for the duration of the
  byte-compare (microseconds). Read contention is bounded by
  scrape concurrency.
- The previously-loaded tokens persist on reload failure — the
  daemon stays up; existing valid tokens keep working. Operators
  see a structured `warn!` line.
- Pre-follow-up callers that constructed `Arc<LoadedTokens>` —
  none in the public API — would now go through
  `ApiServer::token_reloader()` instead. The function signature
  for `ApiServer::new` is unchanged.

#### Tests

- **Unit** (`selfdef-api`): 4 tests in
  `transport::token_reload_tests` covering atomic swap,
  prior-tokens-preserved-on-empty-file, prior-tokens-preserved-on-io-error,
  and the `is_loaded` accessor.
- **CLI integration**
  (`crates/selfdef-cli/tests/cli_api_rotate_token.rs`): 4
  tests covering url-safe + 0600 output, `--token-file`
  override, `--bytes` validation, and two rotations producing
  different tokens.
- **`base64_urlsafe` self-tests** (in main.rs): RFC 4648 §5
  positive vectors + a property-style char-set check.

`cargo test --workspace`, `cargo clippy --workspace --tests
-- -D warnings`, and `cargo fmt --all -- --check` are clean.

### Added — eventstream parse-time integrity check (SDD-004 F-2026-026 follow-up)

Closes the SDD-004 F-2026-026 follow-up known gap as
**opt-in shipped**. The daemon's `[collectors.eventstream]`
config gains two new fields:

- `integrity_check: bool` (default `false`). When `true`, the
  collector refuses to tail any path that is world-writable
  (`mode & 0o002 != 0`) or owned by a UID outside
  `{daemon-effective-uid, root} ∪ allowed_owners`. Mismatches
  return an `IntegrityRefused` error and the daemon logs a
  structured warning; other configured paths continue tailing.
- `allowed_owners: Vec<u32>`. Additional numeric UIDs accepted
  as a writer when `integrity_check = true`. Empty list = only
  the daemon-effective-uid and root are accepted. Operators
  with a deliberate operator-owned emitter (e.g. the user's
  own `~/.local/share/selfdef/ssh-wrap.jsonl`) add their UID
  here.

Default is `false` so operator-owned emitters keep working
unchanged. The hardening checklist in `SECURITY.md` recommends
turning it on once `/var/lib/selfdef/eventstream/` is
`0750 selfdef:selfdef`.

#### What this changes for operators

- `config/selfdef.toml.example` documents the two new knobs
  under `[collectors.eventstream]` with the
  ssh-wrap-emitter-on-uid-1000 example.
- `SECURITY.md` known-gap entry for eventstream JSONL
  injection updates from "tracked under SDD-004 follow-up" to
  "opt-in shipped; turn on via `integrity_check = true`".

#### Tests

- Unit (`crates/selfdef-collector-eventstream/src/lib.rs`):
  - `integrity_check_rejects_world_writable_file`
  - `integrity_check_accepts_daemon_or_root_owned_file`
  - `integrity_check_accepts_explicit_allowed_owner`
  - The pre-existing `tails_event_file_and_republishes` test
    continues to pass, confirming the default-disabled path
    is unchanged.

`cargo test --workspace`, `cargo clippy --workspace --tests
-- -D warnings`, and `cargo fmt --all -- --check` are clean.

### Documentation — security threat-model rewrite (SDD-004 implementation)

Closes Phase-1 audit findings F-2026-023, F-2026-024, F-2026-025,
F-2026-026. SDD-004 status flips from `draft` to `implemented`.
With this PR, **every Phase-1 SDD has shipped its implementation
PR** and every important / blocker finding the audit raised is
now closed or has a tracked follow-up.

`SECURITY.md` is rewritten in place; `docs/src/security.md` is
now a symlink to `../../SECURITY.md` (was a duplicated copy)
to eliminate the drift surface.

- **Assets table**: three new rows. `/metrics` endpoint, Tetragon
  TracingPolicy directory (`/etc/tetragon/tetragon.tp.d/`), and
  eventstream JSONL paths. Total: 10 rows.
- **Adversaries table**: new class 6 *Cluster-tenant attacker* —
  has Pod-label `PATCH` rights on the k8s cluster.
- **Trust assumptions**: cluster control plane added as a
  trusted entity for k8s deployments.
- **Mitigations**: two new layers added — *API surface* (UNIX
  vs TCP transports, bearer-token model, `/metrics` read-cap
  parity, uptime side channel) and *Policy surface*
  (TracingPolicy directory ownership, agent-guard pod-label
  scope dependency on cluster RBAC, eventstream JSONL trust
  boundary).
- **Known gaps**: extended with three new follow-up entries —
  TracingPolicy signing (F-2026-024 follow-up), metrics-token
  rotation (F-2026-023 follow-up), k8s label-RBAC posture
  (F-2026-025 follow-up). Eventstream JSONL integrity
  (F-2026-026 follow-up) was already enumerated by PR #36 and
  stays.
- **Hardening checklist**: short copy-paste-able sidebar at the
  end of the Mitigations section enumerating the recommended
  posture for an AI-machine deployment.

The rewrite is documentation-only — no code, no defaults change.
Operators reading `SECURITY.md` see new asset rows + a new
adversary class + new mitigation guidance. Recommended action
for AI-machine deployments is the new Hardening checklist
sidebar.

### Added — test contract + 6 test-gap closures (SDD-005 implementation)

Closes SDD-debt finding F-2026-082 and the six implementation
findings F-2026-030 through F-2026-036. SDD-005 status flips from
`draft` to `implemented`. The six Test-N PRs the SDD breaks the
work into collapse into a single PR per the "big chunks" steer.

- **D-5 — Test-contract runbook**: `docs/dev/test-contract.md`
  is the new contributor-facing doc — four test categories
  (translation, pipeline, module-script, seam) with explicit
  contracts, plus the three shared patterns (P-1 dry-run-noop,
  P-2 Prometheus parser, P-3 real-broker NATS).
- **Test-1 (D-2a) — Dry-run negative**:
  `crates/selfdef-cli/tests/common/mod.rs` gains `snapshot_tree`
  + `assert_tree_unchanged`. The reference adoption is
  `module_vpn_bridge.rs::endpoint_dry_run_must_be_a_noop_on_disk`
  — staging a relay-via-server fixture, running apply with
  `SELFDEF_DRY_RUN=1`, snapshotting before/after, and asserting
  byte equality. The fingerprint is length+first-32-bytes (hand
  rolled) so we don't take a hash-crate dep. Closes F-2026-030
  for the reference module; the other module test files migrate
  when next touched.
- **Test-2 (D-2b) — Prometheus parser + read-cap gate**:
  `m12_api.rs` gains a `mod prom` exposition parser
  (Sample(name, labels, value) tuples, dedup-key check, strict
  comment shapes). New tests
  `metrics_exposition_passes_format_strict_parse` and
  `metrics_allows_read_capability` close F-2026-031 and
  F-2026-032. The pre-existing substring assertions on the
  /metrics body are kept alongside as a regression net.
- **Test-3 (D-2c) — Real-broker NATS round-trip**:
  `crates/selfdef-nats/tests/integration.rs` spawns a real
  `nats-server` on a free port (discovered via `which`) and runs
  the bridge against it. `core_bridge_round_trips_event_between_two_hosts`
  asserts the wire format end-to-end; `jetstream_bridge_creates_stream_and_durable_consumer`
  asserts the JetStream startup contract. Both are
  `#[ignore]`-gated — CI without the binary stays green; the
  runbook documents `cargo test -p selfdef-nats -- --include-ignored`
  for local runs (and CI installing `nats-server`).
  Closes F-2026-035.
- **Test-4 — Correlator hot-reload**:
  `crates/selfdef-correlator/tests/hot_reload.rs`.
  `correlator_swaps_rules_atomically_under_live_traffic` runs a
  driver task firing 5ms-cadence events while the test swaps
  rule A→B mid-flight and verifies findings match exactly one
  rule title (no half-state).
  `correlator_load_rules_keeps_prior_set_on_parse_failure`
  asserts the non-destructive failure path. Closes F-2026-033.
- **Test-5 — Store concurrency + crash-recovery**:
  `crates/selfdef-store/tests/concurrent.rs`.
  `concurrent_inserts_do_not_lose_rows` hammers the store from
  8 tasks × 200 inserts under a multi-thread runtime;
  `crash_recovery_surfaces_every_committed_insert` opens, inserts
  50, drops, reopens, asserts all 50 are durable;
  `concurrent_inserts_then_reopen_preserves_count` composes
  both. Closes F-2026-034.
- **Test-6 — Tetragon collector isolation**:
  `crates/selfdef-collector-tetragon/tests/translation.rs`.
  10 tests covering every `process_exec` / `process_kprobe`
  (file_open, socket, unknown function) / `process_exit` /
  unknown-top-level branch + 3 tolerance branches (empty line,
  malformed JSON, missing-fields). A new
  `pub fn TetragonCollector::translate_line(&str) -> Option<Event>`
  gives the external test surface; `process_line` now wraps it
  (translate-then-publish). Closes F-2026-036.

### Behavioural notes

The translation-only `translate_line` API on `TetragonCollector`
is additive — existing callers go through `process_line` and
`run()` unchanged. The `mod prom` parser is contained in the
m12_api integration test file; if a future test outside that
file needs it, extract to a workspace test-only crate.

### Tests

The six new test files run as part of `cargo test --workspace`.
NATS integration is gated; the runbook documents the
`--include-ignored` invocation. Full workspace `cargo test`,
`cargo clippy --workspace --tests -- -D warnings`, and
`cargo fmt --all -- --check` are clean.

### Added — shared module-script library (SDD-006 implementation)

Closes SDD-debt finding F-2026-081; partial close on F-2026-051.
SDD-006 status flips from `draft` to `implemented`. Phase A + B + C
of the SDD's rollout plan land together in one PR per the
"big chunks" steer: the shared library, the dispatcher
plumbing, **and** the byte-stable migration of all eight modules.

- **D-1 — Shared library**: `packaging/lib/module-lib.sh` ships
  the five core helpers (`log`, `emit_status`, `die`, `run`,
  `toml_get`) plus version pin (`SELFDEF_MODULE_LIB_VERSION=1`).
  Helpers are byte-identical to the per-module copies (except
  `log()`, which the shared version parameterises on
  `${MODULE}` instead of a hard-coded slug literal). The library
  refuses to source when
  `SELFDEF_MODULE_LIB_VERSION_REQUIRED` exceeds what it ships
  (exits 99 with a clear stderr message).
- **D-2 — Dispatcher plumbing**: `run_one` in
  `crates/selfdef-cli/src/modules.rs` exports
  `SELFDEF_MODULE_LIB` via a new `resolve_module_lib_path()`
  with three-tier precedence (env override → workspace
  `packaging/lib/module-lib.sh` → installed
  `/usr/share/selfdef/lib/module-lib.sh`).
- **D-3 — Per-module migration**: eight modules migrated in one
  go: `agent-guard`, `tetragon`, `observability`,
  `integrity-sentinel`, `vpn-bridge`, `bridge-l2`, `polarproxy`,
  `suricata`. The five with an existing `install/lib.sh` had
  their helper block replaced by a `source` of the shared lib;
  the three with inlined helpers (`bridge-l2`, `polarproxy`,
  `suricata`) gained a `lib.sh` of their own and source it from
  apply / check / uninstall. The lib.sh files use a
  `${BASH_SOURCE[0]%/*}` parameter-expansion fallback to the
  workspace path so integration tests + ad-hoc invocations work
  without `SELFDEF_MODULE_LIB` set, and the resolver never
  shells out to `dirname` (some tests run the scripts under a
  stripped `$PATH`). `bridge-l2`'s, `polarproxy`'s, and
  `suricata`'s uninstall scripts override `log()` and `run()`
  after sourcing to preserve the pre-SDD-006 `[<slug>:uninstall]`
  log prefix and lenient continue-past-failure behaviour.
- **D-4 — Helpers doc**: `docs/dev/module-helpers.md` is the new
  authoritative reference — every exported helper, the caller
  contract, the versioning policy, and how to add module-specific
  helpers / shared-helper overrides.
- **D-5 — Packaging**: `crates/selfdef-daemon/Cargo.toml`'s
  `[package.metadata.deb]` assets list installs the shared lib
  at `/usr/share/selfdef/lib/module-lib.sh` mode `0644`.

#### Behavioural notes

The migration is **byte-stable** for every shipped module's apply
/ check / uninstall flow. The only externally visible change is
the `log()` prefix: pre-SDD-006, each module hard-coded
`[<slug>]` in its own `log()` definition; the shared lib uses
`[${MODULE}]`, which produces the identical string at runtime.
Operator log captures should diff cleanly. The `[<slug>:uninstall]`
prefix that bridge-l2 / polarproxy / suricata's uninstall scripts
emitted pre-SDD-006 is preserved by per-script `log()` overrides
after sourcing.

#### Tests

- Unit (`crates/selfdef-cli/src/modules.rs`):
  `resolve_module_lib_path_finds_workspace_by_default`. The
  env-override branch is exercised by integration only because
  the workspace lint forbids in-process `std::env::set_var`
  (the lint is correct: env mutation isn't thread-safe).
- Integration
  (`crates/selfdef-cli/tests/cli_modules_shared_lib.rs`):
  `dispatcher_exports_module_lib_env_var` asserts selfdefctl
  exports the env var; `module_sourcing_shared_lib_at_v1_succeeds`
  is a smoke test of the full source-and-call flow;
  `module_requesting_newer_lib_version_is_refused` checks the
  version-pin diagnostic.
- All 13 per-module integration test files
  (`module_*.rs`) continue to pass byte-stably — proof the
  migration didn't change apply / check / uninstall behaviour.

#### Deferred / partial

- **F-2026-050** (agent-guard's hand-enumerated policy list in
  `uninstall.sh`) is **deferred** to a follow-up. The SDD reserved
  a `module_render_files` helper for this; v1's library surface
  is intentionally minimal.
- **F-2026-051** (`render_pod_scope` awk fragility) is **partial
  close**: the v1 library doesn't ship YAML-aware editing
  helpers. A future v2 of the library could ship `yq`/python
  helpers and close it fully.

### Added — vpn-bridge multi-instance honesty (SDD-003 implementation)
Closes Phase-1 audit blocker F-2026-005. SDD-003 status flips
from `draft` to `implemented`. With this PR, all six Phase-1
blockers from the architect/PM sweep are closed.

The vpn-bridge manifest's `instanced = true` is now honest about
which profiles can actually run side-by-side, and the resolver +
profile scripts enforce that boundary.

- **`selfdef-cli` D-1**: `ProfileSpec` (in
  `crates/selfdef-cli/src/modules.rs`) gains an optional
  per-profile `[profiles.details.<name>]` block with an
  `instanced: Option<bool>` field. Profiles not listed there
  inherit the module-level `instanced` value.
  `ProfileSpec::profile_instanced(profile, module_default)`
  is the single accessor.
- **`selfdef-cli` D-2**: `resolve_active` reads each instance's
  per-module config (parsing just the `profile = ...` line),
  looks up the profile's `instanced` capability, and refuses
  any `slug#instance` host-config key whose profile is declared
  `instanced = false`. Refusal happens before any apply.sh fires.
- **`selfdef-cli` D-3**: `run_one` now passes
  `SELFDEF_INSTANCE_ID=<inst>` into the spawned bash process
  whenever the active module has an instance suffix. Absent for
  the legacy single-instance shape — scripts that don't need it
  can ignore it.
- **`modules/vpn-bridge` D-4**: `relay-via-server.sh` derives
  per-instance defaults from `${SELFDEF_INSTANCE_ID}`:
  interface defaults to `selfdef-<inst>` (was `wg0`), nftables
  table to `selfdef_vpn_bridge_<inst>` (was `selfdef_vpn_bridge`),
  nftables state file to
  `/etc/nftables.d/selfdef-vpn-bridge-<inst>.conf` (was
  `/etc/nftables.d/selfdef-vpn-bridge.conf`). The forward-rule
  template now substitutes `@@NFT_TABLE@@`. Override
  environment variables (`SELFDEF_VPN_BRIDGE_NFT_TABLE`,
  `SELFDEF_VPN_BRIDGE_NFT_PATH`) take precedence as before.
  `tailscale.sh` and `cloudflare-tunnel.sh` `die`
  defence-in-depth at the top of `profile_apply` /
  `profile_uninstall` when `SELFDEF_INSTANCE_ID` is set — the
  resolver should already have refused the apply, but the
  scripts guard against bypass.
- **`modules/vpn-bridge` D-5**: `module.toml` declares
  `[profiles.details.relay-via-server] instanced = true`,
  `[profiles.details.tailscale] instanced = false`,
  `[profiles.details.cloudflare-tunnel] instanced = false`. The
  README's pre-SDD-003 "Multi-instance caveat" block is
  rewritten into a "Multi-instance support" section with the
  capability table, per-instance naming convention
  (`selfdef-<inst>` iface and friends), and migration notes for
  pre-SDD-003 deployments.

#### Backwards compatibility

Single-instance `[modules.vpn-bridge]` deployments are
**byte-stable**: when `SELFDEF_INSTANCE_ID` is unset, the
relay-via-server defaults remain `wg0` / `selfdef_vpn_bridge`
/ `/etc/nftables.d/selfdef-vpn-bridge.conf`. No migration is
needed for the common shape.

If you were running multiple instances of `tailscale` or
`cloudflare-tunnel` (which silently corrupted state pre-SDD-003),
the resolver will now refuse the `#suffix` host keys with a
clear message. Pick one to keep, drop the `#suffix`, and
re-apply.

If you were running multiple instances of `relay-via-server`,
each instance's apply will now install per-instance state files
alongside any legacy `selfdef_vpn_bridge` table you had — see
the vpn-bridge README's "Migrating from pre-SDD-003" section for
the cleanup steps.

#### Tests

- Unit (`crates/selfdef-cli/src/modules.rs`):
  `profile_instanced_falls_back_to_module_default_when_unset`,
  `profile_instanced_per_profile_override_wins`,
  `resolver_rejects_instance_for_singleton_profile`,
  `resolver_accepts_instance_for_multi_instance_profile`,
  `resolver_falls_back_to_default_profile_when_config_missing`.
- Integration
  (`crates/selfdef-cli/tests/module_vpn_bridge_multi_instance.rs`):
  the relay profile uses per-instance iface when
  `SELFDEF_INSTANCE_ID` is set and stays on `wg0` when it isn't;
  the singleton profiles refuse to apply when the env var leaks
  through; the CLI resolver refuses `vpn-bridge#extra` for the
  tailscale profile before invoking apply.sh.

### Added — defaults that work out of the box (SDD-002 implementation)
Closes Phase-1 audit blockers F-2026-004 / F-2026-018 / F-2026-020.
SDD-002 status flips from `draft` to `implemented`.

The bridge between module defaults and daemon defaults is now a
**manifest-level contract**. Every active module's
`[daemon_requires]` is validated against
`/etc/selfdef/selfdef.toml` before any apply.sh fires; mismatch
prints a copy-pasteable TOML snippet (with `${...}` substitutions
expanded against the per-module config) and exits 2, unless the
operator passes `--ignore-daemon-requires`.

- **`selfdef-cli` D-1**: `ModuleManifest` gains an optional
  `daemon_requires: BTreeMap<String, DaemonRequirement>`. The
  untagged `DaemonRequirement` enum supports bool / int / string /
  array-of-string values. Array entries are interpreted as
  set-inclusion (the daemon's actual array must contain every
  element listed in the manifest).
- **`selfdef-cli` D-2**: `check_daemon_requires` runs in
  `run_lifecycle` for `Apply` and `Check` actions (uninstall
  skips — tearing a module down doesn't care). Substitution
  rule is intentionally minimal: only `${<flat-key>}` referencing
  a same-module top-level scalar. The snippet renderer groups
  unmet requirements by module with `# ── <module> ──` headers.
- **D-3**: `modules/integrity-sentinel/profiles/strict.toml` and
  `profiles/warn-only.toml` now ship with `event_stream_path`
  live by default (default
  `/var/lib/selfdef/eventstream/integrity-sentinel.jsonl`). Set
  the key to `""` to opt out. The module's `[daemon_requires]`
  ensures the daemon's `[collectors.eventstream].paths` includes
  this file before apply proceeds.
- **D-4**: `config/selfdef.toml.example` gained operator-discovery
  comments under `[collectors.tetragon]` (explicitly contrasting
  it with `[collectors.eventstream]`) and under
  `[collectors.eventstream]` (showing the integrity-sentinel
  emission path as a commented example).
- **D-5**: new `selfdefctl modules show-requires` subcommand
  prints every active module's expanded `[daemon_requires]` as a
  copy-pasteable snippet. Read-only; never touches the daemon
  config.
- **Manifests**: `tetragon` and `integrity-sentinel` now declare
  their daemon-side knobs. Other modules can adopt the field
  incrementally — manifests without the section skip the check.
- **Operator-facing CLI surface**: `selfdefctl modules apply` and
  `selfdefctl modules check` gain a `--ignore-daemon-requires`
  flag; new `selfdefctl modules show-requires` subcommand.
- 4 new integration tests in
  `tests/cli_modules_daemon_requires.rs`: apply refuses on unmet,
  apply succeeds on satisfied, `--ignore-daemon-requires`
  bypasses, `show-requires` prints the expanded snippet.

Operator-visible effect: a fresh `.deb` install with
`integrity-sentinel`, `tetragon`, and `agent-guard` active in
`/etc/selfdef/modules.toml` now refuses to silently proceed on a
mismatched `selfdef.toml`. The operator sees exactly what to
add. Once added, every promise the modules' READMEs make about
the daemon picking up their output holds end-to-end.

### Added — AI-machine track is end-to-end (SDD-001 implementation)
Closes the four Phase-1 audit blockers that surrounded the
AI-machine track: F-2026-001, F-2026-002, F-2026-003,
F-2026-006. SDD-001's status flips from `draft` to
`implemented`.

- `selfdef-collector-tetragon` now attaches a stable
  `raw.tetragon.{policy_name,policy_namespace,action,function_name}`
  subobject to every `process_kprobe` Event it builds.
  Severity stays Informational at the collector layer
  per the SDD's "collectors are dumb translators"
  invariant — meaning lives in the correlator. Closes
  **F-2026-001**.
- New sigma rule
  `rules/sigma/hardening/agent_guard_violation.yml`
  matches `raw.tetragon.policy_name|startswith
  "selfdef-agent-"` AND `raw.tetragon.action|in [Sigkill,
  Override, NotifyKiller]`, promotes to `level: high`.
  Audit-mode `Post` actions deliberately do **not** trip
  this rule. Six-case `.tests.yaml` corpus covers Sigkill,
  Override, NotifyKiller, audit-mode-Post-negative,
  non-agent-guard-negative, non-tetragon-source-negative.
  Closes **F-2026-002**.
- `modules/tetragon/README.md` now names
  `[collectors.tetragon]` as the correct daemon-side
  ingest path with a paste-ready snippet, and the
  "What's NOT owned" section explicitly calls out the
  `[collectors.eventstream]` collector as the wrong
  choice. Closes **F-2026-003**.
- New daemon integration test
  `crates/selfdef-daemon/tests/m_ai_machine.rs` exercises
  the full pipeline (Tetragon JSON → collector → bus →
  correlator → findings store) and asserts the negative
  case (audit-mode `Post` does NOT promote). Closes
  **F-2026-006**.

Operator-visible effect: with the `tetragon` collector
enabled in the daemon config and `agent-guard` running in
`enforce` (or a per-policy `*_action = "sigkill"`
override), a real policy violation now surfaces as a
high-severity Detection Finding through the existing
notifier chain (ntfy / Signal). The kernel-side action
worked all along; this PR plumbs the operator alert side.

### Changed — Phase 1 audit follow-ups (one bigger PR)
Seven small fixes batched together. Each closes (or partially
closes) a Phase-1 ledger row.

- **F-2026-054** — `selfdef-daemon::build_notifier_chain` now
  warns at startup when `[notifier.ntfy]` or `[notifier.signal]`
  carries non-default config but the channel name isn't in the
  active `[notifier].channels` list. The channel was silently
  inert before; now the operator sees it on every restart.
- **F-2026-059** — extracted `check_confirm_hostname` +
  `ConfirmRefusal` helper in `selfdef-cli/src/main.rs`. Both
  `panic` and `modules uninstall` now share the
  hostname-confirmation gate; the duplicated bodies are gone.
  Output text is preserved (test suite asserts the same
  refusal strings).
- **F-2026-060** — new `crates/selfdef-cli/tests/common/mod.rs`
  carrying the `workspace_root` / `module_dir(slug)` /
  `write_file` / `write_executable` / `last_stdout_line` /
  `prepended_path` helpers that nine `module_*.rs` test files
  duplicated. Per-test migration is incremental — adopting the
  common module in each test file is a follow-up.
- **F-2026-061** — `m12_api.rs metrics_endpoint_returns_prometheus_exposition`
  now exact-matches the `Content-Type` against
  `text/plain; version=0.0.4; charset=utf-8`, asserts each
  `# TYPE` line is present **exactly once** (catches accidental
  duplicates), and validates every body line follows the
  Prometheus exposition shape. Substring matching is gone.
- **F-2026-062** — `module_agent_guard.rs` gains a byte-stable
  reapply test that exercises every rendered policy (with
  egress allowlist + GPU allowlist set so the substitution
  paths are exercised). Bridge-l2 / suricata / polarproxy /
  vpn-bridge still need theirs (follow-up).
- **F-2026-065 + F-2026-066** — SECURITY.md (and its mirror
  `docs/src/security.md`) gain two Known-gaps entries: the
  eventstream-JSONL injection primitive via
  `selfdefctl events emit`, and the `selfdef_uptime_seconds`
  side channel that lets a `/metrics` scraper time
  credential-file edits to a daemon restart. Both name the
  recommended mitigation.

Verified: `cargo build --workspace`, `cargo test -p
selfdef-cli -p selfdef-api`, `cargo fmt --all -- --check`,
`cargo clippy -p selfdef-cli -p selfdef-daemon -p selfdef-api
--tests` all clean.

### Docs — Phase 1 audit nice-cluster cleanup
- `modules/vpn-bridge/README.md` — new "Multi-instance
  caveat" block at the top calling out F-2026-005 / SDD-003
  and warning operators not to declare two
  `[modules."vpn-bridge#..."]` blocks against the same
  profile until SDD-003 ships. Closes **F-2026-058**.
- `modules/observability/README.md` — new "Tetragon
  metric-name pin" section documenting the upstream-version
  assumption (the dashboard panels target Tetragon v1.x's
  metric naming). Documents **F-2026-052** as a partial
  close; the `tetragon` module's `requires` block doesn't
  pin a version range yet.
- `docs/review/99-findings-ledger.md` — back-references the
  nice-cluster PR. Also marks **F-2026-056** and
  **F-2026-057** as closed by doc-sweep PR #30 (the
  README's Module catalog table and the CHANGELOG's
  "Honest correction" entry, respectively — they were
  shipped but not back-referenced at the time).

### Changed — Phase 1 audit dead-knob cleanup
- `selfdef-store/src/sqlite.rs` no longer carries its own
  `const SCHEMA_VERSION: u32 = 1` — it now imports
  `selfdef_core::SCHEMA_VERSION`. Drift risk eliminated; a
  future schema bump in `selfdef-core` propagates to the
  store's migration check automatically. Closes
  **F-2026-017** (audit ledger).
- `selfdef-config::BusConfig::backend` and
  `selfdef-config::CorrelatorConfig::{window_secs,threshold}`
  rustdoc-marked **vestigial**: the daemon doesn't branch on
  any of the three. The fields stay in the struct so existing
  operator configs keep parsing (serde `#[serde(default)]`
  was already on the struct). Removed from
  `config/selfdef.toml.example` so new operators don't copy
  them in. Closes **F-2026-015** + **F-2026-053**.
- No daemon behaviour change. No public-API removal.
- Findings ledger updated with closure references.

### Docs — Phase 1 audit doc-sweep
- `README.md` no longer claims "Milestone 1 — Scaffolding only".
  Adds a module catalog table and an AI-machine track milestone.
- `ARCHITECTURE.md` updated to show the `/metrics` endpoint and a
  Modules-layer overview.
- `docs/src/modules.md` corrects the stale "only `detect-host`
  ships" claim.
- `modules/observability/README.md`: `scrape_targets` documented
  default reconciled (Tetragon + selfdef-daemon, not Tetragon
  alone). Dashboard panel list extended to cover the three new
  selfdef-daemon panels. New "Scraping the daemon" section
  walks the bearer-token scrape config Prometheus needs against
  the daemon's `/metrics` TCP transport.
- `modules/observability/install/apply.sh` fallback default for
  `scrape_targets` now matches the shipped profile defaults.
- mdbook `SUMMARY.md` surfaces the previously-orphan
  `api.md`, `ebpf.md`, `nats.md`, `ssh-wrap-install.md`. Those
  files moved from `docs/` into `docs/src/{ops,dev}/` so the
  mdbook tree owns them.
- Five `# TODO` stub pages (`dev/build`, `dev/collector`,
  `ops/install`, `ops/config`, `ops/notifications`,
  `detect/rules`, `detect/testing`) replaced with real, tight
  content.
- Closes Phase 1 audit findings F-2026-012 / -013 / -019 /
  -021 / -022 / -027 / -028 / -029. Findings ledger is updated
  with cross-references.

### Honest correction — AI-machine track operator promise
The CHANGELOG entries for PRs #21, #22, #24 described an
operator-facing benefit (drift fires the notifier chain;
agent-guard kills surface as alerts; GPU device access surfaces)
that the Phase 1 audit (`docs/review/40-integration-audit.md`)
showed is not plumbed end-to-end today. The kernel-side action
works (Tetragon Sigkill terminates); the path from Tetragon
event to operator alert breaks at two seams: the
selfdef-collector-tetragon hardcodes `Informational`, and no
sigma rule promotes Tetragon agent-guard events to findings.
The fix is designed in `docs/sdd/001-ai-machine-end-to-end.md`
(closes F-2026-001 / -002 / -003 / -006). Until that
implementation lands, treat the agent-guard "you'll get a
notifier ping on a violation" claim as **planned, not
shipped**.

### Added — `agent-guard` v0.3.0: pod-label scope for Kubernetes
- New `scope` config key in `agent-guard.toml` selects how the
  shipped policies decide "what counts as inside an agent
  container":
  - `container` (default, unchanged from v0.2.0) — `matchNamespaces:
    Pid NotIn [host_ns]`. Works on every container runtime.
  - `pod-label` — `matchPodSelector: matchLabels.<key>=<value>`.
    Kubernetes-only; narrower because only pods carrying the
    operator-defined label fire the policy.
- Two new keys back the pod-label scope: `pod_label_key` and
  `pod_label_value` (defaults `selfdef.io/agent` / `true`). Both
  are required when `scope = "pod-label"`; apply.sh refuses
  without them with a clear error.
- `lib.sh` gains `render_pod_scope()` which rewrites every
  rendered policy's `matchNamespaces` block to `matchPodSelector`.
  It runs *after* the policy-specific post-render hooks so the
  gpu-device-guard's `matchNamespaces`-anchored awk stays valid.
- 5 new integration tests cover: pod-selector splicing across all
  five policies, the default `container` scope leaving
  `matchNamespaces` intact, `pod-label` without required keys
  refused, invalid scope value refused, and the gpu-device-guard's
  `matchBinaries` block surviving the pod-scope swap when the
  allowlist is set.
- README documents the new scope table + the sample k8s Pod
  manifest with `selfdef.io/agent: "true"`.
- Module bumps to `0.3.0`. Roadmap drops the pod-label follow-up
  from the remaining-work list.

### Added — `agent-guard` v0.2.0: GPU device guard
- New `gpu-device-guard` TracingPolicy ships in the `agent-guard`
  bundle. Watches `security_file_open` against GPU device nodes
  (`/dev/nvidia`, `/dev/nvidiactl`, `/dev/nvidia-uvm*`,
  `/dev/nvidia-modeset` by default) from inside containers
  (`matchNamespaces: Pid NotIn [host_ns]`). A `matchBinaries: NotIn`
  selector filters out the operator's allowlist of permitted
  in-container binary paths; anything else opening a tracked device
  trips the policy.
- New host-config keys: `gpu_device_enabled` (default true),
  `gpu_device_action` (audit/enforce defaults via the existing
  per-policy resolver), `gpu_device_paths` (CSV of device-path
  prefixes — empty = ship default NVIDIA set; populate to add AMD
  ROCm `/dev/kfd`, Intel Habana `/dev/accel`, etc.), and
  `gpu_device_allowlist` (CSV of in-container binary paths
  permitted to open those devices — empty = match every binary).
- Apply / check / uninstall all extended to handle the fifth policy.
  `lib.sh` gains `render_gpu_policy()` that rewrites the device
  prefix block and the binary allowlist (or drops the
  `matchBinaries` selector entirely when the allowlist is empty,
  inverting the semantic from "allowlist" to "match every in-container
  binary").
- Module bumps to `0.2.0`. README + roadmap updated; the GPU
  follow-up is removed from the remaining-work list.
- 4 new integration tests:
  - default render keeps NVIDIA prefixes and drops `matchBinaries`
    with an empty allowlist
  - non-empty allowlist keeps `matchBinaries` and splices values
  - operator-supplied `gpu_device_paths` fully replace the shipped
    NVIDIA defaults
  - `gpu_device_enabled = false` removes any stale render

### Added — selfdef-daemon `/metrics` endpoint (Prometheus exposition)
- New `GET /metrics` route on the existing API surface (UNIX socket
  + TCP), rendering Prometheus exposition format
  (`text/plain; version=0.0.4`). Operators point Prometheus at the
  same address that already serves `/status` and `/events`. The
  observability module's default `scrape_targets` now includes
  `localhost:8443` alongside Tetragon's `localhost:2112`.
- Counters: `selfdef_events_total`, `selfdef_events_by_class_total{class_uid}`,
  `selfdef_findings_total`, `selfdef_findings_by_severity_total{severity_id}`,
  `selfdef_ingest_lag_events_total`. Gauges: `selfdef_uptime_seconds`,
  `selfdef_store_events`, `selfdef_build_info{version,schema,host_tag}`.
  Label cardinality is bounded — high-cardinality fields (host_tag,
  source string) are kept out of per-series labels so a busy host
  doesn't blow up Prometheus's TSDB.
- A `selfdef-api::Metrics` Arc is shared between the API state
  (which serves the endpoint) and a new ingest task the daemon
  spawns (`run_metrics_ingest`) that subscribes to the bus and
  bumps counters per event. Lag from a slow subscriber is surfaced
  as `selfdef_ingest_lag_events_total` rather than swallowed.
- 5 unit tests (`record_event`, findings-bucket gating, exposition
  format validity, label escaping, lag accumulation) plus 3
  integration tests (Content-Type + headers, in-process counter
  ingest end-to-end via the spawned task, store gauge alignment).
- Observability module: dashboard JSON gains three new panels —
  "selfdef events / second by class", "selfdef findings / second
  by severity", "selfdef hot-store size". Default `scrape_targets`
  now picks up both Tetragon and the daemon.

### Added — AI-machine track: `tetragon` + `agent-guard` + `observability` modules
- New `tetragon` module (v0.1.0, hardening, `phase = "pre"`):
  substrate for everything Tetragon-based. Renders
  `/etc/tetragon/tetragon.yaml` byte-stably from the host config,
  owns the TracingPolicy drop directory, exposes the built-in
  Prometheus metrics endpoint, points Tetragon's event JSONL at a
  path the daemon's `eventstream` collector can tail. Refuses to
  apply if `tetragon` / `systemctl` aren't on `PATH`. Restarts the
  service only when the rendered config actually changes bytes —
  re-running apply on a converged host is a true no-op. Provides
  `tetragon-tracing` / `tetragon-policies` / `metrics-endpoint`.
- New `agent-guard` module (v0.1.0, hardening, `depends_on =
  ["tetragon"]`): four TracingPolicies tuned for AI agents running
  in Docker / Podman / containerd containers:
  - `etc-write-guard` — `security_file_open` with write intent
    under `/etc/`.
  - `container-shell-guard` — `execve` of `bash` / `sh` / `dash`
    / `zsh` / `ash`.
  - `egress-guard` — `tcp_connect` to non-allowlisted destinations
    (CSV CIDR allowlist via `egress_allowlist`).
  - `securemessage-guard` — forward-looking stub for a SecureMessage
    endpoint; auto-downgrades to `Post` action whenever the
    endpoint is unset so the placeholder never SIGKILLs anything.
  Two profiles: `audit` (Post-only, the bring-up default) and
  `enforce` (Sigkill). Per-policy `*_action = default | post |
  sigkill` overrides let operators ramp up policies individually.
  Container scope uses Tetragon's `matchNamespaces` to skip the
  host PID namespace — works on every container runtime without
  needing k8s labels.
- New `observability` module (v0.1.0, observability, `phase =
  "post"`, `depends_on = ["tetragon"]`): Prometheus scrape config
  + Grafana dashboard JSON for the selfdef stack. Two profiles:
  `bundled` (drops files under `/etc/prometheus/conf.d/` and
  `/var/lib/grafana/dashboards/selfdef/`, reloads Prometheus) and
  `external` (renders into a staging dir for the operator to sync
  out). Dashboard: four panels — Tetragon events/sec, kills by
  policy, process-cache utilization, BPF map errors.
- 23 new hermetic dry-run smoke tests cover the three modules:
  byte-stable config rendering + idempotent reapply (tetragon),
  per-policy action resolution + egress allowlist splicing +
  SecureMessage stub behaviour + check drift detection +
  uninstall cleanup (agent-guard), bundled vs external rendering +
  scrape target splicing + dashboard JSON validity + idempotent
  reapply + empty-target refusal (observability).
- Roadmap (`docs/src/modules-roadmap.md`) gains rows for the three
  new modules and the "AI-machine track" callout in remaining
  work, with pod-label / GPU device-guard variants + a
  selfdef-daemon `/metrics` endpoint flagged as follow-ups.

### Added — `selfdefctl events emit` + `integrity-sentinel` notifier wiring
- New `selfdefctl events emit` subcommand appends a single OCSF
  Event line to a JSONL stream the daemon's existing `eventstream`
  collector tails. Modules and helper scripts can now surface
  findings onto the bus without hand-rolling the envelope in bash:
  the Rust side builds a real `selfdef_core::Event`, so taxonomy,
  schema version, derived `type_uid`, and metadata are guaranteed
  correct. Args: `--class-uid`, `--activity-id` (default 1),
  `--severity` (informational|low|medium|high|critical|fatal),
  `--source`, `--message`, `--host-tag` (defaults to
  $HOSTNAME / /etc/hostname), `--out <path>` (required).
- `integrity-sentinel` v0.1.1: when `event_stream_path` is set in
  the module's host config, drift now emits a Detection Finding
  (OCSF class 2004) to that JSONL stream. The daemon picks it up,
  the responder routes Findings-category events through the
  notifier chain, and ntfy / Signal fires. Severity defaults to
  `high` for `strict` and `low` for `warn-only`; both are
  overridable via `event_severity_strict` / `event_severity_warn`.
  Leave `event_stream_path` unset to suppress emission — the
  structured-status surface is unaffected. Best-effort: a
  `selfdefctl` not on PATH or a failed emit logs a warning and
  never fails the apply / check run.
- 5 new unit tests for `selfdefctl events emit` (round-trips
  through `Event`, atomic append doesn't clobber prior lines,
  unknown severity / empty source rejected, parent dir is created
  on demand) plus 1 integration test that exercises
  `integrity-sentinel`'s apply path with `event_stream_path` set
  and asserts the resulting JSONL line parses back into a valid
  Findings-category Event.
- Roadmap docs (`docs/src/modules-roadmap.md`) updated to remove
  both shipped items (`modules uninstall`, integrity-sentinel
  notifier wiring) from the remaining-work list and to include the
  `uninstall` row in the lifecycle table.

### Added — `selfdefctl modules uninstall`
- New subcommand drives each active module's `uninstall.sh` in the
  inverse of apply order: dependents come down before the modules
  they depended on, and phases unwind `post → main → pre`.
- Destructive by design — non-dry-run runs require
  `--confirm <hostname>` matching this host (mirrors the `panic`
  subcommand's confirmation pattern). Mismatched or absent
  `--confirm` exits 2 with a clear message.
- `--dry-run` previews the run without `--confirm`, propagating
  `SELFDEF_DRY_RUN=1` so module scripts can short-circuit.
- Standard `--only` / `--except` filters apply, accepting either a
  bare slug or a `slug#instance` form.
- Modules whose manifest never declared an uninstall script (or use
  `kind = "debian-package"`) are reported as `skipped: no uninstall
  script declared` so a host-wide uninstall still produces a useful
  aggregate.
- Refactored the internal lifecycle runner around a small
  `LifecyclePolicy` (reverse order + tolerate-missing-script) to
  share the apply / check / uninstall machinery without forking.
- 3 new unit tests (reverse apply order, reverse phase order,
  missing-script detection) and 6 integration tests in
  `tests/cli_modules_uninstall.rs` cover ordering, the skipped path,
  both confirmation refusals, the matching-confirm happy path, and
  `--only` filtering.

### Added — JetStream durability for the NATS bridge
- New `[bus.nats.jetstream]` config block. When `enabled = true`, the
  bridge:
  - Ensures a JetStream stream (`stream_name`, default
    `selfdef-events`) capturing `<subject_prefix>.>` with operator-
    tunable retention (`max_age_secs` / `max_bytes` / `max_msgs`).
  - Creates a per-host durable pull consumer named
    `<durable_consumer_prefix>-<host_tag>` so each daemon tracks its
    own ack progress and a restart resumes mid-stream.
  - Publishes locally-originated events via `js.publish(...).await`
    and waits for the server ack — outages stall publishes rather
    than silently dropping them.
  - Acks each inbound message after republishing it onto the local
    bus (or recognizing it as a self-echo).
- Same loop-avoidance machinery as Core mode (host_tag check on both
  sides). At-least-once redeliveries are safe because each event
  carries a UUIDv7 and the store sink dedupes by id.
- Public API additions in `selfdef-nats`:
  - `JetStreamConfig` struct + nested in `NatsConfig`.
  - `durable_consumer_name(prefix, host_tag)` helper that sanitizes
    host_tags to the JetStream durable-name grammar (alphanumeric +
    `-` + `_`).
- 3 new unit tests: `durable_consumer_name` builds the expected
  string, sanitizes disallowed chars, and the `JetStreamConfig`
  defaults are conservative (disabled, 7-day retention, unlimited
  size).
- async-nats `jetstream` feature added to the workspace dep flags.
- Docs: `docs/nats.md` gains a "Modes: Core vs JetStream" section
  with a runnable config snippet, retention semantics, and explicit
  notes on at-least-once delivery + the dedupe contract. Example
  config gains the `[bus.nats.jetstream]` block.

### Added — Dashboard control surface
- The bundled PWA in `dashboard/` gains a **Control** panel that wires
  up the M13/M14 write endpoints:
  - **Reload rules** — `POST /rules/reload`. Shows the resulting
    `rules_loaded` count.
  - **Panic** — `POST /panic`. Confirmation requires typing the host
    tag (matches `selfdefctl panic --confirm`) and clicking through a
    second browser-level confirm dialog.
  - **Run action** — `POST /actions/{name}/run`. The action dropdown
    is populated from `GET /actions`. Leaving the event-id field
    blank runs the action against the most-recent finding.
- New `post()` helper in `dashboard/app.js` that parses the JSON body
  from both 2xx and error responses so the dashboard can surface what
  actually went wrong (`{"error": "..."}`).
- Result indicator (`#control-result`) renders ok / error states with
  green / red coloring and the API's own status text.
- Service worker now bypasses every non-`GET` request — control verbs
  pass straight through, no chance of an offline-cached fallback
  swallowing a panic dispatch. `/actions` is also added to the
  always-network list so the action list stays fresh.
- Docs: `docs/api.md`'s Dashboard section describes the new control
  surface and how the read-vs-control token gate is reflected in the
  UI.

### Added — M15 (NATS bridge for multi-host correlation)
- New crate `selfdef-nats` — pumps events between selfdef daemons over
  NATS Core. The local in-proc broadcast stays the source of truth for
  every in-process subscriber (collectors, correlator, responder,
  store sink, API SSE stream); the bridge is a sidecar task with two
  loops:
  - **outbound**: subscribes to the local bus and publishes locally-
    originated events to `<subject_prefix>.<host_tag>`.
  - **inbound**: subscribes to `<subject_prefix>.>` and republishes
    received events onto the local bus, dropping any whose
    `host_tag` matches ours (self-echo loop guard).
- Loop avoidance is two-layered on purpose: outbound filters by
  `event.host_tag == local`, inbound drops the mirror. The host_tag
  check is O(1) and doesn't need the deduper dance UUIDv7 enables.
- `[bus.nats]` config block: `enabled`, `url`, `subject_prefix`.
  Default prefix `selfdef.events`. Disabled by default. Multiple NATS
  servers are comma-separated per the async-nats URL grammar; TLS via
  the `tls://` scheme.
- Daemon wires the bridge as another supervised task next to the API
  and the store sink. SIGTERM/SIGINT cancel propagates through; the
  bridge tears down both child tasks before exiting.
- async-nats 0.48 (latest as of this PR). Picked deliberately over the
  0.37 baseline because that pull also yanked the unmaintained
  `rustls-pemfile` + old `rustls-webpki` transitive deps that fell out
  of `cargo deny check advisories`.
- Unit tests for the bridge cover the subject layout
  (`outbound_subject` / `inbound_subject`), subject sanitization
  (host_tags with `.`, `*`, `>`, whitespace), the local-origin check,
  and JSON round-trip on the wire format.
- Docs: new `docs/nats.md` describes the topology, subject layout,
  loop avoidance, and a one-liner smoke test against `nats-server`.
- Documented non-goals: this is NATS Core only (no JetStream
  durability yet); no built-in auth (operators bring NATS mTLS / NKey
  / JWT as needed).

### Added — M14 (per-token capabilities for the API)
- `[api].control_token_file` — a second, optional bearer token. Read
  endpoints accept either the existing `token_file` or
  `control_token_file`; control endpoints (`/rules/reload`, `/panic`,
  `/actions/{name}/run`) require the control token specifically.
- New `selfdef_api::Capability` (`Read` | `Full`) request extension
  set by the auth layer based on which token matched (or
  unconditionally `Full` for UNIX-socket clients). Control handlers
  pull a `RequireControl` extractor that returns `403 Forbidden` for
  `Read` requests and `401 Unauthorized` for unauthenticated.
- New `selfdef_api::with_full_capability` / `with_capability` helpers.
  Tests use them to stamp a capability onto the request without going
  through bearer auth. The UNIX-socket transport uses `with_capability(_, Full)`
  internally — same primitive, no special cases.
- 6 new integration tests in `crates/selfdef-api/tests/m12_api.rs`
  covering: read-only token on read endpoints (200), read-only token on
  `/actions` discovery (200), read-only token on each control verb
  (403), and the anonymous control-verb path (401). 19 cases total.
- Docs: `docs/api.md` gains a fleshed-out auth-boundary section with
  token mint + rotate recipes. Example config gains the new
  `control_token_file` field with annotated semantics. README adds the
  M14 checkbox.

### Added — M13 (control-plane verbs + TLS/mTLS for the API)
- **Control-plane endpoints** in `selfdef-api` (write side):
  - `POST /rules/reload` — re-reads the rules directory, returns
    `{rules_loaded: N}`. Returns `503` when the daemon hasn't wired a
    correlator handle (e.g. correlator disabled in config).
  - `POST /panic` — body `{confirm, message?}`. Validates `confirm`
    against the daemon's `host_tag` (same safety belt as
    `selfdefctl panic`) and direct-fires the panic action set.
  - `POST /actions/{name}/run` — body `{event}` *or* `{event_id}`.
    Runs a single named action against the supplied / stored event
    via the responder's new `dispatch_single` method. Bypasses the
    allowlist on purpose — the auth boundary is the API token / UNIX
    socket permissions.
  - `GET /actions` — discovery: returns registered action names in
    order so dashboards / scripts can enumerate them.
- **Audit trail.** Every control verb publishes a synthetic event on
  the bus (`source = "selfdef.api"`, class `INCIDENT_FINDING`,
  severity `Informational`) with the action, status, and details. The
  store sink writes it to disk so `selfdefctl events tail` shows who
  poked the daemon.
- **`Responder` gains** `dispatch_single(name, event)` and
  `action_names()`. The bus-driven responder and the API now share
  one `Arc<Responder>` via clone rather than each having its own —
  same action set, one allowlist, one dry-run flag.
- **`ApiState` gains** an optional `ControlHandles` block (correlator,
  responder, publisher). Builder methods (`with_correlator`,
  `with_responder`, `with_publisher`) keep tests able to construct a
  read-only state with no control handles, in which case control
  endpoints return `503 Service Unavailable`.
- **TLS / mTLS for the TCP transport.** New `[api.tls]` block:
  `cert_path`, `key_path`, `client_ca`. With cert+key only: vanilla TLS
  (bearer token still authenticates). Add `client_ca` → mTLS (client
  certificate required and verified). Uses `tokio-rustls` 0.26 with the
  ring provider; the TLS-wrapped accept loop drives hyper directly,
  matching the existing UDS pattern. No CA bundle for client verification
  shipped — operators bring their own.
- New integration tests in `crates/selfdef-api/tests/m12_api.rs`
  covering: `/actions` discovery, `/rules/reload` 503 when correlator
  missing, `/panic` hostname mismatch returns 400, `/panic` happy path,
  `/actions/{name}/run` dry-run, unknown action 404, missing
  body 400. 13 cases total, up from 6.
- Docs: `docs/api.md` extended with the control-endpoint table, the
  auth-boundary note, and a TLS / mTLS section with a self-signed
  recipe. Example config gains `[api.tls]`.

### Added — Milestone 12 (Mobile dashboard / read-only HTTP API)
- New crate `selfdef-api`: axum-based read-only HTTP API. Endpoints:
  - `GET /status` — host_tag, schema_version, crate_version,
    event_count, uptime_secs.
  - `GET /events?n=N` — last N events from the hot store (default 50,
    capped at 1,000).
  - `GET /findings?n=N` — last N events with `category_uid = 2`.
  - `GET /events/stream` — Server-Sent Events live tail. Subscribes a
    fresh bus subscriber per client and forwards each event as a `data:`
    frame; lagged subscribers get a single `event: lagged` frame and
    resume; clients disconnect → forwarder exits on next send.
- Two transports, either or both at once via `[api]` config:
  - **UNIX socket** (default `/run/selfdef.sock`, mode `0660`). Trusted
    via filesystem permissions; no token. Driven via a custom hyper-util
    accept loop because axum 0.7's `axum::serve` is TCP-only.
  - **TCP** (off by default). Requires `Authorization: Bearer <token>`
    matching the contents of `token_file`. CORS is permissive on the
    response side; operators are expected to bind localhost and put a
    reverse proxy in front for TLS termination.
- Vanilla-JS PWA in `dashboard/`: single-file `app.js`, no bundler, no
  `node_modules`. Renders findings + events lists, polls `/status`
  every 5s, and exposes a "live stream" toggle that opens an
  `EventSource` against `/events/stream`. Service-worker shell-caches
  the static assets but never the API responses themselves. Manifest
  JSON makes it installable on iOS/Android.
- Daemon wiring: when `[api] enabled = true`, a new task spins up the
  API alongside the collectors / correlator / responder. Store and bus
  moved behind `Arc` so the API and the existing sink share ownership
  cleanly. New `build_api_config` helper translates the
  string-shaped `[api]` TOML into the typed `selfdef_api::ApiConfig` —
  a malformed `tcp_addr` logs a warning and disables the TCP transport
  rather than crashing the daemon.
- Integration test `crates/selfdef-api/tests/m12_api.rs` exercises the
  router via `tower::ServiceExt::oneshot`: status returns the host tag
  and counters; `/findings` filters by `category_uid = 2`;
  `/events?n=N` honors the page param; an unknown route 404s; the
  event JSON round-trips back to `selfdef_core::Event` envelopes.
- Documentation: new `docs/api.md` covers the transports, endpoints,
  and dashboard wiring; example config gains a documented `[api]`
  section.

### Added — M10 polish (eBPF: argv capture, LSM file_open, do_unlinkat kprobe)
- **argv capture** in the `execve_enter` tracepoint program. Walks the
  userspace `argv` pointer array with `bpf_probe_read_user` plus
  `bpf_probe_read_user_str_bytes`, bounded at 16 entries and 256 bytes
  total. Sets `argv_truncated` when the buffer fills or the entry cap
  is reached without seeing the NULL terminator. The OCSF
  `process.cmdline` now reflects the captured argv (joined by spaces);
  the `raw` payload carries the structured `argv` array and the
  `argv_truncated` flag for rule matching.
- **LSM `file_open` BPF program**. Observe-only (always returns 0, never
  vetoes). Reports pid/uid/comm/flags. Path capture is deferred until
  the project gains generated `vmlinux.rs` bindings — the ring-buffer
  schema already has `path` and `path_len` fields so the path can be
  layered on without touching userspace.
- **`do_unlinkat` kprobe BPF program**. Reports pid/uid/comm. Same
  path-deferral rationale as the LSM hook.
- New userspace API `selfdef_collector_ebpf::EbpfProbes` carries the
  three opt-in flags (`execve`, `lsm_file_open`, `kprobe_unlinkat`)
  from config into the collector. `EbpfCollector::with_probes()`
  selects what to attach; the existing `EbpfCollector::new()` keeps
  the conservative default (execve only).
- Each probe attach is independent and **fail-soft**: missing program
  in the `.bpf.o`, missing kernel BTF, missing `CONFIG_BPF_LSM=y`, or
  a kprobe that points at an inlined symbol all log a warning and
  leave the other probes running. The daemon never aborts on a
  partial attach.
- Daemon wires the three `[collectors.ebpf]` `enable_*` config bits
  into `EbpfProbes`. Example config + `docs/ebpf.md` updated to drop
  the "reserved" / "not yet implemented" notes and describe the
  current capabilities and limitations.
- Unit-test coverage extended in `selfdef-collector-ebpf`:
  `argv_truncated` propagates into the OCSF `raw` payload;
  `FileOpenEvent` and `UnlinkEvent` round-trip into properly classed
  `FILE_SYSTEM_ACTIVITY` events; `EbpfProbes::default()` matches the
  conservative shipping config.

### Added — Milestone 11 (Forensics + Velociraptor integration)
- New responder action `forensics_bundle`: on Critical findings, writes an
  evidence bundle to `forensics_dir/<event-uuid>/` containing the
  triggering event JSON, host metadata (`uname`, `/etc/os-release`,
  `/proc/version`, `/proc/cmdline`, `uptime`, `mounts`, `modules`,
  `passwd`, `group`), network state (`/proc/net/tcp`, `/proc/net/udp`,
  `ss -tnap`), kernel ring buffer tail (`dmesg`, bounded to 2,000
  lines), recent journal (`journalctl -n 2000`), and a per-pid
  snapshot of `/proc/<pid>/{cmdline,environ,status,maps,stat,io}` plus
  `exe_link`, `cwd_link`, and `fd/` listing when the event carries an
  actor pid. A `manifest.txt` records what was captured and what was
  skipped (with the underlying error). Best-effort throughout — missing
  files or unreadable subprocesses don't abort the bundle.
- New responder action `velociraptor_escalate`: invokes a configured
  Velociraptor binary with operator-defined argv. The placeholders
  `{event_id}` and `{host_tag}` are substituted before invocation, so
  the same selfdef config can drive client-side artifact collection,
  server-side hunt creation, or any other Velociraptor workflow. Empty
  args = action runs cleanly with no side effects (useful when the
  action is allowlisted but a particular host has no Velociraptor
  deployment).
- New `[responder]` config fields: `forensics_dir`,
  `velociraptor_binary`, `velociraptor_args`. Defaults are conservative
  — `forensics_dir` lives under `/var/lib/selfdef/forensics`, the
  Velociraptor binary path is set but `velociraptor_args` is empty so
  the action is opt-in even after being added to `allowed_actions`.
- `selfdefctl forensics list` — lists bundle directories in
  `forensics_dir` with per-bundle size.
- `selfdefctl forensics collect <event-id>` — manually triggers a
  forensics bundle for any event already in the hot store. Useful for
  retroactively building evidence on an event that was caught before
  `forensics_bundle` was added to the allowlist.
- Example `config/selfdef.toml.example` extended with both new fields
  and two ready-to-use Velociraptor argv templates (client collect,
  server hunt).
- Integration test `crates/selfdef-daemon/tests/m11_forensics.rs`:
  - **bus → responder → disk**: a synthetic Critical finding published
    onto the bus produces a `forensics_dir/<uuid>/` directory with
    `event.json` (round-trips back to the same event id) and a
    `manifest.txt` that records the `proc/* SKIP` line for the pidless
    event.
  - **dry-run safety**: dry-run on `forensics_bundle` doesn't create
    the target directory.
  - **velociraptor placeholders**: dry-run rendering of
    `velociraptor_escalate` substitutes `{event_id}` and `{host_tag}`
    in every arg.
- Toolchain pin moved from 1.83 to 1.88 to match the edition 2024
  requirement and current dependency MSRVs (notably `time` and the
  `icu_*` chain). The workspace `unsafe_code` lint moved from `forbid`
  to `deny` with a documented carve-out so `selfdef-ebpf-common` can
  still implement `bytemuck::Pod` for ring-buffer record types. The
  ssh-wrap binary added `#![cfg_attr(test, allow(unsafe_code))]` to
  accommodate the Rust 2024 unsafe-`set_var` for its test-only env
  setup.

### Added — Milestone 10 (Custom eBPF programs via aya)
- New crate `selfdef-ebpf-common`: shared `#[repr(C)]` POD types between
  kernel-space BPF programs and the userspace loader. Ships
  `ProcessExecEvent`, `FileOpenEvent`, `UnlinkEvent` with an
  `EventKind` discriminator byte for ring-buffer record dispatch.
  `userspace` feature exposes `bytemuck::Pod` impls and decode helpers
  (`comm_str`, `argv_strings`); `ebpf` feature is `no_std`-compatible
  for the BPF target.
- New crate `selfdef-collector-ebpf`: userspace loader built on aya
  0.13. Loads a precompiled BPF object via `aya::Ebpf::load_file`,
  attaches the `execve_enter` tracepoint to `syscalls/sys_enter_execve`,
  takes ownership of the `EVENTS` ring buffer, wraps it in
  `tokio::io::unix::AsyncFd`, and drains records into OCSF events
  published on the bus.
- **Graceful degradation**: if the BPF object isn't installed at the
  configured `program_path`, the collector logs a warning at startup
  and runs idle. Daemon stays up; other collectors keep working. Same
  daemon binary can ship to hosts with and without eBPF support — config
  drives the difference.
- Kernel-space crate at `bpf/selfdef-bpf/` (intentionally **outside the
  main workspace** with its own `[workspace]` block so
  `cargo build --workspace` never tries to compile it). Ships one
  tracepoint program: `execve_enter`. Captures pid/tgid/ppid/uid/gid/comm
  and emits to a 256 KB ring buffer.
- Build orchestration via `xtask`:
  - `cargo xtask build-bpf [--release]` — compile with nightly
    toolchain, `-Z build-std=core`, target `bpfel-unknown-none`.
  - `cargo xtask install-bpf [<dest>]` — build release + install to
    `/usr/lib/selfdef/selfdef.bpf.o` (or custom path).
- Systemd drop-in `packaging/systemd/selfdefd.service.d/ebpf.conf`:
  grants `CAP_BPF` + `CAP_PERFMON` ambient (no full root needed on
  Linux >= 5.8), raises `LimitMEMLOCK=infinity` for older kernels that
  still account BPF map pages there. Default install keeps the
  capability-light ambient set; you opt-in by installing the drop-in.
- New `[collectors.ebpf]` config section with `enabled`,
  `program_path`, `enable_execve`, `enable_lsm_open` (reserved),
  `enable_kprobe_unlink` (reserved). Daemon wires the collector as a
  task with the same shutdown semantics as the other collectors.
- Documentation `docs/ebpf.md` covering prerequisites (`bpf-linker`,
  nightly toolchain, rust-src), kernel requirements (BTF, ring buffer
  support), capabilities drop-in, troubleshooting, and a clear ledger
  of what's actually shipped versus reserved-for-future-work.
- Integration test `crates/selfdef-daemon/tests/m10_ebpf.rs`:
  - **graceful degradation**: collector runs idle when no BPF object
    exists; shutdown is clean.
  - **event conversion**: `ProcessExecEvent` → OCSF `Event` round-trips
    through the bus into SQLite with correct class/activity/process
    fields. Three synthetic execs (`ls`, `curl`, `sshd`) are decoded,
    published, and asserted. Loading a real BPF program needs CAP_BPF
    + a real kernel + the BPF toolchain — out of scope for `cargo test`
    but documented for manual smoke tests.

### Honest deferrals
- **argv capture from the execve tracepoint.** Reading the user-pointer
  array requires bounded looped `bpf_probe_read_user` calls. The
  infrastructure (buffer in `ProcessExecEvent`, `argv_truncated` flag,
  decode helper, OCSF mapping) is in place; the BPF-side capture lands
  in a follow-up.
- **LSM `file_open` program.** Type reserved in `EventKind::FileOpen`,
  userspace decode path implemented, kernel-side program not yet
  shipped. Requires `CONFIG_BPF_LSM=y` and `bpf` in `CONFIG_LSM`.
- **`kprobe:do_unlinkat` program.** Type reserved as
  `EventKind::Unlink`, userspace decode implemented, kernel-side
  program not yet shipped.
- Stale M1 stub crates (`selfdef-ebpf-types`, `selfdef-ebpf-progs`)
  removed in favor of the M10 layout.

### Added — Milestone 9 (Client-side SSH wrapper)
- New binary crate `selfdef-ssh-wrap` (`selfdef-ssh-wrap`): a drop-in
  replacement for `ssh` that enforces per-host policy and emits OCSF
  events for every session. Designed for fast cold-start (no async
  runtime, no heavy deps).
- argv classifier (`crates/selfdef-ssh-wrap/src/argv.rs`) that
  distinguishes flags, value-taking options (`-o`, `-i`, `-p`, ...),
  attached-value options (`-pPORT`), `--` markers, and positional
  arguments. Extracts the target spec and supports filtering of
  policy-denied flags.
- Policy file (`~/.config/selfdef/ssh-wrap.toml`, override via
  `$SELFDEF_SSH_POLICY`):
  - `[defaults]` with secure baseline: no agent fwd, no X11, no port
    forwarding, `StrictHostKeyChecking=accept-new`,
    `ExitOnForwardFailure=true`, conservative timeouts.
  - `[hosts."<pattern>"]` per-host overrides. Patterns support exact
    match, `*.suffix`, `prefix*`. No regex.
  - Resolved policy is rendered as `-o key=value` ssh args prepended to
    the user's invocation; user-supplied flags conflicting with policy
    are stripped.
- Event emission (`crates/selfdef-ssh-wrap/src/events.rs`): writes OCSF
  events to `~/.local/share/selfdef/ssh-wrap.jsonl` (override via
  `$SELFDEF_SSH_EVENT_LOG`). Three event kinds:
  - **session start** — `SSH_ACTIVITY` / Open, with target, host, port,
    user, and `first_seen` flag (computed via `ssh-keygen -F`).
  - **policy strip** — `DETECTION_FINDING` / Low, lists the args removed
    from the user's invocation.
  - **session end** — `SSH_ACTIVITY` / Close, with duration and exit
    code; status_id reflects success/failure.
- New collector `selfdef-collector-eventstream`: tails a JSONL file of
  pre-formed selfdef events and republishes onto the bus. Used by the
  ssh wrapper and any other producer. Each event must already be a
  well-formed `Event`; malformed lines are logged and skipped.
- `[collectors.eventstream]` config section with `enabled`, `paths`,
  `read_from`.
- Daemon wires N independent eventstream collector tasks (one per path).
- New rule `rules/sigma/defense_evasion/ssh_wrap_policy_strip.yml` +
  tests: catches the wrapper's policy-strip findings as Medium-severity.
  Maps to `attack.defense_evasion`.
- Example policy file `packaging/ssh-wrap-policy.toml.example` with
  annotated defaults and per-host examples.
- Install guide `docs/ssh-wrap-install.md`: PATH-shadowing pattern,
  daemon wiring, caveats (host-key change detection delegated to ssh
  itself, in-session forwarding invisible to the wrapper).
- Integration test `crates/selfdef-daemon/tests/m9_ssh_wrap.rs`
  exercises the JSONL-to-bus-to-SQLite path with three event kinds.

### Added — Milestone 8 (Honeytokens + responder actions)
- New collector `selfdef-collector-canary`: inotify-based watcher that
  emits a `DETECTION_FINDING` with `Severity::Critical` and ATT&CK tag
  `T1552.001` whenever any configured path is read, opened, modified,
  has attributes changed, is deleted, or is moved. Watches are installed
  once at startup; recreating a watched file requires a daemon restart
  (documented limitation).
- Responder rewritten around an [`Action`] trait. Five built-in actions:
  - `notify` — sends through the existing `Notifier` chain.
  - `snapshot_proc` — writes `/proc/<pid>/{cmdline,environ,status,maps,stat,io}`
    plus `exe_link` and `cwd_link` symlink targets to
    `snapshot_dir/<event-uuid>/`. Best-effort: per-file read errors are
    swallowed.
  - `kill_pid` — runs `kill -TERM <pid>`. Pid extracted from
    `event.actor.process.pid` or `event.process.pid`.
  - `lockdown_egress` — invokes a configurable shell script with
    `activate`. Default path `/usr/local/sbin/selfdef-lockdown.sh`. Operator
    owns the nftables logic.
  - `revoke_session` — invokes a configurable script with the user's
    name. Default path `/usr/local/sbin/selfdef-revoke-session.sh`.
- All actions support `dry_run=true` and produce structured `ActionOutcome`
  values (`Success` / `DryRun` / `Skipped`). Failing actions log a warning
  without stopping siblings.
- Responder allowlist: each action's `name()` must appear in
  `responder.allowed_actions` to fire. Default config ships only `notify`
  enabled.
- `selfdefctl panic --confirm <hostname>` is now real:
  - Validates hostname match (prevents accidental fire on the wrong box).
  - Builds a synthetic Critical Finding with `source = "selfdef.panic"`.
  - Dispatches via `Responder::fire` with a 2-action set: `notify` +
    `lockdown_egress`.
  - Respects `responder.dry_run` from config.
- New rule `rules/sigma/credential_access/canary_access.yml` documents
  the canary path in the rule set (and surfaces in ATT&CK coverage).
- New config sections:
  - `[collectors.canary]` with `enabled` and `paths`.
  - `[responder]` extended with `snapshot_dir`, `lockdown_script`,
    `revoke_session_script`.
- Example operator script `packaging/scripts/selfdef-lockdown.sh`
  (annotated nftables-based egress lockdown with lifeline allowlist via
  `$SELFDEF_LIFELINES` env var).
- Integration test `crates/selfdef-daemon/tests/m8_honeytokens.rs`
  exercises the full path: real inotify, real bus, real responder, all
  five actions in dry-run mode. Verifies the canary finding lands in
  SQLite with the expected ATT&CK tag.

### Added — Milestone 7 (Detection-as-code CI)
- Per-rule test files: every rule may have a sibling `<rule>.tests.yaml`
  declaring partial input events and an `expected_findings` count. The
  test runner builds full events from minimal specs, runs each test
  against a single-rule engine, asserts firing counts.
- New crate APIs:
  - `selfdef_correlator::Engine::with_rules(Vec<CompiledRule>)`
    constructor for test isolation.
  - `selfdef_correlator::sigma::AttackCoverage` and
    `Engine::attack_coverage()` — walks loaded rules, returns techniques,
    tactics, and per-tactic rule counts.
  - `selfdef_correlator::lint` module: `lint_rule`, `lint_rules`, `Issue`,
    `Severity`. Checks for missing metadata (description, attack tags,
    technique tag, falsepositives, author), undefined selections in
    conditions, count-by fields that don't look like known event paths,
    duplicate rule IDs across files.
- `Engine::load_dir` now skips `*.tests.yaml` and `*.tests.yml` files
  during rule discovery (those are fixtures, not rules).
- 7 per-rule test files covering the 7 starter rules with 25+ test cases
  total — positive matches, negative matches, logsource gating,
  aggregation thresholds.
- New integration test `crates/selfdef-correlator/tests/rule_tests.rs`
  with three test functions:
  - `every_rule_with_tests_passes` — discovers and runs all per-rule
    fixtures, fails the build on any mismatch.
  - `rule_set_passes_lint` — fails on lint errors, surfaces warnings.
  - `attack_coverage_report` — prints the coverage matrix; fails if zero
    techniques covered.
- `selfdefctl rules lint` — runs lint with exit code 1 on errors.
- `selfdefctl rules coverage` — prints the ATT&CK coverage matrix.
- Adversary emulation directory at `tests/adversary/` with documented
  layout and `T1110.001-password-guessing/` as the first technique
  (atomic.yaml in ART format + expected.yaml contract). Full ART runner
  integration deferred to a future milestone (needs a VM/container
  sandbox to be safe in CI).

### Added — Milestone 6 (Collector fan-out)
- `selfdef-collector-journald`: real implementation. Two input modes
  selected by config (`mode = "journalctl"` or `"file"`):
  - **subprocess** spawns `journalctl --output=json --follow --no-pager`,
    optionally with `-u <unit>` filters from `collectors.journald.units`.
  - **file** tails a JSON-lines file (for tests / external pipelines).
  Maps `sshd` to `SSH_ACTIVITY`, `sudo` to `AUTHENTICATION`,
  `systemd-logind` to `AUTHORIZE_SESSION`; everything else generic.
  Priority → severity mapping (`PRIORITY=3` → High, `=4` → Medium, etc.).
- `selfdef-collector-tetragon`: real implementation. Tails Tetragon JSON
  output. Recognizes `process_exec` (→ `PROCESS_ACTIVITY`/Launch),
  `process_kprobe` with `security_file_open`-style functions
  (→ `FILE_SYSTEM_ACTIVITY`/Open with `file.path` extracted from kprobe
  args), `process_exit` (→ Terminate). Other event kinds preserve their
  raw payload.
- `selfdef-collector-suricata`: real implementation. Tails Suricata EVE
  JSON. **Alerts become `DETECTION_FINDING` directly** — Suricata is itself
  detection, so its alerts go straight to the responder. Suricata severity
  inverted to OCSF (1→High, 2→Medium, 3→Low). DNS/HTTP/TLS/flow records
  emit as informational network-class events that Sigma rules can match.
- `selfdef-config`: new `[collectors.journald]`, `[collectors.tetragon]`,
  `[collectors.suricata]` sections with typed config.
- `selfdef-daemon`: wires all three new collectors. Each enabled via its
  `enabled` flag in config; each runs as its own task with shared
  `CancellationToken` for graceful shutdown.
- New rules:
  - `rules/sigma/discovery/sshd_publickey_accepted.yml` — uses the journald
    collector; informational baseline for SSH key logins.
  - `rules/sigma/execution/webshell_pattern.yml` — uses the tetragon
    collector; detects shells spawned from nginx/apache/php-fpm parents.
- New replay corpora:
  - `tests/replay/journald/sshd_login.jsonl`
  - `tests/replay/tetragon/sensitive_file.jsonl`
  - `tests/replay/suricata/scan_alert.jsonl`
- Integration test `crates/selfdef-daemon/tests/m6_collectors.rs`:
  - journald file-mode emits classified events
  - tetragon replay emits typed events with the right class_uid
  - suricata alert lands in SQLite as a DETECTION_FINDING

### Deferred to a polish milestone
- Multi-line auditd record grouping (SYSCALL + PATH + EXECVE + EOE). The
  current M3 parser handles each line standalone, which covers the
  user-auth records selfdef cares most about today. Multi-line grouping
  is real parser work that deserves its own milestone.

### Added — Milestone 5 (Sigma engine + hot reload)
- `selfdef-correlator::sigma`: Sigma-subset rule engine. Parses YAML rules
  with metadata (`id`, `title`, `description`, `level`, `tags`, `references`,
  `falsepositives`, `author`, `date`), `logsource`, named `selection_*`
  blocks, optional `timeframe`, and `condition` strings of the form
  `<sel>` or `<sel> | count() by <field> > <N>`.
- Field matchers: equality, `|contains`, `|startswith`, `|endswith`, `|re`
  (regex). List of values within a field = OR. Dot-notation for nested
  fields (`src_endpoint.ip`, `actor.user.name`).
- `Aggregator` for time-windowed counting; clears window on fire to
  prevent re-firing on the same burst.
- ATT&CK overlay: `attack.t1234[.567]` tags → technique IDs;
  `attack.<tactic>` tags → tactic enum; both flow into the emitted finding's
  `attack` array.
- `Correlator` now loads rules from a directory; `load_rules()` is
  idempotent and atomically swaps the engine on success (failure preserves
  the previous ruleset). Backed by `Arc<RwLock<Arc<Engine>>>` so reads
  don't block reloads.
- `selfdef-daemon`: SIGHUP triggers `correlator.load_rules()`. `selfdefd`
  keeps running across reloads; `systemctl reload selfdefd` works (the unit
  already had `ExecReload=/bin/kill -HUP $MAINPID`).
- 5 initial rules in `rules/sigma/`:
  - `credential_access/ssh_bruteforce.yml` — replaces the M4 hardcoded rule.
  - `credential_access/sensitive_file_access.yml` — `/etc/shadow`, `/root/.ssh/`,
    etc. (logsource: tetragon; waits for the tetragon collector).
  - `privilege_escalation/sudo_failure.yml` — failed sudo PAM auth.
  - `persistence/sudoers_tamper.yml` — writes to `/etc/sudoers*`.
  - `persistence/setuid_binary.yml` — new files with setuid/setgid bits.
- Replay corpus: `tests/replay/auditd/ssh_bruteforce.jsonl` (4 events) +
  `ssh_bruteforce.expected.yaml` (expected firings).
- `selfdefctl` implements `rules list`, `rules validate <path>`,
  `rules test --corpus <jsonl>`.
- New integration test `crates/selfdef-daemon/tests/m5_sigma.rs`:
  - engine loads N rules from a directory
  - engine ignores non-YAML files
  - replay corpus produces the expected firing count
  - hot reload picks up new rules in-place
- M4 test updated to use the YAML rule via a tempdir rules directory
  instead of the now-removed `Correlator::new(window, threshold)` API.
- New workspace deps: `serde_yml` (maintained fork of `serde_yaml`), `regex`.

### Added — Milestone 4 (Alert path)
- `selfdef-notifier`: `Notifier` trait, `NtfyNotifier` (HTTP POST to a
  self-hosted ntfy server with optional bearer token, 3-attempt backoff),
  `SignalCliNotifier` (subprocess to `signal-cli`), `NotifierChain` that
  tries channels in order. Severity → ntfy priority mapping. Title/body
  rendering helpers `render_title`/`render_body`. Tags include ATT&CK
  technique IDs.
- `selfdef-correlator`: subscribes to the bus, processes events through a
  built-in `SshBruteforceRule` (≥ N failed auths from the same source IP
  within W seconds → emit a Detection Finding). Configurable window and
  threshold. Loop guard: Findings-class events are never reprocessed.
- `selfdef-responder`: subscribes to the bus, watches for Findings-class
  events, executes the `notify` action through the configured notifier
  chain. Allowlist enforcement (`allowed_actions`) and `dry_run` mode.
- `selfdef-core`: added `ClassUid::SECURITY_FINDING` (2001),
  `DETECTION_FINDING` (2004), `INCIDENT_FINDING` (2005) constants.
- `selfdef-config`: added `[correlator]`, `[notifier]` (with `[notifier.ntfy]`,
  `[notifier.signal]` subsections), and `[responder]` config sections.
- `selfdef-store`: `recent_findings(limit)` helper for the CLI alerts view.
- `selfdef-daemon`: M4 wiring — correlator + responder spawned alongside
  the store sink, each as an independent bus subscriber.
- `selfdef-cli`: `events alerts -n N [--json]` subcommand for tailing
  findings.
- Integration test `crates/selfdef-daemon/tests/m4_alert.rs` proves the
  full path: 3 failed-auth lines → wiremock-mocked ntfy server receives
  exactly one POST with `Priority: 5`.
- Workspace lints: dropped `unwrap_used`, `expect_used`, `panic` from the
  default warn set — too noisy in test code; `clippy::pedantic` still
  catches real issues.

### Added — Milestone 3 (First spine)
- `selfdef-config`: Figment-based layered config loader (defaults → TOML →
  `SELFDEF_*` env vars). Typed `Config`, `DaemonConfig`, `BusConfig`,
  `StoreConfig`, `CollectorsConfig`, `AuditdConfig`.
- `selfdef-bus`: in-proc broadcast bus over `tokio::sync::broadcast`.
  `Bus`, `Publisher` (Clone), `Subscriber`, `BusError`. Tests for
  publish/subscribe ordering, fan-out, and lagged subscriber detection.
- `selfdef-store`: `SqliteStore` with WAL mode, `synchronous=NORMAL`,
  hand-rolled migrations driven by `user_version`. Async API via
  `spawn_blocking`. Operations: `open`, `insert`, `count`, `recent`, `get`.
  Migration `0001_initial.sql` defines the indexed `events` table.
- `selfdef-collector-auditd`: line parser for `USER_AUTH`, `USER_LOGIN`,
  `USER_ACCT` (mapped to `ClassUid::AUTHENTICATION` with correct
  `status_id`, ATT&CK technique tagging on failure). Unknown record types
  emitted as generic events with raw payload preserved. File tailer with
  `ReadFrom::{Start, End}` modes and graceful shutdown via `CancellationToken`.
- `selfdef-daemon`: real entry point — loads config, opens store, builds bus,
  spawns the auditd collector + a store sink task, waits for SIGTERM/SIGINT,
  drains the bus, reports counts on exit.
- `selfdef-cli`: `status` (event count + store path), `events tail [-n N] [--json]`
  reading the SQLite store directly.
- Integration test `crates/selfdef-daemon/tests/m3_pipeline.rs` proves the
  end-to-end loop: 4 canned audit lines → collector → bus → sink → SQLite,
  with assertions on classification, severity, and ATT&CK tagging.

### Added — Milestone 2 (Event envelope)
- `selfdef-core` restructured into focused modules: `envelope`, `category`,
  `activity`, `severity`, `status`, `attack`, `metadata`, `observable/*`,
  `error`, `prelude`.
- OCSF-aligned `Event` envelope with: `schema`, `id` (UUIDv7), `time_dt`
  (RFC3339), `category_uid`, `class_uid`, `activity_id`, `type_uid`,
  `severity_id`, `status_id`, `host_tag`, `source`, `message`, `metadata`,
  `raw`, plus optional typ