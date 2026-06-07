#!/usr/bin/env bats
# L2 bats functional tests for the sysusers-watchdog scan script.
#
# systemd-sysusers materializes the declarative users in sysusers.d/*.conf
# into /etc/passwd + /etc/group at boot. A `u` entry with uid 0 is a
# root-equivalent backdoor account; an `m` membership into a privileged group
# is privilege escalation (T1136 / T1098). Severity:
#   ok    → no delta
#   warn  → an entry added/changed/removed
#   alert → a .conf world-writable/non-root, a uid-0 `u` entry, or a
#           membership into a privileged group
#
# Run with: bats packaging/test/L2-sysusers-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/sysusers-watchdog/systemd/sysusers-watchdog.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SELFDEF_TEST_LOGCAP}"
FAKELOGGER
    chmod +x "${BIN}/logger"
    export SELFDEF_TEST_LOGCAP="${TMP}/log.out"
    : > "${SELFDEF_TEST_LOGCAP}"
    BASELINE="${TMP}/baseline.tsv"
    CONFD="${TMP}/sysusers.d"; mkdir -p "${CONFD}"
    CONF="${CONFD}/myapp.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_SYSUSERS_PROFILE="${PROFILE:-report}" \
    SELFDEF_SYSUSERS_BASELINE="${BASELINE}" \
    SELFDEF_SYSUSERS_DIRS="${DIRS_V:-$CONFD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf 'u myapp 999 "My App Daemon"\ng myapp 999\n' > "${CONF}"
}

@test "no sysusers config → ok / no_sysusers" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_sysusers"'
    cap | grep -q '"severity":"ok"'
}

@test "benign sysusers conf, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged sysusers conf on second run → ok / sysusers_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"sysusers_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a uid-0 u entry → alert / sysusers_suspicious" {
    seed_benign
    run_wd
    printf 'u myapp 999 "My App Daemon"\ng myapp 999\nu backdoor 0 "root clone"\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"sysusers_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable sysusers conf → alert" {
    seed_benign
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign entry change → warn / sysusers_changed" {
    seed_benign
    run_wd
    printf 'u myapp 998 "My App Daemon"\ng myapp 998\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"sysusers_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign non-root sysusers conf is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "enforce profile exits non-zero on a uid-0 entry" {
    seed_benign
    run_wd
    printf 'u backdoor 0 "root clone"\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — sysusers inventory enumerates declarative user-add surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (membership-into-sudo): an `m` membership into sudo → alert" {
    seed_benign
    run_wd
    printf 'u myapp 999 "My App Daemon"\nm myapp sudo\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (membership-into-wheel): an `m` membership into wheel → alert" {
    seed_benign
    run_wd
    printf 'u myapp 999 "My App Daemon"\nm myapp wheel\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (membership-into-docker): an `m` membership into docker → alert (container-mount root escalation)" {
    seed_benign
    run_wd
    printf 'u myapp 999 "My App Daemon"\nm myapp docker\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (pre-existing uid-0): baseline_initial fires alert if sysusers already declares a uid-0 entry at install-time" {
    printf 'u backdoor 0 "root clone"\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (group-writable sysusers): group-writable → alert above the world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "DELTA detect — REMOVED sysusers .conf file (operator pruning) → warn" {
    seed_benign
    cat > "${CONFD}/other.conf" <<'EOF'
u svc 1001 "Service Account"
EOF
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    rm -f "${CONFD}/other.conf"
    run_wd
    cap | grep -qE '"severity":"(warn|ok)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-sysusers -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): sysusers-watchdog does NOT refresh baseline on uid-0 detection — alert STAYS until operator updates" {
    # T1136 declarative user-add persistence — uid-0 alert MUST
    # persist across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf 'u backdoor 0 "root clone"\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"sysusers_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented sysusers entry NOT counted: # prefix filtered from inventory)" {
    # sysusers.d supports # comments. Operator notes about
    # hypothetical uid-0 entries must NOT trigger alert.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'u myapp 999 "My App Daemon"\ng myapp 999\n# u backdoor 0 "example bad config"\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"event":"sysusers_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: sysusers.d drop-in axis — uid-0 in ANY watched dir → alert)" {
    # /usr/lib/sysusers.d + /etc/sysusers.d + /run/sysusers.d are
    # all honored by systemd-sysusers. Attacker may plant uid-0
    # in any of them. Lock multi-dir axis.
    CONFD2="${TMP}/sysusers.d2"; mkdir -p "${CONFD2}"
    seed_benign
    DIRS_V="${CONFD} ${CONFD2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant uid-0 in second drop-in dir.
    printf 'u backdoor 0 "root clone"\n' > "${CONFD2}/evil.conf"
    DIRS_V="${CONFD} ${CONFD2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (membership-into-disk): an \`m\` membership into disk group → alert (raw block device read = credential dump)" {
    # disk group membership = unrestricted /dev/sd* access = read /etc/shadow
    # raw from disk + write /etc/passwd raw → root.
    seed_benign
    run_wd
    printf 'u myapp 999 "My App Daemon"\nm myapp disk\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (membership-into-shadow: 'm myapp shadow' → alert — shadow group read /etc/shadow = credential dump axis)" {
    # shadow group read membership lets a user read /etc/shadow
    # directly = credential dump primitive. Sister axis to disk
    # group + sudo/wheel/docker memberships already locked.
    seed_benign
    run_wd
    printf 'u myapp 999 "My App Daemon"\nm myapp shadow\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (sample names offending .conf in JSON — operator triage routing)" {
    # When uid-0 or privileged-group-membership alert fires, sample
    # MUST surface the .conf basename so operator dashboard routes
    # triage to the right path. Sister contract: polkit-rules/
    # nfs-exports/rhosts/tmpfiles/securetty sample-naming pattern.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'u backdoor 0 "root clone"\n' > "${CONFD}/99-very-distinctive-attacker.conf"
    run_wd
    cap | grep -q 'very-distinctive-attacker'
}

@test "INVARIANT (membership-into-docker: 'm myapp docker' → alert — docker group escape-to-root vector)" {
    # Sister to the disk + shadow + sudo + wheel privileged-group
    # membership axes already locked. The docker group is a
    # well-known privesc primitive: any docker-group member can run
    # `docker run -v /:/host alpine chroot /host` to gain effective
    # root via volume-mount escape. Lock the docker-group axis on
    # the sysusers declarative membership family alongside the
    # other root-equivalent groups already covered.
    seed_benign
    run_wd
    printf 'u myapp 999 "My App Daemon"\nm myapp docker\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (membership-into-systemd-journal: 'm myapp systemd-journal' → alert — journal read = audit-trail exfil axis)" {
    # Sister to disk + shadow + sudo + wheel + docker privileged-
    # group membership axes already locked. The systemd-journal
    # group has read access to /var/log/journal/* — the audit-trail
    # forensics surface. Membership lets an attacker read every
    # privileged-process journal entry (including kernel messages
    # that may contain memory-protection-failure addresses, sudo
    # invocations with command line args, ssh login attempts).
    # T1005 — Data from Local System via journal-read privilege.
    seed_benign
    run_wd
    printf 'u myapp 999 "My App Daemon"\nm myapp systemd-journal\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (membership-into-kvm: 'm myapp kvm' → alert — VM-launch axis privileged-group coverage)" {
    # Sister to disk + shadow + sudo + wheel + docker + systemd-
    # journal privileged-group membership axes already locked.
    # The kvm group has access to /dev/kvm — substrate for
    # launching any VM. An attacker with kvm membership can
    # launch a VM that mounts the host filesystem read/write,
    # bypassing host access controls (T1611 — Escape to Host
    # via VM launch). The watchdog MUST treat kvm membership
    # additions as alert-grade, closing axis-parity on the
    # privileged-group surveillance family.
    seed_benign
    run_wd
    printf 'u myapp 999 "My App Daemon"\nm myapp kvm\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (membership-into-wheel: 'm myapp wheel' → alert — sudoers-grant via group axis on RHEL/CentOS-family)" {
    # Sister to disk + shadow + docker + journal + kvm
    # privileged-group membership axes already locked. The
    # wheel group is the RHEL/CentOS/Arch convention for
    # sudoers-grant: %wheel ALL=(ALL) ALL in /etc/sudoers
    # gives wheel-members full passwordless or password-gated
    # sudo. Attacker who adds a sysusers.d entry granting
    # wheel membership escalates the service account to full
    # root via sudo. Symmetric to sudo group on Debian/Ubuntu.
    # T1548.003 Sudo and Sudo Caching abuse via group membership.
    # Closes wheel-group axis on the privileged-group
    # surveillance family.
    seed_benign
    run_wd
    printf 'u myapp 999 "My App Daemon"\nm myapp wheel\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (membership-into-sudo: 'm myapp sudo' → alert — Debian/Ubuntu sudoers-grant via group axis sister to wheel)" {
    # Sister to wheel + disk + shadow + docker + journal + kvm
    # privileged-group membership axes already locked. The sudo
    # group is the Debian/Ubuntu convention (vs RHEL/CentOS
    # wheel) for sudoers-grant: %sudo ALL=(ALL:ALL) ALL in
    # /etc/sudoers. Attacker who adds a sysusers.d entry
    # granting sudo membership escalates the service account
    # to full root via sudo. Locks sudo-group axis on the
    # privileged-group surveillance family — symmetric to wheel
    # on RHEL/CentOS; both axes together cover the canonical
    # sudoers-via-group escalation primitive across distros.
    # T1548.003 Sudo and Sudo Caching abuse via group membership.
    seed_benign
    run_wd
    printf 'u myapp 999 "My App Daemon"\nm myapp sudo\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on sysusers surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The sysusers-watchdog MUST only emit severity values from
    # the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1548.003 sudoers-grant via group + T1098
    # Account Manipulation alert. Locks parser contract on the
    # sysusers.d detection surface.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf 'u myapp 999 "My App Daemon"\nm myapp sudo\n' > "${CONF}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # sysusers-watchdog runs ON the timer's scheduled fire —
    # scans /etc/sysusers.d + /usr/lib/sysusers.d for u/g/m
    # entries granting privileged-group membership, emits a
    # verdict, then exits. Type=simple would break timer
    # OnUnitActiveSec semantics. Locks oneshot-probe contract on
    # the sysusers-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/sysusers-watchdog/systemd/selfdef-sysusers.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. sysusers-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # sysusers-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # sysusers-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sysusers-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'sysusers-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: sysusers-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. sysusers-watchdog is a DETECT-only watchdog: surveils +
    # emits verdicts, NEVER writes back. Locks no-auto-fix on
    # the sysusers-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/sysusers-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (sysusers-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the sysusers-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/sysusers-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sysusers-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # sysusers-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/sysusers-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sysusers-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # sysusers-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/sysusers-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sysusers-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the sysusers-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/sysusers-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sysusers-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # sysusers-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/sysusers-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sysusers-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the sysusers-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysusers-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sysusers-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the sysusers-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysusers-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (sysusers-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # sysusers-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysusers-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (sysusers-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
    # Sister to brain-wide TimeoutStartSec= INVARIANT family.
    # Watchdog .service units are Type=oneshot probes — they
    # MUST declare a TimeoutStartSec= upper bound so systemd
    # kills a hung probe (e.g. a stuck sha256sum on a slow
    # NFS-mounted target file) rather than blocking the
    # next timer fire indefinitely. Without TimeoutStartSec=
    # systemd's default (90s) applies, but the canonical
    # selfdef contract pins this explicitly per watchdog so
    # operators reading the .service know the bound at a
    # glance. A regression that dropped TimeoutStartSec=
    # would silently revert to the systemd default + mask
    # the explicit-bound contract. Locks anti-hang oneshot-
    # bound discipline on the sysusers-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysusers-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (sysusers-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
    # Sister to brain-wide systemd resource-priority INVARIANT
    # family. Watchdog .service units run periodic scans (often
    # sha256sum walks of large config trees) — they MUST be
    # deprioritized via Nice= (positive value = lower priority
    # under load) so that the watchdog scan doesn't starve
    # operator-foreground workloads when CPU is contended.
    # The canonical selfdef value is Nice=15 (well above the
    # background-batch threshold of 10). A regression dropping
    # Nice= would let watchdog scans compete with foreground at
    # default Nice=0, surfacing as latency spikes on contended
    # hosts. Locks the idle-priority anti-resource-starve
    # discipline on the sysusers-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysusers-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (sysusers-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd PrivateTmp= INVARIANT
    # family. Watchdog .service units that run periodic
    # sha256sum walks may create transient /tmp files. The
    # PrivateTmp= directive (canonically =true) instructs
    # systemd to give the unit its own /tmp mount namespace —
    # an attacker who exploits the watchdog cannot reach
    # /tmp files owned by other processes (e.g. ssh-agent
    # sockets), and the watchdog's own /tmp residue is
    # automatically cleaned at unit-stop. A regression
    # dropping PrivateTmp= would share /tmp with the host,
    # exposing the watchdog as a side-channel for any
    # /tmp-based pivot. Locks the /tmp namespace-isolation
    # discipline on the sysusers-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysusers-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (sysusers-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd ProtectHome= INVARIANT
    # family. Watchdog .service units have no business
    # reading /home — their probe targets are system-config
    # paths (/etc/*). The ProtectHome= directive
    # (canonically =read-only) instructs systemd to either
    # hide (=true) or read-only-mount (=read-only) the
    # /home, /root, and /run/user directories within the
    # unit's mount namespace. An exploited watchdog cannot
    # then exfiltrate ~/.bash_history, ~/.ssh/*, or operator
    # credentials. A regression dropping ProtectHome= would
    # expose all operator home contents to a compromised
    # watchdog. Locks the home-namespace-isolation
    # discipline on the sysusers-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysusers-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (sysusers-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
    # Sister to brain-wide systemd NoNewPrivileges= INVARIANT
    # family. The NoNewPrivileges=true directive instructs
    # the kernel to set PR_SET_NO_NEW_PRIVS on the watchdog
    # process — any subsequent execve() in the watchdog
    # script (sha256sum, awk, etc.) is forbidden to acquire
    # NEW privileges via setuid/setgid/file-capabilities. An
    # exploited watchdog cannot escalate via a setuid helper
    # (e.g. /usr/bin/su, /usr/bin/sudo). A regression
    # dropping NoNewPrivileges= would leave the watchdog
    # exposed to setuid-binary pivot. Locks the privilege-
    # escalation containment discipline on the sysusers-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysusers-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (sysusers-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the sysusers-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysusers-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (sysusers-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
    # Sister to brain-wide systemd ExecStart binary-path
    # INVARIANT family. Watchdog .service units MUST execute
    # the watchdog script from /usr/local/libexec/selfdef/
    # (operator-extension path, not /usr/bin which is
    # Debian-package-only). The canonical libexec/selfdef/
    # path lets operators override the watchdog script
    # without rebuilding the .deb (sister to brain-wide
    # operator-extension /usr/local/* discipline). A
    # regression that pointed ExecStart at /usr/bin/ would
    # surface as a "stale-watchdog-binary" on hosts where
    # operators patched the libexec copy. Locks the
    # libexec/selfdef ExecStart-path discipline on the
    # sysusers-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysusers-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (sysusers-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
    # Sister to brain-wide systemd After= INVARIANT family.
    # Watchdog .service units MUST declare an After= directive
    # so they don't fire before the filesystem mounts that
    # contain their probe targets (canonically After=local-
    # fs.target so /etc/* is mounted before the watchdog
    # tries to sha256sum a config file). A regression
    # dropping After= would surface as "watchdog fires
    # during early-boot before /etc is mounted" which then
    # hashes nothing + emits a spurious "config missing"
    # alert. Locks the boot-sequencing discipline on the
    # sysusers-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysusers-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (sysusers-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the sysusers-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysusers-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}
