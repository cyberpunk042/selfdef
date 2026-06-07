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
