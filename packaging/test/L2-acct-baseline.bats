#!/usr/bin/env bats
# L2 functional suite for acct-baseline.
#
# acct-baseline provisions process accounting (BSD-style acct):
#   - Creates /var/account/ + pacct file (mode 0640 root:root)
#   - Installs a logrotate drop-in to roll pacct daily/weekly
#   - enabled profile: accton on /var/account/pacct + enables
#     acct.service / psacct.service (distro-dependent)
#   - disabled profile: accton off + leaves the logrotate drop-
#     in installed (operator can re-enable later without
#     re-touching the rotate config)
#
# Adds SELFDEF_ACCT_DIR + SELFDEF_PACCT_FILE + SELFDEF_LOGROTATE_DIR
# env-var overrides for L2 testability (ACCT_DIR added 2026-06-06).
# Live defaults unchanged.
#
# Run with: bats packaging/test/L2-acct-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/accton" <<'ACEOF'
#!/usr/bin/env bash
printf 'accton %s\n' "$*" >> "${ACCT_LOG}"
exit 0
ACEOF
    chmod +x "${BIN}/accton"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export ACCT_LOG="${TMP}/accton.log"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${ACCT_LOG}"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/acct-baseline.toml"
    ACCT_DIR="${TMP}/account"
    PACCT_FILE="${ACCT_DIR}/pacct"
    LOGROTATE_DIR="${TMP}/logrotate.d"
    LOGROTATE_DST="${LOGROTATE_DIR}/selfdef-acct"
    mkdir -p "${LOGROTATE_DIR}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    ACCT_LOG="${ACCT_LOG}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_ACCT_CONFIG="${CONF}" \
    SELFDEF_ACCT_DIR="${ACCT_DIR}" \
    SELFDEF_PACCT_FILE="${PACCT_FILE}" \
    SELFDEF_LOGROTATE_DIR="${LOGROTATE_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_ACCT_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_ACCT_CONFIG="${SELFDEF_ACCT_CONFIG}" \
        SELFDEF_ACCT_DIR="${ACCT_DIR}" \
        SELFDEF_PACCT_FILE="${PACCT_FILE}" \
        SELFDEF_LOGROTATE_DIR="${LOGROTATE_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_ACCT_CONFIG="${CONF}" \
        SELFDEF_ACCT_DIR="${ACCT_DIR}" \
        SELFDEF_PACCT_FILE="${PACCT_FILE}" \
        SELFDEF_LOGROTATE_DIR="${LOGROTATE_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be enabled|disabled"* ]]
}

@test "enabled profile creates ACCT_DIR + pacct file + installs logrotate drop-in" {
    write_config "enabled"
    run_wd
    [ -d "${ACCT_DIR}" ]
    [ -f "${PACCT_FILE}" ]
    [ -f "${LOGROTATE_DST}" ]
}

@test "enabled profile fires accton on <pacct> AND enables the OS service" {
    write_config "enabled"
    run_wd
    grep -qE "accton ${PACCT_FILE}" "${ACCT_LOG}"
    # Tries acct.service first; falls back to psacct (distro-aware).
    grep -qE 'systemctl enable --now (acct|psacct)' "${SYSEOF_LOG}"
}

@test "disabled profile fires accton off (no <pacct> arg) AND does NOT touch the OS service" {
    write_config "disabled"
    run_wd
    grep -q 'accton off' "${ACCT_LOG}"
    ! grep -q 'systemctl enable' "${SYSEOF_LOG}"
}

@test "disabled profile STILL installs the logrotate drop-in (operator-pull re-enable)" {
    write_config "disabled"
    run_wd
    [ -f "${LOGROTATE_DST}" ]
}

@test "logrotate drop-in is chmod 0644 (system-config convention)" {
    write_config "enabled"
    run_wd
    [ "$(stat -c '%a' "${LOGROTATE_DST}")" = "644" ]
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite logrotate drop-in" {
    write_config "enabled"
    run_wd
    [ -f "${LOGROTATE_DST}" ]
    mtime_before="$(stat -c '%Y' "${LOGROTATE_DST}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${LOGROTATE_DST}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: profile switch enabled → disabled changes accton arg + leaves logrotate drop-in intact" {
    write_config "enabled"
    run_wd
    [ -f "${LOGROTATE_DST}" ]
    logrotate_mtime_before="$(stat -c '%Y' "${LOGROTATE_DST}")"
    : > "${ACCT_LOG}"
    sleep 1
    write_config "disabled"
    run_wd
    grep -q 'accton off' "${ACCT_LOG}"
    [ -f "${LOGROTATE_DST}" ]
    # logrotate file unchanged (no re-install needed across profile switch).
    logrotate_mtime_after="$(stat -c '%Y' "${LOGROTATE_DST}")"
    [ "${logrotate_mtime_before}" = "${logrotate_mtime_after}" ]
}

@test "INVARIANT: DRY_RUN does not write pacct, logrotate drop-in, or fire accton/systemctl" {
    write_config "enabled"
    DRY_RUN=1 run_wd
    ! [ -f "${PACCT_FILE}" ]
    ! [ -f "${LOGROTATE_DST}" ]
    ! grep -q 'accton' "${ACCT_LOG}"
    ! grep -q 'systemctl' "${SYSEOF_LOG}"
}

@test "default profile is enabled (no profile key — captures process accounting by default)" {
    : > "${CONF}"
    run_wd
    [ -f "${PACCT_FILE}" ]
    grep -qE "accton ${PACCT_FILE}" "${ACCT_LOG}"
}

@test "emit_status reports changes count + pacct path in JSON" {
    write_config "enabled"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'changes=1'* ]]
    [[ "${output}" == *"pacct=${PACCT_FILE}"* ]]
    # Second apply: logrotate unchanged → changes=0.
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'changes=0'* ]]
}

@test "INVARIANT (profile reverse disabled → enabled): fires accton on + re-enables service" {
    write_config "disabled"
    run_wd
    : > "${ACCT_LOG}"
    : > "${SYSEOF_LOG}"
    write_config "enabled"
    run_wd
    grep -qE "accton ${PACCT_FILE}" "${ACCT_LOG}"
    grep -qE 'systemctl enable --now (acct|psacct)' "${SYSEOF_LOG}"
}

@test "INVARIANT (pacct file chmod 0640 — root + adm-group readable, NOT world-readable)" {
    # pacct contains process-history with command names + args + exit
    # codes — sensitive on a multi-user system. Lock 0640.
    write_config "enabled"
    run_wd
    [ "$(stat -c '%a' "${PACCT_FILE}")" = "640" ]
}

@test "INVARIANT (ACCT_DIR chmod 0750 — root + adm-group can list, NOT world-listable)" {
    write_config "enabled"
    run_wd
    [ "$(stat -c '%a' "${ACCT_DIR}")" = "750" ]
}

@test "INVARIANT (logrotate drop-in references /var/account/pacct — the canonical pacct path)" {
    # The drop-in is shipped as a fixture (modules/acct-baseline/systemd/
    # selfdef-acct.logrotate) with /var/account/pacct hard-coded. This
    # is intentional: logrotate config refs the canonical live path, not
    # the (test-overridable) PACCT_FILE env var.
    write_config "enabled"
    run_wd
    grep -q '/var/account/pacct' "${LOGROTATE_DST}"
}

@test "INVARIANT (logrotate drop-in carries the actual rotate directive)" {
    write_config "enabled"
    run_wd
    grep -qE '^[[:space:]]*(daily|weekly|monthly)' "${LOGROTATE_DST}"
}

@test "INVARIANT (no render-timestamp in logrotate drop-in): defeats cmp -s idempotency" {
    write_config "enabled"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${LOGROTATE_DST}"
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates pacct file + ACCT_DIR + logrotate drop-in)" {
    write_config "enabled"
    run_wd
    [ -f "${PACCT_FILE}" ]
    [ -d "${ACCT_DIR}" ]
    [ -f "${LOGROTATE_DST}" ]
    rm -rf "${ACCT_DIR}"
    rm -f "${LOGROTATE_DST}"
    run_wd
    [ -d "${ACCT_DIR}" ]
    [ -f "${PACCT_FILE}" ]
    [ -f "${LOGROTATE_DST}" ]
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "enabled"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"acct-baseline"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=enabled'* ]]
}

@test "INVARIANT (logrotate drop-in carries compress + missingok + notifempty — operator-standard rotation directives)" {
    # The drop-in must implement proper rotation safety:
    # compress (saves disk), missingok (no rotate-bail if log absent),
    # notifempty (skip zero-byte rotations). Lock against rotation-
    # config drift to operator-unfriendly defaults.
    write_config "enabled"
    run_wd
    grep -qE 'compress' "${LOGROTATE_DST}"
    grep -qE 'missingok' "${LOGROTATE_DST}"
    grep -qE 'notifempty' "${LOGROTATE_DST}"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # TOML; parser must tolerate without altering the profile-gated
    # behavior. enabled-with-noise still fires accton on; disabled-
    # with-noise still fires accton off.
    cat > "${CONF}" <<'TOMLEOF'
profile = "enabled"
operator_note = "process accounting tier-1 substrate"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    grep -qE "accton ${PACCT_FILE}" "${ACCT_LOG}"
    [ -f "${LOGROTATE_DST}" ]
}

@test "INVARIANT (logrotate drop-in carries rotation-count directive — defines retention window)" {
    # Beyond just daily/weekly/monthly + compress + missingok +
    # notifempty already locked, the drop-in must declare a 'rotate
    # N' count directive that defines the retention window (default
    # would otherwise be 4 weeks, may be too short for forensic
    # window in incident investigation). Locks against drift to a
    # too-short retention. Sister to other rotation-directive
    # INVARIANTs (rsyslog-tune, journal-tune, audit-rules retention).
    write_config "enabled"
    run_wd
    grep -qE '^[[:space:]]*rotate[[:space:]]+[0-9]+' "${LOGROTATE_DST}"
}

@test "INVARIANT (logrotate drop-in carries selfdef self-identifying header — head -1 stale-cleanup discipline)" {
    # Sister to many other installer module's header-marker
    # INVARIANT across the brain (ssh-hardening / journal-tune /
    # slm-cpu-loop / tensor-parallel-inference / hardware-tune-
    # cache). The drop-in lands at /etc/logrotate.d/selfdef-acct
    # alongside operator-hand-authored / packaging-provided
    # logrotate drop-ins (cron, syslog, etc.). A stale-cleanup
    # pass (operator housekeeping or uninstall path) inspects the
    # first non-blank comment line to identify selfdef-rendered
    # config from operator config. Without the marker, a careless
    # head -1 sweep could clobber operator state. Locks the
    # provenance contract on the BSD-style process accounting
    # surface.
    write_config "enabled"
    run_wd
    first_nonblank="$(grep -E -m1 -v '^[[:space:]]*$' "${LOGROTATE_DST}")"
    [[ "${first_nonblank}" == *"selfdef"* ]]
}

@test "INVARIANT (logrotate drop-in carries postrotate accton-restart — without it accton continues writing to the rotated/compressed file)" {
    # Process-accounting via accton holds an OPEN file descriptor
    # against /var/account/pacct. logrotate moves the file but the
    # kernel keeps the FD valid against the rotated inode — accton
    # continues appending to what becomes pacct.1.gz (broken).
    # Without an accton off/on cycle in postrotate, ALL rotated
    # entries land in the wrong file, and the forensic window
    # silently corrupts. Locks rotation-correctness for the
    # accton FD-holding surface. Sister to logrotate
    # rotation-directive INVARIANTs (compress/missingok/notifempty/
    # rotate N) — those define WHEN to rotate; postrotate accton
    # defines that rotation actually works.
    write_config "enabled"
    run_wd
    grep -qE 'postrotate' "${LOGROTATE_DST}"
    grep -qE 'accton[[:space:]]+off' "${LOGROTATE_DST}"
    grep -qE 'accton[[:space:]]+on' "${LOGROTATE_DST}"
    grep -qE 'endscript' "${LOGROTATE_DST}"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO logrotate drop-in written AND NO accton fires when DRY_RUN=1)" {
    # Sister to brain-wide installer DRY_RUN INVARIANTs. The
    # acct-baseline DRY_RUN path MUST be a no-op against live
    # state — operator using --dry-run expects ZERO mutations
    # (no rendered drop-in, no live accton command fires).
    write_config "enabled"
    rm -f "${LOGROTATE_DST}"
    : > "${ACCT_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${LOGROTATE_DST}" ]
    ! grep -qE 'accton' "${ACCT_LOG}"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on acct-baseline installer surface
    # across pacct-file + ACCT_DIR + logrotate-drop-in phases.
    write_config "enabled"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"acct-baseline"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (logrotate drop-in chmod 0644 — logrotate.d sourcing convention; world-readable required for logrotate to parse)" {
    # Sister to brain-wide drop-in chmod 0644 INVARIANTs across
    # L2 suites. The acct-baseline logrotate drop-in lives in
    # /etc/logrotate.d/selfdef-acct-baseline and MUST be world-
    # readable mode 0644 because logrotate is invoked by cron
    # AS ROOT but the SELinux/AppArmor profile around logrotate
    # may drop capabilities — mode 0600 would defeat the
    # canonical logrotate.d sourcing semantics on hardened
    # deployments. Locks file-mode contract on the acct-baseline
    # logrotate.d drop-in substrate.
    write_config "enabled"
    run_wd
    [ -f "${LOGROTATE_DST}" ]
    mode="$(stat -c '%a' "${LOGROTATE_DST}")"
    [ "${mode}" = "644" ]
}

@test "INVARIANT (no auto-uninstall: acct-baseline NEVER emits package-remove commands on acct/psacct)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The acct-baseline installer enables process
    # accounting via accton + ships logrotate drop-in but MUST
    # NEVER emit shell commands that uninstall the acct/psacct
    # package itself (apt/dpkg/dnf/rpm/yum remove|purge|
    # uninstall acct|psacct). Silent auto-removal would tear
    # down the process-accounting audit-trail entirely —
    # operator's pacct/wtmp records would not be written.
    # T1562.001 self-defeat. Locks anti-package-removal
    # contract on the acct-baseline substrate.
    write_config "enabled"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(acct|psacct)'
}
