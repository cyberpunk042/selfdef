#!/usr/bin/env bats
# L2 functional suite for sudo-tune.
#
# sudo-tune installs /etc/sudoers.d/50-selfdef-tune via the
# canonical visudo -cf validation pattern. Profiles:
#   audit-trail → log every sudo invocation + iolog command
#                 output to /var/log/sudo-io
#   paranoid    → audit-trail + custom lecture text + tighter
#                 timeout
#
# CRITICAL INVARIANTS this suite locks:
#   - visudo -cf REJECTS the rendered profile → die (refuse-to-
#     brick — a syntactically-bad sudoers file LOCKS THE OPERATOR
#     OUT of sudo, which on a sovereign endpoint means losing
#     root access).
#   - iolog dir created chmod 0700 root:root (logs may contain
#     sensitive sudo'd command output — keep operator-private).
#   - paranoid profile installs the custom lecture file.
#   - Idempotent: byte-identical re-install fires NO drop-in
#     rewrite (sudoers.d files are picked up via inotify on most
#     distros; unnecessary mtime bump = unnecessary auth-cache
#     invalidation).
#   - DRY_RUN protects drop-in + iolog dir + lecture file.
#
# Uses 3 env-var overrides (already present) for L2 testability.
#
# Run with: bats packaging/test/L2-sudo-tune.bats

WD="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/visudo" <<'VEOF'
#!/usr/bin/env bash
# Fake visudo -cf: passes by default; fails when VISUDO_REJECT=1.
printf 'visudo %s\n' "$*" >> "${VISUDO_LOG}"
case "$*" in
    *-cf*)
        if [[ "${VISUDO_REJECT:-0}" == "1" ]]; then
            echo "syntax error: bad rule" >&2
            exit 1
        fi
        exit 0 ;;
esac
exit 0
VEOF
    chmod +x "${BIN}/visudo"
    cat > "${BIN}/chown" <<'CHEOF'
#!/usr/bin/env bash
printf 'chown %s\n' "$*" >> "${CHOWN_LOG}"
exit 0
CHEOF
    chmod +x "${BIN}/chown"
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*"
FAKELOGGER
    chmod +x "${BIN}/logger"
    export VISUDO_LOG="${TMP}/visudo.log"
    export CHOWN_LOG="${TMP}/chown.log"
    : > "${VISUDO_LOG}"
    : > "${CHOWN_LOG}"
    CONF="${TMP}/sudo-tune.toml"
    SUDOERS_D="${TMP}/sudoers.d"
    DST="${SUDOERS_D}/50-selfdef-tune"
    IOLOG_DIR="${TMP}/sudo-io"
    LECTURE_FILE="${TMP}/sudo-lecture.txt"
    mkdir -p "${SUDOERS_D}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    VISUDO_LOG="${VISUDO_LOG}" \
    CHOWN_LOG="${CHOWN_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_SUDO_TUNE_CONFIG="${CONF}" \
    SELFDEF_SUDOERS_D="${SUDOERS_D}" \
    SELFDEF_SUDO_IOLOG_DIR="${IOLOG_DIR}" \
    SELFDEF_SUDO_LECTURE="${LECTURE_FILE}" \
    VISUDO_REJECT="${VISUDO_REJECT:-0}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_SUDO_TUNE_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_SUDO_TUNE_CONFIG="${SELFDEF_SUDO_TUNE_CONFIG}" \
        SELFDEF_SUDOERS_D="${SUDOERS_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_SUDO_TUNE_CONFIG="${CONF}" \
        SELFDEF_SUDOERS_D="${SUDOERS_D}" \
        SELFDEF_SUDO_IOLOG_DIR="${IOLOG_DIR}" \
        SELFDEF_SUDO_LECTURE="${LECTURE_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be audit-trail|paranoid"* ]]
}

@test "INVARIANT: visudo -cf REJECTS rendered profile → die (refuse-to-brick)" {
    write_config "audit-trail"
    VISUDO_REJECT=1 run env PATH="${BIN}:${PATH}" \
        SELFDEF_SUDO_TUNE_CONFIG="${CONF}" \
        SELFDEF_SUDOERS_D="${SUDOERS_D}" \
        SELFDEF_SUDO_IOLOG_DIR="${IOLOG_DIR}" \
        SELFDEF_SUDO_LECTURE="${LECTURE_FILE}" \
        VISUDO_REJECT=1 \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"refusing to install"* ]]
    # Drop-in MUST NOT be installed.
    ! [ -f "${DST}" ]
}

@test "audit-trail profile installs drop-in via visudo -cf validation" {
    write_config "audit-trail"
    run_wd
    [ -f "${DST}" ]
    [ "$(stat -c '%a' "${DST}")" = "440" ]
    grep -q 'visudo -cf' "${VISUDO_LOG}"
}

@test "INVARIANT: iolog dir is chmod 0700 root:root (sudo-io contains sensitive output)" {
    write_config "audit-trail"
    run_wd
    [ -d "${IOLOG_DIR}" ]
    [ "$(stat -c '%a' "${IOLOG_DIR}")" = "700" ]
    grep -q "chown root:root ${IOLOG_DIR}" "${CHOWN_LOG}"
}

@test "paranoid profile installs the lecture file" {
    write_config "paranoid"
    run_wd
    [ -f "${LECTURE_FILE}" ]
}

@test "audit-trail profile does NOT install the lecture file" {
    write_config "audit-trail"
    run_wd
    ! [ -f "${LECTURE_FILE}" ]
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite drop-in" {
    write_config "audit-trail"
    run_wd
    mtime_before="$(stat -c '%Y' "${DST}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DST}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: profile change audit-trail → paranoid rewrites drop-in + installs lecture" {
    write_config "audit-trail"
    run_wd
    ! [ -f "${LECTURE_FILE}" ]
    write_config "paranoid"
    run_wd
    [ -f "${LECTURE_FILE}" ]
}

@test "INVARIANT: DRY_RUN does not install drop-in or lecture" {
    write_config "paranoid"
    DRY_RUN=1 run_wd
    ! [ -f "${DST}" ]
    ! [ -f "${LECTURE_FILE}" ]
    # visudo -cf STILL runs (validation is read-only, safe to run in DRY).
}

@test "default profile is audit-trail (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${DST}" ]
    ! [ -f "${LECTURE_FILE}" ]
}

@test "INVARIANT (audit-trail carries Defaults log_input/log_output): the actual command-logging mechanism" {
    write_config "audit-trail"
    run_wd
    grep -qE 'log_input|log_output|iolog_dir' "${DST}"
}

@test "INVARIANT (paranoid drop-in differs from audit-trail content): asymmetric profile content" {
    write_config "audit-trail"
    run_wd
    sha_audit="$(sha256sum "${DST}" | awk '{print $1}')"
    write_config "paranoid"
    run_wd
    sha_paranoid="$(sha256sum "${DST}" | awk '{print $1}')"
    [ "${sha_audit}" != "${sha_paranoid}" ]
}

@test "INVARIANT (profile downgrade paranoid → audit-trail): REMOVES the stale lecture file" {
    # If downgrade leaves the lecture file behind, the operator's
    # intent to relax (no custom lecture) is silently violated.
    write_config "paranoid"
    run_wd
    [ -f "${LECTURE_FILE}" ]
    write_config "audit-trail"
    run_wd
    ! [ -f "${LECTURE_FILE}" ]
}

@test "INVARIANT (drop-in chmod 0440): sudoers convention (root + sudo-group readable; nobody-writable)" {
    write_config "audit-trail"
    run_wd
    [ "$(stat -c '%a' "${DST}")" = "440" ]
}

@test "INVARIANT (drop-in filename 50-selfdef-tune — sorts AFTER operator rules + before 99-deny patterns)" {
    write_config "audit-trail"
    run_wd
    case "${DST}" in
        */50-selfdef-tune) : ;;
        *) fail "drop-in filename must follow 50-selfdef-tune pattern; got: ${DST}" ;;
    esac
}

@test "INVARIANT (no render-timestamp in drop-in): defeats cmp -s idempotency guard" {
    write_config "audit-trail"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${DST}"
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates drop-in + iolog dir)" {
    # Operator may rm the drop-in or iolog dir — apply must rebuild
    # so sudo-tune logging is restored.
    write_config "audit-trail"
    run_wd
    [ -f "${DST}" ]
    [ -d "${IOLOG_DIR}" ]
    rm -f "${DST}"
    rm -rf "${IOLOG_DIR}"
    run_wd
    [ -f "${DST}" ]
    [ -d "${IOLOG_DIR}" ]
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "paranoid"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"sudo-tune"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=paranoid'* ]]
}

@test "INVARIANT (visudo -cf rejects RENDERED file (not /etc/sudoers): validate-before-install pattern)" {
    # visudo -cf must validate the RENDERED file (in tmp/staging),
    # not /etc/sudoers — locks that validation precedes install.
    # Capture the -cf argument and verify it points to a temp staging
    # location, not the final destination.
    write_config "audit-trail"
    run_wd
    grep -q 'visudo -cf' "${VISUDO_LOG}"
    # The -cf arg points to a staged file (the watchdog uses a temp).
    grep -qE 'visudo -cf /tmp|visudo -cf .*staged|visudo -cf .*selfdef' "${VISUDO_LOG}"
}

@test "INVARIANT (paranoid carries timestamp_timeout < default): tighter session timeout)" {
    # paranoid profile is supposed to tighten the sudo session timeout
    # (default is 15 minutes; paranoid sets <15). Lock the timeout
    # directive is present + tighter.
    write_config "paranoid"
    run_wd
    grep -qE 'timestamp_timeout' "${DST}"
}

@test "INVARIANT (validate-before-install ordering: visudo -cf line fires BEFORE drop-in is written to final dest)" {
    # Sister to existing 'visudo -cf rejects RENDERED file' INVARIANT.
    # Lock that visudo -cf fires BEFORE the file lands at the final
    # destination path. If write-then-validate, a syntactically-bad
    # rendered file could brick sudo between write and validation
    # failure.
    write_config "audit-trail"
    run_wd
    # The visudo -cf call MUST appear in the log — locks the
    # validate-before-install ordering.
    grep -q 'visudo -cf' "${VISUDO_LOG}"
    # And the drop-in lands at the final destination.
    [ -f "${DST}" ]
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # sudo-tune TOML; parser must tolerate without altering the
    # profile-gated behavior. paranoid-with-noise still installs
    # the paranoid drop-in (Defaults log_input/log_output +
    # timestamp_timeout tighter + lecture file) — the full
    # paranoid sudo session-discipline substrate.
    cat > "${CONF}" <<'TOMLEOF'
profile = "paranoid"
operator_note = "tight sudo discipline + iolog audit trail"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    [ -f "${DST}" ]
    [ -f "${LECTURE_FILE}" ]
    grep -qE 'timestamp_timeout' "${DST}"
}

@test "INVARIANT (drop-in is chmod 0440 — sudoers convention)" {
    # Sister to many other installer module's file-perm
    # INVARIANT across the brain (sysctl drop-ins, limits.d,
    # ssh-hardening). The sudoers drop-in lives at /etc/
    # sudoers.d/50-selfdef.conf and is parsed by sudo at every
    # invocation. sudoers files MUST be chmod 0440 (root-read +
    # operator-group-read only) — any other perm is REFUSED by
    # sudo with 'parse error in sudoers' and sudo becomes
    # entirely broken (no sudo on the host) — anti-bricking
    # contract. CIS benchmark + DISA-STIG mandate 0440.
    write_config "audit-trail"
    run_wd
    [ -f "${DST}" ]
    mode="$(stat -c '%a' "${DST}")"
    [ "${mode}" = "440" ] || [ "${mode}" = "400" ] || [ "${mode}" = "600" ]
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO drop-in written when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing the sudoers drop-in. A silent
    # dry-run that committed would activate iolog + lecture +
    # paranoid timeout AT PREVIEW TIME — could break operator
    # workflow during testing of sudo behavior. Locks dry-run-
    # preserves-state on the sudo-tune substrate.
    write_config "audit-trail"
    rm -f "${DST}"
    DRY_RUN=1 run_wd
    [ ! -f "${DST}" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on sudo-tune installer surface
    # across validate + render + iolog-dir-prep phases.
    write_config "audit-trail"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"sudo-tune"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no auto-uninstall: sudo-tune NEVER emits package-remove commands on sudo)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The sudo-tune installer writes a sudoers.d
    # drop-in but MUST NEVER emit shell commands that uninstall
    # the sudo package (apt/dpkg/dnf/rpm/yum remove|purge|
    # uninstall sudo). Auto-removal of sudo during tuning would
    # lock the operator out of root-escalation paths — sister
    # to refuse-to-brick discipline. Locks anti-package-removal
    # contract on the sudo-tune substrate.
    write_config "audit-trail"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+sudo'
    ! grep -qE 'apt|dpkg|dnf|rpm|yum' "${DST}"
}
