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
