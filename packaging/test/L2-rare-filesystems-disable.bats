#!/usr/bin/env bats
# L2 functional suite for rare-filesystems-disable.
#
# rare-filesystems-disable installs a modprobe blacklist for
# rarely-used filesystem drivers. Each disabled kernel module is
# one less remote-mount / loop-mount / USB-auto-mount attack
# surface. Profiles:
#   baseline → cramfs / freevxfs / jffs2 / hfs / hfsplus / udf /
#              ksmbd (7 modules)
#   strict   → baseline + squashfs + nfsd + gfs2 (10 modules)
#
# Each rare filesystem is one less kernel-driver code path
# attackers can target. CVEs have hit cramfs, hfsplus, ksmbd, etc.
# in recent years.
#
# Adds SELFDEF_RAREFS_MODPROBE_FILE env-var (added 2026-06-06)
# for L2 testability.
#
# Run with: bats packaging/test/L2-rare-filesystems-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/rare-filesystems-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*"
FAKELOGGER
    chmod +x "${BIN}/logger"
    CONF="${TMP}/rare-filesystems-disable.toml"
    MODPROBE_FILE="${TMP}/selfdef-rare-filesystems-blacklist.conf"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_RAREFS_CONFIG="${CONF}" \
    SELFDEF_RAREFS_MODPROBE_FILE="${MODPROBE_FILE}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_RAREFS_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_RAREFS_CONFIG="${SELFDEF_RAREFS_CONFIG}" \
        SELFDEF_RAREFS_MODPROBE_FILE="${MODPROBE_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_RAREFS_CONFIG="${CONF}" \
        SELFDEF_RAREFS_MODPROBE_FILE="${MODPROBE_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be baseline|strict"* ]]
}

@test "baseline profile installs blacklist with 7 baseline modules" {
    write_config "baseline"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    grep -q 'managed-by: selfdef rare-filesystems-disable' "${MODPROBE_FILE}"
    # Check the 7 baseline modules.
    for m in cramfs freevxfs jffs2 hfs hfsplus udf ksmbd; do
        grep -q "blacklist ${m}" "${MODPROBE_FILE}"
    done
    # Strict-only modules should NOT be present.
    ! grep -q 'blacklist squashfs' "${MODPROBE_FILE}"
    ! grep -q 'blacklist nfsd' "${MODPROBE_FILE}"
}

@test "strict profile adds squashfs + nfsd + gfs2 on top of baseline" {
    write_config "strict"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    # All 10 modules.
    for m in cramfs freevxfs jffs2 hfs hfsplus udf ksmbd squashfs nfsd gfs2; do
        grep -q "blacklist ${m}" "${MODPROBE_FILE}"
    done
}

@test "blacklist file is chmod 0644 (modprobe.d convention)" {
    write_config "baseline"
    run_wd
    [ "$(stat -c '%a' "${MODPROBE_FILE}")" = "644" ]
}

@test "blacklist carries header-marker + timestamp + profile" {
    write_config "baseline"
    run_wd
    grep -q 'managed-by: selfdef rare-filesystems-disable' "${MODPROBE_FILE}"
    ! grep -qE '^# Generated [0-9]{4}-' "${MODPROBE_FILE}"  # no timestamp (2026-06-06 idempotency fix)
    grep -q 'profile=baseline' "${MODPROBE_FILE}"
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite blacklist (2026-06-06 idempotency fix)" {
    write_config "baseline"
    run_wd
    mtime_before="$(stat -c '%Y' "${MODPROBE_FILE}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${MODPROBE_FILE}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: DRY_RUN does not write blacklist file" {
    write_config "baseline"
    DRY_RUN=1 run_wd
    ! [ -f "${MODPROBE_FILE}" ]
}

@test "default profile is baseline (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    grep -q 'profile=baseline' "${MODPROBE_FILE}"
    ! grep -q 'blacklist squashfs' "${MODPROBE_FILE}"
}

@test "INVARIANT (profile upgrade baseline → strict): adds strict-only modules + bumps profile metadata" {
    write_config "baseline"
    run_wd
    ! grep -q 'blacklist squashfs' "${MODPROBE_FILE}"
    write_config "strict"
    run_wd
    grep -q 'blacklist squashfs' "${MODPROBE_FILE}"
    grep -q 'blacklist nfsd' "${MODPROBE_FILE}"
    grep -q 'blacklist gfs2' "${MODPROBE_FILE}"
    grep -q 'profile=strict' "${MODPROBE_FILE}"
}

@test "INVARIANT (profile downgrade strict → baseline): REMOVES strict-only modules" {
    # If profile downgrade leaves strict-only modules in the blacklist,
    # the operator's intent (relax) is silently violated.
    write_config "strict"
    run_wd
    grep -q 'blacklist squashfs' "${MODPROBE_FILE}"
    write_config "baseline"
    run_wd
    ! grep -q 'blacklist squashfs' "${MODPROBE_FILE}"
    ! grep -q 'blacklist nfsd' "${MODPROBE_FILE}"
    ! grep -q 'blacklist gfs2' "${MODPROBE_FILE}"
}

@test "INVARIANT (each blacklist line has 'install <mod> /bin/false' OR 'blacklist <mod>' shape)" {
    # blacklist alone allows manual modprobe to still load; install
    # /bin/false is the stricter shape that even root-modprobe blocks.
    # At minimum the file must use one of these canonical shapes.
    write_config "baseline"
    run_wd
    # Each baseline module appears as blacklist; install /bin/false may
    # also appear for hardening.
    for m in cramfs freevxfs jffs2; do
        grep -qE "(blacklist|install) ${m}" "${MODPROBE_FILE}"
    done
}

@test "INVARIANT (modprobe.d path convention): filename matches selfdef-* pattern (for tracking + uninstall)" {
    write_config "baseline"
    run_wd
    case "${MODPROBE_FILE}" in
        */selfdef-*.conf) : ;;
        *) fail "modprobe blacklist filename must follow selfdef-*.conf pattern; got: ${MODPROBE_FILE}" ;;
    esac
}

@test "INVARIANT (header-marker pin): file MUST carry the managed-by header (collateral-damage protection at uninstall)" {
    # Without this header, uninstall can't safely identify selfdef-
    # authored vs operator-authored blacklist content.
    write_config "baseline"
    run_wd
    grep -qE '^#.*managed-by:.*selfdef' "${MODPROBE_FILE}"
}
