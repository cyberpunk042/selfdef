#!/usr/bin/env bats
# L2 functional suite for apparmor-baseline.
#
# apparmor-baseline ensures AppArmor LSM is enabled, the
# apparmor.service is running, and a curated set of profiles
# (selfdef-curated-profiles.list) is flipped to complain or
# enforce mode. AppArmor confines mandatory access — even a
# CVE-execution-via-RCE in firefox can't access /etc/shadow if
# firefox's profile denies it. Foundational defense-in-depth.
#
# Profiles:
#   complain → log violations, don't block (the safe rollout)
#   enforce  → block violations (the actual hardening)
#
# Test challenges:
#   - Requires /sys/kernel/security/apparmor sysfs check (added
#     SELFDEF_AA_SYSFS_DIR override 2026-06-06).
#   - PATH-shadows aa-status, aa-enforce, aa-complain.
#   - Uses SELFDEF_AA_LIST env-var (already present) for the
#     curated profile list.
#
# Run with: bats packaging/test/L2-apparmor-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
case "$1" in
    is-active) exit 0 ;;     # apparmor is "active" by default
esac
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    # aa-status: emits the configured loaded profile set.
    cat > "${BIN}/aa-status" <<'AAEOF'
#!/usr/bin/env bash
# Emit loaded profiles. The list is configured per-test via
# AA_LOADED env var (newline-separated).
case "$1" in
    --profiled) printf '%s\n' "${AA_LOADED:-}" ;;
    *)          printf '%s\n' "${AA_LOADED:-}" ;;
esac
exit 0
AAEOF
    chmod +x "${BIN}/aa-status"
    cat > "${BIN}/aa-enforce" <<'AAFEOF'
#!/usr/bin/env bash
printf 'aa-enforce %s\n' "$*" >> "${AAFLIP_LOG}"
exit 0
AAFEOF
    chmod +x "${BIN}/aa-enforce"
    cat > "${BIN}/aa-complain" <<'AAFCOM'
#!/usr/bin/env bash
printf 'aa-complain %s\n' "$*" >> "${AAFLIP_LOG}"
exit 0
AAFCOM
    chmod +x "${BIN}/aa-complain"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    export AAFLIP_LOG="${TMP}/aa-flip.log"
    : > "${SYSEOF_LOG}"
    : > "${AAFLIP_LOG}"
    CONF="${TMP}/apparmor-baseline.toml"
    AA_SYSFS_DIR="${TMP}/aa-sysfs"
    mkdir -p "${AA_SYSFS_DIR}"
    # Fixture CONFIGS_SRC so the script's install step copies OUR
    # curated list (not the production one). Also point AA_LIST at
    # the install destination so the install is a no-op (cmp -s
    # matches) after the first run.
    CONFIGS_SRC="${TMP}/aa-configs-src"
    mkdir -p "${CONFIGS_SRC}"
    cat > "${CONFIGS_SRC}/selfdef-curated-profiles.list" <<'CURATED'
# Test-curated set
firefox
cupsd
avahi-daemon
CURATED
    AA_LIST="${TMP}/curated-profiles.list"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    AAFLIP_LOG="${AAFLIP_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_AA_BASELINE_CONFIG="${CONF}" \
    SELFDEF_AA_SYSFS_DIR="${AA_SYSFS_DIR}" \
    SELFDEF_AA_CONFIGS_SRC="${CONFIGS_SRC}" \
    SELFDEF_AA_LIST="${AA_LIST}" \
    AA_LOADED="${AA_LOADED:-}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_AA_BASELINE_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_AA_BASELINE_CONFIG="${SELFDEF_AA_BASELINE_CONFIG}" \
        SELFDEF_AA_SYSFS_DIR="${AA_SYSFS_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_AA_BASELINE_CONFIG="${CONF}" \
        SELFDEF_AA_SYSFS_DIR="${AA_SYSFS_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be complain|enforce"* ]]
}

@test "INVARIANT: AppArmor LSM not enabled in kernel → die (no silent skip)" {
    write_config "complain"
    rm -rf "${AA_SYSFS_DIR}"            # simulate AppArmor not loaded
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_AA_BASELINE_CONFIG="${CONF}" \
        SELFDEF_AA_SYSFS_DIR="${AA_SYSFS_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"AppArmor LSM not enabled"* ]]
}

@test "complain profile flips loaded profiles to complain mode" {
    write_config "complain"
    AA_LOADED='firefox
cupsd' run_wd
    grep -q 'aa-complain firefox' "${AAFLIP_LOG}"
    grep -q 'aa-complain cupsd' "${AAFLIP_LOG}"
    # NOT in loaded list → skipped.
    ! grep -q 'aa-complain avahi-daemon' "${AAFLIP_LOG}"
}

@test "enforce profile flips loaded profiles to enforce mode" {
    write_config "enforce"
    AA_LOADED='firefox
cupsd
avahi-daemon' run_wd
    grep -q 'aa-enforce firefox' "${AAFLIP_LOG}"
    grep -q 'aa-enforce cupsd' "${AAFLIP_LOG}"
    grep -q 'aa-enforce avahi-daemon' "${AAFLIP_LOG}"
    # NOT complain-tool fired.
    ! grep -q 'aa-complain' "${AAFLIP_LOG}"
}

@test "NOT-loaded profiles are skipped (won't aa-enforce a profile the kernel doesn't know)" {
    write_config "enforce"
    AA_LOADED='firefox' run_wd               # only firefox is loaded
    grep -q 'aa-enforce firefox' "${AAFLIP_LOG}"
    ! grep -q 'aa-enforce cupsd' "${AAFLIP_LOG}"
    ! grep -q 'aa-enforce avahi-daemon' "${AAFLIP_LOG}"
}

@test "comments + blank lines in curated list are ignored" {
    write_config "enforce"
    # Override CONFIGS_SRC to point at a different fixture for this test.
    cat > "${CONFIGS_SRC}/selfdef-curated-profiles.list" <<'EOF'
# This is a comment

firefox
# Another comment
   # indented comment

cupsd
EOF
    AA_LOADED='firefox
cupsd' run_wd
    grep -q 'aa-enforce firefox' "${AAFLIP_LOG}"
    grep -q 'aa-enforce cupsd' "${AAFLIP_LOG}"
}

@test "INVARIANT: DRY_RUN does not fire aa-enforce / aa-complain" {
    write_config "enforce"
    # Pre-seed AA_LIST so DRY_RUN can read it (skipping the install branch).
    cp "${CONFIGS_SRC}/selfdef-curated-profiles.list" "${AA_LIST}"
    AA_LOADED='firefox' DRY_RUN=1 run_wd
    ! grep -q 'aa-enforce firefox' "${AAFLIP_LOG}"
    ! grep -q 'aa-complain' "${AAFLIP_LOG}"
}

@test "default profile is complain (no profile key — the safe-rollout default)" {
    : > "${CONF}"
    AA_LOADED='firefox' run_wd
    grep -q 'aa-complain firefox' "${AAFLIP_LOG}"
    ! grep -q 'aa-enforce' "${AAFLIP_LOG}"
}
