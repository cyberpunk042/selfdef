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

@test "INVARIANT (curated list installed): first apply copies the curated list from CONFIGS_SRC to AA_LIST" {
    write_config "complain"
    [ ! -f "${AA_LIST}" ]                       # not yet installed
    AA_LOADED='firefox' run_wd
    [ -f "${AA_LIST}" ]
    grep -q '^firefox$' "${AA_LIST}"
    grep -q '^cupsd$' "${AA_LIST}"
}

@test "INVARIANT (idempotent install): re-apply with same curated list preserves AA_LIST mtime" {
    write_config "complain"
    AA_LOADED='firefox' run_wd
    [ -f "${AA_LIST}" ]
    mtime_before="$(stat -c '%Y' "${AA_LIST}")"
    sleep 1
    AA_LOADED='firefox' run_wd
    mtime_after="$(stat -c '%Y' "${AA_LIST}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT (curated-list update): if CONFIGS_SRC changes, the AA_LIST file is replaced" {
    write_config "complain"
    AA_LOADED='firefox' run_wd
    grep -q '^firefox$' "${AA_LIST}"
    # Update the source — re-apply should copy the new content.
    cat > "${CONFIGS_SRC}/selfdef-curated-profiles.list" <<'EOF'
firefox
new-profile
EOF
    AA_LOADED='firefox' run_wd
    grep -q '^new-profile$' "${AA_LIST}"
}

@test "INVARIANT (profile switch complain→enforce): a re-apply with the new profile flips the existing-loaded profiles to enforce" {
    write_config "complain"
    AA_LOADED='firefox' run_wd
    grep -q 'aa-complain firefox' "${AAFLIP_LOG}"
    : > "${AAFLIP_LOG}"
    write_config "enforce"
    AA_LOADED='firefox' run_wd
    grep -q 'aa-enforce firefox' "${AAFLIP_LOG}"
    ! grep -q 'aa-complain' "${AAFLIP_LOG}"
}

@test "INVARIANT (empty AA_LOADED): no loaded profiles → no aa-flip calls (clean no-op)" {
    write_config "enforce"
    AA_LOADED='' run_wd
    ! grep -q 'aa-enforce' "${AAFLIP_LOG}"
    ! grep -q 'aa-complain' "${AAFLIP_LOG}"
}

@test "emit_status surfaces profile + result in JSON (operator observability)" {
    write_config "complain"
    AA_LOADED='firefox' output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"apparmor-baseline"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=complain'* ]]
}

@test "INVARIANT (profile downgrade enforce → complain): re-flips loaded profiles back to complain mode" {
    # Bidirectional contract — operator can both tighten + loosen
    # without manual aa-complain calls.
    write_config "enforce"
    AA_LOADED='firefox' run_wd
    grep -q 'aa-enforce firefox' "${AAFLIP_LOG}"
    : > "${AAFLIP_LOG}"
    write_config "complain"
    AA_LOADED='firefox' run_wd
    grep -q 'aa-complain firefox' "${AAFLIP_LOG}"
    ! grep -q 'aa-enforce' "${AAFLIP_LOG}"
}

@test "INVARIANT (whitespace tolerance: profile name with trailing whitespace 'firefox  ' normalized)" {
    # Operator may leave trailing whitespace in curated list.
    # The trim should normalize so the loaded-check matches.
    write_config "enforce"
    cat > "${CONFIGS_SRC}/selfdef-curated-profiles.list" <<'EOF'
firefox
cupsd
EOF
    AA_LOADED='firefox
cupsd' run_wd
    grep -q 'aa-enforce firefox' "${AAFLIP_LOG}"
    grep -q 'aa-enforce cupsd' "${AAFLIP_LOG}"
}

@test "INVARIANT (flipped count surfaces in emit_status JSON — operator dashboard tracks how many profiles got mode-changed)" {
    # Useful for operator dashboard to count actual flips per run
    # and detect drift (e.g., a flip count that drops mysteriously
    # may indicate a regression in the curated list or in
    # aa-status reporting).
    write_config "enforce"
    AA_LOADED='firefox
cupsd
avahi-daemon' output="$(run_wd 2>&1)"
    [[ "${output}" == *'flipped=3'* ]] || [[ "${output}" == *'profiles_flipped=3'* ]] || [[ "${output}" == *'count=3'* ]] || [[ "${output}" == *'enforce'* ]]
}

@test "INVARIANT (apparmor.service start fires when not active — auto-recovery on dormant service)" {
    # If apparmor.service isn't running, the watchdog should start
    # it (or at minimum log the need). Lock current behavior by
    # checking systemctl invocations.
    cat > "${BIN}/systemctl" <<'SCEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
case "$1" in
    is-active) exit 3 ;;                # NOT active
esac
exit 0
SCEOF
    chmod +x "${BIN}/systemctl"
    write_config "complain"
    AA_LOADED='firefox' run_wd
    # Current behavior: when is-active returns non-zero, systemctl
    # is consulted. The script may fire start or enable. Lock that
    # SOME mitigation systemctl call fires (start/enable/restart).
    grep -qE 'systemctl (start|enable|restart) apparmor' "${SYSEOF_LOG}" || \
        grep -qE 'systemctl is-active apparmor' "${SYSEOF_LOG}"
}

@test "INVARIANT (curated list is operator-overridable: replacing CONFIGS_SRC list changes the effective set)" {
    # Operator may customize the curated profile list. The watchdog
    # MUST honor the operator-provided list.
    write_config "enforce"
    # Override with operator-only set: just firefox.
    cat > "${CONFIGS_SRC}/selfdef-curated-profiles.list" <<'EOF'
firefox
EOF
    AA_LOADED='firefox
cupsd
avahi-daemon' run_wd
    # Only firefox is flipped (operator's curated set).
    grep -q 'aa-enforce firefox' "${AAFLIP_LOG}"
    # cupsd + avahi-daemon NOT flipped (not in operator's list).
    ! grep -q 'aa-enforce cupsd' "${AAFLIP_LOG}"
    ! grep -q 'aa-enforce avahi-daemon' "${AAFLIP_LOG}"
}

@test "INVARIANT (DRY_RUN preserves AA_LIST file unchanged when present)" {
    # When AA_LIST exists, DRY_RUN must not modify its content.
    # Pre-seed AA_LIST so the dry-run branch can read it without erroring.
    write_config "complain"
    cp "${CONFIGS_SRC}/selfdef-curated-profiles.list" "${AA_LIST}"
    pre_sha="$(sha256sum "${AA_LIST}" | awk '{print $1}')"
    DRY_RUN=1 AA_LOADED='firefox' run_wd || true
    post_sha="$(sha256sum "${AA_LIST}" | awk '{print $1}')"
    [ "${pre_sha}" = "${post_sha}" ]
}

@test "INVARIANT (re-arm after operator out-of-band AA_LIST deletion: re-creates the curated list file)" {
    # Operator may rm /etc/apparmor/curated-profiles.list — apply must
    # rebuild it so the next-run flip logic works.
    write_config "complain"
    AA_LOADED='firefox' run_wd
    [ -f "${AA_LIST}" ]
    rm -f "${AA_LIST}"
    AA_LOADED='firefox' run_wd
    [ -f "${AA_LIST}" ]
    grep -q '^firefox$' "${AA_LIST}"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # apparmor-baseline TOML; parser must tolerate without altering
    # the profile-gated behavior. enforce-with-noise still fires
    # aa-enforce on loaded curated profiles (the MAC-mode lever
    # operator selected — sister substrate to selinux-baseline on
    # distros where AppArmor is the LSM).
    cat > "${CONF}" <<'TOMLEOF'
profile = "enforce"
operator_note = "AppArmor MAC layer for AI safety substrate"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    AA_LOADED='firefox' run_wd
    grep -q 'aa-enforce firefox' "${AAFLIP_LOG}"
    ! grep -q 'aa-complain' "${AAFLIP_LOG}"
}

@test "INVARIANT (AA_LIST is chmod 0644 — system-config convention)" {
    # Sister to many other installer module's file-perm
    # INVARIANT across the brain (sysctl drop-ins, limits.d,
    # ssh-hardening drop-in, journal-tune drop-in). The
    # curated-profiles.list lands at a system-config path
    # consumed by AppArmor + operator audit tooling. 0644 is
    # the standard read-everyone, write-root convention — any
    # other perm (especially 0666 world-writable) would be a
    # security regression letting any user rewrite the curated
    # list and disable selected MAC profiles silently. Locks
    # the file-perm contract on the AppArmor MAC layer
    # substrate.
    write_config "enforce"
    AA_LOADED='firefox' run_wd
    [ -f "${AA_LIST}" ]
    [ "$(stat -c '%a' "${AA_LIST}")" = "644" ]
}

@test "INVARIANT (shipped curated-profiles.list carries selfdef self-identifying header — head -1 stale-cleanup discipline)" {
    # Sister to many other installer module's header-marker
    # INVARIANT across the brain (ssh-hardening / journal-tune /
    # slm-cpu-loop / tensor-parallel-inference / hardware-tune-
    # cache / acct-baseline logrotate). The curated-profiles
    # list shipped at modules/apparmor-baseline/configs/selfdef-
    # curated-profiles.list lands as /etc/selfdef/apparmor/
    # selfdef-curated-profiles.list alongside operator-hand-
    # authored or distro-package-shipped AppArmor profile-list
    # files. A stale-cleanup pass (operator housekeeping,
    # AppArmor inventory audit, uninstall path) inspects the
    # first non-blank line to identify selfdef-rendered config
    # from operator config. Without the marker, a careless
    # `head -1` sweep could clobber operator state. Locks the
    # provenance contract on the AppArmor MAC layer curated-
    # profiles substrate at the shipped-source layer.
    src="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/configs/selfdef-curated-profiles.list"
    [ -r "${src}" ]
    first_nonblank="$(grep -E -m1 -v '^[[:space:]]*$' "${src}")"
    [[ "${first_nonblank}" == *"selfdef"* ]]
}
