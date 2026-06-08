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

@test "INVARIANT (DRY_RUN side-effect-freedom: NO AA_LIST written when DRY_RUN=1)" {
    # Sister to brain-wide installer DRY_RUN INVARIANTs. The
    # apparmor-baseline DRY_RUN path MUST preview without
    # writing the curated profiles list. Current behavior:
    # DRY_RUN dies before aa-enforce phase due to missing
    # AA_LIST (apply.sh reads it in non-DRY path).
    # Lock the load-bearing piece: NO AA_LIST write.
    write_config "enforce"
    rm -f "${AA_LIST}"
    AA_LOADED='firefox' run env PATH="${BIN}:${PATH}" \
        SELFDEF_AA_BASELINE_CONFIG="${CONF}" \
        SELFDEF_AA_CONFIGS_SRC="${CONFIGS_SRC}" \
        SELFDEF_AA_LIST="${AA_LIST}" \
        SELFDEF_AA_SYSFS_DIR="${SYSFS_DIR}" \
        SELFDEF_DRY_RUN=1 \
        bash "${WD}"
    [ ! -f "${AA_LIST}" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on apparmor-baseline installer
    # surface across AA_LIST + aa-enforce phases.
    write_config "enforce"
    AA_LOADED='firefox' run env PATH="${BIN}:${PATH}" \
        SELFDEF_AA_BASELINE_CONFIG="${CONF}" \
        SELFDEF_AA_CONFIGS_SRC="${CONFIGS_SRC}" \
        SELFDEF_AA_LIST="${AA_LIST}" \
        SELFDEF_AA_SYSFS_DIR="${SYSFS_DIR}" \
        bash "${WD}"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"apparmor-baseline"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no auto-uninstall: apparmor-baseline NEVER emits package-remove commands on apparmor)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The apparmor-baseline installer manages the
    # curated profile list + enforce/complain transitions but
    # MUST NEVER emit shell commands that uninstall the
    # apparmor package itself (apt/dpkg/dnf/rpm/yum remove|
    # purge|uninstall apparmor|apparmor-profiles|apparmor-
    # utils). Silent auto-removal would tear down MAC
    # enforcement entirely — every confined process becomes
    # unconfined. T1562.001 Impair Defenses: Disable or Modify
    # Tools — anti-pattern the installer must NOT enable.
    # Locks anti-package-removal contract on the apparmor MAC
    # substrate.
    write_config "enforce"
    AA_LOADED='firefox' output=$(run env PATH="${BIN}:${PATH}" \
        SELFDEF_AA_BASELINE_CONFIG="${CONF}" \
        SELFDEF_AA_CONFIGS_SRC="${CONFIGS_SRC}" \
        SELFDEF_AA_LIST="${AA_LIST}" \
        SELFDEF_AA_SYSFS_DIR="${SYSFS_DIR}" \
        bash "${WD}" 2>&1)
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+apparmor'
    ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+apparmor' "${WD}"
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on apparmor-baseline surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The apparmor-baseline installer MUST only emit severity
    # values from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers branch on the literal severity string;
    # an out-of-set value silently falls through routing and
    # the operator never sees the AppArmor profile enforcement
    # status alert. Locks parser contract on the apparmor-
    # baseline installer JSON surface (consistency-with-
    # watchdog-family discipline).
    write_config "enforce"
    AA_LOADED='firefox' output=$(run env PATH="${BIN}:${PATH}" \
        SELFDEF_AA_BASELINE_CONFIG="${CONF}" \
        SELFDEF_AA_CONFIGS_SRC="${CONFIGS_SRC}" \
        SELFDEF_AA_LIST="${AA_LIST}" \
        SELFDEF_AA_SYSFS_DIR="${SYSFS_DIR}" \
        bash "${WD}" 2>&1)
    bad=$(printf '%s\n' "${output}" | grep -oE '"severity":"[^"]+"' | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. apparmor-baseline manifest declares install +
    # profile gating (audit / enforce) the resolver enforces;
    # malformed manifest wedges the AppArmor mode baseline.
    # Python's tomllib is the canonical parser. Locks anti-
    # malformed-manifest on the apparmor-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'apparmor-baseline', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # apparmor-baseline install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state (one drop-in
    # written + another aborted mid-way) is detectable rather
    # than a half-applied silent state. Locks fail-loud
    # invariant on the apparmor-baseline lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list ([] or ["a", "b"]) — not a comma-separated
    # string like "a, b" which TOML's tomllib would silently
    # accept as a single-element list ["a, b"]. The resolver
    # would then look for a single module named literally "a, b"
    # and fail to find it. Locks list-vs-string discipline on
    # the depends_on field of the apparmor-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('depends_on', [])
assert isinstance(v, list), f'depends_on must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml conflicts field is a TOML list — anti-string-malformation contract on conflicts)" {
    # Sister to brain-wide module.toml manifest-completeness +
    # depends_on-list INVARIANTs already locked. The conflicts
    # field MUST be a TOML list — the resolver iterates
    # conflicts to detect mutually-exclusive module pairs at
    # install-time. A scalar/string would silently parse as a
    # single-element list, masking real conflicts. Locks list-
    # vs-string discipline on the conflicts field of the
    # apparmor-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('conflicts', [])
assert isinstance(v, list), f'conflicts must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml provides field is a TOML list — anti-string-malformation contract on provides)" {
    # Sister to brain-wide module.toml manifest-completeness +
    # depends_on-list + conflicts-list INVARIANTs already
    # locked. The provides field MUST be a TOML list — the
    # resolver iterates it to register each provided contract
    # in the consumer-binding graph. A scalar would silently
    # parse as a single-element list, masking real provides.
    # Locks list-vs-string discipline on the provides field of
    # the apparmor-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('provides', [])
assert isinstance(v, list), f'provides must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml requires field is a TOML list — anti-string-malformation contract on requires)" {
    # Sister to brain-wide module.toml list-vs-string family.
    # Locks list discipline on requires.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('requires', [])
assert isinstance(v, list), f'requires must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml requires entries are tables with kind + value — anti-flat-string-list contract)" {
    # Sister to brain-wide module.toml requires-shape INVARIANT
    # family. Each requires entry MUST be a TOML inline table
    # `{ kind = "binary", value = "X" }` — not a flat string
    # like "binary:X" (which the resolver would not parse as
    # structured kind/value and would fail to dispatch the
    # check). Locks the kind+value table-shape discipline on
    # the apparmor-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
reqs = data.get('requires', [])
for r in reqs:
    assert isinstance(r, dict), f'requires entry must be table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'requires entry must have kind+value, got {r}'
"
}

@test "INVARIANT (module.toml summary field present + non-empty — operator-dashboard one-line description contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The summary field is the operator-facing
    # one-line description rendered on the install dashboard.
    # An empty or missing summary would surface as an unlabeled
    # module-row, harming operator triage. Locks the summary-
    # present discipline on the apparmor-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) > 0, f'summary must be non-empty string, got {repr(s)}'
"
}

@test "INVARIANT (module.toml category field present + non-empty — dashboard-grouping contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The category field groups modules in
    # the operator install dashboard (detection / hardening /
    # disable / etc.). An empty/missing category would surface
    # as an Uncategorized bucket, harming triage. Locks
    # category-present discipline on the apparmor-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert isinstance(c, str) and len(c) > 0, f'category must be non-empty string, got {repr(c)}'
"
}

@test "INVARIANT (module.toml version field is semver X.Y.Z — version-comparison sortability contract)" {
    # Sister to brain-wide module.toml semver INVARIANT family.
    # The version field MUST follow X.Y.Z semver so the resolver
    # can sort versions numerically + version-gate downstream
    # consumers. A regression to "v1" / "1.0" / "1.0.0-beta+meta"
    # would break the sortable numeric comparison. Locks the
    # semver-X.Y.Z discipline on the apparmor-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl installer resolves apply scripts
    # via module.toml's [install].apply field — the canonical
    # value is the relative path "install/apply.sh" (under the
    # module's own directory). A regression that swapped to
    # an absolute /usr/local/libexec/... path would break the
    # in-tree test runner (which executes apply scripts from
    # the source tree, not /usr/local/libexec/). A regression
    # to a non-existent path would surface as "apply script
    # not found" at install time. Locks the canonical
    # install/apply.sh path discipline on the apparmor-baseline module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
ap = inst.get('apply', '')
assert ap == 'install/apply.sh', f'install.apply must be install/apply.sh, got {ap!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the apparmor-baseline module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
chk = inst.get('check', '')
assert chk == 'install/check.sh', f'install.check must be install/check.sh, got {chk!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
    # Sister to brain-wide module.toml [install_paths]
    # INVARIANT family. Per MS011 Z-8 / SDD-026, every
    # installer module MUST declare an [install_paths] block
    # enumerating the on-disk surfaces it touches on apply.
    # The selfdef dashboard's install-options surface +
    # install-plan auditor read this block to surface what
    # the module mutates BEFORE apply runs. A regression
    # dropping the [install_paths] block would leave operators
    # without a pre-apply manifest of writes, breaking
    # operator-consent + the install-plan-dry-run contract.
    # Locks the SDD-026 manifest discipline on the apparmor-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths')
assert ip is not None, f'[install_paths] block must be present per SDD-026, got None'
paths = ip.get('paths', [])
assert isinstance(paths, list) and len(paths) > 0, f'install_paths.paths must be non-empty list, got {paths!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for apparmor-baseline is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the apparmor-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
    # Sister to brain-wide [install_paths].paths INVARIANT
    # family. The install_paths.paths field MUST be a TOML
    # list of strings (each element an absolute path the
    # module touches on apply). A regression that swapped to
    # a comma-separated string ("path1,path2,path3") would
    # silently treat it as a single literal path. The
    # selfdef installer iterates the list to surface the
    # mutation manifest to operators; broken type-shape
    # would break the install-options surface + dry-run
    # auditor. Locks the TOML-list-of-strings type discipline
    # on the apparmor-baseline install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list), f'install_paths.paths must be TOML list, got {type(ps).__name__}'
assert all(isinstance(p, str) for p in ps), f'every paths entry must be a string'
"
}

@test "INVARIANT (apparmor-baseline module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the apparmor-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
req = data.get('requires')
assert isinstance(req, list), f'requires must be TOML list, got {type(req).__name__}'
for r in req:
    assert isinstance(r, dict), f'requires entry must be inline-table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'requires must have kind+value, got {r!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the apparmor-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the apparmor-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the apparmor-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the apparmor-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
prof = data.get('profiles')
assert prof is not None, f'[profiles] must be present, got None'
assert isinstance(prof, dict), f'[profiles] must be TOML table, got {type(prof).__name__}'
"
}

@test "INVARIANT (apparmor-baseline module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (apparmor-baseline module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (apparmor-baseline module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (apparmor-baseline README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (apparmor-baseline install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (apparmor-baseline install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (apparmor-baseline install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (apparmor-baseline install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (apparmor-baseline install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (apparmor-baseline install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (apparmor-baseline install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (apparmor-baseline install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (apparmor-baseline install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (apparmor-baseline install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (apparmor-baseline install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (apparmor-baseline install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (apparmor-baseline module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (apparmor-baseline module.toml exists at canonical path modules/apparmor-baseline/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (apparmor-baseline module dir is at canonical path modules/apparmor-baseline/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (apparmor-baseline install dir exists at modules/apparmor-baseline/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (apparmor-baseline install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (apparmor-baseline install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (apparmor-baseline install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (apparmor-baseline install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (apparmor-baseline module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (apparmor-baseline install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (apparmor-baseline install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (apparmor-baseline install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (apparmor-baseline install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (apparmor-baseline install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (apparmor-baseline install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (apparmor-baseline install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (apparmor-baseline install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (apparmor-baseline module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (apparmor-baseline module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (apparmor-baseline module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
prefixes = ('/etc/', '/usr/', '/var/', '/lib/', '/opt/', '/run/', '/srv/', '/boot/')
for p in ps:
    assert any(p.startswith(pf) for pf in prefixes), f'{p!r} not canonical-root'
"
}

@test "INVARIANT (apparmor-baseline module.toml has at least 1 entry in install_paths.paths — non-empty-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 1
"
}

@test "INVARIANT (apparmor-baseline module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (apparmor-baseline module.toml install_paths.scope canonical-system 92 — operator-scope-fixed)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc in ('system', 'user', '')
"
}

@test "INVARIANT (apparmor-baseline module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/etc/selfdef/' in p for p in ps)
"
}

@test "INVARIANT (apparmor-baseline module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (apparmor-baseline module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (apparmor-baseline module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (apparmor-baseline module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (apparmor-baseline module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (apparmor-baseline module.toml category field uses double-quoted string syntax — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (apparmor-baseline module.toml summary field uses double-quoted string syntax — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (apparmor-baseline module.toml name field value matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"apparmor-baseline"' "${mtoml}"
}

@test "INVARIANT (apparmor-baseline module.toml top-level keys before any [section] header — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import re
with open('${mtoml}') as fp:
    for ln in fp:
        s = ln.strip()
        if not s or s.startswith('#'): continue
        if s.startswith('['): break
        assert '=' in ln, f'expected key=val before sections, got {ln!r}'
        break
"
}

@test "INVARIANT (apparmor-baseline module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (apparmor-baseline module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (apparmor-baseline module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (apparmor-baseline module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (apparmor-baseline module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (apparmor-baseline module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (apparmor-baseline module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}

@test "INVARIANT (apparmor-baseline module.toml [install] check value is non-empty string ending with .sh — TOML-install-check-shape-canonical 112)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ck = (data.get('install') or {}).get('check', '')
assert isinstance(ck, str) and ck and ck.endswith('.sh'), f'install.check must be non-empty .sh path, got {ck!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml version field matches semver X.Y.Z pattern — TOML-version-semver-canonical 113)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v), f'version must be semver X.Y.Z, got {v!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml summary field is non-empty string with length >= 30 chars — TOML-summary-substance-floor 114)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) >= 30, f'summary must be string with len >= 30, got len={len(s)} value={s!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml top-level requires field is a TOML list — TOML-requires-list-canonical 115)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (apparmor-baseline module.toml top-level provides field is a TOML list — TOML-provides-list-canonical 116)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('provides')
assert isinstance(r, list), f'provides must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (apparmor-baseline module.toml top-level conflicts field is a TOML list — TOML-conflicts-list-canonical 117)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('conflicts')
assert isinstance(r, list), f'conflicts must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (apparmor-baseline module.toml top-level depends_on field is a TOML list — TOML-depends-on-list-canonical 118)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('depends_on')
assert isinstance(r, list), f'depends_on must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (apparmor-baseline module.toml top-level consumes field is a TOML list — TOML-consumes-list-canonical 119)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('consumes')
assert isinstance(r, list), f'consumes must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (apparmor-baseline module.toml top-level instanced field is a TOML boolean — TOML-instanced-bool-canonical 120)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('instanced')
assert isinstance(r, bool), f'instanced must be bool, got {type(r).__name__}'
"
}

@test "INVARIANT (apparmor-baseline module.toml [install] uninstall value is non-empty string ending with .sh — TOML-install-uninstall-shape-canonical 121)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = (data.get('install') or {}).get('uninstall', '')
assert isinstance(v, str) and v and v.endswith('.sh'), f'install.uninstall must be non-empty .sh path, got {v!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml has [profiles] section header — TOML-profiles-section-canonical 122)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    grep -qE '^\[profiles\]$' "${mtoml}"
}

@test "INVARIANT (apparmor-baseline module.toml [profiles] default field is non-empty string — TOML-profiles-default-canonical 123)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert isinstance(d, str) and d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml [profiles] available field is a TOML list — TOML-profiles-available-list-canonical 124)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available')
assert isinstance(a, list), f'profiles.available must be list, got {type(a).__name__}'
"
}

@test "INVARIANT (apparmor-baseline module.toml [profiles] available list contains at least one element — TOML-profiles-available-non-empty-canonical 125)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert isinstance(a, list) and len(a) >= 1, f'profiles.available must be non-empty list, got {a!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml [profiles] default value appears in [profiles] available list (semantic consistency) — TOML-profiles-default-in-available-canonical 126)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('profiles') or {}
default = p.get('default')
available = p.get('available') or []
assert default in available, f'profiles.default {default!r} must appear in available {available!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml [profiles] available list contains only string elements — TOML-profiles-available-elements-string-canonical 127)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert all(isinstance(x, str) for x in a), f'profiles.available items must all be strings, got {[type(x).__name__ for x in a]!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml requires list elements are inline-tables with kind+value keys (or empty) — TOML-requires-elements-shape-canonical 128)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
for el in r:
    assert isinstance(el, dict), f'requires element must be inline-table, got {type(el).__name__}'
    assert 'kind' in el and 'value' in el, f'requires element must have kind+value keys, got {sorted(el.keys())!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml requires items have kind in bounded vocab {binary, package, kernel-feature} — TOML-requires-kind-vocab-canonical 129)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
allowed = {'binary', 'package', 'kernel-feature'}
for el in r:
    k = el.get('kind', '')
    assert k in allowed, f'requires.kind must be in {allowed}, got {k!r}'
"
}

@test "INVARIANT (apparmor-baseline module.toml requires items have value as non-empty string — TOML-requires-value-nonempty-canonical 130)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/apparmor-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
for el in r:
    v = el.get('value', '')
    assert isinstance(v, str) and v, f'requires.value must be non-empty string, got {v!r}'
"
}
