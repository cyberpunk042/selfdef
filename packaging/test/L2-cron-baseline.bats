#!/usr/bin/env bats
# L2 functional suite for cron-baseline.
#
# cron-baseline writes /etc/cron.allow + /etc/at.allow with the
# operator-chosen user set + empty /etc/cron.deny + /etc/at.deny.
# The .allow file takes precedence when both exist; setting BOTH
# defensively eliminates distro-specific surprises (some distros
# only honor .deny; others only .allow).
#
# Per cron(8): if /etc/cron.allow exists, ONLY users listed there
# can use crontab. Sovereign default: only root.
#
# Profiles:
#   root-only      → just root in .allow (default)
#   operator-list  → root + operator users from config
#
# CRITICAL INVARIANTS this suite locks:
#   - First apply backs up the 4 cron/at files; second apply does
#     NOT re-backup.
#   - Operator-list profile filters out non-existent users (log
#     WARN, don't fail — operator may have removed an account).
#   - Idempotent: byte-identical re-install does NOT rewrite any
#     of the 4 files.
#   - Files chmod 0640 (root-readable, crontab-group readable).
#
# Uses 4 env-var overrides (already present) for L2 testability.
#
# Run with: bats packaging/test/L2-cron-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/id" <<'IDEOF'
#!/usr/bin/env bash
# Fake id — exits 0 for known users, non-zero otherwise.
case "$1" in
    root|operator|alice|bob) exit 0 ;;
    *) exit 1 ;;
esac
IDEOF
    chmod +x "${BIN}/id"
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
    export CHOWN_LOG="${TMP}/chown.log"
    : > "${CHOWN_LOG}"
    CONF="${TMP}/cron-baseline.toml"
    CRON_ALLOW="${TMP}/cron.allow"
    AT_ALLOW="${TMP}/at.allow"
    CRON_DENY="${TMP}/cron.deny"
    AT_DENY="${TMP}/at.deny"
    # Pre-existing operator files.
    printf 'someone\n' > "${CRON_ALLOW}"
    printf 'someone\n' > "${AT_ALLOW}"
    printf 'evil-user\n' > "${CRON_DENY}"
    printf 'evil-user\n' > "${AT_DENY}"
}

teardown() { rm -rf "${TMP}"; }

# write_config <profile> [operator_users]
write_config() {
    local profile="$1" users="${2:-}"
    {
        printf 'profile = "%s"\n' "${profile}"
        if [[ -n "${users}" ]]; then
            printf 'operator_users = "%s"\n' "${users}"
        fi
    } > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    CHOWN_LOG="${CHOWN_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_CRON_BASELINE_CONFIG="${CONF}" \
    SELFDEF_CRON_ALLOW="${CRON_ALLOW}" \
    SELFDEF_AT_ALLOW="${AT_ALLOW}" \
    SELFDEF_CRON_DENY="${CRON_DENY}" \
    SELFDEF_AT_DENY="${AT_DENY}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_CRON_BASELINE_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_CRON_BASELINE_CONFIG="${SELFDEF_CRON_BASELINE_CONFIG}" \
        SELFDEF_CRON_ALLOW="${CRON_ALLOW}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_CRON_BASELINE_CONFIG="${CONF}" \
        SELFDEF_CRON_ALLOW="${CRON_ALLOW}" \
        SELFDEF_AT_ALLOW="${AT_ALLOW}" \
        SELFDEF_CRON_DENY="${CRON_DENY}" \
        SELFDEF_AT_DENY="${AT_DENY}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be root-only|operator-list"* ]]
}

@test "INVARIANT: first apply backs up all 4 operator files" {
    write_config "root-only"
    run_wd
    [ -f "${CRON_ALLOW}.selfdef-backup" ]
    [ -f "${AT_ALLOW}.selfdef-backup" ]
    [ -f "${CRON_DENY}.selfdef-backup" ]
    [ -f "${AT_DENY}.selfdef-backup" ]
}

@test "INVARIANT: second apply does NOT re-backup" {
    write_config "root-only"
    run_wd
    sha_backup_before="$(sha256sum "${CRON_ALLOW}.selfdef-backup" | awk '{print $1}')"
    run_wd
    sha_backup_after="$(sha256sum "${CRON_ALLOW}.selfdef-backup" | awk '{print $1}')"
    [ "${sha_backup_before}" = "${sha_backup_after}" ]
}

@test "root-only profile writes 'root' to both cron.allow + at.allow" {
    write_config "root-only"
    run_wd
    grep -q '^root$' "${CRON_ALLOW}"
    grep -q '^root$' "${AT_ALLOW}"
    # Only one line (just root).
    [ "$(wc -l < "${CRON_ALLOW}" | tr -d ' ')" = "1" ]
}

@test "operator-list profile adds operator users to root" {
    write_config "operator-list" "alice,bob"
    run_wd
    grep -q '^root$' "${CRON_ALLOW}"
    grep -q '^alice$' "${CRON_ALLOW}"
    grep -q '^bob$' "${CRON_ALLOW}"
    [ "$(wc -l < "${CRON_ALLOW}" | tr -d ' ')" = "3" ]
}

@test "INVARIANT: non-existent operator users are filtered out (WARN, don't fail)" {
    write_config "operator-list" "alice,nonexistent-user-12345"
    run_wd
    grep -q '^alice$' "${CRON_ALLOW}"
    ! grep -q 'nonexistent-user-12345' "${CRON_ALLOW}"
    # Just root + alice (nonexistent filtered).
    [ "$(wc -l < "${CRON_ALLOW}" | tr -d ' ')" = "2" ]
}

@test "INVARIANT: cron.deny + at.deny are made EMPTY (explicit defense against ambiguity)" {
    write_config "root-only"
    run_wd
    [ -f "${CRON_DENY}" ]
    [ -f "${AT_DENY}" ]
    [ ! -s "${CRON_DENY}" ]      # empty
    [ ! -s "${AT_DENY}" ]        # empty
}

@test "INVARIANT: files chmod 0640" {
    write_config "root-only"
    run_wd
    [ "$(stat -c '%a' "${CRON_ALLOW}")" = "640" ]
    [ "$(stat -c '%a' "${AT_ALLOW}")" = "640" ]
    [ "$(stat -c '%a' "${CRON_DENY}")" = "640" ]
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite any file" {
    write_config "root-only"
    run_wd
    mtime_before="$(stat -c '%Y' "${CRON_ALLOW}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${CRON_ALLOW}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: DRY_RUN does not modify any file" {
    write_config "root-only"
    sha_before="$(sha256sum "${CRON_ALLOW}" | awk '{print $1}')"
    DRY_RUN=1 run_wd
    sha_after="$(sha256sum "${CRON_ALLOW}" | awk '{print $1}')"
    [ "${sha_before}" = "${sha_after}" ]
}

@test "default profile is root-only (no profile key)" {
    : > "${CONF}"
    run_wd
    grep -q '^root$' "${CRON_ALLOW}"
    [ "$(wc -l < "${CRON_ALLOW}" | tr -d ' ')" = "1" ]
}

@test "INVARIANT (profile transition root-only → operator-list): adds operator users" {
    write_config "root-only"
    run_wd
    [ "$(wc -l < "${CRON_ALLOW}" | tr -d ' ')" = "1" ]
    write_config "operator-list" "alice,bob"
    run_wd
    [ "$(wc -l < "${CRON_ALLOW}" | tr -d ' ')" = "3" ]
    grep -q '^alice$' "${CRON_ALLOW}"
}

@test "INVARIANT (profile downgrade operator-list → root-only): REMOVES operator users (sovereign tightening)" {
    write_config "operator-list" "alice,bob"
    run_wd
    grep -q '^alice$' "${CRON_ALLOW}"
    write_config "root-only"
    run_wd
    ! grep -q '^alice$' "${CRON_ALLOW}"
    ! grep -q '^bob$' "${CRON_ALLOW}"
    [ "$(wc -l < "${CRON_ALLOW}" | tr -d ' ')" = "1" ]
}

@test "INVARIANT (cron.allow AND at.allow both updated symmetrically — operator-list applies to both)" {
    write_config "operator-list" "alice"
    run_wd
    grep -q '^alice$' "${CRON_ALLOW}"
    grep -q '^alice$' "${AT_ALLOW}"
}

@test "INVARIANT (operator-list with whitespace-padded users): whitespace handling" {
    # If the config has 'alice, bob' (whitespace after comma), the
    # split should trim whitespace.
    write_config "operator-list" "alice, bob"
    run_wd
    grep -q '^alice$' "${CRON_ALLOW}"
    grep -q '^bob$' "${CRON_ALLOW}"
    # No literal ' bob' (with leading space) leaking through.
    ! grep -qE '^ ' "${CRON_ALLOW}"
}

@test "INVARIANT (empty operator-list config → root-only effective)" {
    # If operator-list profile is set but operator_users is empty, the
    # effective output should still include root + nothing else.
    write_config "operator-list" ""
    run_wd
    grep -q '^root$' "${CRON_ALLOW}"
    [ "$(wc -l < "${CRON_ALLOW}" | tr -d ' ')" = "1" ]
}

@test "INVARIANT (deny files MUST be empty even on second apply — no stale entries leak)" {
    # Even if operator put something in the deny files between
    # selfdef apply runs, the second apply must re-zero them.
    write_config "root-only"
    run_wd
    echo 'sneaky-attacker' > "${CRON_DENY}"
    run_wd
    [ ! -s "${CRON_DENY}" ]
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates all 4 files)" {
    # Operator may rm one of the .allow/.deny files — apply must
    # rebuild them so cron/at access policy is restored.
    write_config "root-only"
    run_wd
    [ -f "${CRON_ALLOW}" ]
    rm -f "${CRON_ALLOW}" "${AT_ALLOW}" "${CRON_DENY}" "${AT_DENY}"
    run_wd
    [ -f "${CRON_ALLOW}" ]
    [ -f "${AT_ALLOW}" ]
    [ -f "${CRON_DENY}" ]
    [ -f "${AT_DENY}" ]
    grep -q '^root$' "${CRON_ALLOW}"
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "operator-list" "alice,bob"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"cron-baseline"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=operator-list'* ]]
}

@test "INVARIANT (operator pre-staged with manual content gets backed up — backup contains ORIGINAL contents)" {
    # The first-apply backup MUST preserve the original .allow file
    # content (with 'someone' user). Lock backup-content fidelity.
    write_config "root-only"
    run_wd
    [ -f "${CRON_ALLOW}.selfdef-backup" ]
    # Backup contains original 'someone' entry.
    grep -q '^someone$' "${CRON_ALLOW}.selfdef-backup"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # cron-baseline TOML; parser must tolerate without altering the
    # profile-gated behavior. operator-list-with-noise still adds
    # alice + bob alongside root.
    cat > "${CONF}" <<'TOMLEOF'
profile = "operator-list"
operator_users = "alice,bob"
operator_note = "ops cluster — bridge sysadmins"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    grep -q '^root$' "${CRON_ALLOW}"
    grep -q '^alice$' "${CRON_ALLOW}"
    grep -q '^bob$' "${CRON_ALLOW}"
}

@test "INVARIANT (root always present even under operator-list — anti-lockout floor)" {
    # Sister to firewalld-baseline ssh-always-allowed anti-lockout
    # floor INVARIANT. Even when the operator deliberately enables
    # operator-list with a small operator set (e.g., 'alice' only),
    # root MUST always be in the .allow list — otherwise a
    # regression that drops root from the rendered file would lock
    # out cron from operating at all (root is what runs the system
    # crontab + every daily/weekly/monthly job). Locks the anti-
    # lockout floor on the cron scheduler-access policy substrate.
    write_config "operator-list" "alice"
    run_wd
    grep -q '^root$' "${CRON_ALLOW}"
    grep -q '^alice$' "${CRON_ALLOW}"
    # And root is present in at.allow too (symmetric anti-lockout).
    grep -q '^root$' "${AT_ALLOW}"
}

@test "INVARIANT (empty .deny files render — sister anti-bypass to .allow positive-list)" {
    # Sister contract to the .allow anti-lockout floor. cron(8)
    # semantics: if .allow exists, ONLY users in .allow can use
    # crontab; if .deny exists, ONLY users NOT in .deny can. The
    # selfdef baseline writes BOTH .allow AND empty .deny — the
    # empty .deny serves as a positive marker that selfdef
    # actively manages the policy (defends against operator
    # accidentally restoring a permissive .deny that would
    # otherwise let everyone use cron on distros where .allow
    # is ignored). Locks the dual-file defense substrate on the
    # cron-scheduler access surface.
    write_config "root-only"
    run_wd
    [ -f "${CRON_DENY}" ]
    [ -f "${AT_DENY}" ]
    # .deny must NOT carry stale operator content (selfdef
    # ownership requires complete rewrite to empty + manage).
    ! grep -q '^evil-user$' "${CRON_DENY}"
    ! grep -q '^evil-user$' "${AT_DENY}"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO .allow/.deny files written when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing /etc/cron.allow + /etc/cron.deny +
    # /etc/at.allow + /etc/at.deny. A silent dry-run that
    # committed would lock out non-root users from crontab AT
    # PREVIEW TIME on a host where operator was investigating —
    # including potentially the operator's own account. Locks
    # dry-run-preserves-state on the cron-scheduler access
    # control substrate.
    rm -f "${CRON_ALLOW}" "${CRON_DENY}" "${AT_ALLOW}" "${AT_DENY}"
    write_config "root-only"
    DRY_RUN=1 run_wd
    [ ! -f "${CRON_ALLOW}" ]
    [ ! -f "${CRON_DENY}" ]
    [ ! -f "${AT_ALLOW}" ]
    [ ! -f "${AT_DENY}" ]
}

@test "INVARIANT (.allow files chmod 0644 — system-config convention)" {
    # Sister to brain-wide chmod 0644 INVARIANTs.
    write_config "root-only"
    run_wd
    [ -f "${CRON_ALLOW}" ]
    [ "$(stat -c '%a' "${CRON_ALLOW}")" = "644" ] || [ "$(stat -c '%a' "${CRON_ALLOW}")" = "640" ] || [ "$(stat -c '%a' "${CRON_ALLOW}")" = "600" ]
    [ -f "${AT_ALLOW}" ]
    [ "$(stat -c '%a' "${AT_ALLOW}")" = "644" ] || [ "$(stat -c '%a' "${AT_ALLOW}")" = "640" ] || [ "$(stat -c '%a' "${AT_ALLOW}")" = "600" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on cron-baseline installer surface
    # across 4-file install (cron.allow + cron.deny + at.allow +
    # at.deny) phases.
    write_config "root-only"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"cron-baseline"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no auto-uninstall: cron-baseline NEVER emits package-remove commands on cron/at)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The cron-baseline installer writes cron.allow/
    # cron.deny + at.allow/at.deny but MUST NEVER emit shell
    # commands that uninstall the cron or at packages
    # themselves (apt/dpkg/dnf/rpm/yum remove|purge|uninstall
    # cron|at|cronie|anacron). Silent auto-removal would tear
    # down the scheduled-task substrate entirely — every
    # downstream scheduled watchdog loses its scheduler.
    # Locks anti-package-removal contract on the cron-baseline
    # substrate.
    write_config "root-only"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(cron|at|cronie|anacron)'
    for f in "${CRON_ALLOW}" "${AT_ALLOW}"; do
        [ ! -f "${f}" ] || ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${f}"
    done
}
