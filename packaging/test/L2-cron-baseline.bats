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

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. cron-baseline installs cron.allow/cron.deny +
    # at.allow/at.deny gates the resolver enforces; a malformed
    # module.toml would break install-time gating + leave the
    # cron-access-control wedged. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # cron-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'cron-baseline', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: cron-baseline installer NEVER deletes operator-pre-existing cron.allow/cron.deny — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # cron-baseline writes its own /etc/cron.allow/cron.deny +
    # /etc/at.allow/at.deny; it MUST NEVER rm/find-delete an
    # operator's pre-existing files outside the canonical set.
    # Locks no-auto-delete on the cron-baseline installer
    # substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/install"
    for f in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${f}" ] || continue
        ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+/etc/cron\.(d|hourly|daily|weekly|monthly)' "${f}"
        ! grep -qE 'find[[:space:]]+/etc/cron\.(d|hourly|daily|weekly|monthly).*-delete' "${f}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # cron-baseline install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the cron-baseline lifecycle
    # substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/install"
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
    # the depends_on field of the cron-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
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
    # cron-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
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
    # the cron-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
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
    # the cron-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
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
    # present discipline on the cron-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
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
    # category-present discipline on the cron-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
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
    # semver-X.Y.Z discipline on the cron-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (cron-baseline module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the cron-baseline module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
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

@test "INVARIANT (cron-baseline module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the cron-baseline module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
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

@test "INVARIANT (cron-baseline module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the cron-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
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

@test "INVARIANT (cron-baseline module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for cron-baseline is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the cron-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (cron-baseline module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the cron-baseline install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
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

@test "INVARIANT (cron-baseline module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the cron-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
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

@test "INVARIANT (cron-baseline module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the cron-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (cron-baseline module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the cron-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (cron-baseline module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the cron-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (cron-baseline module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (cron-baseline module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the cron-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
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

@test "INVARIANT (cron-baseline module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (cron-baseline module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (cron-baseline module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (cron-baseline module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (cron-baseline module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (cron-baseline module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (cron-baseline README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (cron-baseline install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (cron-baseline install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (cron-baseline install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (cron-baseline install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (cron-baseline install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (cron-baseline install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/cron-baseline/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}
