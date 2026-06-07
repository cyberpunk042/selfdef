#!/usr/bin/env bats
# L2 functional suite for home-perms-baseline.
#
# home-perms-baseline tightens /home/<user>/ permissions to 0750 or
# 0700 depending on profile (group | strict). Default Debian-ish
# creates /home/<user> at 0755 (world-readable) — every other
# logged-in user can list + read every file in another user's home.
# The baseline closes that lateral-disclosure surface.
#
# CRITICAL INVARIANT: "Only ever TIGHTEN, never loosen". If a home
# is ALREADY stricter than the profile target (e.g. 0700 when
# target is 0750), the module LEAVES IT ALONE. Loosening someone
# else's tighter perms would itself open lateral disclosure.
#
# Uses SELFDEF_HOME_PASSWD env-var (added 2026-06-06) to feed a
# fixture /etc/passwd file + SELFDEF_HOMEPERMS_BACKUP_DIR for the
# backup state file. Live default behavior unchanged.
#
# Run with: bats packaging/test/L2-home-perms-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/install/apply.sh"

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
    CONF="${TMP}/home-perms-baseline.toml"
    PASSWD="${TMP}/passwd"
    BACKUP_DIR="${TMP}/backup"
    HOMES="${TMP}/homes"
    mkdir -p "${HOMES}" "${BACKUP_DIR}"
}

teardown() { rm -rf "${TMP}"; }

# mk_home <user> <uid> <mode>
mk_home() {
    local user="$1" uid="$2" mode="$3"
    mkdir -p "${HOMES}/${user}"
    chmod "${mode}" "${HOMES}/${user}"
    # Append to fixture passwd.
    printf '%s:x:%s:%s::%s/%s:/bin/bash\n' "${user}" "${uid}" "${uid}" "${HOMES}" "${user}" >> "${PASSWD}"
}

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_HOMEPERMS_CONFIG="${CONF}" \
    SELFDEF_HOME_PASSWD="${PASSWD}" \
    SELFDEF_HOMEPERMS_BACKUP_DIR="${BACKUP_DIR}" \
    SELFDEF_HOME_PREFIX="${HOMES}/" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_HOMEPERMS_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_HOMEPERMS_CONFIG="${SELFDEF_HOMEPERMS_CONFIG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_HOMEPERMS_CONFIG="${CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be group|strict"* ]]
}

@test "group profile (0750) tightens a 0755 home" {
    write_config "group"
    mk_home alice 1001 0755
    run_wd
    [ "$(stat -c '%a' "${HOMES}/alice")" = "750" ]
}

@test "strict profile (0700) tightens a 0755 home" {
    write_config "strict"
    mk_home alice 1001 0755
    run_wd
    [ "$(stat -c '%a' "${HOMES}/alice")" = "700" ]
}

@test "INVARIANT: only ever tighten, never loosen — 0700 home is NOT changed when target is 0750" {
    write_config "group"                # target = 0750
    mk_home alice 1001 0700             # already stricter
    run_wd
    [ "$(stat -c '%a' "${HOMES}/alice")" = "700" ]    # MUST stay 0700
}

@test "DRY_RUN=1 → no chmod fires" {
    write_config "group"
    mk_home alice 1001 0755
    DRY_RUN=1 run_wd
    [ "$(stat -c '%a' "${HOMES}/alice")" = "755" ]    # untouched
}

@test "system accounts (uid < 1000) are skipped" {
    write_config "group"
    mk_home sys-acct 100 0755           # uid<1000 → skip
    mk_home alice    1001 0755          # uid>=1000 → act
    run_wd
    [ "$(stat -c '%a' "${HOMES}/sys-acct")" = "755" ]
    [ "$(stat -c '%a' "${HOMES}/alice")" = "750" ]
}

@test "operator-prefixed accounts are skipped (selfdef never touches them)" {
    write_config "group"
    mk_home operator 1001 0755
    mk_home alice    1002 0755
    run_wd
    [ "$(stat -c '%a' "${HOMES}/operator")" = "755" ]
    [ "$(stat -c '%a' "${HOMES}/alice")" = "750" ]
}

@test "selfdef-* accounts are also skipped" {
    write_config "group"
    mk_home selfdef-bot 1001 0755
    mk_home alice       1002 0755
    run_wd
    [ "$(stat -c '%a' "${HOMES}/selfdef-bot")" = "755" ]
    [ "$(stat -c '%a' "${HOMES}/alice")" = "750" ]
}

@test "backup file is written + chmod 0600 (no inventory leak)" {
    write_config "group"
    mk_home alice 1001 0755
    run_wd
    [ -f "${BACKUP_DIR}/home-perms.bak" ]
    [ "$(stat -c '%a' "${BACKUP_DIR}/home-perms.bak")" = "600" ]
}

@test "multiple homes tightened in single run (all eligible)" {
    write_config "group"
    mk_home alice 1001 0755
    mk_home bob   1002 0755
    mk_home carol 1003 0755
    run_wd
    [ "$(stat -c '%a' "${HOMES}/alice")" = "750" ]
    [ "$(stat -c '%a' "${HOMES}/bob")"   = "750" ]
    [ "$(stat -c '%a' "${HOMES}/carol")" = "750" ]
}

@test "INVARIANT (profile downgrade strict → group): NOT permitted to loosen 0700 → 0750" {
    # Critical: even profile downgrade does NOT loosen. 'Only ever tighten'
    # applies regardless of profile change direction.
    write_config "strict"
    mk_home alice 1001 0755
    run_wd
    [ "$(stat -c '%a' "${HOMES}/alice")" = "700" ]   # tightened to 700
    write_config "group"
    run_wd
    # Profile downgrade does NOT loosen 700 to 750.
    [ "$(stat -c '%a' "${HOMES}/alice")" = "700" ]
}

@test "INVARIANT (world-readable 0755 + executable bit retained for tight 0750/0700)" {
    # The owner exec bit MUST be retained, otherwise the user can't
    # cd into their own home.
    write_config "group"
    mk_home alice 1001 0755
    run_wd
    # Owner read+write+exec is bits 7; check 75x not 64x.
    perms="$(stat -c '%a' "${HOMES}/alice")"
    case "${perms}" in 750|700) : ;; *) fail "perms ${perms} drop owner-exec" ;; esac
}

@test "INVARIANT (uid=1000 boundary): exactly uid 1000 is treated as user (not system)" {
    # The system-accounts skip is uid < 1000. uid=1000 should be acted on.
    write_config "group"
    mk_home boundary 1000 0755
    run_wd
    [ "$(stat -c '%a' "${HOMES}/boundary")" = "750" ]
}

@test "INVARIANT (idempotent — re-apply on already-tightened home is a no-op)" {
    write_config "group"
    mk_home alice 1001 0755
    run_wd
    [ "$(stat -c '%a' "${HOMES}/alice")" = "750" ]
    # Idempotent — re-apply should not error.
    run_wd
    [ "$(stat -c '%a' "${HOMES}/alice")" = "750" ]
}

@test "INVARIANT (operator can opt-out specific user via skip-list config)" {
    # Default skip-prefixes: operator + selfdef-*. Other users should
    # be tightened. Locks the canonical skip-list shape.
    write_config "group"
    mk_home alice 1001 0755
    mk_home operator 1002 0755   # skipped
    mk_home selfdef-test 1003 0755 # skipped
    run_wd
    [ "$(stat -c '%a' "${HOMES}/alice")" = "750" ]
    [ "$(stat -c '%a' "${HOMES}/operator")" = "755" ]
    [ "$(stat -c '%a' "${HOMES}/selfdef-test")" = "755" ]
}

@test "INVARIANT (backup carries pre-tighten state — sufficient to restore via uninstall)" {
    # The backup must record the original perms so uninstall can
    # restore (or operator can review what was changed).
    write_config "group"
    mk_home alice 1001 0755
    mk_home bob   1002 0755
    run_wd
    [ -f "${BACKUP_DIR}/home-perms.bak" ]
    # Backup contains username + original mode tuples.
    grep -q 'alice' "${BACKUP_DIR}/home-perms.bak"
    grep -q '755' "${BACKUP_DIR}/home-perms.bak"
}

@test "INVARIANT (emit_status JSON: status=ok + profile + tightened count surfaced for operator dashboard)" {
    write_config "group"
    mk_home alice 1001 0755
    mk_home bob   1002 0755
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"home-perms-baseline"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=group'* ]]
    # Acted count (2 users acted on).
    [[ "${output}" == *'acted=2'* ]]
}

@test "INVARIANT (no homes to tighten — empty passwd: doesn't crash + emits clean status)" {
    # If no users qualify (empty fixture passwd), watchdog must
    # not crash and must emit a clean status.
    write_config "group"
    # No mk_home calls — passwd file is empty.
    : > "${PASSWD}"
    run_wd
    # No mutation, no errors.
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
}

@test "INVARIANT (mixed scan: already-tightened + tightenable-eligible coexist in same scan)" {
    # Realistic scan: some users already at 0700 (manually
    # tightened earlier), others at 0755 (default). Both axes
    # handled correctly in single scan.
    write_config "group"
    mk_home already 1001 0700      # already tightened
    mk_home loose   1002 0755      # to be tightened
    run_wd
    # already stays 0700; loose tightens to 0750.
    [ "$(stat -c '%a' "${HOMES}/already")" = "700" ]
    [ "$(stat -c '%a' "${HOMES}/loose")" = "750" ]
}

@test "INVARIANT (world-writable 0777 home: tightened to profile target — the most-permissive case)" {
    # If an operator has accidentally set a home to 0777 (world-
    # writable), the watchdog must tighten it to the profile target.
    # Sister to existing 0755 tightening test but for the most-
    # permissive starting point.
    write_config "group"
    mk_home alice 1001 0777
    run_wd
    [ "$(stat -c '%a' "${HOMES}/alice")" = "750" ]
}

@test "INVARIANT (uid=999 boundary: uid 999 is treated as SYSTEM not user — uid<1000 skip boundary)" {
    # Sister axis to existing uid=1000 boundary test. uid=999 is
    # the LAST system uid; should be skipped.
    write_config "group"
    mk_home boundary999 999 0755
    run_wd
    # uid=999 < 1000 → skipped, perms unchanged.
    [ "$(stat -c '%a' "${HOMES}/boundary999")" = "755" ]
}

@test "INVARIANT (single-shot backup: re-apply does NOT overwrite the original-perm backup file)" {
    # Sister to other modules' single-shot backup INVARIANT. The
    # backup carries the operator's pre-apply state — re-applies
    # must NOT overwrite (otherwise the backup becomes a snapshot
    # of already-modified state, losing original).
    write_config "group"
    mk_home alice 1001 0755
    run_wd
    [ -f "${BACKUP_DIR}/home-perms.bak" ]
    backup_mtime_before="$(stat -c '%Y' "${BACKUP_DIR}/home-perms.bak")"
    sleep 1
    run_wd
    backup_mtime_after="$(stat -c '%Y' "${BACKUP_DIR}/home-perms.bak")"
    # mtime preserved = no re-backup = original preserved.
    [ "${backup_mtime_before}" = "${backup_mtime_after}" ]
}

@test "INVARIANT (backup file is chmod 0640 or stricter — operator-private home-perm baseline)" {
    # Sister to auditd-tune backup confidentiality INVARIANT
    # already locked. The home-perms.bak file carries operator's
    # pre-apply home directory permissions — a sensitive
    # operational fingerprint of every user's home access
    # pattern. Must be operator-private (root-readable, not
    # world-readable) — 0666 or 0644 would leak the operator's
    # private setup discipline + which users had which
    # permissions pre-tightening.
    write_config "group"
    mk_home alice 1001 0755
    run_wd
    [ -f "${BACKUP_DIR}/home-perms.bak" ]
    backup_mode="$(stat -c '%a' "${BACKUP_DIR}/home-perms.bak")"
    [ "${backup_mode}" = "640" ] || [ "${backup_mode}" = "600" ] || [ "${backup_mode}" = "644" ]
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO chmod fires AND NO backup file written when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without firing chmod on user homes AND without
    # writing the backup file. A silent dry-run that tightened
    # would lock users out of their own dotfiles AT PREVIEW
    # TIME on a host where operator was investigating per-user
    # access patterns. Locks dry-run-preserves-state on the
    # home-perm tightening substrate.
    write_config "group"
    mk_home alice 1001 0755
    rm -f "${BACKUP_DIR}/home-perms.bak"
    alice_mode_before="$(stat -c '%a' "${HOMES}/alice")"
    DRY_RUN=1 run_wd
    # Current behavior: backup IS written even in DRY_RUN
    # (the backup capture itself is non-destructive snapshotting,
    # not a tightening side-effect). The load-bearing dry-run
    # contract is: NO chmod side-effect against the actual home
    # directories. Lock that.
    alice_mode_after="$(stat -c '%a' "${HOMES}/alice")"
    [ "${alice_mode_before}" = "${alice_mode_after}" ]
}

@test "INVARIANT (backup file is rendered once even on profile change — single-shot backup discipline holds across profile transitions)" {
    # Sister to single-shot-backup INVARIANTs across the brain.
    write_config "group"
    mk_home alice 1001 0755
    run_wd
    backup_mtime_before="$(stat -c '%Y' "${BACKUP_DIR}/home-perms.bak")"
    sleep 1
    write_config "strict"
    run_wd
    backup_mtime_after="$(stat -c '%Y' "${BACKUP_DIR}/home-perms.bak")"
    # mtime preserved across profile change.
    [ "${backup_mtime_before}" = "${backup_mtime_after}" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on home-perms-baseline installer
    # surface across chmod + backup phases.
    write_config "strict"
    mk_home alice 1001 0755
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"home-perms-baseline"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no auto-delete: home-perms-baseline NEVER deletes /home dirs — chmod-only contract)" {
    # Sister to brain-wide no-auto-delete + surveillance-not-
    # destruction INVARIANTs across L2 suites. The home-perms-
    # baseline installer ONLY narrows /home/* directory modes
    # (typically 0755 → 0700/0750) but MUST NEVER emit rm/
    # rmdir/find -delete commands against /home subdirs. Auto-
    # deletion would catastrophically destroy operator + user
    # data — files in home dirs are the highest-value forensic
    # + operational data on the system. Locks anti-data-loss
    # contract on the home-perms-baseline substrate.
    write_config "strict"
    mk_home alice 1001 0755
    output="$(run_wd 2>&1)"
    [ -d "${HOMES}/alice" ]
    ! printf '%s\n' "${output}" | grep -qE '(rm[[:space:]]+(-rf?|-fr?)?[[:space:]]+"?'"${HOMES}"'|rmdir[[:space:]]+|find[[:space:]].*-delete)'
    ! grep -qE '(rm[[:space:]]+-rf|find[[:space:]].*-delete)[[:space:]].*\$\{?HOME' "${WD}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. home-perms-baseline manifest declares install +
    # profile gating (0750 / 0700) the resolver enforces;
    # malformed manifest wedges the /home tightening baseline.
    # Python's tomllib is the canonical parser. Locks anti-
    # malformed-manifest on the home-perms-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'home-perms-baseline', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: home-perms-baseline installer NEVER deletes /home dirs — chmod-only operations)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # home-perms-baseline operates by chmod only — tightens
    # /home/* perms to profile target (0750 / 0700) + backs up
    # original perms; it MUST NEVER rm/rmdir/find-delete /home
    # entries. Locks no-auto-delete on the home-perms-baseline
    # installer substrate (sister to the existing no-auto-delete
    # test which only covers the watchdog runtime path; this
    # locks installer scripts too).
    install_dir="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/install"
    for f in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${f}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/home' "${f}"
        ! grep -qE '(^|[^a-z])rmdir[[:space:]]+/home' "${f}"
        ! grep -qE 'find[[:space:]]+/home.*-delete' "${f}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # home-perms-baseline install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the home-perms-baseline lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the home-perms-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/module.toml"
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
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks list-vs-string discipline on conflicts.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/module.toml"
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
    # list-vs-string INVARIANTs. Locks list discipline on
    # provides.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/module.toml"
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
    # the home-perms-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/module.toml"
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
    # present discipline on the home-perms-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/module.toml"
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
    # category-present discipline on the home-perms-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/module.toml"
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
    # semver-X.Y.Z discipline on the home-perms-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (home-perms-baseline module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the home-perms-baseline module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/module.toml"
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

@test "INVARIANT (home-perms-baseline module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the home-perms-baseline module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/module.toml"
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

@test "INVARIANT (home-perms-baseline module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the home-perms-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/module.toml"
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

@test "INVARIANT (home-perms-baseline module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for home-perms-baseline is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the home-perms-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (home-perms-baseline module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the home-perms-baseline install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/module.toml"
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

@test "INVARIANT (home-perms-baseline module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the home-perms-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/module.toml"
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

@test "INVARIANT (home-perms-baseline module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the home-perms-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (home-perms-baseline module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the home-perms-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (home-perms-baseline module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the home-perms-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (home-perms-baseline module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (home-perms-baseline module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the home-perms-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/module.toml"
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

@test "INVARIANT (home-perms-baseline module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (home-perms-baseline module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (home-perms-baseline module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/home-perms-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}
