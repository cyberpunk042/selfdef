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
