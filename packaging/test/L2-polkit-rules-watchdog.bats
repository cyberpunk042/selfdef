#!/usr/bin/env bats
# L2 bats functional tests for the polkit-rules-watchdog scan script.
#
# /etc/polkit-1/rules.d/*.rules (JS) decide authorization for privileged
# actions. A new rule file, a world-writable/non-root one, or a new
# authorization GRANT (polkit.Result.YES) is a privesc-persistence surface
# (T1548). Severity:
#   ok    → no delta
#   warn  → a rule changed or removed
#   alert → a NEW rule file, a new grant, or a world-writable/non-root file
#
# Run with: bats packaging/test/L2-polkit-rules-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/polkit-rules-watchdog/systemd/polkit-rules-watchdog.sh"

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
    BASELINE="${TMP}/baseline.tsv"
    RULESD="${TMP}/rules.d"; mkdir -p "${RULESD}"
    RULE="${RULESD}/10-benign.rules"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_POLKIT_PROFILE="${PROFILE:-report}" \
    SELFDEF_POLKIT_BASELINE="${BASELINE}" \
    SELFDEF_POLKIT_DIRS="${DIRS_V:-$RULESD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# Benign rule: REQUIRES admin auth (does not GRANT) — no polkit.Result.YES.
seed_benign() {
    printf 'polkit.addRule(function(action, subject) {\n  if (action.id == "org.example.app") {\n    return polkit.Result.AUTH_ADMIN;\n  }\n});\n' > "${RULE}"
}

@test "no polkit rules → ok / no_polkit_rules" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_polkit_rules"'
    cap | grep -q '"severity":"ok"'
}

@test "benign rule, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged rules on second run → ok / polkit_rules_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"polkit_rules_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a NEW rule file → alert / polkit_rules_new" {
    seed_benign
    run_wd
    printf 'polkit.addRule(function(action, subject) { return polkit.Result.AUTH_ADMIN; });\n' > "${RULESD}/20-extra.rules"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"polkit_rules_new"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable rule file → alert / polkit_rules_suspicious" {
    seed_benign
    run_wd
    chmod 0666 "${RULE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"polkit_rules_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a benign rule content change → warn / polkit_rules_changed" {
    seed_benign
    run_wd
    printf 'polkit.addRule(function(action, subject) {\n  if (action.id == "org.example.other") {\n    return polkit.Result.AUTH_ADMIN;\n  }\n});\n' > "${RULE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"polkit_rules_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign auth-admin rule is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "enforce profile exits non-zero on a new rule file" {
    seed_benign
    run_wd
    printf 'polkit.addRule(function(a, s) { return polkit.Result.YES; });\n' > "${RULESD}/30-grant.rules"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — polkit rules inventory enumerates auth-grant surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (existing-file polkit.Result.YES grant addition): editing a rule to add a YES grant → alert" {
    # An ADDED rule file is the canonical case (test 4 above), but
    # an attacker can also edit an EXISTING file to add a YES grant.
    # Locks both attack paths.
    seed_benign
    run_wd
    printf 'polkit.addRule(function(action, subject) {\n  return polkit.Result.YES;\n});\n' > "${RULE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable rule): baseline_initial fires alert if a rule file is already world-writable at install-time" {
    seed_benign
    chmod 0666 "${RULE}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (group-writable rule file): a group-writable .rules → alert above the bare world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${RULE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "DELTA detect — REMOVED rule file → warn / polkit_rules_changed (operator pruning)" {
    seed_benign
    cat > "${RULESD}/20-other.rules" <<'EOF'
polkit.addRule(function(a, s) { return polkit.Result.AUTH_ADMIN; });
EOF
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    rm -f "${RULESD}/20-other.rules"
    run_wd
    cap | grep -qE '"event":"polkit_rules_changed"'
}

@test "DELTA detect — newly-ADDED rule filename surfaces in JSON sample (operator triage)" {
    seed_benign
    run_wd
    printf 'polkit.addRule(function(a, s) { return polkit.Result.AUTH_ADMIN; });\n' > "${RULESD}/99-distinctive-attacker.rules"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q 'distinctive-attacker'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-polkit-rules -- ')
    [ "${main_count}" = "1" ]
}
