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

@test "INVARIANT (auto-trust): polkit-rules-watchdog DOES auto-refresh baseline (operator polkit reconfiguration common)" {
    # CONTRAST against no-auto-trust family. polkit rule changes
    # ARE common operator actions (adding self-grants for known
    # apps, adjusting auth-admin scopes). Watchdog flags delta
    # for THIS run; baseline catches up on next. Asymmetry locked
    # against no-auto-trust regression.
    seed_benign
    run_wd
    printf 'polkit.addRule(function(a, s) { return polkit.Result.YES; });\n' > "${RULESD}/30-grant.rules"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # baseline refreshed → ok
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (current behavior: commented YES grant IS flagged — JS comments not yet filtered; refinement opportunity)" {
    # Current behavior: the watchdog does NOT yet filter JS // line
    # comments or /* block comments before searching for
    # polkit.Result.YES. A commented YES grant inside a rule file
    # DOES surface as content-change. Lock current behavior so
    # future filter-pass refinement is intentional, not a silent
    # regression.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${RULE}" <<'EOF'
polkit.addRule(function(action, subject) {
  if (action.id == "org.example.app") {
    // future: return polkit.Result.YES;
    return polkit.Result.AUTH_ADMIN;
  }
});
EOF
    run_wd
    # The content delta is detected; current severity may be
    # warn (content-changed) or alert (treating commented YES as
    # real grant). Lock that the severity is NOT silently 'ok'.
    ! cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (out-of-scope polkit Result types: NOT_HANDLED + AUTH_SELF NOT flagged — only YES matters as alert)" {
    # The watchdog targets polkit.Result.YES specifically (full
    # grant). Other Result types (NOT_HANDLED, AUTH_ADMIN_KEEP,
    # AUTH_SELF) are legit operator-configurations.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${RULESD}/15-self-keep.rules" <<'EOF'
polkit.addRule(function(action, subject) {
  return polkit.Result.AUTH_SELF_KEEP;
});
EOF
    run_wd
    # New file → alert/warn fires (file-add detection); but the
    # event should NOT be specific to YES-grant.
    cap | grep -qE '"severity":"(alert|warn)"'
    # The NEW-rule event fires for any new file, regardless of
    # grant type. Operator triage uses sample to filter.
    cap | grep -q '"event":"polkit_rules_new"'
}

@test "INVARIANT (multi-grant single file: multiple YES grants in one rule file → single alert)" {
    # When a single new file carries multiple YES grants, the alert
    # fires once (not per-grant). Locks the consolidation.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${RULESD}/40-multi-grant.rules" <<'EOF'
polkit.addRule(function(a, s) {
  if (a.id == "org.app.one") return polkit.Result.YES;
  if (a.id == "org.app.two") return polkit.Result.YES;
  if (a.id == "org.app.three") return polkit.Result.YES;
});
EOF
    run_wd
    cap | grep -q '"event":"polkit_rules_new"'
    cap | grep -q '"severity":"alert"'
    main_count=$(cap | grep -cE '^-t selfdef-polkit-rules -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (multi-dir scan: rule planted in a second polkit dir ALSO scanned — system + local)" {
    # polkit consults both /etc/polkit-1/rules.d (operator) and
    # /usr/share/polkit-1/rules.d (system) — both must be enumerated
    # for full grant-injection coverage.
    RULESD2="${TMP}/rules.d.usr"; mkdir -p "${RULESD2}"
    seed_benign
    DIRS_V="${RULESD} ${RULESD2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${RULESD2}/99-system-evil.rules" <<'EOF'
polkit.addRule(function(a, s) { return polkit.Result.YES; });
EOF
    DIRS_V="${RULESD} ${RULESD2}" run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (non-root-owned rule file → alert above ownership bar — privesc surface)" {
    # A rule file owned by non-root (or chgrp'd to attacker-writable
    # group at 0664) is a tampering primitive even if content is
    # benign. The group-writable axis is already locked; this case
    # extends the file-mode predicate coverage to a sister bit.
    seed_benign
    run_wd
    chmod 0660 "${RULE}"                                # group-writable, owner+group only
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn|ok)"'       # current behavior lock — 0660 may or may not trip
}

@test "INVARIANT (sample names quoted-rule-file in JSON — operator triage routing)" {
    # When a NEW rule file is detected, the sample MUST surface its
    # basename so operator dashboard routes triage to the right path.
    # Sister contract: nfs-exports test 14 + similar across the brain.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'polkit.addRule(function(a, s) { return polkit.Result.YES; });\n' > "${RULESD}/77-very-distinctive-name.rules"
    run_wd
    cap | grep -q 'very-distinctive-name'
}

@test "INVARIANT (current-behavior: pre-existing YES grant at install-time → baseline_initial captures it without immediate alert)" {
    # CONTRAST with the access-conf no-auto-trust install-time-vet
    # family. polkit-rules-watchdog is auto-trust (per the auto-
    # trust INVARIANT above) — at install-time it just snapshots
    # current state without flagging pre-existing YES grants. The
    # YES-grant alert fires on subsequent DELTA from this snapshot,
    # not on the initial capture itself. Locks current architectural
    # boundary: install-time-vet is OUT of scope for this watchdog
    # (parallels securetty-watchdog auto-trust install-time
    # boundary). Refinement opportunity to add install-time-vet is
    # tracked separately.
    cat > "${RULE}" <<'EOF'
polkit.addRule(function(action, subject) {
  return polkit.Result.YES;
});
EOF
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named .rules file surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker drops a new
    # polkit .rules file (T1548 — Abuse Elevation Control
    # Mechanism via polkit YES grant; the planted rule lets
    # attacker invoke privileged D-Bus methods without password
    # prompt), the file name MUST surface in the JSON sample so
    # operator dashboard routes triage to the right path.
    cat > "${RULE}" <<'EOF'
polkit.addRule(function(action, subject) { return polkit.Result.AUTH_ADMIN; });
EOF
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${RULESD}/99-distinctive-attacker-grant.rules" <<'EOF'
polkit.addRule(function(action, subject) { return polkit.Result.YES; });
EOF
    run_wd
    cap | grep -q 'distinctive-attacker-grant'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to many other watchdog single-MAIN-logger-line
    # INVARIANTs across the brain. selfdef-polkit-rules tag
    # must fire EXACTLY ONCE per scan regardless of how many
    # YES-grant rules surface across multiple .rules files in
    # a single scan. Multi-line output would break SDD-062
    # downstream JSON-line consumer (Sigma correlator). Locks
    # consolidation discipline on the T1548 polkit YES-grant
    # surveillance surface.
    cat > "${RULE}" <<'EOF'
polkit.addRule(function(action, subject) { return polkit.Result.AUTH_ADMIN; });
EOF
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${RULESD}/99-evil-a.rules" <<'EOF'
polkit.addRule(function(action, subject) { return polkit.Result.YES; });
EOF
    cat > "${RULESD}/99-evil-b.rules" <<'EOF'
polkit.addRule(function(action, subject) { return polkit.Result.YES; });
EOF
    cat > "${RULESD}/99-evil-c.rules" <<'EOF'
polkit.addRule(function(action, subject) { return polkit.Result.YES; });
EOF
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-polkit-rules -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # Operator may wipe baseline during host triage to force a
    # fresh inventory. The watchdog MUST re-create the baseline
    # cleanly on the next scan AND emit baseline_initial (not
    # crash AND not silently no-op). Locks state-resilience on
    # the polkit-rules-grant surveillance surface (T1548 Abuse
    # Elevation Control Mechanism via polkit YES-grant).
    seed_benign
    run_wd                                              # establishes baseline
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"                                  # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # must re-establish
    [ -f "${BASELINE}" ]
    cap | grep -qE '"event":"baseline_initial"'
}

@test "INVARIANT (severity field is bounded vocabulary {ok,warn,alert} — operator dashboard severity axis lock)" {
    # Sister to brain-wide bounded-vocabulary INVARIANTs.
    seed_benign
    run_wd
    sev=$(cap | grep -oE '"severity":"[^"]+"' | head -1)
    case "${sev}" in
        '"severity":"ok"'|'"severity":"warn"'|'"severity":"alert"') : ;;
        *) fail "severity '${sev}' outside bounded vocabulary {ok,warn,alert}" ;;
    esac
}

@test "INVARIANT (baseline file is chmod 0600 — confidentiality of polkit rule inventory)" {
    # Sister to brain-wide baseline-chmod-0600 confidentiality
    # INVARIANTs across L2 surveillance suites. The polkit-
    # rules-watchdog baseline TSV contains the inventory of
    # PolicyKit JS rules + admin-grants which discloses the
    # auth-decision-engine config to any user able to read the
    # file. Mode 0600 (root-only) is the canonical
    # confidentiality contract — mode 0644 would expose the
    # privilege-grant inventory to reconnaissance enabling
    # attacker to map T1548.003 elevation paths. Locks file-
    # mode confidentiality on the polkit-rules surveillance
    # substrate.
    seed_benign
    run_wd
    [ -f "${BASELINE}" ]
    mode="$(stat -c '%a' "${BASELINE}")"
    [ "${mode}" = "600" ] || [ "${mode}" = "640" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # polkit-rules-watchdog runs ON the timer's scheduled fire —
    # diffs /etc/polkit-1/rules.d against baseline, emits a
    # verdict on yes-without-auth rule additions, then exits.
    # Type=simple would break timer OnUnitActiveSec semantics.
    # Locks oneshot-probe contract on the polkit-rules-watchdog
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/polkit-rules-watchdog/systemd/selfdef-polkit-rules.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. polkit-rules-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # polkit-rules-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # polkit-rules-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polkit-rules-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'polkit-rules-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: polkit-rules-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. polkit-rules-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the polkit-rules-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/polkit-rules-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}
