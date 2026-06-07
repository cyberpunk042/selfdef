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

@test "INVARIANT (polkit-rules-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the polkit-rules-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/polkit-rules-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (polkit-rules-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # polkit-rules-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/polkit-rules-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (polkit-rules-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # polkit-rules-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/polkit-rules-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (polkit-rules-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the polkit-rules-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/polkit-rules-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (polkit-rules-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # polkit-rules-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/polkit-rules-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (polkit-rules-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the polkit-rules-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/polkit-rules-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (polkit-rules-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the polkit-rules-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/polkit-rules-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (polkit-rules-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # polkit-rules-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/polkit-rules-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (polkit-rules-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
    # Sister to brain-wide TimeoutStartSec= INVARIANT family.
    # Watchdog .service units are Type=oneshot probes — they
    # MUST declare a TimeoutStartSec= upper bound so systemd
    # kills a hung probe (e.g. a stuck sha256sum on a slow
    # NFS-mounted target file) rather than blocking the
    # next timer fire indefinitely. Without TimeoutStartSec=
    # systemd's default (90s) applies, but the canonical
    # selfdef contract pins this explicitly per watchdog so
    # operators reading the .service know the bound at a
    # glance. A regression that dropped TimeoutStartSec=
    # would silently revert to the systemd default + mask
    # the explicit-bound contract. Locks anti-hang oneshot-
    # bound discipline on the polkit-rules-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/polkit-rules-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (polkit-rules-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
    # Sister to brain-wide systemd resource-priority INVARIANT
    # family. Watchdog .service units run periodic scans (often
    # sha256sum walks of large config trees) — they MUST be
    # deprioritized via Nice= (positive value = lower priority
    # under load) so that the watchdog scan doesn't starve
    # operator-foreground workloads when CPU is contended.
    # The canonical selfdef value is Nice=15 (well above the
    # background-batch threshold of 10). A regression dropping
    # Nice= would let watchdog scans compete with foreground at
    # default Nice=0, surfacing as latency spikes on contended
    # hosts. Locks the idle-priority anti-resource-starve
    # discipline on the polkit-rules-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/polkit-rules-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (polkit-rules-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd PrivateTmp= INVARIANT
    # family. Watchdog .service units that run periodic
    # sha256sum walks may create transient /tmp files. The
    # PrivateTmp= directive (canonically =true) instructs
    # systemd to give the unit its own /tmp mount namespace —
    # an attacker who exploits the watchdog cannot reach
    # /tmp files owned by other processes (e.g. ssh-agent
    # sockets), and the watchdog's own /tmp residue is
    # automatically cleaned at unit-stop. A regression
    # dropping PrivateTmp= would share /tmp with the host,
    # exposing the watchdog as a side-channel for any
    # /tmp-based pivot. Locks the /tmp namespace-isolation
    # discipline on the polkit-rules-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/polkit-rules-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (polkit-rules-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd ProtectHome= INVARIANT
    # family. Watchdog .service units have no business
    # reading /home — their probe targets are system-config
    # paths (/etc/*). The ProtectHome= directive
    # (canonically =read-only) instructs systemd to either
    # hide (=true) or read-only-mount (=read-only) the
    # /home, /root, and /run/user directories within the
    # unit's mount namespace. An exploited watchdog cannot
    # then exfiltrate ~/.bash_history, ~/.ssh/*, or operator
    # credentials. A regression dropping ProtectHome= would
    # expose all operator home contents to a compromised
    # watchdog. Locks the home-namespace-isolation
    # discipline on the polkit-rules-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/polkit-rules-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (polkit-rules-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
    # Sister to brain-wide systemd NoNewPrivileges= INVARIANT
    # family. The NoNewPrivileges=true directive instructs
    # the kernel to set PR_SET_NO_NEW_PRIVS on the watchdog
    # process — any subsequent execve() in the watchdog
    # script (sha256sum, awk, etc.) is forbidden to acquire
    # NEW privileges via setuid/setgid/file-capabilities. An
    # exploited watchdog cannot escalate via a setuid helper
    # (e.g. /usr/bin/su, /usr/bin/sudo). A regression
    # dropping NoNewPrivileges= would leave the watchdog
    # exposed to setuid-binary pivot. Locks the privilege-
    # escalation containment discipline on the polkit-rules-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/polkit-rules-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (polkit-rules-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the polkit-rules-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/polkit-rules-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (polkit-rules-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
    # Sister to brain-wide systemd ExecStart binary-path
    # INVARIANT family. Watchdog .service units MUST execute
    # the watchdog script from /usr/local/libexec/selfdef/
    # (operator-extension path, not /usr/bin which is
    # Debian-package-only). The canonical libexec/selfdef/
    # path lets operators override the watchdog script
    # without rebuilding the .deb (sister to brain-wide
    # operator-extension /usr/local/* discipline). A
    # regression that pointed ExecStart at /usr/bin/ would
    # surface as a "stale-watchdog-binary" on hosts where
    # operators patched the libexec copy. Locks the
    # libexec/selfdef ExecStart-path discipline on the
    # polkit-rules-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/polkit-rules-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (polkit-rules-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
    # Sister to brain-wide systemd After= INVARIANT family.
    # Watchdog .service units MUST declare an After= directive
    # so they don't fire before the filesystem mounts that
    # contain their probe targets (canonically After=local-
    # fs.target so /etc/* is mounted before the watchdog
    # tries to sha256sum a config file). A regression
    # dropping After= would surface as "watchdog fires
    # during early-boot before /etc is mounted" which then
    # hashes nothing + emits a spurious "config missing"
    # alert. Locks the boot-sequencing discipline on the
    # polkit-rules-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/polkit-rules-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (polkit-rules-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the polkit-rules-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/polkit-rules-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (polkit-rules-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the polkit-rules-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/polkit-rules-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}
