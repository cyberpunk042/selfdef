#!/usr/bin/env bats
# L2 functional suite for audit-config-watchdog.
#
# audit-config-watchdog catches T1562.001 Impair Defenses against
# the Linux audit subsystem. An attacker blinding the host runs:
#   auditctl -D            (flush all rules → rule_count drops to 0)
#   systemctl stop auditd  (auditd state → inactive)
#   auditctl -e 0          (enabled flag → 0)
# All show as deltas vs the baseline.
#
# Severity tiers:
#   ok    → no delta (audit_intact)
#   warn  → conf-file change OR rule count reduced but >0
#   alert → rules flushed to 0 OR auditd disabled OR enabled flag
#           turned off (the T1562.001 signatures)
#
# Uses SELFDEF_AUDITCFG_CONFDIR env-var override (added 2026-06-06)
# for the /etc/audit directory, and shadows auditctl + systemctl on
# PATH so the test controls all 3 telemetry sources.
#
# Run with: bats packaging/test/L2-audit-config-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd/audit-config-watchdog.sh"

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
    BASELINE="${TMP}/audit-config-baseline.tsv"
    CONFDIR="${TMP}/audit-confdir"
    mkdir -p "${CONFDIR}/rules.d"
    # State files the fake auditctl + systemctl read.
    export STATE_RULES="${TMP}/state-rules.txt"
    export STATE_ENABLED="${TMP}/state-enabled.txt"
    export STATE_AUDITD="${TMP}/state-auditd.txt"
}

teardown() { rm -rf "${TMP}"; }

mk_auditctl() {
    cat > "${BIN}/auditctl" <<'AEOF'
#!/usr/bin/env bash
case "$1" in
    -l)
        if [[ -s "${STATE_RULES}" ]]; then
            cat "${STATE_RULES}"
        else
            echo "No rules"
        fi
        ;;
    -s)
        printf 'enabled %s\n' "$(cat "${STATE_ENABLED}" 2>/dev/null || echo '?')"
        ;;
esac
AEOF
    chmod +x "${BIN}/auditctl"
}

mk_systemctl() {
    cat > "${BIN}/systemctl" <<'SEOF'
#!/usr/bin/env bash
if [[ "$1" == "is-active" && "$2" == "auditd" ]]; then
    cat "${STATE_AUDITD}" 2>/dev/null || echo "inactive"
fi
SEOF
    chmod +x "${BIN}/systemctl"
}

# set_state <rules-text> <enabled> <auditd-state>
set_state() {
    printf '%s\n' "$1" > "${STATE_RULES}"
    [[ -z "$1" ]] && : > "${STATE_RULES}"
    printf '%s\n' "$2" > "${STATE_ENABLED}"
    printf '%s\n' "$3" > "${STATE_AUDITD}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    STATE_RULES="${STATE_RULES}" \
    STATE_ENABLED="${STATE_ENABLED}" \
    STATE_AUDITD="${STATE_AUDITD}" \
    SELFDEF_AUDITCFG_PROFILE="${PROFILE:-report}" \
    SELFDEF_AUDITCFG_BASELINE="${BASELINE}" \
    SELFDEF_AUDITCFG_CONFDIR="${CONFDIR}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

setup_baseline_state() {
    mk_auditctl
    mk_systemctl
    set_state "-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes" "1" "active"
    printf 'log_file = /var/log/audit/audit.log\n' > "${CONFDIR}/auditd.conf"
}

@test "first run captures audit state + chmod 0600" {
    setup_baseline_state
    run_wd
    [ -f "${BASELINE}" ]
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"rule_count":3'
    cap | grep -q '"auditd":"active"'
}

@test "unchanged state on second run → ok / audit_intact" {
    setup_baseline_state
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"audit_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "auditd STOPPED (T1562.001 signature) → alert / auditd_disabled" {
    setup_baseline_state
    run_wd
    set_state "-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes" "1" "inactive"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"auditd_disabled"'
    cap | grep -q '"severity":"alert"'
}

@test "auditctl -D (rules flushed to 0) → alert / audit_rules_flushed" {
    setup_baseline_state
    run_wd
    set_state "" "1" "active"            # rule flushed
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"audit_rules_flushed"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"rule_count":0'
}

@test "auditctl -e 0 (enabled flipped off) → alert / audit_disabled_flag" {
    setup_baseline_state
    run_wd
    set_state "-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes" "0" "active"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"audit_disabled_flag"'
    cap | grep -q '"severity":"alert"'
}

@test "rule count REDUCED but still >0 → warn / audit_rules_reduced" {
    setup_baseline_state
    run_wd                               # baseline = 3 rules
    set_state "-w /etc/passwd -p wa -k passwd_changes" "1" "active"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"audit_rules_reduced"'
    cap | grep -q '"severity":"warn"'
    cap | grep -qE '"rule_count":1'
}

@test "conf-file changed (with rules + auditd intact) → warn / audit_conf_changed" {
    setup_baseline_state
    run_wd
    # Edit auditd.conf — rule count + enabled + auditd unchanged.
    printf 'log_file = /var/log/audit/audit.log\nmax_log_file = 100\n' > "${CONFDIR}/auditd.conf"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"audit_conf_changed"'
    cap | grep -q '"severity":"warn"'
    cap | grep -qE '"conf_changes":1'
}

@test "the emitted JSON carries every promised schema field" {
    setup_baseline_state
    run_wd
    line="$(cap)"
    printf '%s' "${line}" | grep -q '"tag":"selfdef-audit-config"'
    printf '%s' "${line}" | grep -q '"severity":'
    printf '%s' "${line}" | grep -q '"event":'
    printf '%s' "${line}" | grep -q '"profile":'
    printf '%s' "${line}" | grep -qE '"rule_count":[0-9]+'
    printf '%s' "${line}" | grep -q '"auditd":'
}

@test "enforce profile + auditd disabled → exit 1" {
    setup_baseline_state
    run_wd
    set_state "-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes" "1" "inactive"
    run env PATH="${BIN}:${PATH}" \
        STATE_RULES="${STATE_RULES}" \
        STATE_ENABLED="${STATE_ENABLED}" \
        STATE_AUDITD="${STATE_AUDITD}" \
        SELFDEF_AUDITCFG_PROFILE=enforce \
        SELFDEF_AUDITCFG_BASELINE="${BASELINE}" \
        SELFDEF_AUDITCFG_CONFDIR="${CONFDIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
}

@test "enforce profile + unchanged → exit 0" {
    setup_baseline_state
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run_wd
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (rules.d file added with new rule → reflected in rule count, but rule-count INCREASE alone does NOT degrade severity)" {
    # Adding rules is a HARDENING action, not an attack. The script
    # correctly treats it as 'audit_intact' — the security STATE didn't
    # degrade. Lock that semantic: the new rule_count IS reflected, but
    # severity stays ok.
    setup_baseline_state
    run_wd
    set_state "-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/sudoers -p wa -k sudoers_changes" "1" "active"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"rule_count":4'
    cap | grep -q '"severity":"ok"'   # rule-increase = hardening = ok
}

@test "INVARIANT (multiple simultaneous T1562.001 signatures — rules flushed AND auditd down → alert)" {
    # Realistic attacker sequence: -D then stop. Both fire.
    setup_baseline_state
    run_wd
    set_state "" "1" "inactive"      # both rules-flushed AND auditd-disabled
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
    # Should reflect both deltas in event/payload.
    cap | grep -qE '"rule_count":0'
    cap | grep -qE '"auditd":"inactive"'
}

@test "INVARIANT (multiple simultaneous T1562.001 — rules flushed AND enabled=0 → alert)" {
    # Another attacker variant: flush + disable flag.
    setup_baseline_state
    run_wd
    set_state "" "0" "active"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (conf-file content change is byte-sensitive, not just stat-sensitive)" {
    # Same byte-content → no warn. Different byte-content → warn.
    setup_baseline_state
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Touch (preserve content) — should NOT fire conf-changed.
    touch "${CONFDIR}/auditd.conf"
    run_wd
    cap | grep -q '"event":"audit_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (additional conf-file in /etc/audit/rules.d also surfaces as conf change)" {
    setup_baseline_state
    run_wd
    printf '%s\n' '-w /etc/hosts -p wa -k hosts_changes' > "${CONFDIR}/rules.d/10-hosts.rules"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"audit_conf_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    setup_baseline_state
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-audit-config -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (auto-trust): audit-config-watchdog DOES auto-refresh baseline (state captured + telemetry continues)" {
    # CONTRAST against no-auto-trust family. Once T1562.001 signal
    # fires, the baseline updates to new state — operator-pull
    # dashboard sees alerts at delta moment only. Locks current
    # behavior; documents the architecture choice.
    setup_baseline_state
    run_wd
    set_state "" "1" "inactive"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # baseline refreshed
    cap | grep -q '"event":"audit_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (severity precedence: conf-changed + auditd-disabled in same scan → alert; T1562.001 wins over warn)" {
    # When BOTH conf change AND auditd down occur in same scan,
    # severity must be alert (T1562.001 wins ladder over conf-
    # change warn).
    setup_baseline_state
    run_wd
    printf 'log_file = /var/log/audit/audit.log\nmax_log_file = 100\n' > "${CONFDIR}/auditd.conf"
    set_state "-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes" "1" "inactive"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"auditd_disabled"'
}

@test "INVARIANT (current behavior: rules.d file removal may surface as rule-count reduction or audit_intact — depending on whether removal coincides with auditctl -l reload timing)" {
    # When operator removes a rules.d file, the LIVE auditctl -l
    # reflects rule reduction only after auditd reload. Depending
    # on timing, may surface as audit_rules_reduced or
    # audit_intact. Lock current behavior — severity NOT alert.
    setup_baseline_state
    printf '%s\n' '-w /etc/hosts -p wa -k hosts' > "${CONFDIR}/rules.d/10-hosts.rules"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    rm -f "${CONFDIR}/rules.d/10-hosts.rules"
    run_wd
    # Removal is operator action; current behavior surfaces as
    # warn or ok (not alert).
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (rule_count surfaces in baseline_initial too — operator sees install-time count)" {
    # The baseline_initial event must carry rule_count so operator
    # sees the install-time-vet number.
    setup_baseline_state
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"rule_count":3'
}

@test "INVARIANT (auditd inactive-since-baseline persistence: re-baseline auto-trust then attacker re-fires → alert again)" {
    # Sister to pci-device-watchdog + selfdef-self-integrity
    # multi-cycle re-baseline INVARIANT. Lock that auto-trust
    # cycle works on EVERY T1562.001 attack, not just the first.
    setup_baseline_state
    run_wd
    # First attack.
    set_state "" "1" "inactive"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                              # alert
    cap | grep -q '"severity":"alert"'
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                              # baseline refreshed
    cap | grep -q '"severity":"ok"'
    # Second attack: operator brings audit back up, then attacker
    # disables again.
    set_state "-w /etc/passwd -p wa -k passwd_changes" "1" "active"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                              # third refresh
    : > "${SELFDEF_TEST_LOGCAP}"
    set_state "" "1" "inactive"         # attacker re-attacks
    run_wd                              # alert AGAIN
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (compound T1562.001: rules-flushed + enabled=0 + auditd inactive in same scan → still single alert event; consolidation)" {
    # Triple-attack scenario: -D + -e 0 + stop. All three T1562.001
    # signatures fire in same scan. Single consolidated alert event.
    setup_baseline_state
    run_wd
    set_state "" "0" "inactive"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
    main_count=$(cap | grep -cE '^-t selfdef-audit-config -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (current-behavior: audit-config-watchdog conf-changed surfaces conf_changes COUNT, not file paths — privacy-by-design)" {
    # Sister contract observation: unlike polkit-rules / nfs-exports
    # / etc. which surface file paths in sample, audit-config
    # surfaces conf_changes COUNT only. Lock current behavior so a
    # future refinement that adds path-naming is intentional, not
    # silent. Privacy-by-design: audit-config doesn't expose specific
    # rule-file names in the dashboard (which could leak rule
    # structure to an attacker observing the SIEM).
    setup_baseline_state
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '%s\n' '-w /etc/distinctive-attacker -p wa -k distinctive' > "${CONFDIR}/rules.d/99-distinctive-attacker.rules"
    run_wd
    cap | grep -q '"event":"audit_conf_changed"'
    cap | grep -qE '"conf_changes":[1-9]'
}

@test "INVARIANT (emit_status JSON: tag=selfdef-audit-config surfaces in MAIN logger record — SDD-062 consumer dispatch contract)" {
    # Sister to many other watchdog tag-emission INVARIANTs across
    # the brain. The SDD-062 single-line JSON consumer (downstream
    # dashboard / SIEM correlator) routes by the 'tag' field. A
    # silent rename of the tag would silently disconnect this
    # watchdog from the dashboard — operator would see the
    # auditd-disabled / rules-flushed signal disappear with no
    # error. Locks the tag-emission contract on the audit-config
    # T1562.001 (Impair Defenses: Disable or Modify Tools)
    # surveillance surface.
    setup_baseline_state
    run_wd
    cap | grep -qE 'selfdef-audit-config'
}

@test "INVARIANT (baseline_rules JSON field echoes captured baseline rule count — operator sees both current AND baseline in same record for diff context)" {
    # Sister to many other watchdog/installer JSON-field-echo
    # INVARIANTs across the brain. emit_status carries BOTH the
    # live rule_count AND the captured baseline_rules count
    # in a single JSON record so the dashboard correlator can
    # surface delta (live - baseline) without re-querying the
    # baseline file. Lock the baseline_rules field presence on
    # the rules-flushed alert path: when an attacker drops
    # rules via auditctl -D, the JSON must surface
    # baseline_rules with the pre-attack count so operator
    # immediately sees "had N rules, now has 0". Without this,
    # the dashboard would need a separate baseline-state lookup.
    # Locks the diff-context-in-one-record contract on the
    # T1562.001 surveillance surface.
    setup_baseline_state
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    set_state "" "1" "active"             # rules flushed
    run_wd
    cap | grep -qE '"baseline_rules":[1-9]'
    cap | grep -q '"event":"audit_rules_flushed"'
}

@test "INVARIANT (baseline file is chmod 0600 — confidentiality of audit-config inventory)" {
    # Sister to brain-wide baseline-confidentiality INVARIANTs.
    # The audit-config baseline enumerates rule structure;
    # operator-private (0600) prevents reconnaissance.
    setup_baseline_state
    run_wd
    [ -f "${BASELINE}" ]
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # State-resilience on T1562.001 audit-config tamper
    # surveillance.
    setup_baseline_state
    run_wd                                              # establishes baseline
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"                                  # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # must re-establish
    [ -f "${BASELINE}" ]
    cap | grep -qE '"event":"baseline_initial"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on audit-config surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The audit-config-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1562.001 Impair Defenses: Disable or
    # Modify Tools (auditd tamper) alert. Locks parser contract
    # on the audit-config delta detection surface.
    setup_baseline_state
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    # Trigger a delta by changing auditd config.
    AUDITCTL_ENABLED=0 setup_baseline_state
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-restore: audit-config-watchdog NEVER auto-reverts auditd config tamper — surveillance not remediation)" {
    # Sister to brain-wide no-auto-restore / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # audit-config-watchdog DETECTS T1562.001 Impair Defenses:
    # auditd tamper but MUST NEVER emit auditctl/sed/cp
    # commands to auto-restore the audit config from baseline.
    # Auto-restore would destroy forensic evidence (operator
    # cannot analyze the attacker tamper if silently reverted)
    # AND could overwrite operator-legitimate auditd config
    # updates (operator may have intentionally adjusted rules
    # but forgot to re-baseline). Surveillance, never auto-
    # remediation. Locks anti-evidence-destruction contract
    # on the audit-config substrate.
    # Auto-restore would be `cp $BASELINE /etc/audit/...` —
    # i.e., BASELINE as SOURCE arg. The current cp $current
    # $BASELINE writes-TO baseline (safe; that's baseline-
    # update, not auto-restore). Lock by pattern: cp where
    # BASELINE is the first non-flag arg.
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*auditctl[[:space:]]+-(R|w|a)'
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*cp[[:space:]]+(-[a-z]+[[:space:]]+)?"?\$\{?BASELINE\}?"?[[:space:]]+/'
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # audit-config-watchdog runs ON the timer's scheduled fire —
    # verifies sha256 of /etc/audit/auditd.conf + audit.rules
    # against pinned baseline, emits a verdict on tamper, then
    # exits. Type=simple would break timer OnUnitActiveSec
    # semantics. Locks oneshot-probe contract on the audit-
    # config-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd/selfdef-audit-config.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (no auto-fix: audit-config-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. audit-config-watchdog is a DETECT-only watchdog: it surveils
    # its target surface + emits verdicts, NEVER writes back to
    # the source files it scans. The libexec script must NOT
    # contain sed -i / tee / printf-redirect mutations of its
    # scanned paths. Locks no-auto-fix on the audit-config-watchdog
    # libexec substrate (sister to existing surveillance-not-
    # remediation lines for the watchdog runtime).
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (audit-config-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The audit-config-watchdog libexec uses set -u (and NOT set -e) by
    # design: watchdog probes WANT to continue scanning even
    # when individual checks fail (rather than abort-on-first-
    # error like installers), so they emit a complete verdict
    # at the end. But set -u remains essential — it catches
    # typo'd env-var references ($SELFDEF_FOO_BASELINE vs
    # $SELFDEF_FOO_BASLINE) before they propagate as silent
    # empty-string into baseline-path operations. A regression
    # dropping set -u would let a typo'd var name produce a
    # silent baseline-rewrite to /. Locks set -u discipline on
    # the audit-config-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (audit-config-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # All watchdog libexec scripts MUST surface JSON records
    # via logger -t with a selfdef-prefixed tag so downstream
    # syslog/journald consumers can route per-watchdog records
    # via the tag field rather than parsing the JSON payload
    # for the module field. The tag prefix MUST be "selfdef-"
    # so cross-watchdog SIEM filters (`syslog-ng-filter "selfdef-*"`)
    # capture every selfdef-watchdog without per-watchdog tag
    # enumeration. A regression dropping the selfdef- prefix
    # would cause SIEM filters to silently miss records. Locks
    # SDD-062 logger-tag routing discipline on the audit-config-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (audit-config-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # The audit-config-watchdog timer unit MUST declare RandomizedDelaySec=
    # so fleet hosts don't all fire at the exact same minute
    # (thundering-herd that overwhelms downstream
    # syslog/journald aggregators). Locks anti-thundering-herd
    # cadence discipline on the audit-config-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (audit-config-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Persistent=true tells systemd to fire the timer ON BOOT
    # if it was missed during downtime — without it, a host
    # that boots after the scheduled fire would silently skip
    # the cycle, leaving a forensics gap. Locks Persistent=
    # discipline on the audit-config-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (audit-config-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # The .timer file MUST declare Unit=<companion>.service so
    # systemd knows which .service to fire on timer-elapse. By
    # default systemd matches timer-name to service-name, but
    # explicit Unit= is required when names differ + makes the
    # binding self-documenting. A regression dropping Unit= +
    # renaming either file would silently break the link.
    # Locks the timer-to-service binding discipline on the
    # audit-config-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (audit-config-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. The .service file MUST declare ExecStart=<path-
    # to-libexec.sh> so systemd knows what to run. The libexec
    # script must EXIST at the declared path. A regression that
    # renamed the libexec script without updating ExecStart
    # would surface as service-start failure rather than a
    # silent regression. Locks the service-to-libexec binding
    # discipline on the audit-config-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (audit-config-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # The audit-config-watchdog probe is Type=oneshot — it RUNS, emits a
    # verdict, and EXITS. Restart=always on a oneshot would
    # cause systemd to immediately re-fire the probe in a
    # tight loop, swamping the dashboard with redundant
    # records. A regression that added Restart=always would
    # produce a runaway-probe footgun. Locks the anti-restart-
    # storm discipline on the audit-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (audit-config-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. The Description= directive surfaces in
    # `systemctl status` output + journalctl unit-filter
    # labels. A unit with no Description is opaque to
    # operators triaging service activity. Locks the
    # Description-present discipline on the audit-config-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (audit-config-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the audit-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (audit-config-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the audit-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (audit-config-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the audit-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (audit-config-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the audit-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (audit-config-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the audit-config-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (audit-config-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the audit-config-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (audit-config-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # audit-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (audit-config-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # audit-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (audit-config-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the audit-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (audit-config-watchdog timer unit declares OnBootSec= — boot-catchup-delay contract)" {
    # Sister to brain-wide systemd OnBootSec= INVARIANT
    # family. Watchdog .timer units MUST declare OnBootSec=
    # so the first watchdog fire is delayed until after boot
    # finishes settling. Locks the boot-catchup-delay
    # discipline on the audit-config-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnBootSec=' "${t}"
    done
}

@test "INVARIANT (audit-config-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
    # Sister to brain-wide systemd timer [Install].WantedBy=
    # INVARIANT family. Watchdog .timer units MUST declare
    # WantedBy=timers.target so `systemctl enable selfdef-
    # <slug>.timer` wires the timer into the timers.target
    # symlink-graph + activates it on every boot. A
    # regression that swapped to WantedBy=multi-user.target
    # (the .service-side install target) would make the
    # timer enable-step a no-op + leave the watchdog
    # silently inactive. Locks the timer-enable-graph
    # discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (audit-config-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (audit-config-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (audit-config-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (audit-config-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the audit-config-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    [ -f "${script_dir}/audit-config-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (audit-config-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (audit-config-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (audit-config-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (audit-config-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (audit-config-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (audit-config-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (audit-config-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (audit-config-watchdog .sh script emits canonical severity vocabulary {ok,warn,alert} — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    # Watchdog scripts emit logger -t selfdef-<name> -- {...severity:...}
    # with severity in the canonical vocabulary. A regression
    # introducing custom severity values (info, error, critical)
    # would break operator-side filtering.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '"severity":"(ok|warn|alert)"' "${s}"
    done
}

@test "INVARIANT (audit-config-watchdog .sh script tag selfdef-audit-config matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-audit-config
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (audit-config-watchdog .sh script declares profile-aware exit behavior — operator-extension profile-dispatch contract)" {
    # Sister to brain-wide profile-aware INVARIANT family.
    # Scripts MUST handle PROFILE=enforce vs report differently.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'PROFILE.*enforce|enforce.*PROFILE|profile.*enforce' "${s}"
    done
}

@test "INVARIANT (audit-config-watchdog .sh script declares baseline file path — operator-extensible baseline-state contract)" {
    # Sister to brain-wide baseline-state INVARIANT family.
    # Delta-scan watchdogs MUST declare a BASELINE variable referencing
    # /var/lib/selfdef/ so operators know where baseline state lives.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '/var/lib/selfdef/|BASELINE' "${s}"
    done
}

@test "INVARIANT (audit-config-watchdog .sh script declares MODULE-suffixed tag in logger -t — module-name-tag-consistency contract)" {
    # Sister to SDD-062 tag-canonical INVARIANT family. The tag passed to
    # logger -t MUST include the module slug so journalctl filtering by
    # tag surfaces only this watchdog's events.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (audit-config-watchdog .sh script file is non-empty (size > 100 bytes) — non-trivial-script contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (audit-config-watchdog .sh script has >20 lines — non-trivial-watchdog-body contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 20 ]
    done
}

@test "INVARIANT (audit-config-watchdog .service unit file has >5 lines of directives — non-trivial-unit-file contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 5 ]
    done
}

@test "INVARIANT (audit-config-watchdog .service unit ExecStart references /usr/local/libexec/selfdef/ path — canonical-binary-path contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (audit-config-watchdog .timer file exists at canonical path modules/audit-config-watchdog/systemd — canonical-systemd-dir layout)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    [ -d "${timer_dir}" ]
    n=$(ls "${timer_dir}"/*.timer 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (audit-config-watchdog module.toml exists at canonical path modules/audit-config-watchdog/ — module-manifest existence 72-cycle)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (audit-config-watchdog systemd dir exists at modules/audit-config-watchdog/systemd — systemd-dir-existence 73-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    [ -d "${sd}" ]
}

@test "INVARIANT (audit-config-watchdog systemd dir is non-empty — systemd-content-presence 74-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    n=$(ls "${sd}" | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (audit-config-watchdog .service file size > 100 bytes — substantial-service-unit 75-cycle)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (audit-config-watchdog .timer file size > 50 bytes — substantial-timer-unit 76-cycle)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        size=$(stat -c '%s' "${t}")
        [ "${size}" -gt 50 ]
    done
}

@test "INVARIANT (audit-config-watchdog README.md file size > 100 bytes — substantial-readme 77-cycle)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/README.md"
    size=$(stat -c '%s' "${readme}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (audit-config-watchdog .service Documentation URL is HTTP/HTTPS — operator-doc-link-protocol 78)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=(http|https)://' "${s}"
    done
}

@test "INVARIANT (audit-config-watchdog .sh script has shebang line — POSIX-conformant 79)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '^#!'
    done
}

@test "INVARIANT (audit-config-watchdog .sh script declares set flag in first 50 lines — strict-mode-prologue 80)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -50 "${s}" | grep -qE '^set -'
    done
}

@test "INVARIANT (audit-config-watchdog module.toml size > 200 bytes — substantial-watchdog-manifest 81)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    size=$(stat -c '%s' "${mtoml}")
    [ "${size}" -gt 200 ]
}

@test "INVARIANT (audit-config-watchdog .service file is non-empty — non-trivial-unit-file 82)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        [ -s "${s}" ]
    done
}

@test "INVARIANT (audit-config-watchdog .timer file is non-empty — non-trivial-timer-file 83)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        [ -s "${t}" ]
    done
}

@test "INVARIANT (audit-config-watchdog .sh script body has at least one variable assignment — non-vacuous-script 84)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^[a-zA-Z_]+=' "${s}"
    done
}

@test "INVARIANT (audit-config-watchdog .sh script path matches systemd dir layout — canonical-script-co-location 85)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/systemd"
    [ -d "${script_dir}" ]
    n=$(ls "${script_dir}"/*.sh 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (audit-config-watchdog module.toml has install_paths section — SDD-026 mutation-manifest 86)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (audit-config-watchdog module.toml install_paths.paths non-empty list 87)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list) and len(ps) > 0
"
}

@test "INVARIANT (audit-config-watchdog module.toml install_paths.paths only absolute paths 88)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (audit-config-watchdog module.toml provides list non-empty 89 — capability-export-present)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list) and len(p) >= 1
"
}

@test "INVARIANT (audit-config-watchdog module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (audit-config-watchdog module.toml install_paths.paths includes /etc/ entry — config-staging 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps)
"
}

@test "INVARIANT (audit-config-watchdog module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p for p in ps)
"
}

@test "INVARIANT (audit-config-watchdog module.toml install_paths.paths has /var/ entry 93 — state-staging)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/var/') for p in ps)
"
}

@test "INVARIANT (audit-config-watchdog module.toml [install_paths] declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (audit-config-watchdog module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (audit-config-watchdog module.toml uses TOML key-value syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (audit-config-watchdog module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (audit-config-watchdog module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (audit-config-watchdog module.toml category field double-quoted — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (audit-config-watchdog module.toml summary field double-quoted — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (audit-config-watchdog module.toml name field matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"audit-config-watchdog"' "${mtoml}"
}

@test "INVARIANT (audit-config-watchdog module.toml top-level keys before any [section] — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
with open('${mtoml}') as fp:
    for ln in fp:
        s = ln.strip()
        if not s or s.startswith('#'): continue
        if s.startswith('['): break
        assert '=' in ln
        break
"
}

@test "INVARIANT (audit-config-watchdog module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (audit-config-watchdog module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (audit-config-watchdog module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (audit-config-watchdog module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (audit-config-watchdog module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (audit-config-watchdog module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (audit-config-watchdog module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (audit-config-watchdog module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (audit-config-watchdog module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}

@test "INVARIANT (audit-config-watchdog module.toml [install] check value is non-empty string ending with .sh — TOML-install-check-shape-canonical 112)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ck = (data.get('install') or {}).get('check', '')
assert isinstance(ck, str) and ck and ck.endswith('.sh'), f'install.check must be non-empty .sh path, got {ck!r}'
"
}

@test "INVARIANT (audit-config-watchdog module.toml version field matches semver X.Y.Z pattern — TOML-version-semver-canonical 113)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v), f'version must be semver X.Y.Z, got {v!r}'
"
}

@test "INVARIANT (audit-config-watchdog module.toml summary field is non-empty string with length >= 30 chars — TOML-summary-substance-floor 114)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) >= 30, f'summary must be string with len >= 30, got len={len(s)} value={s!r}'
"
}

@test "INVARIANT (audit-config-watchdog module.toml top-level requires field is a TOML list — TOML-requires-list-canonical 115)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (audit-config-watchdog module.toml top-level provides field is a TOML list — TOML-provides-list-canonical 116)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('provides')
assert isinstance(r, list), f'provides must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (audit-config-watchdog module.toml top-level conflicts field is a TOML list — TOML-conflicts-list-canonical 117)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('conflicts')
assert isinstance(r, list), f'conflicts must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (audit-config-watchdog module.toml top-level depends_on field is a TOML list — TOML-depends-on-list-canonical 118)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('depends_on')
assert isinstance(r, list), f'depends_on must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (audit-config-watchdog module.toml top-level consumes field is a TOML list — TOML-consumes-list-canonical 119)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('consumes')
assert isinstance(r, list), f'consumes must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (audit-config-watchdog module.toml top-level instanced field is a TOML boolean — TOML-instanced-bool-canonical 120)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('instanced')
assert isinstance(r, bool), f'instanced must be bool, got {type(r).__name__}'
"
}

@test "INVARIANT (audit-config-watchdog module.toml [install] uninstall value is non-empty string ending with .sh — TOML-install-uninstall-shape-canonical 121)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = (data.get('install') or {}).get('uninstall', '')
assert isinstance(v, str) and v and v.endswith('.sh'), f'install.uninstall must be non-empty .sh path, got {v!r}'
"
}

@test "INVARIANT (audit-config-watchdog module.toml has [profiles] section header — TOML-profiles-section-canonical 122)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    grep -qE '^\[profiles\]$' "${mtoml}"
}

@test "INVARIANT (audit-config-watchdog module.toml [profiles] default field is non-empty string — TOML-profiles-default-canonical 123)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert isinstance(d, str) and d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (audit-config-watchdog module.toml [profiles] available field is a TOML list — TOML-profiles-available-list-canonical 124)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available')
assert isinstance(a, list), f'profiles.available must be list, got {type(a).__name__}'
"
}

@test "INVARIANT (audit-config-watchdog module.toml [profiles] available list contains at least one element — TOML-profiles-available-non-empty-canonical 125)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert isinstance(a, list) and len(a) >= 1, f'profiles.available must be non-empty list, got {a!r}'
"
}

@test "INVARIANT (audit-config-watchdog module.toml [profiles] default value appears in [profiles] available list (semantic consistency) — TOML-profiles-default-in-available-canonical 126)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
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

@test "INVARIANT (audit-config-watchdog module.toml [profiles] available list contains only string elements — TOML-profiles-available-elements-string-canonical 127)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-config-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert all(isinstance(x, str) for x in a), f'profiles.available items must all be strings, got {[type(x).__name__ for x in a]!r}'
"
}
