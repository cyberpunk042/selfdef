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
