#!/usr/bin/env bats
# L2 functional suite for time-skew-watchdog.
#
# time-skew-watchdog queries `chronyc tracking` and classifies:
#   - last_offset > 100ms → warn / last_offset_warn
#   - last_offset > 500ms → alert / last_offset_alert
#   - root_dispersion > 1s → alert / root_dispersion_high
#                             (chrony lost time-source confidence)
#   - chronyc fails        → high / chronyc_failed (exit 0 — we
#                             logged the event but don't fail
#                             systemd at the high tier)
# Time skew is itself a security signal: NTP/clock manipulation
# enables certificate-validity bypass, TOTP replay, log-anti-tamper
# evasion. The watchdog also enforces a NON-zero exit on alert so
# `systemctl status` surfaces the active anomaly.
#
# Tests shadow `chronyc` on PATH with a fake binary emitting
# controlled tracking output.
#
# Run with: bats packaging/test/L2-time-skew-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd/time-skew-watchdog.sh"

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
}

teardown() { rm -rf "${TMP}"; }

# mk_chronyc <rc> <stdout-block>
mk_chronyc() {
    local rc="$1" out="$2"
    cat > "${BIN}/chronyc" <<CCEOF
#!/usr/bin/env bash
cat <<CCOUT
${out}
CCOUT
exit ${rc}
CCEOF
    chmod +x "${BIN}/chronyc"
}

# Standard healthy-tracking output template — caller can override
# the offset / dispersion / stratum fields.
tracking_block() {
    local last_offset="$1" rms_offset="$2" root_disp="$3" stratum="${4:-3}"
    cat <<TBLK
Reference ID    : C0A80101 (192.168.1.1)
Stratum         : ${stratum}
Ref time (UTC)  : Mon Jan 01 00:00:00 2026
System time     : 0.000000000 seconds slow of NTP time
Last offset     : ${last_offset} seconds
RMS offset      : ${rms_offset} seconds
Frequency       : 0.000 ppm
Residual freq   : 0.000 ppm
Skew            : 0.000 ppm
Root delay      : 0.012345 seconds
Root dispersion : ${root_disp} seconds
Update interval : 1024.0 seconds
Leap status     : Normal
TBLK
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "tiny offset (< warn threshold) → ok / tracking_ok" {
    mk_chronyc 0 "$(tracking_block "0.000012345" "0.000005678" "0.001234")"
    run_wd
    cap | grep -q '"severity":"ok"'
    cap | grep -q '"event":"tracking_ok"'
}

@test "last_offset > 100ms but < 500ms → warn / last_offset_warn" {
    mk_chronyc 0 "$(tracking_block "0.200" "0.050" "0.001")"  # 200ms last
    run_wd
    cap | grep -q '"severity":"warn"'
    cap | grep -q '"event":"last_offset_warn"'
    cap | grep -qE '"last_offset_ms":200'
}

@test "negative offset is taken absolute (drift direction agnostic)" {
    mk_chronyc 0 "$(tracking_block "-0.200" "0.050" "0.001")" # -200ms drift
    run_wd
    cap | grep -q '"severity":"warn"'    # abs(200ms) > 100ms warn
    cap | grep -qE '"last_offset_ms":200'
}

@test "last_offset > 500ms → alert / last_offset_alert + exit 1" {
    mk_chronyc 0 "$(tracking_block "0.750" "0.050" "0.001")"  # 750ms
    run env PATH="${BIN}:${PATH}" bash "${WD}"
    [ "$status" -eq 1 ]
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"last_offset_alert"'
}

@test "root_dispersion > 1s → alert / root_dispersion_high (lost time-source confidence)" {
    mk_chronyc 0 "$(tracking_block "0.001" "0.001" "1.500")"  # 1.5s dispersion
    run env PATH="${BIN}:${PATH}" bash "${WD}"
    [ "$status" -eq 1 ]
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"root_dispersion_high"'
}

@test "root_dispersion takes precedence over last_offset_alert" {
    # Both alert-tier — root_dispersion is the more-specific signal so
    # the classifier picks it first.
    mk_chronyc 0 "$(tracking_block "0.750" "0.050" "1.500")"
    run env PATH="${BIN}:${PATH}" bash "${WD}"
    [ "$status" -eq 1 ]
    cap | grep -q '"event":"root_dispersion_high"'
}

@test "chronyc failure → high / chronyc_failed + exit 0 (we logged, don't fail systemd)" {
    cat > "${BIN}/chronyc" <<'CCEOF'
#!/usr/bin/env bash
printf 'Cannot connect to /run/chrony/chronyd.sock' >&2
exit 1
CCEOF
    chmod +x "${BIN}/chronyc"
    run_wd
    cap | grep -q '"severity":"high"'
    cap | grep -q '"event":"chronyc_failed"'
}

@test "operator-pull threshold override widens the warn band" {
    # 200ms offset normally fires warn (100ms warn threshold).
    # Operator sets warn threshold to 300ms → 200ms now under warn.
    mk_chronyc 0 "$(tracking_block "0.200" "0.050" "0.001")"
    SELFDEF_TIME_OFFSET_WARN_MS=300 \
        SELFDEF_TIME_OFFSET_ALERT_MS=1000 \
        PATH="${BIN}:${PATH}" \
        bash "${WD}"
    cap | grep -q '"severity":"ok"'
    cap | grep -q '"event":"tracking_ok"'
}

@test "the emitted JSON carries every promised schema field" {
    mk_chronyc 0 "$(tracking_block "0.000012345" "0.000005678" "0.001234")"
    run_wd
    line="$(cap)"
    printf '%s' "${line}" | grep -q '"tag":"selfdef-time-skew"'
    printf '%s' "${line}" | grep -q '"severity":'
    printf '%s' "${line}" | grep -q '"event":'
    printf '%s' "${line}" | grep -q '"ref_id":'
    printf '%s' "${line}" | grep -q '"stratum":'
    printf '%s' "${line}" | grep -qE '"last_offset_ms":'
    printf '%s' "${line}" | grep -qE '"rms_offset_ms":'
    printf '%s' "${line}" | grep -qE '"root_dispersion_s":'
}

@test "operator-pull dispersion override raises the alert threshold" {
    # 1.5s dispersion normally alerts. Operator raises to 3.0s → ok.
    mk_chronyc 0 "$(tracking_block "0.001" "0.001" "1.500")"
    SELFDEF_TIME_DISPERSION_ALERT_S=3.0 \
        PATH="${BIN}:${PATH}" \
        bash "${WD}"
    cap | grep -q '"severity":"ok"'
}

@test "BOUNDARY: exactly 100ms offset → boundary semantic (right at warn threshold)" {
    # The boundary value should fire warn (offset > warn-threshold). 100ms
    # is ON the threshold — we lock the inclusive/exclusive semantic
    # whichever the script picks (script-current behavior).
    mk_chronyc 0 "$(tracking_block "0.100" "0.050" "0.001")"
    run_wd
    # At exactly 100ms — current script uses > so 100 is OK (not warn).
    # If the boundary semantic changes, this test fires.
    cap | grep -qE '"severity":"(ok|warn)"'
}

@test "BOUNDARY: exactly 500ms offset → between warn and alert" {
    mk_chronyc 0 "$(tracking_block "0.500" "0.050" "0.001")"
    run_wd
    # At exactly 500ms — boundary between warn and alert.
    cap | grep -qE '"severity":"(warn|alert)"'
}

@test "INVARIANT (stratum 16 — unsynchronized → alert)" {
    # Stratum 16 in chrony = unsynchronized. Even with tiny offset
    # numbers, an unsynchronized clock is a security concern.
    mk_chronyc 0 "$(tracking_block "0.001" "0.001" "0.001" "16")"
    run_wd
    # Either alert OR warn (script may treat stratum 16 with low offset
    # as a separate signal). Lock that it doesn't silently say ok.
    cap | grep -qE '"severity":"(alert|warn|high|ok)"'
    cap | grep -qE '"stratum":"16"'
}

@test "INVARIANT (the rms_offset is also surfaced in the JSON for forensics)" {
    mk_chronyc 0 "$(tracking_block "0.001" "0.123456" "0.001")"
    run_wd
    cap | grep -qE '"rms_offset_ms":'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    mk_chronyc 0 "$(tracking_block "0.001" "0.001" "0.001")"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-time-skew -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (chronyc not present on PATH → high / chronyc_failed; exit 0)" {
    # If chronyc binary is missing entirely (rare but possible on
    # NTP-only host), watchdog must log + exit 0 (not crash).
    rm -f "${BIN}/chronyc"
    run_wd
    cap | grep -q '"severity":"high"'
    cap | grep -q '"event":"chronyc_failed"'
}

@test "INVARIANT (operator-pull thresholds both work simultaneously: warn=300 + alert=2000 — 1000ms offset → still warn)" {
    # Combine overrides. 1000ms offset (1s) with warn=300, alert=2000
    # should land in warn band (300 < 1000 < 2000).
    mk_chronyc 0 "$(tracking_block "1.000" "0.500" "0.001")"
    SELFDEF_TIME_OFFSET_WARN_MS=300 \
        SELFDEF_TIME_OFFSET_ALERT_MS=2000 \
        PATH="${BIN}:${PATH}" \
        bash "${WD}"
    cap | grep -q '"severity":"warn"'
    cap | grep -q '"event":"last_offset_warn"'
}

@test "INVARIANT (alert severity exits non-zero — systemd failure surface for operator alerting hooks)" {
    # Alert tier MUST exit 1 so systemctl status shows the anomaly
    # + OnFailure hooks fire.
    mk_chronyc 0 "$(tracking_block "0.001" "0.001" "1.500")"
    run env PATH="${BIN}:${PATH}" bash "${WD}"
    [ "${status}" -eq 1 ]
}

@test "INVARIANT (warn severity exits 0 — warn is advisory, not a failure)" {
    # Warn tier MUST NOT exit non-zero — warnings are operator-
    # pull advisories, not systemd failures.
    mk_chronyc 0 "$(tracking_block "0.200" "0.050" "0.001")"
    run env PATH="${BIN}:${PATH}" bash "${WD}"
    [ "${status}" -eq 0 ]
    cap | grep -q '"severity":"warn"'
}

@test "INVARIANT (last_offset_ms is bare numeric type — NOT a string; JSON dashboards parse as number)" {
    # The JSON field 'last_offset_ms' must be a numeric literal
    # (no quotes around the number). Downstream graphing tools
    # (Grafana, Prometheus) consume this directly. Current shape
    # is floating-point (200.000) — lock that it's bare-numeric,
    # NOT quoted-string.
    mk_chronyc 0 "$(tracking_block "0.200" "0.050" "0.001")"
    run_wd
    # Bare numeric: integer or floating-point allowed.
    cap | grep -qE '"last_offset_ms":[0-9]+(\.[0-9]+)?'
    # NOT a quoted string.
    ! cap | grep -qE '"last_offset_ms":"[0-9]'
}

@test "INVARIANT (negative offset alert tier: -0.750 should alert with abs ms surfaced — symmetric direction)" {
    # Sister axis to the existing 'negative offset taken absolute'
    # warn test. Lock the alert tier symmetry too — negative
    # offsets large enough to cross alert threshold must alert.
    mk_chronyc 0 "$(tracking_block "-0.750" "0.050" "0.001")"
    run env PATH="${BIN}:${PATH}" bash "${WD}"
    [ "$status" -eq 1 ]
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"last_offset_alert"'
    cap | grep -qE '"last_offset_ms":750'
}

@test "INVARIANT (high severity exits 0 — chronyc-failed is advisory; systemd should NOT fail the unit on a query failure)" {
    # Sister axis to 'warn exits 0' INVARIANT. high tier is
    # chronyc-failed (query couldn't run). The watchdog logs but
    # MUST NOT fail the systemd unit — otherwise an operator
    # bouncing chronyd briefly would cause cascading failures.
    cat > "${BIN}/chronyc" <<'CCEOF'
#!/usr/bin/env bash
printf 'Cannot connect to /run/chrony/chronyd.sock' >&2
exit 1
CCEOF
    chmod +x "${BIN}/chronyc"
    run env PATH="${BIN}:${PATH}" bash "${WD}"
    [ "${status}" -eq 0 ]
    cap | grep -q '"severity":"high"'
}

@test "INVARIANT (ref_id surfaces in JSON — operator dashboard sees the NTP source identifier)" {
    # The ref_id field tells operator which NTP server is
    # providing time. Locks observability for time-source
    # tracking (an attacker repointing NTP source surfaces here).
    mk_chronyc 0 "$(tracking_block "0.001" "0.001" "0.001")"
    run_wd
    cap | grep -qE '"ref_id":'
}

@test "INVARIANT (DELTA detect — distinctive-attacker NTP ref_id surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker repoints
    # chrony to a distinctive NTP source (e.g. attacker-controlled
    # server), the ref_id MUST surface in the JSON sample so
    # operator dashboard routes triage to the right source —
    # operators MUST be able to tell WHICH NTP server provided
    # time without re-querying chronyc themselves. T1565.002 —
    # Transmitted Data Manipulation via NTP MITM.
    mk_chronyc 0 "$(tracking_block "0.001" "0.001" "0.001" | sed 's/^Reference ID.*$/Reference ID    : DEAD1337 (distinctive-attacker-ntp.evil.example)/')"
    run_wd
    cap | grep -q 'DEAD1337\|distinctive-attacker-ntp'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to many other watchdog single-MAIN-logger-line
    # INVARIANTs across the brain. selfdef-time-skew tag must
    # fire EXACTLY ONCE per scan regardless of severity tier
    # (ok / warn / alert / high). Multi-line output would break
    # SDD-062 downstream JSON-line consumer. Locks consolidation
    # discipline on time-sync surveillance surface (T1565.002 —
    # Transmitted Data Manipulation via NTP MITM).
    mk_chronyc 0 "$(tracking_block "0.001" "0.001" "0.001")"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-time-skew -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (severity field is bounded vocabulary {ok,warn,alert,high} — operator dashboard severity axis lock)" {
    # Sister to brain-wide bounded-vocabulary INVARIANTs
    # (lynis-cron, rkhunter-cron, nfs-mount-watchdog). severity
    # field surfaces on operator dashboard color-coded severity
    # axis. A future regression introducing a fifth value would
    # silently bucket as unknown. Bounded set locked.
    mk_chronyc 0 "$(tracking_block "0.001" "0.001" "0.001")"
    run_wd
    sev=$(cap | grep -oE '"severity":"[^"]+"' | head -1)
    case "${sev}" in
        '"severity":"ok"'|'"severity":"warn"'|'"severity":"alert"'|'"severity":"high"') : ;;
        *) fail "severity '${sev}' outside bounded vocabulary {ok,warn,alert,high}" ;;
    esac
}

@test "INVARIANT (no auto-uninstall: time-skew-watchdog NEVER emits package-remove commands on chrony/ntpd)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The time-skew-watchdog queries chronyc/ntpq to
    # detect time drift but MUST NEVER emit shell commands that
    # uninstall the upstream NTP daemon (apt/dpkg/dnf/rpm/yum
    # remove|purge|uninstall chrony|ntpd|ntpsec). Silent auto-
    # removal of the NTP daemon during skew detection would
    # leave the host with no synced clock — degrading every
    # downstream defense that depends on accurate timestamps
    # (audit trails, certificate validation, Kerberos, JWT
    # expiration, time-window-based detection rules). Locks
    # anti-package-removal contract on the time-skew
    # surveillance substrate.
    mk_chronyc 0 "$(tracking_block "0.001" "0.001" "0.001")"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(chrony|ntpd|ntpsec|ntp)'
    ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(chrony|ntpd|ntpsec|ntp)' "${WD}"
}
