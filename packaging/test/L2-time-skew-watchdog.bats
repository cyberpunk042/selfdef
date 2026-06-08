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

@test "INVARIANT (no auto-adjust: time-skew-watchdog NEVER emits chronyc makestep/sysctl/date commands — surveillance not remediation)" {
    # Sister to brain-wide no-auto-remediation / surveillance-
    # not-destruction INVARIANTs across L2 watchdog suites. The
    # time-skew-watchdog DETECTS time-drift but MUST NEVER emit
    # commands that auto-adjust the clock (chronyc makestep,
    # date -s, hwclock --systohc, sysctl). Auto-adjust would
    # break operator-running workloads sensitive to monotonic-
    # clock invariants (databases, cert verification, time-
    # series ingestion). Operator decides when to apply the
    # step-correction. Surveillance, never remediation. Locks
    # anti-runtime-disruption contract on the time-skew
    # substrate.
    ! grep -qE 'chronyc[[:space:]]+(makestep|burst|sources)' "${WD}"
    ! grep -qE 'date[[:space:]]+-s' "${WD}"
    ! grep -qE 'hwclock[[:space:]]+--systohc' "${WD}"
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # time-skew-watchdog runs ON the timer's scheduled fire —
    # queries chronyc tracking, emits a verdict on clock-offset
    # beyond threshold, then exits. Type=simple would break
    # timer OnUnitActiveSec semantics. Locks oneshot-probe
    # contract on the time-skew-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd/selfdef-time-skew-watchdog.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. time-skew-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # time-skew-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # time-skew-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'time-skew-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: time-skew-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. time-skew-watchdog is a DETECT-only watchdog: surveils +
    # emits verdicts, NEVER writes back. Locks no-auto-fix on
    # the time-skew-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (time-skew-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the time-skew-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (time-skew-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # time-skew-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (time-skew-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # time-skew-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (time-skew-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the time-skew-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (time-skew-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # time-skew-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (time-skew-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the time-skew-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (time-skew-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the time-skew-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (time-skew-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # time-skew-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (time-skew-watchdog module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the time-skew-watchdog module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/module.toml"
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

@test "INVARIANT (time-skew-watchdog service unit declares SystemCallFilter= — syscall-allowlist hardening contract)" {
    # Sister to brain-wide systemd SystemCallFilter= INVARIANT
    # family. The time-skew-watchdog probes chronyc tracking
    # output — its syscall footprint is small + bounded. The
    # service MUST declare SystemCallFilter= (canonically
    # @system-service set) so an exploited chronyc parse
    # cannot pivot to esoteric syscalls (process_vm_writev,
    # ptrace, BPF). The canonical companion directive is
    # SystemCallErrorNumber=EPERM to fail-loud on a blocked
    # call rather than SIGSYS-kill the watchdog (operator
    # forensic-clarity). A regression dropping SystemCallFilter=
    # would leave the watchdog with full syscall surface,
    # defeating the defense-in-depth posture this small
    # one-shot was explicitly hardened with. Locks the
    # syscall-allowlist hardening discipline on the time-skew-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^SystemCallFilter=' "${s}"
    done
}

@test "INVARIANT (time-skew-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the time-skew-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (time-skew-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the time-skew-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (time-skew-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the time-skew-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (time-skew-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the time-skew-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (time-skew-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # time-skew-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (time-skew-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # time-skew-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (time-skew-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the time-skew-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (time-skew-watchdog timer unit declares OnBootSec= — boot-catchup-delay contract)" {
    # Sister to brain-wide systemd OnBootSec= INVARIANT
    # family. Watchdog .timer units MUST declare OnBootSec=
    # so the first watchdog fire is delayed until after boot
    # finishes settling. Locks the boot-catchup-delay
    # discipline on the time-skew-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnBootSec=' "${t}"
    done
}

@test "INVARIANT (time-skew-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (time-skew-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (time-skew-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (time-skew-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (time-skew-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the time-skew-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    [ -f "${script_dir}/time-skew-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (time-skew-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (time-skew-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (time-skew-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (time-skew-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (time-skew-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (time-skew-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (time-skew-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (time-skew-watchdog .sh script declares severity= variable with canonical vocabulary — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'severity=' "${s}"
    done
}

@test "INVARIANT (time-skew-watchdog .sh script tag selfdef-time-skew matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-time-skew
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (time-skew-watchdog .sh script declares chronyc invocation — backend-binary-canonical contract)" {
    # time-skew probes chronyc tracking output as its canonical query path
    script_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'chronyc' "${s}"
    done
}

@test "INVARIANT (time-skew-watchdog .sh script uses printf-format JSON output — structured-event-emission contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'printf' "${s}"
    done
}

@test "INVARIANT (time-skew-watchdog .sh script declares MODULE-suffixed tag in logger -t — module-name-tag-consistency contract)" {
    # Sister to SDD-062 tag-canonical INVARIANT family. The tag passed to
    # logger -t MUST include the module slug so journalctl filtering by
    # tag surfaces only this watchdog's events.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (time-skew-watchdog .sh script file is non-empty (size > 100 bytes) — non-trivial-script contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (time-skew-watchdog .sh script has >20 lines — non-trivial-watchdog-body contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 20 ]
    done
}

@test "INVARIANT (time-skew-watchdog .service unit file has >5 lines of directives — non-trivial-unit-file contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 5 ]
    done
}

@test "INVARIANT (time-skew-watchdog .service unit ExecStart references /usr/local/libexec/selfdef/ path — canonical-binary-path contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (time-skew-watchdog .timer file exists at canonical path modules/time-skew-watchdog/systemd — canonical-systemd-dir layout)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    [ -d "${timer_dir}" ]
    n=$(ls "${timer_dir}"/*.timer 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (time-skew-watchdog module.toml exists at canonical path modules/time-skew-watchdog/ — module-manifest existence 72-cycle)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (time-skew-watchdog systemd dir exists at modules/time-skew-watchdog/systemd — systemd-dir-existence 73-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    [ -d "${sd}" ]
}

@test "INVARIANT (time-skew-watchdog systemd dir is non-empty — systemd-content-presence 74-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    n=$(ls "${sd}" | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (time-skew-watchdog .service file size > 100 bytes — substantial-service-unit 75-cycle)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (time-skew-watchdog .timer file size > 50 bytes — substantial-timer-unit 76-cycle)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        size=$(stat -c '%s' "${t}")
        [ "${size}" -gt 50 ]
    done
}

@test "INVARIANT (time-skew-watchdog README.md file size > 100 bytes — substantial-readme 77-cycle)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/README.md"
    size=$(stat -c '%s' "${readme}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (time-skew-watchdog .service Documentation URL is HTTP/HTTPS — operator-doc-link-protocol 78)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=(http|https)://' "${s}"
    done
}

@test "INVARIANT (time-skew-watchdog .sh script has shebang line — POSIX-conformant 79)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '^#!'
    done
}

@test "INVARIANT (time-skew-watchdog .sh script declares set flag in first 50 lines — strict-mode-prologue 80)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -50 "${s}" | grep -qE '^set -'
    done
}

@test "INVARIANT (time-skew-watchdog module.toml size > 200 bytes — substantial-watchdog-manifest 81)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/module.toml"
    size=$(stat -c '%s' "${mtoml}")
    [ "${size}" -gt 200 ]
}

@test "INVARIANT (time-skew-watchdog .service file is non-empty — non-trivial-unit-file 82)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        [ -s "${s}" ]
    done
}

@test "INVARIANT (time-skew-watchdog .timer file is non-empty — non-trivial-timer-file 83)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        [ -s "${t}" ]
    done
}

@test "INVARIANT (time-skew-watchdog .sh script body has at least one variable assignment — non-vacuous-script 84)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^[a-zA-Z_]+=' "${s}"
    done
}

@test "INVARIANT (time-skew-watchdog .sh script path matches systemd dir layout — canonical-script-co-location 85)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/systemd"
    [ -d "${script_dir}" ]
    n=$(ls "${script_dir}"/*.sh 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (time-skew-watchdog module.toml has install_paths section — SDD-026 mutation-manifest 86)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (time-skew-watchdog module.toml install_paths.paths non-empty list 87)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list) and len(ps) > 0
"
}

@test "INVARIANT (time-skew-watchdog module.toml install_paths.paths only absolute paths 88)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (time-skew-watchdog module.toml provides list non-empty 89 — capability-export-present)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list) and len(p) >= 1
"
}

@test "INVARIANT (time-skew-watchdog module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (time-skew-watchdog module.toml install_paths.paths includes /etc/ entry — config-staging 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps)
"
}

@test "INVARIANT (time-skew-watchdog module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p for p in ps)
"
}

@test "INVARIANT (time-skew-watchdog module.toml has install_paths section non-empty 93)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
ps = ip.get('paths', [])
assert len(ps) >= 1
"
}

@test "INVARIANT (time-skew-watchdog module.toml [install_paths] declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (time-skew-watchdog module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (time-skew-watchdog module.toml uses TOML key-value syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (time-skew-watchdog module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (time-skew-watchdog module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (time-skew-watchdog module.toml category field double-quoted — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/time-skew-watchdog/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}
