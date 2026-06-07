#!/usr/bin/env bats
# L2 functional suite for swap-encryption-detect.
#
# swap-encryption-detect runs a periodic check that all swap
# devices are dm-crypt-backed (or zram with random key) — the
# unencrypted-swap vector exposes RAM contents to disk-recovery
# attacks against decommissioned drives or to attackers with
# physical disk access.
#
# Profiles:
#   report  → log finding; service exits 0 regardless
#   enforce → service exits non-zero if any swap is
#             unencrypted (failure surface for operator
#             alerting hooks)
#
# Same install pattern as mta-loopback-detect + secure-boot-
# status (libexec + service + timer + profile drop-in).
# Idempotency: install_one() uses cmp -s; systemctl reload +
# enable are gated on `changes > 0`.
#
# Run with: bats packaging/test/L2-swap-encryption-detect.bats

WD="${BATS_TEST_DIRNAME}/../../modules/swap-encryption-detect/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/swap-encryption-detect.toml"
    LIBEXEC_DIR="${TMP}/libexec/selfdef"
    SYSTEMD_DIR="${TMP}/systemd"
    DROPIN_DIR_SVC="${SYSTEMD_DIR}/selfdef-swap-encryption.service.d"
    DROPIN_PROFILE="${DROPIN_DIR_SVC}/50-profile.conf"
    SCRIPT_DST="${LIBEXEC_DIR}/swap-encryption-detect.sh"
    SVC_DST="${SYSTEMD_DIR}/selfdef-swap-encryption.service"
    TIMER_DST="${SYSTEMD_DIR}/selfdef-swap-encryption.timer"
    mkdir -p "${SYSTEMD_DIR}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_SWAPENC_CONFIG="${CONF}" \
    SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
    SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_SWAPENC_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_SWAPENC_CONFIG="${SELFDEF_SWAPENC_CONFIG}" \
        SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_SWAPENC_CONFIG="${CONF}" \
        SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be report|enforce"* ]]
}

@test "report profile installs libexec script + service + timer + profile dropin" {
    write_config "report"
    run_wd
    [ -f "${SCRIPT_DST}" ]
    [ -f "${SVC_DST}" ]
    [ -f "${TIMER_DST}" ]
    [ -f "${DROPIN_PROFILE}" ]
    grep -q '^Environment=SELFDEF_SWAPENC_PROFILE=report$' "${DROPIN_PROFILE}"
}

@test "enforce profile installs artifact set with enforce profile env" {
    write_config "enforce"
    run_wd
    [ -f "${DROPIN_PROFILE}" ]
    grep -q '^Environment=SELFDEF_SWAPENC_PROFILE=enforce$' "${DROPIN_PROFILE}"
}

@test "libexec script is chmod 0755" {
    write_config "report"
    run_wd
    [ "$(stat -c '%a' "${SCRIPT_DST}")" = "755" ]
}

@test "service + timer + dropin are chmod 0644" {
    write_config "report"
    run_wd
    [ "$(stat -c '%a' "${SVC_DST}")" = "644" ]
    [ "$(stat -c '%a' "${TIMER_DST}")" = "644" ]
    [ "$(stat -c '%a' "${DROPIN_PROFILE}")" = "644" ]
}

@test "first apply fires daemon-reload + enables the timer" {
    write_config "report"
    run_wd
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
    grep -q 'systemctl enable --now selfdef-swap-encryption.timer' "${SYSEOF_LOG}"
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite artifacts OR fire systemctl" {
    write_config "report"
    run_wd
    script_mtime_before="$(stat -c '%Y' "${SCRIPT_DST}")"
    svc_mtime_before="$(stat -c '%Y' "${SVC_DST}")"
    timer_mtime_before="$(stat -c '%Y' "${TIMER_DST}")"
    dropin_mtime_before="$(stat -c '%Y' "${DROPIN_PROFILE}")"
    : > "${SYSEOF_LOG}"
    sleep 1
    run_wd
    script_mtime_after="$(stat -c '%Y' "${SCRIPT_DST}")"
    svc_mtime_after="$(stat -c '%Y' "${SVC_DST}")"
    timer_mtime_after="$(stat -c '%Y' "${TIMER_DST}")"
    dropin_mtime_after="$(stat -c '%Y' "${DROPIN_PROFILE}")"
    [ "${script_mtime_before}" = "${script_mtime_after}" ]
    [ "${svc_mtime_before}" = "${svc_mtime_after}" ]
    [ "${timer_mtime_before}" = "${timer_mtime_after}" ]
    [ "${dropin_mtime_before}" = "${dropin_mtime_after}" ]
    ! grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
    ! grep -q 'systemctl enable' "${SYSEOF_LOG}"
}

@test "INVARIANT: profile switch report → enforce REWRITES profile dropin AND fires daemon-reload + enable" {
    write_config "report"
    run_wd
    : > "${SYSEOF_LOG}"
    write_config "enforce"
    run_wd
    grep -q '^Environment=SELFDEF_SWAPENC_PROFILE=enforce$' "${DROPIN_PROFILE}"
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
    grep -q 'systemctl enable --now selfdef-swap-encryption.timer' "${SYSEOF_LOG}"
}

@test "INVARIANT: DRY_RUN does not write any artifact or fire systemctl" {
    write_config "report"
    DRY_RUN=1 run_wd
    ! [ -f "${SCRIPT_DST}" ]
    ! [ -f "${SVC_DST}" ]
    ! [ -f "${TIMER_DST}" ]
    ! [ -f "${DROPIN_PROFILE}" ]
    ! grep -q 'systemctl' "${SYSEOF_LOG}"
}

@test "default profile is report (no profile key — conservative log-only default)" {
    : > "${CONF}"
    run_wd
    [ -f "${DROPIN_PROFILE}" ]
    grep -q '^Environment=SELFDEF_SWAPENC_PROFILE=report$' "${DROPIN_PROFILE}"
}

@test "emit_status reports changes count (4 first install; 0 idempotent)" {
    write_config "report"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'changes=4'* ]]
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'changes=0'* ]]
}

@test "INVARIANT (profile downgrade enforce → report): rewrites drop-in back + fires daemon-reload" {
    write_config "enforce"
    run_wd
    grep -q '^Environment=SELFDEF_SWAPENC_PROFILE=enforce$' "${DROPIN_PROFILE}"
    : > "${SYSEOF_LOG}"
    write_config "report"
    run_wd
    grep -q '^Environment=SELFDEF_SWAPENC_PROFILE=report$' "${DROPIN_PROFILE}"
    ! grep -q '^Environment=SELFDEF_SWAPENC_PROFILE=enforce$' "${DROPIN_PROFILE}"
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT (libexec script probes /proc/swaps + dm-crypt + zram — actually checks swap encryption)" {
    # The detector must actually walk the swap inventory.
    # /proc/swaps is the kernel's canonical view; dm-crypt + zram
    # are the two acceptable encrypted-swap backends.
    write_config "report"
    run_wd
    grep -q '/proc/swaps' "${SCRIPT_DST}"
    grep -qE '(dm-crypt|cryptsetup|crypttab|zram)' "${SCRIPT_DST}"
}

@test "INVARIANT (service unit references libexec script — wiring is correct)" {
    write_config "report"
    run_wd
    grep -qE '^ExecStart=' "${SVC_DST}"
    grep -q 'swap-encryption-detect' "${SVC_DST}"
}

@test "INVARIANT (timer unit carries OnCalendar / OnBootSec / OnUnitActiveSec — actually fires periodically)" {
    write_config "report"
    run_wd
    grep -qE '(OnCalendar|OnBootSec|OnUnitActiveSec)=' "${TIMER_DST}"
}

@test "INVARIANT (no render-timestamp in ANY of the 4 installed files): variant-A guard fleet-wide" {
    write_config "report"
    run_wd
    for f in "${SCRIPT_DST}" "${SVC_DST}" "${TIMER_DST}" "${DROPIN_PROFILE}"; do
        ! grep -qE '^# Generated [0-9]{4}-' "$f"
    done
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates all 4 files + fires daemon-reload)" {
    write_config "report"
    run_wd
    [ -f "${TIMER_DST}" ]
    rm -f "${SCRIPT_DST}" "${SVC_DST}" "${TIMER_DST}" "${DROPIN_PROFILE}"
    : > "${SYSEOF_LOG}"
    run_wd
    [ -f "${SCRIPT_DST}" ]
    [ -f "${SVC_DST}" ]
    [ -f "${TIMER_DST}" ]
    [ -f "${DROPIN_PROFILE}" ]
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "enforce"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"swap-encryption-detect"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=enforce'* ]]
}

@test "INVARIANT (enforce profile non-zero-exit semantics in libexec: PROFILE check translates unencrypted-swap to systemd-failure)" {
    # The enforce profile is the lever that turns unencrypted-swap
    # into a systemd service failure. Lock that the libexec script
    # contains profile-aware exit logic.
    write_config "enforce"
    run_wd
    grep -qE 'PROFILE|SELFDEF_SWAPENC_PROFILE|enforce' "${SCRIPT_DST}"
    grep -qE 'exit\s+[1-9]|return\s+[1-9]' "${SCRIPT_DST}"
}

@test "INVARIANT (timer + service carry 'selfdef' identifier in Description/Documentation — operator-audit-trail)" {
    write_config "report"
    run_wd
    grep -qE '^Description=.*selfdef|^Documentation=.*selfdef' "${TIMER_DST}"
    grep -qE '^Description=.*selfdef|^Documentation=.*selfdef' "${SVC_DST}"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # swap-encryption-detect TOML; parser must tolerate without
    # altering the profile-gated behavior. enforce-with-noise still
    # writes the SELFDEF_SWAPENC_PROFILE=enforce drop-in (escalates
    # unencrypted-swap from log-only to systemd-failure-recorded —
    # the operator-dashboard signal for RAM-to-disk exfiltration
    # surface surveillance).
    cat > "${CONF}" <<'TOMLEOF'
profile = "enforce"
operator_note = "unencrypted swap = RAM-to-disk exfil at decommission"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    grep -q '^Environment=SELFDEF_SWAPENC_PROFILE=enforce$' "${DROPIN_PROFILE}"
    ! grep -q '^Environment=SELFDEF_SWAPENC_PROFILE=report$' "${DROPIN_PROFILE}"
}

@test "INVARIANT (libexec is shell-sourceable: bash -n parses cleanly — service ExecStart contract)" {
    # Sister to many other installer module's shell-sourceable
    # INVARIANT across the brain. The libexec script runs from
    # systemd ExecStart. bash -n must parse cleanly. A syntax
    # regression would silently break the surveillance every fire
    # (timer scheduled; service can't ExecStart; unencrypted-swap
    # RAM-to-disk exfil surface goes unmonitored).
    write_config "report"
    run_wd
    bash -n "${SCRIPT_DST}"
}

@test "INVARIANT (timer unit carries OnUnitActiveSec — recurrent re-armed cadence beyond OnBootSec one-shot)" {
    # Sister to doctor-timer + entropy-baseline + secure-boot-
    # status OnUnitActiveSec INVARIANTs already locked. A one-
    # shot timer that fires only on OnBootSec would let a long-
    # uptime host run for weeks without swap-encryption check.
    # The selfdef-swap-encryption.timer MUST carry
    # OnUnitActiveSec=<period> so the unencrypted-swap RAM-to-
    # disk-exfil surveillance runs recurrently across long
    # uptimes (operator-resume from suspend or runtime swap
    # add could change the encryption state mid-uptime).
    write_config "report"
    run_wd
    grep -qE '^OnUnitActiveSec=' "${TIMER_DST}"
}

@test "INVARIANT (timer unit carries Persistent=true — missed-fires catch up after long downtime)" {
    # Sister to doctor-timer + entropy-baseline + secure-boot-
    # status + mta-loopback-detect Persistent=true INVARIANTs.
    # Without it host offline for 24+ hours misses every swap-
    # encryption probe in that window.
    write_config "report"
    run_wd
    grep -qE '^Persistent=true' "${TIMER_DST}"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on swap-encryption-detect installer
    # surface across 4 installed artifacts (script + service +
    # timer + drop-in).
    write_config "report"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"swap-encryption-detect"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics, not persistent service)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family
    # for timer-driven scheduled probes (entropy-baseline,
    # secure-boot-status, mta-loopback-detect, doctor-timer).
    # The swap-encryption-detect probe runs ON the timer's
    # scheduled fire — it executes ONCE, emits a verdict, then
    # exits. Type=simple would leave systemd thinking the probe
    # is a long-running daemon, breaking timer's OnSuccess /
    # OnFailure / OnUnitActiveSec semantics (which depend on
    # the service reaching inactive(dead) before the next fire).
    # Locks oneshot-probe contract on the swap-encryption-
    # detect substrate.
    write_config "report"
    run_wd
    grep -qE '^Type=oneshot' "${SVC_DST}"
}
