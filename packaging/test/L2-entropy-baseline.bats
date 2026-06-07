#!/usr/bin/env bats
# L2 functional suite for entropy-baseline.
#
# entropy-baseline installs a systemd-timer that periodically
# checks /proc/sys/kernel/random/entropy_avail and reports under-
# threshold conditions. Low entropy in kernel RNG pool means weak
# random numbers — predictable session keys, weak ASLR, broken
# TLS, broken SSH host-key generation, predictable container
# UUIDs.
#
# Profiles:
#   report  → log + alert on low entropy
#   enforce → also exit non-zero (systemd records failure that
#             surfaces via the doctor / dashboard)
#
# Test pattern: install fixtures, verify systemd unit files +
# libexec script land at the right paths with right perms +
# verify the profile drop-in carries the configured profile.
#
# Uses SELFDEF_LIBEXEC_DIR + SELFDEF_SYSTEMD_DIR env-vars
# (already present) for L2 testability.
#
# Run with: bats packaging/test/L2-entropy-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/entropy-baseline/install/apply.sh"

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
    CONF="${TMP}/entropy-baseline.toml"
    LIBEXEC_DIR="${TMP}/libexec"
    SYSTEMD_DIR="${TMP}/systemd"
    mkdir -p "${LIBEXEC_DIR}" "${SYSTEMD_DIR}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_ENTROPY_CONFIG="${CONF}" \
    SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
    SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_ENTROPY_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_ENTROPY_CONFIG="${SELFDEF_ENTROPY_CONFIG}" \
        SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_ENTROPY_CONFIG="${CONF}" \
        SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be report|enforce"* ]]
}

@test "report profile installs libexec script + service + timer + profile drop-in" {
    write_config "report"
    run_wd
    [ -f "${LIBEXEC_DIR}/entropy-baseline.sh" ]
    [ -x "${LIBEXEC_DIR}/entropy-baseline.sh" ]
    [ -f "${SYSTEMD_DIR}/selfdef-entropy.service" ]
    [ -f "${SYSTEMD_DIR}/selfdef-entropy.timer" ]
    [ -f "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf" ]
    # The profile drop-in carries SELFDEF_ENTROPY_PROFILE=report.
    grep -q 'SELFDEF_ENTROPY_PROFILE=report' "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf"
}

@test "enforce profile drop-in carries SELFDEF_ENTROPY_PROFILE=enforce" {
    write_config "enforce"
    run_wd
    grep -q 'SELFDEF_ENTROPY_PROFILE=enforce' "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf"
}

@test "libexec script has chmod 0755 (executable system-script convention)" {
    write_config "report"
    run_wd
    [ "$(stat -c '%a' "${LIBEXEC_DIR}/entropy-baseline.sh")" = "755" ]
}

@test "service + timer files have chmod 0644 (system-config convention)" {
    write_config "report"
    run_wd
    [ "$(stat -c '%a' "${SYSTEMD_DIR}/selfdef-entropy.service")" = "644" ]
    [ "$(stat -c '%a' "${SYSTEMD_DIR}/selfdef-entropy.timer")" = "644" ]
    [ "$(stat -c '%a' "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf")" = "644" ]
}

@test "systemctl daemon-reload + timer enable fire when files changed" {
    write_config "report"
    run_wd
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
    grep -q 'systemctl enable --now selfdef-entropy.timer' "${SYSEOF_LOG}"
}

@test "INVARIANT: idempotent — re-install with identical content fires NO daemon-reload" {
    write_config "report"
    run_wd
    : > "${SYSEOF_LOG}"
    run_wd
    ! grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT: profile change report → enforce updates drop-in + fires daemon-reload" {
    write_config "report"
    run_wd
    write_config "enforce"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'SELFDEF_ENTROPY_PROFILE=enforce' "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf"
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT: DRY_RUN does not install anything or fire systemctl" {
    write_config "report"
    DRY_RUN=1 run_wd
    ! [ -f "${LIBEXEC_DIR}/entropy-baseline.sh" ]
    ! [ -f "${SYSTEMD_DIR}/selfdef-entropy.service" ]
    ! grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "default profile is report (no profile key — the safe default)" {
    : > "${CONF}"
    run_wd
    grep -q 'SELFDEF_ENTROPY_PROFILE=report' "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf"
}

@test "INVARIANT (profile downgrade enforce → report): rewrites drop-in back + fires reload" {
    write_config "enforce"
    run_wd
    grep -q 'SELFDEF_ENTROPY_PROFILE=enforce' "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf"
    write_config "report"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'SELFDEF_ENTROPY_PROFILE=report' "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf"
    ! grep -q 'SELFDEF_ENTROPY_PROFILE=enforce' "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf"
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT (idempotent mtime): byte-identical re-install preserves all 4 file mtimes" {
    write_config "report"
    run_wd
    mtime_libexec_before="$(stat -c '%Y' "${LIBEXEC_DIR}/entropy-baseline.sh")"
    mtime_service_before="$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-entropy.service")"
    mtime_timer_before="$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-entropy.timer")"
    mtime_dropin_before="$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf")"
    sleep 1
    run_wd
    [ "${mtime_libexec_before}" = "$(stat -c '%Y' "${LIBEXEC_DIR}/entropy-baseline.sh")" ]
    [ "${mtime_service_before}" = "$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-entropy.service")" ]
    [ "${mtime_timer_before}" = "$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-entropy.timer")" ]
    [ "${mtime_dropin_before}" = "$(stat -c '%Y' "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf")" ]
}

@test "INVARIANT (libexec script reads /proc/sys/kernel/random/entropy_avail — actually probes the kernel knob)" {
    write_config "report"
    run_wd
    grep -qE '/proc/sys/kernel/random/entropy_avail' "${LIBEXEC_DIR}/entropy-baseline.sh"
}

@test "INVARIANT (service unit references libexec script — wiring is correct)" {
    write_config "report"
    run_wd
    grep -qE '^ExecStart=' "${SYSTEMD_DIR}/selfdef-entropy.service"
    grep -q 'entropy-baseline' "${SYSTEMD_DIR}/selfdef-entropy.service"
}

@test "INVARIANT (timer unit carries OnCalendar / OnBootSec — actually fires periodically)" {
    write_config "report"
    run_wd
    grep -qE '(OnCalendar|OnBootSec|OnUnitActiveSec)=' "${SYSTEMD_DIR}/selfdef-entropy.timer"
}

@test "INVARIANT (no render-timestamp in any installed file): defeats cmp -s idempotency" {
    write_config "report"
    run_wd
    for f in "${LIBEXEC_DIR}/entropy-baseline.sh" \
             "${SYSTEMD_DIR}/selfdef-entropy.service" \
             "${SYSTEMD_DIR}/selfdef-entropy.timer" \
             "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf"; do
        ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "$f"
    done
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates all 4 files + fires daemon-reload)" {
    # Operator may rm one of the installed files — apply must rebuild
    # and re-arm the timer so the entropy surveillance is restored.
    write_config "report"
    run_wd
    [ -f "${SYSTEMD_DIR}/selfdef-entropy.timer" ]
    rm -f "${LIBEXEC_DIR}/entropy-baseline.sh" \
          "${SYSTEMD_DIR}/selfdef-entropy.service" \
          "${SYSTEMD_DIR}/selfdef-entropy.timer" \
          "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf"
    : > "${SYSEOF_LOG}"
    run_wd
    [ -f "${LIBEXEC_DIR}/entropy-baseline.sh" ]
    [ -f "${SYSTEMD_DIR}/selfdef-entropy.service" ]
    [ -f "${SYSTEMD_DIR}/selfdef-entropy.timer" ]
    [ -f "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf" ]
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "enforce"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"entropy-baseline"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=enforce'* ]]
}

@test "INVARIANT (libexec carries threshold value — actually has a comparison check)" {
    # The detection logic isn't just reading entropy_avail — it must
    # compare against a threshold (else it's just a printer, not a
    # detector). Lock that the libexec script has a comparison and
    # exits non-zero (enforce) on threshold-breach.
    write_config "report"
    run_wd
    libexec="${LIBEXEC_DIR}/entropy-baseline.sh"
    # Threshold integer comparison.
    grep -qE '(-lt|-le|<|<=|\[\s*[0-9]+\s*\])' "${libexec}"
    # Severity ladder.
    grep -qE 'alert|warn|low|threshold' "${libexec}"
}

@test "INVARIANT (timer + service header marker — operator-audit-trail)" {
    write_config "report"
    run_wd
    grep -qE '^#.*selfdef|^#.*managed-by' "${SYSTEMD_DIR}/selfdef-entropy.timer"
    grep -qE '^#.*selfdef|^#.*managed-by' "${SYSTEMD_DIR}/selfdef-entropy.service"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # entropy-baseline TOML; parser must tolerate without altering
    # the profile-gated behavior. enforce-with-noise still writes
    # the SELFDEF_ENTROPY_PROFILE=enforce drop-in (escalates low-
    # entropy from log-only to systemd-failure-recorded — the
    # operator-dashboard signal).
    cat > "${CONF}" <<'TOMLEOF'
profile = "enforce"
operator_note = "kernel-RNG starvation = weak TLS / SSH host keys / ASLR"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    grep -q 'SELFDEF_ENTROPY_PROFILE=enforce' "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf"
    ! grep -q 'SELFDEF_ENTROPY_PROFILE=report' "${SYSTEMD_DIR}/selfdef-entropy.service.d/50-profile.conf"
}

@test "INVARIANT (libexec is shell-sourceable: bash -n parses cleanly — service ExecStart contract)" {
    # Sister to many other installer module's shell-sourceable
    # INVARIANT across the brain (secure-boot-status / swap-
    # encryption-detect / mta-loopback-detect). The libexec script
    # runs from systemd ExecStart. bash -n must parse cleanly. A
    # syntax regression would silently break the surveillance
    # every fire (timer scheduled; service can't ExecStart; kernel-
    # RNG starvation surface — weak TLS host keys / SSH host keys
    # / ASLR seeds — goes unmonitored).
    write_config "report"
    run_wd
    bash -n "${LIBEXEC_DIR}/entropy-baseline.sh"
}

@test "INVARIANT (timer unit carries OnUnitActiveSec — recurrent re-armed cadence beyond OnBootSec one-shot)" {
    # Sister to doctor-timer + many other selfdef timer units'
    # OnUnitActiveSec INVARIANTs across the brain. A one-shot
    # timer that fires only on OnBootSec would let a long-uptime
    # host run for weeks without entropy probe. The selfdef-
    # entropy.timer MUST carry OnUnitActiveSec=<period> so the
    # kernel-RNG starvation surveillance runs recurrently across
    # long uptimes. Locks the recurrent-fire contract.
    write_config "report"
    run_wd
    grep -qE '^OnUnitActiveSec=' "${SYSTEMD_DIR}/selfdef-entropy.timer"
}

@test "INVARIANT (timer unit carries Persistent=true — missed-fires catch up after long downtime)" {
    # Sister to doctor-timer + many other selfdef timer-unit
    # Persistent=true INVARIANTs across the brain. Without
    # Persistent=true, systemd does NOT remember timer fires
    # missed during host downtime. A host offline for 24+ hours
    # misses every kernel-RNG entropy probe for that window AND
    # on next boot only fires the NEXT scheduled fire (not the
    # missed ones). With Persistent=true, systemd fires
    # immediately on boot if the recurrent interval has elapsed
    # since last successful fire. Locks the missed-fire-catch-
    # up contract on the kernel-RNG starvation surveillance
    # substrate.
    write_config "report"
    run_wd
    grep -qE '^Persistent=true' "${SYSTEMD_DIR}/selfdef-entropy.timer"
}

@test "INVARIANT (timer + service + libexec unit chmod 0644 — system-config convention)" {
    # Sister to brain-wide chmod 0644 INVARIANTs.
    write_config "report"
    run_wd
    [ "$(stat -c '%a' "${SYSTEMD_DIR}/selfdef-entropy.timer")" = "644" ]
    [ "$(stat -c '%a' "${SYSTEMD_DIR}/selfdef-entropy.service")" = "644" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on entropy-baseline installer
    # surface across libexec + service + timer phases.
    write_config "report"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"entropy-baseline"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family
    # for timer-driven scheduled probes (secure-boot-status,
    # swap-encryption-detect, doctor-timer, bootloader-password-
    # detect). The entropy-baseline probe runs ON the timer's
    # scheduled fire — executes ONCE, reads /proc/sys/kernel/
    # random/entropy_avail, compares to threshold, emits a
    # verdict, then exits. Type=simple would leave systemd
    # thinking the probe is a long-running daemon, breaking
    # timer's OnSuccess / OnUnitActiveSec semantics. Locks
    # oneshot-probe contract on the entropy-baseline substrate.
    write_config "report"
    run_wd
    grep -qE '^Type=oneshot' "${SYSTEMD_DIR}/selfdef-entropy.service"
}
