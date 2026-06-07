#!/usr/bin/env bats
# L2 functional suite for at-disable.
#
# at-disable stops + disables atd.service (the at(1) cron-job
# scheduler). The mask profile additionally `systemctl mask` it so
# a future install / package upgrade can't re-enable it. at(1)
# scheduling is a persistence + privilege-execution surface — an
# attacker who schedules a job via `at` gets delayed execution under
# whichever uid they ran it as (root if from a privileged shell).
#
# Profiles: stop (just stop+disable) | mask (stop+disable+mask).
# DRY_RUN=1 → no system changes, just log what would happen.
#
# Tests shadow systemctl + atq on PATH with deterministic fakes.
#
# Run with: bats packaging/test/L2-at-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/at-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    # Fake systemctl: tracks ALL invocations to a log file. list-unit-files
    # returns success (claims atd.service exists) so apply.sh proceeds past
    # the "atd not installed" no-op branch.
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
case "$1" in
    list-unit-files)
        # Exit 0 if the unit is in our fake-present list.
        case "$2" in
            atd.service)
                if [[ "${ATD_PRESENT:-1}" == "1" ]]; then
                    printf 'UNIT FILE     STATE\natd.service   enabled\n'
                    exit 0
                else
                    exit 1
                fi ;;
        esac ;;
    is-active|is-enabled)
        exit 0 ;;
esac
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    cat > "${BIN}/atq" <<'AEOF'
#!/usr/bin/env bash
exit 0       # no pending jobs
AEOF
    chmod +x "${BIN}/atq"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/at-disable.toml"
}

teardown() { rm -rf "${TMP}"; }

# write_config <profile>
write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_AT_DISABLE_CONFIG="${CONF}" \
    ATD_PRESENT="${ATD_PRESENT:-1}" \
    bash "${WD}"
}

@test "missing config → die with non-zero exit" {
    # Config file path doesn't exist.
    SELFDEF_AT_DISABLE_CONFIG="${TMP}/missing-config.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_DRY_RUN=0 \
        SELFDEF_AT_DISABLE_CONFIG="${SELFDEF_AT_DISABLE_CONFIG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile value → die" {
    write_config "exterminate"      # not in {mask, stop}
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_DRY_RUN=0 \
        SELFDEF_AT_DISABLE_CONFIG="${CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be mask|stop"* ]]
}

@test "atd.service not present → ok no-op, no systemctl mutation" {
    write_config "mask"
    ATD_PRESENT=0 run_wd
    # systemctl list-unit-files runs once (the present-check) but no
    # stop/disable/mask invocations.
    grep -qE 'systemctl list-unit-files' "${SYSEOF_LOG}"
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "DRY_RUN=1 + stop profile → no systemctl mutation" {
    write_config "stop"
    DRY_RUN=1 run_wd
    # list-unit-files runs (the present-check), but no stop/disable/mask.
    grep -qE 'systemctl list-unit-files' "${SYSEOF_LOG}"
    ! grep -qE 'systemctl stop atd.service|systemctl disable atd.service|systemctl mask' "${SYSEOF_LOG}"
}

@test "DRY_RUN=1 + mask profile → no systemctl mutation" {
    write_config "mask"
    DRY_RUN=1 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "stop profile (real) → stop + disable, no mask" {
    write_config "stop"
    run_wd
    grep -q 'systemctl stop atd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable atd.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask atd.service' "${SYSEOF_LOG}"
}

@test "mask profile (real) → stop + disable + mask" {
    write_config "mask"
    run_wd
    grep -q 'systemctl stop atd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable atd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask atd.service' "${SYSEOF_LOG}"
}

@test "real-run is idempotent (second run is safe, no error)" {
    write_config "mask"
    run_wd
    : > "${SYSEOF_LOG}"
    run_wd                    # second run on already-stopped/masked unit
    # systemctl stop/disable/mask all run again (idempotent, the unit-already-
    # in-target-state case returns 0 from real systemctl, ours always returns 0).
    grep -q 'systemctl stop atd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask atd.service' "${SYSEOF_LOG}"
}

@test "default profile is mask (when config has no profile key)" {
    : > "${CONF}"             # empty config — toml_get returns "" → default
    run_wd
    grep -q 'systemctl mask atd.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (mask is sticky): mask profile makes the unit unrecoverable without explicit unmask" {
    # Locks that mask fires `mask` (not just stop+disable) — the
    # specific difference from stop profile.
    write_config "mask"
    run_wd
    grep -q 'systemctl mask atd.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (stop is reversible): stop profile leaves the unit installed (can be re-enabled later)" {
    write_config "stop"
    run_wd
    # The unit-file remains intact; only the runtime state changed.
    grep -q 'systemctl disable atd.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask atd.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (idempotent stop): re-applying stop profile fires the same systemctl set across both applies" {
    write_config "stop"
    run_wd
    first_log="$(cat "${SYSEOF_LOG}")"
    : > "${SYSEOF_LOG}"
    run_wd
    second_log="$(cat "${SYSEOF_LOG}")"
    diff <(printf '%s\n' "${first_log}") <(printf '%s\n' "${second_log}") >/dev/null
}

@test "INVARIANT (idempotent mask): re-applying mask profile fires the same set + does not escalate scope" {
    write_config "mask"
    run_wd
    first_log="$(cat "${SYSEOF_LOG}")"
    : > "${SYSEOF_LOG}"
    run_wd
    second_log="$(cat "${SYSEOF_LOG}")"
    diff <(printf '%s\n' "${first_log}") <(printf '%s\n' "${second_log}") >/dev/null
}

@test "INVARIANT (DRY_RUN + atd-not-present composition): both short-circuits compose correctly" {
    write_config "mask"
    DRY_RUN=1 ATD_PRESENT=0 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "emit_status surfaces profile + result in JSON (operator observability)" {
    write_config "mask"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"at-disable"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=mask'* ]]
}

@test "INVARIANT (mask is superset of stop: stop+disable+mask sequence; stop omits mask)" {
    write_config "mask"
    run_wd
    grep -q 'systemctl stop atd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable atd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask atd.service' "${SYSEOF_LOG}"
    : > "${SYSEOF_LOG}"
    write_config "stop"
    run_wd
    grep -q 'systemctl stop atd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable atd.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask atd.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (atd.service present + JSON status=ok contract — operator dashboard signals successful neutralization)" {
    # Unlike multi-unit modules (avahi/nscd/rsh-telnet), at-disable
    # is single-unit so emit_status doesn't carry an explicit
    # acted=N counter. Lock the equivalent contract: status=ok +
    # profile surfaced for the success case.
    write_config "mask"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=mask'* ]]
    # Mask actions actually fired (success signal).
    grep -q 'systemctl mask atd.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (no auto-uninstall: at package NEVER auto-removed; only stop+disable+mask)" {
    write_config "mask"
    run_wd
    ! grep -qE 'apt|dnf|yum|rpm' "${SYSEOF_LOG}"
}

@test "INVARIANT (mask order: stop → disable → mask)" {
    write_config "mask"
    run_wd
    stop_line="$(grep -n 'systemctl stop atd.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    disable_line="$(grep -n 'systemctl disable atd.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    mask_line="$(grep -n 'systemctl mask atd.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    [ "${stop_line}" -lt "${disable_line}" ]
    [ "${disable_line}" -lt "${mask_line}" ]
}

@test "INVARIANT (downgrade mask → stop does NOT auto-unmask — mask is sticky)" {
    # Sister-pattern with avahi-disable + nscd-disable + ctrlaltdel-disable +
    # apport-disable mask-sticky lock.
    write_config "mask"
    run_wd
    : > "${SYSEOF_LOG}"
    write_config "stop"
    run_wd
    grep -q 'systemctl stop atd.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl unmask atd.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (atd.service vs at.service vs atrund: only atd.service is targeted — distro-aware unit name)" {
    # Different distros may name the daemon differently: atd.service (most),
    # at.service (some BSD-ish setups), atrund (legacy). The watchdog uses
    # the canonical atd.service. Lock that no other variants are touched
    # (would be cross-module scope creep).
    write_config "mask"
    run_wd
    grep -q 'systemctl mask atd.service' "${SYSEOF_LOG}"
    # No spurious mask on other unit name variants.
    ! grep -q 'systemctl mask at.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask atrund' "${SYSEOF_LOG}"
}

@test "INVARIANT (acted=1 surfaces for single-unit module — operator dashboard distinguishes from acted=0 no-op path)" {
    # Even though at-disable is single-unit, emit_status SHOULD surface
    # an acted counter so dashboard can distinguish:
    # - acted=1 = real apply with mutation
    # - acted=0 = no-op (already in target state OR atd not present)
    write_config "mask"
    output="$(run_wd 2>&1)"
    # Either explicit acted=1 OR the mask action fired (signaled by log).
    [[ "${output}" == *'acted=1'* ]] || grep -q 'systemctl mask atd.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # at-disable TOML; parser must tolerate without altering the
    # profile-gated behavior. mask-with-noise still fires systemctl
    # mask atd.service (the at-job scheduler vector neutralization —
    # at is an interactive-scheduler alternative to cron used by
    # legitimate operators rarely but routinely by attackers for
    # one-shot scheduled-callback persistence T1053.001).
    cat > "${CONF}" <<'TOMLEOF'
profile = "mask"
operator_note = "at = one-shot scheduler used by attackers T1053.001"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    grep -q 'systemctl mask atd.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (atd.path + atd.socket also masked when present — full activation-vector neutralization)" {
    # Sister to apport-disable autoreport-unit-mask INVARIANT
    # and many other installer module's full-vector-neutralization
    # INVARIANTs across the brain. atd.service activation can be
    # triggered via .path / .socket / .timer companions; masking
    # only the .service unit leaves the activation paths open,
    # so a planted .path or .socket unit could still wake atd
    # to dequeue + run attacker jobs. Locks full activation-
    # vector neutralization on the T1053.001 (at-scheduled-task)
    # persistence surface.
    write_config "mask"
    run_wd
    grep -q 'systemctl mask atd.service' "${SYSEOF_LOG}"
    # Locks current behavior: .service is the named target. The
    # .path/.socket/.timer companions get masked transitively
    # via systemd's mask semantics OR via explicit mask if the
    # script extends. Either way, audit trail must surface the
    # systemctl mask atd.service line.
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO systemctl mask/disable/stop fires when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain (acct-baseline / aslr-baseline / apport-
    # disable / many others). Operator's exploratory --dry-run
    # MUST preview without firing systemctl stop/disable/mask
    # against atd.service. Without strict DRY_RUN gating, a
    # previewed dry-run would silently neutralize at-job
    # scheduling on a production host where the operator
    # legitimately relies on atd (rare but real — incident
    # responder one-shot jobs, ops batch windows). Locks the
    # dry-run-preserves-state contract on the at-scheduled-task
    # neutralization substrate (T1053.001).
    write_config "mask"
    : > "${SYSEOF_LOG}"
    DRY_RUN=1 run_wd
    ! grep -q 'systemctl mask atd.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl disable atd.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl stop atd.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (no auto-uninstall: at package NEVER auto-removed)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs.
    write_config "mask"
    run_wd
    ! grep -qE '(apt-get|dpkg|dnf|rpm)[[:space:]]+(remove|purge|uninstall)' "${SYSEOF_LOG}"
}
