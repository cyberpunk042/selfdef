#!/usr/bin/env bats
# L2 functional suite for journal-tune.
#
# journal-tune installs /etc/systemd/journald.conf.d/50-selfdef.
# conf with the chosen profile. Journald is the audit trail —
# tampered / undersized / world-readable journals defeat incident
# forensics. The two profiles tighten different axes:
#   standard  → reasonable retention + size caps (the always-safe
#               baseline)
#   paranoid  → tight retention, forward to remote, strict mode,
#               larger pool for high-volume hosts
#
# CRITICAL INVARIANTS this suite locks:
#   - Idempotent: byte-identical re-install fires NO journald
#     restart (a restart loses the in-memory journal queue —
#     unnecessary restart = potential data loss).
#   - Profile change standard → paranoid replaces drop-in +
#     restarts.
#   - DRY_RUN protects BOTH drop-in AND systemctl restart.
#
# Uses SELFDEF_JOURNAL_DROPIN_DIR env-var (already present) for
# L2 testability.
#
# Run with: bats packaging/test/L2-journal-tune.bats

WD="${BATS_TEST_DIRNAME}/../../modules/journal-tune/install/apply.sh"

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
    CONF="${TMP}/journal-tune.toml"
    DROPIN_DIR="${TMP}/journald.conf.d"
    mkdir -p "${DROPIN_DIR}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_JOURNAL_TUNE_CONFIG="${CONF}" \
    SELFDEF_JOURNAL_DROPIN_DIR="${DROPIN_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_JOURNAL_TUNE_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_JOURNAL_TUNE_CONFIG="${SELFDEF_JOURNAL_TUNE_CONFIG}" \
        SELFDEF_JOURNAL_DROPIN_DIR="${DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_JOURNAL_TUNE_CONFIG="${CONF}" \
        SELFDEF_JOURNAL_DROPIN_DIR="${DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be standard|paranoid"* ]]
}

@test "standard profile installs drop-in + restarts journald" {
    write_config "standard"
    run_wd
    [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    cmp -s modules/journal-tune/configs/standard.conf "${DROPIN_DIR}/50-selfdef.conf"
    grep -q 'systemctl restart systemd-journald' "${SYSEOF_LOG}"
}

@test "paranoid profile installs the tighter drop-in" {
    write_config "paranoid"
    run_wd
    [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    cmp -s modules/journal-tune/configs/paranoid.conf "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT: idempotent — re-install with identical content fires NO journald restart" {
    write_config "standard"
    run_wd
    : > "${SYSEOF_LOG}"
    run_wd                              # byte-identical re-install
    # CRITICAL: no restart = no data loss to in-memory journal queue.
    ! grep -q 'systemctl restart' "${SYSEOF_LOG}"
}

@test "INVARIANT: profile change standard → paranoid replaces drop-in + restarts" {
    write_config "standard"
    run_wd
    cmp -s modules/journal-tune/configs/standard.conf "${DROPIN_DIR}/50-selfdef.conf"
    write_config "paranoid"
    : > "${SYSEOF_LOG}"
    run_wd
    cmp -s modules/journal-tune/configs/paranoid.conf "${DROPIN_DIR}/50-selfdef.conf"
    grep -q 'systemctl restart systemd-journald' "${SYSEOF_LOG}"
}

@test "INVARIANT: DRY_RUN does not write drop-in or restart" {
    write_config "standard"
    DRY_RUN=1 run_wd
    ! [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    ! grep -q 'systemctl restart' "${SYSEOF_LOG}"
}

@test "drop-in is chmod 0644" {
    write_config "standard"
    run_wd
    [ "$(stat -c '%a' "${DROPIN_DIR}/50-selfdef.conf")" = "644" ]
}

@test "default profile is standard (no profile key)" {
    : > "${CONF}"
    run_wd
    cmp -s modules/journal-tune/configs/standard.conf "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (idempotent mtime): byte-identical re-install preserves drop-in mtime" {
    # Stronger than test-94's "no restart" — locks the file-mtime
    # preservation that the cmp -s guard provides.
    write_config "standard"
    run_wd
    mtime_before="$(stat -c '%Y' "${DROPIN_DIR}/50-selfdef.conf")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DROPIN_DIR}/50-selfdef.conf")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT (profile downgrade paranoid → standard): replaces drop-in + restarts journald" {
    # The reverse direction of test-103. Both transitions must work —
    # locks the bidirectional contract.
    write_config "paranoid"
    run_wd
    cmp -s modules/journal-tune/configs/paranoid.conf "${DROPIN_DIR}/50-selfdef.conf"
    write_config "standard"
    : > "${SYSEOF_LOG}"
    run_wd
    cmp -s modules/journal-tune/configs/standard.conf "${DROPIN_DIR}/50-selfdef.conf"
    grep -q 'systemctl restart systemd-journald' "${SYSEOF_LOG}"
}

@test "INVARIANT (paranoid carries Storage=persistent): paranoid drop-in must commit journals to disk (forward-to-remote requires persistent)" {
    write_config "paranoid"
    run_wd
    grep -qE '^Storage=persistent' "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (no render-timestamp in drop-in): journald drop-in must not carry a Generated <ISO-date> line" {
    # Latent variant-A risk class — without this guard, re-install
    # would replace the drop-in every time + flush in-memory journal.
    write_config "standard"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (graceful-reload preferred when available): journald supports SIGUSR1 reload — but restart is the canonical for journal-tune config-change semantics" {
    # journald drop-ins require restart (USR1 only re-rotates), so the
    # restart is the *correct* mechanism here (not a fallback).
    write_config "standard"
    run_wd
    grep -q 'systemctl restart systemd-journald' "${SYSEOF_LOG}"
}

@test "INVARIANT (standard carries SystemMaxUse retention cap — disk-usage upper bound)" {
    # Audit-trail integrity requires bounded retention so journald
    # doesn't fill disk + cause secondary outages. Lock standard
    # has SystemMaxUse= directive.
    write_config "standard"
    run_wd
    grep -qE '^SystemMaxUse=' "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (paranoid SystemMaxUse > standard SystemMaxUse — paranoid sized for high-volume hosts)" {
    # Paranoid is for audit-rules paranoid + AI tool processes that
    # journal-log heavily — must have LARGER retention than standard
    # to capture more forensic history before rotation.
    write_config "standard"
    run_wd
    std_max="$(grep -oE 'SystemMaxUse=[0-9]+[GMK]?' "${DROPIN_DIR}/50-selfdef.conf" | head -1)"
    write_config "paranoid"
    run_wd
    para_max="$(grep -oE 'SystemMaxUse=[0-9]+[GMK]?' "${DROPIN_DIR}/50-selfdef.conf" | head -1)"
    # Both must be present + paranoid value lexically/numerically > standard.
    [ -n "${std_max}" ]
    [ -n "${para_max}" ]
    [ "${std_max}" != "${para_max}" ]
}

@test "INVARIANT (drop-in re-arm after operator out-of-band deletion: re-creates drop-in + fires restart)" {
    write_config "standard"
    run_wd
    [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    rm -f "${DROPIN_DIR}/50-selfdef.conf"
    : > "${SYSEOF_LOG}"
    run_wd
    [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    grep -q 'systemctl restart systemd-journald' "${SYSEOF_LOG}"
}

@test "INVARIANT (emit_status JSON: status=ok + profile surfaced for operator dashboard)" {
    write_config "standard"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"journal-tune"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=standard'* ]]
}

@test "INVARIANT (standard carries SystemMaxFileSize cap — per-journal-file size bound)" {
    # Per-file size cap controls rotation cadence — too-large files
    # delay rotation + create single-file-corruption risk; too-small
    # files churn rotation. Lock standard has SystemMaxFileSize directive.
    write_config "standard"
    run_wd
    grep -qE '^SystemMaxFileSize=' "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT ([Journal] section header in drop-in — valid systemd-journald.conf fragment)" {
    # journald drop-ins MUST declare [Journal] section header to be
    # honored by systemd-journald.
    write_config "standard"
    run_wd
    grep -qE '^\[Journal\]' "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (paranoid carries ForwardToSyslog OR ForwardToWall OR Storage tightening — paranoid does MORE than just retention bump)" {
    # paranoid is not just bigger retention — it tightens forward/storage
    # too. Lock that paranoid drop-in carries at least one forward/
    # storage directive beyond the size caps.
    write_config "paranoid"
    run_wd
    grep -qE '^(ForwardTo(Syslog|Wall|KMsg)|Storage|Seal|Compress)=' "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # journal-tune TOML; parser must tolerate without altering the
    # profile-gated behavior. paranoid-with-noise still installs
    # the tighter drop-in (Storage=persistent + forward-to + size
    # bumps — the audit-trail-integrity ladder for high-volume
    # hosts).
    cat > "${CONF}" <<'TOMLEOF'
profile = "paranoid"
operator_note = "high-volume audit-rules + AI-tool journal heavy"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    cmp -s modules/journal-tune/configs/paranoid.conf "${DROPIN_DIR}/50-selfdef.conf"
    grep -qE '^Storage=persistent' "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (drop-in carries selfdef self-identifying header — head -1 stale-cleanup discipline)" {
    # Sister to many other installer module's header-marker
    # INVARIANT across the brain (ssh-hardening / slm-cpu-loop /
    # tensor-parallel-inference / hardware-tune-cache). The drop-in
    # lands at /etc/systemd/journald.conf.d/50-selfdef.conf
    # alongside operator-hand-authored 60-/99- drop-ins. A stale-
    # cleanup pass (operator housekeeping or uninstall path) inspects
    # the first non-blank comment line to identify selfdef-rendered
    # config from operator config. Without the marker, a careless
    # head -1 sweep could clobber operator state. Locks the
    # provenance contract on BOTH standard + paranoid profiles.
    write_config "standard"
    run_wd
    first_nonblank="$(grep -E -m1 -v '^[[:space:]]*$' "${DROPIN_DIR}/50-selfdef.conf")"
    [[ "${first_nonblank}" == *"selfdef"* ]]
    write_config "paranoid"
    run_wd
    first_nonblank="$(grep -E -m1 -v '^[[:space:]]*$' "${DROPIN_DIR}/50-selfdef.conf")"
    [[ "${first_nonblank}" == *"selfdef"* ]]
}

@test "INVARIANT (drop-in is chmod 0644 — system-config convention)" {
    # Sister to many other installer module's chmod 0644 INVARIANT
    # across the brain (sysctl drop-ins, limits.d, ssh-hardening
    # drop-in, apparmor-baseline AA_LIST). The journald conf.d
    # drop-in must be world-readable (systemd-journald reads it at
    # daemon start) and root-write-only (any other mode would let
    # an attacker silently retune the journal — Storage=none
    # would defeat audit-trail forensics).
    write_config "standard"
    run_wd
    [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    [ "$(stat -c '%a' "${DROPIN_DIR}/50-selfdef.conf")" = "644" ]
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO drop-in written AND NO journald restart fired when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing /etc/systemd/journald.conf.d/
    # 50-selfdef.conf AND without restarting systemd-journald.
    # A silent dry-run that committed would re-tune journal
    # storage AT PREVIEW TIME on a host where operator was
    # investigating journal behavior. Locks dry-run-preserves-
    # state on the journal-retention substrate.
    write_config "standard"
    rm -f "${DROPIN_DIR}/50-selfdef.conf"
    : > "${SYSEOF_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${DROPIN_DIR}/50-selfdef.conf" ]
    ! grep -qE 'systemctl (restart|reload) systemd-journald' "${SYSEOF_LOG}"
}

@test "INVARIANT (paranoid carries SystemMaxUse cap — disk-bound retention floor)" {
    # Sister to standard SystemMaxFileSize INVARIANT.
    # SystemMaxUse caps total journal disk usage on the host —
    # without it on paranoid, a busy host's journal can fill
    # /var/log/journal indefinitely, eventually triggering disk
    # exhaustion (denial-of-availability via log-volume).
    write_config "paranoid"
    run_wd
    drop_in="${DROPIN_DIR}/50-selfdef.conf"
    [ -f "${drop_in}" ]
    grep -qE '^SystemMaxUse[[:space:]]*=' "${drop_in}"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on journal-tune installer surface
    # across drop-in + journald-restart phases.
    write_config "paranoid"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"journal-tune"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no auto-uninstall: journal-tune NEVER emits package-remove commands on systemd-journald)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The journal-tune installer writes a journald.
    # conf.d drop-in pinning SystemMaxUse + Storage + retention
    # but MUST NEVER emit shell commands that uninstall the
    # systemd package itself (apt/dpkg/dnf/rpm/yum remove|purge|
    # uninstall systemd|systemd-journal-remote). Silent auto-
    # removal would be catastrophic — systemd-journald is the
    # init system's logging substrate, removing it would break
    # the entire OS audit trail + most service monitoring.
    # T1562.001 self-defeat. Locks anti-package-removal contract
    # on the journal-tune substrate.
    write_config "paranoid"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(systemd|systemd-journal-remote)'
    drop_in="${DROPIN_DIR}/50-selfdef.conf"
    [ ! -f "${drop_in}" ] || ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${drop_in}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. journal-tune manifest declares install + profile
    # gating (default / paranoid) the resolver enforces;
    # malformed manifest wedges the journald retention baseline.
    # Python's tomllib is the canonical parser. Locks anti-
    # malformed-manifest on the journal-tune substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/journal-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'journal-tune', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: journal-tune installer NEVER deletes operator-pre-existing journald configs — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # journal-tune writes its own /etc/systemd/journald.conf.d/
    # drop-in; it MUST NEVER rm/find-delete an operator's
    # pre-existing /etc/systemd/journald.conf or journald.conf.d
    # entries not owned by THIS module. Locks no-auto-delete on
    # the journal-tune installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/journal-tune/install"
    for f in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${f}" ] || continue
        ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+/etc/systemd/journald\.conf' "${f}"
        ! grep -qE 'find[[:space:]]+/etc/systemd/journald.*-delete' "${f}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # journal-tune install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the journal-tune lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/journal-tune/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}
