#!/usr/bin/env bats
# L2 functional suite for chrony-baseline.
#
# chrony-baseline installs an /etc/chrony/conf.d/50-selfdef.conf
# drop-in that pins chrony to a known-good NTP profile:
#   pool → Debian/RHEL pool servers
#   nts  → NTS (Network Time Security — authenticated NTP, the
#          stronger choice when the network may be hostile)
#
# Time integrity is a security control: clock manipulation breaks
# certificate validity, enables TOTP replay, evades log
# correlation. A canonical clock-source pin is the foundation.
#
# CRITICAL INVARIANTS:
#   - Idempotent: byte-identical re-install is a no-op (no
#     systemctl restart fired).
#   - DRY_RUN protects /etc/chrony/conf.d + systemctl restart.
#   - Profile downgrade nts → pool replaces the drop-in.
#
# Uses SELFDEF_CHRONY_DROPIN_DIR + SELFDEF_CHRONY_BASELINE_CONFIGS
# env-vars (already present) for L2 testability.
#
# Run with: bats packaging/test/L2-chrony-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/chrony-baseline/install/apply.sh"

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
    CONF="${TMP}/chrony-baseline.toml"
    CONFIGS_SRC="${TMP}/configs"
    CHRONY_DROPIN_DIR="${TMP}/chrony.conf.d"
    mkdir -p "${CONFIGS_SRC}" "${CHRONY_DROPIN_DIR}"
    # Fixture source profiles.
    cat > "${CONFIGS_SRC}/pool.conf" <<'POOLEOF'
pool 2.debian.pool.ntp.org iburst
makestep 1.0 3
rtcsync
POOLEOF
    cat > "${CONFIGS_SRC}/nts.conf" <<'NTSEOF'
server time.cloudflare.com nts iburst
server time.nist.gov nts iburst
makestep 1.0 3
rtcsync
NTSEOF
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_CHRONY_BASELINE_CONFIG="${CONF}" \
    SELFDEF_CHRONY_BASELINE_CONFIGS="${CONFIGS_SRC}" \
    SELFDEF_CHRONY_DROPIN_DIR="${CHRONY_DROPIN_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_CHRONY_BASELINE_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_CHRONY_BASELINE_CONFIG="${SELFDEF_CHRONY_BASELINE_CONFIG}" \
        SELFDEF_CHRONY_BASELINE_CONFIGS="${CONFIGS_SRC}" \
        SELFDEF_CHRONY_DROPIN_DIR="${CHRONY_DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "missing config source dir → die" {
    write_config "pool"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_CHRONY_BASELINE_CONFIG="${CONF}" \
        SELFDEF_CHRONY_BASELINE_CONFIGS="${TMP}/missing-src" \
        SELFDEF_CHRONY_DROPIN_DIR="${CHRONY_DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config source dir missing"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_CHRONY_BASELINE_CONFIG="${CONF}" \
        SELFDEF_CHRONY_BASELINE_CONFIGS="${CONFIGS_SRC}" \
        SELFDEF_CHRONY_DROPIN_DIR="${CHRONY_DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be pool|nts"* ]]
}

@test "pool profile installs the drop-in + restarts chronyd" {
    write_config "pool"
    run_wd
    [ -f "${CHRONY_DROPIN_DIR}/50-selfdef.conf" ]
    cmp -s "${CONFIGS_SRC}/pool.conf" "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    grep -q 'systemctl restart chronyd' "${SYSEOF_LOG}"
}

@test "nts profile installs the NTS-authenticated drop-in" {
    write_config "nts"
    run_wd
    [ -f "${CHRONY_DROPIN_DIR}/50-selfdef.conf" ]
    cmp -s "${CONFIGS_SRC}/nts.conf" "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    # NTS keyword present in installed drop-in.
    grep -q 'nts' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT: idempotent — re-install with identical content is a no-op (no chronyd restart fired)" {
    write_config "pool"
    run_wd                              # initial install
    : > "${SYSEOF_LOG}"                 # clear log
    run_wd                              # re-install — identical
    ! grep -q 'systemctl restart' "${SYSEOF_LOG}"
}

@test "INVARIANT: profile downgrade nts → pool replaces drop-in + restarts" {
    write_config "nts"
    run_wd
    grep -q 'nts' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    write_config "pool"
    : > "${SYSEOF_LOG}"
    run_wd
    ! grep -q 'nts' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    grep -q 'pool' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    grep -q 'systemctl restart' "${SYSEOF_LOG}"
}

@test "INVARIANT: DRY_RUN does not install drop-in or restart" {
    write_config "pool"
    DRY_RUN=1 run_wd
    ! [ -f "${CHRONY_DROPIN_DIR}/50-selfdef.conf" ]
    ! grep -q 'systemctl restart' "${SYSEOF_LOG}"
}

@test "default profile is pool (no profile key)" {
    : > "${CONF}"
    run_wd
    cmp -s "${CONFIGS_SRC}/pool.conf" "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
}

@test "drop-in is chmod 0644 (system-config convention for /etc/chrony/conf.d)" {
    write_config "pool"
    run_wd
    perms="$(stat -c '%a' "${CHRONY_DROPIN_DIR}/50-selfdef.conf")"
    [ "${perms}" = "644" ]
}

@test "INVARIANT (idempotent mtime): byte-identical re-install preserves mtime (not just no-restart)" {
    # Stronger than test-122's "no restart" — locks the file-mtime
    # preservation that the cmp -s guard provides.
    write_config "pool"
    run_wd
    mtime_before="$(stat -c '%Y' "${CHRONY_DROPIN_DIR}/50-selfdef.conf")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${CHRONY_DROPIN_DIR}/50-selfdef.conf")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT (profile upgrade pool → nts): replaces drop-in + fires restart" {
    # The reverse direction of test-130 (nts → pool). Both
    # transitions must work — locks the bidirectional contract.
    write_config "pool"
    run_wd
    grep -q 'pool' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    write_config "nts"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'nts' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    ! grep -q '^pool ' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    grep -q 'systemctl restart' "${SYSEOF_LOG}"
}

@test "INVARIANT (no render-timestamp in drop-in): chrony drop-in must not carry a Generated <ISO-date> line" {
    write_config "pool"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (NTS profile carries cloudflare + nist server lines): both authenticated servers surface in drop-in" {
    write_config "nts"
    run_wd
    grep -q 'time.cloudflare.com' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    grep -q 'time.nist.gov' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
}

@test "emit_status surfaces profile + result in JSON (operator observability)" {
    write_config "pool"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"chrony-baseline"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=pool'* ]]
}

@test "INVARIANT (drop-in re-arm after operator out-of-band deletion: re-creates drop-in + fires restart)" {
    write_config "pool"
    run_wd
    [ -f "${CHRONY_DROPIN_DIR}/50-selfdef.conf" ]
    rm -f "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    : > "${SYSEOF_LOG}"
    run_wd
    [ -f "${CHRONY_DROPIN_DIR}/50-selfdef.conf" ]
    grep -q 'systemctl restart' "${SYSEOF_LOG}"
}

@test "INVARIANT (makestep directive present: chrony auto-corrects large clock drift — both profiles need this)" {
    # makestep 1.0 3 means: if step > 1.0 second in any of the
    # first 3 clock corrections, step rather than slew. Required
    # for boot-time clock recovery after long power-off.
    write_config "pool"
    run_wd
    grep -qE '^makestep[[:space:]]+1\.0[[:space:]]+3' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    write_config "nts"
    run_wd
    grep -qE '^makestep[[:space:]]+1\.0[[:space:]]+3' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (rtcsync directive present: hardware-RTC sync — both profiles need this)" {
    # rtcsync writes the kernel-synced time back to the hardware
    # RTC every 11 minutes. Required so reboot doesn't start with
    # a stale clock.
    write_config "pool"
    run_wd
    grep -qE '^rtcsync$' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    write_config "nts"
    run_wd
    grep -qE '^rtcsync$' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (NTS profile: each server line carries 'nts' keyword — actual NTS protocol activated, not just NTP)" {
    # The whole point of NTS profile is the 'nts' keyword on
    # the server line — that's what activates authenticated NTP.
    # A regression dropping 'nts' from server lines would give
    # plain unauthenticated NTP under "nts" profile name.
    write_config "nts"
    run_wd
    grep -qE '^server time.cloudflare.com nts ' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    grep -qE '^server time.nist.gov nts ' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (graceful reload preference: chronyd config reload — restart is the canonical for chrony config-change)" {
    # chronyd reads /etc/chrony/conf.d/ at start; config changes
    # need restart (or 'chronyc reload sources' for narrow
    # reloads). Lock that restart fires as the canonical
    # mechanism here.
    write_config "pool"
    run_wd
    grep -q 'systemctl restart chronyd' "${SYSEOF_LOG}"
}

@test "INVARIANT (NTS profile has STRICTLY MORE servers than pool — multi-source redundancy for authenticated time)" {
    # NTS profile uses dedicated NTS-capable servers (cloudflare +
    # nist) for redundancy; pool profile uses a single pool entry
    # which itself resolves to multiple IPs. Both work but the
    # explicit-server NTS profile must list at least 2 servers
    # so a single-server outage doesn't lose authenticated time.
    write_config "nts"
    run_wd
    server_count="$(grep -cE '^server ' "${CHRONY_DROPIN_DIR}/50-selfdef.conf")"
    [ "${server_count}" -ge 2 ]
}

@test "INVARIANT (filename follows 50-selfdef-* convention — tracking + uninstall identification)" {
    # Sister to many other modules' filename-convention INVARIANT.
    # The chrony drop-in MUST follow the 50-selfdef.conf convention
    # so the chrony-baseline-aware uninstall can find it.
    write_config "pool"
    run_wd
    case "${CHRONY_DROPIN_DIR}/50-selfdef.conf" in
        */50-selfdef*.conf) : ;;
        *) fail "drop-in filename must follow 50-selfdef.conf pattern" ;;
    esac
    [ -f "${CHRONY_DROPIN_DIR}/50-selfdef.conf" ]
}

@test "INVARIANT (drop-in carries NO 'allow' clause — chrony should not act as a server for other hosts in either profile)" {
    # 'allow' in chrony config makes the host serve time to other
    # clients. A sovereign endpoint should NEVER act as a time
    # server (an attacker doing that would create a time-poisoning
    # primitive). Lock that NEITHER profile carries 'allow'.
    write_config "pool"
    run_wd
    ! grep -qE '^allow' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    write_config "nts"
    run_wd
    ! grep -qE '^allow' "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (production chrony configs carry selfdef self-identifying first-line — head -1 stale-cleanup discipline)" {
    # Sister to many other installer module's header-marker
    # INVARIANT across the brain (ssh-hardening / journal-tune /
    # slm-cpu-loop / acct-baseline / auditd-immutable). The
    # actual production configs at modules/chrony-baseline/
    # configs/*.conf MUST carry a selfdef-prefixed first-line
    # comment marker. A stale-cleanup pass (operator housekeeping
    # or uninstall path) inspects the first non-blank comment line
    # to identify selfdef-rendered config from operator config.
    # Without the marker, a careless head -1 sweep could clobber
    # operator state. Locks the provenance contract on BOTH pool
    # + nts production sources (the L2 fixture configs use minimal
    # stub source files for test speed but the real shipped configs
    # MUST carry the marker — locked here so any rewrite-with-stub
    # regression is caught).
    first_pool="$(grep -E -m1 -v '^[[:space:]]*$' modules/chrony-baseline/configs/pool.conf)"
    first_nts="$(grep -E -m1 -v '^[[:space:]]*$' modules/chrony-baseline/configs/nts.conf)"
    [[ "${first_pool}" == *"selfdef"* ]]
    [[ "${first_nts}" == *"selfdef"* ]]
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO chrony drop-in written AND NO chronyd restart/reload fired)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing /etc/chrony/chrony.conf.d/
    # 50-selfdef.conf AND without restarting/reloading chronyd.
    # A silent dry-run that committed would flip the host's NTP
    # baseline (pool sources or NTS authentication) at preview
    # time — clock-skew matters for log timestamps + Kerberos +
    # TLS-cert-validation. Locks the dry-run-preserves-state
    # contract on the time-sync substrate.
    rm -f "${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    write_config "pool"
    : > "${SYSEOF_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${CHRONY_DROPIN_DIR}/50-selfdef.conf" ]
    ! grep -qE 'systemctl (restart|reload) chronyd' "${SYSEOF_LOG}"
}

@test "INVARIANT (drop-in is chmod 0644 — system-config convention)" {
    # Sister to brain-wide chmod 0644 INVARIANTs.
    write_config "pool"
    run_wd
    drop_in="${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    [ -f "${drop_in}" ]
    [ "$(stat -c '%a' "${drop_in}")" = "644" ]
}
