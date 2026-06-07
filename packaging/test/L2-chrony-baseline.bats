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

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on chrony-baseline installer
    # surface across drop-in + reload phases.
    write_config "pool"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"chrony-baseline"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no auto-uninstall: chrony-baseline NEVER emits package-remove commands on chrony/ntp)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The chrony-baseline installer writes a chrony
    # drop-in pinning operator-curated NTP sources but MUST
    # NEVER emit shell commands that uninstall the chrony or
    # ntp package itself (apt/dpkg/dnf/rpm/yum remove|purge|
    # uninstall chrony|ntp|ntpsec|ntpd). Silent auto-removal
    # would leave the host with no time-sync substrate —
    # degrading every downstream defense that depends on
    # accurate timestamps (audit trails, certificate validation,
    # Kerberos, JWT expiration, time-window-based detection).
    # Locks anti-package-removal contract on the chrony NTP
    # substrate.
    write_config "pool"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(chrony|ntp|ntpsec|ntpd)'
    drop_in="${CHRONY_DROPIN_DIR}/50-selfdef.conf"
    [ ! -f "${drop_in}" ] || ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${drop_in}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. The chrony-baseline module.toml declares the install
    # contract + requires (chronyd, systemctl, awk) that the
    # dependency-resolver enforces at install-time. A malformed
    # manifest would break the resolver + leave the chrony
    # drop-in install wedged. Python's tomllib is the canonical
    # parser — must parse to a dict with the canonical top-level
    # keys (name, version, install). Locks anti-malformed-
    # manifest on the chrony-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/chrony-baseline/module.toml"
    python3 -c "
import tomllib, sys
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'chrony-baseline', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: chrony-baseline installer NEVER deletes operator-pre-existing chrony.conf — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # chrony-baseline writes its own /etc/chrony/conf.d drop-in;
    # it MUST NEVER rm/find-delete an operator's /etc/chrony/
    # chrony.conf or chrony.d/* not owned by THIS module. Locks
    # no-auto-delete on the chrony-baseline installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/chrony-baseline/install"
    for f in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${f}" ] || continue
        ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+/etc/chrony/chrony\.conf' "${f}"
        ! grep -qE 'find[[:space:]]+/etc/chrony.*-delete' "${f}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # chrony-baseline install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the chrony-baseline lifecycle
    # substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/chrony-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list ([] or ["a", "b"]) — not a comma-separated
    # string like "a, b" which TOML's tomllib would silently
    # accept as a single-element list ["a, b"]. The resolver
    # would then look for a single module named literally "a, b"
    # and fail to find it. Locks list-vs-string discipline on
    # the depends_on field of the chrony-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/chrony-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('depends_on', [])
assert isinstance(v, list), f'depends_on must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml conflicts field is a TOML list — anti-string-malformation contract on conflicts)" {
    # Sister to brain-wide module.toml manifest-completeness +
    # depends_on-list INVARIANTs already locked. The conflicts
    # field MUST be a TOML list — the resolver iterates
    # conflicts to detect mutually-exclusive module pairs at
    # install-time. A scalar/string would silently parse as a
    # single-element list, masking real conflicts. Locks list-
    # vs-string discipline on the conflicts field of the
    # chrony-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/chrony-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('conflicts', [])
assert isinstance(v, list), f'conflicts must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml provides field is a TOML list — anti-string-malformation contract on provides)" {
    # Sister to brain-wide module.toml manifest-completeness +
    # depends_on-list + conflicts-list INVARIANTs already
    # locked. The provides field MUST be a TOML list — the
    # resolver iterates it to register each provided contract
    # in the consumer-binding graph. A scalar would silently
    # parse as a single-element list, masking real provides.
    # Locks list-vs-string discipline on the provides field of
    # the chrony-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/chrony-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('provides', [])
assert isinstance(v, list), f'provides must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml requires field is a TOML list — anti-string-malformation contract on requires)" {
    # Sister to brain-wide module.toml list-vs-string family.
    # Locks list discipline on requires.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/chrony-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('requires', [])
assert isinstance(v, list), f'requires must be list, got {type(v).__name__}'
"
}
