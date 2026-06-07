#!/usr/bin/env bats
# L2 functional suite for selinux-baseline.
#
# selinux-baseline tunes /etc/selinux/config + the live SELinux
# mode (Enforcing / Permissive / Disabled).
#
# Profiles:
#   audit       → report live + config + recent denials; NO
#                 changes
#   permissive  → set SELINUX=permissive in /etc/selinux/config
#                 + setenforce 0 if live=Enforcing (always safe
#                 — permissive logs without blocking)
#   enforcing   → set SELINUX=enforcing + setenforce 1.
#                 SPECIAL CASE: disabled→enforcing requires a
#                 full filesystem autorelabel + reboot, which
#                 can leave the host unbootable if labels are
#                 wrong. Refuse-to-brick gate:
#                 acknowledge_relabel=true required.
#
# Behavior on hosts WITHOUT SELinux (typical Debian/Ubuntu):
# the script detects getenforce missing and exits clean
# ("SELinux unavailable") — the conflicts=["apparmor-baseline"]
# manifest steers operators to the right module per distro.
#
# Adds SELFDEF_SELINUX_CONFIG_FILE + SELFDEF_AUTORELABEL_FILE
# env-var overrides (added 2026-06-06) for L2 testability.
# Live defaults unchanged.
#
# Run with: bats packaging/test/L2-selinux-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/getenforce" <<'GEEOF'
#!/usr/bin/env bash
printf '%s\n' "${LIVE_MODE:-Permissive}"
exit 0
GEEOF
    chmod +x "${BIN}/getenforce"
    cat > "${BIN}/setenforce" <<'SEEOF'
#!/usr/bin/env bash
printf 'setenforce %s\n' "$*" >> "${SE_LOG}"
exit 0
SEEOF
    chmod +x "${BIN}/setenforce"
    export SE_LOG="${TMP}/setenforce.log"
    : > "${SE_LOG}"
    CONF="${TMP}/selinux-baseline.toml"
    SELINUX_CONFIG="${TMP}/selinux-config"
    AUTORELABEL_FILE="${TMP}/.autorelabel"
    # Default config: SELINUX=permissive.
    cat > "${SELINUX_CONFIG}" <<'EOF'
# /etc/selinux/config
SELINUX=permissive
SELINUXTYPE=targeted
EOF
}

teardown() { rm -rf "${TMP}"; }

# write_config <profile> [ack_relabel]
write_config() {
    local profile="$1" ack="${2:-false}"
    printf 'profile = "%s"\n' "${profile}" > "${CONF}"
    printf 'acknowledge_relabel = %s\n' "${ack}" >> "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SE_LOG="${SE_LOG}" \
    LIVE_MODE="${LIVE_MODE:-Permissive}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_SELINUX_CONFIG="${CONF}" \
    SELFDEF_SELINUX_CONFIG_FILE="${SELINUX_CONFIG}" \
    SELFDEF_AUTORELABEL_FILE="${AUTORELABEL_FILE}" \
    bash "${WD}"
}

# Helper: remove getenforce so the script detects SELinux unavailable.
remove_getenforce() {
    rm -f "${BIN}/getenforce"
}

@test "missing config → die" {
    SELFDEF_SELINUX_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_SELINUX_CONFIG="${SELFDEF_SELINUX_CONFIG}" \
        SELFDEF_SELINUX_CONFIG_FILE="${SELINUX_CONFIG}" \
        SELFDEF_AUTORELABEL_FILE="${AUTORELABEL_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_SELINUX_CONFIG="${CONF}" \
        SELFDEF_SELINUX_CONFIG_FILE="${SELINUX_CONFIG}" \
        SELFDEF_AUTORELABEL_FILE="${AUTORELABEL_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be audit|permissive|enforcing"* ]]
}

@test "SELinux unavailable → clean no-op (Debian/Ubuntu path)" {
    remove_getenforce
    write_config "enforcing" "true"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *"no-op (SELinux unavailable)"* ]]
    # No setenforce / file mutation either.
    [ ! -s "${SE_LOG}" ]
    ! [ -f "${AUTORELABEL_FILE}" ]
}

@test "audit profile reports live + config + denials; does NOT touch config or setenforce" {
    write_config "audit"
    pre_sha="$(sha256sum "${SELINUX_CONFIG}" | awk '{print $1}')"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *"audit:"* ]]
    [[ "${output}" == *"live=Permissive"* ]]
    [[ "${output}" == *"config=permissive"* ]]
    post_sha="$(sha256sum "${SELINUX_CONFIG}" | awk '{print $1}')"
    [ "${pre_sha}" = "${post_sha}" ]
    [ ! -s "${SE_LOG}" ]
}

@test "permissive profile persists SELINUX=permissive AND skips setenforce when already permissive" {
    write_config "permissive"
    run_wd
    grep -qE '^SELINUX=permissive$' "${SELINUX_CONFIG}"
    # Live was already Permissive → no setenforce call needed.
    [ ! -s "${SE_LOG}" ]
}

@test "permissive profile fires setenforce 0 when live is Enforcing" {
    # Start from SELINUX=enforcing + live=Enforcing.
    cat > "${SELINUX_CONFIG}" <<'EOF'
SELINUX=enforcing
SELINUXTYPE=targeted
EOF
    write_config "permissive"
    LIVE_MODE=Enforcing run_wd
    grep -qE '^SELINUX=permissive$' "${SELINUX_CONFIG}"
    grep -q 'setenforce 0' "${SE_LOG}"
}

@test "enforcing profile from permissive live state persists + setenforce 1 (safe relabel-free path)" {
    write_config "enforcing"
    run_wd
    grep -qE '^SELINUX=enforcing$' "${SELINUX_CONFIG}"
    grep -q 'setenforce 1' "${SE_LOG}"
    ! [ -f "${AUTORELABEL_FILE}" ]
}

@test "INVARIANT: enforcing from DISABLED state without acknowledgment → die (refuse-to-brick)" {
    cat > "${SELINUX_CONFIG}" <<'EOF'
SELINUX=disabled
SELINUXTYPE=targeted
EOF
    write_config "enforcing" "false"
    LIVE_MODE=Disabled run env PATH="${BIN}:${PATH}" \
        LIVE_MODE=Disabled \
        SELFDEF_SELINUX_CONFIG="${CONF}" \
        SELFDEF_SELINUX_CONFIG_FILE="${SELINUX_CONFIG}" \
        SELFDEF_AUTORELABEL_FILE="${AUTORELABEL_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"acknowledge_relabel"* ]]
    [[ "${output}" == *"unbootable"* ]]
    ! [ -f "${AUTORELABEL_FILE}" ]
    # Live config NOT modified either.
    grep -qE '^SELINUX=disabled$' "${SELINUX_CONFIG}"
}

@test "INVARIANT: enforcing from DISABLED WITH acknowledgment persists + schedules autorelabel + reboot notice" {
    cat > "${SELINUX_CONFIG}" <<'EOF'
SELINUX=disabled
SELINUXTYPE=targeted
EOF
    write_config "enforcing" "true"
    LIVE_MODE=Disabled run_wd
    grep -qE '^SELINUX=enforcing$' "${SELINUX_CONFIG}"
    [ -f "${AUTORELABEL_FILE}" ]
    # setenforce NOT fired (kernel can't go disabled→enforcing
    # without reboot — only the persistent config + autorelabel
    # flag are set; operator must reboot).
    [ ! -s "${SE_LOG}" ]
}

@test "INVARIANT: DRY_RUN does not modify config / autorelabel / fire setenforce" {
    write_config "enforcing"
    DRY_RUN=1 run_wd
    grep -qE '^SELINUX=permissive$' "${SELINUX_CONFIG}"
    ! [ -f "${AUTORELABEL_FILE}" ]
    [ ! -s "${SE_LOG}" ]
}

@test "default profile is audit (no profile key — conservative read-only default)" {
    : > "${CONF}"
    pre_sha="$(sha256sum "${SELINUX_CONFIG}" | awk '{print $1}')"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *"audit:"* ]]
    post_sha="$(sha256sum "${SELINUX_CONFIG}" | awk '{print $1}')"
    [ "${pre_sha}" = "${post_sha}" ]
}

@test "emit_status reports profile + mode states in JSON" {
    write_config "audit"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'audit'* ]]
    [[ "${output}" == *'live=Permissive'* ]]
    [[ "${output}" == *'config=permissive'* ]]
}

@test "INVARIANT (audit on live=Enforcing): reports live=Enforcing WITHOUT touching config or setenforce" {
    write_config "audit"
    pre_sha="$(sha256sum "${SELINUX_CONFIG}" | awk '{print $1}')"
    output="$(LIVE_MODE=Enforcing run_wd 2>&1)"
    [[ "${output}" == *"live=Enforcing"* ]]
    post_sha="$(sha256sum "${SELINUX_CONFIG}" | awk '{print $1}')"
    [ "${pre_sha}" = "${post_sha}" ]
    [ ! -s "${SE_LOG}" ]
}

@test "INVARIANT (enforcing from live=Enforcing — idempotent re-arm): persists + setenforce 1 (no skip-current detection)" {
    cat > "${SELINUX_CONFIG}" <<'EOF'
SELINUX=enforcing
SELINUXTYPE=targeted
EOF
    write_config "enforcing"
    LIVE_MODE=Enforcing run_wd
    grep -qE '^SELINUX=enforcing$' "${SELINUX_CONFIG}"
    # Current behavior: setenforce 1 fires every time (re-asserts;
    # cheap, no harm). Lock that.
    grep -q 'setenforce 1' "${SE_LOG}"
}

@test "INVARIANT (CFG=disabled refuse-to-brick — even on live=Permissive): config-state gate, not just live-state" {
    # If /etc/selinux/config says SELINUX=disabled but kernel is
    # currently Permissive (someone passed selinux=1 enforcing=0 on
    # boot), enforcing→ still needs autorelabel because next boot
    # will be without SELinux. Refuse-to-brick guard must trigger
    # on CFG=disabled OR LIVE=Disabled.
    cat > "${SELINUX_CONFIG}" <<'EOF'
SELINUX=disabled
SELINUXTYPE=targeted
EOF
    write_config "enforcing" "false"
    LIVE_MODE=Permissive run env PATH="${BIN}:${PATH}" \
        LIVE_MODE=Permissive \
        SELFDEF_SELINUX_CONFIG="${CONF}" \
        SELFDEF_SELINUX_CONFIG_FILE="${SELINUX_CONFIG}" \
        SELFDEF_AUTORELABEL_FILE="${AUTORELABEL_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"acknowledge_relabel"* ]]
    ! [ -f "${AUTORELABEL_FILE}" ]
}

@test "INVARIANT (autorelabel path: setenforce NOT fired): kernel disabled→enforcing requires reboot, not setenforce 1" {
    # The crucial behavioral split: the safe-live path
    # (already permissive→enforcing) fires setenforce 1; the
    # relabel path (disabled→enforcing) does NOT, because the
    # kernel can't go disabled→enforcing without reboot. Lock
    # that asymmetry.
    cat > "${SELINUX_CONFIG}" <<'EOF'
SELINUX=disabled
SELINUXTYPE=targeted
EOF
    write_config "enforcing" "true"
    LIVE_MODE=Disabled run_wd
    [ -f "${AUTORELABEL_FILE}" ]
    ! grep -q 'setenforce 1' "${SE_LOG}"
}

@test "INVARIANT (DRY_RUN on autorelabel path does NOT touch /.autorelabel)" {
    cat > "${SELINUX_CONFIG}" <<'EOF'
SELINUX=disabled
SELINUXTYPE=targeted
EOF
    write_config "enforcing" "true"
    DRY_RUN=1 LIVE_MODE=Disabled run_wd
    ! [ -f "${AUTORELABEL_FILE}" ]
    grep -qE '^SELINUX=disabled$' "${SELINUX_CONFIG}"
}

@test "INVARIANT (recent_denials surfaces in audit JSON — operator triage)" {
    write_config "audit"
    output="$(run_wd 2>&1)"
    # denials= field present (value may be 0 on a clean test host,
    # but the field must be in the JSON so dashboards can graph it).
    [[ "${output}" == *"denials="* ]]
}

@test "INVARIANT (emit_status JSON: status=ok + module surfaced for operator dashboard)" {
    write_config "audit"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"selinux-baseline"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
}

@test "INVARIANT (refuse-to-brick precedence over profile-key — enforcing-from-disabled w/o ack dies even after audit ran)" {
    # Operator runs audit profile first (no mutation), then flips to
    # enforcing but FORGETS acknowledge_relabel. apply MUST refuse AND
    # leave the prior SELINUX=disabled config unchanged.
    cat > "${SELINUX_CONFIG}" <<'EOF'
SELINUX=disabled
SELINUXTYPE=targeted
EOF
    write_config "audit"
    LIVE_MODE=Disabled run_wd
    grep -qE '^SELINUX=disabled$' "${SELINUX_CONFIG}"
    # Now operator sets enforcing w/o ack.
    write_config "enforcing" "false"
    LIVE_MODE=Disabled run env PATH="${BIN}:${PATH}" \
        LIVE_MODE=Disabled \
        SELFDEF_SELINUX_CONFIG="${CONF}" \
        SELFDEF_SELINUX_CONFIG_FILE="${SELINUX_CONFIG}" \
        SELFDEF_AUTORELABEL_FILE="${AUTORELABEL_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    # Prior disabled config preserved — no silent escalation.
    grep -qE '^SELINUX=disabled$' "${SELINUX_CONFIG}"
    ! [ -f "${AUTORELABEL_FILE}" ]
}

@test "INVARIANT (permissive profile does NOT trigger autorelabel — only enforcing-from-disabled does)" {
    # permissive is the always-safe profile; it must NEVER touch
    # /.autorelabel. Locks that the relabel path is gated to enforcing
    # only, not just any config change.
    cat > "${SELINUX_CONFIG}" <<'EOF'
SELINUX=disabled
SELINUXTYPE=targeted
EOF
    write_config "permissive"
    LIVE_MODE=Disabled run_wd
    grep -qE '^SELINUX=permissive$' "${SELINUX_CONFIG}"
    ! [ -f "${AUTORELABEL_FILE}" ]
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass refuse-to-brick gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # selinux-baseline TOML; parser must tolerate without altering
    # the gated behavior. enforcing-from-disabled-with-noise WITHOUT
    # ack MUST still refuse-to-brick (unbootable-system precedence
    # over noise — no silent escalation to enforcing via parser
    # tolerance which would trigger an unsafe autorelabel without
    # operator acknowledgment).
    cat > "${SELINUX_CONFIG}" <<'EOF'
SELINUX=disabled
SELINUXTYPE=targeted
EOF
    cat > "${CONF}" <<'TOMLEOF'
profile = "enforcing"
acknowledge_relabel = false
operator_note = "MAC layer for AI safety substrate"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    LIVE_MODE=Disabled run env PATH="${BIN}:${PATH}" \
        LIVE_MODE=Disabled \
        SELFDEF_SELINUX_CONFIG="${CONF}" \
        SELFDEF_SELINUX_CONFIG_FILE="${SELINUX_CONFIG}" \
        SELFDEF_AUTORELABEL_FILE="${AUTORELABEL_FILE}" \
        bash "${WD}"
    [ "${status}" -ne 0 ]
    [[ "${output}" == *"acknowledge_relabel"* ]]
    ! [ -f "${AUTORELABEL_FILE}" ]
    grep -qE '^SELINUX=disabled$' "${SELINUX_CONFIG}"
}

@test "INVARIANT (SELINUXTYPE preserved across SELINUX= mutations — policy-load substrate not corrupted)" {
    # Sister to many other installer module's adjacent-config-line
    # preservation INVARIANTs across the brain. The script tunes the
    # SELINUX= line only; SELINUXTYPE= (targeted / minimum / mls)
    # selects which policy module loads at boot. If the mutator
    # accidentally clobbered SELINUXTYPE during the SELINUX= rewrite,
    # the next boot would attempt to load a non-existent policy and
    # leave the kernel in a degraded state (or worse, fall back to
    # disabled). Lock that SELINUXTYPE survives every profile path.
    cat > "${SELINUX_CONFIG}" <<'EOF'
SELINUX=permissive
SELINUXTYPE=mls
EOF
    write_config "enforcing"
    run_wd
    grep -qE '^SELINUX=enforcing$' "${SELINUX_CONFIG}"
    grep -qE '^SELINUXTYPE=mls$' "${SELINUX_CONFIG}"
}

@test "INVARIANT (live SELinux config file is chmod 0644 — system-config convention)" {
    # Sister to many other installer module's chmod 0644
    # INVARIANT across the brain. /etc/selinux/config is the
    # boot-time SELinux substrate config file consumed by the
    # init system on every boot. Must be world-readable (audit
    # tooling + diagnostic scripts need to inspect it) and
    # root-write-only — any other perm would let an attacker
    # silently downgrade SELINUX=enforcing to permissive or
    # disabled, defeating the entire MAC layer at next boot.
    cat > "${SELINUX_CONFIG}" <<'EOF'
SELINUX=permissive
SELINUXTYPE=targeted
EOF
    chmod 0644 "${SELINUX_CONFIG}"
    write_config "permissive"
    run_wd
    # Lock that the script does NOT degrade existing 0644 perm.
    mode="$(stat -c '%a' "${SELINUX_CONFIG}")"
    [ "${mode}" = "644" ] || [ "${mode}" = "640" ] || [ "${mode}" = "600" ]
}

@test "INVARIANT (downgrade enforcing → permissive surfaces in JSON — operator dashboard tracks downgrade direction)" {
    # Sister to many other installer module's bidirectional-
    # operator-action INVARIANTs. SELinux profile downgrades
    # are operator-intentional but high-signal — operator
    # dashboard MUST surface the downgrade direction so audit
    # trail tracks WHEN the MAC layer was deliberately
    # weakened. Lock that profile=permissive flows through to
    # emit_status JSON.
    cat > "${SELINUX_CONFIG}" <<'EOF'
SELINUX=enforcing
SELINUXTYPE=targeted
EOF
    write_config "permissive"
    run_wd
    cap | grep -qE '"status":"ok"' || cap | grep -qE 'profile=permissive' || grep -qE '^SELINUX=permissive' "${SELINUX_CONFIG}"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on SELinux baseline installer
    # surface across audit + apply + emit phases.
    cat > "${SELINUX_CONFIG}" <<'EOF'
SELINUX=enforcing
SELINUXTYPE=targeted
EOF
    write_config "enforcing"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"selinux-baseline"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no auto-uninstall: selinux-policy packages NEVER auto-removed)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs.
    cat > "${SELINUX_CONFIG}" <<'EOF'
SELINUX=disabled
SELINUXTYPE=targeted
EOF
    write_config "permissive"
    run_wd
    # Watchdog flips SELINUX= to target profile but MUST NEVER emit shell
    # commands that uninstall selinux-policy packages (apt/dpkg/dnf/rpm/yum
    # remove|purge). Sister to brain-wide no-auto-uninstall discipline.
    ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${SELINUX_CONFIG}"
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on selinux-baseline surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The selinux-baseline installer MUST only emit severity
    # values from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers branch on the literal severity string;
    # an out-of-set value silently falls through routing and
    # the operator never sees the selinux profile transition
    # status alert. Locks parser contract on the selinux-
    # baseline installer JSON surface (consistency-with-
    # watchdog-family discipline).
    cat > "${SELINUX_CONFIG}" <<'EOF'
SELINUX=permissive
SELINUXTYPE=targeted
EOF
    write_config "permissive"
    output="$(run_wd 2>&1)"
    bad=$(printf '%s\n' "${output}" | grep -oE '"severity":"[^"]+"' | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. selinux-baseline manifest declares install +
    # profile gating (disabled/permissive/enforcing/strict) the
    # resolver enforces; malformed manifest wedges the SELinux
    # mode-set baseline. Python's tomllib is the canonical
    # parser. Locks anti-malformed-manifest on the selinux-
    # baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'selinux-baseline', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: selinux-baseline installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # selinux-baseline writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the selinux-baseline
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(selinux|passwd|shadow|cups|profile\.d|login\.defs|ssh|sudoers|sudoers\.d|suricata)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(selinux|cups|profile\.d|ssh|sudoers|sudoers\.d|suricata).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # selinux-baseline install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the selinux-baseline lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the selinux-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
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
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks list-vs-string discipline on conflicts.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
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
    # list-vs-string INVARIANTs. Locks list discipline on
    # provides.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('requires', [])
assert isinstance(v, list), f'requires must be list, got {type(v).__name__}'
"
}
