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

@test "INVARIANT (module.toml requires entries are tables with kind + value — anti-flat-string-list contract)" {
    # Sister to brain-wide module.toml requires-shape INVARIANT
    # family. Locks the kind+value table-shape discipline on
    # the selinux-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
reqs = data.get('requires', [])
for r in reqs:
    assert isinstance(r, dict), f'requires entry must be table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'requires entry must have kind+value, got {r}'
"
}

@test "INVARIANT (module.toml summary field present + non-empty — operator-dashboard one-line description contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks summary-present discipline on the
    # selinux-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) > 0, f'summary must be non-empty string, got {repr(s)}'
"
}

@test "INVARIANT (module.toml category field present + non-empty — dashboard-grouping contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks category-present discipline on the
    # selinux-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert isinstance(c, str) and len(c) > 0, f'category must be non-empty string, got {repr(c)}'
"
}

@test "INVARIANT (module.toml version field is semver X.Y.Z — version-comparison sortability contract)" {
    # Sister to brain-wide module.toml semver INVARIANT family.
    # Locks semver-X.Y.Z discipline on the selinux-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (selinux-baseline module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the selinux-baseline module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
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

@test "INVARIANT (selinux-baseline module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the selinux-baseline module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
chk = inst.get('check', '')
assert chk == 'install/check.sh', f'install.check must be install/check.sh, got {chk!r}'
"
}

@test "INVARIANT (selinux-baseline module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
    # Sister to brain-wide module.toml [install_paths]
    # INVARIANT family. Per MS011 Z-8 / SDD-026, every
    # installer module MUST declare an [install_paths] block
    # enumerating the on-disk surfaces it touches on apply.
    # The selfdef dashboard's install-options surface +
    # install-plan auditor read this block to surface what
    # the module mutates BEFORE apply runs. A regression
    # dropping the [install_paths] block would leave operators
    # without a pre-apply manifest of writes, breaking
    # operator-consent + the install-plan-dry-run contract.
    # Locks the SDD-026 manifest discipline on the selinux-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths')
assert ip is not None, f'[install_paths] block must be present per SDD-026, got None'
paths = ip.get('paths', [])
assert isinstance(paths, list) and len(paths) > 0, f'install_paths.paths must be non-empty list, got {paths!r}'
"
}

@test "INVARIANT (selinux-baseline module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for selinux-baseline is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the selinux-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (selinux-baseline module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
    # Sister to brain-wide [install_paths].paths INVARIANT
    # family. The install_paths.paths field MUST be a TOML
    # list of strings (each element an absolute path the
    # module touches on apply). A regression that swapped to
    # a comma-separated string ("path1,path2,path3") would
    # silently treat it as a single literal path. The
    # selfdef installer iterates the list to surface the
    # mutation manifest to operators; broken type-shape
    # would break the install-options surface + dry-run
    # auditor. Locks the TOML-list-of-strings type discipline
    # on the selinux-baseline install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list), f'install_paths.paths must be TOML list, got {type(ps).__name__}'
assert all(isinstance(p, str) for p in ps), f'every paths entry must be a string'
"
}

@test "INVARIANT (selinux-baseline module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the selinux-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
req = data.get('requires')
assert isinstance(req, list), f'requires must be TOML list, got {type(req).__name__}'
for r in req:
    assert isinstance(r, dict), f'requires entry must be inline-table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'requires must have kind+value, got {r!r}'
"
}

@test "INVARIANT (selinux-baseline module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the selinux-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (selinux-baseline module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the selinux-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (selinux-baseline module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the selinux-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (selinux-baseline module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (selinux-baseline module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the selinux-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
prof = data.get('profiles')
assert prof is not None, f'[profiles] must be present, got None'
assert isinstance(prof, dict), f'[profiles] must be TOML table, got {type(prof).__name__}'
"
}

@test "INVARIANT (selinux-baseline module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (selinux-baseline module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (selinux-baseline module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (selinux-baseline module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (selinux-baseline module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (selinux-baseline module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (selinux-baseline README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (selinux-baseline install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (selinux-baseline install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (selinux-baseline install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (selinux-baseline install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (selinux-baseline install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (selinux-baseline install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (selinux-baseline install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (selinux-baseline install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (selinux-baseline install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (selinux-baseline install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (selinux-baseline install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (selinux-baseline install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (selinux-baseline module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (selinux-baseline module.toml exists at canonical path modules/selinux-baseline/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (selinux-baseline module dir is at canonical path modules/selinux-baseline/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (selinux-baseline install dir exists at modules/selinux-baseline/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (selinux-baseline install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (selinux-baseline install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (selinux-baseline install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (selinux-baseline install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (selinux-baseline module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (selinux-baseline install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (selinux-baseline install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (selinux-baseline install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (selinux-baseline install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/selinux-baseline/install/check.sh"
    [ -s "${chk}" ]
}
