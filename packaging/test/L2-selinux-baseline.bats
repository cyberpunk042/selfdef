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
