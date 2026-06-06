#!/usr/bin/env bats
# L2 functional suite for sysctl-network-baseline.
#
# sysctl-network-baseline installs /etc/sysctl.d/50-selfdef-
# network-baseline.conf with classic network-hardening sysctls
# and runs sysctl --load to apply live. The kernel knobs block:
#   - ICMP redirect acceptance (route-poisoning)
#   - Source routing (network-path attacker control)
#   - Martian packets (forged-source IP filtering)
#   - SYN cookies (SYN-flood resistance)
#
# Profiles:
#   baseline → endpoint defaults (block redirects + source-route
#              + martians + enable SYN cookies)
#   router   → endpoint baseline + enable IPv4/IPv6 forwarding
#              (for hosts intentionally routing traffic)
#   paranoid → endpoint baseline + ignore ICMP echo + disable
#              IPv6 entirely (highest restriction)
#
# Adds SELFDEF_SYSCTL_NETWORK_DROPIN env-var (added 2026-06-06)
# for L2 testability.
#
# Run with: bats packaging/test/L2-sysctl-network-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/sysctl-network-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/sysctl" <<'SCEOF'
#!/usr/bin/env bash
printf 'sysctl %s\n' "$*" >> "${SCTL_LOG}"
exit 0
SCEOF
    chmod +x "${BIN}/sysctl"
    export SCTL_LOG="${TMP}/sysctl.log"
    : > "${SCTL_LOG}"
    CONF="${TMP}/sysctl-network-baseline.toml"
    DROPIN="${TMP}/50-selfdef-network-baseline.conf"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SCTL_LOG="${SCTL_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_SYSCTL_NETWORK_CONFIG="${CONF}" \
    SELFDEF_SYSCTL_NETWORK_DROPIN="${DROPIN}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_SYSCTL_NETWORK_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_SYSCTL_NETWORK_CONFIG="${SELFDEF_SYSCTL_NETWORK_CONFIG}" \
        SELFDEF_SYSCTL_NETWORK_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_SYSCTL_NETWORK_CONFIG="${CONF}" \
        SELFDEF_SYSCTL_NETWORK_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be baseline|router|paranoid"* ]]
}

@test "baseline profile installs drop-in with the classic endpoint hardening sysctls" {
    write_config "baseline"
    run_wd
    [ -f "${DROPIN}" ]
    # Header + profile marker.
    grep -q 'managed-by: selfdef sysctl-network-baseline' "${DROPIN}"
    grep -q 'profile=baseline' "${DROPIN}"
    # Classic hardening keys.
    grep -q 'accept_redirects' "${DROPIN}"
    grep -q 'accept_source_route' "${DROPIN}"
    grep -q 'rp_filter' "${DROPIN}"
    grep -q 'tcp_syncookies' "${DROPIN}"
}

@test "router profile installs drop-in with IPv4/IPv6 forwarding enabled" {
    write_config "router"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'ip_forward' "${DROPIN}"
    # Still has SYN cookies + redirect blocking.
    grep -q 'tcp_syncookies' "${DROPIN}"
    grep -q 'accept_redirects' "${DROPIN}"
}

@test "paranoid profile installs drop-in with ICMP echo ignore + IPv6 disabled" {
    write_config "paranoid"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'icmp_echo_ignore' "${DROPIN}"
    grep -q 'disable_ipv6' "${DROPIN}"
}

@test "drop-in is chmod 0644 (system-config convention)" {
    write_config "baseline"
    run_wd
    [ "$(stat -c '%a' "${DROPIN}")" = "644" ]
}

@test "drop-in carries header marker + profile + source-ref (no timestamp — defeats cmp -s)" {
    write_config "baseline"
    run_wd
    grep -q 'managed-by: selfdef sysctl-network-baseline' "${DROPIN}"
    grep -q 'profile=baseline' "${DROPIN}"
    grep -q 'Source: modules/sysctl-network-baseline/configs/baseline.conf' "${DROPIN}"
    # Anti-timestamp invariant: no '# Generated <ISO-date>' line —
    # rendering one defeats cmp -s idempotency (2026-06-06 sweep).
    ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "${DROPIN}"
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite drop-in (2026-06-06 idempotency fix)" {
    write_config "baseline"
    run_wd
    mtime_before="$(stat -c '%Y' "${DROPIN}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DROPIN}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: DRY_RUN does not write drop-in or fire sysctl --load" {
    write_config "baseline"
    DRY_RUN=1 run_wd
    ! [ -f "${DROPIN}" ]
    ! grep -q 'sysctl --load' "${SCTL_LOG}"
}

@test "default profile is baseline (no profile key — the endpoint default)" {
    : > "${CONF}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'profile=baseline' "${DROPIN}"
    ! grep -q 'ip_forward' "${DROPIN}"      # router-only
}

@test "INVARIANT (baseline tcp_syncookies = 1): the actual SYN-flood resistance" {
    write_config "baseline"
    run_wd
    grep -qE 'net\.ipv4\.tcp_syncookies\s*=\s*1' "${DROPIN}"
}

@test "INVARIANT (baseline accept_redirects = 0): block ICMP route-poisoning" {
    write_config "baseline"
    run_wd
    grep -qE 'accept_redirects\s*=\s*0' "${DROPIN}"
}

@test "INVARIANT (baseline accept_source_route = 0): block network-path attacker control" {
    write_config "baseline"
    run_wd
    grep -qE 'accept_source_route\s*=\s*0' "${DROPIN}"
}

@test "INVARIANT (baseline rp_filter = 1 or 2): reverse-path filter on (block martians)" {
    write_config "baseline"
    run_wd
    grep -qE 'rp_filter\s*=\s*[12]' "${DROPIN}"
}

@test "INVARIANT (profile transition baseline → router): rewrites drop-in with ip_forward enabled" {
    write_config "baseline"
    run_wd
    ! grep -qE 'ip_forward\s*=\s*1' "${DROPIN}"
    write_config "router"
    run_wd
    grep -qE 'ip_forward\s*=\s*1' "${DROPIN}"
}

@test "INVARIANT (sysctl --load fires on EVERY apply — even when drop-in idempotent-unchanged)" {
    # Operator could have manually flipped a knob; live re-apply ensures
    # the kernel state matches the drop-in.
    write_config "baseline"
    run_wd
    : > "${SCTL_LOG}"
    run_wd
    grep -qE 'sysctl --(load|system|p)' "${SCTL_LOG}"
}
