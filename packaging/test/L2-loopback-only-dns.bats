#!/usr/bin/env bats
# L2 functional suite for loopback-only-dns.
#
# loopback-only-dns installs /etc/systemd/resolved.conf.d/
# 50-selfdef-loopback.conf to bind systemd-resolved's DNS-stub
# listener to loopback only (preventing the host from exposing
# a DNS resolver on its public/LAN interfaces — a classic
# off-host DNS-attack vector).
#
# Profiles:
#   loopback           → DNSStubListener=yes + bind to 127.0.0.53
#                        (mainstream secure default — apps using
#                        /etc/resolv.conf still get resolution)
#   disabled-listener  → DNSStubListener=no (no DNS stub at all;
#                        apps must use /run/systemd/resolve/resolv.conf
#                        or a local resolver directly)
#
# Idempotency: drop-in is installed via cmp -s against source so a
# byte-identical re-install does NOT trigger systemctl restart of
# resolved (which would briefly interrupt name resolution).
#
# Run with: bats packaging/test/L2-loopback-only-dns.bats

WD="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/install/apply.sh"

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
    CONF="${TMP}/loopback-only-dns.toml"
    DROPIN_DIR="${TMP}/resolved.conf.d"
    DST="${DROPIN_DIR}/50-selfdef-loopback.conf"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_LOOPBACK_DNS_CONFIG="${CONF}" \
    SELFDEF_RESOLVED_DROPIN_DIR="${DROPIN_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_LOOPBACK_DNS_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_LOOPBACK_DNS_CONFIG="${SELFDEF_LOOPBACK_DNS_CONFIG}" \
        SELFDEF_RESOLVED_DROPIN_DIR="${DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_LOOPBACK_DNS_CONFIG="${CONF}" \
        SELFDEF_RESOLVED_DROPIN_DIR="${DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be loopback|disabled-listener"* ]]
}

@test "loopback profile installs drop-in with DNSStubListener=yes + binding to 127.0.0.53" {
    write_config "loopback"
    run_wd
    [ -f "${DST}" ]
    grep -qE '^DNSStubListener=yes' "${DST}"
    grep -q '127.0.0.53' "${DST}"
}

@test "disabled-listener profile installs drop-in with DNSStubListener=no" {
    write_config "disabled-listener"
    run_wd
    [ -f "${DST}" ]
    grep -qE '^DNSStubListener=no' "${DST}"
}

@test "drop-in is chmod 0644 (system-config convention)" {
    write_config "loopback"
    run_wd
    [ "$(stat -c '%a' "${DST}")" = "644" ]
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite drop-in OR restart resolved" {
    write_config "loopback"
    run_wd
    [ -f "${DST}" ]
    mtime_before="$(stat -c '%Y' "${DST}")"
    : > "${SYSEOF_LOG}"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DST}")"
    [ "${mtime_before}" = "${mtime_after}" ]
    # Resolved restart is gated on content-change — no restart on no-op.
    ! grep -q 'restart systemd-resolved' "${SYSEOF_LOG}"
}

@test "INVARIANT: profile switch loopback → disabled-listener REWRITES the drop-in AND restarts resolved" {
    write_config "loopback"
    run_wd
    sha_before="$(sha256sum "${DST}" | awk '{print $1}')"
    : > "${SYSEOF_LOG}"
    write_config "disabled-listener"
    run_wd
    sha_after="$(sha256sum "${DST}" | awk '{print $1}')"
    [ "${sha_before}" != "${sha_after}" ]
    grep -q 'restart systemd-resolved' "${SYSEOF_LOG}"
}

@test "INVARIANT: first install triggers resolved restart (live config picked up)" {
    write_config "loopback"
    run_wd
    grep -q 'restart systemd-resolved' "${SYSEOF_LOG}"
}

@test "INVARIANT: DRY_RUN does not write drop-in or restart resolved" {
    write_config "loopback"
    DRY_RUN=1 run_wd
    ! [ -f "${DST}" ]
    ! grep -q 'restart systemd-resolved' "${SYSEOF_LOG}"
}

@test "default profile is loopback (no profile key — conservative bind-to-127.0.0.53 default)" {
    : > "${CONF}"
    run_wd
    [ -f "${DST}" ]
    grep -qE '^DNSStubListener=yes' "${DST}"
}

@test "emit_status reports changes count (1 on first install, 0 on idempotent re-apply)" {
    write_config "loopback"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'changes=1'* ]]
    # Second apply is a no-op.
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'changes=0'* ]]
}
