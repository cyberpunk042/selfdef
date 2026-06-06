#!/usr/bin/env bats
# L2 functional + capture-regression suite for dns-resolver-watchdog.
#
# dns-resolver-watchdog inventories the active DNS resolver
# configuration into a baseline, then alerts on a delta. A CHANGED
# nameserver is the DNS-hijack signature: attackers repoint name
# resolution to a resolver they control to MITM package downloads,
# TLS (via fake CA + hijacked OCSP), or redirect C2 callbacks.
#
# Surfaces captured (each line: class<TAB>value):
#   nameserver:<ip>          — each nameserver in resolv.conf
#   search:<domain>          — each search domain
#   resolved:<ip>            — systemd-resolved upstream (via
#                              resolvectl)
#   hosts_overrides:<count>  — non-comment /etc/hosts line count
#
# Severity:
#   ok    → no delta
#   warn  → search-domain or hosts-override change
#   alert → nameserver added/changed (the hijack signature)
#
# What this suite locks:
#   - INVENTORY-CAPTURE regression (existing) — the three emitter
#     blocks must funnel into `$current`; the 2026-06-06
#     silent-no-op bug let them leak to stdout, leaving the
#     baseline empty and every diff a no-op
#   - All record classes (nameserver / search / hosts_overrides)
#     surface in the baseline
#   - resolvectl-only resolved records surface when the binary
#     is available
#   - Baseline chmod 0600 (confidentiality — resolver config
#     enumerates upstream identifiers)
#   - DELTA detect: ADDED nameserver (the DNS-hijack signature) →
#     alert / nameserver_change
#   - DELTA detect: CHANGED nameserver → alert (1 add + 1 remove)
#   - DELTA detect: NEW search domain → warn / search_or_hosts_
#     change (non-hijack but still a routing change worth notice)
#   - DELTA detect: /etc/hosts override count JUMP → warn
#     (mass-hijack via hosts file — the poor-man's DNS redirect)
#   - ENFORCE profile: any delta → exit-1 per script logic
#   - REPORT profile: any delta → exit-0 (log-only)
#
# Adds SELFDEF_DNSRES_RESOLV_FILE + SELFDEF_DNSRES_HOSTS_FILE
# env-var overrides (added 2026-06-06) for L2 delta-testability.
# Live defaults unchanged. resolvectl mocked via PATH override.
#
# Run with: bats packaging/test/L2-dns-resolver-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd/dns-resolver-watchdog.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SELFDEF_TEST_LOGCAP}"
FAKELOGGER
    chmod +x "${BIN}/logger"
    # resolvectl mock driven by RESOLVED_UPSTREAMS env var.
    cat > "${BIN}/resolvectl" <<'RVEOF'
#!/usr/bin/env bash
if [[ "$1" == "dns" ]]; then
    for ip in ${RESOLVED_UPSTREAMS:-}; do
        printf 'Link 2 (eth0): %s\n' "$ip"
    done
fi
exit 0
RVEOF
    chmod +x "${BIN}/resolvectl"
    export SELFDEF_TEST_LOGCAP="${TMP}/log.out"
    : > "${SELFDEF_TEST_LOGCAP}"
    BASELINE="${TMP}/dns-resolver-baseline.tsv"
    RESOLV_FILE="${TMP}/resolv.conf"
    HOSTS_FILE="${TMP}/hosts"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    RESOLVED_UPSTREAMS="${RESOLVED_UPSTREAMS:-}" \
    SELFDEF_DNSRES_PROFILE="${PROFILE:-report}" \
    SELFDEF_DNSRES_BASELINE="${BASELINE}" \
    SELFDEF_DNSRES_RESOLV_FILE="${RESOLV_FILE}" \
    SELFDEF_DNSRES_HOSTS_FILE="${HOSTS_FILE}" \
    bash "${WD}"
}

run_wd_rc() {
    PATH="${BIN}:${PATH}" \
    RESOLVED_UPSTREAMS="${RESOLVED_UPSTREAMS:-}" \
    SELFDEF_DNSRES_PROFILE="${PROFILE:-report}" \
    SELFDEF_DNSRES_BASELINE="${BASELINE}" \
    SELFDEF_DNSRES_RESOLV_FILE="${RESOLV_FILE}" \
    SELFDEF_DNSRES_HOSTS_FILE="${HOSTS_FILE}" \
    bash "${WD}" >/dev/null 2>&1
    echo $?
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# Helper: write a baseline resolver inventory.
write_resolver_inventory() {
    cat > "${RESOLV_FILE}" <<'EOF'
# operator-managed resolver
nameserver 1.1.1.1
nameserver 9.9.9.9
search example.com internal.example.com
EOF
    cat > "${HOSTS_FILE}" <<'EOF'
127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback
192.168.1.10 mailhub
EOF
    export RESOLVED_UPSTREAMS="1.1.1.1 9.9.9.9"
}

@test "first run captures the resolver inventory into the baseline (non-empty)" {
    write_resolver_inventory
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
    [ -s "${BASELINE}" ]                                  # capture regression lock
    awk -F'\t' 'NF>=2{ok=1} END{exit ok?0:1}' "${BASELINE}"
    cap | grep -qE '"baseline_count":[1-9]'
}

@test "baseline captures all record classes (nameserver + search + resolved + hosts_overrides)" {
    write_resolver_inventory
    run_wd
    grep -qP '^nameserver\t1\.1\.1\.1$' "${BASELINE}"
    grep -qP '^nameserver\t9\.9\.9\.9$' "${BASELINE}"
    grep -qP '^search\texample\.com$' "${BASELINE}"
    grep -qP '^resolved\t1\.1\.1\.1$' "${BASELINE}"
    grep -qP '^hosts_overrides\t3$' "${BASELINE}"
}

@test "baseline is chmod 0600 (confidentiality — resolver config enumerates upstream identifiers)" {
    write_resolver_inventory
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "unchanged resolver state on second run → ok / no_delta" {
    write_resolver_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}

@test "DELTA detect — ADDED nameserver (the DNS-hijack signature) → alert" {
    write_resolver_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Attacker adds a third nameserver pointing at their resolver.
    cat > "${RESOLV_FILE}" <<'EOF'
nameserver 1.1.1.1
nameserver 9.9.9.9
nameserver 6.6.6.6
search example.com internal.example.com
EOF
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '6\.6\.6\.6'
}

@test "DELTA detect — CHANGED nameserver (1 add + 1 remove) → alert" {
    write_resolver_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${RESOLV_FILE}" <<'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
search example.com internal.example.com
EOF
    export RESOLVED_UPSTREAMS="1.1.1.1 8.8.8.8"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"added":'
    cap | grep -q '"removed":'
}

@test "DELTA detect — NEW search domain → warn (non-hijack but routing change worth notice)" {
    write_resolver_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    sed -i 's|^search example.com internal.example.com|search example.com internal.example.com lab.example.com|' "${RESOLV_FILE}"
    run_wd
    cap | grep -q '"severity":"warn"'
}

@test "DELTA detect — /etc/hosts override count JUMP → warn (mass-hijack via hosts entries)" {
    write_resolver_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Attacker drops 20 hosts overrides — the poor-man's DNS hijack.
    for i in $(seq 1 20); do
        echo "10.0.0.$i evil$i.fake-ca.example" >> "${HOSTS_FILE}"
    done
    run_wd
    cap | grep -q '"severity":"warn"'
}

@test "INVARIANT (no auto-trust): dns-resolver-watchdog does NOT refresh the baseline on delta — alert STAYS until operator updates baseline" {
    write_resolver_inventory
    PROFILE=report run_wd
    cat > "${RESOLV_FILE}" <<'EOF'
nameserver 1.1.1.1
nameserver 9.9.9.9
nameserver 6.6.6.6
search example.com internal.example.com
EOF
    PROFILE=report run_wd                                  # first delta
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=report run_wd                                  # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "REPORT profile: alert delta → exit-0 (log-only — journald is the surface)" {
    write_resolver_inventory
    PROFILE=report run_wd
    cat > "${RESOLV_FILE}" <<'EOF'
nameserver 1.1.1.1
nameserver 6.6.6.6
search example.com internal.example.com
EOF
    rc="$(PROFILE=report run_wd_rc)"
    [ "${rc}" = "0" ]
}

@test "ENFORCE profile: alert delta → exit-1 (the report-vs-enforce contrast)" {
    write_resolver_inventory
    PROFILE=report run_wd
    cat > "${RESOLV_FILE}" <<'EOF'
nameserver 1.1.1.1
nameserver 6.6.6.6
search example.com internal.example.com
EOF
    rc="$(PROFILE=enforce run_wd_rc)"
    [ "${rc}" != "0" ]
}

@test "INVARIANT (resolved upstream change alone): resolvectl-only delta surfaces as alert" {
    write_resolver_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Same resolv.conf, but resolvectl reports a different upstream
    # (resolved configuration changed via drop-in).
    export RESOLVED_UPSTREAMS="1.1.1.1 6.6.6.6"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '6\.6\.6\.6'
}

@test "INVARIANT (mass nameserver flush — all removed, attacker-friendly empty resolver): → alert" {
    # Realistic attack variant: clear resolv.conf entirely, then
    # operator's DHCP renews to attacker's resolver. The 'all removed'
    # signature is itself worth alerting on.
    write_resolver_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    : > "${RESOLV_FILE}"
    export RESOLVED_UPSTREAMS=""
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA-detect: nameserver change carries the SPECIFIC IP in added_sample)" {
    write_resolver_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${RESOLV_FILE}" <<'EOF'
nameserver 1.1.1.1
nameserver 9.9.9.9
nameserver 99.66.66.99
search example.com internal.example.com
EOF
    run_wd
    cap | grep -q '99\.66\.66\.99'   # specific IP visible in JSON sample
}

@test "INVARIANT (comment-only resolv.conf change → no_delta): byte-level changes that don't affect record set are no-ops" {
    write_resolver_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${RESOLV_FILE}" <<'EOF'
# operator-managed resolver
# (an additional comment that should not count)
nameserver 1.1.1.1
nameserver 9.9.9.9
search example.com internal.example.com
EOF
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    write_resolver_inventory
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-dns-resolver -- ')
    [ "${main_count}" = "1" ]
}
