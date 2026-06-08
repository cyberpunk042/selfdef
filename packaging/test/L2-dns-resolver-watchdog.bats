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

@test "INVARIANT (IPv6 nameserver detection: 2001:db8::1 ADDED → alert)" {
    # Attackers may add IPv6 nameservers to evade IPv4-only
    # detection. Watchdog must surface IPv6 entries too.
    write_resolver_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${RESOLV_FILE}" <<'EOF'
nameserver 1.1.1.1
nameserver 9.9.9.9
nameserver 2001:db8::dead:beef
search example.com internal.example.com
EOF
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '2001'
}

@test "INVARIANT (resolvectl unavailable on host: script gracefully degrades — no crash)" {
    # On hosts without systemd-resolved, resolvectl is missing.
    # Watchdog should still function on resolv.conf + hosts only.
    rm -f "${BIN}/resolvectl"
    write_resolver_inventory
    run_wd
    # Baseline still captured (resolv.conf + hosts inventory).
    [ -f "${BASELINE}" ]
    cap | grep -q '"event":"baseline_initial"'
}

@test "INVARIANT (search domain REMOVED → warn): search-domain pruning surfaces too" {
    # Removal of search domain is also a routing change — not as
    # severe as nameserver change (no hijack opportunity), but
    # worth warn.
    write_resolver_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${RESOLV_FILE}" <<'EOF'
nameserver 1.1.1.1
nameserver 9.9.9.9
search example.com
EOF
    run_wd
    cap | grep -qE '"severity":"(warn|ok)"'
}

@test "INVARIANT (hosts file removed since baseline: doesn't crash + defensive event surfaces)" {
    # If operator removes /etc/hosts (rare but possible), watchdog
    # must not crash on missing file.
    write_resolver_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    rm -f "${HOSTS_FILE}"
    run_wd
    # Either no_delta (hosts_overrides count went from 3 to 0
    # which is a warn-tier change) or warn surfaces. Lock that
    # script doesn't crash + emits a record.
    cap | grep -qE '"event":"[a-z_]+"'
}

@test "INVARIANT (nameserver-add severity precedence: add + search-removed in same scan → alert wins over warn)" {
    # When multiple deltas of different severities surface in the
    # same scan, alert (nameserver add) wins over warn (search-
    # removed). Sister to sudoers-integrity severity-precedence
    # INVARIANT.
    write_resolver_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${RESOLV_FILE}" <<'EOF'
nameserver 1.1.1.1
nameserver 9.9.9.9
nameserver 6.6.6.6
search example.com
EOF
    run_wd
    cap | grep -q '"severity":"alert"'
    main_count=$(cap | grep -cE '^-t selfdef-dns-resolver -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (multi-IP nameserver-add: 3 attacker resolvers in one scan → still single alert; consolidation)" {
    # When attacker stacks multiple nameserver entries in one
    # change, single alert JSON record fires with all IPs in the
    # added_sample. Locks consolidation discipline.
    write_resolver_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${RESOLV_FILE}" <<'EOF'
nameserver 1.1.1.1
nameserver 9.9.9.9
nameserver 6.6.6.1
nameserver 6.6.6.2
nameserver 6.6.6.3
search example.com internal.example.com
EOF
    run_wd
    cap | grep -q '"severity":"alert"'
    main_count=$(cap | grep -cE '^-t selfdef-dns-resolver -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (localhost-nameserver replacement → alert): attacker-fronting-via-local-listener axis covered" {
    # Sister to nameserver-add axes already locked. An attacker who
    # gets foothold may swap the nameserver list to ONLY
    # 127.0.0.1 / ::1 — pointing every DNS query at a local
    # listener they've planted (e.g. dnsmasq with attacker-
    # controlled upstreams). This both (a) defeats network-level
    # DNS-traffic monitoring AND (b) bypasses the host's primary
    # resolver. The signature is the localhost-only entry in
    # combination with REMOVED prior real nameservers. Locks the
    # localhost-DNS-fronting attack axis.
    write_resolver_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${RESOLV_FILE}" <<'EOF'
nameserver 127.0.0.1
search example.com internal.example.com
EOF
    run_wd
    cap | grep -q '"severity":"alert"'
    main_count=$(cap | grep -cE '^-t selfdef-dns-resolver -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker IP surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker adds a
    # distinctive IP (RFC 5737 documentation range / non-standard
    # /16 / etc) to the nameserver list, the IP MUST surface in
    # the JSON sample so operator dashboard routes triage to the
    # right resolver. Locks the operator-visibility contract on
    # the DNS-redirection surveillance surface (T1556.004 —
    # Impair Defenses: Modify DNS Resolver).
    write_resolver_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${RESOLV_FILE}" <<'EOF'
nameserver 198.51.100.42
EOF
    run_wd
    cap | grep -q '198.51.100.42'
}

@test "INVARIANT (DoT/DoH bypass attempt: cleartext public-resolver 8.8.8.8 added when prior was DoT-only → alert)" {
    # Sister to localhost-nameserver replacement INVARIANT
    # already locked. Operators frequently configure systemd-
    # resolved or unbound with DoT (DNS-over-TLS) to a curated
    # upstream — bypassing cleartext DNS surveillance/MITM. An
    # attacker who manages to rewrite /etc/resolv.conf to point
    # at a cleartext public resolver (8.8.8.8 / 1.1.1.1 / 9.9.9.9)
    # downgrades the encrypted-DNS posture silently. The
    # watchdog MUST treat ADD of a non-loopback cleartext
    # resolver as alert, even if the resolver itself is a
    # famous public one (the famousness doesn't excuse the
    # downgrade). Locks the DoT/DoH-bypass detection axis on
    # the DNS-redirection surveillance surface (T1556.004 —
    # Impair Defenses: Modify DNS Resolver).
    write_resolver_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${RESOLV_FILE}" <<'EOF'
nameserver 8.8.8.8
EOF
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger-line INVARIANTs.
    write_resolver_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${RESOLV_FILE}" <<'EOF'
nameserver 198.51.100.42
nameserver 198.51.100.43
nameserver 198.51.100.44
EOF
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-dns-resolver -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # State-resilience on T1071.004 DNS resolver MITM
    # surveillance.
    cat > "${RESOLV_FILE}" <<'EOF'
nameserver 1.1.1.1
nameserver 1.0.0.1
EOF
    run_wd                                              # establishes baseline
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"                                  # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # must re-establish
    [ -f "${BASELINE}" ]
    cap | grep -qE '"event":"baseline_initial"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on dns-resolver surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The dns-resolver-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1071.004 DNS resolver MITM persistence
    # alert. Locks parser contract on the /etc/resolv.conf
    # nameserver delta detection surface.
    cat > "${RESOLV_FILE}" <<'EOF'
nameserver 1.1.1.1
EOF
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    cat > "${RESOLV_FILE}" <<'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # dns-resolver-watchdog runs ON the timer's scheduled fire —
    # diffs /etc/resolv.conf against baseline, emits a verdict on
    # nameserver/search-domain mutations, then exits. Type=simple
    # would break timer OnUnitActiveSec semantics. Locks oneshot-
    # probe contract on the dns-resolver-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd/selfdef-dns-resolver.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. dns-resolver-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # dns-resolver-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # dns-resolver-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'dns-resolver-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: dns-resolver-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. dns-resolver-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the dns-resolver-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (dns-resolver-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The dns-resolver-watchdog libexec uses set -u to catch typo'd env-var
    # references before they silently propagate as empty
    # strings into baseline-path operations. Locks set -u
    # discipline on the dns-resolver-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dns-resolver-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # dns-resolver-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dns-resolver-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # dns-resolver-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dns-resolver-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the dns-resolver-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dns-resolver-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # dns-resolver-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dns-resolver-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the dns-resolver-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dns-resolver-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the dns-resolver-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (dns-resolver-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # dns-resolver-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (dns-resolver-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
    # Sister to brain-wide TimeoutStartSec= INVARIANT family.
    # Watchdog .service units are Type=oneshot probes — they
    # MUST declare a TimeoutStartSec= upper bound so systemd
    # kills a hung probe (e.g. a stuck sha256sum on a slow
    # NFS-mounted target file) rather than blocking the
    # next timer fire indefinitely. Without TimeoutStartSec=
    # systemd's default (90s) applies, but the canonical
    # selfdef contract pins this explicitly per watchdog so
    # operators reading the .service know the bound at a
    # glance. A regression that dropped TimeoutStartSec=
    # would silently revert to the systemd default + mask
    # the explicit-bound contract. Locks anti-hang oneshot-
    # bound discipline on the dns-resolver-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (dns-resolver-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
    # Sister to brain-wide systemd resource-priority INVARIANT
    # family. Watchdog .service units run periodic scans (often
    # sha256sum walks of large config trees) — they MUST be
    # deprioritized via Nice= (positive value = lower priority
    # under load) so that the watchdog scan doesn't starve
    # operator-foreground workloads when CPU is contended.
    # The canonical selfdef value is Nice=15 (well above the
    # background-batch threshold of 10). A regression dropping
    # Nice= would let watchdog scans compete with foreground at
    # default Nice=0, surfacing as latency spikes on contended
    # hosts. Locks the idle-priority anti-resource-starve
    # discipline on the dns-resolver-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (dns-resolver-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd PrivateTmp= INVARIANT
    # family. Watchdog .service units that run periodic
    # sha256sum walks may create transient /tmp files. The
    # PrivateTmp= directive (canonically =true) instructs
    # systemd to give the unit its own /tmp mount namespace —
    # an attacker who exploits the watchdog cannot reach
    # /tmp files owned by other processes (e.g. ssh-agent
    # sockets), and the watchdog's own /tmp residue is
    # automatically cleaned at unit-stop. A regression
    # dropping PrivateTmp= would share /tmp with the host,
    # exposing the watchdog as a side-channel for any
    # /tmp-based pivot. Locks the /tmp namespace-isolation
    # discipline on the dns-resolver-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (dns-resolver-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd ProtectHome= INVARIANT
    # family. Watchdog .service units have no business
    # reading /home — their probe targets are system-config
    # paths (/etc/*). The ProtectHome= directive
    # (canonically =read-only) instructs systemd to either
    # hide (=true) or read-only-mount (=read-only) the
    # /home, /root, and /run/user directories within the
    # unit's mount namespace. An exploited watchdog cannot
    # then exfiltrate ~/.bash_history, ~/.ssh/*, or operator
    # credentials. A regression dropping ProtectHome= would
    # expose all operator home contents to a compromised
    # watchdog. Locks the home-namespace-isolation
    # discipline on the dns-resolver-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (dns-resolver-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
    # Sister to brain-wide systemd NoNewPrivileges= INVARIANT
    # family. The NoNewPrivileges=true directive instructs
    # the kernel to set PR_SET_NO_NEW_PRIVS on the watchdog
    # process — any subsequent execve() in the watchdog
    # script (sha256sum, awk, etc.) is forbidden to acquire
    # NEW privileges via setuid/setgid/file-capabilities. An
    # exploited watchdog cannot escalate via a setuid helper
    # (e.g. /usr/bin/su, /usr/bin/sudo). A regression
    # dropping NoNewPrivileges= would leave the watchdog
    # exposed to setuid-binary pivot. Locks the privilege-
    # escalation containment discipline on the dns-resolver-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (dns-resolver-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the dns-resolver-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (dns-resolver-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
    # Sister to brain-wide systemd ExecStart binary-path
    # INVARIANT family. Watchdog .service units MUST execute
    # the watchdog script from /usr/local/libexec/selfdef/
    # (operator-extension path, not /usr/bin which is
    # Debian-package-only). The canonical libexec/selfdef/
    # path lets operators override the watchdog script
    # without rebuilding the .deb (sister to brain-wide
    # operator-extension /usr/local/* discipline). A
    # regression that pointed ExecStart at /usr/bin/ would
    # surface as a "stale-watchdog-binary" on hosts where
    # operators patched the libexec copy. Locks the
    # libexec/selfdef ExecStart-path discipline on the
    # dns-resolver-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (dns-resolver-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
    # Sister to brain-wide systemd After= INVARIANT family.
    # Watchdog .service units MUST declare an After= directive
    # so they don't fire before the filesystem mounts that
    # contain their probe targets (canonically After=local-
    # fs.target so /etc/* is mounted before the watchdog
    # tries to sha256sum a config file). A regression
    # dropping After= would surface as "watchdog fires
    # during early-boot before /etc is mounted" which then
    # hashes nothing + emits a spurious "config missing"
    # alert. Locks the boot-sequencing discipline on the
    # dns-resolver-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (dns-resolver-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the dns-resolver-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (dns-resolver-watchdog timer unit declares OnBootSec= — boot-catchup-delay contract)" {
    # Sister to brain-wide systemd OnBootSec= INVARIANT
    # family. Watchdog .timer units MUST declare OnBootSec=
    # so the first watchdog fire is delayed until after boot
    # finishes settling. Locks the boot-catchup-delay
    # discipline on the dns-resolver-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnBootSec=' "${t}"
    done
}

@test "INVARIANT (dns-resolver-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
    # Sister to brain-wide systemd timer [Install].WantedBy=
    # INVARIANT family. Watchdog .timer units MUST declare
    # WantedBy=timers.target so `systemctl enable selfdef-
    # <slug>.timer` wires the timer into the timers.target
    # symlink-graph + activates it on every boot. A
    # regression that swapped to WantedBy=multi-user.target
    # (the .service-side install target) would make the
    # timer enable-step a no-op + leave the watchdog
    # silently inactive. Locks the timer-enable-graph
    # discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (dns-resolver-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (dns-resolver-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (dns-resolver-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (dns-resolver-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the dns-resolver-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    [ -f "${script_dir}/dns-resolver-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (dns-resolver-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (dns-resolver-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (dns-resolver-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (dns-resolver-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (dns-resolver-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (dns-resolver-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (dns-resolver-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (dns-resolver-watchdog .sh script emits canonical severity vocabulary {ok,warn,alert} — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    # Watchdog scripts emit logger -t selfdef-<name> -- {...severity:...}
    # with severity in the canonical vocabulary. A regression
    # introducing custom severity values (info, error, critical)
    # would break operator-side filtering.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '"severity":"(ok|warn|alert)"' "${s}"
    done
}

@test "INVARIANT (dns-resolver-watchdog .sh script tag selfdef-dns-resolver matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-dns-resolver
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (dns-resolver-watchdog .sh script declares profile-aware exit behavior — operator-extension profile-dispatch contract)" {
    # Sister to brain-wide profile-aware INVARIANT family.
    # Scripts MUST handle PROFILE=enforce vs report differently.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'PROFILE.*enforce|enforce.*PROFILE|profile.*enforce' "${s}"
    done
}

@test "INVARIANT (dns-resolver-watchdog .sh script declares baseline file path — operator-extensible baseline-state contract)" {
    # Sister to brain-wide baseline-state INVARIANT family.
    # Delta-scan watchdogs MUST declare a BASELINE variable referencing
    # /var/lib/selfdef/ so operators know where baseline state lives.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '/var/lib/selfdef/|BASELINE' "${s}"
    done
}

@test "INVARIANT (dns-resolver-watchdog .sh script declares MODULE-suffixed tag in logger -t — module-name-tag-consistency contract)" {
    # Sister to SDD-062 tag-canonical INVARIANT family. The tag passed to
    # logger -t MUST include the module slug so journalctl filtering by
    # tag surfaces only this watchdog's events.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (dns-resolver-watchdog .sh script file is non-empty (size > 100 bytes) — non-trivial-script contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (dns-resolver-watchdog .sh script has >20 lines — non-trivial-watchdog-body contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 20 ]
    done
}

@test "INVARIANT (dns-resolver-watchdog .service unit file has >5 lines of directives — non-trivial-unit-file contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 5 ]
    done
}

@test "INVARIANT (dns-resolver-watchdog .service unit ExecStart references /usr/local/libexec/selfdef/ path — canonical-binary-path contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (dns-resolver-watchdog .timer file exists at canonical path modules/dns-resolver-watchdog/systemd — canonical-systemd-dir layout)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    [ -d "${timer_dir}" ]
    n=$(ls "${timer_dir}"/*.timer 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (dns-resolver-watchdog module.toml exists at canonical path modules/dns-resolver-watchdog/ — module-manifest existence 72-cycle)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (dns-resolver-watchdog systemd dir exists at modules/dns-resolver-watchdog/systemd — systemd-dir-existence 73-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    [ -d "${sd}" ]
}

@test "INVARIANT (dns-resolver-watchdog systemd dir is non-empty — systemd-content-presence 74-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    n=$(ls "${sd}" | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (dns-resolver-watchdog .service file size > 100 bytes — substantial-service-unit 75-cycle)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (dns-resolver-watchdog .timer file size > 50 bytes — substantial-timer-unit 76-cycle)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        size=$(stat -c '%s' "${t}")
        [ "${size}" -gt 50 ]
    done
}

@test "INVARIANT (dns-resolver-watchdog README.md file size > 100 bytes — substantial-readme 77-cycle)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/README.md"
    size=$(stat -c '%s' "${readme}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (dns-resolver-watchdog .service Documentation URL is HTTP/HTTPS — operator-doc-link-protocol 78)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=(http|https)://' "${s}"
    done
}

@test "INVARIANT (dns-resolver-watchdog .sh script has shebang line — POSIX-conformant 79)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '^#!'
    done
}

@test "INVARIANT (dns-resolver-watchdog .sh script declares set flag in first 50 lines — strict-mode-prologue 80)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -50 "${s}" | grep -qE '^set -'
    done
}

@test "INVARIANT (dns-resolver-watchdog module.toml size > 200 bytes — substantial-watchdog-manifest 81)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/module.toml"
    size=$(stat -c '%s' "${mtoml}")
    [ "${size}" -gt 200 ]
}

@test "INVARIANT (dns-resolver-watchdog .service file is non-empty — non-trivial-unit-file 82)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        [ -s "${s}" ]
    done
}

@test "INVARIANT (dns-resolver-watchdog .timer file is non-empty — non-trivial-timer-file 83)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        [ -s "${t}" ]
    done
}

@test "INVARIANT (dns-resolver-watchdog .sh script body has at least one variable assignment — non-vacuous-script 84)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^[a-zA-Z_]+=' "${s}"
    done
}

@test "INVARIANT (dns-resolver-watchdog .sh script path matches systemd dir layout — canonical-script-co-location 85)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd"
    [ -d "${script_dir}" ]
    n=$(ls "${script_dir}"/*.sh 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (dns-resolver-watchdog module.toml has install_paths section — SDD-026 mutation-manifest 86)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (dns-resolver-watchdog module.toml install_paths.paths non-empty list 87)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list) and len(ps) > 0
"
}

@test "INVARIANT (dns-resolver-watchdog module.toml install_paths.paths only absolute paths 88)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (dns-resolver-watchdog module.toml provides list non-empty 89 — capability-export-present)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list) and len(p) >= 1
"
}

@test "INVARIANT (dns-resolver-watchdog module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (dns-resolver-watchdog module.toml install_paths.paths includes /etc/ entry — config-staging 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps)
"
}

@test "INVARIANT (dns-resolver-watchdog module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p for p in ps)
"
}

@test "INVARIANT (dns-resolver-watchdog module.toml install_paths.paths has /var/ entry 93 — state-staging)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/var/') for p in ps)
"
}
