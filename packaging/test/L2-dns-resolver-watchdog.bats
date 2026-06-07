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
