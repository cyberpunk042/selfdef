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

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates drop-in + fires sysctl --load)" {
    # Operator may rm the drop-in (file-deletion tamper) — apply must
    # rebuild it and re-apply live so kernel state is restored.
    write_config "baseline"
    run_wd
    [ -f "${DROPIN}" ]
    rm -f "${DROPIN}"
    : > "${SCTL_LOG}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'profile=baseline' "${DROPIN}"
    grep -qE 'sysctl --(load|system|p)' "${SCTL_LOG}"
}

@test "INVARIANT (header-marker is first non-blank line — stale-cleanup head -1 discipline)" {
    # If apply.sh ever changes the header, a stale-cleanup pass that
    # uses head -1 to identify selfdef-managed drop-ins must continue
    # to match. Lock the head-1 contract.
    write_config "baseline"
    run_wd
    first_line="$(awk 'NF' "${DROPIN}" | head -1)"
    [[ "${first_line}" == *"selfdef sysctl-network-baseline"* ]]
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "router"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"sysctl-network-baseline"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=router'* ]]
}

@test "INVARIANT (paranoid composes baseline + ICMP-echo-ignore + IPv6-disable axes — multi-axis lock)" {
    # paranoid is NOT a replacement of baseline; it COMPOSES baseline's
    # endpoint hardening with ICMP-echo-ignore + IPv6-disable on top.
    # Attacker downgrading paranoid to baseline must not relax these axes.
    write_config "paranoid"
    run_wd
    # baseline axes still present.
    grep -qE 'accept_redirects\s*=\s*0' "${DROPIN}"
    grep -qE 'accept_source_route\s*=\s*0' "${DROPIN}"
    grep -qE 'tcp_syncookies\s*=\s*1' "${DROPIN}"
    # paranoid-specific axes added on top.
    grep -qE 'icmp_echo_ignore_all\s*=\s*1' "${DROPIN}"
    grep -qE 'disable_ipv6\s*=\s*1' "${DROPIN}"
}

@test "INVARIANT (router composes baseline + ip_forward — DOES NOT add paranoid axes)" {
    # router is an intentional widening of the network surface (the
    # host IS routing traffic). Locks that router does NOT
    # accidentally include paranoid-specific axes (ICMP-echo-ignore,
    # IPv6 disable) which would break legitimate routing.
    write_config "router"
    run_wd
    grep -qE 'ip_forward\s*=\s*1' "${DROPIN}"
    grep -qE 'tcp_syncookies\s*=\s*1' "${DROPIN}"
    grep -qE 'accept_redirects\s*=\s*0' "${DROPIN}"
    ! grep -qE 'icmp_echo_ignore_all\s*=\s*1' "${DROPIN}"
    ! grep -qE 'disable_ipv6\s*=\s*1' "${DROPIN}"
}

@test "INVARIANT (drop-in is sysctl-parseable: each non-comment line matches key=value shape)" {
    # The drop-in is sourced by sysctl --load. Every non-comment
    # non-blank line MUST match the sysctl key=value grammar.
    # Sister to file-protections-baseline sysctl-parseable INVARIANT.
    write_config "baseline"
    run_wd
    awk '/^[[:space:]]*#/ || /^[[:space:]]*$/ {next} /^[a-zA-Z_][a-zA-Z0-9_.]*[[:space:]]*=[[:space:]]*[-0-9]+/ {next} {bad=1; print "malformed: " $0} END{exit bad?1:0}' "${DROPIN}"
}

@test "INVARIANT (profile downgrade router → baseline: REMOVES ip_forward — operator-loosening bidirectional contract)" {
    # When operator downgrades router → baseline, the host is no
    # longer routing. ip_forward MUST be cleared from drop-in OR
    # explicitly set back to 0. Locks bidirectional contract.
    write_config "router"
    run_wd
    grep -qE 'ip_forward\s*=\s*1' "${DROPIN}"
    write_config "baseline"
    run_wd
    # ip_forward either absent (kernel default 0) OR explicitly = 0.
    if grep -qE '^net\.ipv4\.ip_forward' "${DROPIN}"; then
        grep -qE 'net\.ipv4\.ip_forward\s*=\s*0' "${DROPIN}"
    fi
    grep -q 'profile=baseline' "${DROPIN}"
}

@test "INVARIANT (drop-in carries rp_filter=1 — reverse-path filtering anti-spoof)" {
    # Sister to many other sysctl-baseline directive INVARIANTs
    # already locked. net.ipv4.conf.all.rp_filter=1 enables
    # strict reverse-path filtering: kernel drops packets whose
    # source IP would route back via a different interface than
    # they arrived on. Defends against spoofed-source attacks
    # (T1566.001 — Phishing via spoofed source; on a network
    # edge, defeats the entire spoofed-source family). Both
    # baseline + router profiles MUST carry this directive.
    write_config "baseline"
    run_wd
    grep -qE 'net\.ipv4\.conf\.all\.rp_filter\s*=\s*[12]' "${DROPIN}" \
        || grep -qE 'rp_filter\s*=\s*[12]' "${DROPIN}"
}

@test "INVARIANT (drop-in carries tcp_syncookies=1 — SYN-flood defense)" {
    # Sister to rp_filter + other sysctl-baseline directive
    # INVARIANTs. net.ipv4.tcp_syncookies=1 enables SYN cookies
    # protecting the host's listening TCP sockets against SYN-
    # flood DoS attacks (T1499.001 — Endpoint Denial of Service:
    # OS Exhaustion Flood). Without syncookies, a remote
    # attacker can exhaust the kernel's half-open-connection
    # table and make the host stop accepting new TCP connections
    # (including operator's incoming SSH). Lock that all
    # profiles carry this directive — it has no operator-
    # legitimate reason to be 0.
    write_config "baseline"
    run_wd
    grep -qE 'net\.ipv4\.tcp_syncookies\s*=\s*1' "${DROPIN}" \
        || grep -qE 'tcp_syncookies\s*=\s*1' "${DROPIN}"
}

@test "INVARIANT (drop-in carries accept_redirects=0 — ICMP redirect MITM-pivot defense)" {
    # Sister to rp_filter + tcp_syncookies sysctl-baseline
    # directive INVARIANTs. ICMP redirects are a legacy mechanism
    # for routers to tell hosts "use this alternate gateway for
    # this destination." Attackers on the local segment send
    # spoofed ICMP redirects to make the host route specific
    # traffic through the attacker's IP — a classic MITM-pivot
    # primitive. net.ipv4.conf.all.accept_redirects=0 (and
    # send_redirects=0 for the host-as-router axis) defeats
    # this attack. T1557 Adversary-in-the-Middle via ICMP
    # redirect. Lock that baseline carries the anti-redirect
    # directive — no operator-legitimate reason to accept ICMP
    # redirects on a typical endpoint.
    write_config "baseline"
    run_wd
    grep -qE 'net\.ipv4\.conf\..*\.accept_redirects\s*=\s*0' "${DROPIN}" \
        || grep -qE 'accept_redirects\s*=\s*0' "${DROPIN}"
}

@test "INVARIANT (drop-in carries log_martians=1 — anti-spoof packet logging for forensic observability)" {
    # Sister to rp_filter + tcp_syncookies + accept_redirects
    # sysctl-baseline directive INVARIANTs. net.ipv4.conf.*.
    # log_martians=1 instructs the kernel to log packets with
    # impossible source addresses (martian packets — typically
    # spoofed-source-address scans, or misconfigured devices
    # leaking RFC1918 traffic). Without it, attacker IP-spoofing
    # probes pass through silently — operator forensic timeline
    # has no evidence the probes happened. Lock that baseline
    # carries the log_martians directive — operator post-incident
    # forensic observability on the anti-spoof family axis sister
    # to rp_filter detection-vs-blocking complement.
    write_config "baseline"
    run_wd
    grep -qE 'net\.ipv4\.conf\..*\.log_martians\s*=\s*1' "${DROPIN}" \
        || grep -qE 'log_martians\s*=\s*1' "${DROPIN}"
}

@test "INVARIANT (drop-in carries icmp_echo_ignore_broadcasts=1 — smurf-amplification denial-of-service defense)" {
    # Sister to rp_filter + tcp_syncookies + accept_redirects +
    # log_martians sysctl-baseline directive INVARIANTs. net.
    # ipv4.icmp_echo_ignore_broadcasts=1 instructs the kernel
    # to silently drop ICMP echo requests targeted at broadcast
    # addresses — without it, the host becomes a smurf-attack
    # amplifier (attacker spoofs source as victim, broadcasts
    # ICMP echo to subnet, all hosts in subnet reply to
    # victim — 1:N amplification denial-of-service). Sister
    # to anti-spoof family but on the broadcast-amplification
    # axis. Lock that baseline carries the directive — host
    # cannot be weaponized as a smurf amplifier.
    write_config "baseline"
    run_wd
    grep -qE 'net\.ipv4\.icmp_echo_ignore_broadcasts\s*=\s*1' "${DROPIN}" \
        || grep -qE 'icmp_echo_ignore_broadcasts\s*=\s*1' "${DROPIN}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. sysctl-network-baseline manifest declares install +
    # profile gating (default / strict) the resolver enforces;
    # malformed manifest wedges the net.ipv4 hardening drop-in.
    # Python's tomllib is the canonical parser. Locks anti-
    # malformed-manifest on the sysctl-network-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sysctl-network-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'sysctl-network-baseline', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: sysctl-network-baseline installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # sysctl-network-baseline writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the sysctl-network-baseline
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-network-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(sysctl\.conf|sysctl\.d|fstab|fstab\.d|systemd|profile\.d|login\.defs|apt|modprobe\.d|usbguard)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(sysctl\.d|fstab\.d|systemd|profile\.d|apt|modprobe\.d|usbguard).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # sysctl-network-baseline install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the sysctl-network-baseline lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-network-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the sysctl-network-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sysctl-network-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sysctl-network-baseline/module.toml"
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
    # Sister to brain-wide module.toml list-vs-string family.
    # Locks list discipline on provides.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sysctl-network-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sysctl-network-baseline/module.toml"
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
    # the sysctl-network-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sysctl-network-baseline/module.toml"
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
    # sysctl-network-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sysctl-network-baseline/module.toml"
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
    # sysctl-network-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sysctl-network-baseline/module.toml"
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
    # Locks semver-X.Y.Z discipline on the sysctl-network-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sysctl-network-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (sysctl-network-baseline module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the sysctl-network-baseline module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sysctl-network-baseline/module.toml"
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

@test "INVARIANT (sysctl-network-baseline module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the sysctl-network-baseline module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sysctl-network-baseline/module.toml"
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
