#!/usr/bin/env bats
# L2 bats unit tests for the polarproxy module (MS023 — transparent
# TLS termination → PCAP-over-IP for content visibility).
#
# Run with: bats packaging/test/L2-polarproxy.bats

MODULE_DIR="${BATS_TEST_DIRNAME}/../../modules/polarproxy"
INSTALL_DIR="${MODULE_DIR}/install"

@test "module.toml exists + declares name = polarproxy" {
    [ -f "${MODULE_DIR}/module.toml" ]
    grep -qE '^name[[:space:]]*=[[:space:]]*"polarproxy"' "${MODULE_DIR}/module.toml"
}

@test "module.toml install.kind = script" {
    grep -qE '^kind[[:space:]]*=[[:space:]]*"script"' "${MODULE_DIR}/module.toml"
}

@test "install/apply.sh + check.sh + uninstall.sh exist + executable" {
    [ -x "${INSTALL_DIR}/apply.sh" ]
    [ -x "${INSTALL_DIR}/check.sh" ]
    [ -x "${INSTALL_DIR}/uninstall.sh" ]
}

@test "apply.sh uses set -euo pipefail" {
    grep -qE '^set -euo pipefail' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh is SELFDEF_DRY_RUN aware" {
    grep -q 'SELFDEF_DRY_RUN' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh exposes 4 override env vars (CONFIG, TEMPLATES, UNIT, NFT)" {
    grep -q 'SELFDEF_POLARPROXY_CONFIG'    "${INSTALL_DIR}/apply.sh"
    grep -q 'SELFDEF_POLARPROXY_TEMPLATES' "${INSTALL_DIR}/apply.sh"
    grep -q 'SELFDEF_POLARPROXY_UNIT_PATH' "${INSTALL_DIR}/apply.sh"
    grep -q 'SELFDEF_POLARPROXY_NFT_PATH'  "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh reads profile + listen_port + pcap_over_ip_port config keys" {
    grep -q 'listen_port'        "${INSTALL_DIR}/apply.sh"
    grep -q 'pcap_over_ip_port'  "${INSTALL_DIR}/apply.sh"
}

@test "module.toml profile default = host-tls-mitm" {
    grep -qE 'default[[:space:]]*=[[:space:]]*"host-tls-mitm"' "${MODULE_DIR}/module.toml"
}

@test "apply.sh writes a systemd unit + nftables ruleset" {
    grep -q 'polarproxy.service'        "${INSTALL_DIR}/apply.sh"
    grep -q 'selfdef-polarproxy.conf'   "${INSTALL_DIR}/apply.sh"
}

# ============================================================================
# nat-redirect template contract — polarproxy installs an nft NAT redirect
# in ITS OWN table (`inet selfdef_polarproxy`) so it never touches the
# operator's existing nat table (same isolation invariant bridge-l2 + vpn-
# bridge encode). The redirect is dstnat-priority on TCP/443 → listener
# port. Silent regression here either (a) takes over the operator's nat
# table or (b) silently stops redirecting, breaking TLS inspection.
# ============================================================================

@test "nat-redirect template lives in its own table (isolation invariant verbatim)" {
    grep -qE 'own table|never touch.*nat table' \
        "${MODULE_DIR}/templates/nat-redirect.rule.tmpl"
}

@test "nat-redirect template declares table inet selfdef_polarproxy" {
    grep -qE '^table[[:space:]]+inet[[:space:]]+selfdef_polarproxy[[:space:]]*\{' \
        "${MODULE_DIR}/templates/nat-redirect.rule.tmpl"
}

@test "nat-redirect chain hooks at output priority dstnat (NAT redirect contract)" {
    grep -qE 'type[[:space:]]+nat[[:space:]]+hook[[:space:]]+output[[:space:]]+priority[[:space:]]+dstnat;[[:space:]]+policy[[:space:]]+accept;' \
        "${MODULE_DIR}/templates/nat-redirect.rule.tmpl"
}

@test "nat-redirect rule targets TCP/443 → @@LISTEN_PORT@@" {
    grep -qE 'meta[[:space:]]+l4proto[[:space:]]+tcp[[:space:]]+tcp[[:space:]]+dport[[:space:]]+443[[:space:]]+redirect[[:space:]]+to[[:space:]]+:@@LISTEN_PORT@@' \
        "${MODULE_DIR}/templates/nat-redirect.rule.tmpl"
}

@test "nat-redirect rule carries selfdef-polarproxy comment (operator audit)" {
    grep -q 'comment "selfdef-polarproxy"' "${MODULE_DIR}/templates/nat-redirect.rule.tmpl"
}

@test "nat-redirect template carries @@LISTEN_PORT@@ substitution token" {
    grep -q '@@LISTEN_PORT@@' "${MODULE_DIR}/templates/nat-redirect.rule.tmpl"
}

# ============================================================================
# polarproxy.service.tmpl contract — systemd hardening + token contract.
# The unit ships with 6 substitution tokens + a 5-clause systemd hardening
# stack (NoNewPrivileges + ProtectSystem=strict + ProtectHome + PrivateTmp +
# DynamicUser). Silent regression of any hardening clause widens the unit's
# capability surface — exactly the failure mode MS024-cousin contract tests
# exist to catch.
# ============================================================================

@test "polarproxy.service template is a systemd Type=simple unit" {
    grep -qE '^Type=simple' "${MODULE_DIR}/templates/polarproxy.service.tmpl"
}

@test "polarproxy.service template runs PolarProxy ExecStart line" {
    grep -qE '^ExecStart=.*PolarProxy' "${MODULE_DIR}/templates/polarproxy.service.tmpl"
}

@test "polarproxy.service template uses DynamicUser=yes (no static UID required)" {
    grep -qE '^DynamicUser=yes' "${MODULE_DIR}/templates/polarproxy.service.tmpl"
}

@test "polarproxy.service template hardening: NoNewPrivileges=yes (no setuid escape)" {
    grep -qE '^NoNewPrivileges=yes' "${MODULE_DIR}/templates/polarproxy.service.tmpl"
}

@test "polarproxy.service template hardening: ProtectSystem=strict (full root RO)" {
    grep -qE '^ProtectSystem=strict' "${MODULE_DIR}/templates/polarproxy.service.tmpl"
}

@test "polarproxy.service template hardening: ProtectHome=yes (no /home access)" {
    grep -qE '^ProtectHome=yes' "${MODULE_DIR}/templates/polarproxy.service.tmpl"
}

@test "polarproxy.service template hardening: PrivateTmp=yes (no /tmp pivot)" {
    grep -qE '^PrivateTmp=yes' "${MODULE_DIR}/templates/polarproxy.service.tmpl"
}

@test "polarproxy.service template ReadWritePaths covers the log dir (only writable namespace)" {
    grep -qE '^ReadWritePaths=@@LOG_DIR@@' "${MODULE_DIR}/templates/polarproxy.service.tmpl"
}

@test "polarproxy.service template carries all six substitution tokens (TLS+PCAP+CERTHTTP+LOG+CA+PASSWORD)" {
    grep -q '@@LISTEN_PORT@@'         "${MODULE_DIR}/templates/polarproxy.service.tmpl"
    grep -q '@@PCAP_OVER_IP_PORT@@'   "${MODULE_DIR}/templates/polarproxy.service.tmpl"
    grep -q '@@CERT_HTTP_FLAG@@'      "${MODULE_DIR}/templates/polarproxy.service.tmpl"
    grep -q '@@LOG_DIR@@'             "${MODULE_DIR}/templates/polarproxy.service.tmpl"
    grep -q '@@CA_PFX_PATH@@'         "${MODULE_DIR}/templates/polarproxy.service.tmpl"
    grep -q '@@CA_PFX_PASSWORD_OPT@@' "${MODULE_DIR}/templates/polarproxy.service.tmpl"
}

@test "polarproxy.service template auto-restarts on failure (operator-visible service contract)" {
    grep -qE '^Restart=on-failure' "${MODULE_DIR}/templates/polarproxy.service.tmpl"
}

@test "polarproxy.service template WantedBy=multi-user.target (boots into multi-user)" {
    grep -qE '^WantedBy=multi-user\.target' "${MODULE_DIR}/templates/polarproxy.service.tmpl"
}

@test "INVARIANT (polarproxy.service template After=network-online.target + Wants=network-online.target — startup-ordering contract)" {
    # Sister to brain-wide systemd-After+Wants ordering
    # INVARIANTs. PolarProxy is a TLS MITM that listens on a
    # TCP port and forwards to upstream HTTPS targets — both
    # endpoints require the network stack ready. After=
    # network-online.target alone is ordering-only (waits if
    # the target is in the boot transaction); Wants=
    # network-online.target is what pulls the target INTO the
    # boot transaction. Both directives are required together
    # OR the unit silently boots before networking is ready
    # on cold-boot and fails its first 5+ restart attempts.
    # Locks startup-ordering contract on the TLS-MITM substrate.
    grep -qE '^After=.*network-online\.target' "${MODULE_DIR}/templates/polarproxy.service.tmpl"
    grep -qE '^Wants=.*network-online\.target' "${MODULE_DIR}/templates/polarproxy.service.tmpl"
}

@test "INVARIANT (polarproxy.service template carries RestartSec — restart-storm dampener for systemd-supervised TLS-MITM)" {
    # Sister to brain-wide systemd RestartSec INVARIANTs
    # (scheduler, integrity-sentinel). PolarProxy is a TLS MITM
    # listener; if the binary fails to start (missing CA cert,
    # bad config) systemd would re-fork it in tight loop without
    # RestartSec — exhausting the system with CPU + log spam.
    # The Restart=on-failure directive (already locked above)
    # MUST be paired with a RestartSec= delay so failed-start
    # cascades pace at human-tractable rate (1s+) for operator
    # MTTR. Locks restart-storm-cap contract on the TLS-MITM
    # substrate.
    grep -qE '^RestartSec=' "${MODULE_DIR}/templates/polarproxy.service.tmpl"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. polarproxy manifest declares install + the TLS+
    # PCAP+CERTHTTP+LOG+CA+PASSWORD substitution gating the
    # resolver enforces; malformed manifest wedges the TLS-MITM
    # service template render. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # polarproxy substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'polarproxy', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: polarproxy installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # polarproxy writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the polarproxy
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/polarproxy/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(apt|pam\.d|security|systemd|sysctl\.d|modprobe\.d|polarproxy|rkhunter|rpcbind|inetd)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(apt|pam\.d|security|systemd|sysctl\.d|modprobe\.d|polarproxy|rkhunter|rpcbind|inetd).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # polarproxy install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the polarproxy lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/polarproxy/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the polarproxy substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
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
    # the polarproxy requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
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
