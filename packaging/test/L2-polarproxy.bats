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

@test "INVARIANT (module.toml summary field present + non-empty — operator-dashboard one-line description contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks summary-present discipline on the
    # polarproxy substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
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
    # polarproxy substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
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
    # Locks semver-X.Y.Z discipline on the polarproxy
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (polarproxy module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the polarproxy module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
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

@test "INVARIANT (polarproxy module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the polarproxy module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
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

@test "INVARIANT (polarproxy module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the polarproxy
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
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

@test "INVARIANT (polarproxy module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for polarproxy is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the polarproxy substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (polarproxy module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the polarproxy install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
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

@test "INVARIANT (polarproxy module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the polarproxy requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
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

@test "INVARIANT (polarproxy module.toml name field matches directory name — canonical-naming alignment contract)" {
    # Sister to brain-wide module.toml name INVARIANT family.
    # The name field MUST match the parent directory name so
    # the selfdef installer can resolve modules/<slug>/
    # module.toml by name field alone (without re-reading
    # parent-dir name). A regression where module.toml name
    # = "foo" lives under modules/bar/ would break the
    # resolver's path-by-name canonical lookup. Locks the
    # name-matches-dir discipline on the polarproxy substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
n = data.get('name', '')
assert n == 'polarproxy', f'name must match dir, got {n!r}'
"
}

@test "INVARIANT (polarproxy module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (polarproxy module.toml provides field present as TOML list of strings — capability-export contract)" {
    # Sister to brain-wide module.toml provides INVARIANT family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list), f'provides must be TOML list, got {type(p).__name__}'
"
}

@test "INVARIANT (polarproxy module.toml conflicts field present as TOML list — mutual-exclusion contract)" {
    # Sister to brain-wide module.toml conflicts INVARIANT family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('conflicts')
assert isinstance(c, list), f'conflicts must be TOML list (may be empty), got {type(c).__name__}'
"
}

@test "INVARIANT (polarproxy module.toml depends_on field present as TOML list — module-dependency-resolver contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = data.get('depends_on')
assert isinstance(d, list), f'depends_on must be TOML list (may be empty), got {type(d).__name__}'
"
}

@test "INVARIANT (polarproxy module.toml consumes field present as TOML list — capability-consumer contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('consumes')
assert isinstance(c, list), f'consumes must be TOML list, got {type(c).__name__}'
"
}

@test "INVARIANT (polarproxy module.toml summary field present + non-empty — module-doc-trail contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert s, f'summary must be non-empty, got {s!r}'
"
}

@test "INVARIANT (polarproxy module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (polarproxy install scripts (apply/check/uninstall) all exist as files — script-file existence contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/polarproxy/install"
    [ -d "${inst_dir}" ]
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (polarproxy README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/polarproxy/README.md"
    [ -f "${readme}" ]
}


@test "INVARIANT (polarproxy install/apply.sh is executable (mode includes +x) — script-runnable contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/polarproxy/install/apply.sh"
    [ -x "${apply}" ]
}

@test "INVARIANT (polarproxy install/check.sh exists as file — check-script existence contract)" {
    [ -f "${BATS_TEST_DIRNAME}/../../modules/polarproxy/install/check.sh" ]
}

@test "INVARIANT (polarproxy install/check.sh is executable — script-runnable contract)" {
    [ -x "${BATS_TEST_DIRNAME}/../../modules/polarproxy/install/check.sh" ]
}

@test "INVARIANT (polarproxy install/uninstall.sh exists as file — uninstall-script existence contract)" {
    [ -f "${BATS_TEST_DIRNAME}/../../modules/polarproxy/install/uninstall.sh" ]
}

@test "INVARIANT (polarproxy install/uninstall.sh is executable — script-runnable contract)" {
    [ -x "${BATS_TEST_DIRNAME}/../../modules/polarproxy/install/uninstall.sh" ]
}

@test "INVARIANT (polarproxy install scripts apply+check+uninstall all are executable — 3-script-runnable contract)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/polarproxy/install"
    [ -x "${inst}/apply.sh" ]
    [ -x "${inst}/check.sh" ]
    [ -x "${inst}/uninstall.sh" ]
}

@test "INVARIANT (polarproxy install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/polarproxy/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (polarproxy install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/polarproxy/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (polarproxy install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/polarproxy/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (polarproxy install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/polarproxy/install/apply.sh"
    [ -s "${apply}" ]
}

@test "INVARIANT (polarproxy install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/polarproxy/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (polarproxy install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/polarproxy/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (polarproxy module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict)
"
}

@test "INVARIANT (polarproxy module.toml install apply path verified via tomllib parse — 69-cadence-cycle apply contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ap = (data.get('install') or {}).get('apply', '')
assert ap == 'install/apply.sh'
"
}

@test "INVARIANT (polarproxy module.toml install check path verified via tomllib parse — 70-cadence-cycle check contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ch = (data.get('install') or {}).get('check', '')
assert ch == 'install/check.sh'
"
}

@test "INVARIANT (polarproxy module.toml exists at canonical path modules/polarproxy/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/polarproxy/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (polarproxy module dir is at canonical path modules/polarproxy/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/polarproxy"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (polarproxy install dir exists at modules/polarproxy/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/polarproxy/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (polarproxy install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/polarproxy/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (polarproxy install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/polarproxy/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}
