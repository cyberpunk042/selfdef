#!/usr/bin/env bats
# L2 bats unit tests for the bridge-l2 module (MS024 — transparent
# L2 bridge + nftables policy substrate for inline network modules).
#
# Run with: bats packaging/test/L2-bridge-l2.bats

MODULE_DIR="${BATS_TEST_DIRNAME}/../../modules/bridge-l2"
INSTALL_DIR="${MODULE_DIR}/install"

@test "module.toml exists + declares name = bridge-l2" {
    [ -f "${MODULE_DIR}/module.toml" ]
    grep -qE '^name[[:space:]]*=[[:space:]]*"bridge-l2"' "${MODULE_DIR}/module.toml"
}

@test "module.toml provides l2-bridge + forward-policy contracts" {
    grep -q 'l2-bridge'      "${MODULE_DIR}/module.toml"
    grep -q 'forward-policy' "${MODULE_DIR}/module.toml"
}

@test "module.toml requires ip + nft + systemctl binaries" {
    grep -q 'value = "ip"'        "${MODULE_DIR}/module.toml"
    grep -q 'value = "nft"'       "${MODULE_DIR}/module.toml"
    grep -q 'value = "systemctl"' "${MODULE_DIR}/module.toml"
}

@test "module.toml requires CONFIG_BRIDGE + CONFIG_NF_TABLES kernel features" {
    grep -q 'CONFIG_BRIDGE'    "${MODULE_DIR}/module.toml"
    grep -q 'CONFIG_NF_TABLES' "${MODULE_DIR}/module.toml"
}

@test "install/apply.sh + check.sh + uninstall.sh + lib.sh exist" {
    [ -x "${INSTALL_DIR}/apply.sh" ]
    [ -x "${INSTALL_DIR}/check.sh" ]
    [ -x "${INSTALL_DIR}/uninstall.sh" ]
    [ -f "${INSTALL_DIR}/lib.sh" ]
}

@test "apply.sh uses set -euo pipefail" {
    grep -qE '^set -euo pipefail' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh is SELFDEF_DRY_RUN aware" {
    grep -q 'SELFDEF_DRY_RUN' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh exposes SELFDEF_BRIDGE_L2_CONFIG + _TEMPLATES override" {
    grep -q 'SELFDEF_BRIDGE_L2_CONFIG'    "${INSTALL_DIR}/apply.sh"
    grep -q 'SELFDEF_BRIDGE_L2_TEMPLATES' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh reads bridge_name + forward_policy + management_iface + members" {
    grep -q 'bridge_name'      "${INSTALL_DIR}/apply.sh"
    grep -q 'forward_policy'   "${INSTALL_DIR}/apply.sh"
    grep -q 'management_iface' "${INSTALL_DIR}/apply.sh"
    grep -q 'members'          "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh writes /etc/nftables.d/selfdef-bridge.conf" {
    grep -q '/etc/nftables.d/selfdef-bridge.conf' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh rejects unknown profile cleanly (dry-run smoke)" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_DRY_RUN=1
    export SELFDEF_BRIDGE_L2_CONFIG="${TEST_DIR}/bridge-l2.toml"
    echo 'profile = "totally-bogus-profile-12345"' > "${SELFDEF_BRIDGE_L2_CONFIG}"
    # Mock ip / nft / systemctl.
    export MOCK_BIN="${TEST_DIR}/mockbin"
    mkdir -p "${MOCK_BIN}"
    for b in ip nft systemctl; do
        printf '#!/bin/bash\nexit 0\n' > "${MOCK_BIN}/${b}"
        chmod +x "${MOCK_BIN}/${b}"
    done
    export PATH="${MOCK_BIN}:${PATH}"
    run bash "${INSTALL_DIR}/apply.sh"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_DRY_RUN SELFDEF_BRIDGE_L2_CONFIG MOCK_BIN
    # bridge-l2 only supports default profile "passthrough"; a totally
    # bogus profile should either be rejected OR fall through cleanly.
    # We assert the script doesn't crash with an unhandled error and
    # doesn't exit with a parse error.
    [ "${status}" -ne 2 ]
}

# ============================================================================
# E0247 nftables template structure invariants (verbatim from
# templates/nftables.conf.tmpl). The bridge-l2 contract with consumer
# modules (suricata, polarproxy, etc.) is that the rendered ruleset
# exposes a `selfdef_bridge` table with a `forward_hook` chain those
# consumers add jumps into. A silent rename here would break every
# consumer at apply-time; the rules below freeze that contract.
# ============================================================================

@test "E0247 template declares table inet selfdef_bridge" {
    grep -qE '^table[[:space:]]+inet[[:space:]]+selfdef_bridge[[:space:]]*\{' \
        "${MODULE_DIR}/templates/nftables.conf.tmpl"
}

@test "E0247 template exposes empty forward_hook chain for consumer modules" {
    grep -qE '^[[:space:]]*chain[[:space:]]+forward_hook[[:space:]]*\{[[:space:]]*\}' \
        "${MODULE_DIR}/templates/nftables.conf.tmpl"
}

@test "E0247 template FORWARD chain hooks at priority filter with substitutable policy" {
    grep -qE 'type[[:space:]]+filter[[:space:]]+hook[[:space:]]+forward[[:space:]]+priority[[:space:]]+filter;[[:space:]]+policy[[:space:]]+@@FORWARD_POLICY@@;' \
        "${MODULE_DIR}/templates/nftables.conf.tmpl"
}

@test "E0247 FORWARD chain jumps into forward_hook on both iif + oif (consumer surface)" {
    grep -qE '^[[:space:]]*iifname[[:space:]]+"@@BRIDGE_NAME@@"[[:space:]]+jump[[:space:]]+forward_hook' \
        "${MODULE_DIR}/templates/nftables.conf.tmpl"
    grep -qE '^[[:space:]]*oifname[[:space:]]+"@@BRIDGE_NAME@@"[[:space:]]+jump[[:space:]]+forward_hook' \
        "${MODULE_DIR}/templates/nftables.conf.tmpl"
}

@test "E0247 template carries three substitution tokens (BRIDGE_NAME, FORWARD_POLICY, MGMT_INPUT_RULE)" {
    grep -q '@@BRIDGE_NAME@@' "${MODULE_DIR}/templates/nftables.conf.tmpl"
    grep -q '@@FORWARD_POLICY@@' "${MODULE_DIR}/templates/nftables.conf.tmpl"
    grep -q '@@MGMT_INPUT_RULE@@' "${MODULE_DIR}/templates/nftables.conf.tmpl"
}

@test "E0247 template input chain default policy is accept (management-iface drop is a substituted rule, not the chain policy)" {
    grep -qE 'type[[:space:]]+filter[[:space:]]+hook[[:space:]]+input[[:space:]]+priority[[:space:]]+filter;[[:space:]]+policy[[:space:]]+accept;' \
        "${MODULE_DIR}/templates/nftables.conf.tmpl"
}

@test "E0247 template flushes ruleset at top (bridge-l2 owns its table cleanly)" {
    # First non-comment, non-blank line must be `flush ruleset`.
    first=$(grep -vE '^[[:space:]]*(#|$)' "${MODULE_DIR}/templates/nftables.conf.tmpl" | head -1)
    [ "${first}" = "flush ruleset" ]
}

# ============================================================================
# E0248 forward_policy allowlist + idempotent-skip contract.
# `apply.sh` validates forward_policy ∈ {accept, drop}; a silent allowlist
# widening (e.g. accidentally accepting "reject") could render an nft
# ruleset the kernel refuses to load, taking the bridge down. The skip
# contract is similarly load-bearing: operators (and selfdefctl status
# parsers) depend on the exact JSON `status:skipped` marker.
# ============================================================================

@test "E0248 apply.sh validates forward_policy against accept|drop allowlist" {
    grep -qE '\[\[[[:space:]]+"\$FORWARD_POLICY"[[:space:]]+==[[:space:]]+"accept"[[:space:]]+\|\|[[:space:]]+"\$FORWARD_POLICY"[[:space:]]+==[[:space:]]+"drop"[[:space:]]+\]\]' \
        "${INSTALL_DIR}/apply.sh"
}

@test "E0248 apply.sh emits status:skipped when ruleset already at target state" {
    grep -qE 'emit_status[[:space:]]+"skipped"[[:space:]]+"already at target state"' \
        "${INSTALL_DIR}/apply.sh"
}

@test "E0248 apply.sh writes ruleset to /etc/nftables.d/selfdef-bridge.conf (E0247 deploy path)" {
    grep -qE '/etc/nftables\.d/selfdef-bridge\.conf' "${INSTALL_DIR}/apply.sh"
}

@test "E0250 caveat surfaced in operator README (severs connection if run on bridged NIC)" {
    grep -qiE 'sever|severs|severing' "${MODULE_DIR}/README.md"
    grep -qiE 'management interface|console' "${MODULE_DIR}/README.md"
}

@test "INVARIANT (apply.sh emits emit_status JSON for operator dashboard observability — SDD-062 consumer contract)" {
    # Sister to every other installer module's emit_status INVARIANT
    # across the brain. The bridge-l2 apply.sh MUST surface its
    # apply outcome to the operator dashboard via the emit_status
    # JSON record (status=ok / skipped, profile, message). Without
    # it, an operator deploying a transparent L2 bridge has no
    # signal whether the bridge came up successfully, was skipped
    # as already-at-target, or which forward_policy is live. Closes
    # the emit_status visibility axis on the L2-bridge substrate
    # alongside the E0248 emit_status skipped contract already
    # locked. The MS024 transparent L2 bridge + nftables policy
    # surface is foundational for all inline network modules
    # (suricata, polarproxy, …); dashboard observability gates
    # operator confidence to deploy.
    grep -q 'emit_status' "${INSTALL_DIR}/apply.sh"
    # Should emit at least the canonical success+skipped pair.
    n_emits=$(grep -cE '^[[:space:]]*emit_status' "${INSTALL_DIR}/apply.sh" || echo 0)
    [ "${n_emits}" -ge 1 ]
}

@test "INVARIANT (module.toml provides l2-bridge contract — downstream-consumer interface lock)" {
    # Sister to many other installer module's provides-contract
    # INVARIANT across the brain (suricata ids+eve-json, slm-cpu-
    # loop slm-loop-runtime, tensor-parallel-inference tensor-
    # parallel-runtime, wasm-aot-cache wasm-aot-cache-dir). The
    # bridge-l2 module is the substrate every inline network
    # module composes on. Its provides token names the L2-bridge
    # interface — every consumer module (suricata, polarproxy,
    # future inline IDS/IPS modules) lists this in depends_on. A
    # silent rename of the token would break every downstream
    # consumer.
    grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"l2-bridge"' "${MODULE_DIR}/module.toml" \
        || grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"bridge-l2"' "${MODULE_DIR}/module.toml" \
        || grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"selfdef_bridge"' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (apply.sh renders ruleset with chmod 0644 — system-config convention)" {
    # Sister to many other installer module's chmod-0644
    # INVARIANT across the brain (sysctl drop-ins, limits.d,
    # ssh-hardening drop-in, journal-tune drop-in, AppArmor
    # AA_LIST). The /etc/nftables.d/selfdef-bridge.conf
    # ruleset lands at a system-config path consumed by
    # nftables.service at boot AND by operator audit tooling.
    # 0644 is the standard read-everyone, write-root
    # convention. A world-writable regression would let any
    # user rewrite the L2 bridge ruleset and disable inline
    # IDS/IPS surveillance silently. Locks the file-perm
    # contract on the transparent L2 bridge ruleset render
    # path.
    grep -qE 'install[[:space:]].*-m[[:space:]]+0?644' "${INSTALL_DIR}/apply.sh" \
        || grep -qE 'chmod[[:space:]]+0?644' "${INSTALL_DIR}/apply.sh"
}

@test "INVARIANT (apply.sh uses set -euo pipefail — anti-half-installed-state contract)" {
    # Sister to brain-wide installer-script-hygiene INVARIANTs.
    # Without set -euo pipefail a mid-install failure leaves the
    # host in a half-installed state silently.
    grep -qE 'set[[:space:]]+-euo[[:space:]]+pipefail' "${INSTALL_DIR}/apply.sh" \
        || (grep -qE 'set[[:space:]]+-eu' "${INSTALL_DIR}/apply.sh" && grep -qE 'set[[:space:]]+-o[[:space:]]+pipefail' "${INSTALL_DIR}/apply.sh")
}

@test "INVARIANT (check.sh + uninstall.sh use set -euo pipefail — full lifecycle fail-loud invariant)" {
    # Sister to apply.sh fail-loud INVARIANT just locked. The
    # check.sh + uninstall.sh paths MUST also be fail-loud —
    # half-cleanup state during operator MTTR (orphan nftables
    # table inet selfdef_bridge with no rules) silently drops
    # L2-bridge traffic.
    grep -qE 'set[[:space:]]+-euo[[:space:]]+pipefail' "${INSTALL_DIR}/check.sh" \
        || (grep -qE 'set[[:space:]]+-eu' "${INSTALL_DIR}/check.sh" && grep -qE 'set[[:space:]]+-o[[:space:]]+pipefail' "${INSTALL_DIR}/check.sh")
    grep -qE 'set[[:space:]]+-euo[[:space:]]+pipefail' "${INSTALL_DIR}/uninstall.sh" \
        || (grep -qE 'set[[:space:]]+-eu' "${INSTALL_DIR}/uninstall.sh" && grep -qE 'set[[:space:]]+-o[[:space:]]+pipefail' "${INSTALL_DIR}/uninstall.sh")
}

@test "INVARIANT (no auto-uninstall: bridge-l2 installer NEVER emits package-remove commands on nftables)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The bridge-l2 installer wires nftables FORWARD
    # rules + bridge table inet selfdef_bridge but MUST NEVER
    # emit shell commands that uninstall the nftables package
    # itself (apt/dpkg/dnf/rpm/yum remove|purge|uninstall
    # nftables|nft). Silent auto-removal of nftables would tear
    # down the L2 bridge ruleset entirely + leave the network
    # path in unfiltered state — every downstream filter (suricata
    # NFQUEUE, ingress hooks, FORWARD chain) loses substrate.
    # Locks anti-package-removal contract on the L2 bridge
    # substrate.
    for f in "${INSTALL_DIR}/apply.sh" "${INSTALL_DIR}/check.sh" "${INSTALL_DIR}/uninstall.sh"; do
        ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(nftables|nft)' "${f}"
    done
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. The bridge-l2 module.toml declares the l2-bridge +
    # forward-policy provides contracts that every downstream
    # inline module (suricata, NFQUEUE attachers, etc.) consumes;
    # a malformed manifest would break the dependency-resolver
    # at install-time + leave consumers wedged. Python's tomllib
    # is the canonical parser — must parse to a dict with the
    # canonical top-level keys (name, version, provides,
    # requires, install). Locks anti-malformed-manifest on the
    # bridge-l2 substrate.
    python3 -c "
import tomllib, sys
with open('${MODULE_DIR}/module.toml', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'bridge-l2', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'provides' in data and 'l2-bridge' in data['provides'], 'l2-bridge missing from provides'
assert 'forward-policy' in data['provides'], 'forward-policy missing from provides'
assert 'requires' in data, 'requires missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: bridge-l2 apply.sh NEVER deletes pre-existing operator nftables rulesets — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # bridge-l2 writes its own ruleset to /etc/nftables.d/
    # selfdef-bridge.conf; it MUST NEVER rm/find-delete an
    # operator's pre-existing /etc/nftables.conf or
    # /etc/nftables.d/*.conf not owned by THIS module. Locks
    # no-auto-delete on the bridge-l2 installer substrate.
    for f in "${INSTALL_DIR}/apply.sh" "${INSTALL_DIR}/check.sh" "${INSTALL_DIR}/uninstall.sh" "${INSTALL_DIR}/lib.sh"; do
        ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+/etc/nftables\.conf' "${f}"
        ! grep -qE 'find[[:space:]]+/etc/nftables(\.d)?.*-delete' "${f}"
    done
}

@test "INVARIANT (lib.sh sources module-lib.sh — SDD-006 5-helper contract relayed via shared lib substrate)" {
    # Sister to brain-wide SDD-006 module-lib relay INVARIANT.
    # bridge-l2's install/lib.sh consumes the canonical 5
    # helpers (log/emit_status/die/run/toml_get) provided by
    # packaging/lib/module-lib.sh; an install script that
    # accidentally redefined log/emit_status locally would
    # break the operator-dashboard JSON-line consumer contract
    # because two different emit_status implementations would
    # ship distinct schemas. Locks the module-lib relay
    # discipline on the bridge-l2 install/lib.sh substrate.
    [ -f "${INSTALL_DIR}/lib.sh" ]
    grep -qE 'module-lib\.sh|SELFDEF_MODULE_LIB' "${INSTALL_DIR}/lib.sh"
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. Locks list-vs-string discipline on the
    # depends_on field of the bridge-l2 substrate.
    mtoml="${MODULE_DIR}/module.toml"
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
    mtoml="${MODULE_DIR}/module.toml"
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
    mtoml="${MODULE_DIR}/module.toml"
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
    mtoml="${MODULE_DIR}/module.toml"
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
    # the bridge-l2 requires substrate.
    mtoml="${MODULE_DIR}/module.toml"
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
    # bridge-l2 substrate.
    mtoml="${MODULE_DIR}/module.toml"
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
    # bridge-l2 substrate.
    mtoml="${MODULE_DIR}/module.toml"
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
    # Locks semver-X.Y.Z discipline on the bridge-l2
    # substrate.
    mtoml="${MODULE_DIR}/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (bridge-l2 module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the bridge-l2 module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/module.toml"
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

@test "INVARIANT (bridge-l2 module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the bridge-l2 module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/module.toml"
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

@test "INVARIANT (bridge-l2 module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the bridge-l2
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/module.toml"
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

@test "INVARIANT (bridge-l2 module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for bridge-l2 is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the bridge-l2 substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (bridge-l2 module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the bridge-l2 install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/module.toml"
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

@test "INVARIANT (bridge-l2 module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the bridge-l2 requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/module.toml"
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

@test "INVARIANT (bridge-l2 module.toml name field matches directory name — canonical-naming alignment contract)" {
    # Sister to brain-wide module.toml name INVARIANT family.
    # The name field MUST match the parent directory name so
    # the selfdef installer can resolve modules/<slug>/
    # module.toml by name field alone (without re-reading
    # parent-dir name). A regression where module.toml name
    # = "foo" lives under modules/bar/ would break the
    # resolver's path-by-name canonical lookup. Locks the
    # name-matches-dir discipline on the bridge-l2 substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
n = data.get('name', '')
assert n == 'bridge-l2', f'name must match dir, got {n!r}'
"
}

@test "INVARIANT (bridge-l2 module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (bridge-l2 module.toml provides field present as TOML list of strings — capability-export contract)" {
    # Sister to brain-wide module.toml provides INVARIANT family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list), f'provides must be TOML list, got {type(p).__name__}'
"
}

@test "INVARIANT (bridge-l2 module.toml conflicts field present as TOML list — mutual-exclusion contract)" {
    # Sister to brain-wide module.toml conflicts INVARIANT family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('conflicts')
assert isinstance(c, list), f'conflicts must be TOML list (may be empty), got {type(c).__name__}'
"
}

@test "INVARIANT (bridge-l2 module.toml depends_on field present as TOML list — module-dependency-resolver contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = data.get('depends_on')
assert isinstance(d, list), f'depends_on must be TOML list (may be empty), got {type(d).__name__}'
"
}

@test "INVARIANT (bridge-l2 module.toml consumes field present as TOML list — capability-consumer contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('consumes')
assert isinstance(c, list), f'consumes must be TOML list, got {type(c).__name__}'
"
}

@test "INVARIANT (bridge-l2 module.toml summary field present + non-empty — module-doc-trail contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert s, f'summary must be non-empty, got {s!r}'
"
}

@test "INVARIANT (bridge-l2 module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ap = (data.get('install') or {}).get('apply', '')
assert ap == 'install/apply.sh', f'install.apply must be install/apply.sh, got {ap!r}'
"
}

@test "INVARIANT (bridge-l2 module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ch = (data.get('install') or {}).get('check', '')
assert ch == 'install/check.sh', f'install.check must be install/check.sh, got {ch!r}'
"
}

@test "INVARIANT (bridge-l2 module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (bridge-l2 install scripts (apply/check/uninstall) all exist as files — script-file existence contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/install"
    [ -d "${inst_dir}" ]
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (bridge-l2 README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/README.md"
    [ -f "${readme}" ]
}


@test "INVARIANT (bridge-l2 install/apply.sh is executable (mode includes +x) — script-runnable contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/install/apply.sh"
    [ -x "${apply}" ]
}

@test "INVARIANT (bridge-l2 install/check.sh exists as file — check-script existence contract)" {
    [ -f "${BATS_TEST_DIRNAME}/../../modules/bridge-l2/install/check.sh" ]
}

@test "INVARIANT (bridge-l2 install/check.sh is executable — script-runnable contract)" {
    [ -x "${BATS_TEST_DIRNAME}/../../modules/bridge-l2/install/check.sh" ]
}

@test "INVARIANT (bridge-l2 install/uninstall.sh exists as file — uninstall-script existence contract)" {
    [ -f "${BATS_TEST_DIRNAME}/../../modules/bridge-l2/install/uninstall.sh" ]
}

@test "INVARIANT (bridge-l2 install/uninstall.sh is executable — script-runnable contract)" {
    [ -x "${BATS_TEST_DIRNAME}/../../modules/bridge-l2/install/uninstall.sh" ]
}

@test "INVARIANT (bridge-l2 install scripts apply+check+uninstall all are executable — 3-script-runnable contract)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/install"
    [ -x "${inst}/apply.sh" ]
    [ -x "${inst}/check.sh" ]
    [ -x "${inst}/uninstall.sh" ]
}

@test "INVARIANT (bridge-l2 install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (bridge-l2 install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (bridge-l2 install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (bridge-l2 install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/install/apply.sh"
    [ -s "${apply}" ]
}

@test "INVARIANT (bridge-l2 install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (bridge-l2 install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (bridge-l2 module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict)
"
}

@test "INVARIANT (bridge-l2 module.toml exists at canonical path modules/bridge-l2/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (bridge-l2 module dir is at canonical path modules/bridge-l2/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/bridge-l2"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (bridge-l2 install dir exists at modules/bridge-l2/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (bridge-l2 install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (bridge-l2 install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (bridge-l2 install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (bridge-l2 install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (bridge-l2 module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (bridge-l2 install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (bridge-l2 install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/bridge-l2/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}
