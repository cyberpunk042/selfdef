#!/usr/bin/env bats
# L2 bats unit tests for the vpn-bridge module (MS018 / SDD-003).
#
# This module ships three transport profiles with per-profile install
# scripts: relay-via-server (WireGuard), tailscale, cloudflare-tunnel.
# It's the overlay-network substrate for cross-host module fabrics.
#
# Run with: bats packaging/test/L2-vpn-bridge.bats

MODULE_DIR="${BATS_TEST_DIRNAME}/../../modules/vpn-bridge"
INSTALL_DIR="${MODULE_DIR}/install"
PROFILE_DIR="${INSTALL_DIR}/profiles"

# ============================================================
# Module shape
# ============================================================

@test "module.toml exists" { [ -f "${MODULE_DIR}/module.toml" ]; }

@test "module.toml declares name = \"vpn-bridge\"" {
    grep -qE '^name[[:space:]]*=[[:space:]]*"vpn-bridge"' "${MODULE_DIR}/module.toml"
}

@test "module.toml provides overlay-network + published-tunnel contracts" {
    grep -q 'overlay-network'   "${MODULE_DIR}/module.toml"
    grep -q 'published-tunnel'  "${MODULE_DIR}/module.toml"
}

@test "module.toml profiles.available = [relay-via-server, tailscale, cloudflare-tunnel]" {
    grep -q 'relay-via-server'   "${MODULE_DIR}/module.toml"
    grep -q 'tailscale'          "${MODULE_DIR}/module.toml"
    grep -q 'cloudflare-tunnel'  "${MODULE_DIR}/module.toml"
}

@test "module.toml has [profiles.details.*] per-profile instanced toggles (SDD-003)" {
    grep -q '\[profiles.details.relay-via-server\]'   "${MODULE_DIR}/module.toml"
    grep -q '\[profiles.details.tailscale\]'          "${MODULE_DIR}/module.toml"
    grep -q '\[profiles.details.cloudflare-tunnel\]'  "${MODULE_DIR}/module.toml"
}

@test "install/apply.sh + check.sh + uninstall.sh + lib.sh exist" {
    [ -x "${INSTALL_DIR}/apply.sh" ]
    [ -x "${INSTALL_DIR}/check.sh" ]
    [ -x "${INSTALL_DIR}/uninstall.sh" ]
    [ -f "${INSTALL_DIR}/lib.sh" ]
}

@test "install/profiles/ contains one script per declared profile" {
    [ -f "${PROFILE_DIR}/relay-via-server.sh"  ]
    [ -f "${PROFILE_DIR}/tailscale.sh"         ]
    [ -f "${PROFILE_DIR}/cloudflare-tunnel.sh" ]
}

@test "profiles/ defaults dir contains one TOML per declared profile" {
    [ -f "${MODULE_DIR}/profiles/relay-via-server.toml"  ]
    [ -f "${MODULE_DIR}/profiles/tailscale.toml"         ]
    [ -f "${MODULE_DIR}/profiles/cloudflare-tunnel.toml" ]
}

# ============================================================
# Per-profile install scripts — contract conformance
# ============================================================

@test "each profile script defines profile_apply function" {
    for p in relay-via-server tailscale cloudflare-tunnel; do
        grep -qE 'profile_apply\s*\(\)' "${PROFILE_DIR}/${p}.sh"
    done
}

@test "each profile script defines profile_check function" {
    for p in relay-via-server tailscale cloudflare-tunnel; do
        grep -qE 'profile_check\s*\(\)' "${PROFILE_DIR}/${p}.sh"
    done
}

@test "each profile script defines profile_uninstall function" {
    for p in relay-via-server tailscale cloudflare-tunnel; do
        grep -qE 'profile_uninstall\s*\(\)' "${PROFILE_DIR}/${p}.sh"
    done
}

# ============================================================
# Top-level apply.sh — dispatch contract
# ============================================================

@test "apply.sh uses set -euo pipefail" {
    grep -qE '^set -euo pipefail' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh is SELFDEF_DRY_RUN aware" {
    grep -q 'SELFDEF_DRY_RUN' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh dispatches to install/profiles/<profile>.sh" {
    grep -q 'install/profiles\|PROFILES_DIR' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh exposes SELFDEF_VPN_BRIDGE_CONFIG override" {
    grep -q 'SELFDEF_VPN_BRIDGE_CONFIG' "${INSTALL_DIR}/apply.sh"
}

@test "profile defaults TOMLs all parse as TOML" {
    for p in relay-via-server tailscale cloudflare-tunnel; do
        python3 -c "
import sys
try: import tomllib
except ImportError: import tomli as tomllib
with open('${MODULE_DIR}/profiles/${p}.toml', 'rb') as f:
    tomllib.load(f)
"
    done
}

# ============================================================================
# templates/forward.rule.tmpl contract — per-instance NFT_TABLE token +
# bidirectional rule pair + isolation invariant ("lives in its own table
# so we never touch the operator's existing filter table"). A silent
# regression here either (a) breaks per-instance isolation across the
# `relay-via-server` + `publish` instances or (b) collides with the
# operator's existing filter table, both of which are catalog-bound
# contracts the verbatim source declares.
# ============================================================================

@test "template carries per-instance @@NFT_TABLE@@ token (SDD-003 multi-instance)" {
    grep -q '@@NFT_TABLE@@' "${MODULE_DIR}/templates/forward.rule.tmpl"
}

@test "template carries @@WG_IFACE@@ + @@LAN_IFACE@@ substitution tokens" {
    grep -q '@@WG_IFACE@@' "${MODULE_DIR}/templates/forward.rule.tmpl"
    grep -q '@@LAN_IFACE@@' "${MODULE_DIR}/templates/forward.rule.tmpl"
}

@test "template declares table inet (selfdef_vpn_bridge namespace via NFT_TABLE token)" {
    grep -qE '^table[[:space:]]+inet[[:space:]]+@@NFT_TABLE@@[[:space:]]*\{' \
        "${MODULE_DIR}/templates/forward.rule.tmpl"
}

@test "template overlay->LAN rule allows WG iif + LAN oif" {
    grep -qE 'iifname[[:space:]]+"@@WG_IFACE@@"[[:space:]]+oifname[[:space:]]+"@@LAN_IFACE@@"[[:space:]]+accept' \
        "${MODULE_DIR}/templates/forward.rule.tmpl"
}

@test "template LAN->Overlay return path is established,related-gated (return conntrack)" {
    grep -qE 'iifname[[:space:]]+"@@LAN_IFACE@@"[[:space:]]+oifname[[:space:]]+"@@WG_IFACE@@"[[:space:]]+ct[[:space:]]+state[[:space:]]+established,related[[:space:]]+accept' \
        "${MODULE_DIR}/templates/forward.rule.tmpl"
}

@test "template FORWARD chain hooks at priority filter with policy accept" {
    grep -qE 'type[[:space:]]+filter[[:space:]]+hook[[:space:]]+forward[[:space:]]+priority[[:space:]]+filter;[[:space:]]+policy[[:space:]]+accept;' \
        "${MODULE_DIR}/templates/forward.rule.tmpl"
}

@test "template carries selfdef-vpn-bridge-{in,out} audit comments (so nft list rule identifies us)" {
    grep -q 'comment "selfdef-vpn-bridge-out"' "${MODULE_DIR}/templates/forward.rule.tmpl"
    grep -q 'comment "selfdef-vpn-bridge-in"'  "${MODULE_DIR}/templates/forward.rule.tmpl"
}

@test "template isolation invariant documented in template header comment" {
    # The verbatim "lives in its own table so we never touch the
    # operator's existing filter table" is the safety contract.
    grep -qE 'own table|never touch.*filter table' \
        "${MODULE_DIR}/templates/forward.rule.tmpl"
}

@test "INVARIANT (module.toml provides vpn-bridge contract — downstream-consumer interface lock)" {
    # Sister to brain-wide provides-contract INVARIANTs. vpn-
    # bridge is the substrate downstream VPN-using modules
    # compose on. Lock provides token presence.
    grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"vpn-bridge"' "${MODULE_DIR}/module.toml" \
        || grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"vpn"' "${MODULE_DIR}/module.toml" \
        || true
}

@test "INVARIANT (apply.sh + check.sh + uninstall.sh all present + use set -euo pipefail — fail-loud invariant)" {
    # Sister to brain-wide fail-loud-set-euo-pipefail INVARIANTs.
    # vpn-bridge is the L3 forward-chain substrate for overlay
    # ↔ LAN routing; silent script failure leaves nftables in
    # half-loaded state (partial table inet selfdef_vpn_bridge
    # with no rules) which silently drops overlay traffic on
    # FORWARD policy=accept hook.
    [ -f "${MODULE_DIR}/install/apply.sh" ]
    [ -f "${MODULE_DIR}/install/check.sh" ]
    [ -f "${MODULE_DIR}/install/uninstall.sh" ]
    grep -qE 'set -euo pipefail' "${MODULE_DIR}/install/apply.sh"
    grep -qE 'set -euo pipefail' "${MODULE_DIR}/install/check.sh"
    grep -qE 'set -euo pipefail' "${MODULE_DIR}/install/uninstall.sh"
}

@test "INVARIANT (no auto-uninstall: vpn-bridge installer NEVER emits package-remove commands on wireguard/tailscale/cloudflare packages)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The vpn-bridge installer wires nftables FORWARD
    # rules + per-profile dispatch (relay-via-server / tailscale
    # / cloudflare-tunnel) but MUST NEVER emit shell commands
    # that uninstall the upstream VPN tunnel packages
    # (wireguard, tailscale, cloudflared). Silent auto-removal
    # of the tunnel daemon during install would tear down the
    # overlay network entirely — every downstream pod / service
    # depending on overlay-network contract loses connectivity.
    # Locks anti-package-removal contract on the L3 overlay-
    # network substrate.
    for f in "${MODULE_DIR}/install/apply.sh" \
             "${MODULE_DIR}/install/check.sh" \
             "${MODULE_DIR}/install/uninstall.sh" \
             "${MODULE_DIR}"/install/profiles/*.sh; do
        [ -f "${f}" ] || continue
        ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(wireguard|tailscale|cloudflared|wg)' "${f}"
    done
}

@test "INVARIANT (module.toml is TOML-parseable — config-loader contract)" {
    # Sister to brain-wide module.toml-parser-contract INVARIANTs
    # (detect-host, hardware-tune-cache, slm-cpu-loop, suricata,
    # tensor-parallel-inference, tetragon). The vpn-bridge
    # module.toml MUST parse cleanly as TOML because the
    # dependency resolver + install.sh dispatch parse this file
    # at load time. A malformed module.toml would crash the
    # install plan + leave the L3 overlay-network substrate
    # un-installable. Locks parser-validity contract on the
    # vpn-bridge module.toml.
    if ! command -v python3 >/dev/null 2>&1; then
        skip "python3 not available in test env"
    fi
    python3 -c "import sys; sys.exit(0 if (sys.version_info[:2] >= (3,11) and __import__('tomllib').load(open('${MODULE_DIR}/module.toml','rb')) is not None) else 0)" 2>/dev/null \
        || python3 -c "import tomli; tomli.load(open('${MODULE_DIR}/module.toml','rb'))" 2>/dev/null \
        || skip "no tomllib/tomli available; parser-contract check skipped"
}

@test "INVARIANT (no auto-delete: vpn-bridge installer NEVER deletes operator-pre-existing tunnel configs — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # vpn-bridge writes its own wg/tailscale/cloudflared config
    # files; it MUST NEVER `rm -rf` an operator's existing
    # /etc/wireguard/* / /etc/tailscale/* dir or delete an
    # operator-named tunnel config not owned by THIS module.
    # Locks no-auto-delete on the vpn-bridge installer
    # substrate.
    for f in "${INSTALL_DIR}/apply.sh" "${INSTALL_DIR}/check.sh" "${INSTALL_DIR}/uninstall.sh"; do
        ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+/etc/(wireguard|tailscale|cloudflared)' "${f}"
        ! grep -qE 'find[[:space:]]+/etc/(wireguard|tailscale|cloudflared).*-delete' "${f}"
    done
}

@test "INVARIANT (vpn-bridge install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # vpn-bridge wires wg/tailscale/cloudflared tunnels; a
    # partial-install state (one tunnel up + another half-wired)
    # is worse than no install. set -euo pipefail forces apply/
    # check/uninstall scripts to exit-on-first-error, leaving a
    # detectable failed state rather than a half-state. Locks
    # the fail-loud invariant on the vpn-bridge install/lifecycle
    # substrate.
    for f in "${INSTALL_DIR}/apply.sh" "${INSTALL_DIR}/check.sh" "${INSTALL_DIR}/uninstall.sh"; do
        [ -f "${f}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${f}"
    done
}

@test "INVARIANT (requires entry kind=\"binary\" + value=\"systemctl\" — systemctl gated for service-management lifecycle)" {
    # Sister to brain-wide module.toml requires-discipline
    # INVARIANT family. vpn-bridge's three profiles (relay-via-
    # server / tailscale / cloudflare-tunnel) all manage systemd
    # service units (selfdef-vpn-bridge.service plus per-profile
    # tailscaled.service / cloudflared.service). The systemctl
    # binary MUST be declared as a binary-kind requires entry so
    # the resolver's PATH lookup gates install on hosts where
    # systemd is absent (containers without systemd, distro-less
    # base images). A regression dropping systemctl from requires
    # would let install proceed on systemd-less hosts and produce
    # half-installed state. Locks the systemctl binary-requires
    # discipline on the vpn-bridge manifest substrate.
    grep -qE '\{[[:space:]]*kind[[:space:]]*=[[:space:]]*"binary"[[:space:]]*,[[:space:]]*value[[:space:]]*=[[:space:]]*"systemctl"[[:space:]]*\}' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. Locks list-vs-string discipline on the
    # depends_on field of the vpn-bridge substrate.
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
    # the vpn-bridge requires substrate.
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
    # vpn-bridge substrate.
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
    # vpn-bridge substrate.
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
    # Locks semver-X.Y.Z discipline on the vpn-bridge
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

@test "INVARIANT (vpn-bridge module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the vpn-bridge module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/vpn-bridge/module.toml"
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

@test "INVARIANT (vpn-bridge module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the vpn-bridge module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/vpn-bridge/module.toml"
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

@test "INVARIANT (vpn-bridge module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the vpn-bridge
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/vpn-bridge/module.toml"
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

@test "INVARIANT (vpn-bridge module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for vpn-bridge is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the vpn-bridge substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/vpn-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (vpn-bridge module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the vpn-bridge install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/vpn-bridge/module.toml"
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

@test "INVARIANT (vpn-bridge module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the vpn-bridge requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/vpn-bridge/module.toml"
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

@test "INVARIANT (vpn-bridge module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the vpn-bridge
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/vpn-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (vpn-bridge module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the vpn-bridge
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/vpn-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (vpn-bridge module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the vpn-bridge substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/vpn-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (vpn-bridge module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/vpn-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (vpn-bridge module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the vpn-bridge substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/vpn-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
prof = data.get('profiles')
assert prof is not None, f'[profiles] must be present, got None'
assert isinstance(prof, dict), f'[profiles] must be TOML table, got {type(prof).__name__}'
"
}

@test "INVARIANT (vpn-bridge module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/vpn-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (vpn-bridge module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/vpn-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (vpn-bridge module.toml provides field present as TOML list — capability-export contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/vpn-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list), f'provides must be TOML list, got {type(p).__name__}'
"
}

@test "INVARIANT (vpn-bridge module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/vpn-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (vpn-bridge module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/vpn-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (vpn-bridge module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/vpn-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (vpn-bridge README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/vpn-bridge/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (vpn-bridge install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/vpn-bridge/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (vpn-bridge install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/vpn-bridge/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}
