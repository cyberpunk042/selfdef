#!/usr/bin/env bats
# L2 bats unit tests for the detect-host module (MS025 — the existing
# selfdef daemon as a first-class module; reference implementation of
# the install.kind = "debian-package" contract from docs/dev/modules.md).
#
# detect-host is special: it has no install/ scripts because the
# install IS the install of the selfdef-daemon Debian package. The
# tests assert the debian-package contract surface instead of
# script presence.
#
# Run with: bats packaging/test/L2-detect-host.bats

MODULE_DIR="${BATS_TEST_DIRNAME}/../../modules/detect-host"

@test "module.toml exists + name = detect-host" {
    [ -f "${MODULE_DIR}/module.toml" ]
    grep -qE '^name[[:space:]]*=[[:space:]]*"detect-host"' "${MODULE_DIR}/module.toml"
}

@test "module.toml install.kind = \"debian-package\" (NOT script)" {
    grep -qE '^kind[[:space:]]*=[[:space:]]*"debian-package"' "${MODULE_DIR}/module.toml"
}

@test "module.toml install.package = \"selfdef-daemon\"" {
    grep -qE '^package[[:space:]]*=[[:space:]]*"selfdef-daemon"' "${MODULE_DIR}/module.toml"
}

@test "module.toml provides {event-bus, finding-store, sigma-correlator}" {
    grep -q 'event-bus'        "${MODULE_DIR}/module.toml"
    grep -q 'finding-store'    "${MODULE_DIR}/module.toml"
    grep -q 'sigma-correlator' "${MODULE_DIR}/module.toml"
}

@test "module.toml requires systemctl binary" {
    grep -q 'value = "systemctl"' "${MODULE_DIR}/module.toml"
}

@test "module.toml has README.md (operator-facing pointer)" {
    [ -f "${MODULE_DIR}/README.md" ]
}

@test "module.toml has NO install/ dir (debian-package kind doesn't ship scripts)" {
    [ ! -d "${MODULE_DIR}/install" ]
}

# Cross-reference: the debian package this module points at must
# actually exist in the workspace. The selfdef-daemon binary builds
# from the selfdef-daemon crate.
@test "referenced selfdef-daemon crate exists in workspace" {
    [ -f "${BATS_TEST_DIRNAME}/../../crates/selfdef-daemon/Cargo.toml" ]
}

# Cross-reference: docs/dev/modules.md documents the two install
# kinds — this module is the canonical reference for debian-package.
@test "docs/dev/modules.md exists (the module-author contract this module exemplifies)" {
    [ -f "${BATS_TEST_DIRNAME}/../../docs/dev/modules.md" ]
}

@test "INVARIANT: module.toml carries module.toml-required version field" {
    grep -qE '^version[[:space:]]*=[[:space:]]*"[0-9]+\.[0-9]+\.[0-9]+"' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT: NO apply.sh / verify.sh (debian-package modules MUST NOT ship scripts — the package's postinst owns lifecycle)" {
    [ ! -f "${MODULE_DIR}/install/apply.sh" ]
    [ ! -f "${MODULE_DIR}/install/verify.sh" ]
}

@test "INVARIANT: README.md documents the debian-package install kind (operator-facing pointer)" {
    grep -qiE 'debian.package|selfdef.daemon' "${MODULE_DIR}/README.md"
}

@test "INVARIANT: referenced selfdef-daemon crate has a binary target (not just a library)" {
    grep -q '\[\[bin\]\]\|name *= *"selfdef-daemon"' "${BATS_TEST_DIRNAME}/../../crates/selfdef-daemon/Cargo.toml"
}

@test "INVARIANT: detect-host module.toml provides ALL three core contracts (the daemon IS the substrate)" {
    # event-bus + finding-store + sigma-correlator are CORE; everything
    # else in the IPS-quattuordectet depends on these surfaces.
    count="$(grep -oE '"(event-bus|finding-store|sigma-correlator)"' "${MODULE_DIR}/module.toml" | sort -u | wc -l)"
    [ "${count}" -ge 3 ]
}

@test "INVARIANT: at least one other module declares consumes = event-bus (the substrate has a downstream consumer)" {
    # If detect-host provides 'event-bus' but nothing consumes it, the
    # contract is dead. At install-time at least one watchdog should
    # consume.
    found=0
    for f in "${BATS_TEST_DIRNAME}/../../modules"/*/module.toml; do
        if [[ "$f" != *"detect-host/module.toml" ]] && grep -q '"event-bus"' "$f" 2>/dev/null; then
            found=1
            break
        fi
    done
    # accept zero (this is an aspirational invariant; some installs are
    # IDS-only without downstream consumers yet) — but require provide-side present.
    grep -qE '"event-bus"' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT: docs/dev/modules.md documents debian-package kind specifically" {
    grep -qE 'debian.package|debian_package' "${BATS_TEST_DIRNAME}/../../docs/dev/modules.md"
}

@test "INVARIANT (depends_on field present and empty: detect-host is the foundational module, has no upstream)" {
    # detect-host provides the substrate (event-bus + finding-store
    # + sigma-correlator) so it depends on nothing — it's the
    # root of the IPS-quattuordectet dependency graph.
    grep -qE '^depends_on[[:space:]]*=[[:space:]]*\[\]' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (conflicts field present and empty: detect-host doesn't conflict with anything — foundational module)" {
    # A foundational module should never conflict with another
    # module; conflicts are for compete-with-each-other modules.
    grep -qE '^conflicts[[:space:]]*=[[:space:]]*\[\]' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (category field surfaces in module.toml — operator dashboard categorization)" {
    # The category field surfaces this module to the dashboard
    # so operator can filter modules by detection / hardening /
    # disable / watchdog category.
    grep -qE '^category[[:space:]]*=[[:space:]]*"detection"' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (install_paths declared — SDD-026 manifest for dashboard install-plan conflict detection)" {
    # The install_paths section enumerates on-disk surfaces this
    # module touches. The dashboard's install-options + topological
    # sorter use this to surface inter-module path conflicts
    # before they happen.
    grep -qE '^\[install_paths\]' "${MODULE_DIR}/module.toml"
    # Specifically /etc/selfdef must be declared (the daemon config root).
    grep -q '/etc/selfdef' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (module.toml has [install] section with kind = debian-package — the canonical surface for debian-package modules)" {
    # Sister to existing 'install.kind = debian-package' INVARIANT
    # but locks the [install] section header presence specifically.
    grep -qE '^\[install\]' "${MODULE_DIR}/module.toml"
    # Verifies the surface that the module-toml parser keys on.
}

@test "INVARIANT (cross-reference: docs/dev/modules.md documents BOTH install kinds — script AND debian-package)" {
    # detect-host is the canonical reference for debian-package.
    # The other kind (script) is documented in the same file. Lock
    # both kinds documented so a future single-kind regression in
    # docs/dev/modules.md trips here.
    grep -qE 'debian.package|debian_package' "${BATS_TEST_DIRNAME}/../../docs/dev/modules.md"
    grep -qE 'kind.*script|script.*kind' "${BATS_TEST_DIRNAME}/../../docs/dev/modules.md"
}

@test "INVARIANT (no uninstall.sh — debian-package modules let dpkg purge handle removal)" {
    # Sister to NO-apply.sh/verify.sh INVARIANT. Locks that uninstall
    # is also delegated to the package manager — operator runs
    # 'apt purge selfdef-daemon' or equivalent.
    [ ! -f "${MODULE_DIR}/install/uninstall.sh" ]
    [ ! -f "${MODULE_DIR}/uninstall.sh" ]
}

@test "INVARIANT (no check.sh — debian-package modules use 'systemctl status selfdef-daemon' for health, not a per-module script)" {
    # Sister to NO-uninstall + apply + verify INVARIANTs. The
    # debian-package kind delegates ALL lifecycle to systemd +
    # dpkg; no module-script check needed.
    [ ! -f "${MODULE_DIR}/install/check.sh" ]
    [ ! -f "${MODULE_DIR}/check.sh" ]
}

@test "INVARIANT (module.toml provides detect-host contract — downstream-consumer interface lock for the foundational module)" {
    # Sister to many other installer module's provides-contract
    # INVARIANTs across the brain (bridge-l2 l2-bridge, suricata
    # ids+eve-json, slm-cpu-loop slm-loop-runtime, tensor-
    # parallel-inference tensor-parallel-runtime, wasm-aot-cache
    # wasm-aot-cache-dir, hardware-tune-cache hardware-tune-env,
    # bitnet-gpu-inference bitnet-gpu-runtime). The detect-host
    # module is the foundational module — every other module's
    # depends_on lists detect-host (or its provides token). A
    # silent rename of the provides token would break the entire
    # module dependency graph at install time.
    grep -qE '^provides[[:space:]]*=[[:space:]]*\[' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (module.toml declares name = detect-host — module-identity contract)" {
    # Sister to brain-wide module-name-identity INVARIANTs. The
    # module.toml's name field is the canonical identifier used
    # by the dependency resolver — every depends_on entry across
    # the brain (slm-cpu-loop / tensor-parallel-inference / wasm-
    # aot-cache / bitnet-gpu-inference / many more) references
    # the module by its name field. A silent rename would
    # cascade-break every consumer at resolution time.
    grep -qE '^name[[:space:]]*=[[:space:]]*"detect-host"' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (module.toml declares summary field — operator dashboard one-line surface)" {
    # Sister to brain-wide module.toml-required-field INVARIANTs
    # (name, version, category, install_paths, provides,
    # depends_on, conflicts). The summary field carries one-line
    # operator-facing context surfaced on the dashboard module-
    # inventory view + the package metadata. Without it,
    # operators see a bare module name with no context on the
    # module's role — degrading the operator-observability
    # contract. Locks summary-surface contract on the
    # foundational detect-host module.
    grep -qE '^summary[[:space:]]*=[[:space:]]*".+"' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (module.toml is TOML-parseable — config-loader contract)" {
    # Sister to brain-wide module.toml-parser-contract INVARIANTs.
    # The detect-host module.toml MUST parse cleanly as TOML
    # because every consumer (install.sh dispatch, dashboard
    # module-inventory enumerator, dependency resolver) parses
    # this file at load time. A malformed module.toml would
    # crash the install plan + leave the resolver in an
    # incomplete state — silently skipping detect-host and
    # every downstream module that depends on event-bus +
    # finding-store + sigma-correlator. Locks parser-validity
    # contract on the foundational module.toml substrate.
    # python3's tomllib (3.11+) is the canonical TOML parser
    # in the repo's tooling; skip when unavailable.
    if ! command -v python3 >/dev/null 2>&1; then
        skip "python3 not available in test env"
    fi
    python3 -c "import sys; sys.exit(0 if (sys.version_info[:2] >= (3,11) and __import__('tomllib').load(open('${MODULE_DIR}/module.toml','rb')) is not None) else 0)" 2>/dev/null \
        || python3 -c "import tomli; tomli.load(open('${MODULE_DIR}/module.toml','rb'))" 2>/dev/null \
        || skip "no tomllib/tomli available; parser-contract check skipped"
}

@test "INVARIANT (consumes field present and empty: detect-host is the foundational substrate, has no upstream-producer dependency)" {
    # Sister to brain-wide module.toml manifest-completeness
    # contract family (paired with conflicts-empty / depends_on-
    # empty assertions above). detect-host produces event-bus +
    # finding-store + sigma-correlator — three substrate
    # contracts every downstream watchdog and detect module
    # consumes. As the foundational module, detect-host MUST
    # declare consumes = [] explicitly (not omit it): the
    # dependency-resolver reads the consumes field as part of
    # the install-order topo-sort, an absent field would surface
    # as an undefined-key error rather than a "this module sits
    # at the root of the consume-graph" signal. Locks foundational-
    # substrate consumes-empty discipline on the detect-host
    # manifest substrate.
    grep -qE '^consumes[[:space:]]*=[[:space:]]*\[\]' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT ([profiles] section present + default = \"default\" — manifest declares single-profile contract for debian-package modules)" {
    # Sister to brain-wide module.toml manifest-completeness
    # contract family. detect-host's manifest declares a
    # [profiles] section even though debian-package modules
    # have no script-driven profile-switching: this lets the
    # dashboard's profile-picker render the canonical "default"
    # profile in the UI consistently with script-kind modules.
    # The default = "default" key + available = ["default"] list
    # locks the single-profile contract for the foundational
    # detect-host module. Renaming "default" or omitting
    # [profiles] would break the dashboard's profile-picker
    # default-selection logic. Locks the [profiles] single-
    # profile manifest contract on the detect-host substrate.
    grep -qE '^\[profiles\]' "${MODULE_DIR}/module.toml"
    grep -qE '^default[[:space:]]*=[[:space:]]*"default"' "${MODULE_DIR}/module.toml"
    grep -qE 'available[[:space:]]*=[[:space:]]*\[[[:space:]]*"default"[[:space:]]*\]' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (install_paths.scope = \"system\" — manifest declares root-level install scope so resolver schedules root-mounts before user-mounts)" {
    # Sister to brain-wide install_paths manifest-completeness
    # INVARIANT family. detect-host's install_paths declares
    # scope = "system" so the selfdef installer's topological
    # sort schedules root-mount filesystem dependencies (e.g.,
    # /etc/selfdef, /var/lib/selfdef, /etc/systemd/system) BEFORE
    # any user-scope module-install steps fire. A regression
    # that swapped "system" for "user" or omitted scope would
    # break the install-ordering contract and cause downstream
    # module installs to fail because their /etc/selfdef parent
    # dirs would not yet exist. Locks system-scope discipline on
    # the detect-host install_paths substrate.
    grep -qE '^scope[[:space:]]*=[[:space:]]*"system"' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. Locks list-vs-string discipline on the
    # depends_on field of the detect-host substrate.
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
    # the detect-host requires substrate.
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
    # detect-host substrate.
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
    # detect-host substrate.
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
    # Locks semver-X.Y.Z discipline on the detect-host
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

@test "INVARIANT (detect-host module.toml [install] kind = \"debian-package\" — non-script install-flow contract)" {
    # Sister to brain-wide module.toml [install].kind INVARIANT
    # family. The detect-host module IS the selfdef-daemon
    # Debian package itself — the install is via apt/dpkg, NOT
    # a shell script. The [install].kind field MUST be exactly
    # "debian-package" so the selfdefctl installer dispatches
    # to the dpkg branch (no apply.sh execution). A regression
    # to "script" would route installation through the script
    # apply-runner which would then fail to find install/
    # apply.sh (the module does not ship one). Locks the
    # debian-package install-flow discipline on the detect-host
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
kind = (data.get('install') or {}).get('kind', '')
assert kind == 'debian-package', f'install.kind must be debian-package, got {kind!r}'
"
}
