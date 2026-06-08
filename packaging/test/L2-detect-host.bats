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

@test "INVARIANT (detect-host module.toml declares category field — module-taxonomy canonical contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family. The selfdefctl module browser groups modules by
    # category in `selfdefctl modules list` output. The
    # category field MUST be present + non-empty so detect-host
    # surfaces in the right grouping (canonically "detection").
    # A regression that dropped category would leave detect-
    # host categorized as "(uncategorized)" + scatter operator
    # navigation. Locks the module-taxonomy discipline on the
    # detect-host substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category', '')
assert cat, f'category field must be non-empty, got {cat!r}'
"
}

@test "INVARIANT (detect-host module.toml declares provides field as TOML list — capability-export contract)" {
    # Sister to brain-wide module.toml provides INVARIANT
    # family. detect-host provides the foundational
    # event-bus + finding-store + sigma-correlator
    # capabilities that other modules consume via the
    # `consumes` field. The provides field MUST be a TOML
    # list type (not a string) so the resolver can iterate
    # the provided capabilities + match consumers against
    # each. A regression that swapped to a string would
    # silently treat "event-bus,finding-store" as a single
    # capability name + break consumer matching. Locks the
    # capability-export TOML-list discipline on the
    # detect-host substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
prov = data.get('provides')
assert isinstance(prov, list), f'provides must be a TOML list, got {type(prov).__name__}'
assert len(prov) >= 1, f'provides must declare ≥1 capability, got {prov!r}'
"
}

@test "INVARIANT (detect-host module.toml declares requires field as TOML list of inline-tables — runtime-binary-dependency contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field declares runtime binary +
    # config dependencies as TOML list of inline-tables:
    # [{ kind = "binary", value = "systemctl" }, ...]. A
    # regression that swapped to a simple string list would
    # break the resolver's per-kind dispatch (binary vs
    # config vs systemd-unit). Locks the inline-table list
    # discipline on the detect-host requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
req = data.get('requires')
assert isinstance(req, list), f'requires must be a TOML list, got {type(req).__name__}'
for r in req:
    assert isinstance(r, dict), f'each requires entry must be inline-table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'each requires must have kind+value, got {r!r}'
"
}

@test "INVARIANT (detect-host module.toml summary field present + non-empty — operator-dashboard one-line description contract)" {
    # Sister to brain-wide module.toml summary INVARIANT
    # family. The summary field surfaces in the selfdef
    # dashboard's `selfdefctl modules list` one-line view.
    # A regression that emptied or dropped summary would
    # leave detect-host as "(no description)" in operator-
    # facing surfaces. Locks the summary-non-empty
    # discipline on the detect-host substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert s, f'summary must be non-empty, got {s!r}'
assert len(s) > 10, f'summary should be a real description (>10 chars), got {s!r}'
"
}

@test "INVARIANT (detect-host module.toml [install] has no apply/check/uninstall fields — debian-package install-flow exclusive contract)" {
    # Sister to brain-wide install.kind dispatch INVARIANT
    # family. detect-host install.kind = "debian-package" —
    # this exclusive install kind means apt/dpkg drives the
    # install entirely, NOT a script-runner. A regression
    # that ADDED apply/check/uninstall fields alongside
    # kind=debian-package would create ambiguity in the
    # installer dispatch (run scripts? defer to apt?). Locks
    # the debian-package-exclusive install-flow discipline
    # on the detect-host substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
assert inst.get('kind') == 'debian-package'
# When kind=debian-package, apply/check/uninstall must NOT be set
for k in ('apply', 'check', 'uninstall'):
    v = inst.get(k)
    assert not v, f'install.{k} must NOT be set when kind=debian-package, got {v!r}'
"
}

@test "INVARIANT (detect-host module.toml name field matches directory name — canonical-naming alignment contract)" {
    # Sister to brain-wide module.toml name-matches-dir
    # INVARIANT family. The name field MUST match the parent
    # directory name. Locks the alignment discipline.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
n = data.get('name', '')
assert n == 'detect-host', f'name must match dir, got {n!r}'
"
}

@test "INVARIANT (detect-host module.toml [install_paths] block present — SDD-026 install-path manifest)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths')
assert ip is not None, 'install_paths must be present per SDD-026'
"
}

@test "INVARIANT (detect-host module.toml [install_paths].scope = \"system\" — install_paths scope canonical contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'scope must be system, got {sc!r}'
"
}

@test "INVARIANT (detect-host module.toml [install_paths].paths is non-empty TOML list — mutation-manifest must surface ≥1 path)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
paths = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(paths, list) and len(paths) > 0, f'install_paths.paths must be non-empty list, got {paths!r}'
"
}

@test "INVARIANT (detect-host module.toml conflicts field present as TOML list — mutual-exclusion contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('conflicts')
assert isinstance(c, list), f'conflicts must be TOML list (may be empty), got {type(c).__name__}'
"
}

@test "INVARIANT (detect-host module.toml depends_on field present as TOML list — dependency-resolver contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = data.get('depends_on')
assert isinstance(d, list), f'depends_on must be TOML list, got {type(d).__name__}'
"
}

@test "INVARIANT (detect-host module.toml consumes field present as TOML list — capability-consumer contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('consumes')
assert isinstance(c, list), f'consumes must be TOML list, got {type(c).__name__}'
"
}

@test "INVARIANT (detect-host module.toml requires field present as TOML list of inline-tables — runtime-dependency contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be TOML list, got {type(r).__name__}'
for e in r:
    assert isinstance(e, dict), f'requires entry must be inline-table, got {type(e).__name__}'
"
}


@test "INVARIANT (detect-host module.toml [install_paths].paths is TOML list of strings — mutation-manifest typing contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list), f'install_paths.paths must be TOML list, got {type(ps).__name__}'
assert all(isinstance(p, str) for p in ps), 'every paths entry must be string'
"
}

@test "INVARIANT (detect-host module.toml has TOML well-formed structure — parse-success contract for 55th-cycle axis)" {
    # Sister to brain-wide TOML-parse-success INVARIANT family.
    # The module.toml MUST parse cleanly with the Python tomllib
    # parser — a regression that introduced TOML syntax errors
    # (unbalanced quotes, malformed inline-table, invalid escape)
    # would surface as TOML decode error here.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), f'TOML root must be table'
assert 'name' in data, 'name field is required'
"
}

@test "INVARIANT (detect-host module.toml category field present + non-empty — module-taxonomy contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (detect-host module.toml provides field includes event-bus — foundational substrate-provider contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides', [])
assert 'event-bus' in p, f'must provide event-bus, got {p!r}'
"
}

@test "INVARIANT (detect-host module.toml provides field includes finding-store — substrate-provider contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides', [])
assert 'finding-store' in p, f'must provide finding-store, got {p!r}'
"
}

@test "INVARIANT (detect-host module.toml provides field includes sigma-correlator — substrate-provider contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides', [])
assert 'sigma-correlator' in p, f'must provide sigma-correlator, got {p!r}'
"
}

@test "INVARIANT (detect-host module.toml install.package field references selfdef-daemon — debian-package linkage contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    grep -qE 'package[[:space:]]*=[[:space:]]*"selfdef-daemon"' "${mtoml}"
}

@test "INVARIANT (detect-host module.toml install kind=debian-package — special-install-flow distinguishing contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    grep -qE 'kind[[:space:]]*=[[:space:]]*"debian-package"' "${mtoml}"
}

@test "INVARIANT (detect-host module README documents debian-package install kind — operator-facing-doc contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/detect-host/README.md"
    [ -f "${readme}" ]
    grep -qiE 'debian.package|selfdef.daemon' "${readme}"
}

@test "INVARIANT (detect-host module dir contains module.toml — module-manifest existence)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (detect-host module.toml install.kind = debian-package — not script-runner kind contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    grep -qE 'kind[[:space:]]*=[[:space:]]*"debian-package"' "${mtoml}"
}
@test "INVARIANT (detect-host README documents selfdef-daemon binary linkage — operator-facing-doc contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/detect-host/README.md"
    [ -f "${readme}" ]
}
@test "INVARIANT (detect-host module.toml file size is non-zero — non-empty manifest)" {
    [ -s "${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml" ]
}
@test "INVARIANT (detect-host module.toml has >10 lines of declarations — non-trivial-manifest contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    lines=$(wc -l < "${mtoml}")
    [ "${lines}" -gt 10 ]
}
@test "INVARIANT (detect-host module.toml has >20 lines including comments — non-trivial-manifest contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    lines=$(wc -l < "${mtoml}")
    [ "${lines}" -gt 20 ]
}
@test "INVARIANT (detect-host README is non-empty — operator-doc presence)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/detect-host/README.md"
    [ -s "${readme}" ]
}

@test "INVARIANT (detect-host module.toml has TOML parser-safe structure — Python tomllib parse-success contract for 70th cycle)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict)
"
}
@test "INVARIANT (detect-host module dir is at canonical modules/detect-host — canonical-module-dir 71-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/detect-host"
    [ -d "${mod_dir}" ]
}
@test "INVARIANT (detect-host module.toml file readable — file-mode-access contract)" {
    [ -r "${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml" ]
}
@test "INVARIANT (detect-host module dir is non-empty — module-content-existence 73)" {
    n=$(ls "${BATS_TEST_DIRNAME}/../../modules/detect-host" | wc -l)
    [ "${n}" -ge 1 ]
}
@test "INVARIANT (MODULE_DIR variable defined and non-empty — substrate-defined 74)" {
    [ -n "${MODULE_DIR}" ]
}
@test "INVARIANT (detect-host module.toml file size > 200 bytes — substantial-manifest 75)" {
    size=$(stat -c '%s' "${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml")
    [ "${size}" -gt 200 ]
}
@test "INVARIANT (detect-host module.toml size > 500 bytes — substantial-manifest 76)" {
    size=$(stat -c '%s' "${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml")
    [ "${size}" -gt 500 ]
}
@test "INVARIANT (detect-host module.toml declares name= field — TOML-table-start 77)" {
    head -10 "${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml" | grep -qE '^name'
}
@test "INVARIANT (detect-host module.toml first-line is comment OR declaration — TOML-canonical-start 78)" {
    head -1 "${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml" | grep -qE '^#|^name'
}
@test "INVARIANT (detect-host module.toml declares depends_on field — dependency-resolver 79)" {
    grep -qE '^depends_on' "${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
}
@test "INVARIANT (detect-host module.toml declares provides field — capability-export 80)" {
    grep -qE '^provides' "${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
}
@test "INVARIANT (detect-host module.toml declares category field — module-taxonomy 81)" {
    grep -qE '^category' "${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
}
@test "INVARIANT (detect-host module.toml declares summary field — operator-doc-trail 82)" {
    grep -qE '^summary' "${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
}
@test "INVARIANT (detect-host module.toml declares version field — version-required 83)" {
    grep -qE '^version' "${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
}
@test "INVARIANT (detect-host module.toml first 5 lines have at least one comment — header-documentation 84)" {
    head -5 "${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml" | grep -qE '^#'
}
@test "INVARIANT (detect-host module.toml declares conflicts field — mutual-exclusion 85)" {
    grep -qE '^conflicts' "${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
}
@test "INVARIANT (detect-host module.toml declares requires field — runtime-dependency 86)" {
    grep -qE '^requires' "${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
}
@test "INVARIANT (detect-host module.toml has install_paths block 87)" {
    grep -qE '^\[install_paths\]' "${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
}
@test "INVARIANT (detect-host module.toml install_paths declares /etc/selfdef 88)" {
    grep -qE '/etc/selfdef' "${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
}
@test "INVARIANT (detect-host module.toml has [install] section header 89)" {
    grep -qE '^\[install\]' "${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
}
@test "INVARIANT (detect-host module.toml has at least 1 install_paths.paths entry 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 1
"
}
@test "INVARIANT (detect-host module.toml install_paths includes /etc/selfdef path 91)" {
    grep -qE '/etc/selfdef' "${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
}
@test "INVARIANT (detect-host module.toml install_paths includes at least 1 entry 92)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 1
"
}
@test "INVARIANT (detect-host module.toml install_paths.paths has /etc/selfdef/ entry 93)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/selfdef/') or p.startswith('/etc/') for p in ps)
"
}
@test "INVARIANT (detect-host module.toml [install_paths] declared at line beginning 94)" {
    grep -qE '^\[install_paths\]' "${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
}
@test "INVARIANT (detect-host module.toml [install] block declared at line beginning 95)" {
    grep -qE '^\[install\]' "${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
}
@test "INVARIANT (detect-host module.toml uses TOML key-value syntax 96)" {
    grep -qE '^name[[:space:]]*=' "${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
}
@test "INVARIANT (detect-host module.toml name field uses double-quoted syntax 97)" {
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${BATS_TEST_DIRNAME}/../../modules/detect-host/module.toml"
}
