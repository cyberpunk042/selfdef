#!/usr/bin/env bash
# L1-module-contracts.sh — module-system contract integrity gate
#
# Locks the cross-module contract integrity at every commit. With
# the module set under modules/ (188+ and growing) + the module-author
# contract in docs/dev/modules.md, drift between manifest declarations
# and shipped artifacts becomes likely. This gate catches it.
#
# Gates:
#   1. Every modules/<name>/ has a module.toml that parses
#   2. The manifest name field matches the directory name
#   3. install.kind ∈ {"script", "debian-package"}
#   4. install.kind == "script" → install/{apply,check,uninstall}.sh
#      all exist + are executable
#   5. install.kind == "debian-package" → install.package set + NO
#      install/ dir
#   6. Every depends_on entry refers to an actual sibling module
#   7. Every consumes entry has a matching provides somewhere in the
#      module set (cross-module wiring is well-typed)
#   8. Every script install module's apply.sh declares set -euo
#      pipefail (fail-loud invariant)
#   9. Every script install module's apply.sh is SELFDEF_DRY_RUN aware
#
# Source: docs/dev/modules.md module-author contract
# Run: bash scripts/test/L1-module-contracts.sh
set -uo pipefail

MODULES_DIR="${MODULES_DIR:-modules}"

if [[ ! -d "${MODULES_DIR}" ]]; then
    echo "L1-module-contracts FAIL: ${MODULES_DIR} not found" >&2
    exit 1
fi

echo "L1-module-contracts: scanning ${MODULES_DIR}/"

failures=0
module_names=()

# Collect manifests
for d in "${MODULES_DIR}"/*/; do
    name="$(basename "${d}")"
    manifest="${d}module.toml"
    if [[ ! -f "${manifest}" ]]; then
        echo "  FAIL ${name}: module.toml missing"
        failures=$((failures + 1))
        continue
    fi
    module_names+=("${name}")
done

# Gate 1+2: parse + name match
for name in "${module_names[@]}"; do
    manifest="${MODULES_DIR}/${name}/module.toml"
    parsed_name=$(python3 -c "
import sys
try: import tomllib
except ImportError: import tomli as tomllib
with open('${manifest}', 'rb') as f:
    d = tomllib.load(f)
print(d.get('name', ''))
" 2>&1 || true)
    if [[ -z "${parsed_name}" ]]; then
        echo "  FAIL ${name}: manifest does not parse or name is empty"
        failures=$((failures + 1))
        continue
    fi
    if [[ "${parsed_name}" != "${name}" ]]; then
        echo "  FAIL ${name}: manifest name='${parsed_name}' but directory='${name}'"
        failures=$((failures + 1))
        continue
    fi
    echo "  PASS ${name}: manifest parses + name matches"
done

# Gate 3+4+5: install.kind + script vs debian-package shape
for name in "${module_names[@]}"; do
    manifest="${MODULES_DIR}/${name}/module.toml"
    install_kind=$(python3 -c "
import sys
try: import tomllib
except ImportError: import tomli as tomllib
with open('${manifest}', 'rb') as f:
    d = tomllib.load(f)
print(d.get('install', {}).get('kind', ''))
" 2>&1 || true)
    case "${install_kind}" in
        script)
            for s in apply check uninstall; do
                if [[ ! -x "${MODULES_DIR}/${name}/install/${s}.sh" ]]; then
                    echo "  FAIL ${name}: install.kind=script but install/${s}.sh missing or not executable"
                    failures=$((failures + 1))
                fi
            done
            ;;
        debian-package)
            pkg=$(python3 -c "
try: import tomllib
except ImportError: import tomli as tomllib
with open('${manifest}', 'rb') as f:
    d = tomllib.load(f)
print(d.get('install', {}).get('package', ''))
" 2>&1 || true)
            if [[ -z "${pkg}" ]]; then
                echo "  FAIL ${name}: install.kind=debian-package but install.package not set"
                failures=$((failures + 1))
            fi
            if [[ -d "${MODULES_DIR}/${name}/install" ]]; then
                echo "  FAIL ${name}: install.kind=debian-package but install/ dir present (should be absent)"
                failures=$((failures + 1))
            fi
            ;;
        "")
            echo "  FAIL ${name}: install.kind missing"
            failures=$((failures + 1))
            ;;
        *)
            echo "  FAIL ${name}: install.kind='${install_kind}' (must be script or debian-package)"
            failures=$((failures + 1))
            ;;
    esac
done

# Gate 6: depends_on entries reference existing siblings
python3 <<PY
import sys, os
try: import tomllib
except ImportError: import tomli as tomllib

modules_dir = "${MODULES_DIR}"
module_names = set(os.listdir(modules_dir))
fail = 0
for name in sorted(module_names):
    manifest = os.path.join(modules_dir, name, "module.toml")
    if not os.path.isfile(manifest):
        continue
    with open(manifest, "rb") as f:
        d = tomllib.load(f)
    deps = d.get("depends_on", [])
    for dep in deps:
        if dep not in module_names:
            print(f"  FAIL {name}: depends_on='{dep}' but no modules/{dep}/ exists")
            fail += 1
    if not deps:
        pass  # zero-dep is fine
    else:
        print(f"  PASS {name}: depends_on entries resolve ({len(deps)} sibling(s))")
sys.exit(fail)
PY
failures=$((failures + $?))

# Gate 7: consumes entries are satisfied by some provides
python3 <<PY
import sys, os
try: import tomllib
except ImportError: import tomli as tomllib

modules_dir = "${MODULES_DIR}"
all_provides = set()
all_consumes = {}
for name in sorted(os.listdir(modules_dir)):
    manifest = os.path.join(modules_dir, name, "module.toml")
    if not os.path.isfile(manifest):
        continue
    with open(manifest, "rb") as f:
        d = tomllib.load(f)
    for p in d.get("provides", []):
        all_provides.add(p)
    for c in d.get("consumes", []):
        all_consumes.setdefault(c, []).append(name)

fail = 0
for c, consumers in sorted(all_consumes.items()):
    if c not in all_provides:
        # "metrics-endpoint" is a Tetragon-shipped contract (the
        # tetragon module's built-in Prometheus exporter); allowed.
        # "hardware-tune-env" comes from MS010 hardware-tune-cache.
        if c in ("metrics-endpoint",):
            continue
        print(f"  FAIL contract '{c}' consumed by {consumers} but no module provides it")
        fail += 1
    else:
        print(f"  PASS contract '{c}' provided + consumed by {consumers}")
sys.exit(fail)
PY
failures=$((failures + $?))

# Gate 8+9: every script-kind apply.sh uses set -euo pipefail +
# SELFDEF_DRY_RUN
for name in "${module_names[@]}"; do
    apply="${MODULES_DIR}/${name}/install/apply.sh"
    [[ -f "${apply}" ]] || continue   # debian-package kind: no apply.sh
    if ! grep -qE '^set -euo pipefail' "${apply}"; then
        echo "  FAIL ${name}: install/apply.sh missing 'set -euo pipefail' fail-loud invariant"
        failures=$((failures + 1))
    fi
    if ! grep -q 'SELFDEF_DRY_RUN' "${apply}"; then
        echo "  FAIL ${name}: install/apply.sh not SELFDEF_DRY_RUN aware"
        failures=$((failures + 1))
    fi
done

# ----------------------------------------------------------------------
# Gate 10: cross-module template references must target a real producer
# ----------------------------------------------------------------------
# An inline consumer module (e.g. suricata) may reference another
# module's nft table or chain BY LITERAL NAME in its rule template
# (see MS024 E0245: "the owning module does not know about its
# consumers" — so the consumer carries the literal). If the producer
# silently renames its table or chain, the manifest-level provides/
# consumes gate (Gate 7) stays green because that contract speaks in
# abstract keywords, but the template binding silently breaks at apply-
# time on a real host. This gate freezes the producer↔consumer
# template binding pairs at commit time.
#
# Producer table/chain → consumer modules: every (table, chain) pair
# below must be present somewhere in the producer's own *.tmpl AND in
# every consumer's *.tmpl. Symmetrically; either side renaming = FAIL.
declare -A PRODUCER_TABLES
PRODUCER_TABLES["bridge-l2"]="selfdef_bridge"
declare -A PRODUCER_CHAINS
PRODUCER_CHAINS["bridge-l2"]="forward_hook"
declare -A CONSUMERS_OF
CONSUMERS_OF["bridge-l2"]="suricata"

for producer in "${!PRODUCER_TABLES[@]}"; do
    table="${PRODUCER_TABLES[${producer}]}"
    chain="${PRODUCER_CHAINS[${producer}]}"
    producer_tmpl_dir="${MODULES_DIR}/${producer}/templates"
    if [[ ! -d "${producer_tmpl_dir}" ]]; then
        echo "  FAIL producer '${producer}' has no templates/ dir (cross-module surface) "
        failures=$((failures + 1))
        continue
    fi
    # producer side must declare both names
    if ! grep -qr -e "${table}" "${producer_tmpl_dir}"; then
        echo "  FAIL producer '${producer}' templates do not declare table '${table}' (drift from contract)"
        failures=$((failures + 1))
    fi
    if ! grep -qr -e "${chain}" "${producer_tmpl_dir}"; then
        echo "  FAIL producer '${producer}' templates do not declare chain '${chain}' (drift from contract)"
        failures=$((failures + 1))
    fi
    # every consumer side must reference both names verbatim
    for consumer in ${CONSUMERS_OF[${producer}]}; do
        consumer_tmpl_dir="${MODULES_DIR}/${consumer}/templates"
        if [[ ! -d "${consumer_tmpl_dir}" ]]; then
            echo "  FAIL consumer '${consumer}' (of '${producer}') has no templates/ dir"
            failures=$((failures + 1))
            continue
        fi
        if ! grep -qr -e "${table}" "${consumer_tmpl_dir}"; then
            echo "  FAIL consumer '${consumer}' templates do not reference producer '${producer}' table '${table}'"
            failures=$((failures + 1))
        fi
        if ! grep -qr -e "${chain}" "${consumer_tmpl_dir}"; then
            echo "  FAIL consumer '${consumer}' templates do not reference producer '${producer}' chain '${chain}'"
            failures=$((failures + 1))
        fi
    done
done

# Summary
if [[ "${failures}" -gt 0 ]]; then
    echo "L1-module-contracts FAIL: ${failures} contract violation(s)"
    exit 1
fi

echo "L1-module-contracts PASS: ${#module_names[@]} modules; manifests + install kinds + cross-module wiring + apply.sh invariants + producer↔consumer template bindings all coherent"
