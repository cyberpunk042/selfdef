#!/usr/bin/env bash
# L1-module-lib-version-coherence.sh — SDD-061 shared module-lib
# version-contract gate.
#
# packaging/lib/module-lib.sh declares SELFDEF_MODULE_LIB_VERSION=<N>.
# Every consumer (watchdog scripts in modules/*/install/lib.sh and a
# few packaging/scripts/) declares
# SELFDEF_MODULE_LIB_VERSION_REQUIRED=<M>; the library FAILs loud at
# load time when M > N. That's the runtime mechanism; this is the
# COMMIT-TIME mechanism: catch a consumer requiring a version the
# library has not yet shipped.
#
# Two silent-drift classes:
#   1. A new consumer requires a version > the library's current
#      version — the library would fail-loud at runtime, but commit
#      time is the right moment to catch it (operator can bump library
#      in the same commit).
#   2. The library's version declaration goes missing / malformed —
#      the require/have comparison breaks at load time on every host.
#
# Run with: bash scripts/test/L1-module-lib-version-coherence.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIB="${REPO_ROOT}/packaging/lib/module-lib.sh"

failures=0

# Gate 1: library declares its version cleanly
echo "▶ Gate 1: packaging/lib/module-lib.sh declares SELFDEF_MODULE_LIB_VERSION"
if [[ ! -f "${LIB}" ]]; then
    echo "  FAIL library not present at ${LIB}"
    exit 1
fi
LIB_VERSION_LINE=$(grep -E '^SELFDEF_MODULE_LIB_VERSION=[0-9]+' "${LIB}" || true)
if [[ -z "${LIB_VERSION_LINE}" ]]; then
    echo "  FAIL library does not declare a clean SELFDEF_MODULE_LIB_VERSION (every consumer's require-check fails at load)"
    exit 1
fi
LIB_VERSION=$(echo "${LIB_VERSION_LINE}" | cut -d= -f2)
echo "  PASS library declares SELFDEF_MODULE_LIB_VERSION=${LIB_VERSION}"

# Gate 2: every consumer's required version is ≤ the library's current
# version (else the require-check fails loud at every host load)
echo "▶ Gate 2: every consumer's SELFDEF_MODULE_LIB_VERSION_REQUIRED ≤ ${LIB_VERSION}"

declare -A version_distribution
total_consumers=0
violating=()

while IFS= read -r consumer; do
    [[ -z "${consumer}" ]] && continue
    req_line=$(grep -E "SELFDEF_MODULE_LIB_VERSION_REQUIRED=[0-9]+" "${consumer}" | head -1 || true)
    [[ -z "${req_line}" ]] && continue
    req_version=$(echo "${req_line}" | grep -oE '[0-9]+' | head -1)
    total_consumers=$((total_consumers + 1))
    version_distribution["${req_version}"]=$((${version_distribution["${req_version}"]:-0} + 1))
    if (( req_version > LIB_VERSION )); then
        violating+=("$(basename "$(dirname "$(dirname "${consumer}")")"):${req_version}")
    fi
done < <(find "${REPO_ROOT}/modules" -path "*/install/*.sh" 2>/dev/null; find "${REPO_ROOT}/packaging/scripts" -name "*.sh" 2>/dev/null)

if [[ "${#violating[@]}" -gt 0 ]]; then
    for v in "${violating[@]}"; do
        IFS=':' read -r module req <<< "${v}"
        echo "  FAIL ${module} requires module-lib v${req} but library is at v${LIB_VERSION} (bump the library or downgrade the consumer)"
        failures=$((failures + 1))
    done
else
    echo "  PASS all ${total_consumers} consumers satisfied by library v${LIB_VERSION}"
    for v in $(printf '%s\n' "${!version_distribution[@]}" | sort -n); do
        echo "    v${v}: ${version_distribution[${v}]} consumer(s)"
    done
fi

# Gate 3: library's *_ifne fail-loud message references both required
# and have values (helps operators diagnose mismatches without reading
# source).
echo "▶ Gate 3: library's failure path surfaces both require/have values for operator"
if grep -qE 'require >=.*have' "${LIB}"; then
    echo "  PASS library failure message surfaces both required + have versions"
else
    echo "  FAIL library failure message does not surface both versions (operator can't diagnose mismatch)"
    failures=$((failures + 1))
fi

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-module-lib-version-coherence FAIL: ${failures} version-contract violation(s)"
    exit 1
fi

echo "L1-module-lib-version-coherence PASS: library v${LIB_VERSION} satisfies all ${total_consumers} consumers"
