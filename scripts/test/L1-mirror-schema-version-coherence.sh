#!/usr/bin/env bash
# L1-mirror-schema-version-coherence.sh — MS007 typed-mirror cross-crate +
# cross-repo schema-version coherence gate.
#
# Every selfdef-*-mirror crate carries a `pub const SCHEMA_VERSION: &str`
# that the sovereign-os consumer scripts at
# `cyberpunk042/sovereign-os/scripts/mirror/selfdef-*-mirror.py` check at
# deserialize time to refuse incompatible payloads. Two silent-drift classes
# this gate catches at commit time:
#
#   1. Cross-crate divergence: one mirror crate bumped to "1.0.1" or "2.0.0"
#      without the others (or worse, to a different schema entirely). The
#      MS007 contract is that the mirror set evolves in lockstep — a
#      mismatched version means the sovereign-os cockpit will reject the
#      mismatched-crate's published artifact while accepting the others,
#      producing partial-blind dashboards with no obvious error path.
#
#   2. Cross-repo drift: a selfdef-side schema_version bump that the
#      sovereign-os consumer scripts haven't been updated to accept. The
#      consumer's allowed_versions list (or hardcoded version check) must
#      include every published selfdef-side version.
#
# Skips with a notice when sovereign-os is not adjacent (dev envs without
# both repos cloned); env var SOVEREIGN_OS_REPO overrides default path.
#
# Run with: bash scripts/test/L1-mirror-schema-version-coherence.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SOV_REPO_DEFAULT="${REPO_ROOT}/../sovereign-os"
SOV_REPO="${SOVEREIGN_OS_REPO:-${SOV_REPO_DEFAULT}}"

failures=0

# ----------------------------------------------------------------------
# Gate 1: cross-crate coherence — every selfdef-*-mirror crate declares
# the SAME SCHEMA_VERSION constant.
# ----------------------------------------------------------------------
echo "▶ Gate 1: cross-crate SCHEMA_VERSION coherence (MS007 lockstep contract)"

declare -A crate_versions
for crate_dir in "${REPO_ROOT}"/crates/selfdef-*-mirror; do
    crate_name="$(basename "${crate_dir}")"
    lib_rs="${crate_dir}/src/lib.rs"
    if [[ ! -f "${lib_rs}" ]]; then
        echo "  SKIP ${crate_name} — no src/lib.rs"
        continue
    fi
    version=$(grep -E '^pub const SCHEMA_VERSION:[[:space:]]*&str[[:space:]]*=' "${lib_rs}" \
        | grep -oE '"[^"]*"' | head -1 | tr -d '"')
    if [[ -z "${version}" ]]; then
        echo "  FAIL ${crate_name}: no \`pub const SCHEMA_VERSION: &str = \"...\"\` declaration"
        failures=$((failures + 1))
        continue
    fi
    crate_versions["${crate_name}"]="${version}"
    echo "  PASS ${crate_name} declares SCHEMA_VERSION = ${version}"
done

# All version values must be identical (the MS007 lockstep invariant)
unique_versions=$(printf '%s\n' "${crate_versions[@]}" | sort -u)
if [[ -z "${unique_versions}" ]]; then
    echo "  FAIL no SCHEMA_VERSION constants found across selfdef-*-mirror crates"
    failures=$((failures + 1))
elif [[ "$(echo "${unique_versions}" | wc -l)" -ne 1 ]]; then
    echo "  FAIL cross-crate divergence — found multiple SCHEMA_VERSION values:"
    while IFS= read -r v; do
        echo "    ${v}"
    done <<< "${unique_versions}"
    failures=$((failures + 1))
else
    echo "  PASS all ${#crate_versions[@]} mirror crates declare SCHEMA_VERSION = ${unique_versions}"
fi

# ----------------------------------------------------------------------
# Gate 2: cross-repo coherence — every sovereign-os consumer accepts (at
# least) the version selfdef publishes. The consumer scripts hard-code or
# allow-list the version — any selfdef-side bump without the consumer-side
# update breaks the cross-repo wire.
# ----------------------------------------------------------------------
echo "▶ Gate 2: cross-repo SCHEMA_VERSION coherence (sovereign-os consumers accept selfdef-published version)"

if [[ ! -d "${SOV_REPO}/scripts/mirror" ]]; then
    echo "  SKIP sovereign-os mirror consumers not present at ${SOV_REPO}/scripts/mirror — set SOVEREIGN_OS_REPO env var to point at the sister repo."
else
    selfdef_version="${unique_versions}"
    for consumer in "${SOV_REPO}"/scripts/mirror/selfdef-*-mirror.py; do
        [[ -f "${consumer}" ]] || continue
        consumer_name="$(basename "${consumer}")"
        # The consumer either hardcodes the expected version OR carries a
        # comment/string referencing it. We accept either pattern; the
        # specific check is "the selfdef-published version is mentioned".
        if grep -qF "\"${selfdef_version}\"" "${consumer}" || \
           grep -qF "'${selfdef_version}'" "${consumer}" || \
           grep -qF "schema_version=${selfdef_version}" "${consumer}" || \
           grep -qE "SCHEMA_VERSION[[:space:]]*=[[:space:]]*[\"']${selfdef_version}[\"']" "${consumer}" || \
           grep -qE "schema_version[[:space:]]*[=:][[:space:]]*[\"']${selfdef_version}[\"']" "${consumer}"; then
            echo "  PASS ${consumer_name} accepts selfdef ${selfdef_version}"
        else
            echo "  FAIL ${consumer_name} does not appear to accept selfdef SCHEMA_VERSION ${selfdef_version} (consumer-side drift?)"
            failures=$((failures + 1))
        fi
    done
fi

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-mirror-schema-version-coherence FAIL: ${failures} version coherence violation(s)"
    exit 1
fi

echo "L1-mirror-schema-version-coherence PASS: cross-crate + cross-repo schema version coherent"
