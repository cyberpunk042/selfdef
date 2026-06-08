#!/usr/bin/env bash
# L1-mirror-artifact-filename-binding.sh — cross-repo mirror filename gate.
#
# The selfdef daemon's mirror_export_loop.rs publishes the MS007 cockpit
# mirror as a set of JSON artifacts whose names are `const *_FILE: &str`
# (active-profile.json / grants.json / capability-tokens.json / ... — 9
# of them). The sovereign-os cockpit reads each by EXACT filename in
# `cyberpunk042/sovereign-os/scripts/mirror/selfdef-*-mirror.py`.
#
# The schema-version coherence gate locks the VERSION contract, but NOT the
# filenames. A selfdef-side rename (active-profile.json -> active_profile
# .json) would leave SCHEMA_VERSION untouched, so that gate stays green
# while the cockpit consumer silently finds nothing — a dead cross-repo
# dashboard with no error path. This gate closes that P4 hole: every
# published `const *_FILE` artifact name MUST be referenced by some
# sovereign-os mirror consumer.
#
# Skips cleanly when sovereign-os is not adjacent (dev env without both
# repos); env var SOVEREIGN_OS_REPO overrides the default sibling path.
#
# Run: bash scripts/test/L1-mirror-artifact-filename-binding.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MIRROR_RS="${REPO_ROOT}/crates/selfdef-daemon/src/mirror_export_loop.rs"
SOV_REPO="${SOVEREIGN_OS_REPO:-${REPO_ROOT}/../sovereign-os}"
CONSUMER_GLOB="${SOV_REPO}/scripts/mirror"

if [[ ! -f "${MIRROR_RS}" ]]; then
    echo "L1-mirror-artifact-filename-binding FAIL: ${MIRROR_RS} missing" >&2
    exit 1
fi

# The published artifact filenames: `const <NAME>_FILE: &str = "x.json";`.
mapfile -t artifacts < <(
    grep -oE 'const [A-Z_]+_FILE:[[:space:]]*&str[[:space:]]*=[[:space:]]*"[a-z0-9-]+\.json"' \
        "${MIRROR_RS}" | grep -oE '"[a-z0-9-]+\.json"' | tr -d '"' | sort -u
)

if [[ "${#artifacts[@]}" -eq 0 ]]; then
    echo "L1-mirror-artifact-filename-binding FAIL: parsed 0 const *_FILE artifacts (parser/path drift)" >&2
    exit 1
fi

if [[ ! -d "${CONSUMER_GLOB}" ]]; then
    echo "L1-mirror-artifact-filename-binding SKIP: sovereign-os consumers not adjacent at ${CONSUMER_GLOB} (set SOVEREIGN_OS_REPO). Parsed ${#artifacts[@]} producer artifact(s)."
    exit 0
fi

failures=0
for f in "${artifacts[@]}"; do
    if grep -rqlF "${f}" "${CONSUMER_GLOB}"/*.py 2>/dev/null; then
        echo "  PASS ${f} — read by a sovereign-os mirror consumer"
    else
        echo "  FAIL ${f}: published by selfdef mirror_export_loop.rs but NO sovereign-os scripts/mirror/*.py reads it — a rename would silently dead-link the cockpit. Update the consumer (or the producer const)."
        failures=$((failures + 1))
    fi
done

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-mirror-artifact-filename-binding FAIL: ${failures} unbound mirror artifact filename(s)"
    exit 1
fi

echo "L1-mirror-artifact-filename-binding PASS: ${#artifacts[@]} published mirror artifacts all bound to a sovereign-os consumer"
