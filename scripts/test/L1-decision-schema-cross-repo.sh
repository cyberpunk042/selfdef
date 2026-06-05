#!/usr/bin/env bash
# L1-decision-schema-cross-repo.sh — selfdef-scheduler-mirror Decision +
# AxisScores schema integrity gate, anchored on the sovereign-os bridge
# consumer expectation.
#
# The sovereign-os scheduler-bridge (`scripts/inference/scheduler-bridge.py`)
# consumes the Decision JSON the selfdef-scheduler-decide binary emits. It
# accesses these fields:
#   decision["route"]                      — selected route
#   decision["request_id"]                 — for trace correlation
#   decision["rationale"]                  — operator-visible explanation
#   decision["axis_scores"]["compound"]    — scoring summary
#
# AND the broader Decision contract documented in
# `docs/operator/ms048-scheduler-integration-contract.md` names these 8
# selfdef-mirror Decision fields + the 7 axis_scores fields. A silent
# rename/drop on the selfdef side breaks the bridge. This gate pins the
# selfdef-side Decision + AxisScores struct shape against the documented
# cross-repo contract.
#
# Companion to sovereign-os tests/lint/test_selfdef_scheduler_metric_
# contract.py — that gates from the consumer side; this gates from the
# producer side. Drift fires whichever pipeline runs first.
#
# Run with: bash scripts/test/L1-decision-schema-cross-repo.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MIRROR_LIB="${REPO_ROOT}/crates/selfdef-scheduler-mirror/src/lib.rs"

failures=0

if [[ ! -f "${MIRROR_LIB}" ]]; then
    echo "FAIL: ${MIRROR_LIB} not present (catalog row MS048 SDD-031 D-1 — mirror crate)"
    exit 1
fi

assert_field() {
    local label="$1"
    local pattern="$2"
    if grep -qE "${pattern}" "${MIRROR_LIB}"; then
        echo "  PASS ${label}"
    else
        echo "  FAIL ${label} — pattern not found: ${pattern}"
        failures=$((failures + 1))
    fi
}

# Gate 1: Decision struct carries the 8 documented fields the bridge +
# integration contract rely on. Order matches the contract doc.
echo "▶ Gate 1: Decision struct fields (selfdef-scheduler-mirror)"
assert_field "Decision.schema_version" "^[[:space:]]+pub schema_version: String,?$"
assert_field "Decision.request_id (sovereign-os bridge consumes)" "^[[:space:]]+pub request_id: String,?$"
assert_field "Decision.profile" "^[[:space:]]+pub profile: Profile,?$"
assert_field "Decision.route (sovereign-os bridge consumes)" "^[[:space:]]+pub route: Route,?$"
assert_field "Decision.axis_scores (sovereign-os bridge consumes compound)" "^[[:space:]]+pub axis_scores: AxisScores,?$"
assert_field "Decision.backpressure" "^[[:space:]]+pub backpressure: BackpressureState,?$"
assert_field "Decision.ts_ms" "^[[:space:]]+pub ts_ms: u64,?$"
assert_field "Decision.hostname" "^[[:space:]]+pub hostname: String,?$"
assert_field "Decision.rationale (sovereign-os bridge consumes)" "^[[:space:]]+pub rationale: String,?$"

# Gate 2: AxisScores carries the 6 axis fields + compound. The
# `compound` field is THE field the bridge reads — silent rename breaks
# the bridge's `decision["axis_scores"]["compound"]` access.
echo "▶ Gate 2: AxisScores struct fields"
assert_field "AxisScores.latency" "^[[:space:]]+pub latency: f32,?$"
assert_field "AxisScores.cost" "^[[:space:]]+pub cost: f32,?$"
assert_field "AxisScores.risk" "^[[:space:]]+pub risk: f32,?$"
assert_field "AxisScores.energy" "^[[:space:]]+pub energy: f32,?$"
assert_field "AxisScores.human_attention" "^[[:space:]]+pub human_attention: f32,?$"
assert_field "AxisScores.hardware_pressure" "^[[:space:]]+pub hardware_pressure: f32,?$"
assert_field "AxisScores.compound (sovereign-os bridge consumes)" "^[[:space:]]+pub compound: f32,?$"

# Gate 3: Route enum carries the 5 documented routes the bridge maps
# via route_to_tier.
echo "▶ Gate 3: Route enum variants (the 5 sovereign-os bridge maps)"
assert_field "Route::Blackwell (oracle tier)" "^[[:space:]]+Blackwell,?$"
assert_field "Route::Rtx3090 (scout tier)" "^[[:space:]]+Rtx3090,?$"
assert_field "Route::Cpu (deterministic cortex)" "^[[:space:]]+Cpu,?$"
assert_field "Route::Hybrid" "^[[:space:]]+Hybrid,?$"
assert_field "Route::Hibernate (bridge maps to defer)" "^[[:space:]]+Hibernate,?$"

# Gate 4: Profile enum carries the 6 variants the bridge emits (also
# pinned sovereign-side in test_selfdef_profile_enum_matches_bridge_
# options — symmetric coverage).
echo "▶ Gate 4: Profile enum variants (the 6 sovereign-os bridge emits)"
assert_field "Profile::Fast" "^[[:space:]]+Fast,?$"
assert_field "Profile::Careful" "^[[:space:]]+Careful,?$"
assert_field "Profile::Private" "^[[:space:]]+Private,?$"
assert_field "Profile::Autonomous" "^[[:space:]]+Autonomous,?$"
assert_field "Profile::Experimental" "^[[:space:]]+Experimental,?$"
assert_field "Profile::Production" "^[[:space:]]+Production,?$"

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-decision-schema-cross-repo FAIL: ${failures} schema violation(s)"
    exit 1
fi

echo "L1-decision-schema-cross-repo PASS: Decision (9 fields) + AxisScores (7 fields) + Route (5 variants) + Profile (6 variants) intact"
