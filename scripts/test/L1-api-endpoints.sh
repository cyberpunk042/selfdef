#!/usr/bin/env bash
# L1-api-endpoints.sh — MS045 SDD-030 Deliverable 3
#
# Verifies the axum Router in selfdef-api declares every SDD-promised
# route. STATIC check — reads crates/selfdef-api/src/lib.rs directly,
# no HTTP server invocation needed.
#
# Source: SDD-030 Deliverable 3 / MS045 R-rows
# Run: bash scripts/test/L1-api-endpoints.sh
set -euo pipefail

LIB="${LIB:-crates/selfdef-api/src/lib.rs}"

if [[ ! -f "${LIB}" ]]; then
    echo "L1-api-endpoints FAIL: ${LIB} not found" >&2
    exit 1
fi

check_route() {
    local route="$1"
    local sdd="$2"
    if grep -qE "\.route\(\"${route}\"" "${LIB}"; then
        echo "  PASS ${route} (${sdd})"
    else
        echo "  FAIL ${route} — declared by ${sdd} but NOT present in ${LIB}"
        return 1
    fi
}

echo "L1-api-endpoints: checking selfdef-api Router (file: ${LIB})"

failures=0
# SDD-027 / MS046
check_route "/v1/friction-audit"          "SDD-027 D6" || failures=$((failures + 1))
check_route "/v1/friction-audit/history"  "SDD-027 D6" || failures=$((failures + 1))
# SDD-028 / MS047
check_route "/v1/perimeter"               "SDD-028 D8" || failures=$((failures + 1))
check_route "/v1/perimeter/history"       "SDD-028 D8" || failures=$((failures + 1))
# SDD-029 / MS044
check_route "/v1/guardian"                "SDD-029 D8" || failures=$((failures + 1))
check_route "/v1/guardian/history"        "SDD-029 D8" || failures=$((failures + 1))
# SDD-031 / MS048
check_route "/v1/scheduler"               "SDD-031 D4" || failures=$((failures + 1))
check_route "/v1/scheduler/history"       "SDD-031 D4" || failures=$((failures + 1))
check_route "/v1/scheduler/backpressure"  "SDD-031 D4" || failures=$((failures + 1))
check_route "/v1/scheduler/weights"       "SDD-031 D4" || failures=$((failures + 1))
check_route "/v1/scheduler/explain/:request_id" "SDD-031 D4" || failures=$((failures + 1))
# MS006 / SDD-009 Q-G — operator-facing modules list (read-only)
check_route "/v1/modules"                 "MS006 / SDD-009 Q-G" || failures=$((failures + 1))
check_route "/v1/modules/:name"           "MS006 / SDD-009 Q-G" || failures=$((failures + 1))

# MS011 Z-13 / SD-R83 — modules diff (catalog ∩/Δ host-active set)
check_route "/v1/modules/diff"            "MS011 Z-13 / SD-R83" || failures=$((failures + 1))

# MS006 / MS016..MS031 — per-module install/check.sh invocation.
check_route "/v1/modules/:name/check"     "MS006 / per-module check" || failures=$((failures + 1))

# MS027 — server-side alert classification (consumed by PWA dashboard
# + selfdefctl alerts; single source of truth for the 9 alert series).
check_route "/v1/alerts"                  "MS027" || failures=$((failures + 1))

# MS010 / SDD-018 — hardware-aware modules HTTP surface (snapshot +
# derived capabilities + sain-01 reference-platform match verdict).
check_route "/v1/hardware"                "MS010 / SDD-018" || failures=$((failures + 1))
check_route "/v1/hardware/capabilities"   "MS010 / SDD-018" || failures=$((failures + 1))
check_route "/v1/hardware/sain01"         "MS010 / SDD-018" || failures=$((failures + 1))

# MS011 Z-7 / SDD-026 — network state surface (internet, dns,
# cloudflared, tailscale, traefik per-component green/yellow/red).
check_route "/v1/network"                 "MS011 Z-7 / SDD-026" || failures=$((failures + 1))

# MS011 Z-10 / SDD-026 — storage state surface (df-parsed mount
# usage + selfdef-managed log-dir byte/file counts).
check_route "/v1/storage"                 "MS011 Z-10 / SDD-026" || failures=$((failures + 1))

# MS011 Z-9 / SDD-026 — software RAID state surface (per-array level
# + member set + health string + state classification from /proc/mdstat).
check_route "/v1/raid"                    "MS011 Z-9 / SDD-026" || failures=$((failures + 1))

# MS011 Z-5 / SDD-026 — GPU watt deviance surface (nvidia-smi current
# draw vs operator-set expected_power_limit_watts in gpu-policy.toml).
check_route "/v1/gpu"                     "MS011 Z-5 / SDD-026" || failures=$((failures + 1))

# MS011 Z-4 / SDD-026 — CPU mode classification surface (governor +
# SMT → ultra-low-power | balanced | sustained-burst | peak-inference
# | custom).
check_route "/v1/cpu"                     "MS011 Z-4 / SDD-026" || failures=$((failures + 1))

# MS011 Z-6 / SDD-026 — composite autohealth aggregate across all
# read surfaces (alerts + network + storage + raid + gpu + cpu).
check_route "/v1/health"                  "MS011 Z-6 / SDD-026" || failures=$((failures + 1))

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-api-endpoints FAIL: ${failures} missing route(s)"
    echo "  See ~/devops-solutions-information-hub/wiki/runbooks/ux-coherence-failures.md for fix procedure."
    exit 1
fi

echo "L1-api-endpoints PASS: all SDD-promised routes declared"
