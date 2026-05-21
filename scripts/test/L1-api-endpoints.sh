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

# MS009 — composite audit-chain replay across perimeter/guardian/scheduler.
check_route "/v1/audit-chains"            "MS009 audit cycles" || failures=$((failures + 1))

# MS041 / SDD-043 D-3 — commit-authority schema discovery surface.
check_route "/v1/commit-authority"        "MS041 / SDD-043" || failures=$((failures + 1))

# MS042 / SDD-050 D-2 — tool-authority schema discovery surface.
check_route "/v1/tool-authority"          "MS042 / SDD-050" || failures=$((failures + 1))

# MS035 / SDD-044 D-2 — capability-tokens schema discovery surface.
check_route "/v1/capability-tokens"       "MS035 / SDD-044" || failures=$((failures + 1))

# MS037 / SDD-045 D-2 — filesystem-boundary schema discovery.
check_route "/v1/filesystem-boundary"     "MS037 / SDD-045" || failures=$((failures + 1))

# MS038 / SDD-046 D-2 — network-boundary schema discovery.
check_route "/v1/network-boundary"        "MS038 / SDD-046" || failures=$((failures + 1))

# MS032 / SDD-047 D-2 — sandbox-tiers schema discovery.
check_route "/v1/sandbox-tiers"           "MS032 / SDD-047" || failures=$((failures + 1))

# MS034 / SDD-048 D-2 — communication-boundary schema discovery.
check_route "/v1/communication-boundary"  "MS034 / SDD-048" || failures=$((failures + 1))

# MS039 + MS040 / SDD-049 D-2 — authority discovery (7 levels + 5
# rings + 6 profiles + 4 transition gates + 5 authority crates).
check_route "/v1/authority"               "MS039 + MS040 / SDD-049" || failures=$((failures + 1))

# MS033 / SDD-051 D-2 — policy-cluster discovery (8 functional
# clusters organizing the 36-crate selfdef-policy-* ecosystem).
check_route "/v1/policy"                  "MS033 / SDD-051" || failures=$((failures + 1))

# MS015 / SDD-053 D-2 — NATS bridge schema discovery.
check_route "/v1/nats"                    "MS015 / SDD-053" || failures=$((failures + 1))

# MS011 Z-11 / SDD-026 + SD-R84 — MCP-interop foundation discovery.
check_route "/v1/mcp"                     "MS011 Z-11 / SDD-026" || failures=$((failures + 1))

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-api-endpoints FAIL: ${failures} missing route(s)"
    echo "  See ~/devops-solutions-information-hub/wiki/runbooks/ux-coherence-failures.md for fix procedure."
    exit 1
fi

echo "L1-api-endpoints PASS: all SDD-promised routes declared"
