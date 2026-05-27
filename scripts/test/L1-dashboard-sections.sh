#!/usr/bin/env bash
# L1-dashboard-sections.sh — MS045 SDD-030 / MS043 dashboard surface gate
#
# Verifies the operator dashboard's HTML + JS declare the three-watchdog-
# trio panels (friction-audit, perimeter, guardian) AND wire their
# refresh handlers + auto-refresh intervals.
#
# Static check — grep on dashboard/*.{html,js,css}.
#
# Source: SDD-030 D2-style extension + SDD-027/028/029 cockpit binding
# Run: bash scripts/test/L1-dashboard-sections.sh
set -euo pipefail

HTML="${HTML:-dashboard/index.html}"
JS="${JS:-dashboard/app.js}"
CSS="${CSS:-dashboard/dashboard.css}"

for f in "${HTML}" "${JS}" "${CSS}"; do
    if [[ ! -f "${f}" ]]; then
        echo "L1-dashboard-sections FAIL: ${f} not found" >&2
        exit 1
    fi
done

check() {
    local what="$1"
    local file="$2"
    local pattern="$3"
    if grep -qE "${pattern}" "${file}"; then
        echo "  PASS ${what}"
    else
        echo "  FAIL ${what} — pattern ${pattern!r} not found in ${file}"
        return 1
    fi
}

echo "L1-dashboard-sections: checking three-watchdog-trio dashboard surface"

failures=0
# HTML section presence (SDD-027 / 028 / 029 D6/D8 cockpit binding)
check "HTML: friction-audit-section"   "${HTML}" 'id="friction-audit-section"' || failures=$((failures + 1))
check "HTML: perimeter-section"         "${HTML}" 'id="perimeter-section"'      || failures=$((failures + 1))
check "HTML: guardian-section"          "${HTML}" 'id="guardian-section"'       || failures=$((failures + 1))
check "HTML: scheduler-section"          "${HTML}" 'id="scheduler-section"'      || failures=$((failures + 1))
check "HTML: modules-section"            "${HTML}" 'id="modules-section"'        || failures=$((failures + 1))
check "HTML: alerts-section"              "${HTML}" 'id="alerts-section"'         || failures=$((failures + 1))
check "HTML: alerts aggregate"            "${HTML}" 'id="alerts-aggregate"'       || failures=$((failures + 1))
check "HTML: panel-nav"                   "${HTML}" 'id="panel-nav"'              || failures=$((failures + 1))
check "HTML: tab-nav scaffold (SDD-056)"  "${HTML}" 'id="tab-nav"'                || failures=$((failures + 1))
check "JS: switchTab() (SDD-056 step 3)"  "${JS}"   'function switchTab'           || failures=$((failures + 1))
check "JS: hashchange listener (SDD-056)" "${JS}"   'addEventListener\("hashchange"' || failures=$((failures + 1))
check "HTML: tab-mode-toggle (SDD-056 step 5)" "${HTML}" 'id="tab-mode-toggle"'    || failures=$((failures + 1))
check "JS: tab-mode-toggle listener (SDD-056)" "${JS}"  'TAB_MODE_KEY|tab-mode-toggle' || failures=$((failures + 1))
check "HTML: hardware-section"            "${HTML}" 'id="hardware-section"'       || failures=$((failures + 1))
check "HTML: hardware sain01 badge"       "${HTML}" 'id="hardware-sain01-badge"'  || failures=$((failures + 1))
check "HTML: network-section"             "${HTML}" 'id="network-section"'        || failures=$((failures + 1))
check "HTML: network aggregate"           "${HTML}" 'id="network-aggregate"'      || failures=$((failures + 1))
check "HTML: storage-section"             "${HTML}" 'id="storage-section"'        || failures=$((failures + 1))
check "HTML: storage aggregate"           "${HTML}" 'id="storage-aggregate"'      || failures=$((failures + 1))
check "HTML: raid-section"                "${HTML}" 'id="raid-section"'           || failures=$((failures + 1))
check "HTML: raid aggregate"              "${HTML}" 'id="raid-aggregate"'         || failures=$((failures + 1))
check "HTML: gpu-section"                 "${HTML}" 'id="gpu-section"'            || failures=$((failures + 1))
check "HTML: gpu aggregate"               "${HTML}" 'id="gpu-aggregate"'          || failures=$((failures + 1))
check "HTML: cpu-section"                 "${HTML}" 'id="cpu-section"'            || failures=$((failures + 1))
check "HTML: cpu aggregate"               "${HTML}" 'id="cpu-aggregate"'          || failures=$((failures + 1))
check "HTML: flex-profile-section"        "${HTML}" 'id="flex-profile-section"'   || failures=$((failures + 1))
check "HTML: flex-profile aggregate"      "${HTML}" 'id="flex-profile-aggregate"' || failures=$((failures + 1))
check "HTML: inference-backends-section"  "${HTML}" 'id="inference-backends-section"'   || failures=$((failures + 1))
check "HTML: inference-backends aggregate" "${HTML}" 'id="inference-backends-aggregate"' || failures=$((failures + 1))
check "HTML: health-section"              "${HTML}" 'id="health-section"'         || failures=$((failures + 1))
check "HTML: health aggregate"            "${HTML}" 'id="health-aggregate"'       || failures=$((failures + 1))
check "HTML: audit-chains-section"        "${HTML}" 'id="audit-chains-section"'   || failures=$((failures + 1))
check "HTML: audit-chains aggregate"      "${HTML}" 'id="audit-chains-aggregate"' || failures=$((failures + 1))
check "HTML: friction-audit aggregate"  "${HTML}" 'id="fa-aggregate"'            || failures=$((failures + 1))
check "HTML: perimeter aggregate"        "${HTML}" 'id="perim-aggregate"'         || failures=$((failures + 1))
check "HTML: guardian aggregate"         "${HTML}" 'id="guard-aggregate"'         || failures=$((failures + 1))
check "HTML: scheduler aggregate"        "${HTML}" 'id="sched-aggregate"'         || failures=$((failures + 1))

# JS handler functions
check "JS: refreshFrictionAudit()"      "${JS}"   'function refreshFrictionAudit' || failures=$((failures + 1))
check "JS: refreshPerimeter()"           "${JS}"   'function refreshPerimeter'      || failures=$((failures + 1))
check "JS: refreshGuardian()"            "${JS}"   'function refreshGuardian'       || failures=$((failures + 1))
check "JS: refreshScheduler()"           "${JS}"   'function refreshScheduler'      || failures=$((failures + 1))
check "JS: refreshModules()"             "${JS}"   'function refreshModules'        || failures=$((failures + 1))
check "JS: refreshAlerts()"               "${JS}"   'function refreshAlerts'         || failures=$((failures + 1))
check "JS: refreshHardware()"             "${JS}"   'function refreshHardware'       || failures=$((failures + 1))
check "JS: refreshNetwork()"              "${JS}"   'function refreshNetwork'        || failures=$((failures + 1))
check "JS: refreshStorage()"              "${JS}"   'function refreshStorage'        || failures=$((failures + 1))
check "JS: refreshRaid()"                 "${JS}"   'function refreshRaid'           || failures=$((failures + 1))
check "JS: refreshGpu()"                  "${JS}"   'function refreshGpu'            || failures=$((failures + 1))
check "JS: refreshCpu()"                  "${JS}"   'function refreshCpu'            || failures=$((failures + 1))
check "JS: refreshFlexProfile()"          "${JS}"   'function refreshFlexProfile'    || failures=$((failures + 1))
check "JS: refreshInferenceBackends()"    "${JS}"   'function refreshInferenceBackends' || failures=$((failures + 1))
check "JS: refreshHealth()"               "${JS}"   'function refreshHealth'         || failures=$((failures + 1))
check "JS: refreshAuditChains()"          "${JS}"   'function refreshAuditChains'    || failures=$((failures + 1))
check "JS: parsePromExposition()"         "${JS}"   'function parsePromExposition'   || failures=$((failures + 1))

# MS035 / SDD-044 — IPS capability-token doctrine panel (first of the IPS
# authority/boundary surfaces wired into the operator dashboard).
check "HTML: capability-tokens-section"   "${HTML}" 'id="capability-tokens-section"' || failures=$((failures + 1))
check "HTML: captok aggregate"            "${HTML}" 'id="captok-aggregate"'          || failures=$((failures + 1))
check "HTML: capability-tokens nav link"  "${HTML}" '#capability-tokens-section'     || failures=$((failures + 1))
check "JS: refreshCapabilityTokens()"     "${JS}"   'function refreshCapabilityTokens' || failures=$((failures + 1))
check "JS: capability-tokens fetches /v1" "${JS}"   '/v1/capability-tokens'          || failures=$((failures + 1))
check "JS: interval refreshCapabilityTokens" "${JS}" 'gatedInterval\(refreshCapabilityTokens' || failures=$((failures + 1))
# MS042 / SDD-050 — IPS tool-authority gate-pipeline panel.
check "HTML: tool-authority-section"      "${HTML}" 'id="tool-authority-section"'   || failures=$((failures + 1))
check "HTML: tool-authority aggregate"    "${HTML}" 'id="ta-aggregate"'              || failures=$((failures + 1))
check "JS: refreshToolAuthority()"        "${JS}"   'function refreshToolAuthority'  || failures=$((failures + 1))
check "JS: tool-authority fetches /v1"    "${JS}"   '/v1/tool-authority'             || failures=$((failures + 1))
check "JS: interval refreshToolAuthority" "${JS}"   'gatedInterval\(refreshToolAuthority' || failures=$((failures + 1))
# MS041 / SDD-043 — IPS commit-authority durable-change envelope panel.
check "HTML: commit-authority-section"    "${HTML}" 'id="commit-authority-section"' || failures=$((failures + 1))
check "HTML: commit-authority aggregate"  "${HTML}" 'id="ca-aggregate"'             || failures=$((failures + 1))
check "JS: refreshCommitAuthority()"      "${JS}"   'function refreshCommitAuthority' || failures=$((failures + 1))
check "JS: commit-authority fetches /v1"  "${JS}"   '/v1/commit-authority'          || failures=$((failures + 1))
check "JS: interval refreshCommitAuthority" "${JS}" 'gatedInterval\(refreshCommitAuthority' || failures=$((failures + 1))
# MS032 / SDD-047 — IPS sandbox tier ladder panel.
check "HTML: sandbox-tiers-section"       "${HTML}" 'id="sandbox-tiers-section"'    || failures=$((failures + 1))
check "HTML: sandbox-tiers aggregate"     "${HTML}" 'id="st-aggregate"'             || failures=$((failures + 1))
check "JS: refreshSandboxTiers()"         "${JS}"   'function refreshSandboxTiers'  || failures=$((failures + 1))
check "JS: sandbox-tiers fetches /v1"     "${JS}"   '/v1/sandbox-tiers'             || failures=$((failures + 1))
check "JS: interval refreshSandboxTiers"  "${JS}"   'gatedInterval\(refreshSandboxTiers' || failures=$((failures + 1))
# MS037 / SDD-045 — IPS explicit-exchange filesystem-boundary panel.
check "HTML: filesystem-boundary-section" "${HTML}" 'id="filesystem-boundary-section"' || failures=$((failures + 1))
check "HTML: filesystem-boundary aggregate" "${HTML}" 'id="fsb-aggregate"' || failures=$((failures + 1))
check "JS: refreshFilesystemBoundary()"  "${JS}"   'function refreshFilesystemBoundary' || failures=$((failures + 1))
check "JS: filesystem-boundary fetches /v1" "${JS}" '/v1/filesystem-boundary' || failures=$((failures + 1))
check "JS: interval refreshFilesystemBoundary" "${JS}" 'gatedInterval\(refreshFilesystemBoundary' || failures=$((failures + 1))
# MS038 / SDD-046 — IPS network-egress boundary panel.
check "HTML: network-boundary-section"  "${HTML}" 'id="network-boundary-section"' || failures=$((failures + 1))
check "HTML: network-boundary aggregate" "${HTML}" 'id="nb-aggregate"' || failures=$((failures + 1))
check "JS: refreshNetworkBoundary()"    "${JS}"   'function refreshNetworkBoundary' || failures=$((failures + 1))
check "JS: network-boundary fetches /v1" "${JS}" '/v1/network-boundary' || failures=$((failures + 1))
check "JS: interval refreshNetworkBoundary" "${JS}" 'gatedInterval\(refreshNetworkBoundary' || failures=$((failures + 1))
# MS034 / SDD-048 — IPS communication-boundary panel.
check "HTML: communication-boundary-section" "${HTML}" 'id="communication-boundary-section"' || failures=$((failures + 1))
check "HTML: communication-boundary aggregate" "${HTML}" 'id="cb-aggregate"' || failures=$((failures + 1))
check "JS: refreshCommunicationBoundary()" "${JS}" 'function refreshCommunicationBoundary' || failures=$((failures + 1))
check "JS: communication-boundary fetches /v1" "${JS}" '/v1/communication-boundary' || failures=$((failures + 1))
check "JS: interval refreshCommunicationBoundary" "${JS}" 'gatedInterval\(refreshCommunicationBoundary' || failures=$((failures + 1))
# MS039 + MS040 / SDD-049 — IPS authority-model panel (capstone).
check "HTML: authority-section"          "${HTML}" 'id="authority-section"' || failures=$((failures + 1))
check "HTML: authority aggregate"        "${HTML}" 'id="auth-aggregate"' || failures=$((failures + 1))
check "JS: refreshAuthority()"           "${JS}"   'function refreshAuthority' || failures=$((failures + 1))
check "JS: authority fetches /v1"        "${JS}"   '/v1/authority' || failures=$((failures + 1))
check "JS: interval refreshAuthority"    "${JS}"   'gatedInterval\(refreshAuthority' || failures=$((failures + 1))
# MS033 / SDD-051 — IPS policy-bus dispatch fabric panel (completes the
# 9-surface IPS authority/boundary dashboard group).
check "HTML: policy-section"             "${HTML}" 'id="policy-section"' || failures=$((failures + 1))
check "HTML: policy aggregate"           "${HTML}" 'id="pol-aggregate"' || failures=$((failures + 1))
check "JS: refreshPolicy()"              "${JS}"   'function refreshPolicy' || failures=$((failures + 1))
check "JS: policy fetches /v1"           "${JS}"   '/v1/policy' || failures=$((failures + 1))
check "JS: interval refreshPolicy"       "${JS}"   'gatedInterval\(refreshPolicy' || failures=$((failures + 1))

# JS auto-refresh intervals wired (every panel of the four-watchdog set)
check "JS: setInterval refreshFrictionAudit"  "${JS}" 'gatedInterval\(refreshFrictionAudit|setInterval\(refreshFrictionAudit' || failures=$((failures + 1))
check "JS: setInterval refreshPerimeter"       "${JS}" 'gatedInterval\(refreshPerimeter|setInterval\(refreshPerimeter'     || failures=$((failures + 1))
check "JS: setInterval refreshGuardian"        "${JS}" 'gatedInterval\(refreshGuardian|setInterval\(refreshGuardian'      || failures=$((failures + 1))
check "JS: setInterval refreshScheduler"       "${JS}" 'gatedInterval\(refreshScheduler|setInterval\(refreshScheduler'     || failures=$((failures + 1))
check "JS: setInterval refreshModules"          "${JS}" 'gatedInterval\(refreshModules|setInterval\(refreshModules'        || failures=$((failures + 1))
check "JS: setInterval refreshAlerts"            "${JS}" 'gatedInterval\(refreshAlerts|setInterval\(refreshAlerts'          || failures=$((failures + 1))
check "JS: setInterval refreshHardware"          "${JS}" 'gatedInterval\(refreshHardware|setInterval\(refreshHardware'        || failures=$((failures + 1))
check "JS: setInterval refreshNetwork"           "${JS}" 'gatedInterval\(refreshNetwork|setInterval\(refreshNetwork'         || failures=$((failures + 1))
check "JS: setInterval refreshStorage"           "${JS}" 'gatedInterval\(refreshStorage|setInterval\(refreshStorage'         || failures=$((failures + 1))
check "JS: setInterval refreshRaid"              "${JS}" 'gatedInterval\(refreshRaid|setInterval\(refreshRaid'            || failures=$((failures + 1))
check "JS: setInterval refreshGpu"               "${JS}" 'gatedInterval\(refreshGpu|setInterval\(refreshGpu'             || failures=$((failures + 1))
check "JS: setInterval refreshCpu"               "${JS}" 'gatedInterval\(refreshCpu|setInterval\(refreshCpu'             || failures=$((failures + 1))
check "JS: setInterval refreshFlexProfile"       "${JS}" 'gatedInterval\(refreshFlexProfile|setInterval\(refreshFlexProfile'     || failures=$((failures + 1))
check "JS: setInterval refreshInferenceBackends" "${JS}" 'gatedInterval\(refreshInferenceBackends|setInterval\(refreshInferenceBackends' || failures=$((failures + 1))
check "JS: setInterval refreshHealth"            "${JS}" 'gatedInterval\(refreshHealth|setInterval\(refreshHealth'          || failures=$((failures + 1))
check "JS: setInterval refreshAuditChains"       "${JS}" 'gatedInterval\(refreshAuditChains|setInterval\(refreshAuditChains'     || failures=$((failures + 1))

# JS endpoint bindings (must match selfdef-api routes)
check "JS: GET /v1/friction-audit"      "${JS}"   'get\("/v1/friction-audit"\)' || failures=$((failures + 1))
check "JS: GET /v1/perimeter"            "${JS}"   'get\("/v1/perimeter"\)'      || failures=$((failures + 1))
check "JS: GET /v1/guardian"             "${JS}"   'get\("/v1/guardian"\)'       || failures=$((failures + 1))
check "JS: GET /v1/scheduler"            "${JS}"   'get\("/v1/scheduler"\)'      || failures=$((failures + 1))
check "JS: GET /v1/modules"              "${JS}"   'get\("/v1/modules"\)'        || failures=$((failures + 1))
check "JS: GET /v1/hardware/capabilities" "${JS}"  'get\("/v1/hardware/capabilities"\)' || failures=$((failures + 1))
check "JS: GET /v1/hardware/sain01"      "${JS}"   'get\("/v1/hardware/sain01"\)' || failures=$((failures + 1))
check "JS: GET /v1/network"              "${JS}"   'get\("/v1/network"\)'        || failures=$((failures + 1))
check "JS: GET /v1/storage"              "${JS}"   'get\("/v1/storage"\)'        || failures=$((failures + 1))
check "JS: GET /v1/raid"                 "${JS}"   'get\("/v1/raid"\)'           || failures=$((failures + 1))
check "JS: GET /v1/gpu"                  "${JS}"   'get\("/v1/gpu"\)'            || failures=$((failures + 1))
check "JS: GET /v1/cpu"                  "${JS}"   'get\("/v1/cpu"\)'            || failures=$((failures + 1))
check "JS: GET /v1/flex-profile"         "${JS}"   'get\("/v1/flex-profile"\)'   || failures=$((failures + 1))
check "JS: GET /v1/inference-backends"   "${JS}"   'get\("/v1/inference-backends"\)' || failures=$((failures + 1))
check "JS: GET /v1/health"               "${JS}"   'get\("/v1/health"\)'         || failures=$((failures + 1))
check "JS: GET /v1/audit-chains"         "${JS}"   'get\("/v1/audit-chains"\)'   || failures=$((failures + 1))

# CSS aggregate classes (all 8 states: ok/fail/override/unknown/alert/extended/degraded/backpressure)
for class in fa-ok fa-fail fa-override fa-unknown fa-alert fa-extended fa-degraded fa-backpressure; do
    check "CSS: .fa-aggregate.${class}" "${CSS}" "\.fa-aggregate\.${class}" || failures=$((failures + 1))
done

# MS043 F05093 — dashboard assets shipped by cargo-deb to
# /usr/share/selfdef/dashboard/* so selfdef-api can serve them at
# runtime under /dashboard/*.
DAEMON_CARGO="${DAEMON_CARGO:-crates/selfdef-daemon/Cargo.toml}"
for asset in index.html app.js dashboard.css manifest.json service-worker.js; do
    check "cargo-deb: ships dashboard/${asset}" "${DAEMON_CARGO}" \
        "dashboard/${asset}.*usr/share/selfdef/dashboard" || failures=$((failures + 1))
done

# selfdef-api wires the ServeDir mount.
API_LIB="${API_LIB:-crates/selfdef-api/src/lib.rs}"
check "selfdef-api: ServeDir import" "${API_LIB}" 'use tower_http::services::ServeDir' \
    || failures=$((failures + 1))
check "selfdef-api: DEFAULT_DASHBOARD_DIR const" "${API_LIB}" 'DEFAULT_DASHBOARD_DIR' \
    || failures=$((failures + 1))
check "selfdef-api: nest_service /dashboard" "${API_LIB}" 'nest_service\("/dashboard"' \
    || failures=$((failures + 1))

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-dashboard-sections FAIL: ${failures} drift(s) detected"
    exit 1
fi

echo "L1-dashboard-sections PASS: all three-watchdog-trio dashboard sections + handlers + intervals + endpoints + aggregate styles + serving wiring present"
