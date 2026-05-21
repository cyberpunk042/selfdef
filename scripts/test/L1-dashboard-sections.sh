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
check "HTML: health-section"              "${HTML}" 'id="health-section"'         || failures=$((failures + 1))
check "HTML: health aggregate"            "${HTML}" 'id="health-aggregate"'       || failures=$((failures + 1))
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
check "JS: refreshHealth()"               "${JS}"   'function refreshHealth'         || failures=$((failures + 1))
check "JS: parsePromExposition()"         "${JS}"   'function parsePromExposition'   || failures=$((failures + 1))

# JS auto-refresh intervals wired (every panel of the four-watchdog set)
check "JS: setInterval refreshFrictionAudit"  "${JS}" 'setInterval\(refreshFrictionAudit' || failures=$((failures + 1))
check "JS: setInterval refreshPerimeter"       "${JS}" 'setInterval\(refreshPerimeter'     || failures=$((failures + 1))
check "JS: setInterval refreshGuardian"        "${JS}" 'setInterval\(refreshGuardian'      || failures=$((failures + 1))
check "JS: setInterval refreshScheduler"       "${JS}" 'setInterval\(refreshScheduler'     || failures=$((failures + 1))
check "JS: setInterval refreshModules"          "${JS}" 'setInterval\(refreshModules'        || failures=$((failures + 1))
check "JS: setInterval refreshAlerts"            "${JS}" 'setInterval\(refreshAlerts'          || failures=$((failures + 1))
check "JS: setInterval refreshHardware"          "${JS}" 'setInterval\(refreshHardware'        || failures=$((failures + 1))
check "JS: setInterval refreshNetwork"           "${JS}" 'setInterval\(refreshNetwork'         || failures=$((failures + 1))
check "JS: setInterval refreshStorage"           "${JS}" 'setInterval\(refreshStorage'         || failures=$((failures + 1))
check "JS: setInterval refreshRaid"              "${JS}" 'setInterval\(refreshRaid'            || failures=$((failures + 1))
check "JS: setInterval refreshGpu"               "${JS}" 'setInterval\(refreshGpu'             || failures=$((failures + 1))
check "JS: setInterval refreshCpu"               "${JS}" 'setInterval\(refreshCpu'             || failures=$((failures + 1))
check "JS: setInterval refreshHealth"            "${JS}" 'setInterval\(refreshHealth'          || failures=$((failures + 1))

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
check "JS: GET /v1/health"               "${JS}"   'get\("/v1/health"\)'         || failures=$((failures + 1))

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
