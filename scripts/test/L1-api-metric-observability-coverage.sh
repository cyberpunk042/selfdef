#!/usr/bin/env bash
# L1-api-metric-observability-coverage.sh — every emitted /metrics family
# has an observability home (P4 verification gate)
#
# The existing L1-grafana-template.sh gate is one-directional: it asserts a
# FIXED list of series IS present in the dashboard. Nothing catches the
# reverse — a NEW metric family added to selfdef-api's /metrics endpoint
# that ships with no dashboard panel and no alert rule, i.e. emitted but
# never observed. That is a P4 violation: a declaration (the metric) with
# no verification gate (an operator surface that reads it).
#
# This gate enumerates every family the selfdef-api metrics renderer emits
# (the canonical `# TYPE selfdef_<name>` lines in metrics.rs) and requires
# each to be EITHER:
#   - referenced by the bundled Grafana dashboard template, OR
#   - referenced by the bundled Prometheus alert-rules template, OR
#   - on the explicit ALLOW-LIST below (info/aggregate metrics that are
#     deliberately not panelled, each with a stated reason).
#
# A metric that is neither covered nor allow-listed fails the gate: the
# author must add a panel/alert or justify the exemption in the allow-list.
#
# Static check — greps metrics.rs + the two templates; no daemon, Grafana,
# or Prometheus instance needed.
#
# Source: P4 (Declarations Aspirational Until Verified) applied to the
# producer→observability contract. Complements L1-grafana-template.sh
# (forward direction) by locking the reverse direction.
# Run: bash scripts/test/L1-api-metric-observability-coverage.sh
set -euo pipefail

METRICS_RS="${METRICS_RS:-crates/selfdef-api/src/metrics.rs}"
DASH="${DASH:-modules/observability/assets/dashboards/selfdef.json.template}"
ALERTS="${ALERTS:-modules/observability/assets/alerts/selfdef.yml.template}"

for f in "${METRICS_RS}" "${DASH}" "${ALERTS}"; do
    if [[ ! -f "${f}" ]]; then
        echo "L1-api-metric-observability-coverage FAIL: ${f} not found" >&2
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# ALLOW-LIST — emitted families that are deliberately NOT panelled/alerted.
# Each entry MUST carry a reason. Keep this list short; the default is to
# give a metric a real observability home, not to exempt it.
# ---------------------------------------------------------------------------
declare -A ALLOWED=(
    [selfdef_build_info]="info metric — a constant 1 whose value is its label set (version/commit); surfaced via labels on other panels, not a standalone series."
    [selfdef_events_total]="aggregate rollup — the 'events / second by class' panel (selfdef_events_by_class_total) sums to this; a dedicated total panel would duplicate it."
    [selfdef_findings_total]="aggregate rollup — the by-severity and by-rule panels (selfdef_findings_by_severity_total / _by_rule_total) cover this; a dedicated total panel would duplicate them."
)

echo "L1-api-metric-observability-coverage: checking ${METRICS_RS}"

# Canonical emitted families: the `# TYPE selfdef_<name> <kind>` lines.
mapfile -t EMITTED < <(grep -oE '# TYPE selfdef_[a-z0-9_]+' "${METRICS_RS}" \
    | awk '{print $3}' | sort -u)

if [[ "${#EMITTED[@]}" -eq 0 ]]; then
    echo "  FAIL no '# TYPE selfdef_*' lines found — renderer changed shape?"
    exit 1
fi
echo "  found ${#EMITTED[@]} emitted metric families"

covered() {
    # A family is covered if its name appears anywhere in the dashboard or
    # alerts template (bare inside an expr, or quoted as a series name).
    grep -qF "$1" "${DASH}" || grep -qF "$1" "${ALERTS}"
}

failures=0
for m in "${EMITTED[@]}"; do
    if covered "${m}"; then
        echo "  PASS ${m} (dashboard/alert)"
    elif [[ -n "${ALLOWED[$m]+x}" ]]; then
        echo "  PASS ${m} (allow-listed: ${ALLOWED[$m]})"
    else
        echo "  FAIL ${m} — emitted by /metrics but no dashboard panel, no"
        echo "       alert rule, and not on the allow-list. Add a panel to"
        echo "       ${DASH}, an alert to ${ALERTS}, or an allow-list entry"
        echo "       (with a reason) in this gate."
        failures=$((failures + 1))
    fi
done

# Guard the allow-list against rot: an allow-listed name that is no longer
# emitted (renamed/removed metric) is stale and should be cleaned up.
for m in "${!ALLOWED[@]}"; do
    found=0
    for e in "${EMITTED[@]}"; do
        [[ "${e}" == "${m}" ]] && { found=1; break; }
    done
    if [[ "${found}" -eq 0 ]]; then
        echo "  FAIL allow-list entry ${m} is no longer emitted by ${METRICS_RS}"
        echo "       — remove the stale allow-list entry from this gate."
        failures=$((failures + 1))
    fi
done

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-api-metric-observability-coverage FAIL: ${failures} issue(s)"
    exit 1
fi

echo "L1-api-metric-observability-coverage PASS: all ${#EMITTED[@]} emitted families have an observability home (panel/alert/justified-exemption)"
