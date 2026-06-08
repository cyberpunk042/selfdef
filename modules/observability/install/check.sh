#!/usr/bin/env bash
# observability — check. Read-only.
#
# Verifies the rendered scrape config + dashboard JSON exist at the
# expected location for the active profile. Does NOT call out to
# Prometheus / Grafana — they're operator-owned services and a
# down service is the operator's problem, not the module's.

set -euo pipefail

MODULE="observability"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_OBSERVABILITY_CONFIG:-/etc/selfdef/modules/observability.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "bundled")
case "$PROFILE" in
    bundled)
        PROM_DIR=$(toml_get prometheus_conf_dir    "$CONFIG_FILE" || echo "/etc/prometheus/conf.d")
        GRAFANA_DIR=$(toml_get grafana_dashboards_dir "$CONFIG_FILE" || echo "/var/lib/grafana/dashboards/selfdef")
        SCRAPE_DST="${PROM_DIR}/selfdef.yml"
        DASHBOARD_DST="${GRAFANA_DIR}/selfdef.json"
        ;;
    external)
        STAGING_DIR=$(toml_get staging_dir "$CONFIG_FILE" || echo "/var/lib/selfdef/observability/staging")
        SCRAPE_DST="${STAGING_DIR}/prometheus/selfdef.yml"
        DASHBOARD_DST="${STAGING_DIR}/grafana/selfdef.json"
        ;;
    *) die "profile must be bundled|external, got '$PROFILE'" ;;
esac

[[ -f "$SCRAPE_DST"    ]] || die "scrape config missing: $SCRAPE_DST (run apply)"
[[ -f "$DASHBOARD_DST" ]] || die "dashboard missing: $DASHBOARD_DST (run apply)"

# SDD-079 operability probe (opt-in, WARN-ONLY): verify the live
# Tetragon /metrics endpoint still exposes the four series the
# dashboard pins (assets/contracts/tetragon-metrics.toml). Closes the
# F-2026-052 silent-flat-panel failure mode: a Tetragon release that
# renames a series renders its panel flat with no error. This probe
# turns that into a loud, actionable warn.
#
# Never die() — Tetragon being down is the operator's problem, not the
# module's (per this file's header doctrine), and check.sh's contract
# is "rendered files present => ok". Gated on the opt-in env var so the
# default read-only check stays offline + side-effect-free.
probe_tetragon_series() {
    [[ "${SELFDEF_OBSERVABILITY_PROBE_TETRAGON:-0}" == "1" ]] || return 0
    command -v curl >/dev/null 2>&1 || { emit_status "warn" "tetragon series probe skipped: curl not available"; return 0; }

    local contract="${LIB_DIR}/../assets/contracts/tetragon-metrics.toml"
    [[ -r "$contract" ]] || { emit_status "warn" "tetragon series probe skipped: contract not readable: $contract"; return 0; }

    local url="${SELFDEF_TETRAGON_METRICS_URL:-http://127.0.0.1:2112/metrics}"
    local body
    if ! body=$(curl -fsS --max-time 5 "$url" 2>/dev/null); then
        emit_status "warn" "tetragon metrics endpoint unreachable ($url); skipping series probe"
        return 0
    fi

    # Pinned series names = the `name = "tetragon_..."` lines in the contract.
    local missing=0 series
    while IFS= read -r series; do
        [[ -n "$series" ]] || continue
        if ! grep -q "^${series}[ {]" <<<"$body"; then
            emit_status "warn" "tetragon series absent from live exposition: ${series} (dashboard panel will render flat; see SDD-079)"
            missing=$((missing + 1))
        fi
    done < <(grep -oE 'name[[:space:]]*=[[:space:]]*"tetragon_[a-z_]+"' "$contract" | grep -oE 'tetragon_[a-z_]+')

    if [[ "$missing" -eq 0 ]]; then
        emit_status "ok" "tetragon series probe: all 4 pinned series present at $url"
    fi
    return 0
}

probe_tetragon_series

emit_status "ok" "observability profile=$PROFILE scrape=$SCRAPE_DST dashboard=$DASHBOARD_DST"
