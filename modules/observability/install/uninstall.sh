#!/usr/bin/env bash
# observability — uninstall.
#
# Removes the rendered scrape config + dashboard JSON. Does NOT
# touch Prometheus or Grafana itself — operator owns those.
# Idempotent. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="observability"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_OBSERVABILITY_CONFIG:-/etc/selfdef/modules/observability.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

PROFILE="bundled"
PROM_SVC="prometheus.service"
SCRAPE_DST="/etc/prometheus/conf.d/selfdef.yml"
DASHBOARD_DST="/var/lib/grafana/dashboards/selfdef/selfdef.json"
if [[ -r "$CONFIG_FILE" ]]; then
    PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "$PROFILE")
    case "$PROFILE" in
        bundled)
            PROM_DIR=$(toml_get prometheus_conf_dir    "$CONFIG_FILE" || echo "/etc/prometheus/conf.d")
            PROM_SVC=$(toml_get prometheus_service     "$CONFIG_FILE" || echo "$PROM_SVC")
            GRAFANA_DIR=$(toml_get grafana_dashboards_dir "$CONFIG_FILE" || echo "/var/lib/grafana/dashboards/selfdef")
            SCRAPE_DST="${PROM_DIR}/selfdef.yml"
            DASHBOARD_DST="${GRAFANA_DIR}/selfdef.json"
            ;;
        external)
            STAGING_DIR=$(toml_get staging_dir "$CONFIG_FILE" || echo "/var/lib/selfdef/observability/staging")
            SCRAPE_DST="${STAGING_DIR}/prometheus/selfdef.yml"
            DASHBOARD_DST="${STAGING_DIR}/grafana/selfdef.json"
            ;;
    esac
fi

removed=0
for f in "$SCRAPE_DST" "$DASHBOARD_DST"; do
    if [[ -f "$f" ]]; then
        run "remove $f" -- rm -f "$f"
        removed=$((removed + 1))
    fi
done

# Bundled profile: signal Prometheus to drop the scrape job.
if [[ "$PROFILE" == "bundled" ]] && [[ "$removed" -gt 0 ]] && command -v systemctl >/dev/null 2>&1; then
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY-RUN: would reload $PROM_SVC"
    else
        systemctl reload-or-restart "$PROM_SVC" 2>/dev/null || true
    fi
fi

emit_status "ok" "observability profile=$PROFILE removed $removed file(s)"
