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

emit_status "ok" "observability profile=$PROFILE scrape=$SCRAPE_DST dashboard=$DASHBOARD_DST"
