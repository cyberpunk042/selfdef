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
if [[ -r "$CONFIG_FILE" ]]; then
    PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "$PROFILE")
    PROM_SVC=$(toml_get prometheus_service "$CONFIG_FILE" || echo "$PROM_SVC")
fi

# F-2027-024: walk the rendered-file manifest. apply.sh records
# both SCRAPE_DST and DASHBOARD_DST; we just iterate.
removed=0
manifest_count=0
while IFS= read -r dst; do
    [[ -z "$dst" ]] && continue
    manifest_count=$((manifest_count + 1))
    if [[ -f "$dst" ]]; then
        run "remove $dst" -- rm -f "$dst"
        removed=$((removed + 1))
    fi
done < <(module_render_files)

# Migration path: pre-v2 install. Re-derive the scrape/dashboard
# paths the same way apply.sh does and remove them.
if [[ "$manifest_count" -eq 0 && -r "$CONFIG_FILE" ]]; then
    case "$PROFILE" in
        bundled)
            PROM_DIR=$(toml_get prometheus_conf_dir    "$CONFIG_FILE" || echo "/etc/prometheus/conf.d")
            GRAFANA_DIR=$(toml_get grafana_dashboards_dir "$CONFIG_FILE" || echo "/var/lib/grafana/dashboards/selfdef")
            LEGACY_SCRAPE="${PROM_DIR}/selfdef.yml"
            LEGACY_DASHBOARD="${GRAFANA_DIR}/selfdef.json"
            ;;
        external)
            STAGING_DIR=$(toml_get staging_dir "$CONFIG_FILE" || echo "/var/lib/selfdef/observability/staging")
            LEGACY_SCRAPE="${STAGING_DIR}/prometheus/selfdef.yml"
            LEGACY_DASHBOARD="${STAGING_DIR}/grafana/selfdef.json"
            ;;
        *)
            LEGACY_SCRAPE=""
            LEGACY_DASHBOARD=""
            ;;
    esac
    for f in "$LEGACY_SCRAPE" "$LEGACY_DASHBOARD"; do
        [[ -z "$f" ]] && continue
        if [[ -f "$f" ]]; then
            run "remove $f (legacy enum)" -- rm -f "$f"
            removed=$((removed + 1))
        fi
    done
fi

# Bundled profile: signal Prometheus to drop the scrape job.
if [[ "$PROFILE" == "bundled" ]] && [[ "$removed" -gt 0 ]] && command -v systemctl >/dev/null 2>&1; then
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY-RUN: would reload $PROM_SVC"
    else
        systemctl reload-or-restart "$PROM_SVC" 2>/dev/null || true
    fi
fi

module_clear_manifest

emit_status "ok" "observability profile=$PROFILE removed $removed file(s)"
