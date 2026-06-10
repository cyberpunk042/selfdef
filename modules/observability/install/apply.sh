#!/usr/bin/env bash
# observability — apply.
#
# Renders the Prometheus scrape config + Grafana dashboard JSON
# from the assets/ templates. In `bundled` mode, drops them under
# /etc/prometheus/conf.d and /var/lib/grafana/dashboards and reloads
# Prometheus so the new scrape picks up. In `external` mode, drops
# them under a staging dir for the operator to sync out.
#
# Idempotent. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="observability"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_OBSERVABILITY_CONFIG:-/etc/selfdef/modules/observability.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
ASSETS_DIR="${SELFDEF_OBSERVABILITY_ASSETS:-${MODULE_DIR}/assets}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$ASSETS_DIR"  ]] || die "assets dir missing: $ASSETS_DIR"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "bundled")
case "$PROFILE" in
    bundled|external) ;;
    *) die "profile must be bundled|external, got '$PROFILE'" ;;
esac

# Default matches the shipped profile defaults (bundled.toml, external.toml).
# Two targets: Tetragon's metrics endpoint + selfdef-daemon's /metrics. See
# modules/observability/README.md "Scraping the daemon" for the bearer-token
# requirement on the daemon endpoint.
SCRAPE_TARGETS=$(toml_get scrape_targets "$CONFIG_FILE" || echo "localhost:2112, localhost:8443")
DASHBOARD_UID=$(toml_get  dashboard_uid   "$CONFIG_FILE" || echo "selfdef")
DASHBOARD_TITLE=$(toml_get dashboard_title "$CONFIG_FILE" || echo "selfdef — Host Self-Defense")

case "$PROFILE" in
    bundled)
        PROM_DIR=$(toml_get prometheus_conf_dir    "$CONFIG_FILE" || echo "/etc/prometheus/conf.d")
        PROM_SVC=$(toml_get prometheus_service     "$CONFIG_FILE" || echo "prometheus.service")
        GRAFANA_DIR=$(toml_get grafana_dashboards_dir "$CONFIG_FILE" || echo "/var/lib/grafana/dashboards/selfdef")
        PROM_RULES_DIR=$(toml_get prometheus_rules_dir "$CONFIG_FILE" || echo "/etc/prometheus/rules.d")
        SCRAPE_DST="${PROM_DIR}/selfdef.yml"
        DASHBOARD_DST="${GRAFANA_DIR}/selfdef.json"
        ALERTS_DST="${PROM_RULES_DIR}/selfdef.yml"
        ;;
    external)
        STAGING_DIR=$(toml_get staging_dir "$CONFIG_FILE" || echo "/var/lib/selfdef/observability/staging")
        SCRAPE_DST="${STAGING_DIR}/prometheus/selfdef.yml"
        DASHBOARD_DST="${STAGING_DIR}/grafana/selfdef.json"
        ALERTS_DST="${STAGING_DIR}/prometheus/rules/selfdef.yml"
        ;;
esac

changes=0

# Ensure destination dirs exist.
for d in "$(dirname "$SCRAPE_DST")" "$(dirname "$DASHBOARD_DST")" "$(dirname "$ALERTS_DST")"; do
    if [[ ! -d "$d" ]]; then
        run "create $d" -- mkdir -p "$d"
        changes=$((changes + 1))
    fi
done

# Render scrape config.
NEW_SCRAPE=$(mktemp)
# Use :- so the trap is safe under `set -u` if apply.sh exits between here and
# the NEW_DASHBOARD assignment below (e.g. a render/manifest failure) — without
# it the trap itself errors "NEW_DASHBOARD: unbound variable", masking the real
# cause.
trap 'rm -f "${NEW_SCRAPE:-}" "${NEW_DASHBOARD:-}"' EXIT
render_scrape_config "${ASSETS_DIR}/scrape/selfdef.yml.template" "$NEW_SCRAPE" "$SCRAPE_TARGETS"

if [[ ! -f "$SCRAPE_DST" ]] || ! cmp -s "$NEW_SCRAPE" "$SCRAPE_DST"; then
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY-RUN: would write $SCRAPE_DST"
    else
        install -m 0644 "$NEW_SCRAPE" "$SCRAPE_DST"
    fi
    changes=$((changes + 1))
fi
# F-2027-024: record both rendered files in the manifest. The
# bool above only counts diff-based changes; we want to record
# unconditionally so an idempotent re-apply still leaves the
# manifest complete.
module_record_file "$SCRAPE_DST"

# Render dashboard.
NEW_DASHBOARD=$(mktemp)
render_dashboard "${ASSETS_DIR}/dashboards/selfdef.json.template" "$NEW_DASHBOARD" "$DASHBOARD_UID" "$DASHBOARD_TITLE"

if [[ ! -f "$DASHBOARD_DST" ]] || ! cmp -s "$NEW_DASHBOARD" "$DASHBOARD_DST"; then
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY-RUN: would write $DASHBOARD_DST"
    else
        install -m 0644 "$NEW_DASHBOARD" "$DASHBOARD_DST"
    fi
    changes=$((changes + 1))
fi
module_record_file "$DASHBOARD_DST"

# Drop the Prometheus alert rules. The template ships the Prometheus
# alert rule groups: MS027 four-watchdog, M060 cross-repo mirror-export,
# SDD-062 detection-watchdog routed findings, MS011 storage thresholds,
# and selfdef-meta-observability (metrics-ingest-lag). All carry
# runbook_url. Verbatim copy today (no placeholder substitution), but
# installed via the same pattern so a future template variable can be
# wired in without changing the deployment shape. (Count-free by design:
# the rule set grows; the source-of-truth count lives in the template.)
ALERTS_TEMPLATE="${ASSETS_DIR}/alerts/selfdef.yml.template"
if [[ -f "$ALERTS_TEMPLATE" ]]; then
    if [[ ! -f "$ALERTS_DST" ]] || ! cmp -s "$ALERTS_TEMPLATE" "$ALERTS_DST"; then
        if [[ "$DRY_RUN" == "1" ]]; then
            log "DRY-RUN: would write $ALERTS_DST"
        else
            install -m 0644 "$ALERTS_TEMPLATE" "$ALERTS_DST"
        fi
        changes=$((changes + 1))
    fi
    module_record_file "$ALERTS_DST"
fi

# Reload Prometheus if bundled and something changed. Prometheus
# 2.x reloads its config on SIGHUP without a full restart.
if [[ "$PROFILE" == "bundled" ]] && [[ "$changes" -gt 0 ]]; then
    if command -v systemctl >/dev/null 2>&1; then
        if [[ "$DRY_RUN" == "1" ]]; then
            log "DRY-RUN: would reload $PROM_SVC"
        else
            systemctl reload-or-restart "$PROM_SVC" 2>/dev/null || \
                log "warning: could not reload $PROM_SVC (continuing — operator picks it up)"
        fi
    fi
fi

if [[ "$changes" -eq 0 ]]; then
    emit_status "ok" "observability profile=$PROFILE already at desired state"
else
    emit_status "ok" "observability profile=$PROFILE ($changes change(s)); scrape=$SCRAPE_DST dashboard=$DASHBOARD_DST"
fi
