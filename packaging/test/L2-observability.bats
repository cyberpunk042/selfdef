#!/usr/bin/env bats
# L2 bats unit tests for the observability module's install + assets.
#
# Locks the MS027 observability module's shipped surface against drift:
#   - install scripts (apply / check / uninstall / lib) exist + are
#     executable in the install/ dir
#   - both profiles (bundled, external) are supported by apply.sh
#   - the three asset templates (scrape config, dashboard JSON, alert
#     rules YAML) parse cleanly
#   - apply.sh actually wires the alerts template into the deployment
#     path (paired with the L1-prometheus-alerts gate)
#   - the alerts template emits ≥ 9 rules (the four-watchdog +
#     selfdef-bus baseline) and every rule carries a runbook_url
#     pointing into the info-hub
#   - apply.sh is SELFDEF_DRY_RUN=1 aware (idempotent dry-run from
#     the module-author contract in docs/dev/modules.md)
#
# Run with: bats packaging/test/L2-observability.bats

MODULE_DIR="${BATS_TEST_DIRNAME}/../../modules/observability"
INSTALL_DIR="${MODULE_DIR}/install"
ASSETS_DIR="${MODULE_DIR}/assets"

# ============================================================
# Module shape — manifest + install dir + asset dir
# ============================================================

@test "module.toml exists at the module root" {
    [ -f "${MODULE_DIR}/module.toml" ]
}

@test "module.toml declares name = \"observability\"" {
    grep -qE '^name[[:space:]]*=[[:space:]]*"observability"' "${MODULE_DIR}/module.toml"
}

@test "module.toml install.kind = \"script\" (not debian-package)" {
    grep -qE '^kind[[:space:]]*=[[:space:]]*"script"' "${MODULE_DIR}/module.toml"
}

@test "install/apply.sh exists + is executable" {
    [ -x "${INSTALL_DIR}/apply.sh" ]
}

@test "install/check.sh exists + is executable" {
    [ -x "${INSTALL_DIR}/check.sh" ]
}

@test "install/uninstall.sh exists + is executable" {
    [ -x "${INSTALL_DIR}/uninstall.sh" ]
}

@test "install/lib.sh exists (sourced by apply/check/uninstall)" {
    [ -f "${INSTALL_DIR}/lib.sh" ]
}

# ============================================================
# apply.sh — profile handling + dry-run + idempotency contract
# ============================================================

@test "apply.sh uses set -euo pipefail (fail-loud)" {
    grep -qE '^set -euo pipefail' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh supports both 'bundled' and 'external' profiles" {
    grep -q 'bundled)' "${INSTALL_DIR}/apply.sh"
    grep -q 'external)' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh refuses unknown profiles" {
    grep -qE "profile must be bundled\|external" "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh is SELFDEF_DRY_RUN aware" {
    grep -q 'SELFDEF_DRY_RUN' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh wires the alerts template (ALERTS_DST)" {
    grep -q 'ALERTS_DST' "${INSTALL_DIR}/apply.sh"
    grep -q 'alerts/selfdef.yml.template' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh wires the dashboard template" {
    grep -q 'dashboards/selfdef.json.template' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh wires the scrape config template" {
    grep -q 'scrape/selfdef.yml.template' "${INSTALL_DIR}/apply.sh"
}

# ============================================================
# check.sh — read-only verifier
# ============================================================

@test "check.sh uses set -euo pipefail" {
    grep -qE '^set -euo pipefail' "${INSTALL_DIR}/check.sh"
}

@test "check.sh declares DRY_RUN=0 (always read-only)" {
    grep -qE '^DRY_RUN=0$' "${INSTALL_DIR}/check.sh"
}

@test "check.sh emits status via emit_status (lib.sh helper)" {
    grep -q 'emit_status' "${INSTALL_DIR}/check.sh"
}

# ============================================================
# Asset templates — structural validity
# ============================================================

@test "assets/alerts/selfdef.yml.template parses as YAML" {
    python3 -c "import yaml; yaml.safe_load(open('${ASSETS_DIR}/alerts/selfdef.yml.template'))"
}

@test "assets/dashboards/selfdef.json.template parses as JSON" {
    python3 -c "import json; json.load(open('${ASSETS_DIR}/dashboards/selfdef.json.template'))"
}

@test "assets/scrape/selfdef.yml.template parses as YAML" {
    python3 -c "import yaml; yaml.safe_load(open('${ASSETS_DIR}/scrape/selfdef.yml.template'))"
}

@test "alerts template carries ≥ 9 rules (four-watchdog baseline)" {
    n="$(python3 -c "import yaml; d=yaml.safe_load(open('${ASSETS_DIR}/alerts/selfdef.yml.template')); print(sum(len(g['rules']) for g in d['groups']))")"
    [ "${n}" -ge 9 ]
}

@test "every alert has a runbook_url pointing into the info-hub" {
    bad="$(python3 -c "
import yaml
d = yaml.safe_load(open('${ASSETS_DIR}/alerts/selfdef.yml.template'))
bad = []
for g in d['groups']:
    for r in g['rules']:
        url = (r.get('annotations') or {}).get('runbook_url', '')
        if 'devops-solutions-information-hub' not in url or 'wiki/runbooks' not in url:
            bad.append(r['alert'])
print(','.join(bad))
")"
    [ -z "${bad}" ]
}

@test "dashboard template carries ≥ 20 panels" {
    n="$(python3 -c "import json; d=json.load(open('${ASSETS_DIR}/dashboards/selfdef.json.template')); print(len(d.get('panels', [])))")"
    [ "${n}" -ge 20 ]
}

# ============================================================
# apply.sh — dry-run smoke (bundled profile)
# ============================================================
# Light end-to-end smoke that exercises apply.sh in dry-run mode
# with a tmpdir config + override env vars. Verifies the script
# completes successfully and doesn't try to talk to a real
# Prometheus / Grafana service.

setup_dry_run() {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_DRY_RUN=1
    export SELFDEF_OBSERVABILITY_CONFIG="${TEST_DIR}/observability.toml"
    cat > "${SELFDEF_OBSERVABILITY_CONFIG}" <<EOF
profile = "bundled"
scrape_targets = "localhost:2112, localhost:8443"
prometheus_conf_dir    = "${TEST_DIR}/prom-conf"
prometheus_rules_dir   = "${TEST_DIR}/prom-rules"
prometheus_service     = "prometheus.service"
grafana_dashboards_dir = "${TEST_DIR}/grafana"
dashboard_uid          = "selfdef-test"
dashboard_title        = "selfdef — test"
EOF
}

teardown_dry_run() {
    rm -rf "${TEST_DIR}"
    unset SELFDEF_DRY_RUN SELFDEF_OBSERVABILITY_CONFIG
}

@test "apply.sh runs cleanly in dry-run mode (bundled profile)" {
    setup_dry_run
    run bash "${INSTALL_DIR}/apply.sh"
    teardown_dry_run
    [ "${status}" -eq 0 ]
}

@test "apply.sh dry-run is idempotent (two runs both succeed)" {
    setup_dry_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    run bash "${INSTALL_DIR}/apply.sh"
    teardown_dry_run
    [ "${status}" -eq 0 ]
}

@test "apply.sh rejects malformed profile" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_DRY_RUN=1
    export SELFDEF_OBSERVABILITY_CONFIG="${TEST_DIR}/observability.toml"
    echo 'profile = "bogus"' > "${SELFDEF_OBSERVABILITY_CONFIG}"
    run bash "${INSTALL_DIR}/apply.sh"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_DRY_RUN SELFDEF_OBSERVABILITY_CONFIG
    [ "${status}" -ne 0 ]
}
