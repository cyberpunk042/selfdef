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

@test "INVARIANT (uninstall.sh uses set -euo pipefail — fail-loud invariant across full module surface)" {
    # Sister to brain-wide fail-loud-set-euo-pipefail INVARIANTs.
    # apply.sh + check.sh fail-loud already locked above;
    # uninstall.sh is the THIRD operator-facing script in the
    # module surface. Silent uninstall.sh failure during
    # package purge would leave the observability stack (alerts
    # + dashboard + scrape configs) in half-removed state —
    # operator dashboard shows phantom alerts or missing data
    # without obvious cause. Locks fail-loud contract on the
    # full module-script surface (apply + check + uninstall).
    grep -qE 'set -euo pipefail' "${INSTALL_DIR}/uninstall.sh"
}

@test "INVARIANT (no auto-uninstall: observability module NEVER emits package-remove commands on prometheus/grafana)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The observability installer wires alerts +
    # dashboard + scrape templates but MUST NEVER emit shell
    # commands that uninstall the upstream observability
    # packages (apt/dpkg/dnf/rpm/yum remove|purge|uninstall
    # prometheus|grafana|prometheus-node-exporter). Silent
    # auto-removal would tear down the operator dashboard
    # entirely — every selfdef-emitted alert + metric loses
    # its consumer. T1562.001 self-defeat. Locks anti-package-
    # removal contract on the observability substrate.
    for f in "${INSTALL_DIR}/apply.sh" "${INSTALL_DIR}/check.sh" "${INSTALL_DIR}/uninstall.sh"; do
        ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(prometheus|grafana|prometheus-node-exporter)' "${f}"
    done
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. observability manifest declares install + profile
    # gating (bundled / external) the resolver enforces;
    # malformed manifest wedges the prometheus/grafana stack
    # bring-up. Python's tomllib is the canonical parser. Locks
    # anti-malformed-manifest on the observability substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'observability', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: observability installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # observability writes its own drop-in or config; it MUST NEVER
    # rm/find-delete an operator's pre-existing entries not
    # owned by THIS module. Locks no-auto-delete on the
    # observability installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/observability/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(postfix|exim|sendmail|nftables|nscd|pam|prometheus|grafana)' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(postfix|exim|sendmail|nftables|nscd|pam|prometheus|grafana).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # observability install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the observability lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/observability/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the observability substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('depends_on', [])
assert isinstance(v, list), f'depends_on must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml conflicts field is a TOML list — anti-string-malformation contract on conflicts)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks list-vs-string discipline on conflicts.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('conflicts', [])
assert isinstance(v, list), f'conflicts must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml provides field is a TOML list — anti-string-malformation contract on provides)" {
    # Sister to brain-wide module.toml manifest-completeness +
    # list-vs-string INVARIANTs. Locks list discipline on
    # provides.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('provides', [])
assert isinstance(v, list), f'provides must be list, got {type(v).__name__}'
"
}
