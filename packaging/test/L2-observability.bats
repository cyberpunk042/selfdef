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

@test "INVARIANT (module.toml requires field is a TOML list — anti-string-malformation contract on requires)" {
    # Sister to brain-wide module.toml list-vs-string family.
    # Locks list discipline on requires.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('requires', [])
assert isinstance(v, list), f'requires must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml requires entries are tables with kind + value — anti-flat-string-list contract)" {
    # Sister to brain-wide module.toml requires-shape INVARIANT
    # family. Locks the kind+value table-shape discipline on
    # the observability requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
reqs = data.get('requires', [])
for r in reqs:
    assert isinstance(r, dict), f'requires entry must be table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'requires entry must have kind+value, got {r}'
"
}

@test "INVARIANT (module.toml summary field present + non-empty — operator-dashboard one-line description contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks summary-present discipline on the
    # observability substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) > 0, f'summary must be non-empty string, got {repr(s)}'
"
}

@test "INVARIANT (module.toml category field present + non-empty — dashboard-grouping contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks category-present discipline on the
    # observability substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert isinstance(c, str) and len(c) > 0, f'category must be non-empty string, got {repr(c)}'
"
}

@test "INVARIANT (module.toml version field is semver X.Y.Z — version-comparison sortability contract)" {
    # Sister to brain-wide module.toml semver INVARIANT family.
    # Locks semver-X.Y.Z discipline on the observability
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (observability module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl installer resolves apply scripts
    # via module.toml's [install].apply field — the canonical
    # value is the relative path "install/apply.sh" (under the
    # module's own directory). A regression that swapped to
    # an absolute /usr/local/libexec/... path would break the
    # in-tree test runner (which executes apply scripts from
    # the source tree, not /usr/local/libexec/). A regression
    # to a non-existent path would surface as "apply script
    # not found" at install time. Locks the canonical
    # install/apply.sh path discipline on the observability module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
ap = inst.get('apply', '')
assert ap == 'install/apply.sh', f'install.apply must be install/apply.sh, got {ap!r}'
"
}

@test "INVARIANT (observability module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the observability module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
chk = inst.get('check', '')
assert chk == 'install/check.sh', f'install.check must be install/check.sh, got {chk!r}'
"
}

@test "INVARIANT (observability module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
    # Sister to brain-wide module.toml [install_paths]
    # INVARIANT family. Per MS011 Z-8 / SDD-026, every
    # installer module MUST declare an [install_paths] block
    # enumerating the on-disk surfaces it touches on apply.
    # The selfdef dashboard's install-options surface +
    # install-plan auditor read this block to surface what
    # the module mutates BEFORE apply runs. A regression
    # dropping the [install_paths] block would leave operators
    # without a pre-apply manifest of writes, breaking
    # operator-consent + the install-plan-dry-run contract.
    # Locks the SDD-026 manifest discipline on the observability
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths')
assert ip is not None, f'[install_paths] block must be present per SDD-026, got None'
paths = ip.get('paths', [])
assert isinstance(paths, list) and len(paths) > 0, f'install_paths.paths must be non-empty list, got {paths!r}'
"
}

@test "INVARIANT (observability module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for observability is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the observability substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (observability module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
    # Sister to brain-wide [install_paths].paths INVARIANT
    # family. The install_paths.paths field MUST be a TOML
    # list of strings (each element an absolute path the
    # module touches on apply). A regression that swapped to
    # a comma-separated string ("path1,path2,path3") would
    # silently treat it as a single literal path. The
    # selfdef installer iterates the list to surface the
    # mutation manifest to operators; broken type-shape
    # would break the install-options surface + dry-run
    # auditor. Locks the TOML-list-of-strings type discipline
    # on the observability install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list), f'install_paths.paths must be TOML list, got {type(ps).__name__}'
assert all(isinstance(p, str) for p in ps), f'every paths entry must be a string'
"
}

@test "INVARIANT (observability module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the observability requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
req = data.get('requires')
assert isinstance(req, list), f'requires must be TOML list, got {type(req).__name__}'
for r in req:
    assert isinstance(r, dict), f'requires entry must be inline-table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'requires must have kind+value, got {r!r}'
"
}

@test "INVARIANT (observability module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the observability
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (observability module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the observability
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (observability module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the observability substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (observability module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (observability module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the observability substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
prof = data.get('profiles')
assert prof is not None, f'[profiles] must be present, got None'
assert isinstance(prof, dict), f'[profiles] must be TOML table, got {type(prof).__name__}'
"
}

@test "INVARIANT (observability module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (observability module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (observability module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late', 'pre', 'post'}, f'phase must be canonical, got {p!r}'
"
}

@test "INVARIANT (observability module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (observability module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (observability module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/observability/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (observability README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/observability/README.md"
    [ -f "${readme}" ]
}
