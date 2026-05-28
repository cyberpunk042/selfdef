"""End-to-end apply.sh integration contract.

The unit tests in test_scrape_partition_contract.py exercise the
bash render function in isolation. This test runs the FULL apply.sh
pipeline against a synthetic config file + synthetic destination
dirs to assert the actual deployment shape operators get.

Locks:
  1. apply.sh exits 0 cleanly under bundled profile with a synthetic
     conf.d + grafana dirs.
  2. The deployed selfdef.yml at conf.d/ parses as valid YAML.
  3. Both scrape jobs (selfdef-tetragon + selfdef-daemon) are present.
  4. The daemon job carries bearer_token_file (Bug #1 regression
     guard at the integration level).
  5. The deployed JSON dashboard parses + is structurally complete.
  6. The deployed alert rules YAML parses + ships all 15 rules.

This catches end-to-end regressions that unit tests miss: e.g. an
apply.sh change that silently skips the alerts file, or a profile
override that bypasses the partition logic.

Run: ``pytest -xvs tests/observability/test_apply_sh_end_to_end_integration.py``
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
APPLY_PATH = REPO_ROOT / "modules" / "observability" / "install" / "apply.sh"


def _run_apply(scrape_targets: str = "localhost:2112, localhost:8443") -> tuple[Path, Path, Path]:
    """Run apply.sh in bundled profile against a synthetic config +
    synthetic destination dirs. Return (scrape_path, dashboard_path,
    alerts_path) of the deployed files."""
    tmp = Path(tempfile.mkdtemp(prefix="selfdef-apply-test-"))
    conf_dir = tmp / "prom_conf"
    grafana_dir = tmp / "grafana"
    rules_dir = tmp / "prom_rules"
    for d in (conf_dir, grafana_dir, rules_dir):
        d.mkdir()
    config_path = tmp / "observability.toml"
    config_path.write_text(
        f"""profile = "bundled"
prometheus_conf_dir = "{conf_dir}"
grafana_dashboards_dir = "{grafana_dir}"
prometheus_rules_dir = "{rules_dir}"
scrape_targets = "{scrape_targets}"
dashboard_uid = "selfdef-test"
dashboard_title = "selfdef test dashboard"
"""
    )
    env = {
        **os.environ,
        "SELFDEF_DRY_RUN": "0",
        "SELFDEF_OBSERVABILITY_CONFIG": str(config_path),
    }
    result = subprocess.run(
        ["bash", str(APPLY_PATH)],
        env=env, capture_output=True, text=True, check=False, timeout=30,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"apply.sh failed (exit {result.returncode}):\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )
    return (conf_dir / "selfdef.yml", grafana_dir / "selfdef.json",
            rules_dir / "selfdef.yml")


@pytest.fixture(scope="module")
def deployed():
    scrape, dashboard, alerts = _run_apply()
    yield scrape, dashboard, alerts
    # Cleanup is best-effort — leave it for tempdir cleanup.


def test_apply_sh_exits_clean_under_default_config(deployed):
    scrape, dashboard, alerts = deployed
    assert scrape.is_file(), f"scrape config not deployed: {scrape}"
    assert dashboard.is_file(), f"dashboard not deployed: {dashboard}"
    assert alerts.is_file(), f"alerts not deployed: {alerts}"


def test_deployed_scrape_yaml_is_valid(deployed):
    scrape, _, _ = deployed
    doc = yaml.safe_load(scrape.read_text())
    assert doc is not None, "scrape YAML failed to load"
    assert "scrape_configs" in doc
    assert isinstance(doc["scrape_configs"], list)


def test_deployed_scrape_has_both_jobs(deployed):
    """Regression guard on Bug #1: silent loss of the daemon job
    silently breaks every selfdef_* scrape."""
    scrape, _, _ = deployed
    doc = yaml.safe_load(scrape.read_text())
    jobs = {j["job_name"] for j in doc["scrape_configs"]}
    assert "selfdef-tetragon" in jobs, "selfdef-tetragon job missing"
    assert "selfdef-daemon" in jobs, (
        "selfdef-daemon job missing — Bug #1 regression: selfdef-daemon "
        "/metrics endpoint won't be scraped"
    )


def test_deployed_daemon_job_carries_bearer_token(deployed):
    """The deployed daemon job MUST carry bearer_token_file. Without
    it, Prometheus 401s on every scrape against the daemon's TCP
    transport."""
    scrape, _, _ = deployed
    doc = yaml.safe_load(scrape.read_text())
    daemon = next(
        j for j in doc["scrape_configs"] if j["job_name"] == "selfdef-daemon"
    )
    assert "bearer_token_file" in daemon, (
        "deployed daemon job missing bearer_token_file (Bug #1)"
    )
    assert daemon["bearer_token_file"].startswith("/")


def test_deployed_targets_routed_by_port(deployed):
    """Default CSV `localhost:2112, localhost:8443` MUST route 2112 →
    tetragon and 8443 → daemon."""
    scrape, _, _ = deployed
    doc = yaml.safe_load(scrape.read_text())
    by_job = {j["job_name"]: j for j in doc["scrape_configs"]}
    tetragon_targets = by_job["selfdef-tetragon"]["static_configs"][0]["targets"]
    daemon_targets = by_job["selfdef-daemon"]["static_configs"][0]["targets"]
    assert "localhost:2112" in tetragon_targets
    assert "localhost:8443" in daemon_targets
    assert "localhost:2112" not in daemon_targets
    assert "localhost:8443" not in tetragon_targets


def test_deployed_dashboard_is_valid_json(deployed):
    _, dashboard, _ = deployed
    doc = json.loads(dashboard.read_text())
    assert "panels" in doc
    assert isinstance(doc["panels"], list)
    assert len(doc["panels"]) > 0


def test_deployed_dashboard_has_substituted_title_and_uid(deployed):
    _, dashboard, _ = deployed
    raw = dashboard.read_text()
    # Synthetic test config sets these; the renderer must substitute the
    # __SELFDEF_DASHBOARD_TITLE__ / _UID__ markers.
    assert "selfdef-test" in raw
    assert "selfdef test dashboard" in raw
    # And the markers themselves must NOT survive to the output.
    assert "__SELFDEF_DASHBOARD_TITLE__" not in raw
    assert "__SELFDEF_DASHBOARD_UID__" not in raw


def test_deployed_alerts_yaml_is_valid_and_complete(deployed):
    """The alerts file ships verbatim (no template substitution). The
    integration test catches a regression where apply.sh silently skips
    the alerts copy step."""
    _, _, alerts = deployed
    doc = yaml.safe_load(alerts.read_text())
    assert "groups" in doc
    n_rules = sum(len(g["rules"]) for g in doc["groups"])
    assert n_rules == 15, (
        f"deployed alerts file should ship 15 rules (4 groups: 4-watchdog + "
        f"storage + M060 + detection-watchdog); got {n_rules}"
    )


def test_idempotent_re_apply_makes_no_changes():
    """The bundled profile claims idempotency. A re-apply against the
    SAME config + deployed state must report zero changes — otherwise
    operators get a Prometheus reload every time `selfdefctl modules
    apply` runs, even with no actual changes."""
    tmp = Path(tempfile.mkdtemp(prefix="selfdef-idempotent-test-"))
    conf_dir = tmp / "prom_conf"
    grafana_dir = tmp / "grafana"
    rules_dir = tmp / "prom_rules"
    for d in (conf_dir, grafana_dir, rules_dir):
        d.mkdir()
    config_path = tmp / "observability.toml"
    config_path.write_text(
        f"""profile = "bundled"
prometheus_conf_dir = "{conf_dir}"
grafana_dashboards_dir = "{grafana_dir}"
prometheus_rules_dir = "{rules_dir}"
scrape_targets = "localhost:2112, localhost:8443"
dashboard_uid = "selfdef-test"
dashboard_title = "selfdef test dashboard"
"""
    )
    env = {
        **os.environ,
        "SELFDEF_DRY_RUN": "0",
        "SELFDEF_OBSERVABILITY_CONFIG": str(config_path),
    }
    # First apply: writes files (≥ 3 changes).
    first = subprocess.run(
        ["bash", str(APPLY_PATH)],
        env=env, capture_output=True, text=True, check=False, timeout=30,
    )
    assert first.returncode == 0
    # Second apply: SAME inputs, deployed state unchanged. Should report
    # "already at desired state".
    second = subprocess.run(
        ["bash", str(APPLY_PATH)],
        env=env, capture_output=True, text=True, check=False, timeout=30,
    )
    assert second.returncode == 0
    # Look for the "already at desired state" emit message OR for a
    # "0 changes" indicator in stdout.
    combined = second.stdout + second.stderr
    assert "already at desired state" in combined or "0 change" in combined, (
        f"second apply should be no-op; got:\n{combined}"
    )
