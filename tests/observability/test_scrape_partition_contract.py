"""Scrape-config partition contract.

The observability module's apply.sh / lib.sh::render_scrape_config
partitions the operator's `scrape_targets` CSV across TWO jobs:
  - tetragon-port targets → selfdef-tetragon job (no bearer)
  - daemon-port targets   → selfdef-daemon job (bearer-token)

Background: the previous renderer put BOTH targets into the
selfdef-tetragon job, silently 401-ing every scrape of selfdefd
/metrics. The M060 mirror-export metrics (selfdef_m060_*) shipped
in 3e60b48 would never reach Prometheus under that bug.

This test runs the actual render_scrape_config bash function across
several CSV inputs and asserts the rendered YAML correctly routes
targets to the right job.

Run: ``pytest -xvs tests/observability/test_scrape_partition_contract.py``
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import textwrap
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE_PATH = (
    REPO_ROOT / "modules" / "observability" / "assets" / "scrape" / "selfdef.yml.template"
)
LIB_PATH = REPO_ROOT / "modules" / "observability" / "install" / "lib.sh"


def _extract_render_fn() -> str:
    """Extract just render_scrape_config from lib.sh so we can run it
    in isolation without sourcing the upstream module-lib chain."""
    result = subprocess.run(
        ["awk", r"/^render_scrape_config\(\)/,/^}$/", str(LIB_PATH)],
        capture_output=True, text=True, check=True, timeout=5,
    )
    return result.stdout


def _render(csv: str) -> str:
    """Render the scrape template through render_scrape_config and
    return the rendered text."""
    fn = _extract_render_fn()
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "src.yml"
        dst = Path(d) / "dst.yml"
        shutil.copy(TEMPLATE_PATH, src)
        script = textwrap.dedent(f"""\
            set -euo pipefail
            die() {{ echo "FATAL: $*" >&2; exit 1; }}
            {fn}
            render_scrape_config "{src}" "{dst}" "{csv}"
            cat "{dst}"
        """)
        result = subprocess.run(
            ["bash", "-c", script],
            capture_output=True, text=True, check=True, timeout=10,
        )
        return result.stdout


def test_default_csv_renders_both_jobs():
    """The bundled-profile default `localhost:2112, localhost:8443`
    must produce both tetragon (2112) AND daemon (8443) jobs."""
    rendered = _render("localhost:2112, localhost:8443")
    doc = yaml.safe_load(rendered)
    assert doc is not None, f"render produced empty YAML; raw:\n{rendered}"
    jobs = {j["job_name"] for j in doc["scrape_configs"]}
    assert "selfdef-tetragon" in jobs
    assert "selfdef-daemon" in jobs


def test_only_tetragon_port_renders_only_tetragon_targets():
    """Operator with tetragon-only deployment doesn't end up with an
    EMPTY daemon job that 401s on every scrape."""
    rendered = _render("localhost:2112, otherhost:2112")
    doc = yaml.safe_load(rendered)
    tetragon = next(
        j for j in doc["scrape_configs"] if j["job_name"] == "selfdef-tetragon"
    )
    daemon = next(
        j for j in doc["scrape_configs"] if j["job_name"] == "selfdef-daemon"
    )
    tetragon_targets = tetragon["static_configs"][0]["targets"]
    daemon_targets = daemon["static_configs"][0].get("targets") or []
    assert sorted(tetragon_targets) == ["localhost:2112", "otherhost:2112"]
    assert daemon_targets == [], f"daemon block should be empty: {daemon_targets}"


def test_only_daemon_port_renders_only_daemon_targets():
    rendered = _render("localhost:8443, otherhost:8443")
    doc = yaml.safe_load(rendered)
    tetragon = next(
        j for j in doc["scrape_configs"] if j["job_name"] == "selfdef-tetragon"
    )
    daemon = next(
        j for j in doc["scrape_configs"] if j["job_name"] == "selfdef-daemon"
    )
    assert (tetragon["static_configs"][0].get("targets") or []) == []
    assert sorted(daemon["static_configs"][0]["targets"]) == [
        "localhost:8443", "otherhost:8443"
    ]


def test_daemon_job_carries_bearer_token_file():
    """The selfdef-daemon job MUST set bearer_token_file — the daemon
    TCP transport returns 401 without it. Silent regression on this
    silently breaks every scrape of selfdef_*."""
    rendered = _render("localhost:8443")
    doc = yaml.safe_load(rendered)
    daemon = next(
        j for j in doc["scrape_configs"] if j["job_name"] == "selfdef-daemon"
    )
    assert "bearer_token_file" in daemon, (
        "selfdef-daemon job MUST set bearer_token_file"
    )
    assert daemon["bearer_token_file"].startswith("/"), (
        f"bearer_token_file must be an absolute path, got {daemon['bearer_token_file']!r}"
    )


def test_tetragon_job_does_NOT_carry_bearer_token():
    """Tetragon's /metrics is open by default; if the renderer
    accidentally adds bearer_token_file to the tetragon job, scrapes
    will fail authentication against an endpoint that doesn't have
    auth."""
    rendered = _render("localhost:2112")
    doc = yaml.safe_load(rendered)
    tetragon = next(
        j for j in doc["scrape_configs"] if j["job_name"] == "selfdef-tetragon"
    )
    assert "bearer_token_file" not in tetragon, (
        "selfdef-tetragon job MUST NOT carry bearer_token_file"
    )


def test_jobs_carry_distinct_source_labels():
    """The two jobs MUST tag scraped series with distinct `source`
    labels so PromQL queries can distinguish them. Both endpoints
    export overlapping metric names (e.g. *_events_total); without
    the source label the streams collide silently."""
    rendered = _render("localhost:2112, localhost:8443")
    doc = yaml.safe_load(rendered)
    sources = []
    for job in doc["scrape_configs"]:
        labels = job["static_configs"][0].get("labels", {})
        sources.append(labels.get("source"))
    assert sorted(sources) == ["selfdef-daemon", "tetragon"], (
        f"source-label set drift: {sources}"
    )


def test_unconventional_port_routes_to_tetragon_safe_default():
    """An operator-defined non-standard port (e.g. 9000) must land in
    the no-auth tetragon job, NOT the bearer-required daemon job —
    otherwise the daemon job would attempt to send a token to an
    endpoint that doesn't expect one."""
    rendered = _render("localhost:9000")
    doc = yaml.safe_load(rendered)
    tetragon = next(
        j for j in doc["scrape_configs"] if j["job_name"] == "selfdef-tetragon"
    )
    daemon = next(
        j for j in doc["scrape_configs"] if j["job_name"] == "selfdef-daemon"
    )
    assert "localhost:9000" in tetragon["static_configs"][0]["targets"]
    assert "localhost:9000" not in (daemon["static_configs"][0].get("targets") or [])


def test_yaml_remains_loadable_as_prometheus_scrape_config():
    """The rendered file must remain valid Prometheus scrape_configs
    YAML — drift in the template would silently break operator
    deploys."""
    rendered = _render("localhost:2112, localhost:8443")
    doc = yaml.safe_load(rendered)
    assert "scrape_configs" in doc
    assert isinstance(doc["scrape_configs"], list)
    assert len(doc["scrape_configs"]) == 2, (
        f"expected exactly 2 scrape jobs, got {len(doc['scrape_configs'])}"
    )
    for job in doc["scrape_configs"]:
        assert "job_name" in job
        assert "scrape_interval" in job
        assert "metrics_path" in job
        assert "static_configs" in job
