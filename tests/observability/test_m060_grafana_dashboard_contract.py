"""Grafana dashboard contract for the M060 mirror-export visualization.

The selfdef observability module ships a Grafana dashboard template
at modules/observability/assets/dashboards/selfdef.json.template
applied by the module's apply.sh. This test locks the M060 panel
surface against drift — Prometheus queries in the panels must match
the canonical metric series the daemon exports, or the panels render
as empty.

Run: ``pytest -xvs tests/observability/test_m060_grafana_dashboard_contract.py``
"""
from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_PATH = (
    REPO_ROOT / "modules" / "observability" / "assets" / "dashboards" / "selfdef.json.template"
)


def _load() -> dict:
    return json.loads(DASHBOARD_PATH.read_text())


def _m060_panels() -> list[dict]:
    return [p for p in _load()["panels"] if 120 <= p.get("id", 0) <= 130]


def _m060_viz_panels() -> list[dict]:
    """Visualization panels only (skip the row delimiter)."""
    return [p for p in _m060_panels() if p.get("type") != "row"]


def test_dashboard_is_valid_json():
    DASHBOARD_PATH.read_text()
    _load()


def test_m060_row_present():
    rows = [p for p in _load()["panels"] if p.get("type") == "row"]
    m060_rows = [r for r in rows if "M060" in r.get("title", "")]
    assert len(m060_rows) == 1, (
        f"expected exactly 1 M060 row, got {len(m060_rows)}: "
        f"{[r.get('title') for r in m060_rows]}"
    )


def test_m060_panel_set_complete():
    """Lock the operator-facing panel set: 3 stat tiles + 2 timeseries
    + 1 table = 6 visualization panels. Drift catch — adding a panel
    requires updating this test (explicit decision)."""
    viz = _m060_viz_panels()
    assert len(viz) == 6, (
        f"expected 6 M060 visualization panels, got {len(viz)}: "
        f"{[p.get('title') for p in viz]}"
    )
    titles = {p["title"] for p in viz}
    for required in (
        "publishes — succeeded (5m rate sum)",
        "publishes — failed (5m increase sum)",
        "stalest publisher (age, seconds)",
        "publish rate per artifact (ok)",
        "failed publishes per artifact (5m increase)",
        "per-artifact health snapshot",
    ):
        assert required in titles, f"missing panel: {required!r}"


def test_every_m060_panel_references_a_canonical_metric():
    """Drift catch: every panel's target expr must reference one of the
    two metric series the daemon actually exports. Otherwise the panel
    renders as empty."""
    canonical = (
        "selfdef_m060_mirror_publish_total",
        "selfdef_m060_mirror_last_publish_unix",
    )
    for panel in _m060_viz_panels():
        targets = panel.get("targets", [])
        assert targets, f"panel {panel['title']!r} has no targets"
        for target in targets:
            expr = target.get("expr", "")
            assert any(c in expr for c in canonical), (
                f"panel {panel['title']!r} target {target.get('refId') or '?'} "
                f"expr does not reference canonical M060 metric: {expr!r}"
            )


def test_failed_publishes_panel_uses_failed_label():
    """Drift catch on the result label — the panel that surfaces
    failures must filter on result=\"failed\", not result=\"ok\"."""
    p = next(p for p in _m060_viz_panels() if "failed (5m" in p["title"])
    targets = p["targets"]
    assert any('result="failed"' in t["expr"] for t in targets), (
        f"failed-publishes panel does not filter on result=\"failed\": "
        f"{[t['expr'] for t in targets]}"
    )


def test_succeeded_publishes_panel_uses_ok_label():
    p = next(p for p in _m060_viz_panels() if "succeeded" in p["title"])
    targets = p["targets"]
    assert any('result="ok"' in t["expr"] for t in targets), (
        f"succeeded-publishes panel does not filter on result=\"ok\": "
        f"{[t['expr'] for t in targets]}"
    )


def test_stalest_publisher_panel_uses_max_age_query():
    p = next(p for p in _m060_viz_panels() if "stalest" in p["title"])
    targets = p["targets"]
    # The query must compute age = time() - last_publish_unix and pick
    # the maximum across artifacts to identify the stalest publisher.
    target = targets[0]
    assert "time() -" in target["expr"] or "time()-" in target["expr"], (
        f"stalest publisher panel does not compute time()-based age: "
        f"{target['expr']!r}"
    )
    assert "max(" in target["expr"], (
        f"stalest publisher panel does not aggregate via max(): "
        f"{target['expr']!r}"
    )


def test_timeseries_panels_label_by_artifact():
    """The per-artifact timeseries panels MUST carry {{artifact}} in
    the legend so the operator can identify which publisher each
    series belongs to."""
    for panel in _m060_viz_panels():
        if panel.get("type") != "timeseries":
            continue
        for target in panel["targets"]:
            assert "{{artifact}}" in target.get("legendFormat", ""), (
                f"timeseries panel {panel['title']!r} target missing "
                f"{{{{artifact}}}} in legendFormat: "
                f"{target.get('legendFormat')!r}"
            )


def test_stat_tiles_carry_thresholds_for_color_coding():
    """The 3 stat tiles must color-code via thresholds — operators glance
    at the dashboard and see red/yellow/green at a distance, not parse
    numeric values."""
    for panel in _m060_viz_panels():
        if panel.get("type") != "stat":
            continue
        defaults = (
            panel.get("fieldConfig", {})
            .get("defaults", {})
        )
        thresholds = defaults.get("thresholds", {})
        steps = thresholds.get("steps", [])
        assert len(steps) >= 2, (
            f"stat panel {panel['title']!r} has fewer than 2 threshold "
            f"steps; can't color-code: {steps!r}"
        )
        colors = {step.get("color") for step in steps}
        # Must use at least one alert-vocabulary color (red OR green).
        assert ("red" in colors) or ("green" in colors), (
            f"stat panel {panel['title']!r} thresholds don't use "
            f"red/green vocabulary: {colors!r}"
        )


def test_table_panel_merges_three_series():
    """The per-artifact health snapshot table merges 3 series (ok count,
    failed count, age) via a transformation so the operator sees one row
    per artifact rather than three separate columns to mentally join."""
    p = next(p for p in _m060_viz_panels() if "health snapshot" in p["title"])
    assert p["type"] == "table"
    targets = p["targets"]
    assert len(targets) == 3, (
        f"snapshot table should query 3 series (ok / failed / age), "
        f"got {len(targets)}"
    )
    transforms = p.get("transformations", [])
    transform_ids = [t.get("id") for t in transforms]
    assert "merge" in transform_ids, (
        f"snapshot table missing 'merge' transformation; operator would "
        f"see 3 separate columns: {transform_ids!r}"
    )


def test_dashboard_panel_id_ranges_dont_collide():
    """Drift catch: the M060 panels occupy 120-130. If a future patch
    adds a panel in that range with a different theme, the M060 contract
    silently breaks. Lock the range as M060-only."""
    panels = _load()["panels"]
    for p in panels:
        pid = p.get("id", 0)
        if 120 <= pid <= 130:
            # Must be either the M060 row OR an M060 panel (judged by
            # the title containing 'M060', or the title being one of
            # the locked panel titles).
            title = p.get("title", "")
            # The M060 cockpit section covers the mirror-publish telemetry
            # AND the liveness of the daemon that performs the publishing
            # (a dead daemon = no publishes), so the daemon-health /
            # retention-liveness panel belongs to this section too.
            m060_marker = ("M060" in title) or any(
                kw in title.lower()
                for kw in ("publish", "stalest", "per-artifact health",
                           "daemon health", "retention", "liveness")
            )
            assert m060_marker, (
                f"panel id {pid} ({title!r}) in M060 range but is not "
                f"an M060 / M060-daemon panel"
            )


def test_dashboard_top_level_structure_intact():
    """Regression guard: the dashboard's top-level Grafana structure
    must remain Grafana-loadable — schemaVersion, panels[], etc."""
    doc = _load()
    assert "schemaVersion" in doc
    assert "panels" in doc and isinstance(doc["panels"], list)
    assert len(doc["panels"]) >= 6, "dashboard suspiciously thin"
    # The pre-existing module-catalog row must still ship.
    titles = [p.get("title", "") for p in doc["panels"]]
    assert any("Module catalog" in t for t in titles), (
        "regression: 'Module catalog' row deleted"
    )
