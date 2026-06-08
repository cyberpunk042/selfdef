"""Shipped Grafana dashboard ⇄ metric emission (forward binding).

modules/observability/assets/dashboards/selfdef.json.template is the
operator's Grafana dashboard. Every `selfdef_*` series its panels query
MUST be a metric the daemon actually exports — otherwise the panel renders
permanently empty (the operator built a surface that shows nothing, the
§1g minimization).

The existing gates cover only PART of this:
  - L1-grafana-template.sh checks the REVERSE direction (every declared
    four-watchdog series appears in a panel).
  - test_m060_grafana_dashboard_contract checks the FORWARD direction for
    the 2 M060 metrics only.
Nothing checks the forward direction for the ~24 four-watchdog +
enforcement-layer panel metrics — a typo there ships an empty panel.

This gate closes it: every `selfdef_*` metric referenced anywhere in the
dashboard template MUST appear in the selfdef crate source as an emitted
series (a `# HELP`/`# TYPE selfdef_*` exposition line or an emit_* call
site). Catches a renamed/typo'd panel metric before it ships dark.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = (REPO_ROOT / "modules" / "observability" / "assets"
            / "dashboards" / "selfdef.json.template")
CRATES = REPO_ROOT / "crates"

_METRIC = re.compile(r"selfdef_[a-z0-9_]+")

# Dashboard-template metric tokens that are NOT daemon-exported series:
# label values, recording-rule fragments, or templating vars. Add only
# with a justification — every entry weakens the gate. (Empty today.)
KNOWN_NON_SERIES: set[str] = set()


def _template_metrics() -> set[str]:
    text = TEMPLATE.read_text(encoding="utf-8")
    return set(_METRIC.findall(text)) - KNOWN_NON_SERIES


def _emitted_metrics() -> set[str]:
    """Every selfdef_* token that appears in a crate source file (excluding
    tests). A dashboard metric that is genuinely emitted will appear here
    via its `# HELP`/`# TYPE` exposition line or its emit_* call; a typo'd
    metric appears nowhere."""
    out: set[str] = set()
    for rs in CRATES.rglob("src/**/*.rs"):
        out |= set(_METRIC.findall(rs.read_text(encoding="utf-8",
                                                errors="ignore")))
    return out


def test_template_present_and_parses_metrics():
    assert TEMPLATE.is_file(), f"dashboard template missing: {TEMPLATE}"
    metrics = _template_metrics()
    assert len(metrics) >= 10, (
        f"only parsed {len(metrics)} selfdef_* series from the dashboard "
        f"template — parser may be broken or the dashboard shrank"
    )


def test_every_dashboard_metric_is_emitted():
    template = _template_metrics()
    emitted = _emitted_metrics()
    dark = sorted(template - emitted)
    assert not dark, (
        "dashboard panel(s) query selfdef_* series the daemon does NOT "
        "emit — they render permanently empty:\n"
        + "\n".join(f"  - {m}" for m in dark)
        + "\nFix the metric name in selfdef.json.template, or add the emit "
        "site, or (if it's a label/var, not a series) waive it in "
        "KNOWN_NON_SERIES with a reason."
    )
