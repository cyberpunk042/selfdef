"""Tetragon metric-name contract (SDD-079 / closes F-2026-052).

The observability module's Grafana dashboard renders four panels off
upstream Tetragon's Prometheus exporter. Those series names are
hard-coded in the dashboard JSON; a Tetragon release that renames any
of them renders the panel flat with no error (the F-2026-052 silent-
flat-panel failure mode).

`modules/observability/assets/contracts/tetragon-metrics.toml` is the
single source of truth pinning the four series. This test locks the
dashboard, the contract, SDD-079, and the README in lockstep — drift on
any one fails the build.

Run: ``pytest -xq tests/observability/test_tetragon_metric_name_contract.py``
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
OBS = REPO_ROOT / "modules" / "observability"
CONTRACT_PATH = OBS / "assets" / "contracts" / "tetragon-metrics.toml"
DASHBOARD_PATH = OBS / "assets" / "dashboards" / "selfdef.json.template"
README_PATH = OBS / "README.md"
SDD_PATH = REPO_ROOT / "docs" / "sdd" / "079-tetragon-metric-name-contract.md"
LEDGER_PATH = REPO_ROOT / "docs" / "review" / "99-findings-ledger.md"

# The canonical four series the dashboard is verified against (E0275).
EXPECTED_SERIES = {
    "tetragon_events_total",
    "tetragon_msg_sigkill_total",
    "tetragon_process_cache_size",
    "tetragon_map_errors_total",
}


def _contract() -> dict:
    return tomllib.loads(CONTRACT_PATH.read_text())


def _dashboard() -> dict:
    return json.loads(DASHBOARD_PATH.read_text())


def _dashboard_exprs() -> list[str]:
    return [
        p["targets"][0]["expr"]
        for p in _dashboard()["panels"]
        if p.get("type") not in ("row", None) and p.get("targets")
    ]


# --------------------------------------------------------------------- #
# Contract file shape
# --------------------------------------------------------------------- #
def test_contract_exists_and_parses():
    assert CONTRACT_PATH.is_file(), f"missing contract: {CONTRACT_PATH}"
    _contract()


def test_contract_declares_exactly_the_four_series():
    series = _contract()["series"]
    names = {s["name"] for s in series}
    assert names == EXPECTED_SERIES, (
        f"contract series drift: {names ^ EXPECTED_SERIES}"
    )
    # Each entry is fully specified.
    for s in series:
        for field in ("name", "panel", "promql"):
            assert s.get(field), f"series {s.get('name')!r} missing {field!r}"


def test_contract_declares_version_pin():
    c = _contract()
    ver = c.get("verified_tetragon_version", "")
    assert ver, "contract missing verified_tetragon_version"
    # A real semver range, not a placeholder.
    assert re.search(r"\d+\.\d+\.\d+", ver), f"version pin not a semver range: {ver!r}"
    assert c.get("canonical_source", "").startswith("http"), "missing canonical_source URL"


# --------------------------------------------------------------------- #
# Dashboard <-> contract lockstep (the load-bearing assertion)
# --------------------------------------------------------------------- #
def test_each_contract_promql_matches_a_dashboard_panel_expr():
    exprs = set(_dashboard_exprs())
    for s in _contract()["series"]:
        assert s["promql"] in exprs, (
            f"contract promql for {s['name']!r} not found verbatim in any "
            f"dashboard panel expr: {s['promql']!r}"
        )


def test_dashboard_has_no_unpinned_tetragon_series():
    """Every tetragon_* series the dashboard renders must be in the
    contract. Adding a fifth Tetragon panel is then a deliberate act
    that must extend the contract (and this test fails until it does)."""
    pinned = {s["name"] for s in _contract()["series"]}
    found: set[str] = set()
    for expr in _dashboard_exprs():
        # Anchor to a token boundary: `\btetragon_` matches the upstream
        # exporter series (preceded by `(`, space, etc.) but NOT a
        # daemon-owned series that merely embeds the word, e.g.
        # `selfdef_guardian_tetragon_socket_present` (preceded by `_`, a
        # word char, so no \b boundary). The daemon-side series are this
        # repo's own and covered by other dashboard contract tests; this
        # contract guards only the upstream surface we don't control.
        found.update(re.findall(r"\btetragon_[a-z_]+", expr))
    unpinned = found - pinned
    assert not unpinned, (
        f"dashboard renders un-pinned Tetragon series {unpinned}; add them "
        f"to {CONTRACT_PATH.name} (SDD-079)"
    )


# --------------------------------------------------------------------- #
# Doc lockstep
# --------------------------------------------------------------------- #
def test_sdd_documents_all_four_series_and_the_pin():
    sdd = SDD_PATH.read_text()
    for name in EXPECTED_SERIES:
        assert name in sdd, f"SDD-079 does not document series {name!r}"
    assert "verified_tetragon_version" in sdd, "SDD-079 omits the version-pin field"
    assert "F-2026-052" in sdd, "SDD-079 must cite the finding it closes"


def test_readme_points_at_the_contract():
    readme = README_PATH.read_text()
    assert "tetragon-metrics.toml" in readme, (
        "observability README must reference the contract asset (single "
        "source of truth) instead of only restating the names in prose"
    )


def test_ledger_marks_finding_closed():
    ledger = LEDGER_PATH.read_text()
    # The F-2026-052 row must reference SDD-079 as its closer.
    row = next(
        (ln for ln in ledger.splitlines() if ln.startswith("| F-2026-052 ")),
        "",
    )
    assert row, "F-2026-052 row missing from findings ledger"
    assert "SDD-079" in row, "F-2026-052 ledger row must cite SDD-079 as closer"
