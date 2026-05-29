"""Module-catalog partner-repo lockstep (selfdef side).

Bidirectional mirror of sovereign-os commit shipping
`test_selfdef_modules_threshold_lockstep_contract.py`. Locks the
selfdef-side producer surface (wrapper + 2 systemd units) AND
opt-in cross-references the sovereign-os consumer surfaces.

In-repo (always-on) — locks the producer:

  packaging/scripts/selfdef-modules-textfile.sh:
    - 5 canonical metric names
    - Atomic mktemp + mv -f write pattern
    - Honest-offline sentinel + selfdefctl PATH check
    - JSON envelope validation

  packaging/systemd/selfdef-modules-textfile.service:
    - Service ExecStart canonical path
    - SuccessExitStatus=0 (no severity ladder)

  packaging/systemd/selfdef-modules-textfile.timer:
    - OnUnitActiveSec=60s (consumer's 300s observer-silent
      threshold = 5x cadence — load-bearing assumption)

Cross-repo opt-in via $SOVEREIGN_OS_REPO_ROOT — locks the consumer
surfaces in the partner repo:

  config/prometheus/alerts/selfdef-modules-catalog.rules.yml:
    - All 3 alerts present (TextfileEmitFailed / ObserverSilent /
      CountLow)
    - Observer-silent expr uses > 300

  docs/observability/dashboards/sovereign-os-selfdef-modules.json:
    - Dashboard exists + UID canonical
"""
from __future__ import annotations

import json
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

CANONICAL_GAUGES = {
    "selfdef_modules_total",
    "selfdef_modules_by_category",
    "selfdef_modules_by_phase",
    "selfdef_modules_last_run_unix",
    "selfdef_modules_textfile_emit_failed",
}

WRAPPER_PATH = (
    REPO_ROOT / "packaging" / "scripts" / "selfdef-modules-textfile.sh"
)
SERVICE_PATH = (
    REPO_ROOT / "packaging" / "systemd" / "selfdef-modules-textfile.service"
)
TIMER_PATH = (
    REPO_ROOT / "packaging" / "systemd" / "selfdef-modules-textfile.timer"
)


def _read(path: Path) -> str:
    return path.read_text()


def test_selfdef_wrapper_carries_canonical_gauges():
    """Authoritative producer. Partner repo's lockstep test cross-
    checks against this via $SELFDEF_REPO_ROOT."""
    body = _read(WRAPPER_PATH)
    for gauge in CANONICAL_GAUGES:
        assert gauge in body, (
            f"wrapper missing canonical gauge {gauge!r}"
        )


def test_selfdef_wrapper_uses_atomic_write_pattern():
    body = _read(WRAPPER_PATH)
    assert "mktemp" in body
    assert "mv -f" in body


def test_selfdef_wrapper_honest_offline_sentinel():
    body = _read(WRAPPER_PATH)
    assert "selfdef_modules_textfile_emit_failed" in body
    assert "command -v selfdefctl" in body


def test_selfdef_wrapper_validates_json_envelope():
    """Refuse to emit zeroed gauges from a malformed response — same
    honest-offline discipline as the four-watchdog wrapper."""
    body = _read(WRAPPER_PATH)
    assert "type == \"array\"" in body, (
        "wrapper must validate JSON envelope is an array before emitting"
    )


def test_selfdef_service_canonical_exec_start():
    body = _read(SERVICE_PATH)
    assert (
        "ExecStart=/usr/share/selfdef/selfdef-modules-textfile.sh" in body
    ), "service ExecStart drift — wrapper path mismatch"


def test_selfdef_service_success_exit_status_zero_only():
    """Module-catalog observer has NO severity ladder (modules either
    enumerate or fail). Service must declare SuccessExitStatus=0 only
    — drift to 0 1 2 would import the doctor-observer convention
    where modules-catalog doesn't apply."""
    body = _read(SERVICE_PATH)
    assert "SuccessExitStatus=0" in body
    # And explicitly NOT the doctor convention (0 1 2).
    assert "SuccessExitStatus=0 1 2" not in body


def test_selfdef_timer_cadence_locks_consumer_alert_threshold():
    """60s cadence is a load-bearing assumption for the consumer's
    300s ObserverSilent alert threshold (= 5x cadence)."""
    body = _read(TIMER_PATH)
    assert "OnUnitActiveSec=60s" in body, (
        "timer cadence drift — 60s locked by consumer's 300s "
        "ObserverSilent alert threshold"
    )


def test_partner_repo_alerts_cover_all_three_canonical_alerts():
    """Cross-repo opt-in: verify all 3 module-catalog alerts exist
    on the partner consumer side."""
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    partner = Path(partner_env)
    rules_path = (
        partner / "config" / "prometheus" / "alerts"
        / "selfdef-modules-catalog.rules.yml"
    )
    if not rules_path.is_file():
        return
    try:
        import yaml
    except ImportError:
        return
    doc = yaml.safe_load(rules_path.read_text())
    names = {
        r["alert"]
        for g in doc["groups"]
        for r in g["rules"]
    }
    expected = {
        "SelfdefModulesTextfileEmitFailed",
        "SelfdefModulesObserverSilent",
        "SelfdefModulesCountLow",
    }
    missing = expected - names
    assert not missing, (
        f"partner-repo missing module-catalog alerts: {sorted(missing)}"
    )


def test_partner_repo_observer_silent_threshold_locked_at_300s():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    partner = Path(partner_env)
    rules_path = (
        partner / "config" / "prometheus" / "alerts"
        / "selfdef-modules-catalog.rules.yml"
    )
    if not rules_path.is_file():
        return
    try:
        import yaml
    except ImportError:
        return
    doc = yaml.safe_load(rules_path.read_text())
    by_name = {
        r["alert"]: r
        for g in doc["groups"]
        for r in g["rules"]
    }
    if "SelfdefModulesObserverSilent" not in by_name:
        return
    expr = by_name["SelfdefModulesObserverSilent"]["expr"]
    assert "> 300" in expr, (
        f"partner-repo ObserverSilent threshold drift: expected > 300; "
        f"got {expr!r}"
    )


def test_partner_repo_dashboard_uid_canonical():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    partner = Path(partner_env)
    dash_path = (
        partner / "docs" / "observability" / "dashboards"
        / "sovereign-os-selfdef-modules.json"
    )
    if not dash_path.is_file():
        return
    dash = json.loads(dash_path.read_text())
    assert dash["uid"] == "sovereign-os-selfdef-modules", (
        f"partner-repo dashboard UID drift: got {dash['uid']!r}"
    )
