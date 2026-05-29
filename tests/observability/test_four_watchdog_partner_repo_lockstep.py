"""Four-watchdog partner-repo lockstep (selfdef side).

Bidirectional mirror of the sovereign-os commit shipping
`test_four_watchdog_threshold_lockstep_contract.py`. Locks the
selfdef-side producer surface (the wrapper script + 2 systemd
units) AND opt-in cross-references the sovereign-os consumer
surfaces.

In-repo (always-on) — locks the producer:

  - `packaging/scripts/four-watchdog-textfile.sh`:
    - 4 canonical metric names
    - severity_to_int ok/warn/critical/unknown → 0/1/2/-1 ladder
    - exit code 0/1/2 mirror

  - `packaging/systemd/selfdef-four-watchdog-doctor.{service,timer}`:
    - Service ExecStart canonical path
    - Service SuccessExitStatus=0 1 2 (severity-ladder contract)
    - Timer OnUnitActiveSec=60s (alert-rule cadence dependency)

Cross-repo opt-in via `$SOVEREIGN_OS_REPO_ROOT` — locks the consumer
surfaces in the partner repo:

  - `config/prometheus/alerts/four-watchdog.rules.yml`:
    - 4 alerts present
    - Observer-silent expr uses `> 300`

  - `docs/observability/dashboards/sovereign-os-four-watchdog.json`:
    - Dashboard exists + UID canonical

Closes the bidirectional drift loop — drift on EITHER side fails
BOTH repos' CI when their respective env vars are set, matching
the M060 + MS022 patterns.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

CANONICAL_GAUGES = {
    "selfdef_four_watchdog_worst_severity",
    "selfdef_four_watchdog_severity",
    "selfdef_four_watchdog_last_run_unix",
    "selfdef_four_watchdog_textfile_emit_failed",
}

WRAPPER_PATH = REPO_ROOT / "packaging" / "scripts" / "four-watchdog-textfile.sh"
SERVICE_PATH = (
    REPO_ROOT / "packaging" / "systemd"
    / "selfdef-four-watchdog-doctor.service"
)
TIMER_PATH = (
    REPO_ROOT / "packaging" / "systemd"
    / "selfdef-four-watchdog-doctor.timer"
)


def _read(path: Path) -> str:
    return path.read_text()


def test_selfdef_wrapper_carries_canonical_gauges():
    """The selfdef-side authoritative producer. The partner repo's
    lockstep test cross-checks against this via $SELFDEF_REPO_ROOT —
    drift here fails BOTH repos' lint suites simultaneously."""
    body = _read(WRAPPER_PATH)
    for gauge in CANONICAL_GAUGES:
        assert gauge in body, (
            f"wrapper missing canonical gauge {gauge!r}"
        )


def test_selfdef_wrapper_severity_ladder_canonical():
    """The wrapper's severity_to_int MUST map all 4 daemon states
    to the canonical 0/1/2/-1 ladder. Drift = textfile gauges
    misclassify."""
    body = _read(WRAPPER_PATH)
    m = re.search(
        r"severity_to_int\(\)[^}]*?ok\)\s*echo\s*(\d+).*?warn\)\s*echo\s*(\d+).*?critical\)\s*echo\s*(\d+).*?unknown\)\s*echo\s*(-?\d+)",
        body, re.DOTALL,
    )
    assert m is not None, (
        "wrapper missing severity_to_int with ok/warn/critical/unknown arms"
    )
    assert (m.group(1), m.group(2), m.group(3), m.group(4)) == (
        "0", "1", "2", "-1",
    ), (
        f"severity ladder drift: ok={m.group(1)} warn={m.group(2)} "
        f"critical={m.group(3)} unknown={m.group(4)}"
    )


def test_selfdef_wrapper_exit_codes_mirror_severity_ladder():
    """Wrapper exit codes MUST mirror the severity ladder so systemd
    SuccessExitStatus=0 1 2 captures all healthy paths."""
    body = _read(WRAPPER_PATH)
    assert "exit 0" in body
    assert "exit 1" in body
    assert "exit 2" in body


def test_selfdef_wrapper_uses_atomic_write_pattern():
    """The wrapper MUST use mktemp + rename so node_exporter never
    sees a half-written file. Same pattern as M060 mirror producers."""
    body = _read(WRAPPER_PATH)
    assert "mktemp" in body
    assert "mv -f" in body


def test_selfdef_wrapper_honest_offline_sentinel():
    """The wrapper MUST emit the honest-offline sentinel gauge — drift
    would let a wedged daemon silently appear healthy."""
    body = _read(WRAPPER_PATH)
    assert "selfdef_four_watchdog_textfile_emit_failed" in body
    assert "command -v selfdefctl" in body


def test_selfdef_service_canonical_exec_start():
    """The systemd service MUST ExecStart the canonical wrapper path
    where the deb installs the script."""
    body = _read(SERVICE_PATH)
    assert (
        "ExecStart=/usr/share/selfdef/four-watchdog-textfile.sh" in body
    ), "service ExecStart drift — wrapper path mismatch with deb-asset layout"


def test_selfdef_service_success_exit_status_severity_contract():
    """The service MUST treat WARN/CRITICAL exit codes as success-
    with-data — matches the cli-mirror + m060 doctor convention."""
    body = _read(SERVICE_PATH)
    assert "SuccessExitStatus=0 1 2" in body, (
        "service SuccessExitStatus must include 0 1 2 — drift means "
        "fired alerts get masked as unit failure"
    )


def test_selfdef_timer_cadence_locks_alert_rule_dependency():
    """The timer's 60s cadence is a load-bearing assumption for the
    sovereign-os FourWatchdogObserverSilent alert (which uses the
    300s = 5x cadence threshold). Drift here would silently
    invalidate the consumer's alert tuning."""
    body = _read(TIMER_PATH)
    assert "OnUnitActiveSec=60s" in body, (
        "timer cadence drift — 60s is locked by the consumer-side "
        "ObserverSilent alert threshold of 300s (= 5x cadence)"
    )


def test_selfdef_wrapper_anchors_ips_spine_milestones():
    """The wrapper MUST anchor the 4 IPS-spine milestones in its
    documentation. Drift = the audit trail thins out at the
    producer surface."""
    body = _read(WRAPPER_PATH)
    for ms in ("MS046", "MS047", "MS044", "MS048"):
        assert ms in body, (
            f"wrapper missing IPS-spine anchor {ms}"
        )


def test_partner_repo_alerts_share_300s_threshold():
    """Cross-repo opt-in: when $SOVEREIGN_OS_REPO_ROOT points at a
    sovereign-os checkout, verify the FourWatchdogObserverSilent
    alert uses `> 300` matching the selfdef-side cadence. Skipped
    silently when env var is unset."""
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    partner = Path(partner_env)
    rules_path = (
        partner / "config" / "prometheus" / "alerts"
        / "four-watchdog.rules.yml"
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
    if "FourWatchdogObserverSilent" not in by_name:
        return  # partner may not have wired yet
    expr = by_name["FourWatchdogObserverSilent"]["expr"]
    assert "> 300" in expr, (
        f"partner-repo FourWatchdogObserverSilent threshold drift: "
        f"expected > 300; got {expr!r}"
    )


def test_partner_repo_alerts_cover_all_four_canonical_alerts():
    """Cross-repo opt-in: verify all 4 four-watchdog alerts exist on
    the partner consumer side."""
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    partner = Path(partner_env)
    rules_path = (
        partner / "config" / "prometheus" / "alerts"
        / "four-watchdog.rules.yml"
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
        "FourWatchdogWorstSeverityCritical",
        "FourWatchdogAnyWarn",
        "FourWatchdogTextfileEmitFailed",
        "FourWatchdogObserverSilent",
    }
    missing = expected - names
    assert not missing, (
        f"partner-repo missing four-watchdog alerts: {sorted(missing)}"
    )


def test_partner_repo_dashboard_uid_canonical():
    """Cross-repo opt-in: the partner's Grafana dashboard MUST carry
    the canonical UID so Grafana's URL anchors remain stable across
    versions."""
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    partner = Path(partner_env)
    dash_path = (
        partner / "docs" / "observability" / "dashboards"
        / "sovereign-os-four-watchdog.json"
    )
    if not dash_path.is_file():
        return
    dash = json.loads(dash_path.read_text())
    assert dash["uid"] == "sovereign-os-four-watchdog", (
        f"partner-repo dashboard UID drift: got {dash['uid']!r}"
    )
