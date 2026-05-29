"""Daemon process-state partner-repo lockstep (selfdef side).

Bidirectional mirror of sovereign-os commit shipping
`test_selfdef_daemon_process_threshold_lockstep_contract.py`.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

CANONICAL_GAUGES = {
    "selfdef_daemon_process_memory_rss_bytes",
    "selfdef_daemon_process_memory_vsize_bytes",
    "selfdef_daemon_process_open_fds",
    "selfdef_daemon_process_threads",
    "selfdef_daemon_process_uptime_seconds",
    "selfdef_daemon_process_restart_count",
    "selfdef_daemon_process_last_run_unix",
    "selfdef_daemon_process_textfile_emit_failed",
}

WRAPPER_PATH = (
    REPO_ROOT / "packaging" / "scripts" / "selfdef-daemon-process-textfile.sh"
)
SERVICE_PATH = (
    REPO_ROOT / "packaging" / "systemd"
    / "selfdef-daemon-process-textfile.service"
)
TIMER_PATH = (
    REPO_ROOT / "packaging" / "systemd"
    / "selfdef-daemon-process-textfile.timer"
)


def _read(p: Path) -> str:
    return p.read_text()


def test_selfdef_wrapper_carries_all_8_canonical_gauges():
    body = _read(WRAPPER_PATH)
    for gauge in CANONICAL_GAUGES:
        assert gauge in body, f"wrapper missing {gauge}"


def test_selfdef_wrapper_resolves_pid_via_systemctl():
    body = _read(WRAPPER_PATH)
    assert "systemctl show -p MainPID" in body


def test_selfdef_wrapper_reads_proc_fs():
    body = _read(WRAPPER_PATH)
    assert "/proc/$pid/status" in body
    assert "/proc/$pid/stat" in body
    assert "/proc/$pid/fd/" in body


def test_selfdef_wrapper_restart_count_is_counter_type():
    body = _read(WRAPPER_PATH)
    assert "# TYPE selfdef_daemon_process_restart_count counter" in body


def test_selfdef_wrapper_atomic_write_pattern():
    body = _read(WRAPPER_PATH)
    assert "mktemp" in body and "mv -f" in body


def test_selfdef_wrapper_honest_offline_sentinel():
    body = _read(WRAPPER_PATH)
    assert "selfdef_daemon_process_textfile_emit_failed" in body
    assert "command -v systemctl" in body


def test_selfdef_service_orders_after_selfdefd():
    body = _read(SERVICE_PATH)
    assert "selfdefd.service" in body


def test_selfdef_service_canonical_exec_start():
    body = _read(SERVICE_PATH)
    assert (
        "ExecStart=/usr/share/selfdef/selfdef-daemon-process-textfile.sh" in body
    )


def test_selfdef_timer_cadence_locks_alert_threshold():
    """60s cadence locked by consumer's 300s ObserverSilent threshold
    (= 5x cadence)."""
    body = _read(TIMER_PATH)
    assert "OnUnitActiveSec=60s" in body


def test_partner_repo_alerts_cover_all_five_canonical_alerts():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    rules_path = (
        Path(partner_env) / "config" / "prometheus" / "alerts"
        / "selfdef-daemon-process.rules.yml"
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
        "SelfdefDaemonProcessTextfileEmitFailed",
        "SelfdefDaemonProcessObserverSilent",
        "SelfdefDaemonProcessMemoryHigh",
        "SelfdefDaemonProcessFdExhaustionApproaching",
        "SelfdefDaemonProcessRestartLoop",
    }
    missing = expected - names
    assert not missing, f"partner missing alerts: {sorted(missing)}"


def test_partner_repo_observer_silent_300s():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    rules_path = (
        Path(partner_env) / "config" / "prometheus" / "alerts"
        / "selfdef-daemon-process.rules.yml"
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
    expr = by_name.get("SelfdefDaemonProcessObserverSilent", {}).get("expr", "")
    if not expr:
        return
    assert "> 300" in expr


def test_partner_repo_dashboard_uid_canonical():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    dash_path = (
        Path(partner_env) / "docs" / "observability" / "dashboards"
        / "sovereign-os-selfdef-daemon-process.json"
    )
    if not dash_path.is_file():
        return
    dash = json.loads(dash_path.read_text())
    assert dash["uid"] == "sovereign-os-selfdef-daemon-process"
