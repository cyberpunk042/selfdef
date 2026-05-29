"""Time-sync partner-repo lockstep (selfdef side)."""
from __future__ import annotations

import json
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

WRAPPER_PATH = (
    REPO_ROOT / "packaging" / "scripts" / "selfdef-time-sync-textfile.sh"
)
SERVICE_PATH = (
    REPO_ROOT / "packaging" / "systemd"
    / "selfdef-time-sync-textfile.service"
)
TIMER_PATH = (
    REPO_ROOT / "packaging" / "systemd" / "selfdef-time-sync-textfile.timer"
)

CANONICAL_GAUGES = {
    "selfdef_time_sync_synced",
    "selfdef_time_sync_ntp_active",
    "selfdef_time_sync_rtc_local_tz",
    "selfdef_time_sync_drift_seconds",
    "selfdef_time_sync_last_run_unix",
    "selfdef_time_sync_textfile_emit_failed",
}


def test_wrapper_carries_all_6_canonical_gauges():
    body = WRAPPER_PATH.read_text()
    for gauge in CANONICAL_GAUGES:
        assert gauge in body


def test_wrapper_calls_timedatectl_status():
    body = WRAPPER_PATH.read_text()
    assert "timedatectl status" in body


def test_wrapper_atomic_write_pattern():
    body = WRAPPER_PATH.read_text()
    assert "mktemp" in body and "mv -f" in body


def test_wrapper_honest_offline_sentinel():
    body = WRAPPER_PATH.read_text()
    assert "selfdef_time_sync_textfile_emit_failed" in body
    assert "command -v timedatectl" in body


def test_wrapper_reads_rtc_since_epoch():
    body = WRAPPER_PATH.read_text()
    assert "/sys/class/rtc/rtc0/since_epoch" in body


def test_service_canonical_exec_start():
    body = SERVICE_PATH.read_text()
    assert (
        "ExecStart=/usr/share/selfdef/selfdef-time-sync-textfile.sh" in body
    )


def test_timer_60s_cadence():
    body = TIMER_PATH.read_text()
    assert "OnUnitActiveSec=60s" in body


def test_timer_boot_offset_330s_11th_distinct():
    body = TIMER_PATH.read_text()
    assert "OnBootSec=330s" in body


def test_partner_repo_alerts_cover_all_six():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    rules_path = (
        Path(partner_env) / "config" / "prometheus" / "alerts"
        / "selfdef-time-sync.rules.yml"
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
        "SelfdefTimeSyncTextfileEmitFailed",
        "SelfdefTimeSyncObserverSilent",
        "SelfdefTimeSyncNotSynced",
        "SelfdefTimeSyncNtpInactive",
        "SelfdefTimeSyncDriftHigh",
        "SelfdefTimeSyncRtcLocalTz",
    }
    missing = expected - names
    assert not missing


def test_partner_repo_drift_threshold_60s():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    rules_path = (
        Path(partner_env) / "config" / "prometheus" / "alerts"
        / "selfdef-time-sync.rules.yml"
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
    expr = by_name.get("SelfdefTimeSyncDriftHigh", {}).get("expr", "")
    if expr:
        assert "> 60" in expr


def test_partner_repo_dashboard_uid_canonical():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    dash_path = (
        Path(partner_env) / "docs" / "observability" / "dashboards"
        / "sovereign-os-selfdef-time-sync.json"
    )
    if not dash_path.is_file():
        return
    dash = json.loads(dash_path.read_text())
    assert dash["uid"] == "sovereign-os-selfdef-time-sync"
