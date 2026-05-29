"""Disk-usage partner-repo lockstep (selfdef side)."""
from __future__ import annotations

import json
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

WRAPPER_PATH = (
    REPO_ROOT / "packaging" / "scripts" / "selfdef-disk-usage-textfile.sh"
)
SERVICE_PATH = (
    REPO_ROOT / "packaging" / "systemd" / "selfdef-disk-usage-textfile.service"
)
TIMER_PATH = (
    REPO_ROOT / "packaging" / "systemd" / "selfdef-disk-usage-textfile.timer"
)

CANONICAL_GAUGES = {
    "selfdef_disk_usage_lib_bytes",
    "selfdef_disk_usage_log_bytes",
    "selfdef_disk_usage_var_log_bytes",
    "selfdef_disk_usage_textfile_collector_bytes",
    "selfdef_disk_usage_var_free_bytes",
    "selfdef_disk_usage_var_used_percent",
    "selfdef_disk_usage_last_run_unix",
    "selfdef_disk_usage_textfile_emit_failed",
}


def test_wrapper_carries_all_8_canonical_gauges():
    body = WRAPPER_PATH.read_text()
    for gauge in CANONICAL_GAUGES:
        assert gauge in body


def test_wrapper_uses_du_and_df():
    body = WRAPPER_PATH.read_text()
    assert "du -sb" in body
    assert "df -B1" in body


def test_wrapper_atomic_write_pattern():
    body = WRAPPER_PATH.read_text()
    assert "mktemp" in body and "mv -f" in body


def test_wrapper_honest_offline_sentinel():
    body = WRAPPER_PATH.read_text()
    assert "selfdef_disk_usage_textfile_emit_failed" in body


def test_wrapper_measures_4_canonical_paths():
    body = WRAPPER_PATH.read_text()
    for path in (
        "/var/lib/selfdef",
        "/var/log/selfdef",
        "/var/log",
        "/var/lib/node_exporter/textfile_collector",
    ):
        assert path in body


def test_service_canonical_exec_start():
    body = SERVICE_PATH.read_text()
    assert "ExecStart=/usr/share/selfdef/selfdef-disk-usage-textfile.sh" in body


def test_service_grants_read_to_var_log():
    body = SERVICE_PATH.read_text()
    assert "/var/log" in body


def test_timer_60s_cadence():
    body = TIMER_PATH.read_text()
    assert "OnUnitActiveSec=60s" in body


def test_timer_boot_offset_300s_10th_distinct():
    body = TIMER_PATH.read_text()
    assert "OnBootSec=300s" in body


def test_partner_repo_alerts_cover_all_five():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    rules_path = (
        Path(partner_env) / "config" / "prometheus" / "alerts"
        / "selfdef-disk-usage.rules.yml"
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
        "SelfdefDiskUsageTextfileEmitFailed",
        "SelfdefDiskUsageObserverSilent",
        "SelfdefDiskUsageVarHigh",
        "SelfdefDiskUsageVarApproaching",
        "SelfdefDiskUsageSelfdefLogHigh",
    }
    missing = expected - names
    assert not missing


def test_partner_repo_var_high_threshold_90():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    rules_path = (
        Path(partner_env) / "config" / "prometheus" / "alerts"
        / "selfdef-disk-usage.rules.yml"
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
    expr = by_name.get("SelfdefDiskUsageVarHigh", {}).get("expr", "")
    if expr:
        assert "> 90" in expr


def test_partner_repo_dashboard_uid_canonical():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    dash_path = (
        Path(partner_env) / "docs" / "observability" / "dashboards"
        / "sovereign-os-selfdef-disk-usage.json"
    )
    if not dash_path.is_file():
        return
    dash = json.loads(dash_path.read_text())
    assert dash["uid"] == "sovereign-os-selfdef-disk-usage"
