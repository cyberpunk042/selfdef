"""Listening-sockets partner-repo lockstep (selfdef side)."""
from __future__ import annotations

import json
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

WRAPPER_PATH = (
    REPO_ROOT / "packaging" / "scripts"
    / "selfdef-listening-sockets-textfile.sh"
)
SERVICE_PATH = (
    REPO_ROOT / "packaging" / "systemd"
    / "selfdef-listening-sockets-textfile.service"
)
TIMER_PATH = (
    REPO_ROOT / "packaging" / "systemd"
    / "selfdef-listening-sockets-textfile.timer"
)

CANONICAL_GAUGES = {
    "selfdef_listening_sockets_tcp",
    "selfdef_listening_sockets_tcp6",
    "selfdef_listening_sockets_udp",
    "selfdef_listening_sockets_udp6",
    "selfdef_listening_sockets_total",
    "selfdef_listening_sockets_last_run_unix",
    "selfdef_listening_sockets_textfile_emit_failed",
}


def test_wrapper_carries_all_7_canonical_gauges():
    body = WRAPPER_PATH.read_text()
    for gauge in CANONICAL_GAUGES:
        assert gauge in body


def test_wrapper_supports_ss_with_proc_fallback():
    body = WRAPPER_PATH.read_text()
    assert "command -v ss" in body
    assert "/proc/net/tcp" in body


def test_wrapper_atomic_write_pattern():
    body = WRAPPER_PATH.read_text()
    assert "mktemp" in body and "mv -f" in body


def test_wrapper_honest_offline_sentinel():
    body = WRAPPER_PATH.read_text()
    assert "selfdef_listening_sockets_textfile_emit_failed" in body


def test_wrapper_ss_separate_v4_v6():
    body = WRAPPER_PATH.read_text()
    assert "ss -H -ltn4" in body or "ss -ltn4" in body
    assert "ss -H -ltn6" in body or "ss -ltn6" in body


def test_wrapper_proc_fallback_state_0a():
    body = WRAPPER_PATH.read_text()
    assert '"0A"' in body or "0A" in body


def test_service_canonical_exec_start():
    body = SERVICE_PATH.read_text()
    assert (
        "ExecStart=/usr/share/selfdef/selfdef-listening-sockets-textfile.sh"
        in body
    )


def test_timer_60s_cadence():
    body = TIMER_PATH.read_text()
    assert "OnUnitActiveSec=60s" in body


def test_timer_boot_offset_270s_9th_distinct():
    body = TIMER_PATH.read_text()
    assert "OnBootSec=270s" in body


def test_partner_repo_alerts_cover_all_four():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    rules_path = (
        Path(partner_env) / "config" / "prometheus" / "alerts"
        / "selfdef-listening-sockets.rules.yml"
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
        "SelfdefListeningSocketsTextfileEmitFailed",
        "SelfdefListeningSocketsObserverSilent",
        "SelfdefListeningSocketsTcpCountHigh",
        "SelfdefListeningSocketsZeroTcp",
    }
    missing = expected - names
    assert not missing


def test_partner_repo_tcp_high_threshold_20():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    rules_path = (
        Path(partner_env) / "config" / "prometheus" / "alerts"
        / "selfdef-listening-sockets.rules.yml"
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
    expr = by_name.get("SelfdefListeningSocketsTcpCountHigh", {}).get("expr", "")
    if expr:
        assert "> 20" in expr


def test_partner_repo_dashboard_uid_canonical():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    dash_path = (
        Path(partner_env) / "docs" / "observability" / "dashboards"
        / "sovereign-os-selfdef-listening-sockets.json"
    )
    if not dash_path.is_file():
        return
    dash = json.loads(dash_path.read_text())
    assert dash["uid"] == "sovereign-os-selfdef-listening-sockets"
