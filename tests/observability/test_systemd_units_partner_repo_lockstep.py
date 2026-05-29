"""Systemd-units-health partner-repo lockstep (selfdef side)."""
from __future__ import annotations

import json
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

WRAPPER_PATH = (
    REPO_ROOT / "packaging" / "scripts"
    / "selfdef-systemd-units-textfile.sh"
)
SERVICE_PATH = (
    REPO_ROOT / "packaging" / "systemd"
    / "selfdef-systemd-units-textfile.service"
)
TIMER_PATH = (
    REPO_ROOT / "packaging" / "systemd"
    / "selfdef-systemd-units-textfile.timer"
)

CANONICAL_GAUGES = {
    "selfdef_systemd_units_total",
    "selfdef_systemd_units_active",
    "selfdef_systemd_units_inactive",
    "selfdef_systemd_units_failed",
    "selfdef_systemd_units_activating",
    "selfdef_systemd_units_other",
    "selfdef_systemd_units_last_run_unix",
    "selfdef_systemd_units_textfile_emit_failed",
}


def test_selfdef_wrapper_carries_all_8_canonical_gauges():
    body = WRAPPER_PATH.read_text()
    for gauge in CANONICAL_GAUGES:
        assert gauge in body


def test_selfdef_wrapper_uses_list_units_all():
    """`--all` flag is load-bearing — without it, inactive +
    failed units are hidden from the count."""
    body = WRAPPER_PATH.read_text()
    assert "systemctl list-units --all" in body


def test_selfdef_wrapper_filters_to_service_and_timer():
    body = WRAPPER_PATH.read_text()
    assert "--type=service,timer" in body


def test_selfdef_wrapper_atomic_write_pattern():
    body = WRAPPER_PATH.read_text()
    assert "mktemp" in body and "mv -f" in body


def test_selfdef_wrapper_honest_offline_sentinel():
    body = WRAPPER_PATH.read_text()
    assert "selfdef_systemd_units_textfile_emit_failed" in body
    assert "command -v systemctl" in body


def test_selfdef_service_canonical_exec_start():
    body = SERVICE_PATH.read_text()
    assert (
        "ExecStart=/usr/share/selfdef/selfdef-systemd-units-textfile.sh"
        in body
    )


def test_selfdef_service_default_prefix_selfdef_dash():
    body = SERVICE_PATH.read_text()
    assert "SELFDEF_SYSTEMD_UNITS_PREFIX=selfdef-" in body


def test_selfdef_timer_cadence_60s():
    body = TIMER_PATH.read_text()
    assert "OnUnitActiveSec=60s" in body


def test_selfdef_timer_boot_offset_240s_8th_distinct():
    """240s offset = 8th distinct boot offset across the 8 sibling
    observer timers (60s/70s/90s/120s/150s/180s/210s/240s)."""
    body = TIMER_PATH.read_text()
    assert "OnBootSec=240s" in body


def test_partner_repo_alerts_cover_all_four_canonical_alerts():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    rules_path = (
        Path(partner_env) / "config" / "prometheus" / "alerts"
        / "selfdef-systemd-units.rules.yml"
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
        "SelfdefSystemdUnitsTextfileEmitFailed",
        "SelfdefSystemdUnitsObserverSilent",
        "SelfdefSystemdUnitFailed",
        "SelfdefSystemdUnitsCountLow",
    }
    missing = expected - names
    assert not missing, f"partner missing: {sorted(missing)}"


def test_partner_repo_observer_silent_300s():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    rules_path = (
        Path(partner_env) / "config" / "prometheus" / "alerts"
        / "selfdef-systemd-units.rules.yml"
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
    expr = by_name.get("SelfdefSystemdUnitsObserverSilent", {}).get("expr", "")
    if not expr:
        return
    assert "> 300" in expr


def test_partner_repo_count_low_threshold_8():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    rules_path = (
        Path(partner_env) / "config" / "prometheus" / "alerts"
        / "selfdef-systemd-units.rules.yml"
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
    expr = by_name.get("SelfdefSystemdUnitsCountLow", {}).get("expr", "")
    if not expr:
        return
    assert "< 8" in expr


def test_partner_repo_dashboard_uid_canonical():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    dash_path = (
        Path(partner_env) / "docs" / "observability" / "dashboards"
        / "sovereign-os-selfdef-systemd-units.json"
    )
    if not dash_path.is_file():
        return
    dash = json.loads(dash_path.read_text())
    assert dash["uid"] == "sovereign-os-selfdef-systemd-units"
