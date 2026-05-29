"""AppArmor partner-repo lockstep (selfdef side)."""
from __future__ import annotations

import json
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

WRAPPER_PATH = (
    REPO_ROOT / "packaging" / "scripts" / "selfdef-apparmor-textfile.sh"
)
SERVICE_PATH = (
    REPO_ROOT / "packaging" / "systemd" / "selfdef-apparmor-textfile.service"
)
TIMER_PATH = (
    REPO_ROOT / "packaging" / "systemd" / "selfdef-apparmor-textfile.timer"
)

CANONICAL_GAUGES = {
    "selfdef_apparmor_profile_loaded",
    "selfdef_apparmor_profile_enforce",
    "selfdef_apparmor_profile_complain",
    "selfdef_apparmor_profiles_loaded_total",
    "selfdef_apparmor_last_run_unix",
    "selfdef_apparmor_textfile_emit_failed",
}


def test_selfdef_wrapper_carries_canonical_gauges():
    body = WRAPPER_PATH.read_text()
    for gauge in CANONICAL_GAUGES:
        assert gauge in body


def test_selfdef_wrapper_reads_kernel_apparmor_profiles_file():
    body = WRAPPER_PATH.read_text()
    assert "/sys/kernel/security/apparmor/profiles" in body


def test_selfdef_wrapper_atomic_write_pattern():
    body = WRAPPER_PATH.read_text()
    assert "mktemp" in body and "mv -f" in body


def test_selfdef_wrapper_honest_offline_sentinel():
    body = WRAPPER_PATH.read_text()
    assert "selfdef_apparmor_textfile_emit_failed" in body


def test_selfdef_service_canonical_exec_start():
    body = SERVICE_PATH.read_text()
    assert (
        "ExecStart=/usr/share/selfdef/selfdef-apparmor-textfile.sh" in body
    )


def test_selfdef_service_default_profile_name_canonical():
    body = SERVICE_PATH.read_text()
    assert "SELFDEF_APPARMOR_PROFILE_NAME=/usr/bin/selfdefd" in body


def test_selfdef_timer_cadence_locks_alert_threshold():
    body = TIMER_PATH.read_text()
    assert "OnUnitActiveSec=60s" in body


def test_partner_repo_alerts_cover_all_four_canonical_alerts():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    rules_path = (
        Path(partner_env) / "config" / "prometheus" / "alerts"
        / "selfdef-apparmor.rules.yml"
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
        "SelfdefApparmorTextfileEmitFailed",
        "SelfdefApparmorObserverSilent",
        "SelfdefApparmorProfileNotLoaded",
        "SelfdefApparmorProfileInComplainMode",
    }
    missing = expected - names
    assert not missing


def test_partner_repo_observer_silent_300s():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    rules_path = (
        Path(partner_env) / "config" / "prometheus" / "alerts"
        / "selfdef-apparmor.rules.yml"
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
    expr = by_name.get("SelfdefApparmorObserverSilent", {}).get("expr", "")
    if not expr:
        return
    assert "> 300" in expr


def test_partner_repo_dashboard_uid_canonical():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    dash_path = (
        Path(partner_env) / "docs" / "observability" / "dashboards"
        / "sovereign-os-selfdef-apparmor.json"
    )
    if not dash_path.is_file():
        return
    dash = json.loads(dash_path.read_text())
    assert dash["uid"] == "sovereign-os-selfdef-apparmor"
