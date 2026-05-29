"""Auth-events partner-repo lockstep (selfdef side)."""
from __future__ import annotations

import json
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

WRAPPER_PATH = (
    REPO_ROOT / "packaging" / "scripts" / "selfdef-auth-events-textfile.sh"
)
SERVICE_PATH = (
    REPO_ROOT / "packaging" / "systemd"
    / "selfdef-auth-events-textfile.service"
)
TIMER_PATH = (
    REPO_ROOT / "packaging" / "systemd"
    / "selfdef-auth-events-textfile.timer"
)

CANONICAL_GAUGES = {
    "selfdef_auth_events_login_failures",
    "selfdef_auth_events_login_successes",
    "selfdef_auth_events_sudo_invocations",
    "selfdef_auth_events_ssh_invalid_users",
    "selfdef_auth_events_ssh_refused_keys",
    "selfdef_auth_events_total",
    "selfdef_auth_events_last_run_unix",
    "selfdef_auth_events_textfile_emit_failed",
}


def test_wrapper_carries_all_8_canonical_gauges():
    body = WRAPPER_PATH.read_text()
    for gauge in CANONICAL_GAUGES:
        assert gauge in body


def test_wrapper_calls_journalctl_for_auth_facility():
    body = WRAPPER_PATH.read_text()
    assert "journalctl" in body and "--facility=auth,authpriv" in body


def test_wrapper_grep_patterns_cover_canonical_signatures():
    """All canonical pam_unix + sshd + sudo log patterns present."""
    body = WRAPPER_PATH.read_text()
    for pat in (
        "authentication failure",
        "Failed password",
        "Accepted password",
        "Invalid user",
    ):
        assert pat in body, f"missing grep pattern {pat!r}"


def test_wrapper_atomic_write_pattern():
    body = WRAPPER_PATH.read_text()
    assert "mktemp" in body and "mv -f" in body


def test_wrapper_honest_offline_sentinel():
    body = WRAPPER_PATH.read_text()
    assert "selfdef_auth_events_textfile_emit_failed" in body
    assert "command -v journalctl" in body


def test_service_default_window_5m():
    body = SERVICE_PATH.read_text()
    assert "SELFDEF_AUTH_EVENTS_WINDOW=5m" in body


def test_service_documents_journal_access_requirement():
    body = SERVICE_PATH.read_text()
    assert "systemd-journal" in body or "SupplementaryGroups" in body


def test_timer_60s_cadence():
    body = TIMER_PATH.read_text()
    assert "OnUnitActiveSec=60s" in body


def test_timer_boot_offset_210s_7th_distinct():
    body = TIMER_PATH.read_text()
    assert "OnBootSec=210s" in body


def test_partner_repo_alerts_cover_all_five_canonical_alerts():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    rules_path = (
        Path(partner_env) / "config" / "prometheus" / "alerts"
        / "selfdef-auth-events.rules.yml"
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
        "SelfdefAuthEventsTextfileEmitFailed",
        "SelfdefAuthEventsObserverSilent",
        "SelfdefAuthEventsBruteForceDetected",
        "SelfdefAuthEventsSshInvalidUserAttempts",
        "SelfdefAuthEventsSudoSpike",
    }
    missing = expected - names
    assert not missing, f"partner missing alerts: {sorted(missing)}"


def test_partner_repo_brute_force_threshold_20():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    rules_path = (
        Path(partner_env) / "config" / "prometheus" / "alerts"
        / "selfdef-auth-events.rules.yml"
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
    expr = by_name.get("SelfdefAuthEventsBruteForceDetected", {}).get("expr", "")
    if not expr:
        return
    assert "> 20" in expr


def test_partner_repo_dashboard_uid_canonical():
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    dash_path = (
        Path(partner_env) / "docs" / "observability" / "dashboards"
        / "sovereign-os-selfdef-auth-events.json"
    )
    if not dash_path.is_file():
        return
    dash = json.loads(dash_path.read_text())
    assert dash["uid"] == "sovereign-os-selfdef-auth-events"
