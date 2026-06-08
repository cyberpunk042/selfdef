"""Prometheus alerting rules contract for the selfdef-side M060 metrics.

The selfdef-api crate exposes per-artifact M060 mirror-export counters
at /metrics (selfdef_m060_mirror_publish_total +
selfdef_m060_mirror_last_publish_unix). The selfdef-observability
module ships alerting rules on those series in
modules/observability/assets/alerts/selfdef.yml.template.

This test locks the alert surface so that:
  1. The new selfdef-m060-mirror-export group is present (it's the
     only group that alerts on the new metrics — drift catch).
  2. Every alert queries the canonical metric (wrong series name =
     silent never-firing alert).
  3. Every alert carries a runbook_url + a `for:` clause.
  4. Severity mapping is sane (publish wedged = critical; transient
     failing or stale = warning).

Run: ``pytest -xvs tests/observability/test_m060_alerts_contract.py``
"""
from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_PATH = REPO_ROOT / "modules" / "observability" / "assets" / "alerts" / "selfdef.yml.template"

EXPECTED_M060_ALERTS = {
    "SelfdefM060PublishFailing",
    "SelfdefM060PublishStale",
    "SelfdefM060PublishWedged",
}


def _load_rules() -> dict:
    return yaml.safe_load(RULES_PATH.read_text())


def _group_by_name(name: str) -> dict | None:
    for g in _load_rules().get("groups", []):
        if g.get("name") == name:
            return g
    return None


def _m060_rules() -> list[dict]:
    g = _group_by_name("selfdef-m060-mirror-export")
    assert g is not None, "missing selfdef-m060-mirror-export group"
    return g.get("rules", [])


def test_alerts_file_present_and_valid_yaml():
    assert RULES_PATH.is_file(), f"alerts file missing at {RULES_PATH}"
    doc = _load_rules()
    assert "groups" in doc
    assert isinstance(doc["groups"], list)
    assert len(doc["groups"]) >= 1


def test_m060_mirror_export_group_is_present():
    assert _group_by_name("selfdef-m060-mirror-export") is not None, (
        "selfdef-m060-mirror-export group missing — alerts on the "
        "selfdef_m060_mirror_publish_total metric will never fire"
    )


def test_every_required_m060_alert_is_defined():
    names = {r["alert"] for r in _m060_rules()}
    missing = EXPECTED_M060_ALERTS - names
    assert not missing, (
        f"selfdef-m060-mirror-export group missing alerts: {sorted(missing)}"
    )


def test_every_m060_alert_queries_a_canonical_metric():
    """Drift catch: the expr MUST reference one of the two metric
    series the daemon actually exports. Otherwise the rule loads but
    never fires."""
    canonical = (
        "selfdef_m060_mirror_publish_total",
        "selfdef_m060_mirror_last_publish_unix",
    )
    for rule in _m060_rules():
        expr = rule["expr"]
        assert any(c in expr for c in canonical), (
            f"alert {rule['alert']!r} expr does not reference the "
            f"canonical m060 metric series; would never fire: {expr!r}"
        )


def test_every_m060_alert_carries_runbook_url():
    """Operators paged at 3 AM need a direct link in the alert
    annotation, not a generic 'see docs'."""
    for rule in _m060_rules():
        ann = rule.get("annotations", {})
        url = ann.get("runbook_url", "")
        assert url.startswith("https://"), (
            f"alert {rule['alert']!r} missing runbook_url: {ann}"
        )
        # The runbook_url must land on an operator-remediation surface:
        # either the deployment-guide troubleshooting matrix OR a dedicated
        # wiki runbook (the M060 publish-anomalies alerts now point at the
        # focused wiki/runbooks/m060-mirror-export-publish-anomalies.md,
        # which is a more direct 3-AM target than the generic guide).
        assert ("deployment-guide" in url or "troubleshooting" in url
                or "/wiki/runbooks/" in url), (
            f"alert {rule['alert']!r} runbook_url does not point at an "
            f"operator-remediation surface (deployment-guide / troubleshooting"
            f" / a wiki runbook): {url}"
        )


def test_every_m060_alert_carries_for_clause():
    """Single-scrape blip suppression — every chain-failure alert
    must carry `for:` to avoid paging on a 30s transient."""
    for rule in _m060_rules():
        assert "for" in rule, (
            f"alert {rule['alert']!r} missing `for:` — single-scrape "
            f"blip would page the operator"
        )


def test_severity_mapping_makes_sense():
    """Wedged means persistent failure — must be critical.
    Failing/stale are transient signals that recover under load — warning."""
    by_name = {r["alert"]: r for r in _m060_rules()}
    assert by_name["SelfdefM060PublishFailing"]["labels"]["severity"] == "warning"
    assert by_name["SelfdefM060PublishStale"]["labels"]["severity"] == "warning"
    assert by_name["SelfdefM060PublishWedged"]["labels"]["severity"] == "critical"


def test_subsystem_label_is_consistent():
    """All M060 mirror-export alerts share a single subsystem label so
    Alertmanager grouping can route them as a unit."""
    for rule in _m060_rules():
        labels = rule.get("labels", {})
        assert labels.get("subsystem") == "m060-mirror-export", (
            f"alert {rule['alert']!r} subsystem label drift: "
            f"{labels.get('subsystem')!r} != 'm060-mirror-export'"
        )


def test_failure_label_classifies_root_cause():
    """The `m060_failure` label discriminates root cause (publish vs
    stale vs wedged) so dashboards/alertmanager can route differently."""
    expected = {
        "SelfdefM060PublishFailing": "publish",
        "SelfdefM060PublishStale":   "stale",
        "SelfdefM060PublishWedged":  "wedged",
    }
    by_name = {r["alert"]: r for r in _m060_rules()}
    for alert, want in expected.items():
        got = by_name[alert]["labels"].get("m060_failure")
        assert got == want, (
            f"alert {alert!r} m060_failure label {got!r} != {want!r}"
        )


def test_full_yaml_is_structurally_loadable():
    """Promtool not available; assert the structural invariants promtool
    would check on the whole file."""
    doc = _load_rules()
    assert "groups" in doc
    for group in doc["groups"]:
        assert "name" in group
        assert "rules" in group and isinstance(group["rules"], list)
        for rule in group["rules"]:
            assert ("alert" in rule and "expr" in rule) or (
                "record" in rule and "expr" in rule
            ), f"rule must have alert+expr or record+expr: {rule!r}"


def test_existing_watchdog_alerts_still_present():
    """Regression guard: adding the M060 group must not displace the
    pre-existing selfdef-four-watchdog rules."""
    g = _group_by_name("selfdef-four-watchdog")
    assert g is not None, "regression: selfdef-four-watchdog group deleted"
    names = {r["alert"] for r in g["rules"]}
    for required in (
        "SelfdefFrictionAuditFailingGate",
        "SelfdefPerimeterSigkill",
        "SelfdefGuardianFailedResponse",
        "SelfdefSchedulerSustainedBackpressure",
    ):
        assert required in names, (
            f"regression: pre-existing watchdog alert {required!r} dropped"
        )
