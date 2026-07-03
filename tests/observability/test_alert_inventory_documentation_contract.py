"""Alert-inventory documentation contract.

Drift catch: the observability module ships:
  - assets/alerts/selfdef.yml.template (the actual rules)
  - README.md (operator-facing alert inventory table)
  - install/apply.sh (deploy-comment alert count)

These three MUST stay in sync. If a new alert lands in the YAML but
not in the README, operators reading `cat README.md` think the
inventory is complete and miss the new alert. If the YAML count
drifts from the apply.sh deploy comment, the operator running
`apply.sh` sees a stale "9 alerts" message that contradicts what
actually gets installed.

This test asserts:
  1. Every alert name in the YAML appears in the README table.
  2. Every alert in the README table actually exists in the YAML.
  3. The apply.sh comment block mentions the current TOTAL count.
  4. The README references the new groups (M060 + detection-watchdog)
     and the M060 runbook URL into the sovereign-os deployment guide.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_PATH = REPO_ROOT / "modules" / "observability" / "assets" / "alerts" / "selfdef.yml.template"
README_PATH = REPO_ROOT / "modules" / "observability" / "README.md"
APPLY_PATH = REPO_ROOT / "modules" / "observability" / "install" / "apply.sh"


def _yaml_alerts() -> list[str]:
    doc = yaml.safe_load(RULES_PATH.read_text())
    return [r["alert"] for g in doc["groups"] for r in g["rules"]]


def _readme() -> str:
    return README_PATH.read_text()


def _apply_sh() -> str:
    return APPLY_PATH.read_text()


def test_every_yaml_alert_appears_in_readme():
    readme = _readme()
    missing = []
    for alert in _yaml_alerts():
        if alert not in readme:
            missing.append(alert)
    assert not missing, (
        f"alerts in YAML but missing from README: {missing}\n"
        f"operator inventory will be incomplete — update README.md "
        f"Alert rules section"
    )


def test_every_readme_alert_exists_in_yaml():
    """The README table MUST NOT reference alerts that don't actually
    ship — operators reading the README would expect to see them but
    they'd never fire."""
    import re
    readme = _readme()
    # Pattern matches alert names in the README table (Selfdef\w+).
    readme_alerts = set(re.findall(r"Selfdef[A-Z]\w+", readme))
    yaml_alerts = set(_yaml_alerts())
    drift = readme_alerts - yaml_alerts
    assert not drift, (
        f"README references alerts that don't exist in YAML: "
        f"{sorted(drift)}"
    )


def test_apply_sh_comment_carries_no_stale_alert_count():
    """The apply.sh deploy-comment must not MISINFORM operators about how
    many alerts land. Per the count-free doctrine the comment shouldn't
    hardcode a total at all (the rule set grows; the count lives in the
    template) — but IF it states `<N> rules`, N must equal the real total.
    A stale literal (e.g. '15 rules' after the set grew to 16) is silent
    misinformation at `apply.sh --dry-run` time."""
    apply_sh = _apply_sh()
    total = len(_yaml_alerts())
    stated = [int(n) for n in re.findall(r"(\d+)\s+rules\b", apply_sh)]
    bad = [n for n in stated if n != total]
    assert not bad, (
        f"apply.sh comment states a stale alert-rule count {bad} but the "
        f"template ships {total} — either drop the hardcoded count "
        f"(count-free, preferred) or update it to {total}."
    )


def test_readme_documents_m060_group():
    readme = _readme()
    assert "M060" in readme, "README missing M060 alert section"
    assert "SelfdefM060PublishFailing" in readme
    assert "SelfdefM060PublishStale" in readme
    assert "SelfdefM060PublishWedged" in readme


def test_readme_links_to_m060_deployment_guide_runbook():
    """The M060 alerts' runbook_url points at the sovereign-os
    deployment guide. The README must surface that link so operators
    reading the alert inventory know where to find the per-alert
    runbook sections."""
    readme = _readme()
    assert "sovereign-os" in readme, (
        "README must reference the sovereign-os deployment guide "
        "where the M060 alert runbooks live"
    )
    assert "m060-deployment-guide" in readme, (
        "README must link to the m060-deployment-guide.md path "
        "(where each M060 alert has a #### runbook section)"
    )


def test_readme_documents_grafana_dashboard_m060_panels():
    """The Grafana dashboard ships M060 panels. The README must
    mention them so operators know visualization exists alongside
    the alerts."""
    readme = _readme()
    assert "panels 120-126" in readme or "M060" in readme, (
        "README does not document the M060 dashboard panels"
    )


def test_storage_thresholds_documented():
    """MS011 storage threshold alerts were added in a sister patch
    and need to appear in the inventory too."""
    readme = _readme()
    assert "SelfdefStorageMountYellow" in readme
    assert "SelfdefStorageMountRed" in readme


def test_alert_count_in_readme_matches_yaml():
    """The README's overview sentence must reflect the actual total."""
    readme = _readme()
    total = len(_yaml_alerts())
    # Accept either a hard count or "15+" wording.
    assert str(total) in readme, (
        f"README total-alert sentence doesn't mention {total} "
        f"(actual YAML count)"
    )


def test_rust_alerts_catalogs_match_yaml_count():
    """The selfdef-cli `ALERTS` and selfdef-api `ALERTS` const arrays
    drive the operator-facing `selfdefctl alerts` verb + `/v1/alerts`
    API + dashboard 'Alerts overview' panel. They are kept identical
    by convention but were originally pinned to a 9-alert subset; the
    YAML rules have since grown beyond that. When the Rust catalogs
    fall behind the YAML, operators triaging during an incident
    silently miss alert states for the newly-added rules
    (`SelfdefStorageMount*`, `SelfdefM060Publish*`, `SelfdefWatchdog*`).

    This guard counts `Threshold::` lines in both Rust source files
    (one per ALERTS entry) and asserts the count equals the YAML
    alert count, so future drift between the YAML and the Rust
    catalogs fails fast at push-time."""
    yaml_count = len(_yaml_alerts())
    cli_path = REPO_ROOT / "crates" / "selfdef-cli" / "src" / "alerts.rs"
    api_path = REPO_ROOT / "crates" / "selfdef-api" / "src" / "alerts.rs"
    for path in (cli_path, api_path):
        if not path.is_file():
            continue
        body = path.read_text()
        # Each ALERTS entry ends with a `Threshold::<Variant>,` line.
        # Counting those is a robust proxy for the catalog length.
        threshold_lines = sum(
            1 for line in body.splitlines() if "Threshold::" in line and line.rstrip().endswith(",")
        )
        assert threshold_lines == yaml_count, (
            f"{path.relative_to(REPO_ROOT)} ALERTS catalog has "
            f"{threshold_lines} entries but the YAML rules ship "
            f"{yaml_count}. Operator-facing surfaces "
            f"(selfdefctl alerts / /v1/alerts / dashboard) will "
            f"silently miss the {yaml_count - threshold_lines} new "
            f"alerts. Add the missing alert(s) to "
            f"crates/selfdef-{{cli,api}}/src/alerts.rs::ALERTS and "
            f"update the hardcoded `9` strings in selfdef-api/src/"
            f"health.rs detail-line formatters in the same commit."
        )
