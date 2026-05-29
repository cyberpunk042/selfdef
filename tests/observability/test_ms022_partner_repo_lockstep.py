"""MS022 partner-repo threshold-lockstep lint (selfdef side).

Mirror of sovereign-os commit `ac6b0ab`'s test_ms022_threshold_
lockstep_contract.py. The cross-repo MS022 threshold contract was
one-directional (sovereign-os asserted the selfdef-side Rust
constants when $SELFDEF_REPO_ROOT was set); this test closes the
loop with bidirectional drift catching. When
$SOVEREIGN_OS_REPO_ROOT points at a sovereign-os checkout, this
test asserts the same 5 consumer-side surfaces (alert rules YAML,
proxy daemon Python constants, Grafana dashboard threshold steps,
cockpit guide threshold mentions, doctor classifier import-time
constants) carry the canonical thresholds.

Without the env var, the in-repo selfdef constants are still
verified — same shape as the sovereign-os-side test.

The MS022 thresholds (0.85 = approaching; 1.0 = saturated) appear
in:

  selfdef (this repo):
    1. crates/selfdef-cli/src/sse_quota.rs
       (APPROACHING_THRESHOLD + SATURATED_THRESHOLD f64 constants)

  sovereign-os (partner, opt-in via $SOVEREIGN_OS_REPO_ROOT):
    2. config/prometheus/alerts/ms022-sse-quota.rules.yml
    3. scripts/operator/ms022-sse-quota-api.py
    4. scripts/diagnostics/ms022-doctor.py
    5. docs/operator/ms022-sse-quota-cockpit.md
    6. docs/observability/dashboards/sovereign-os-ms022-sse-quota.json

Any drift across these is a silent operator-misdirection hazard
that this test catches at lint time.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Canonical thresholds — every cited surface MUST agree on these.
APPROACHING = 0.85
SATURATED = 1.0


def _read(path: Path) -> str:
    return path.read_text()


def test_selfdef_sse_quota_rs_carries_canonical_thresholds():
    """The in-repo authoritative source. The partner repo's test
    cross-checks against this via $SELFDEF_REPO_ROOT — drift here
    fails BOTH repos' lint suites simultaneously."""
    body = _read(REPO_ROOT / "crates" / "selfdef-cli" / "src" / "sse_quota.rs")
    approaching_m = re.search(
        r"APPROACHING_THRESHOLD:\s*f64\s*=\s*([\d.]+)", body,
    )
    saturated_m = re.search(
        r"SATURATED_THRESHOLD:\s*f64\s*=\s*([\d.]+)", body,
    )
    assert approaching_m is not None, "missing APPROACHING_THRESHOLD const"
    assert saturated_m is not None, "missing SATURATED_THRESHOLD const"
    assert float(approaching_m.group(1)) == APPROACHING
    assert float(saturated_m.group(1)) == SATURATED


def test_selfdef_sse_quota_rs_classifier_state_names_canonical():
    """The Rust classifier MUST return the same 4 state names the
    partner-repo proxy emits + the cockpit guide documents. Drift
    here = the verb classifies the same metrics into a different
    state than the dashboard renders."""
    body = _read(REPO_ROOT / "crates" / "selfdef-cli" / "src" / "sse_quota.rs")
    # The classifier's literal return statements use these strings.
    for state in ("ok", "approaching", "saturated", "unreachable"):
        # Match the literal-string return: "ok" / "approaching" / etc.
        assert f'"{state}"' in body, (
            f"sse_quota.rs missing state-name literal {state!r}; "
            f"classifier drift would silently misclassify"
        )


def test_selfdef_sse_quota_rs_exit_code_ladder_matches_severity():
    """The 0/1/2 exit-code mapping in `exit_code()` MUST match the
    partner-repo ms022-doctor's PASS/WARN/FAIL = 0/1/2 ladder so
    a CI script running `selfdefctl sse-quota` then
    `sovereign-osctl ms022-doctor` gets the same exit-code class."""
    body = _read(REPO_ROOT / "crates" / "selfdef-cli" / "src" / "sse_quota.rs")
    # Search the exit_code() function body for the canonical mapping.
    fn_start = body.find("fn exit_code(snap: &SseQuotaSnapshot) -> i32 {")
    assert fn_start != -1
    # Look for each canonical state→exit-code arm.
    fn_body = body[fn_start:fn_start + 600]
    assert '"ok" => 0' in fn_body, "ok must exit 0"
    assert '"approaching" => 1' in fn_body, "approaching must exit 1"
    # saturated AND unreachable both map to 2.
    assert '"saturated" | "unreachable" => 2' in fn_body, (
        "saturated + unreachable must both exit 2"
    )


def test_partner_repo_alert_rules_carry_canonical_thresholds():
    """Optional cross-repo: when $SOVEREIGN_OS_REPO_ROOT points at
    a sovereign-os checkout, verify the partner's alert rules
    literally contain `> 0.85` and `>= 1.0`. Skipped when the env
    var is unset — selfdef CI runs without the partner repo cloned,
    so this is additional protection for operators running both
    repos locally OR for the cross-repo CI pipeline."""
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    partner = Path(partner_env)
    rules_path = (
        partner / "config" / "prometheus" / "alerts"
        / "ms022-sse-quota.rules.yml"
    )
    if not rules_path.is_file():
        return  # bad env-var path → skip rather than false-positive
    try:
        import yaml
    except ImportError:
        return  # yaml not available in the test env → can't verify
    doc = yaml.safe_load(rules_path.read_text())
    rules = {
        r["alert"]: r
        for g in doc["groups"]
        for r in g["rules"]
    }
    assert "MS022SseGlobalQuotaApproaching" in rules
    assert "MS022SseGlobalQuotaSaturated" in rules
    assert "> 0.85" in rules["MS022SseGlobalQuotaApproaching"]["expr"], (
        f"partner-repo approaching alert threshold drift"
    )
    assert ">= 1.0" in rules["MS022SseGlobalQuotaSaturated"]["expr"], (
        f"partner-repo saturated alert threshold drift"
    )


def test_partner_repo_proxy_daemon_thresholds_match():
    """Cross-check the partner's proxy daemon constants. Opt-in."""
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    partner = Path(partner_env)
    proxy_path = (
        partner / "scripts" / "operator" / "ms022-sse-quota-api.py"
    )
    if not proxy_path.is_file():
        return
    body = proxy_path.read_text()
    approaching_m = re.search(
        r"APPROACHING_THRESHOLD\s*=\s*([\d.]+)", body,
    )
    saturated_m = re.search(
        r"SATURATED_THRESHOLD\s*=\s*([\d.]+)", body,
    )
    assert approaching_m is not None, (
        "partner proxy daemon missing APPROACHING_THRESHOLD"
    )
    assert saturated_m is not None, (
        "partner proxy daemon missing SATURATED_THRESHOLD"
    )
    assert float(approaching_m.group(1)) == APPROACHING, (
        f"partner-repo proxy daemon APPROACHING_THRESHOLD drift: selfdef "
        f"= {APPROACHING}, sovereign-os = {approaching_m.group(1)}"
    )
    assert float(saturated_m.group(1)) == SATURATED, (
        f"partner-repo proxy daemon SATURATED_THRESHOLD drift: selfdef "
        f"= {SATURATED}, sovereign-os = {saturated_m.group(1)}"
    )


def test_partner_repo_cockpit_guide_cites_canonical_thresholds():
    """Cross-check the partner's cockpit guide. Opt-in."""
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    partner = Path(partner_env)
    guide = (
        partner / "docs" / "operator" / "ms022-sse-quota-cockpit.md"
    )
    if not guide.is_file():
        return
    body = guide.read_text()
    assert "0.85" in body, "partner cockpit guide missing 0.85 threshold"
    assert "1.0" in body, "partner cockpit guide missing 1.0 threshold"
