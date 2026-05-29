"""M060 partner-repo threshold-lockstep lint (selfdef side).

Bidirectional mirror of sovereign-os commit shipping
`test_m060_threshold_lockstep_contract.py`. The M060 stale-age
threshold (`STALE_AGE_SECS = 5 * 60 = 300`) and the chain-state
enum (online/degraded/stale/offline/unreachable) appear across:

  selfdef (this repo):
    1. crates/selfdef-api/src/m060_health.rs
       const STALE_AGE_SECS: u64 = 5 * 60;

  sovereign-os (partner, opt-in via $SOVEREIGN_OS_REPO_ROOT):
    2. config/prometheus/alerts/m060-chain-health.rules.yml
       (`> 300` literal in observer-silent expressions)
    3. webapp/master-dashboard/index.html
       (`M060_TILE_STALE_AGE_SECS = 5 * 60`)
    4. scripts/operator/m060-health-api.py
       (5-state enum advertised in /version)

In-repo (always-on) tests verify the authoritative selfdef-side
const. Opt-in partner-repo tests verify the same canonical value
appears in the 3 sovereign-os surfaces — same shape as the MS022
bidirectional lockstep (sovereign-os commit ac6b0ab / selfdef
commit 625f3d9).
"""
from __future__ import annotations

import os
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

STALE_AGE_SECS = 300
# The full 5-state set the sovereign-os m060-health-api advertises.
# 'unreachable' is sovereign-os-only — it's the proxy's classification
# when selfdefd is unreachable from outside. The selfdef-side
# classify_state() returns the other 4 (online/degraded/stale/offline);
# sovereign-os adds 'unreachable' atop them.
SELFDEF_CHAIN_STATES = {"online", "degraded", "stale", "offline"}
PARTNER_CHAIN_STATES = SELFDEF_CHAIN_STATES | {"unreachable"}

HEALTH_RS = REPO_ROOT / "crates" / "selfdef-api" / "src" / "m060_health.rs"


def _read(path: Path) -> str:
    return path.read_text()


def test_selfdef_health_rs_stale_age_const_canonical():
    """The selfdef-api authoritative source. The partner repo's
    lockstep test cross-checks against this via $SELFDEF_REPO_ROOT
    — drift here fails BOTH repos' lint suites simultaneously."""
    body = _read(HEALTH_RS)
    m = re.search(
        r"const STALE_AGE_SECS:\s*u64\s*=\s*([^;]+);", body,
    )
    assert m is not None, "m060_health.rs missing STALE_AGE_SECS"
    value_expr = m.group(1).strip()
    value = eval(value_expr, {"__builtins__": {}}, {})
    assert value == STALE_AGE_SECS, (
        f"selfdef-api STALE_AGE_SECS drift: expected {STALE_AGE_SECS}, "
        f"got {value} (from literal {value_expr!r})"
    )


def test_selfdef_health_rs_classify_state_handles_all_states():
    """The Rust classify_state() function MUST return strings from
    the canonical 4-state set (online/degraded/stale/offline). The
    5th state 'unreachable' is sovereign-os-only — added by the
    proxy when selfdefd is unreachable. Drift = the daemon emits a
    state the consumer cockpit doesn't render."""
    body = _read(HEALTH_RS)
    # Search the function body for the literal return values.
    classify_start = body.find("fn classify_state")
    assert classify_start != -1, "m060_health.rs missing classify_state fn"
    # Bound by the next top-level item or test-mod marker.
    classify_end = body.find("\nfn ", classify_start + 1)
    if classify_end == -1:
        classify_end = classify_start + 2000
    classify_body = body[classify_start:classify_end]
    for state in SELFDEF_CHAIN_STATES:
        assert f'"{state}"' in classify_body, (
            f"m060_health.rs classify_state missing state {state!r}"
        )
    # Conversely: the Rust classifier MUST NOT directly return
    # "unreachable" — that's the sovereign-os proxy's job.
    assert '"unreachable"' not in classify_body, (
        "m060_health.rs classify_state must NOT return 'unreachable' — "
        "that state is sovereign-os-only (proxy emits it when "
        "selfdefd is unreachable). Drift here would mean the daemon "
        "lies about its own reachability"
    )


def test_selfdef_health_rs_stale_check_uses_const():
    """The stale-age comparison in classify_state MUST reference
    the STALE_AGE_SECS const (not a magic 300). Catches the case
    where the const drifts but the inline literal doesn't."""
    body = _read(HEALTH_RS)
    # Look for `STALE_AGE_SECS` referenced in the classify_state body.
    classify_start = body.find("fn classify_state")
    classify_body = body[classify_start:classify_start + 2000]
    assert "STALE_AGE_SECS" in classify_body, (
        "classify_state must use the STALE_AGE_SECS const (no magic "
        "number) — drift catch for the literal-300 anti-pattern"
    )


def test_partner_repo_observer_silent_alerts_share_300():
    """Cross-repo opt-in: when $SOVEREIGN_OS_REPO_ROOT points at
    a sovereign-os checkout, verify both observer-silent alerts
    use `> 300` matching the selfdef-side const. Skipped when env
    var is unset."""
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    partner = Path(partner_env)
    rules_path = (
        partner / "config" / "prometheus" / "alerts"
        / "m060-chain-health.rules.yml"
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
    for alert in (
        "M060CliMirrorObserverSilent",
        "M060MirrorDomainObserverSilent",
    ):
        if alert not in by_name:
            continue  # may not be wired yet in older partner checkouts
        expr = by_name[alert]["expr"]
        assert "> 300" in expr, (
            f"partner-repo {alert!r} threshold drift: expected '> 300'; "
            f"got: {expr!r}"
        )


def test_partner_repo_master_dashboard_stale_const_matches():
    """Cross-check sovereign-os master-dashboard's
    M060_TILE_STALE_AGE_SECS const. Opt-in."""
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    partner = Path(partner_env)
    md_path = partner / "webapp" / "master-dashboard" / "index.html"
    if not md_path.is_file():
        return
    body = md_path.read_text()
    m = re.search(
        r"const M060_TILE_STALE_AGE_SECS\s*=\s*([0-9*\s]+);", body,
    )
    if m is None:
        return  # may not be wired yet
    value_expr = m.group(1).strip()
    value = eval(value_expr, {"__builtins__": {}}, {})
    assert value == STALE_AGE_SECS, (
        f"partner-repo master-dashboard STALE drift: expected "
        f"{STALE_AGE_SECS}, got {value}"
    )


def test_partner_repo_health_api_states_match():
    """Cross-check sovereign-os m060-health-api advertised states."""
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    partner = Path(partner_env)
    api_path = partner / "scripts" / "operator" / "m060-health-api.py"
    if not api_path.is_file():
        return
    body = api_path.read_text()
    states_match = re.search(
        r'"states":\s*\[([^\]]+)\]', body,
    )
    if states_match is None:
        return
    found = set(re.findall(r'"([^"]+)"', states_match.group(1)))
    assert found == PARTNER_CHAIN_STATES, (
        f"partner-repo m060-health-api states drift: expected "
        f"{PARTNER_CHAIN_STATES!r}, got {found!r}"
    )
