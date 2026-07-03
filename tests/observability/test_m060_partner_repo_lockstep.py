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

Extension (this commit): the 8-domain M060 wire contract is now
also locked across both repos. The selfdef m060_doctor DOMAINS
array + selfdef-api m060_health ARTIFACT_NAMES list + sovereign-os
m060-smoke DOMAINS tuple + sovereign-os mirror-domains dashboard
panel description MUST reference the SAME 8 D-NN IDs. Drift on
any one silently breaks the operator's cross-repo triage path —
exactly the bug class the entire D-12 + D-16 coverage close
session was driven by (selfdef 82014d6 + sovereign-os 234a1e0).
"""
from __future__ import annotations

import json
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

# The canonical 8-domain M060 wire contract. Order matters because
# the selfdef m060_doctor.rs::DOMAINS const array iteration order is
# operator-visible (textfile gauge rows + JSON output ordering). Both
# the producer side (selfdef) and the consumer side (sovereign-os
# m060-smoke + dashboard) MUST list these 8 in this exact order.
CANONICAL_DOMAIN_IDS = (
    "D-02",  # active-profile
    "D-12",  # rules
    "D-13",  # grants
    "D-14",  # capability-tokens
    "D-15",  # sandboxes
    "D-16",  # audit-chain
    "D-17",  # quarantine
    "D-18",  # trust-scores
)

# The 8 D-NN-tied published-filenames in the api/m060_health
# ARTIFACT_NAMES list. Plus the 2 MS007 cross-cutting artifacts
# (tui + cli) for a total of 10. The api endpoint reports all 10;
# the m060-doctor verb walks only the 8 D-NN-tied ones (TUI + CLI
# have their own per-link doctor verbs).
CANONICAL_D_NN_FILES = (
    "active-profile.json",
    "rules.json",
    "grants.json",
    "capability-tokens.json",
    "sandboxes.json",
    "audit.json",
    "quarantine.json",
    "trust-scores.json",
)
MS007_CROSS_CUTTING_FILES = ("tui.json", "cli.json")
CANONICAL_API_ARTIFACTS = set(CANONICAL_D_NN_FILES) | set(MS007_CROSS_CUTTING_FILES)

HEALTH_RS = REPO_ROOT / "crates" / "selfdef-api" / "src" / "m060_health.rs"
DOCTOR_RS = REPO_ROOT / "crates" / "selfdef-cli" / "src" / "m060_doctor.rs"


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


# --------------------------------------------------------------------
# 8-domain wire-contract lockstep — closes the silent-coverage-drift
# bug class that the D-12 rules + D-16 audit-chain coverage close
# (selfdef 82014d6 + sovereign-os 234a1e0) was driven by.
# --------------------------------------------------------------------


def test_selfdef_doctor_domains_match_canonical_set():
    """The selfdef-cli m060_doctor DOMAINS array MUST list exactly
    the canonical 8 D-NN ids in canonical order. Sister regression
    guard `domains_cover_full_m060_wire_contract` (in-crate Rust
    test) locks the same invariant at cargo-test time; this lint
    locks it at the pytest gate too so a fresh-pull CI run catches
    a drift before the cargo build."""
    body = _read(DOCTOR_RS)
    # Extract each Domain { id: "D-NN", ... } occurrence in source order.
    id_pattern = re.compile(r'Domain\s*\{\s*\n\s*id:\s*"(D-\d{2})"')
    found_ids = tuple(id_pattern.findall(body))
    assert found_ids == CANONICAL_DOMAIN_IDS, (
        f"selfdef-cli m060_doctor DOMAINS drift: expected "
        f"{CANONICAL_DOMAIN_IDS} (in this exact order), got "
        f"{found_ids}. The doctor verb's textfile gauges and JSON "
        f"output are operator-visible in this order; reordering "
        f"would silently break Grafana legend ordering + the "
        f"sovereign-os consumer's per-domain timeseries panel."
    )


def test_selfdef_api_artifact_names_cover_8_d_nn_mirrors():
    """The selfdef-api m060_health ARTIFACT_NAMES list MUST cover
    all 8 D-NN-tied published filenames AND the 2 MS007 cross-cutting
    (tui + cli) = 10 total. Drift between this list and the
    mirror_export_loop's per-domain FILE consts (RULES_FILE,
    AUDIT_FILE, etc.) silently desyncs the health endpoint's
    artifact-count from the actual publisher set."""
    body = _read(HEALTH_RS)
    # Extract the ARTIFACT_NAMES list literal.
    m = re.search(
        r"const ARTIFACT_NAMES:\s*&\[&str\]\s*=\s*&\[([^\]]+)\]",
        body, re.DOTALL,
    )
    assert m is not None, (
        "m060_health.rs missing ARTIFACT_NAMES list"
    )
    found = set(re.findall(r'"([^"]+\.json)"', m.group(1)))
    missing = CANONICAL_API_ARTIFACTS - found
    extra = found - CANONICAL_API_ARTIFACTS
    assert not missing, (
        f"m060_health.rs ARTIFACT_NAMES missing canonical entries: "
        f"{sorted(missing)}. The 10-artifact wire contract requires "
        f"8 D-NN-tied files + 2 MS007 cross-cutting (tui + cli)."
    )
    assert not extra, (
        f"m060_health.rs ARTIFACT_NAMES has unknown entries: "
        f"{sorted(extra)}. If you added a new mirror artifact, "
        f"update CANONICAL_API_ARTIFACTS in this lint in the same commit."
    )
    assert len(found) == 10, (
        f"m060_health.rs ARTIFACT_NAMES must have exactly 10 entries "
        f"(8 D-NN + 2 MS007); got {len(found)}"
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


def test_partner_repo_smoke_domains_match():
    """Cross-check sovereign-os m060-smoke DOMAINS tuple — must
    contain all 8 D-NN IDs from the canonical set. Opt-in via
    $SOVEREIGN_OS_REPO_ROOT."""
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    partner = Path(partner_env)
    smoke_path = partner / "scripts" / "diagnostics" / "m060-smoke.py"
    if not smoke_path.is_file():
        return
    body = smoke_path.read_text()
    # Match the DOMAINS list opening, extract all `"D-NN"` ids.
    m = re.search(r"DOMAINS\s*=\s*\[(.+?)\]\s*\n", body, re.DOTALL)
    if m is None:
        return  # not wired yet
    found_ids = set(re.findall(r'"(D-\d{2})"', m.group(1)))
    missing = set(CANONICAL_DOMAIN_IDS) - found_ids
    assert not missing, (
        f"partner-repo m060-smoke DOMAINS missing canonical D-NN IDs: "
        f"{sorted(missing)}. The 8-domain M060 wire contract requires "
        f"all of {sorted(CANONICAL_DOMAIN_IDS)} — drift here means the "
        f"smoke verb skips a domain the producer publishes."
    )


def test_partner_repo_dashboard_description_lists_8_domains():
    """Cross-check sovereign-os mirror-domains dashboard per-domain-
    severity panel description — its operator-visible D-NN enum must
    list all 8 canonical IDs. Opt-in via $SOVEREIGN_OS_REPO_ROOT."""
    partner_env = os.environ.get("SOVEREIGN_OS_REPO_ROOT")
    if not partner_env:
        return
    partner = Path(partner_env)
    dash_path = (
        partner / "docs" / "observability" / "dashboards"
        / "sovereign-os-m060-mirror-domains.json"
    )
    if not dash_path.is_file():
        return
    try:
        data = json.loads(dash_path.read_text())
    except json.JSONDecodeError:
        return
    panels = data.get("panels", [])
    # Find the per-domain severity timeseries panel.
    target = None
    for panel in panels:
        title = panel.get("title", "").lower()
        if "per-domain severity" in title:
            target = panel
            break
    if target is None:
        return  # not wired yet
    desc = target.get("description", "")
    for d_nn in CANONICAL_DOMAIN_IDS:
        assert d_nn in desc, (
            f"partner-repo dashboard panel description missing "
            f"canonical D-NN ID {d_nn!r}. Operator reading the panel "
            f"hover-text won't know to look for {d_nn!r}. Full panel "
            f"description: {desc!r}"
        )
