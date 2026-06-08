"""Watchdog expected-owner knob contract (SDD-080).

Locks the fix that greens the four-watchdog coherence harness under a
non-root CI runner:

  1. No watchdog script may carry a *bare* `!= "root"` owner check —
     it must read the `SELFDEF_WATCHDOG_EXPECTED_OWNER` knob (default
     root) so the heuristic is declarable and the L2 benign-path tests
     are hermetic under any runner.
  2. The coherence harness must export the knob, defaulting to the
     harness runner's identity, so the benign fixtures it creates are
     treated as expected-owner regardless of who runs CI.

Run: ``pytest -xq tests/observability/test_watchdog_expected_owner_contract.py``
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
COHERENCE = REPO_ROOT / "scripts" / "test" / "coherence.sh"
KNOB = "SELFDEF_WATCHDOG_EXPECTED_OWNER"

# A bare owner-vs-root comparison: `!= "root"` not immediately preceded
# by the knob's default-expansion. The fixed form is
# `!= "${SELFDEF_WATCHDOG_EXPECTED_OWNER:-root}"`.
_BARE_OWNER_ROOT = re.compile(r'!=\s*"root"')


def _watchdog_scripts() -> list[Path]:
    return sorted(REPO_ROOT.glob("modules/*-watchdog/systemd/*.sh"))


def test_no_watchdog_uses_a_bare_owner_root_check():
    offenders: list[str] = []
    for script in _watchdog_scripts():
        for i, line in enumerate(script.read_text().splitlines(), 1):
            # Only owner-ownership lines, not arbitrary "root" mentions.
            if ("owner" in line and "!=" in line) and _BARE_OWNER_ROOT.search(line):
                if KNOB not in line:
                    offenders.append(f"{script.relative_to(REPO_ROOT)}:{i}: {line.strip()}")
    assert not offenders, (
        "watchdog scripts with a bare `!= \"root\"` owner check (must read "
        f"${{{KNOB}:-root}} per SDD-080):\n" + "\n".join(offenders)
    )


def test_at_least_one_watchdog_reads_the_knob():
    """Guard against the regex above passing vacuously (e.g. if the glob
    matched nothing): the knob must actually be wired into the family."""
    using = [
        s for s in _watchdog_scripts()
        if f"{KNOB}:-root" in s.read_text()
    ]
    assert len(using) >= 50, (
        f"expected the expected-owner knob wired across the watchdog "
        f"family; only {len(using)} scripts read it"
    )


def test_coherence_harness_exports_the_knob():
    src = COHERENCE.read_text()
    assert f"export {KNOB}=" in src, (
        "coherence.sh must export the expected-owner knob so L2 benign-path "
        "assertions are hermetic under a non-root runner (SDD-080)"
    )
    # Defaulted to the harness runner identity, overridable.
    assert "id -un" in src, (
        "the harness export should default to the runner identity via $(id -un)"
    )
