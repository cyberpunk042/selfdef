"""selfdef SHIPPED.md production-delivery tracker — integrity lint.

Locks `backlog/SHIPPED.md` against drift. Sister to sovereign-os's
`tests/lint/test_shipped_tracker_integrity.py` — same shape, same
operator-constraint discipline.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SHIPPED = REPO_ROOT / "backlog" / "SHIPPED.md"
MILESTONES_DIR = REPO_ROOT / "backlog" / "milestones"


def _shipped_text() -> str:
    return SHIPPED.read_text()


def _commit_exists(sha: str) -> bool:
    try:
        subprocess.check_call(
            ["git", "cat-file", "-e", sha],
            cwd=REPO_ROOT,
            stderr=subprocess.DEVNULL,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def test_shipped_file_present():
    assert SHIPPED.is_file(), f"SHIPPED.md missing at {SHIPPED}"


def test_rollup_table_present():
    text = _shipped_text()
    assert "## Roll-up" in text, "SHIPPED.md missing the Roll-up section"
    assert "Catalogued (total)" in text
    assert "11,520" in text, "roll-up must reference the catalogue total"


def test_referenced_local_commits_exist():
    """At least one commit hash referenced in SHIPPED.md must resolve
    in `git log` — proving the file is anchored to real history."""
    text = _shipped_text()
    sha_pattern = re.compile(r"`([0-9a-f]{7})`")
    shas = {m.group(1) for m in sha_pattern.finditer(text)}
    verified = [sha for sha in shas if _commit_exists(sha)]
    assert verified, (
        f"no SHAs in SHIPPED.md resolved locally — SHIPPED.md appears "
        f"to reference nonexistent commits. Saw: {shas}"
    )


def test_referenced_milestones_resolve_to_real_files():
    text = _shipped_text()
    heading_re = re.compile(r"^## (MS\d{3})\b", re.MULTILINE)
    headings = {m.group(1) for m in heading_re.finditer(text)}
    if not headings:
        return
    available_files = list(MILESTONES_DIR.glob("MS*-*.md"))
    available_ids = set()
    for p in available_files:
        match = re.match(r"(MS\d{3})", p.name)
        if match:
            available_ids.add(match.group(1))
    missing = headings - available_ids
    assert not missing, (
        f"SHIPPED.md references milestones with no file in "
        f"backlog/milestones/: {sorted(missing)}"
    )


def test_operator_constraint_quoted_verbatim():
    text = _shipped_text()
    assert "You cannot mark something done if it hasn't reached Prod" in text


def test_no_invention_clause_present():
    text = _shipped_text()
    assert "No invention" in text


def test_partner_repo_cross_reference_present():
    text = _shipped_text()
    assert "sovereign-os" in text.lower(), (
        "selfdef's SHIPPED.md must reference its sovereign-os partner"
    )


def test_catalog_total_matches_index_md():
    """SHIPPED.md's roll-up must reference the same catalogue total
    as backlog/INDEX.md so the two files don't drift apart."""
    text = _shipped_text()
    index_path = REPO_ROOT / "backlog" / "INDEX.md"
    if not index_path.is_file():
        # No INDEX.md → skip the cross-check (test environment).
        return
    index_text = index_path.read_text()
    # Both must reference 11,520 (selfdef catalogue total).
    assert "11,520" in index_text, "INDEX.md changed its catalogue total"
    assert "11,520" in text, "SHIPPED.md catalogue total drifted from INDEX.md"
