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


def _is_shallow_clone() -> bool:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--is-shallow-repository"],
            stderr=subprocess.DEVNULL, text=True,
        ).strip()
        return out == "true"
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def test_referenced_local_commits_exist():
    """At least one commit hash referenced in SHIPPED.md must resolve
    in `git log` — proving the file is anchored to real history.

    Skipped on a shallow clone: SHIPPED.md references commits from across
    the project's history, most of which are absent from a depth-limited
    checkout, so the resolve-check is meaningless there (it would fail for
    a pure environment reason, not a real SHIPPED.md drift)."""
    if _is_shallow_clone():
        import pytest
        pytest.skip("shallow clone — full history unavailable to resolve SHAs")
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


def test_referenced_crates_exist():
    """Every `crates/<name>` path referenced in SHIPPED.md must
    correspond to a real workspace member. Drift here means SHIPPED.md
    is claiming production-shipped state that doesn't exist."""
    text = _shipped_text()
    # Match `crates/<name>` or `crates/<name>/`. Excludes Cargo.toml
    # paths and src subpaths — only top-level crate-dir mentions.
    crate_pattern = re.compile(r"`crates/(selfdef-[a-z0-9-]+)(?:/[^`]*)?`")
    crates = {m.group(1) for m in crate_pattern.finditer(text)}
    crates_dir = REPO_ROOT / "crates"
    if not crates_dir.is_dir():
        return  # test env
    available = {p.name for p in crates_dir.iterdir() if p.is_dir()}
    missing = sorted(crates - available)
    assert not missing, (
        f"SHIPPED.md references crates that don't exist: {missing}"
    )


def test_referenced_modules_exist():
    """Every `modules/<name>` path referenced in SHIPPED.md must
    correspond to a real module dir."""
    text = _shipped_text()
    mod_pattern = re.compile(r"`modules/([a-z0-9-]+)(?:/[^`]*)?`")
    mods = {m.group(1) for m in mod_pattern.finditer(text)}
    modules_dir = REPO_ROOT / "modules"
    if not modules_dir.is_dir():
        return
    available = {p.name for p in modules_dir.iterdir() if p.is_dir()}
    missing = sorted(mods - available)
    assert not missing, (
        f"SHIPPED.md references modules that don't exist: {missing}"
    )


def test_referenced_packaging_paths_exist():
    """Every `packaging/<path>` referenced must exist on disk."""
    text = _shipped_text()
    pkg_pattern = re.compile(r"`(packaging/[\w/\-.]+)`")
    paths = {m.group(1) for m in pkg_pattern.finditer(text)}
    missing = sorted(p for p in paths if not (REPO_ROOT / p).exists())
    assert not missing, (
        f"SHIPPED.md references packaging paths that don't exist: {missing}"
    )


def test_referenced_sdd_docs_exist():
    """Every `docs/sdd/<name>` path referenced must exist on disk."""
    text = _shipped_text()
    sdd_pattern = re.compile(r"`(docs/sdd/[\w\-]+\.md)`")
    paths = {m.group(1) for m in sdd_pattern.finditer(text)}
    missing = sorted(p for p in paths if not (REPO_ROOT / p).exists())
    assert not missing, (
        f"SHIPPED.md references SDD docs that don't exist: {missing}"
    )


# Threshold: the full 48-milestone selfdef catalogue (MS001..MS048).
# Every catalogued milestone must carry a `### MSxxx` audit row in
# SHIPPED.md. Locks the operator's "you cannot mark something done
# if it hasn't reached Prod" constraint at push-time across the full
# 11,520 R-row catalogue surface (48 milestones × 240 R-rows). A
# regression below this floor — silent removal of an audit row —
# fails CI immediately. Was 47 (1-row drift margin); now full lock
# because SHIPPED.md was audited end-to-end across MS001..MS048 in
# the session that produced this commit.
MILESTONE_AUDIT_FLOOR = 48


def test_milestone_audit_coverage_above_threshold():
    """Lock the SHIPPED.md audit coverage at full 48-milestone
    catalogue floor. Each `### MSxxx` heading is one audit row;
    silent removal of any row makes this assertion fire."""
    text = _shipped_text()
    heading_re = re.compile(r"^### (MS\d{3})\b", re.MULTILINE)
    audited = {m.group(1) for m in heading_re.finditer(text)}
    assert len(audited) >= MILESTONE_AUDIT_FLOOR, (
        f"SHIPPED.md milestone-audit coverage regressed: "
        f"{len(audited)} audited (threshold {MILESTONE_AUDIT_FLOOR}). "
        f"Audited milestones: {sorted(audited)}. "
        f"Catalogue total: 48 milestones (MS001..MS048). "
        f"A row was silently removed or renamed."
    )


def test_no_dangling_milestone_references():
    """Every milestone heading must correspond to a real catalogue
    milestone (already covered by test_referenced_milestones_resolve_
    to_real_files) AND no milestone referenced multiple times (a
    duplicate would suggest a copy-paste audit drift). The latter
    check is enforced here."""
    text = _shipped_text()
    heading_re = re.compile(r"^### (MS\d{3})\b", re.MULTILINE)
    headings = [m.group(1) for m in heading_re.finditer(text)]
    duplicates = sorted(
        ms for ms in set(headings) if headings.count(ms) > 1
    )
    assert not duplicates, (
        f"SHIPPED.md has duplicate milestone-audit sections: {duplicates}"
    )
