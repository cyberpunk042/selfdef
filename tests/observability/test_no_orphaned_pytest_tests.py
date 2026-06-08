"""No orphaned pytest-style test files (test self-coverage).

selfdef's Python CI runs `python3 -m unittest <explicit module list>` —
which collects ZERO tests from a pytest-style file (bare `def test_` +
parametrize, no `unittest.TestCase`). The coherence harness compensates
with an L2 pytest layer, but only for an explicit set of paths. A new
pytest-style test file dropped ANYWHERE ELSE under tests/ runs NOWHERE: it
looks like coverage, executes never. The whole tests/observability suite
(~190 tests) and tests/replay/test_rule_corpus_coverage lived this way —
orphaned, with real drift accumulating unseen — until they were wired in.

This gate freezes test self-coverage: every pytest-style test file under
tests/ MUST be covered by a runner — either the coherence unittest module
list OR the coherence pytest layer's path set. A new orphan fails here with
instructions to wire it.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS = REPO_ROOT / "tests"
COHERENCE = REPO_ROOT / "scripts" / "test" / "coherence.sh"


# A real unittest test = a class that INHERITS TestCase (not a mere string
# mention of "unittest.TestCase", which this very file contains).
_TESTCASE_CLASS = re.compile(r"(?m)^\s*class\s+\w+\s*\([^)]*\bTestCase\b")


def _defines_testcase(text: str) -> bool:
    return _TESTCASE_CLASS.search(text) is not None


def _is_pytest_style(p: Path) -> bool:
    text = p.read_text(encoding="utf-8", errors="ignore")
    has_bare = re.search(r"(?m)^def test_\w+", text) is not None
    return has_bare and not _defines_testcase(text)


def _covered_paths() -> tuple[set[str], list[str]]:
    """From coherence.sh: the unittest module list (dotted, → file paths)
    and the pytest layer's path args (dirs/files)."""
    body = COHERENCE.read_text(encoding="utf-8")
    # Dotted modules: `tests.replay.test_audit_chain_continuity` etc.
    unittest_mods = set(re.findall(r"\btests(?:\.[\w-]+)+\b", body))
    unittest_files = {m.replace(".", "/") + ".py" for m in unittest_mods}
    # pytest layer args: `tests/observability/` and `tests/<...>.py`.
    pytest_args = re.findall(r"\btests/[\w./-]+", body)
    return unittest_files, pytest_args


def _is_covered(rel: str, unittest_files: set[str],
                pytest_args: list[str]) -> bool:
    if rel in unittest_files:
        return True
    for arg in pytest_args:
        arg = arg.rstrip("/")
        if rel == arg or rel.startswith(arg + "/") or arg == rel:
            return True
        # directory arg (no .py) covers everything beneath it
        if not arg.endswith(".py") and rel.startswith(arg + "/"):
            return True
    return False


def test_every_pytest_style_test_is_wired_into_a_runner():
    unittest_files, pytest_args = _covered_paths()
    # sanity: the parser actually found the runner config
    assert pytest_args, "no pytest paths parsed from coherence.sh"

    orphans = []
    for p in TESTS.rglob("test_*.py"):
        if "__pycache__" in p.parts:
            continue
        if not _is_pytest_style(p):
            continue  # unittest-style files are run by the unittest layer
        rel = str(p.relative_to(REPO_ROOT))
        if not _is_covered(rel, unittest_files, pytest_args):
            orphans.append(rel)

    assert not orphans, (
        "pytest-style test file(s) run by NO test runner (python3 -m "
        "unittest can't collect them, and they're outside the coherence "
        "pytest layer) — they execute never:\n"
        + "\n".join(f"  - {o}" for o in sorted(orphans))
        + "\nWire each into the coherence.sh L2 pytest layer path set."
    )


def _is_unittest_style(p: Path) -> bool:
    return _defines_testcase(p.read_text(encoding="utf-8", errors="ignore"))


def test_every_unittest_style_test_is_in_the_unittest_list():
    """The coherence unittest layer runs an EXPLICIT hardcoded module list.
    A new `unittest.TestCase` test file dropped under tests/ but not added
    to that list runs nowhere — the unittest sibling of the pytest-orphan
    class. Freeze it: every TestCase test file MUST be in the list."""
    unittest_files, _ = _covered_paths()
    orphans = []
    for p in TESTS.rglob("test_*.py"):
        if "__pycache__" in p.parts:
            continue
        if not _is_unittest_style(p):
            continue
        rel = str(p.relative_to(REPO_ROOT))
        # A file that mixes styles but has bare pytest funcs is run by the
        # pytest layer; only flag pure-TestCase files absent from the list.
        if _is_pytest_style(p):
            continue
        if rel not in unittest_files:
            orphans.append(rel)
    assert not orphans, (
        "unittest.TestCase test file(s) NOT in the coherence `python3 -m "
        "unittest` module list — they execute never:\n"
        + "\n".join(f"  - {o}" for o in sorted(orphans))
        + "\nAdd each (dotted module path) to the L2 unittest layer in "
        "scripts/test/coherence.sh."
    )
