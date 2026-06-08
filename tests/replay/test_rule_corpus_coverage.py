"""F-2026-064: audit of sigma-rule ↔ replay-corpus coverage.

The replay corpora (`tests/replay/<source>/<scenario>.jsonl` +
`.expected.yaml`) are the end-to-end regression net: a corpus is replayed
through the engine and the `.expected.yaml` asserts which rules fire. The
per-rule `.tests.yaml` unit suite is paired by the coherence harness, but
nothing audited the *corpus* side — so a `.expected.yaml` could reference
a rule_id that no longer exists (a silently dead assertion), or ship a
malformed corpus, and CI would not notice.

This audits the corpus integrity (stdlib only — no yaml dep):
  1. every `rule_id` a `.expected.yaml` references is a real rule in
     `rules/sigma/` (no orphan / typo'd assertions);
  2. every `.jsonl` corpus is valid JSON-lines;
  3. every `.expected.yaml` has its sibling `.jsonl`;
  4. the corpus is non-vacuous (at least one real expected firing).

Run: ``pytest -xq tests/replay/test_rule_corpus_coverage.py``
"""
from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SIGMA_DIR = REPO_ROOT / "rules" / "sigma"
REPLAY_DIR = REPO_ROOT / "tests" / "replay"

_UUID = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
)


def _rule_ids() -> set[str]:
    """Every rule UUID declared under rules/sigma/ (the `id:` field)."""
    ids: set[str] = set()
    for f in SIGMA_DIR.rglob("*.yml"):
        if f.name.endswith(".tests.yaml"):
            continue
        for m in re.finditer(r"(?m)^\s*id:\s*(\S+)", f.read_text()):
            tok = m.group(1).strip().strip("\"'")
            if _UUID.fullmatch(tok):
                ids.add(tok)
    return ids


def _expected_files() -> list[Path]:
    return sorted(REPLAY_DIR.rglob("*.expected.yaml"))


def _jsonl_files() -> list[Path]:
    return sorted(REPLAY_DIR.rglob("*.jsonl"))


def _referenced_rule_ids(expected: Path) -> set[str]:
    """rule_ids cited in a .expected.yaml (expected_findings + negative)."""
    ids: set[str] = set()
    for m in re.finditer(r"rule_id:\s*([^\s#]+)", expected.read_text()):
        tok = m.group(1).strip().strip("\"'")
        if _UUID.fullmatch(tok):
            ids.add(tok)
    return ids


def test_sigma_rule_ids_present():
    ids = _rule_ids()
    assert len(ids) >= 15, f"expected the sigma rule corpus; found {len(ids)} ids"


def test_every_expected_rule_id_is_a_real_rule():
    rule_ids = _rule_ids()
    orphans: list[str] = []
    total = 0
    for exp in _expected_files():
        for rid in _referenced_rule_ids(exp):
            total += 1
            if rid not in rule_ids:
                orphans.append(f"{exp.relative_to(REPO_ROOT)} -> {rid}")
    assert total > 0, "no rule_ids referenced by any .expected.yaml — corpus not wired"
    assert not orphans, (
        "replay .expected.yaml files reference rule_ids that no rule in "
        "rules/sigma/ declares (dead assertions):\n" + "\n".join(orphans)
    )


def test_every_expected_yaml_has_its_jsonl():
    missing = [
        str(exp.relative_to(REPO_ROOT))
        for exp in _expected_files()
        if not exp.with_name(exp.name.replace(".expected.yaml", ".jsonl")).is_file()
    ]
    assert not missing, "expected.yaml without a sibling .jsonl corpus:\n" + "\n".join(missing)


def test_every_jsonl_corpus_is_valid_json_lines():
    bad: list[str] = []
    for corpus in _jsonl_files():
        for n, line in enumerate(corpus.read_text().splitlines(), 1):
            if not line.strip():
                continue
            try:
                json.loads(line)
            except json.JSONDecodeError as e:
                bad.append(f"{corpus.relative_to(REPO_ROOT)}:{n}: {e}")
    assert not bad, "malformed JSON in replay corpora:\n" + "\n".join(bad)
