#!/usr/bin/env bash
# L1-sigma-rule-test-coverage.sh — Sigma rule ↔ test-corpus coverage gate
#
# Closes findings-ledger F-2026-064 ("No audit of rule ↔ corpus
# coverage").
#
# selfdef ships 22 Sigma detection rules under rules/sigma/<tactic>/, each
# paired with a co-located <rule>.tests.yaml fixture that drives the
# correlator's per-rule replay tests. The pairing is complete today, but
# it was maintained by manual discipline only — nothing FAILED if:
#   (a) a new rule.yml landed with no .tests.yaml (rule ships untested —
#       a detection that has never been exercised against a firing event);
#   (b) a .tests.yaml was left orphaned after its rule was renamed/removed;
#   (c) a .tests.yaml exercised only the fire path OR only the no-fire path
#       — coverage that looks green but never proves the rule DOESN'T fire
#       on benign input (false-positive blindness) or DOES fire on the
#       real attack (false-negative blindness).
#
# A silently-untested detection rule is a production-readiness gap: the
# operator believes a tactic is covered when the rule may match nothing
# (or everything). This gate makes all three land RED.
#
# Gates (all mandatory; PyYAML is always present — same contract as
# L1-yaml-parse-scan.sh):
#   Gate 1: every rules/sigma/**/*.yml (excluding README) has a co-located
#           <base>.tests.yaml.
#   Gate 2: every <base>.tests.yaml has a co-located <base>.yml (no orphan
#           fixtures).
#   Gate 3: every .tests.yaml is a mapping with a non-empty `tests:` list,
#           and every case has name + non-empty events list +
#           integer expected_findings.
#   Gate 4: every .tests.yaml has at least ONE positive case
#           (expected_findings > 0) AND at least ONE negative case
#           (expected_findings == 0) — both the fire and no-fire paths
#           are proven.
#
# Source: extends the MS045/SDD-030 coherence harness; parallel to
# L1-yaml-parse-scan.sh (syntax) — this gate is the semantic coverage
# layer on top of it.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${REPO_ROOT}" || { echo "cd ${REPO_ROOT} failed" >&2; exit 2; }

SIGMA_DIR="rules/sigma"
if [[ ! -d "${SIGMA_DIR}" ]]; then
    echo "L1-sigma-rule-test-coverage FAIL: ${SIGMA_DIR} not found" >&2
    exit 1
fi

python3 - "${SIGMA_DIR}" <<'PY'
import glob
import os
import sys

import yaml

sigma_dir = sys.argv[1]

rules = sorted(
    p for p in glob.glob(os.path.join(sigma_dir, "**", "*.yml"), recursive=True)
)
tests = sorted(
    glob.glob(os.path.join(sigma_dir, "**", "*.tests.yaml"), recursive=True)
)

errors = []

# Gate 1: every rule has a co-located .tests.yaml.
for rule in rules:
    base = rule[: -len(".yml")]
    tf = base + ".tests.yaml"
    if not os.path.isfile(tf):
        errors.append(f"MISSING-TESTS  {rule} has no {os.path.basename(tf)}")

# Gate 2: every .tests.yaml has a co-located rule .yml.
for tf in tests:
    base = tf[: -len(".tests.yaml")]
    rule = base + ".yml"
    if not os.path.isfile(rule):
        errors.append(
            f"ORPHAN-TESTS   {tf} has no matching {os.path.basename(rule)}"
        )

# Gates 3 + 4: structure + positive/negative coverage per fixture.
for tf in tests:
    try:
        doc = yaml.safe_load(open(tf, encoding="utf-8"))
    except yaml.YAMLError as e:
        errors.append(f"PARSE-ERROR    {tf}: {e}")
        continue
    if not isinstance(doc, dict) or "tests" not in doc:
        errors.append(f"NO-TESTS-KEY   {tf}: not a mapping with a `tests:` list")
        continue
    cases = doc.get("tests") or []
    if not isinstance(cases, list) or not cases:
        errors.append(f"EMPTY-TESTS    {tf}: `tests:` is empty")
        continue
    positive = 0
    negative = 0
    for i, c in enumerate(cases):
        if not isinstance(c, dict):
            errors.append(f"BAD-CASE       {tf}[{i}]: case is not a mapping")
            continue
        if not c.get("name"):
            errors.append(f"BAD-CASE       {tf}[{i}]: missing `name`")
        evs = c.get("events")
        if not isinstance(evs, list) or not evs:
            errors.append(f"BAD-CASE       {tf}[{i}]: `events` must be a non-empty list")
        exp = c.get("expected_findings")
        if not isinstance(exp, int) or isinstance(exp, bool):
            errors.append(
                f"BAD-CASE       {tf}[{i}]: `expected_findings` must be an int"
            )
            continue
        if exp > 0:
            positive += 1
        elif exp == 0:
            negative += 1
        else:
            errors.append(
                f"BAD-CASE       {tf}[{i}]: `expected_findings` must be >= 0"
            )
    if positive == 0:
        errors.append(
            f"NO-POSITIVE    {tf}: no case with expected_findings > 0 "
            f"(the rule's fire path is never proven)"
        )
    if negative == 0:
        errors.append(
            f"NO-NEGATIVE    {tf}: no case with expected_findings == 0 "
            f"(the rule's no-fire path is never proven — false-positive blind)"
        )

if errors:
    print("L1-sigma-rule-test-coverage FAIL:")
    for e in errors:
        print(f"  {e}")
    print(
        "\nFix: pair every rules/sigma/<tactic>/<rule>.yml with a "
        "<rule>.tests.yaml carrying at least one firing (expected_findings"
        " > 0) and one non-firing (expected_findings == 0) case."
    )
    sys.exit(1)

print(
    f"  PASS {len(rules)} Sigma rules each have a .tests.yaml with "
    f"positive + negative coverage ({len(tests)} fixtures audited)"
)
PY
