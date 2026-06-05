#!/usr/bin/env bash
# L1-sigma-rule-test-pairing.sh — sigma rule ↔ tests-yaml pairing
# integrity gate.
#
# rules/sigma/ ships sigma detection rules organized into MITRE
# tactic directories (command_and_control / credential_access /
# defense_evasion / discovery / execution / hardening / impact /
# persistence / privilege_escalation). Each rule lives in two files:
#
#   <tactic>/<name>.yml        — the sigma rule itself
#   <tactic>/<name>.tests.yaml — the test fixtures (events that should
#                                 fire / not fire the rule)
#
# Per the SDD-062 routing discipline: every shipped rule MUST have
# matching tests so the rule's classification behavior is regression-
# locked. A rule without tests is a black-box detection — any future
# refactor can silently change what it matches. Shipping a tests file
# without the rule is similarly broken (test references a non-existent
# detection).
#
# Three gates:
#   1. Every .yml has a matching .tests.yaml
#   2. Every .tests.yaml has a matching .yml
#   3. Every .tests.yaml carries `tests:` and at least one `name:`
#      entry (catches an accidentally-empty tests file)
#
# Run with: bash scripts/test/L1-sigma-rule-test-pairing.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SIGMA_DIR="${REPO_ROOT}/rules/sigma"

failures=0

if [[ ! -d "${SIGMA_DIR}" ]]; then
    echo "FAIL: ${SIGMA_DIR} not present"
    exit 1
fi

# Gate 1: rule → tests pairing
echo "▶ Gate 1: every .yml rule has a matching .tests.yaml"
rule_count=0
while IFS= read -r rule; do
    rule_count=$((rule_count + 1))
    tests_file="${rule%.yml}.tests.yaml"
    if [[ -f "${tests_file}" ]]; then
        echo "  PASS $(realpath --relative-to="${SIGMA_DIR}" "${rule}")"
    else
        echo "  FAIL $(realpath --relative-to="${SIGMA_DIR}" "${rule}") has NO matching .tests.yaml"
        failures=$((failures + 1))
    fi
done < <(find "${SIGMA_DIR}" -name '*.yml' -type f 2>/dev/null | sort)

# Gate 2: tests → rule pairing
echo "▶ Gate 2: every .tests.yaml has a matching rule"
tests_count=0
while IFS= read -r tests_file; do
    tests_count=$((tests_count + 1))
    # strip the .tests.yaml suffix; the rule is at <stem>.yml
    stem="${tests_file%.tests.yaml}"
    rule="${stem}.yml"
    if [[ -f "${rule}" ]]; then
        : # silent pass — already reported under Gate 1
    else
        echo "  FAIL $(realpath --relative-to="${SIGMA_DIR}" "${tests_file}") has NO matching rule"
        failures=$((failures + 1))
    fi
done < <(find "${SIGMA_DIR}" -name '*.tests.yaml' -type f 2>/dev/null | sort)

# Gate 3: each tests file is non-trivial (carries `tests:` + at least
# one `name:` entry — catches accidentally-emptied tests file)
echo "▶ Gate 3: every .tests.yaml carries tests: + at least one name: entry"
trivial=0
while IFS= read -r tests_file; do
    if ! grep -qE '^tests:' "${tests_file}"; then
        echo "  FAIL $(realpath --relative-to="${SIGMA_DIR}" "${tests_file}") missing top-level 'tests:' key"
        failures=$((failures + 1))
        continue
    fi
    if ! grep -qE '^\s+- name:' "${tests_file}"; then
        echo "  FAIL $(realpath --relative-to="${SIGMA_DIR}" "${tests_file}") has 'tests:' but no '- name:' entries (empty test list — rule is effectively untested)"
        failures=$((failures + 1))
        continue
    fi
    trivial=$((trivial + 0))
done < <(find "${SIGMA_DIR}" -name '*.tests.yaml' -type f 2>/dev/null | sort)

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-sigma-rule-test-pairing FAIL: ${failures} pairing/coverage violation(s)"
    exit 1
fi

echo "L1-sigma-rule-test-pairing PASS: ${rule_count} sigma rules ↔ ${tests_count} test files, all non-trivial"
