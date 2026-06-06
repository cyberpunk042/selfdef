#!/usr/bin/env bash
# L1-json-schema-fleet.sh — fleet contract gate for every JSON Schema
# the repo ships at docs/schemas/.
#
# docs/schemas/ houses operator-facing JSON Schema documents that
# define cross-module contract shapes (currently:
# bitnet-schedule.schema.json — SD-R28/SD-R46 bitnet-gpu-inference
# module's apply.sh emit; tensor-parallel-slice-plan.schema.json —
# SD-R58/SD-R60 tensor-parallel inference module's slice plan).
# Each is consumed cross-repo by sovereign-os (inference pick-gpu /
# slice-plan parser). None are currently L1-gated.
#
# Three silent-drift classes:
#   1. $schema declaration drift — consumers using strict JSON Schema
#      validators reject the schema if the draft version drifts off
#      what they support.
#   2. $id drift — consumers identifying schemas by $id break when
#      the URL changes silently.
#   3. additionalProperties=false missing — schema accidentally allows
#      arbitrary extra fields, defeating the strict-shape contract
#      the docstring promises.
#
# This gate walks every *.schema.json under docs/schemas/ and asserts:
#
#   1. Parses as valid JSON
#   2. Top-level $schema is set to a json-schema.org draft URL
#   3. Top-level $id is set + matches the file path convention
#   4. Top-level title is set + non-empty
#   5. Top-level required is a non-empty array
#   6. Top-level additionalProperties === false (strict-shape promise)
#
# Run with: bash scripts/test/L1-json-schema-fleet.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCHEMAS_DIR="${REPO_ROOT}/docs/schemas"

failures=0

if [[ ! -d "${SCHEMAS_DIR}" ]]; then
    echo "L1-json-schema-fleet PASS: ${SCHEMAS_DIR} not present (no schemas to gate)"
    exit 0
fi

shopt -s nullglob
schemas=("${SCHEMAS_DIR}"/*.schema.json)
shopt -u nullglob

if [[ "${#schemas[@]}" -eq 0 ]]; then
    echo "L1-json-schema-fleet PASS: no *.schema.json files under ${SCHEMAS_DIR}"
    exit 0
fi

echo "▶ Walking ${#schemas[@]} JSON Schema files for fleet integrity invariants..."

result=$(python3 - "${schemas[@]}" <<'PY'
import json
import os
import sys

failures = 0
for path in sys.argv[1:]:
    short = os.path.relpath(path, os.path.dirname(os.path.dirname(os.path.dirname(path))))
    try:
        with open(path, "r", encoding="utf-8") as fh:
            d = json.load(fh)
    except json.JSONDecodeError as e:
        print(f"  FAIL {short}: JSON parse error: {e}")
        failures += 1
        continue

    file_failures = 0

    schema_val = d.get("$schema")
    if not isinstance(schema_val, str) or "json-schema.org" not in schema_val:
        print(f"  FAIL {short}: $schema missing or not a json-schema.org URL (got {schema_val!r})")
        failures += 1
        file_failures += 1

    id_val = d.get("$id")
    if not isinstance(id_val, str) or not id_val.strip():
        print(f"  FAIL {short}: $id missing or empty")
        failures += 1
        file_failures += 1

    title = d.get("title")
    if not isinstance(title, str) or not title.strip():
        print(f"  FAIL {short}: title missing or empty")
        failures += 1
        file_failures += 1

    required = d.get("required")
    if not isinstance(required, list) or len(required) == 0:
        print(f"  FAIL {short}: 'required' missing or empty (no fields are mandatory — schema is too permissive)")
        failures += 1
        file_failures += 1

    addl = d.get("additionalProperties")
    if addl is not False:
        print(f"  FAIL {short}: additionalProperties != false (got {addl!r}) — strict-shape contract not enforced")
        failures += 1
        file_failures += 1

    if file_failures == 0:
        req_count = len(required) if isinstance(required, list) else 0
        print(f"  PASS {short}: $schema + $id + title + required ({req_count} fields) + additionalProperties=false")

if failures > 0:
    print(f"FLEET_FAILURES={failures}")
PY
)
echo "${result}"

fleet_failures=$(echo "${result}" | { grep -oE 'FLEET_FAILURES=[0-9]+' || true; } | head -1 | cut -d= -f2)
if [[ -n "${fleet_failures}" && "${fleet_failures}" -gt 0 ]]; then
    failures=$((failures + fleet_failures))
fi

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-json-schema-fleet FAIL: ${failures} integrity violation(s)"
    exit 1
fi

echo "L1-json-schema-fleet PASS: ${#schemas[@]} JSON schemas all structurally coherent"
