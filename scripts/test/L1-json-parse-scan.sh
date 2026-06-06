#!/usr/bin/env bash
# L1-json-parse-scan.sh — repo-wide JSON parse + duplicate-key gate
#
# selfdef ships a handful of hand-maintained JSON documents that real code
# paths consume: the two JSON-schemas under docs/schemas/ (loaded by the
# selfdef-cli module_bitnet_gpu_inference / module_tensor_parallel_inference
# integration tests), the auditd replay fixture (tests/replay/), and the
# dashboard manifest. Until now no coherence layer validated that any of
# them parses, and none guarded duplicate object keys.
#
# A duplicate key is a silent data-loss bug: json.load keeps only the LAST
# value for a repeated key with no error, so a doubled field in a schema or
# fixture quietly drops the earlier value — the file loads fine but means
# something different. This gate makes both land RED:
#   - every JSON document must parse;
#   - no object may declare the same key twice (object_pairs_hook guard).
#
# Stdlib-only (PyYAML not needed). Parallel to L1-yaml-parse-scan.sh,
# L1-shellcheck-scan.sh, and L1-ruff-python.sh.
#
# Source: extends the MS045/SDD-030 coherence harness.
set -euo pipefail

mapfile -t files < <(
    # Exclude target/ + node_modules + sister-repo checkouts (_infohub/,
    # _selfdef/, _sovereign-os/). See L1-ruff-python.sh + L1-yaml-parse-
    # scan.sh for the rationale: CI four-watchdog clones info-hub into
    # _infohub/ for runbook-URL existence checks, and its wiki/ JSON
    # files (manifest.json etc.) aren't selfdef's responsibility to scan.
    find . \( -path ./target -o -path '*/node_modules/*' \
              -o -path ./_infohub -o -path ./_selfdef \
              -o -path ./_sovereign-os \) -prune -o \
        -name '*.json' -type f -print 2>/dev/null \
        | grep -vE '/target/|/node_modules/|/_infohub/|/_selfdef/|/_sovereign-os/' \
        | sort
)
if [[ ${#files[@]} -eq 0 ]]; then
    echo "L1-json-parse-scan FAIL: no JSON files found" >&2
    exit 1
fi

python3 - "${files[@]}" <<'PY'
import json
import sys


class DuplicateKeyError(Exception):
    pass


def no_dup_keys(pairs):
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise DuplicateKeyError(f"duplicate key {key!r}")
        seen.add(key)
    return dict(pairs)


bad = []
for path in sys.argv[1:]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            json.load(fh, object_pairs_hook=no_dup_keys)
    except (DuplicateKeyError, json.JSONDecodeError, OSError) as e:
        bad.append((path, str(e).splitlines()[0]))

if bad:
    sys.stderr.write("L1-json-parse-scan FAIL: JSON parse / duplicate-key errors:\n")
    for path, err in bad:
        sys.stderr.write(f"  {path}: {err}\n")
    sys.exit(1)
print(f"L1-json-parse-scan PASS: {len(sys.argv) - 1} JSON files parse clean, 0 duplicate keys")
PY
