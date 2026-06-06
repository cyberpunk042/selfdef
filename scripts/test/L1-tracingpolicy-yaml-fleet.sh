#!/usr/bin/env bash
# L1-tracingpolicy-yaml-fleet.sh — fleet-level structural integrity
# gate for every Tetragon TracingPolicy YAML the repo ships.
#
# Selfdef ships TracingPolicy YAMLs in two trees today:
#   packaging/tetragon-policies/ — installed by Debian postinst,
#                                  enforces real kernel-fence policy
#                                  (Sigkill actions). The flagship
#                                  sovereign-perimeter.yaml is heavily
#                                  pinned by L1-perimeter-yaml-lint.sh
#                                  (R-row-grounded contract).
#   rules/tetragon/             — observability policies (no Sigkill,
#                                  just Post / observe actions). These
#                                  are not currently pinned by any L1.
#
# Both trees follow the same outer schema:
#   apiVersion: cilium.io/v1alpha1
#   kind: TracingPolicy
#   metadata:
#     name: <unique-policy-name>
#   spec:
#     kprobes: [...]
#
# A silent regression of any outer field breaks the kernel's load of
# the policy (apiVersion/kind mismatch) or the policy registry's
# de-duplication (metadata.name collision). This gate walks every
# *.yaml under both trees and asserts:
#
#   1. parses as YAML
#   2. apiVersion == "cilium.io/v1alpha1"
#   3. kind == "TracingPolicy"
#   4. metadata.name is set + non-empty + globally unique across the fleet
#   5. spec.kprobes is a non-empty list
#
# Per-policy semantic details (Sigkill actions / verbatim allowlist /
# selectors) stay the named-unit gate's scope; this is the broader
# structural integrity layer.
#
# Run with: bash scripts/test/L1-tracingpolicy-yaml-fleet.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

failures=0

# Walk both TracingPolicy trees. The find expression is repo-relative
# so the gate works from any cwd.
shopt -s nullglob
candidates=()
for d in "${REPO_ROOT}/packaging/tetragon-policies" "${REPO_ROOT}/rules/tetragon"; do
    [[ -d "${d}" ]] || continue
    for f in "${d}"/*.yaml; do
        [[ -f "${f}" ]] || continue
        candidates+=("${f}")
    done
done
shopt -u nullglob

if [[ "${#candidates[@]}" -eq 0 ]]; then
    echo "L1-tracingpolicy-yaml-fleet PASS: no TracingPolicy YAMLs found at packaging/tetragon-policies/ or rules/tetragon/"
    exit 0
fi

echo "▶ Walking ${#candidates[@]} TracingPolicy YAML files for fleet structural invariants..."

# Use python to validate (yaml.safe_load handles the structure
# checks; jq would also work but yaml.safe_load is already a
# dependency of the existing L1-perimeter-yaml-lint.sh gate).
result=$(python3 - "${candidates[@]}" <<'PY'
import sys
import yaml

candidates = sys.argv[1:]
seen_names: dict[str, str] = {}
failures = 0

for path in candidates:
    rel = path.split("/")
    try:
        idx = rel.index("selfdef") if "selfdef" in rel else 0
    except ValueError:
        idx = 0
    short = "/".join(rel[idx:])

    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except yaml.YAMLError as e:
        print(f"  FAIL {short}: YAML parse error: {e}")
        failures += 1
        continue

    if not isinstance(doc, dict):
        print(f"  FAIL {short}: top-level is not a mapping (got {type(doc).__name__})")
        failures += 1
        continue

    # Tracks failures for this specific file so the PASS summary is
    # only printed when no per-file failure was recorded.
    file_failures = 0

    api = doc.get("apiVersion")
    if api != "cilium.io/v1alpha1":
        print(f"  FAIL {short}: apiVersion != 'cilium.io/v1alpha1' (got {api!r})")
        failures += 1
        file_failures += 1

    kind = doc.get("kind")
    if kind != "TracingPolicy":
        print(f"  FAIL {short}: kind != 'TracingPolicy' (got {kind!r})")
        failures += 1
        file_failures += 1

    metadata = doc.get("metadata") or {}
    name = metadata.get("name")
    if not isinstance(name, str) or not name.strip():
        print(f"  FAIL {short}: metadata.name missing or empty")
        failures += 1
        file_failures += 1
    else:
        if name in seen_names:
            print(f"  FAIL {short}: metadata.name {name!r} collides with {seen_names[name]}")
            failures += 1
            file_failures += 1
        else:
            seen_names[name] = short

    spec = doc.get("spec") or {}
    kprobes = spec.get("kprobes")
    if not isinstance(kprobes, list) or len(kprobes) == 0:
        print(f"  FAIL {short}: spec.kprobes is not a non-empty list")
        failures += 1
        file_failures += 1

    if file_failures == 0:
        kp_count = len(kprobes) if isinstance(kprobes, list) else 0
        print(f"  PASS {short}: apiVersion + kind + metadata.name={name!r} + spec.kprobes ({kp_count} kprobes)")

if failures > 0:
    print(f"FLEET_FAILURES={failures}")
    sys.exit(0)  # exit shell decides; print so shell can read
print(f"FLEET_PASS: {len(candidates)} policies, all structural invariants present")
PY
)
echo "${result}"

# Extract failure count from python output
fleet_failures=$(echo "${result}" | grep -oE 'FLEET_FAILURES=[0-9]+' | head -1 | cut -d= -f2)
if [[ -n "${fleet_failures}" && "${fleet_failures}" -gt 0 ]]; then
    failures=$((failures + fleet_failures))
fi

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-tracingpolicy-yaml-fleet FAIL: ${failures} structural violation(s)"
    exit 1
fi

echo "L1-tracingpolicy-yaml-fleet PASS: ${#candidates[@]} TracingPolicy YAMLs all structurally coherent"
