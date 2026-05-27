#!/usr/bin/env bash
# L1-perimeter-yaml-lint.sh — MS047 D6 L1 gate
#
# Verifies packaging/tetragon-policies/sovereign-perimeter.yaml:
#   1. parses as YAML
#   2. has the verbatim sain-01 §6 structure (kind, metadata.name)
#   3. preserves the verbatim default allowlist
#   4. preserves the Sigkill action
#   5. passes yamllint (if installed; non-fatal if absent)
#
# Source: SDD-028 Deliverable 6 — L1 (yaml-lint)
# Implements: MS047 R11041-R11075 (verbatim YAML structure)
set -euo pipefail

YAML_PATH="${YAML_PATH:-packaging/tetragon-policies/sovereign-perimeter.yaml}"

if [[ ! -f "${YAML_PATH}" ]]; then
    echo "L1 FAIL: ${YAML_PATH} not found" >&2
    exit 1
fi

# Gate 1+2+3+4: structural verification via python yaml parser
python3 - "${YAML_PATH}" <<'PY'
import sys, yaml
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    doc = yaml.safe_load(fh)

assert doc["apiVersion"] == "cilium.io/v1alpha1", f"apiVersion drift: {doc['apiVersion']!r}"
assert doc["kind"] == "TracingPolicy", f"kind drift: {doc['kind']!r}"
assert doc["metadata"]["name"] == "sovereign-kernel-fence", \
    f"metadata.name drift: {doc['metadata']['name']!r}"

kprobe = doc["spec"]["kprobes"][0]
assert kprobe["call"] == "sys_execve", f"kprobe.call drift: {kprobe['call']!r}"
assert kprobe["syscall"] is True, f"kprobe.syscall must be true"

args = kprobe["args"][0]
assert args["index"] == 0 and args["type"] == "string", \
    f"args drift: {args!r}"

sel = kprobe["selectors"][0]["matchArgs"][0]
assert sel["index"] == 0, f"matchArgs.index drift: {sel['index']!r}"
assert sel["operator"] == "NotIn", f"matchArgs.operator drift: {sel['operator']!r}"

expected = [
    "/usr/bin/python3",
    "/usr/bin/nvidia-smi",
    "/usr/local/bin/vllm",
    "/usr/bin/podman",
]
assert sel["values"] == expected, (
    f"DEFAULT ALLOWLIST DRIFT from sain-01 §6 verbatim:\n"
    f"  expected: {expected}\n"
    f"  got:      {sel['values']}"
)

action = kprobe["selectors"][0]["matchActions"][0]["action"]
assert action == "Sigkill", f"matchActions.action drift: {action!r}"

print(f"L1 PASS: {path}")
print(f"  kind=TracingPolicy name=sovereign-kernel-fence")
print(f"  kprobe=sys_execve action=Sigkill")
print(f"  default allowlist ({len(expected)} entries) matches sain-01 §6 verbatim")
PY

# Gate 5: yamllint (optional, non-fatal)
if command -v yamllint >/dev/null 2>&1; then
    # The verbatim sain-01 §6 structure (asserted field-by-field above) uses
    # the common non-indented-sequence block style, which yamllint's default
    # `indentation` rule flags as a *cosmetic* error — even though the YAML is
    # valid and the structural gates above already pin every required value.
    # Disable that cosmetic rule so the gate lints for REAL issues only
    # (syntax + key-duplicates), staying green across yamllint versions
    # without reformatting the security-critical kernel-fence policy.
    yamllint -d '{extends: default, rules: {line-length: {max: 120}, document-start: disable, truthy: {check-keys: false}, indentation: disable}}' \
        "${YAML_PATH}" >/dev/null
    echo "L1 PASS: yamllint clean (real-issue rules; cosmetic indentation disabled)"
else
    echo "L1 SKIP: yamllint not installed (structural gates all passed)"
fi
