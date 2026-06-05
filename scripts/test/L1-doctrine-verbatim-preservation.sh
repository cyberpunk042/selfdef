#!/usr/bin/env bash
# L1-doctrine-verbatim-preservation.sh — operator-doctrine verbatim
# preservation gate.
#
# Multiple selfdef crates carry `pub const DOCTRINE_<NAME>: &str = "..."`
# constants that encode OPERATOR-VERBATIM doctrine strings (one per
# named operator standing direction or dump-line quote). The operator's
# "Hard Rule — operator words are SACROSANCT" applies AT THE CODE LAYER:
# silent paraphrase of any of these constants breaches the sacrosanct
# rule with no detection until production.
#
# Two distinct silent-drift classes this gate catches:
#
#   1. **Value drift** — the `DOCTRINE_X` constant's string value got
#      paraphrased (extra word added, capitalization changed, period
#      dropped). The exact-string registry below is the verbatim-pinned
#      reference; any drift FAILs.
#
#   2. **Cross-crate divergence** — the same DOCTRINE_* constant name
#      appears in multiple crates (currently DOCTRINE_TRACE_AT_DECISION
#      lives in BOTH selfdef-policy-decision + selfdef-trace-span). All
#      copies must have IDENTICAL value (otherwise the doctrine is being
#      silently paraphrased by either copy).
#
# Source-grounding: every doctrine string in the registry below was
# extracted from the operator-verbatim dump or from a milestone catalog
# row that cites the dump line. This gate doesn't invent doctrine — it
# pins what's already in the source.
#
# Run with: bash scripts/test/L1-doctrine-verbatim-preservation.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CRATES_DIR="${REPO_ROOT}/crates"

failures=0

# ============================================================================
# Verbatim-pinned doctrine registry (DOCTRINE_NAME=value)
# Each entry: `name|crate|exact-value`
# ============================================================================
declare -a DOCTRINE_ROWS=(
    "DOCTRINE_FULLSTACK_AT_THE_EDGES|selfdef-cli-mirror|Fullstack at the edges"
    "DOCTRINE_NO_VANITY_GRAPHS|selfdef-tui-mirror|A dashboard should not show vanity graphs"
    "DOCTRINE_COMMIT_IS_DURABLE_CHANGE|selfdef-commit-authority|A commit is any durable change"
    "DOCTRINE_VM_NEVER_MUTATES|selfdef-communication-boundary|Never let the VM directly mutate host truth"
    "DOCTRINE_VM_PROPOSES_HOST_COMMITS|selfdef-communication-boundary|The VM proposes. Host commits."
    "DOCTRINE_EXPLICIT_EXCHANGE|selfdef-filesystem-boundary|Use explicit exchange directories"
    "DOCTRINE_VM_WRITES_PROPOSALS|selfdef-filesystem-boundary|VM writes proposals, not final state"
    "DOCTRINE_EVERY_ACTION_OBSERVABLE|selfdef-policy-decision|Every action becomes observable and governed"
    "DOCTRINE_AUTHORITY_FOLLOWS_EVIDENCE|selfdef-profile-authority-gate|Authority follows evidence"
    "DOCTRINE_EVERY_ACTION_EMITS_TRACE|selfdef-trace-span|Every action MUST emit a trace event object"
    # Multi-line const declarations (value on a separate line after the `=`):
    "DOCTRINE_FIVE_BOUNDARIES|selfdef-boundary-summary|the IPS-side 5-boundary doctrine: Communication / Capability / Sandbox / Filesystem / Network"
    "DOCTRINE_TRACE_AT_DECISION|selfdef-policy-decision|Trace is emitted when the action is decided, not after"
    "DOCTRINE_TRACE_AT_DECISION|selfdef-trace-span|Trace is emitted when the action is decided, not after"
)

# ============================================================================
# Gate 1: every pinned doctrine constant has the exact verbatim value
# ============================================================================
echo "▶ Gate 1: each pinned DOCTRINE_* constant carries the verbatim operator string"
for row in "${DOCTRINE_ROWS[@]}"; do
    IFS='|' read -r name crate expected <<< "${row}"
    lib_rs="${CRATES_DIR}/${crate}/src/lib.rs"
    if [[ ! -f "${lib_rs}" ]]; then
        echo "  FAIL ${crate}: src/lib.rs missing (registry rot — crate moved or deleted)"
        failures=$((failures + 1))
        continue
    fi
    # Extract the string literal for this constant. Handles both single-line
    # (`pub const X: &str = "...";`) and multi-line (`pub const X: &str =\n
    # "...";`) forms.
    actual=$(awk -v target="${name}" '
        /^pub const / {
            if (index($0, "const " target ":") > 0) {
                # collect until we find the first quoted string after the `=`
                rest = $0
                while (1) {
                    # find a "..." literal on this line
                    if (match(rest, /"[^"]*"/)) {
                        val = substr(rest, RSTART+1, RLENGTH-2)
                        print val
                        exit
                    }
                    if ((getline next_line) <= 0) exit
                    rest = next_line
                }
            }
        }
    ' "${lib_rs}")
    if [[ "${actual}" == "${expected}" ]]; then
        echo "  PASS ${name} (${crate}) verbatim"
    else
        echo "  FAIL ${name} (${crate}) drift detected:"
        echo "    expected: \"${expected}\""
        echo "    actual:   \"${actual}\""
        failures=$((failures + 1))
    fi
done

# ============================================================================
# Gate 2: cross-crate name collision — same constant name in multiple
# crates must have identical value (or one crate has paraphrased it).
# ============================================================================
echo "▶ Gate 2: cross-crate DOCTRINE_* name collision coherence"

declare -A name_to_crates
declare -A name_to_values

while IFS= read -r match; do
    # match form: crates/<crate>/src/lib.rs:pub const DOCTRINE_X: &str = "..."
    file=$(echo "${match}" | cut -d: -f1)
    crate_dir=$(echo "${file}" | sed 's|crates/\([^/]*\)/.*|\1|')
    cname=$(echo "${match}" | grep -oE 'DOCTRINE_[A-Z_]+' | head -1)
    [[ -z "${cname}" ]] && continue
    # extract value (use grep -E across multiline isn't easy; collect
    # the value via awk over the file)
    val=$(awk -v target="${cname}" '
        /^pub const / {
            if (index($0, "const " target ":") > 0) {
                rest = $0
                while (1) {
                    if (match(rest, /"[^"]*"/)) {
                        val = substr(rest, RSTART+1, RLENGTH-2)
                        print val
                        exit
                    }
                    if ((getline next_line) <= 0) exit
                    rest = next_line
                }
            }
        }
    ' "${REPO_ROOT}/${file}")
    name_to_crates["${cname}"]+="${crate_dir} "
    if [[ -z "${name_to_values[${cname}]:-}" ]]; then
        name_to_values["${cname}"]="${val}"
    elif [[ "${name_to_values[${cname}]}" != "${val}" ]]; then
        name_to_values["${cname}"]="__DRIFT__"
    fi
done < <(cd "${REPO_ROOT}" && grep -rE '^pub const DOCTRINE_[A-Z_]+' crates/*/src/lib.rs 2>/dev/null)

for name in "${!name_to_crates[@]}"; do
    crates="${name_to_crates[${name}]}"
    crate_count=$(echo "${crates}" | wc -w)
    if [[ "${crate_count}" -lt 2 ]]; then
        continue   # only one crate uses this name — no cross-crate concern
    fi
    if [[ "${name_to_values[${name}]}" == "__DRIFT__" ]]; then
        echo "  FAIL ${name} appears in multiple crates with divergent values: ${crates}"
        failures=$((failures + 1))
    else
        echo "  PASS ${name} appears in ${crate_count} crates (${crates}) with identical value"
    fi
done

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-doctrine-verbatim-preservation FAIL: ${failures} doctrine drift violation(s)"
    exit 1
fi

echo "L1-doctrine-verbatim-preservation PASS: all pinned doctrine constants verbatim + cross-crate name-collisions coherent"
