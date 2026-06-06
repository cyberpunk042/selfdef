#!/usr/bin/env bash
# L1-yaml-parse-scan.sh — repo-wide YAML parse + real-bug gate
#
# selfdef ships ~62 YAML documents that drive runtime behavior: 22 Sigma
# detection rules (+ their 22 .tests.yaml fixtures), Tetragon tracing
# policies (packaging/, rules/, config/), agent-guard + host-sentinel
# policy sets, the observability scrape/alert templates, GitHub workflows,
# and replay/adversary fixtures. Until now only ONE of them — the MS047
# perimeter policy (see L1-perimeter-yaml-lint.sh) — had any L1 gate; the
# Sigma rules are exercised by the Rust correlator suite, but the policy
# sets, templates, workflows and fixtures had no coverage at all.
#
# A YAML file that fails to parse does not loudly crash its consumer — a
# malformed Sigma rule or Tetragon policy is typically SKIPPED by the
# loader, so a hardening detection silently disappears. Worse, a DUPLICATE
# mapping key parses fine but silently drops the earlier value (e.g. two
# `action:` keys → only the last survives), which can turn a Sigkill policy
# into a no-op without any syntax error. This gate makes both land RED:
#   Gate 1 (mandatory): every YAML doc must parse (PyYAML safe_load_all);
#   Gate 2 (optional):  yamllint at real-bug severity — key-duplicates and
#                       syntax only, all cosmetic style rules disabled, so
#                       it never flags formatting. Skips if yamllint absent
#                       (CI installs it; this is the same non-fatal contract
#                       as L1-perimeter-yaml-lint.sh).
#
# Source: extends the MS045/SDD-030 coherence harness; parallel to the
# L1-shellcheck-scan.sh (.sh) and L1-ruff-python.sh (.py) surface gates.
set -euo pipefail

mapfile -t files < <(
    # Exclude target/ + sister-repo checkouts (_infohub/, _selfdef/,
    # _sovereign-os/) so the CI four-watchdog job's `actions/checkout@v4
    # path: _infohub` doesn't contaminate selfdef's YAML surface with
    # info-hub's wiki frontmatter etc.
    find . \( -path ./target -o -path ./_infohub \
              -o -path ./_selfdef -o -path ./_sovereign-os \) -prune -o \
        \( -name '*.yaml' -o -name '*.yml' \
           -o -name '*.yml.template' -o -name '*.yaml.template' \) \
        -type f -print 2>/dev/null \
        | grep -v -e '/target/' -e '/_infohub/' -e '/_selfdef/' \
                  -e '/_sovereign-os/' \
        | sort
)
if [[ ${#files[@]} -eq 0 ]]; then
    echo "L1-yaml-parse-scan FAIL: no YAML files found" >&2
    exit 1
fi

# Gate 1 (mandatory): every document must parse. PyYAML is always present
# (the perimeter gate, the modules-gate mirror, and ux-harness all rely on
# it), so this gate always runs — no skip path.
python3 - "${files[@]}" <<'PY'
import sys
import yaml

bad = []
for path in sys.argv[1:]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            list(yaml.safe_load_all(fh))
    except (OSError, yaml.YAMLError) as e:
        bad.append((path, str(e).replace("\n", " ")))

if bad:
    sys.stderr.write("L1-yaml-parse-scan FAIL: YAML parse errors:\n")
    for path, err in bad:
        sys.stderr.write(f"  {path}: {err}\n")
    sys.exit(1)
print(f"L1-yaml-parse-scan: {len(sys.argv) - 1} YAML documents parse clean")
PY

# Gate 2 (optional): yamllint at real-bug severity only. Every cosmetic
# style rule is disabled so this never trips on formatting — it exists
# purely to catch duplicate mapping keys (silent data loss) and any syntax
# defect PyYAML's permissive loader might tolerate.
if command -v yamllint >/dev/null 2>&1 || python3 -c "import yamllint" >/dev/null 2>&1; then
    cfg='{extends: default, rules: {
        line-length: disable, document-start: disable,
        truthy: {check-keys: false}, comments: disable,
        comments-indentation: disable, indentation: disable,
        empty-lines: disable, trailing-spaces: disable,
        new-line-at-end-of-file: disable, brackets: disable,
        braces: disable, colons: disable, commas: disable,
        hyphens: disable, empty-values: disable,
        key-duplicates: enable}}'
    if command -v yamllint >/dev/null 2>&1; then
        yamllint -d "${cfg}" -f parsable "${files[@]}"
    else
        python3 -m yamllint -d "${cfg}" -f parsable "${files[@]}"
    fi
    echo "L1-yaml-parse-scan PASS: ${#files[@]} YAML files, 0 parse + 0 real-bug (key-dup) findings"
else
    echo "L1-yaml-parse-scan PASS: ${#files[@]} YAML files parse clean (yamllint absent — key-dup check skipped; CI installs it)"
fi
exit 0
