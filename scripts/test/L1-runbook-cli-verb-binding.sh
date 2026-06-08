#!/usr/bin/env bash
# L1-runbook-cli-verb-binding.sh — info-hub runbook ⇄ selfdefctl verb gate.
#
# The operator incident runbooks in the info-hub wiki
# (wiki/runbooks/*.md) tell the operator to run `selfdefctl <verb>` during
# an incident. If a runbook names a verb the CLI doesn't dispatch, the
# remediation is DEAD — the operator hits `unknown command` mid-incident.
# This caught two: `selfdefctl mirror inspect/export` (no top-level mirror
# verb — only rules-mirror/cli-mirror/tui-mirror + m060-doctor/m060-metrics)
# and `selfdefctl findings recent` (no findings verb — recent findings are
# `events alerts`).
#
# This gate binds every `selfdefctl <verb>` referenced in the info-hub
# runbooks to the canonical CLI command set (the top-level `Command` clap
# enum in crates/selfdef-cli/src/main.rs). Matching is done on a normalized
# key (lowercase, strip non-alphanumeric) so clap's CamelCase→kebab-case
# rendering (M060Doctor→m060-doctor, SseQuota→sse-quota) is handled without
# replicating the exact algorithm.
#
# Skips cleanly when the info-hub repo is not adjacent (dev env without all
# repos cloned); env var SELFDEF_INFO_HUB_REPO overrides the default path.
#
# Run: bash scripts/test/L1-runbook-cli-verb-binding.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MAIN_RS="${REPO_ROOT}/crates/selfdef-cli/src/main.rs"
INFO_HUB="${SELFDEF_INFO_HUB_REPO:-${REPO_ROOT}/../devops-solutions-information-hub}"
RUNBOOKS="${INFO_HUB}/wiki/runbooks"

if [[ ! -f "${MAIN_RS}" ]]; then
    echo "L1-runbook-cli-verb-binding FAIL: ${MAIN_RS} missing" >&2
    exit 1
fi
if [[ ! -d "${RUNBOOKS}" ]]; then
    echo "L1-runbook-cli-verb-binding SKIP: info-hub runbooks not adjacent at ${RUNBOOKS} (set SELFDEF_INFO_HUB_REPO)."
    exit 0
fi

MAIN_RS="${MAIN_RS}" RUNBOOKS="${RUNBOOKS}" python3 - <<'PY'
import os, re, sys

main_rs = open(os.environ["MAIN_RS"], encoding="utf-8").read()
m = re.search(r'enum Command \{(.*?)\n\}', main_rs, re.S)
if not m:
    print("L1-runbook-cli-verb-binding FAIL: could not locate `enum Command`")
    sys.exit(1)
variants = re.findall(r'^\s{4}([A-Z][A-Za-z0-9]+)\b', m.group(1), re.M)

def norm(s: str) -> str:
    return re.sub(r'[^a-z0-9]', '', s.lower())

valid = {norm(v) for v in variants}
if len(valid) < 20:
    print(f"L1-runbook-cli-verb-binding FAIL: only parsed {len(valid)} CLI "
          f"verbs — parser/enum drift")
    sys.exit(1)

runbooks = os.environ["RUNBOOKS"]
refs: dict[str, list[str]] = {}
for fn in sorted(os.listdir(runbooks)):
    if not fn.endswith(".md"):
        continue
    text = open(os.path.join(runbooks, fn), encoding="utf-8").read()
    for verb in set(re.findall(r'selfdefctl ([a-z][a-z0-9-]+)', text)):
        refs.setdefault(verb, []).append(fn)

dangling = {v: sorted(set(fs)) for v, fs in refs.items()
            if norm(v) not in valid}
if dangling:
    for v, fs in sorted(dangling.items()):
        print(f"  FAIL `selfdefctl {v}` referenced in {', '.join(fs)} is NOT "
              f"a selfdefctl command — broken operator remediation. Use a "
              f"real verb (selfdefctl --help / the Command enum).")
    print(f"L1-runbook-cli-verb-binding FAIL: {len(dangling)} runbook "
          f"command(s) reference a non-existent selfdefctl verb")
    sys.exit(1)

print(f"L1-runbook-cli-verb-binding PASS: {len(refs)} distinct selfdefctl "
      f"verb(s) across the info-hub runbooks all dispatch ({len(valid)} CLI "
      f"verbs in the Command enum)")
PY
