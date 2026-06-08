#!/usr/bin/env bash
# L1-module-config-key-discoverability.sh — operator-config-key discoverability
#
# A module's install/apply.sh (or check.sh) reads operator-settable options
# from the module's OWN config via `toml_get <key> "$CONFIG_FILE"`. If a key
# is read but documented in NONE of the module's shipped profiles/*.toml (or
# config/*.toml, or the module.toml [profiles] commentary), the operator
# can't discover the option exists — they only find out when apply.sh fails
# (worst case: a safety acknowledgment like kernel-yama-baseline's
# `acknowledge_paranoid`, which gates an IRREVERSIBLE ptrace_scope=3 raise,
# was undocumented — the operator hit the die() mid-apply).
#
# This gate binds own-config reads to shipped documentation: every
# `toml_get <key> "$CONFIG_FILE"` key MUST appear in one of the module's
# shipped config docs. Keys read from a SIBLING module's config (e.g.
# agent-guard reading tetragon's `policy_dir` from "$TG_CFG") are NOT this
# module's to document and are excluded by anchoring on "$CONFIG_FILE".
#
# Run: bash scripts/test/L1-module-config-key-discoverability.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${REPO_ROOT}" || { echo "cd ${REPO_ROOT} failed" >&2; exit 2; }

python3 - <<'PY'
import re, glob, os, sys

violations = []
checked = 0
for mod_dir in sorted(glob.glob("modules/*/")):
    name = os.path.basename(mod_dir.rstrip("/"))
    own_keys = set()
    for s in ("install/apply.sh", "install/check.sh"):
        p = os.path.join(mod_dir, s)
        if os.path.isfile(p):
            txt = open(p, errors="ignore").read()
            # Own-config reads only: toml_get <key> "$CONFIG_FILE".
            own_keys |= set(re.findall(
                r'toml_get\s+([a-z][a-z0-9_]+)\s+"\$CONFIG_FILE"', txt))
    if not own_keys:
        continue
    checked += 1
    doc = ""
    for pat in ("profiles/*.toml", "config/*.toml"):
        for prof in glob.glob(os.path.join(mod_dir, pat)):
            doc += open(prof, errors="ignore").read() + "\n"
    mt = os.path.join(mod_dir, "module.toml")
    if os.path.isfile(mt):
        doc += open(mt, errors="ignore").read()
    documented = set(re.findall(r'\b([a-z][a-z0-9_]+)\b', doc))
    undoc = sorted(k for k in own_keys if k not in documented)
    if undoc:
        violations.append((name, undoc))

if checked == 0:
    print("L1-module-config-key-discoverability FAIL: no modules read "
          "$CONFIG_FILE keys (parser/path drift)")
    sys.exit(1)

for name, keys in violations:
    for k in keys:
        print(f"  FAIL {name}: reads operator key '{k}' from $CONFIG_FILE "
              f"but it is documented in NO shipped profiles/*.toml, "
              f"config/*.toml, or module.toml — operators can't discover it. "
              f"Add it (with the default + a comment) to the relevant profile.")

if violations:
    n = sum(len(k) for _, k in violations)
    print(f"L1-module-config-key-discoverability FAIL: {n} undocumented "
          f"operator config key(s) across {len(violations)} module(s)")
    sys.exit(1)

print(f"L1-module-config-key-discoverability PASS: {checked} modules read "
      f"own $CONFIG_FILE keys; every one is documented in a shipped profile")
PY
