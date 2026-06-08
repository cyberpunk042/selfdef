#!/usr/bin/env bash
# L1-module-requires-binary-coherence.sh — module.toml binary `requires`
# vs apply-time hard requirements (P4 verification gate)
#
# Every module's install scripts abort on a missing binary with the
# canonical pattern:
#
#     command -v <bin> ... || die "<bin> missing"
#
# The dependency pre-flight (daemon_requires / `selfdefctl modules apply`'s
# requirement check) reads the module.toml `requires` block to decide,
# BEFORE running apply.sh, whether the host has what the module needs. If a
# binary that apply.sh hard-requires (`|| die`) is NOT declared as a
# `{ kind = "binary", value = "<bin>" }` require, the pre-flight passes and
# the module then dies mid-apply — exactly the half-applied state the
# pre-flight exists to prevent.
#
# This gate locks the declaration ⇄ reality alignment: every binary an
# install script hard-requires with `|| die` must be declared as a binary
# require. It keys ONLY on the unambiguous `|| die` form — graceful
# `command -v X || { warn; return 0; }` probes (optional features) are
# correctly NOT required to be declared.
#
# Static check — reads module.toml + install/*.sh; no host binaries needed.
#
# Source: P4 (Declarations Aspirational Until Verified) applied to the
# module dependency contract. Run: bash scripts/test/L1-module-requires-binary-coherence.sh
set -euo pipefail

MODULES_DIR="${MODULES_DIR:-modules}"

if [[ ! -d "${MODULES_DIR}" ]]; then
    echo "L1-module-requires-binary-coherence FAIL: ${MODULES_DIR} not found" >&2
    exit 1
fi

python3 - "${MODULES_DIR}" << 'PY'
import re, sys, pathlib

root = pathlib.Path(sys.argv[1])
die_re = re.compile(r'command -v\s+(\S+)\b[^\n]*\|\|\s*die\b')
bin_decl_re = (
    re.compile(r'kind\s*=\s*"binary"\s*,\s*value\s*=\s*"([^"]+)"'),
    re.compile(r'value\s*=\s*"([^"]+)"\s*,\s*kind\s*=\s*"binary"'),
)

checked = 0
violations = []
for mdir in sorted(p for p in root.iterdir() if p.is_dir()):
    mtoml = mdir / "module.toml"
    idir = mdir / "install"
    if not (mtoml.exists() and (idir / "apply.sh").exists()):
        continue
    checked += 1
    toml_text = mtoml.read_text()
    declared = set()
    for rx in bin_decl_re:
        declared |= set(rx.findall(toml_text))

    required = set()
    for sh in sorted(idir.glob("*.sh")):
        for m in die_re.finditer(sh.read_text()):
            b = m.group(1).strip('"').strip("'")
            if re.fullmatch(r'[a-zA-Z0-9_.-]+', b):  # a real binary name token
                required.add(b)

    missing = sorted(required - declared)
    if missing:
        violations.append((mdir.name, missing, sorted(declared)))

for name, missing, declared in violations:
    print(f"  FAIL {name}: install scripts `|| die` on {missing} but "
          f"module.toml declares binary requires {declared} — add "
          f"`{{ kind = \"binary\", value = \"<bin>\" }}` so the dependency "
          f"pre-flight catches a missing binary before apply, not mid-apply")

print(f"  checked {checked} modules")
if violations:
    print(f"L1-module-requires-binary-coherence FAIL: {len(violations)} module(s) "
          f"hard-require an undeclared binary")
    sys.exit(1)
print("L1-module-requires-binary-coherence PASS: every `|| die` binary "
      "requirement is declared in module.toml")
PY
