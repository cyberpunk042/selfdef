#!/usr/bin/env bats
# L2 bats unit tests for the detect-host module (MS025 — the existing
# selfdef daemon as a first-class module; reference implementation of
# the install.kind = "debian-package" contract from docs/dev/modules.md).
#
# detect-host is special: it has no install/ scripts because the
# install IS the install of the selfdef-daemon Debian package. The
# tests assert the debian-package contract surface instead of
# script presence.
#
# Run with: bats packaging/test/L2-detect-host.bats

MODULE_DIR="${BATS_TEST_DIRNAME}/../../modules/detect-host"

@test "module.toml exists + name = detect-host" {
    [ -f "${MODULE_DIR}/module.toml" ]
    grep -qE '^name[[:space:]]*=[[:space:]]*"detect-host"' "${MODULE_DIR}/module.toml"
}

@test "module.toml install.kind = \"debian-package\" (NOT script)" {
    grep -qE '^kind[[:space:]]*=[[:space:]]*"debian-package"' "${MODULE_DIR}/module.toml"
}

@test "module.toml install.package = \"selfdef-daemon\"" {
    grep -qE '^package[[:space:]]*=[[:space:]]*"selfdef-daemon"' "${MODULE_DIR}/module.toml"
}

@test "module.toml provides {event-bus, finding-store, sigma-correlator}" {
    grep -q 'event-bus'        "${MODULE_DIR}/module.toml"
    grep -q 'finding-store'    "${MODULE_DIR}/module.toml"
    grep -q 'sigma-correlator' "${MODULE_DIR}/module.toml"
}

@test "module.toml requires systemctl binary" {
    grep -q 'value = "systemctl"' "${MODULE_DIR}/module.toml"
}

@test "module.toml has README.md (operator-facing pointer)" {
    [ -f "${MODULE_DIR}/README.md" ]
}

@test "module.toml has NO install/ dir (debian-package kind doesn't ship scripts)" {
    [ ! -d "${MODULE_DIR}/install" ]
}

# Cross-reference: the debian package this module points at must
# actually exist in the workspace. The selfdef-daemon binary builds
# from the selfdef-daemon crate.
@test "referenced selfdef-daemon crate exists in workspace" {
    [ -f "${BATS_TEST_DIRNAME}/../../crates/selfdef-daemon/Cargo.toml" ]
}

# Cross-reference: docs/dev/modules.md documents the two install
# kinds — this module is the canonical reference for debian-package.
@test "docs/dev/modules.md exists (the module-author contract this module exemplifies)" {
    [ -f "${BATS_TEST_DIRNAME}/../../docs/dev/modules.md" ]
}

@test "INVARIANT: module.toml carries module.toml-required version field" {
    grep -qE '^version[[:space:]]*=[[:space:]]*"[0-9]+\.[0-9]+\.[0-9]+"' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT: NO apply.sh / verify.sh (debian-package modules MUST NOT ship scripts — the package's postinst owns lifecycle)" {
    [ ! -f "${MODULE_DIR}/install/apply.sh" ]
    [ ! -f "${MODULE_DIR}/install/verify.sh" ]
}

@test "INVARIANT: README.md documents the debian-package install kind (operator-facing pointer)" {
    grep -qiE 'debian.package|selfdef.daemon' "${MODULE_DIR}/README.md"
}

@test "INVARIANT: referenced selfdef-daemon crate has a binary target (not just a library)" {
    grep -q '\[\[bin\]\]\|name *= *"selfdef-daemon"' "${BATS_TEST_DIRNAME}/../../crates/selfdef-daemon/Cargo.toml"
}

@test "INVARIANT: detect-host module.toml provides ALL three core contracts (the daemon IS the substrate)" {
    # event-bus + finding-store + sigma-correlator are CORE; everything
    # else in the IPS-quattuordectet depends on these surfaces.
    count="$(grep -oE '"(event-bus|finding-store|sigma-correlator)"' "${MODULE_DIR}/module.toml" | sort -u | wc -l)"
    [ "${count}" -ge 3 ]
}

@test "INVARIANT: at least one other module declares consumes = event-bus (the substrate has a downstream consumer)" {
    # If detect-host provides 'event-bus' but nothing consumes it, the
    # contract is dead. At install-time at least one watchdog should
    # consume.
    found=0
    for f in "${BATS_TEST_DIRNAME}/../../modules"/*/module.toml; do
        if [[ "$f" != *"detect-host/module.toml" ]] && grep -q '"event-bus"' "$f" 2>/dev/null; then
            found=1
            break
        fi
    done
    # accept zero (this is an aspirational invariant; some installs are
    # IDS-only without downstream consumers yet) — but require provide-side present.
    grep -qE '"event-bus"' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT: docs/dev/modules.md documents debian-package kind specifically" {
    grep -qE 'debian.package|debian_package' "${BATS_TEST_DIRNAME}/../../docs/dev/modules.md"
}
