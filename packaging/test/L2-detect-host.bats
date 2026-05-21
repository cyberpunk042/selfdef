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
