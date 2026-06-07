#!/usr/bin/env bats
# L2 bats unit tests for the agent-guard module's install + assets.
#
# Locks the MS017 agent-guard module's shipped surface against drift:
#   - install scripts (apply / check / uninstall / lib) exist + are
#     executable in the install/ dir
#   - both profiles (audit, enforce) are supported by apply.sh
#   - the five shipped TracingPolicy templates exist + parse as YAML:
#       container-shell-guard, egress-guard, etc-write-guard,
#       gpu-device-guard, securemessage-guard
#   - apply.sh is SELFDEF_DRY_RUN aware (idempotency contract per
#     docs/dev/modules.md)
#   - apply.sh rejects unknown profiles cleanly
#   - dry-run smoke: end-to-end against a tmpdir Tetragon config
#
# Run with: bats packaging/test/L2-agent-guard.bats

MODULE_DIR="${BATS_TEST_DIRNAME}/../../modules/agent-guard"
INSTALL_DIR="${MODULE_DIR}/install"
POLICIES_DIR="${MODULE_DIR}/policies"

# ============================================================
# Module shape
# ============================================================

@test "module.toml exists at the module root" {
    [ -f "${MODULE_DIR}/module.toml" ]
}

@test "module.toml declares name = \"agent-guard\"" {
    grep -qE '^name[[:space:]]*=[[:space:]]*"agent-guard"' "${MODULE_DIR}/module.toml"
}

@test "module.toml depends_on includes tetragon (MS016 substrate)" {
    grep -qE '^depends_on[[:space:]]*=[[:space:]]*\[.*"tetragon"' "${MODULE_DIR}/module.toml"
}

@test "module.toml profiles.available = [audit, enforce]" {
    grep -qE 'available[[:space:]]*=[[:space:]]*\[\s*"audit"\s*,\s*"enforce"\s*\]' "${MODULE_DIR}/module.toml"
}

@test "module.toml install.kind = \"script\"" {
    grep -qE '^kind[[:space:]]*=[[:space:]]*"script"' "${MODULE_DIR}/module.toml"
}

@test "install/apply.sh exists + is executable" {
    [ -x "${INSTALL_DIR}/apply.sh" ]
}

@test "install/check.sh exists + is executable" {
    [ -x "${INSTALL_DIR}/check.sh" ]
}

@test "install/uninstall.sh exists + is executable" {
    [ -x "${INSTALL_DIR}/uninstall.sh" ]
}

@test "install/lib.sh exists" {
    [ -f "${INSTALL_DIR}/lib.sh" ]
}

# ============================================================
# apply.sh — profile handling + dry-run + per-policy toggles
# ============================================================

@test "apply.sh uses set -euo pipefail" {
    grep -qE '^set -euo pipefail' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh supports both 'audit' and 'enforce' profiles" {
    grep -qE 'audit\|enforce' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh is SELFDEF_DRY_RUN aware" {
    grep -q 'SELFDEF_DRY_RUN' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh exposes per-policy enable toggles (5 policies)" {
    grep -q 'etc_write_enabled'      "${INSTALL_DIR}/apply.sh"
    grep -q 'shell_exec_enabled'     "${INSTALL_DIR}/apply.sh"
    grep -q 'egress_enabled'         "${INSTALL_DIR}/apply.sh"
    grep -q 'securemessage_enabled'  "${INSTALL_DIR}/apply.sh"
    grep -q 'gpu_device_enabled'     "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh exposes per-policy action overrides (5 policies)" {
    grep -q 'etc_write_action'      "${INSTALL_DIR}/apply.sh"
    grep -q 'shell_exec_action'     "${INSTALL_DIR}/apply.sh"
    grep -q 'egress_action'         "${INSTALL_DIR}/apply.sh"
    grep -q 'securemessage_action'  "${INSTALL_DIR}/apply.sh"
    grep -q 'gpu_device_action'     "${INSTALL_DIR}/apply.sh"
}

# ============================================================
# Policy assets — structural validity
# ============================================================

@test "policies/ dir exists" {
    [ -d "${POLICIES_DIR}" ]
}

@test "container-shell-guard.yaml policy parses as YAML" {
    python3 -c "import yaml; yaml.safe_load(open('${POLICIES_DIR}/container-shell-guard.yaml'))"
}

@test "egress-guard.yaml policy parses as YAML" {
    python3 -c "import yaml; yaml.safe_load(open('${POLICIES_DIR}/egress-guard.yaml'))"
}

@test "etc-write-guard.yaml policy parses as YAML" {
    python3 -c "import yaml; yaml.safe_load(open('${POLICIES_DIR}/etc-write-guard.yaml'))"
}

@test "gpu-device-guard.yaml policy parses as YAML" {
    python3 -c "import yaml; yaml.safe_load(open('${POLICIES_DIR}/gpu-device-guard.yaml'))"
}

@test "securemessage-guard.yaml policy parses as YAML" {
    python3 -c "import yaml; yaml.safe_load(open('${POLICIES_DIR}/securemessage-guard.yaml'))"
}

@test "every shipped policy declares kind: TracingPolicy" {
    for f in "${POLICIES_DIR}"/*.yaml; do
        grep -qE '^kind:[[:space:]]+TracingPolicy(Namespaced)?$' "$f"
    done
}

@test "every shipped policy has metadata.name (Kubernetes object shape)" {
    for f in "${POLICIES_DIR}"/*.yaml; do
        python3 -c "
import yaml, sys
d = yaml.safe_load(open('$f'))
assert d.get('metadata', {}).get('name'), 'missing metadata.name in $f'
"
    done
}

# ============================================================
# Dry-run smoke (audit profile, tmpdir Tetragon config)
# ============================================================

setup_dry_run() {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_DRY_RUN=1
    export SELFDEF_AGENT_GUARD_CONFIG="${TEST_DIR}/agent-guard.toml"
    cat > "${SELFDEF_AGENT_GUARD_CONFIG}" <<EOF
profile = "audit"
scope = "container"
pod_label_key = ""
pod_label_value = ""
etc_write_enabled = "true"
etc_write_action = "default"
shell_exec_enabled = "true"
shell_exec_action = "default"
egress_enabled = "true"
egress_action = "default"
egress_allowlist = ""
securemessage_enabled = "true"
securemessage_action = "default"
securemessage_endpoint = ""
gpu_device_enabled = "true"
gpu_device_action = "default"
gpu_device_paths = ""
EOF
    # Tetragon module substrate config the apply.sh reads to discover
    # the policy_dir. Point it at our tmpdir.
    export SELFDEF_TETRAGON_CONFIG="${TEST_DIR}/tetragon.toml"
    cat > "${SELFDEF_TETRAGON_CONFIG}" <<EOF
policy_dir = "${TEST_DIR}/tetragon-policies"
EOF
    mkdir -p "${TEST_DIR}/tetragon-policies"
}

teardown_dry_run() {
    rm -rf "${TEST_DIR}"
    unset SELFDEF_DRY_RUN SELFDEF_AGENT_GUARD_CONFIG SELFDEF_TETRAGON_CONFIG
}

@test "apply.sh runs cleanly in dry-run mode (audit profile)" {
    setup_dry_run
    run bash "${INSTALL_DIR}/apply.sh"
    teardown_dry_run
    [ "${status}" -eq 0 ]
}

@test "apply.sh dry-run is idempotent (two runs both succeed)" {
    setup_dry_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    run bash "${INSTALL_DIR}/apply.sh"
    teardown_dry_run
    [ "${status}" -eq 0 ]
}

@test "apply.sh rejects malformed profile" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_DRY_RUN=1
    export SELFDEF_AGENT_GUARD_CONFIG="${TEST_DIR}/agent-guard.toml"
    echo 'profile = "bogus"' > "${SELFDEF_AGENT_GUARD_CONFIG}"
    run bash "${INSTALL_DIR}/apply.sh"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_DRY_RUN SELFDEF_AGENT_GUARD_CONFIG
    [ "${status}" -ne 0 ]
}

@test "INVARIANT (apply.sh + check.sh + uninstall.sh use set -euo pipefail — fail-loud invariant)" {
    # Sister to brain-wide fail-loud-set-euo-pipefail INVARIANTs.
    # agent-guard is the Tetragon-based AI-runtime safety
    # substrate (MS017 — runtime guard layer for LLM tool calls);
    # silent install/uninstall failure would leave the kernel-
    # attestation policies in half-loaded state — partial AI-
    # safety enforcement is worse than none (operator believes
    # they have full coverage when they don't).
    grep -qE 'set -euo pipefail' "${INSTALL_DIR}/apply.sh"
    grep -qE 'set -euo pipefail' "${INSTALL_DIR}/check.sh"
    grep -qE 'set -euo pipefail' "${INSTALL_DIR}/uninstall.sh"
}

@test "INVARIANT (every shipped policy declares apiVersion: cilium.io/v1alpha1 — Tetragon CRD apiVersion contract)" {
    # Sister to brain-wide Tetragon CRD apiVersion/kind/
    # metadata.name INVARIANTs. The Tetragon CRD requires
    # apiVersion: cilium.io/v1alpha1 (the Cilium-Tetragon
    # TracingPolicy CRD shape). Without apiVersion, kubectl
    # apply -f silently rejects the manifest as an unknown
    # CRD — partial policy load + half-enforced runtime guard.
    # Cousin to kind:TracingPolicy + metadata.name already
    # locked. Locks apiVersion axis on the MS017 AI-runtime
    # guard Tetragon-policy substrate.
    POLICY_DIR="${BATS_TEST_DIRNAME}/../../modules/agent-guard/policies"
    for f in "${POLICY_DIR}"/*.yaml; do
        grep -qE '^apiVersion:[[:space:]]+cilium\.io/v1alpha1' "${f}"
    done
}

@test "INVARIANT (every shipped policy file has chmod 0644 — Tetragon CRD readable contract)" {
    # Sister to brain-wide file-mode 0644 INVARIANTs across L2
    # policy/config surfaces. Tetragon-policy YAML files MUST be
    # mode 0644 (world-readable + root-write-only) because the
    # Tetragon agent reads the policies AS its configured user
    # (often non-root in some deployments via DynamicUser) AND
    # the policies are non-secret kernel-attestation rules.
    # Mode 0600 would defeat policy loading on non-root
    # Tetragon deployments; mode 0666 (group-writable) would
    # permit silent tamper of kernel-attestation rules. Locks
    # file-mode contract on the MS017 AI-runtime guard policy
    # substrate.
    POLICY_DIR="${BATS_TEST_DIRNAME}/../../modules/agent-guard/policies"
    for f in "${POLICY_DIR}"/*.yaml; do
        mode="$(stat -c '%a' "${f}")"
        [ "${mode}" = "644" ] || [ "${mode}" = "640" ]
    done
}
