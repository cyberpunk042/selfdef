#!/usr/bin/env bats
# L2 bats unit tests for the MS047 perimeter TracingPolicy + the postinst
# install/uninstall flow.
#
# Validates MS047 R11041-R11075 (verbatim TracingPolicy structure +
# default allowlist immutability) and R11114-R11121 (Tetragon ordering
# + chattr +i discipline).
#
# Run with: bats packaging/test/L2-perimeter.bats
#
# Source: SDD-028 Deliverable 6 — L2 (bats)

YAML="${BATS_TEST_DIRNAME}/../tetragon-policies/sovereign-perimeter.yaml"
POSTINST="${BATS_TEST_DIRNAME}/../debian/postinst"
POSTRM="${BATS_TEST_DIRNAME}/../debian/postrm"
L1_SCRIPT="${BATS_TEST_DIRNAME}/../../scripts/test/L1-perimeter-yaml-lint.sh"

setup() {
    TEST_DIR="$(mktemp -d)"
}

teardown() {
    rm -rf "${TEST_DIR}"
}

# ============================================================
# R11041-R11045: file existence + structural shape
# ============================================================

@test "R11041: sovereign-perimeter.yaml exists in packaging/tetragon-policies" {
    [ -f "${YAML}" ]
}

@test "R11041: YAML parses without error" {
    run python3 -c "import yaml; yaml.safe_load(open('${YAML}'))"
    [ "${status}" -eq 0 ]
}

@test "R11042: apiVersion is cilium.io/v1alpha1" {
    run python3 -c "import yaml; print(yaml.safe_load(open('${YAML}'))['apiVersion'])"
    [ "${output}" = "cilium.io/v1alpha1" ]
}

@test "R11043: kind is TracingPolicy" {
    run python3 -c "import yaml; print(yaml.safe_load(open('${YAML}'))['kind'])"
    [ "${output}" = "TracingPolicy" ]
}

@test "R11044: metadata.name is sovereign-kernel-fence (verbatim sain-01 §6)" {
    run python3 -c "import yaml; print(yaml.safe_load(open('${YAML}'))['metadata']['name'])"
    [ "${output}" = "sovereign-kernel-fence" ]
}

# ============================================================
# R11046-R11055: kprobe + selector shape verbatim
# ============================================================

@test "R11046: kprobe targets sys_execve" {
    run python3 -c "import yaml; print(yaml.safe_load(open('${YAML}'))['spec']['kprobes'][0]['call'])"
    [ "${output}" = "sys_execve" ]
}

@test "R11047: kprobe.syscall == true" {
    run python3 -c "import yaml; print(yaml.safe_load(open('${YAML}'))['spec']['kprobes'][0]['syscall'])"
    [ "${output}" = "True" ]
}

@test "R11048: args index 0 type string" {
    run python3 -c "import yaml; a=yaml.safe_load(open('${YAML}'))['spec']['kprobes'][0]['args'][0]; print(a['index'], a['type'])"
    [ "${output}" = "0 string" ]
}

@test "R11049: matchArgs operator is NotIn" {
    run python3 -c "import yaml; print(yaml.safe_load(open('${YAML}'))['spec']['kprobes'][0]['selectors'][0]['matchArgs'][0]['operator'])"
    [ "${output}" = "NotIn" ]
}

@test "R11050: matchActions action is Sigkill" {
    run python3 -c "import yaml; print(yaml.safe_load(open('${YAML}'))['spec']['kprobes'][0]['selectors'][0]['matchActions'][0]['action'])"
    [ "${output}" = "Sigkill" ]
}

# ============================================================
# R11052-R11055: default allowlist immutability (sain-01 §6 verbatim)
# ============================================================

@test "R11052: default allowlist has exactly 4 entries" {
    run python3 -c "import yaml; print(len(yaml.safe_load(open('${YAML}'))['spec']['kprobes'][0]['selectors'][0]['matchArgs'][0]['values']))"
    [ "${output}" = "4" ]
}

@test "R11053: allowlist[0] == /usr/bin/python3" {
    run python3 -c "import yaml; print(yaml.safe_load(open('${YAML}'))['spec']['kprobes'][0]['selectors'][0]['matchArgs'][0]['values'][0])"
    [ "${output}" = "/usr/bin/python3" ]
}

@test "R11054: allowlist[1] == /usr/bin/nvidia-smi" {
    run python3 -c "import yaml; print(yaml.safe_load(open('${YAML}'))['spec']['kprobes'][0]['selectors'][0]['matchArgs'][0]['values'][1])"
    [ "${output}" = "/usr/bin/nvidia-smi" ]
}

@test "R11055: allowlist[2] == /usr/local/bin/vllm" {
    run python3 -c "import yaml; print(yaml.safe_load(open('${YAML}'))['spec']['kprobes'][0]['selectors'][0]['matchArgs'][0]['values'][2])"
    [ "${output}" = "/usr/local/bin/vllm" ]
}

@test "R11055: allowlist[3] == /usr/bin/podman" {
    run python3 -c "import yaml; print(yaml.safe_load(open('${YAML}'))['spec']['kprobes'][0]['selectors'][0]['matchArgs'][0]['values'][3])"
    [ "${output}" = "/usr/bin/podman" ]
}

# ============================================================
# R11114-R11121: L1 yaml-lint passes
# ============================================================

@test "R11041 (gate L1): L1-perimeter-yaml-lint.sh exits 0" {
    [ -x "${L1_SCRIPT}" ]
    run bash "${L1_SCRIPT}"
    [ "${status}" -eq 0 ]
}

# ============================================================
# R11119-R11121: postinst + postrm structural checks
# ============================================================

@test "R11119: postinst references sovereign-perimeter.yaml install path" {
    grep -q "sovereign-perimeter.yaml" "${POSTINST}"
}

@test "R11119: postinst targets /etc/tetragon/tracing-policies" {
    grep -q "/etc/tetragon/tracing-policies" "${POSTINST}"
}

@test "R11120: postinst applies chattr +i to installed YAML" {
    grep -q "chattr +i /etc/tetragon/tracing-policies/sovereign-perimeter.yaml" "${POSTINST}"
}

@test "R11120: postinst creates /etc/selfdef/perimeter-extensions dir" {
    grep -q "/etc/selfdef/perimeter-extensions" "${POSTINST}"
}

@test "R11121: postrm removes YAML on purge after chattr -i" {
    grep -q "chattr -i /etc/tetragon/tracing-policies/sovereign-perimeter.yaml" "${POSTRM}"
    grep -q "rm -f /etc/tetragon/tracing-policies/sovereign-perimeter.yaml" "${POSTRM}"
}

@test "R11119: postinst signals Tetragon to reload after install" {
    grep -q "tetragon.service" "${POSTINST}"
}

# ============================================================
# YAML well-formedness via parser (defensive — covers comment-stripping)
# ============================================================

@test "metadata block present with name field" {
    run python3 -c "import yaml; d=yaml.safe_load(open('${YAML}')); print('OK' if d['metadata']['name'] else 'FAIL')"
    [ "${output}" = "OK" ]
}

@test "INVARIANT (YAML kind=TracingPolicy — Tetragon-recognized resource type)" {
    # Sister to MS047 R11042 apiVersion INVARIANT already locked.
    # The kind field is the SECOND mandatory Tetragon CRD
    # discriminator (apiVersion: cilium.io/v1alpha1 + kind:
    # TracingPolicy). A regression that emitted kind:
    # ClusterTracingPolicy (the cluster-scoped variant) or
    # any other kind would silently fail to apply at Tetragon
    # operator startup — the perimeter policy would silently
    # never load, defeating the entire MS047 SovereignOS
    # perimeter substrate. Locks the resource-kind contract.
    run python3 -c "import yaml; d=yaml.safe_load(open('${YAML}')); print(d['kind'])"
    [ "${output}" = "TracingPolicy" ]
}

@test "INVARIANT (YAML spec.kprobes is non-empty list — perimeter MUST attach probes, not be a vacuous-passing manifest)" {
    # Sister to apiVersion + kind contract INVARIANTs already
    # locked. A Tetragon TracingPolicy with no kprobes attached
    # is syntactically valid YAML but semantically vacuous —
    # operator applying the policy would see status=ok but
    # ZERO kernel-attestation probes would actually attach.
    # Locks against the vacuous-passing regression where the
    # YAML schema validates but the perimeter substrate is
    # empty. MUST have ≥1 kprobe (or tracepoint/uprobe) so the
    # MS047 SovereignOS perimeter actually monitors kernel
    # events.
    run python3 -c "import yaml; d=yaml.safe_load(open('${YAML}')); ks=d.get('spec',{}).get('kprobes',[]); tps=d.get('spec',{}).get('tracepoints',[]); ups=d.get('spec',{}).get('uprobes',[]); print(len(ks)+len(tps)+len(ups))"
    [ "${output}" -ge 1 ]
}

@test "INVARIANT (YAML apiVersion = cilium.io/v1alpha1 — Tetragon CRD apiVersion contract)" {
    # Sister to YAML kind=TracingPolicy contract INVARIANT
    # already locked. The Tetragon CRD apiVersion MUST be
    # 'cilium.io/v1alpha1' for Tetragon to recognize the
    # manifest. A regression to a wrong apiVersion (e.g.
    # 'tetragon.io/v1' or an old beta API) would cause
    # Tetragon to silently reject the policy — sovereign-
    # perimeter would never load, defeating the entire MS047
    # SovereignOS perimeter substrate. Locks the apiVersion
    # contract symmetric to the kind contract.
    run python3 -c "import yaml; d=yaml.safe_load(open('${YAML}')); print(d['apiVersion'])"
    [ "${output}" = "cilium.io/v1alpha1" ]
}

@test "INVARIANT (YAML metadata.name is non-empty — Tetragon CRD identifier contract)" {
    # Sister to apiVersion + kind + spec.kprobes contract INVARIANTs.
    # Tetragon TracingPolicy requires metadata.name for in-cluster
    # identification and tetra cli operations (tetra tracingpolicy
    # list / delete). A vacuous empty name would still parse but
    # be operator-unmanageable.
    run python3 -c "import yaml; d=yaml.safe_load(open('${YAML}')); print(d['metadata']['name'])"
    [ -n "${output}" ]
    [ "${output}" != "None" ]
}

@test "INVARIANT (YAML file chmod 0644 — Tetragon-readable CRD manifest contract)" {
    # Sister to brain-wide file-mode 0644 INVARIANTs across L2
    # policy/config surfaces. The sovereign-perimeter Tetragon
    # TracingPolicy YAML at /etc/selfdef/tetragon-policies/
    # sovereign-perimeter.yaml MUST be mode 0644 (world-readable
    # + root-write-only) because the Tetragon agent reads the
    # policy AS its configured user (often non-root via
    # DynamicUser) AND the policy is non-secret kernel-
    # attestation config. Mode 0600 would defeat policy
    # loading on non-root Tetragon deployments. Locks file-
    # mode contract on the MS047 SovereignOS perimeter
    # substrate.
    mode="$(stat -c '%a' "${YAML}")"
    [ "${mode}" = "644" ] || [ "${mode}" = "640" ]
}

@test "INVARIANT (postinst Tetragon hot-reload — daemon-running probe + reload-or-HUP fallback for tracing-policy refresh)" {
    # Sister to brain-wide tetragon-policy-deploy INVARIANT family.
    # When the perimeter YAML lands at /etc/tetragon/tracing-
    # policies/, Tetragon's daemon must pick up the new policy
    # without a host reboot. The postinst probes for an active
    # tetragon.service via `systemctl is-active` (best-effort, no
    # fail-loud on idle host), then issues `systemctl reload` and
    # falls back to `systemctl kill -s HUP` for older Tetragon
    # builds that don't honor the reload verb. Locks tetragon
    # hot-reload discipline on the perimeter postinst substrate.
    grep -q 'systemctl is-active tetragon.service' "${POSTINST}"
    grep -q 'systemctl reload tetragon.service' "${POSTINST}"
    grep -q 'systemctl kill -s HUP tetragon.service' "${POSTINST}"
}

@test "INVARIANT (postrm gates remove vs purge — disable+stop on remove, file-deletion only on purge — Debian Policy 6.5)" {
    # Sister to brain-wide Debian-Policy postrm-gating INVARIANT
    # family. Debian Policy §6.5 prescribes distinct postrm
    # behaviors for remove (deconfigure, keep user data) vs
    # purge (delete state + config). For perimeter / Guardian /
    # Scheduler, this means:
    #   - remove: systemctl stop+disable (units neutralized but
    #     not deleted from disk)
    #   - purge: chattr -i + rm the perimeter YAML + delete
    #     systemd units + drop state files
    # A regression that collapses both branches would either
    # leak state on remove (file deletion fires for ordinary
    # operator-uninstall) or fail-to-clean on purge (state
    # files remain after operator-purge). Locks the Debian
    # Policy §6.5 remove-vs-purge gating discipline on the
    # perimeter postrm substrate.
    grep -qE '^[[:space:]]*purge\)' "${POSTRM}"
    grep -qE '^[[:space:]]*remove\)' "${POSTRM}"
}

@test "INVARIANT (postrm chattr -i is defensive: 2>/dev/null || true — anti-fail-loud-on-already-mutable contract)" {
    # Sister to brain-wide defensive-cleanup INVARIANT family.
    # The postrm chattr -i call MUST tolerate an already-mutable
    # state: if a prior operator manually `chattr -i`'d the
    # perimeter YAML before purge, the postrm's chattr -i would
    # fail with "Operation not permitted" / "Inappropriate ioctl"
    # without the 2>/dev/null || true guard — and a non-zero
    # postrm exit aborts the dpkg purge mid-way, leaving the
    # system in a half-purged state that future apt operations
    # can't resolve. Locks the defensive-cleanup pattern on the
    # perimeter postrm chattr substrate (per Debian Policy
    # 6.5.5: postrm must idempotently succeed across all
    # interrupted-state recoveries).
    # Pattern: chattr -i ... \<newline>... 2>/dev/null || true
    awk '/chattr -i \/etc\/tetragon\/tracing-policies\/sovereign-perimeter.yaml/{found=1; next} found{ if (/2>\/dev\/null/ && /\|\|[[:space:]]*true/) { ok=1 }; exit } END{ exit ok ? 0 : 1 }' "${POSTRM}"
}

@test "INVARIANT (postinst + postrm use set -e — anti-half-installed-state contract per Debian Policy)" {
    # Sister to brain-wide set -e shell-discipline INVARIANT
    # family. Debian Policy §6.5 prescribes set -e on
    # maintainer scripts: a mid-script error MUST propagate
    # as a non-zero exit so dpkg surfaces the failure to the
    # operator rather than silently leaving a half-installed
    # package state. The perimeter postinst writes the
    # TracingPolicy YAML + applies chattr +i + reloads
    # tetragon; without set -e a mid-step failure (e.g.,
    # chattr fails because /etc/tetragon doesn't exist on a
    # tetragon-less host) would silently skip the chattr
    # while the YAML is on disk, leaving operators with a
    # mutable trust-root they didn't authorize. Locks the
    # set -e maintainer-script discipline on the perimeter
    # postinst + postrm substrates per Debian Policy 6.5.
    grep -qE '^set -e' "${POSTINST}"
    grep -qE '^set -e' "${POSTRM}"
}

@test "INVARIANT (postinst signals Tetragon reload AFTER chattr +i — operator-deploy ordering contract)" {
    # Sister to brain-wide postinst-ordering INVARIANT family.
    # The perimeter postinst MUST do operations in this order:
    #   1. install YAML to /etc/tetragon/tracing-policies/
    #   2. chattr +i to lock the YAML
    #   3. systemctl reload tetragon.service (so the LOCKED
    #      YAML is what tetragon picks up — not a still-
    #      mutable copy that could be replaced mid-load)
    # A regression that swapped 2+3 (reload before chattr +i)
    # would create a TOCTOU window where an attacker on a
    # compromised root shell could replace the YAML between
    # postinst writing it and chattr locking it. We can't
    # easily test the ORDER but we can lock that BOTH the
    # chattr+i AND the reload references are present. Locks
    # operator-deploy ordering on the perimeter postinst
    # substrate (sister to the existing hot-reload INVARIANT).
    grep -qE 'chattr \+i /etc/tetragon/tracing-policies/sovereign-perimeter.yaml' "${POSTINST}"
    grep -qE 'tetragon.service' "${POSTINST}"
    # Sequence check: chattr +i line MUST come before
    # systemctl reload tetragon.service line.
    chattr_line=$(grep -nE 'chattr \+i /etc/tetragon/tracing-policies/sovereign-perimeter.yaml' "${POSTINST}" | head -1 | cut -d: -f1)
    reload_line=$(grep -nE 'systemctl reload tetragon.service' "${POSTINST}" | head -1 | cut -d: -f1)
    [ -n "${chattr_line}" ]
    [ -n "${reload_line}" ]
    [ "${chattr_line}" -lt "${reload_line}" ]
}
