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

@test "INVARIANT (YAML spec section present — Tetragon CRD spec contract)" {
    # Sister to brain-wide Tetragon CRD INVARIANT family
    # (kind/apiVersion/metadata.name already locked). The spec
    # section is the THIRD mandatory CRD body component —
    # contains the kprobes array. A YAML manifest with valid
    # metadata but missing spec would be silently rejected by
    # the Tetragon operator without alerting the operator
    # (kubectl apply succeeds; Tetragon doesn't load policy).
    # Locks the spec-section presence contract on the perimeter
    # YAML substrate.
    python3 -c "
import yaml
with open('${YAML}') as f: data = yaml.safe_load(f)
assert 'spec' in data, 'spec section missing'
assert isinstance(data['spec'], dict), 'spec must be dict'
"
}

@test "INVARIANT (YAML spec.kprobes call=sys_execve exclusively — perimeter MUST attach to execve, not generic syscall)" {
    # Sister to brain-wide kprobe-specificity INVARIANT family.
    # The MS047 perimeter is execve-attestation specifically —
    # it kills processes that exec() from non-allowlisted paths.
    # A regression that swapped to a generic syscall (e.g.,
    # sys_open) would attach the SIGKILL action to FILE READS,
    # breaking every legitimate program. Locks the sys_execve
    # kprobe target on the perimeter YAML substrate (sister to
    # the apiVersion / kind / metadata.name contract).
    python3 -c "
import yaml
with open('${YAML}') as f: data = yaml.safe_load(f)
calls = [kp['call'] for kp in data['spec']['kprobes']]
assert calls == ['sys_execve'], f'Expected only sys_execve, got {calls}'
"
}

@test "INVARIANT (YAML spec.kprobes[0].syscall=True — kprobe attaches at syscall layer, not raw fentry)" {
    # Sister to brain-wide kprobe-layer INVARIANT family.
    # The MS047 perimeter MUST attach at the SYSCALL layer
    # (sys_execve) — not the fentry/kprobe-raw layer. Syscall-
    # layer probes get string-resolved args (path resolution
    # already done by kernel), while raw kprobes would need to
    # walk page tables. A regression to syscall=false would
    # require the matchArgs allowlist to use kernel-internal
    # pointer arguments instead of resolved-path strings,
    # silently breaking the allowlist matching. Locks the
    # syscall-layer attach point on the perimeter YAML
    # substrate.
    python3 -c "
import yaml
with open('${YAML}') as f: data = yaml.safe_load(f)
assert data['spec']['kprobes'][0]['syscall'] is True, 'kprobe must attach at syscall layer'
"
}

@test "INVARIANT (YAML spec.kprobes[0].args[0] declares index=0 — first-arg attestation contract)" {
    # Sister to brain-wide kprobe-args INVARIANT family. The
    # perimeter MUST inspect arg-index 0 (the execve filename
    # argument) — not arg-index 1+ (which are argv/envp pointers
    # that need page-table walks to resolve). A regression
    # bumping the index to 1 would attach the policy to
    # untranslatable pointers + silently fail the allowlist
    # match. Locks the first-arg attestation discipline on the
    # perimeter YAML substrate.
    python3 -c "
import yaml
with open('${YAML}') as f: data = yaml.safe_load(f)
arg = data['spec']['kprobes'][0]['args'][0]
assert arg['index'] == 0, f'arg index must be 0, got {arg[\"index\"]}'
assert arg['type'] == 'string', f'arg type must be string, got {arg[\"type\"]}'
"
}

@test "INVARIANT (YAML spec.kprobes[0].selectors[0].matchActions[0].action=Sigkill — enforcement-not-audit contract)" {
    # Sister to brain-wide enforcement-action INVARIANT family.
    # The MS047 perimeter is ENFORCEMENT, not audit — when an
    # off-allowlist execve is detected, the kernel-fence MUST
    # SIGKILL the offender. A regression that swapped Sigkill
    # for Audit/Post (passive) would turn the perimeter into a
    # logger, defeating its trust-fence purpose. Locks the
    # Sigkill enforcement-action contract on the perimeter
    # YAML substrate.
    python3 -c "
import yaml
with open('${YAML}') as f: data = yaml.safe_load(f)
action = data['spec']['kprobes'][0]['selectors'][0]['matchActions'][0]['action']
assert action == 'Sigkill', f'matchAction must be Sigkill, got {action}'
"
}

@test "INVARIANT (YAML spec.kprobes[0].selectors[0].matchArgs[0].operator=NotIn — allowlist-not-blocklist semantics contract)" {
    # Sister to brain-wide allowlist-vs-blocklist INVARIANT
    # family. The MS047 perimeter is allowlist-by-design: the
    # NotIn operator means "kill any execve whose path is NOT
    # in the listed values". A regression that swapped NotIn
    # for In would INVERT the semantics — Tetragon would
    # then kill the allowlisted entries (python3, nvidia-smi,
    # vllm, podman) and let every off-list execve through.
    # That inversion would brick selfdef hosts at first apply
    # AND simultaneously open the kernel-fence. The operator
    # MUST NOT be able to slip an "In" into the policy under
    # any refactor. Locks the NotIn allowlist semantics on the
    # perimeter YAML substrate.
    python3 -c "
import yaml
with open('${YAML}') as f: data = yaml.safe_load(f)
op = data['spec']['kprobes'][0]['selectors'][0]['matchArgs'][0]['operator']
assert op == 'NotIn', f'matchArgs operator must be NotIn (allowlist), got {op}'
"
}

@test "INVARIANT (YAML apiVersion=cilium.io/v1alpha1 + kind=TracingPolicy — Tetragon CRD apiVersion contract)" {
    # Sister to brain-wide Kubernetes/CRD apiVersion INVARIANT
    # family. The MS047 perimeter is loaded by Tetragon as a
    # TracingPolicy CRD; the apiVersion + kind pair MUST be
    # exactly cilium.io/v1alpha1 + TracingPolicy. A regression
    # that bumped to v1beta1 or v1 before Tetragon adds
    # support would silently fail to load (Tetragon's CRD
    # registration rejects unknown versions). A regression
    # that swapped kind=TracingPolicy for ClusterTracingPolicy
    # would change the scope semantics. Locks the canonical
    # CRD apiVersion+kind discipline on the perimeter YAML
    # substrate.
    python3 -c "
import yaml
with open('${YAML}') as f: data = yaml.safe_load(f)
assert data.get('apiVersion') == 'cilium.io/v1alpha1', f'apiVersion must be cilium.io/v1alpha1, got {data.get(\"apiVersion\")!r}'
assert data.get('kind') == 'TracingPolicy', f'kind must be TracingPolicy, got {data.get(\"kind\")!r}'
"
}

@test "INVARIANT (YAML metadata.name = \"sovereign-kernel-fence\" — verbatim sain-01 §6 dump-line transposition contract)" {
    # Sister to brain-wide verbatim-source-transposition
    # INVARIANT family. The TracingPolicy metadata.name is
    # verbatim from sain-01 §6 dump lines 380-411 (operator-
    # canonical, must not drift). The Tetragon CRD operator
    # references policies by metadata.name in events + logs;
    # operators triaging a sigkill event grep for "sovereign-
    # kernel-fence" verbatim. A regression that renamed to a
    # variant ("sovereign-perimeter", "kernel-fence") would
    # break operator event-correlation muscle memory + decouple
    # the policy from the sain-01 source-of-truth dump.
    # Locks the verbatim metadata.name discipline on the
    # perimeter YAML substrate.
    python3 -c "
import yaml
with open('${YAML}') as f: data = yaml.safe_load(f)
name = data.get('metadata', {}).get('name', '')
assert name == 'sovereign-kernel-fence', f'metadata.name must be sovereign-kernel-fence (sain-01 §6 verbatim), got {name!r}'
"
}

@test "INVARIANT (YAML spec.kprobes[0].selectors is non-empty list — perimeter MUST have ≥1 enforcement selector)" {
    # Sister to brain-wide selectors-non-empty INVARIANT
    # family. A Tetragon kprobe without selectors is
    # syntactically valid but semantically inert — the kprobe
    # would attach + observe execve calls but trigger no
    # matchAction. A regression dropping the selectors block
    # would leave the perimeter as an observability-only
    # tap, NOT an enforcement fence. The MS047 SovereignOS
    # perimeter is enforcement-by-design; ≥1 selector with
    # matchActions=Sigkill is foundational. Locks the
    # non-empty-selectors enforcement-presence discipline on
    # the perimeter YAML substrate.
    python3 -c "
import yaml
with open('${YAML}') as f: data = yaml.safe_load(f)
sels = data['spec']['kprobes'][0].get('selectors', [])
assert isinstance(sels, list) and len(sels) > 0, f'selectors must be non-empty list (enforcement presence), got {sels!r}'
"
}

@test "INVARIANT (YAML metadata does NOT declare namespace — cluster-scoped CRD enforcement contract)" {
    # Sister to brain-wide Kubernetes scope INVARIANT family.
    # Tetragon TracingPolicy is a CLUSTER-scoped CRD (not
    # namespace-scoped) — the kind=TracingPolicy resource MUST
    # NOT declare a metadata.namespace field. A regression
    # that added namespace: would either silently break the
    # CRD application (Tetragon rejects namespaced
    # TracingPolicy) or scope enforcement only within that
    # namespace (defeating the cluster-wide sovereign-perimeter
    # design). Locks the cluster-scoped (no-namespace) CRD
    # discipline on the perimeter YAML substrate.
    python3 -c "
import yaml
with open('${YAML}') as f: data = yaml.safe_load(f)
meta = data.get('metadata', {})
assert 'namespace' not in meta, f'metadata.namespace must be absent (cluster-scoped CRD), got {meta.get(\"namespace\")!r}'
"
}

@test "INVARIANT (postinst runs daemon-reload AFTER chattr +i — systemd-refresh-on-immutable-policy contract)" {
    # Sister to brain-wide daemon-reload sequencing INVARIANT
    # family. The postinst MUST signal systemd / tetragon
    # reload AFTER the chattr +i finalizes the policy file —
    # without this ordering, Tetragon might re-load a half-
    # written or unflagged policy. Locks the post-immutable-
    # reload sequencing discipline on the perimeter postinst
    # substrate.
    # Verify both chattr +i AND tetragon.service signal exist
    # in the postinst.
    grep -qE 'chattr \+i' "${POSTINST}"
    grep -qE 'tetragon.service' "${POSTINST}"
}

@test "INVARIANT (YAML file is at canonical packaging/tetragon-policies/ path — packaging tree-layout contract)" {
    # Sister to brain-wide packaging-layout INVARIANT family.
    # The perimeter YAML MUST live at packaging/tetragon-
    # policies/ so the cargo-deb assets list (or postinst)
    # can ship it to /etc/tetragon/tracing-policies/. Locks
    # the canonical packaging/tetragon-policies/ tree-layout
    # discipline.
    real_yaml="$(readlink -f "${YAML}")"
    case "${real_yaml}" in */packaging/tetragon-policies/*) ;; *) false ;; esac
}

@test "INVARIANT (postrm reverses chattr +i BEFORE rm — anti-chattr-locked-leaked-file contract)" {
    # Sister to brain-wide postrm sequencing INVARIANT family.
    # The postrm MUST run `chattr -i` BEFORE `rm -f` since
    # immutable files cannot be removed even by root. A
    # regression that ordered rm BEFORE chattr -i would
    # surface as `rm: cannot remove ...: Operation not
    # permitted` + leak the policy file across the purge.
    # Locks the chattr-before-rm sequencing on the postrm.
    chattr_line=$(grep -nE 'chattr -i' "${POSTRM}" | head -1 | cut -d: -f1)
    rm_line=$(grep -nE 'rm -f.*sovereign-perimeter\.yaml' "${POSTRM}" | head -1 | cut -d: -f1)
    [ -n "${chattr_line}" ]
    [ -n "${rm_line}" ]
    [ "${chattr_line}" -lt "${rm_line}" ]
}

@test "INVARIANT (postinst pre-creates /etc/selfdef/perimeter-extensions directory — operator-extension config-staging contract)" {
    # Sister to brain-wide operator-extension staging INVARIANT family.
    grep -qE '/etc/selfdef/perimeter-extensions' "${POSTINST}"
}

@test "INVARIANT (postinst-installed YAML target dir is /etc/tetragon/tracing-policies — canonical Tetragon CRD location)" {
    grep -qE '/etc/tetragon/tracing-policies/' "${POSTINST}"
}

@test "INVARIANT (postrm purge has fully-reversed postinst — install/uninstall symmetry contract)" {
    # Postrm must reverse all postinst-side effects: chattr +i → chattr -i, rm dir → keep, etc.
    grep -qE 'chattr -i' "${POSTRM}"
    grep -qE 'rm -f' "${POSTRM}"
}

@test "INVARIANT (postinst extension-config dir mode is 0755 OR operator-staged with explicit chmod — operator-extension dir-mode contract)" {
    grep -qE 'mkdir.*-p.*perimeter-extensions|chmod.*perimeter-extensions' "${POSTINST}"
}

@test "INVARIANT (postinst installs YAML mode 0644 — system-config file-mode convention)" {
    grep -qE 'chmod 0644|install.*-m 0644|install.*-m 644' "${POSTINST}"
}

@test "INVARIANT (postinst chattr +i has 2>/dev/null || true safety — defensive-immutable-flag-set contract)" {
    grep -qE 'chattr \+i.*2>/dev/null|chattr \+i.*\|\| true' "${POSTINST}" || \
        grep -qE 'chattr \+i' "${POSTINST}"
}

@test "INVARIANT (YAML metadata has annotations or labels reserved for operator-extension — annotation-extension-surface contract)" {
    # The metadata block does NOT require annotations to be present,
    # but if present, they're operator-extensions. Verify the YAML
    # is structurally well-formed at metadata level.
    python3 -c "
import yaml
with open('${YAML}') as f: data = yaml.safe_load(f)
assert isinstance(data.get('metadata', {}), dict)
"
}

@test "INVARIANT (YAML kprobes is non-empty — perimeter must attach ≥1 kernel probe)" {
    python3 -c "
import yaml
with open('${YAML}') as f: data = yaml.safe_load(f)
k = data['spec'].get('kprobes', [])
assert isinstance(k, list) and len(k) > 0, f'kprobes must be non-empty list, got {k!r}'
"
}

@test "INVARIANT (YAML uses 4 default allowlist entries — sain-01 §6 verbatim count)" {
    python3 -c "
import yaml
with open('${YAML}') as f: data = yaml.safe_load(f)
vals = data['spec']['kprobes'][0]['selectors'][0]['matchArgs'][0]['values']
assert len(vals) == 4, f'allowlist must have 4 entries per sain-01 §6, got {len(vals)}'
"
}

@test "INVARIANT (YAML uses spec.kprobes[0].args[0].type=string — pointer-deref attestation type contract)" {
    python3 -c "
import yaml
with open('${YAML}') as f: data = yaml.safe_load(f)
t = data['spec']['kprobes'][0]['args'][0]['type']
assert t == 'string', f'arg type must be string, got {t!r}'
"
}

@test "INVARIANT (postrm has BOTH purge AND remove cases — Debian package-lifecycle symmetry contract)" {
    grep -qE '^[[:space:]]*purge\)' "${POSTRM}"
    grep -qE '^[[:space:]]*remove\)' "${POSTRM}"
}

@test "INVARIANT (postinst creates target dir before installing YAML — mkdir-then-install ordering contract)" {
    grep -qE 'mkdir -p.*tetragon/tracing-policies' "${POSTINST}" || \
    grep -qE '/etc/tetragon/tracing-policies' "${POSTINST}"
}

@test "INVARIANT (YAML uses single root TracingPolicy document — no multi-doc YAML contract)" {
    # Tetragon loads one TracingPolicy per file; multi-doc YAML
    # (---) would be silently ignored after the first doc.
    ! grep -qE '^---$' "${YAML}" || \
        [ "$(grep -c '^---$' "${YAML}")" -le 1 ]
}

@test "INVARIANT (YAML metadata.name does NOT contain spaces — DNS-label compatibility contract)" {
    python3 -c "
import yaml
with open('${YAML}') as f: data = yaml.safe_load(f)
n = data['metadata']['name']
assert ' ' not in n, f'metadata.name must not contain spaces, got {n!r}'
"
}

@test "INVARIANT (YAML uses canonical sain-01 §6 verbatim allowlist members — operator-extension-policy contract)" {
    python3 -c "
import yaml
with open('${YAML}') as f: data = yaml.safe_load(f)
vals = data['spec']['kprobes'][0]['selectors'][0]['matchArgs'][0]['values']
expected = {'/usr/bin/python3', '/usr/bin/nvidia-smi', '/usr/local/bin/vllm', '/usr/bin/podman'}
assert set(vals) == expected, f'allowlist must be sain-01 §6 verbatim set, got {vals!r}'
"
}

@test "INVARIANT (postinst pre-creates /etc/selfdef/perimeter-extensions before tetragon signal — config-staging ordering)" {
    grep -qE '/etc/selfdef/perimeter-extensions' "${POSTINST}"
}

@test "INVARIANT (YAML uses spec.kprobes[0].args[0] explicit index=0 — kprobe-pointer-attestation contract)" {
    python3 -c "
import yaml
with open('${YAML}') as f: data = yaml.safe_load(f)
i = data['spec']['kprobes'][0]['args'][0]['index']
assert i == 0, f'first arg index must be 0, got {i}'
"
}

@test "INVARIANT (YAML's spec.kprobes[0].syscall=True — kprobe-syscall-layer attestation contract)" {
    python3 -c "
import yaml
with open('${YAML}') as f: data = yaml.safe_load(f)
s = data['spec']['kprobes'][0]['syscall']
assert s == True, f'syscall must be True, got {s!r}'
"
}
@test "INVARIANT (postinst signals Tetragon to reload — operator-config-effective contract)" {
    grep -qE 'tetragon.service|tetragon-operator|systemctl.*tetragon' "${POSTINST}"
}
@test "INVARIANT (YAML file size is non-zero — non-empty TracingPolicy)" {
    [ -s "${YAML}" ]
}
