#!/usr/bin/env bats
# L2 functional suite for loopback-only-dns.
#
# loopback-only-dns installs /etc/systemd/resolved.conf.d/
# 50-selfdef-loopback.conf to bind systemd-resolved's DNS-stub
# listener to loopback only (preventing the host from exposing
# a DNS resolver on its public/LAN interfaces — a classic
# off-host DNS-attack vector).
#
# Profiles:
#   loopback           → DNSStubListener=yes + bind to 127.0.0.53
#                        (mainstream secure default — apps using
#                        /etc/resolv.conf still get resolution)
#   disabled-listener  → DNSStubListener=no (no DNS stub at all;
#                        apps must use /run/systemd/resolve/resolv.conf
#                        or a local resolver directly)
#
# Idempotency: drop-in is installed via cmp -s against source so a
# byte-identical re-install does NOT trigger systemctl restart of
# resolved (which would briefly interrupt name resolution).
#
# Run with: bats packaging/test/L2-loopback-only-dns.bats

WD="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/loopback-only-dns.toml"
    DROPIN_DIR="${TMP}/resolved.conf.d"
    DST="${DROPIN_DIR}/50-selfdef-loopback.conf"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_LOOPBACK_DNS_CONFIG="${CONF}" \
    SELFDEF_RESOLVED_DROPIN_DIR="${DROPIN_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_LOOPBACK_DNS_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_LOOPBACK_DNS_CONFIG="${SELFDEF_LOOPBACK_DNS_CONFIG}" \
        SELFDEF_RESOLVED_DROPIN_DIR="${DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_LOOPBACK_DNS_CONFIG="${CONF}" \
        SELFDEF_RESOLVED_DROPIN_DIR="${DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be loopback|disabled-listener"* ]]
}

@test "loopback profile installs drop-in with DNSStubListener=yes + binding to 127.0.0.53" {
    write_config "loopback"
    run_wd
    [ -f "${DST}" ]
    grep -qE '^DNSStubListener=yes' "${DST}"
    grep -q '127.0.0.53' "${DST}"
}

@test "disabled-listener profile installs drop-in with DNSStubListener=no" {
    write_config "disabled-listener"
    run_wd
    [ -f "${DST}" ]
    grep -qE '^DNSStubListener=no' "${DST}"
}

@test "drop-in is chmod 0644 (system-config convention)" {
    write_config "loopback"
    run_wd
    [ "$(stat -c '%a' "${DST}")" = "644" ]
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite drop-in OR restart resolved" {
    write_config "loopback"
    run_wd
    [ -f "${DST}" ]
    mtime_before="$(stat -c '%Y' "${DST}")"
    : > "${SYSEOF_LOG}"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DST}")"
    [ "${mtime_before}" = "${mtime_after}" ]
    # Resolved restart is gated on content-change — no restart on no-op.
    ! grep -q 'restart systemd-resolved' "${SYSEOF_LOG}"
}

@test "INVARIANT: profile switch loopback → disabled-listener REWRITES the drop-in AND restarts resolved" {
    write_config "loopback"
    run_wd
    sha_before="$(sha256sum "${DST}" | awk '{print $1}')"
    : > "${SYSEOF_LOG}"
    write_config "disabled-listener"
    run_wd
    sha_after="$(sha256sum "${DST}" | awk '{print $1}')"
    [ "${sha_before}" != "${sha_after}" ]
    grep -q 'restart systemd-resolved' "${SYSEOF_LOG}"
}

@test "INVARIANT: first install triggers resolved restart (live config picked up)" {
    write_config "loopback"
    run_wd
    grep -q 'restart systemd-resolved' "${SYSEOF_LOG}"
}

@test "INVARIANT: DRY_RUN does not write drop-in or restart resolved" {
    write_config "loopback"
    DRY_RUN=1 run_wd
    ! [ -f "${DST}" ]
    ! grep -q 'restart systemd-resolved' "${SYSEOF_LOG}"
}

@test "default profile is loopback (no profile key — conservative bind-to-127.0.0.53 default)" {
    : > "${CONF}"
    run_wd
    [ -f "${DST}" ]
    grep -qE '^DNSStubListener=yes' "${DST}"
}

@test "emit_status reports changes count (1 on first install, 0 on idempotent re-apply)" {
    write_config "loopback"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'changes=1'* ]]
    # Second apply is a no-op.
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'changes=0'* ]]
}

@test "INVARIANT (profile transition disabled-listener → loopback): reverse direction works" {
    write_config "disabled-listener"
    run_wd
    grep -qE '^DNSStubListener=no' "${DST}"
    write_config "loopback"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -qE '^DNSStubListener=yes' "${DST}"
    grep -q 'restart systemd-resolved' "${SYSEOF_LOG}"
}

@test "INVARIANT (drop-in carries [Resolve] section header — valid systemd-resolved fragment)" {
    write_config "loopback"
    run_wd
    grep -qE '^\[Resolve\]' "${DST}"
}

@test "INVARIANT (loopback profile binds to 127.0.0.53 — the canonical systemd-resolved address)" {
    # If the bind address drifts, apps using /etc/resolv.conf would
    # break OR the host could expose the listener on wider iface.
    write_config "loopback"
    run_wd
    grep -qE '127\.0\.0\.53' "${DST}"
}

@test "INVARIANT (no render-timestamp in drop-in): defeats cmp -s idempotency guard" {
    write_config "loopback"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${DST}"
}

@test "INVARIANT (drop-in does NOT bind to 0.0.0.0 or :: — the off-host-attack vector)" {
    # If the drop-in accidentally specified 0.0.0.0 or :: (any-iface),
    # the host would expose a DNS resolver on its public interface,
    # defeating the whole point of loopback-only.
    write_config "loopback"
    run_wd
    ! grep -qE '0\.0\.0\.0|:::$' "${DST}"
}

@test "INVARIANT (drop-in re-arm after operator out-of-band deletion: re-creates drop-in + fires restart)" {
    write_config "loopback"
    run_wd
    [ -f "${DST}" ]
    rm -f "${DST}"
    : > "${SYSEOF_LOG}"
    run_wd
    [ -f "${DST}" ]
    grep -qE '^DNSStubListener=yes' "${DST}"
    grep -q 'restart systemd-resolved' "${SYSEOF_LOG}"
}

@test "INVARIANT (drop-in carries managed-by header marker — operator audit trail + stale-cleanup)" {
    write_config "loopback"
    run_wd
    grep -qE '^#.*selfdef.*loopback-only-dns|^#.*managed-by' "${DST}"
}

@test "INVARIANT (disabled-listener profile does NOT carry 127.0.0.53 — scope boundary; profiles are mutually-exclusive mechanisms)" {
    # disabled-listener turns OFF the stub listener entirely. Lock
    # that this profile doesn't accidentally also include the
    # loopback bind address (which only makes sense with the
    # listener enabled).
    write_config "disabled-listener"
    run_wd
    grep -qE '^DNSStubListener=no' "${DST}"
    # No DNS= line binding to loopback (only loopback profile sets that).
    ! grep -qE '^DNS=127\.0\.0\.53' "${DST}"
}

@test "INVARIANT (emit_status JSON: status=ok + profile surfaced for operator dashboard)" {
    write_config "loopback"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"loopback-only-dns"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=loopback'* ]]
}

@test "INVARIANT (drop-in filename follows 50-selfdef-*.conf convention — tracking + uninstall identification)" {
    # Sister to many other modules' filename-convention INVARIANT.
    # Lock the 50-selfdef-*.conf prefix so a future filename change
    # is intentional, not silent regression.
    write_config "loopback"
    run_wd
    case "${DST}" in
        */50-selfdef-*.conf) : ;;
        *) fail "drop-in filename must follow 50-selfdef-*.conf pattern" ;;
    esac
}

@test "INVARIANT (header-marker first non-blank line — stale-cleanup head -1 grep predictability)" {
    # Sister to many other modules' header-first-line INVARIANT.
    # The selfdef-identifier MUST appear on the first non-blank
    # line so stale-detection head -1 scans reliably identify
    # selfdef-owned drop-ins.
    write_config "loopback"
    run_wd
    first_nonblank="$(grep -m1 -v '^[[:space:]]*$' "${DST}")"
    [[ "${first_nonblank}" == *"selfdef"* ]] || [[ "${first_nonblank}" == *"managed-by"* ]]
}

@test "INVARIANT (no DNSStubListenerExtra= 0.0.0.0 — alternate widen-bind axis must also stay loopback-bound)" {
    # systemd-resolved supports DNSStubListenerExtra= for additional
    # bind addresses. An attacker (or operator mistake) setting this
    # to 0.0.0.0 would expose the stub on the public interface, just
    # like a direct 0.0.0.0 in the main bind. Lock that the drop-in
    # NEVER carries that directive at all (we don't widen the bind
    # via the alternate axis either).
    write_config "loopback"
    run_wd
    ! grep -qE '^DNSStubListenerExtra=' "${DST}"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # loopback-only-dns TOML; parser must tolerate without
    # altering the profile-gated behavior. loopback-with-noise
    # still installs the DNSStubListener=127.0.0.1 binding (the
    # actual neutralization of the public-stub-attack-surface
    # that DNS rebind / DNS-tunnel / cache-poisoning exploits).
    cat > "${CONF}" <<'TOMLEOF'
profile = "loopback"
operator_note = "loopback-only stub = no public DNS exposure"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    [ -f "${DST}" ]
    grep -qE '^DNSStubListener=yes' "${DST}" || grep -qE 'DNSStubListenerAddress.*127\.0\.0\.1' "${DST}" || grep -qE 'DNSStubListener=127\.0\.0\.1' "${DST}"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-logger
    # INVARIANTs (SDD-062 consumer dispatch contract). One run of
    # the installer must emit EXACTLY ONE emit_status JSON record —
    # not zero (silent run = invisible to operator dashboard) and
    # not multiple (duplicate records corrupt the dashboard's
    # apply-count + last-status invariants).
    write_config "loopback"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"loopback-only-dns"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO drop-in render AND NO systemctl restart fires when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing /etc/systemd/resolved.conf.d/
    # 50-selfdef.conf AND without restarting systemd-resolved.
    # A silent dry-run that committed would re-bind the DNS
    # stub listener on a host under investigation, breaking
    # any host that uses systemd-resolved as DNS-server-for-
    # containers (Docker bridge networks etc). Locks dry-run-
    # preserves-state on the DNS-stub-binding substrate.
    write_config "loopback"
    rm -f "${DST}"
    : > "${SYSEOF_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${DST}" ]
    ! grep -qE 'systemctl (restart|reload) systemd-resolved' "${SYSEOF_LOG}"
}

@test "INVARIANT (baseline observability: changes count surfaces in emit_status — operator dashboard tracks first-install vs idempotent)" {
    # Sister to brain-wide changes-count observability INVARIANTs.
    # First install reports changes=1; idempotent re-apply
    # reports changes=0. Operator dashboard distinguishes the
    # two so audit-trail shows when the drop-in actually got
    # mutated.
    write_config "loopback"
    output_first="$(run_wd 2>&1)"
    [[ "${output_first}" == *'changes=1'* ]]
    output_second="$(run_wd 2>&1)"
    [[ "${output_second}" == *'changes=0'* ]]
}

@test "INVARIANT (no auto-uninstall: loopback-only-dns NEVER emits package-remove commands on systemd-resolved)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The loopback-only-dns installer writes a
    # systemd-resolved drop-in to pin DNSStubListener=0.0.0.0
    # → 127.0.0.1 but MUST NEVER emit shell commands that
    # uninstall systemd-resolved itself (apt/dpkg/dnf/rpm/yum
    # remove|purge|uninstall systemd-resolved). Silent auto-
    # removal would break the DNS resolver substrate entirely.
    # Locks anti-package-removal contract on the loopback-only-
    # dns substrate.
    write_config "loopback"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+systemd-resolved'
    [ ! -f "${DST}" ] || ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${DST}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. loopback-only-dns manifest declares install +
    # profile gating the resolver enforces; malformed manifest
    # wedges the resolved DNSStubListener loopback baseline.
    # Python's tomllib is the canonical parser. Locks anti-
    # malformed-manifest on the loopback-only-dns substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'loopback-only-dns', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: loopback-only-dns installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # loopback-only-dns writes its own drop-in into a system config dir;
    # it MUST NEVER rm/find-delete an operator's pre-existing
    # entries not owned by THIS module. Locks no-auto-delete on
    # the loopback-only-dns installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+/etc/(login\.defs|systemd|update-motd|motd)([[:space:]]|$)' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(login\.defs|systemd|update-motd|motd).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # loopback-only-dns install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the loopback-only-dns lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the loopback-only-dns substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('depends_on', [])
assert isinstance(v, list), f'depends_on must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml conflicts field is a TOML list — anti-string-malformation contract on conflicts)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks list-vs-string discipline on conflicts.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('conflicts', [])
assert isinstance(v, list), f'conflicts must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml provides field is a TOML list — anti-string-malformation contract on provides)" {
    # Sister to brain-wide module.toml manifest-completeness +
    # list-vs-string INVARIANTs. Locks list discipline on
    # provides.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('provides', [])
assert isinstance(v, list), f'provides must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml requires field is a TOML list — anti-string-malformation contract on requires)" {
    # Sister to brain-wide module.toml list-vs-string family.
    # Locks list discipline on requires.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('requires', [])
assert isinstance(v, list), f'requires must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml requires entries are tables with kind + value — anti-flat-string-list contract)" {
    # Sister to brain-wide module.toml requires-shape INVARIANT
    # family. Each requires entry MUST be a TOML inline table
    # `{ kind = "binary", value = "X" }` — not a flat string
    # like "binary:X" (which the resolver would not parse as
    # structured kind/value and would fail to dispatch the
    # check). Locks the kind+value table-shape discipline on
    # the loopback-only-dns requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
reqs = data.get('requires', [])
for r in reqs:
    assert isinstance(r, dict), f'requires entry must be table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'requires entry must have kind+value, got {r}'
"
}

@test "INVARIANT (module.toml summary field present + non-empty — operator-dashboard one-line description contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The summary field is the operator-facing
    # one-line description rendered on the install dashboard.
    # An empty or missing summary would surface as an unlabeled
    # module-row, harming operator triage. Locks the summary-
    # present discipline on the loopback-only-dns substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) > 0, f'summary must be non-empty string, got {repr(s)}'
"
}

@test "INVARIANT (module.toml category field present + non-empty — dashboard-grouping contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The category field groups modules in
    # the operator install dashboard (detection / hardening /
    # disable / etc.). An empty/missing category would surface
    # as an Uncategorized bucket, harming triage. Locks
    # category-present discipline on the loopback-only-dns substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert isinstance(c, str) and len(c) > 0, f'category must be non-empty string, got {repr(c)}'
"
}

@test "INVARIANT (module.toml version field is semver X.Y.Z — version-comparison sortability contract)" {
    # Sister to brain-wide module.toml semver INVARIANT family.
    # The version field MUST follow X.Y.Z semver so the resolver
    # can sort versions numerically + version-gate downstream
    # consumers. A regression to "v1" / "1.0" / "1.0.0-beta+meta"
    # would break the sortable numeric comparison. Locks the
    # semver-X.Y.Z discipline on the loopback-only-dns substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (loopback-only-dns module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl installer resolves apply scripts
    # via module.toml's [install].apply field — the canonical
    # value is the relative path "install/apply.sh" (under the
    # module's own directory). A regression that swapped to
    # an absolute /usr/local/libexec/... path would break the
    # in-tree test runner (which executes apply scripts from
    # the source tree, not /usr/local/libexec/). A regression
    # to a non-existent path would surface as "apply script
    # not found" at install time. Locks the canonical
    # install/apply.sh path discipline on the loopback-only-dns module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
ap = inst.get('apply', '')
assert ap == 'install/apply.sh', f'install.apply must be install/apply.sh, got {ap!r}'
"
}

@test "INVARIANT (loopback-only-dns module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the loopback-only-dns module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
chk = inst.get('check', '')
assert chk == 'install/check.sh', f'install.check must be install/check.sh, got {chk!r}'
"
}

@test "INVARIANT (loopback-only-dns module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
    # Sister to brain-wide module.toml [install_paths]
    # INVARIANT family. Per MS011 Z-8 / SDD-026, every
    # installer module MUST declare an [install_paths] block
    # enumerating the on-disk surfaces it touches on apply.
    # The selfdef dashboard's install-options surface +
    # install-plan auditor read this block to surface what
    # the module mutates BEFORE apply runs. A regression
    # dropping the [install_paths] block would leave operators
    # without a pre-apply manifest of writes, breaking
    # operator-consent + the install-plan-dry-run contract.
    # Locks the SDD-026 manifest discipline on the loopback-only-dns
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths')
assert ip is not None, f'[install_paths] block must be present per SDD-026, got None'
paths = ip.get('paths', [])
assert isinstance(paths, list) and len(paths) > 0, f'install_paths.paths must be non-empty list, got {paths!r}'
"
}

@test "INVARIANT (loopback-only-dns module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for loopback-only-dns is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the loopback-only-dns substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (loopback-only-dns module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
    # Sister to brain-wide [install_paths].paths INVARIANT
    # family. The install_paths.paths field MUST be a TOML
    # list of strings (each element an absolute path the
    # module touches on apply). A regression that swapped to
    # a comma-separated string ("path1,path2,path3") would
    # silently treat it as a single literal path. The
    # selfdef installer iterates the list to surface the
    # mutation manifest to operators; broken type-shape
    # would break the install-options surface + dry-run
    # auditor. Locks the TOML-list-of-strings type discipline
    # on the loopback-only-dns install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list), f'install_paths.paths must be TOML list, got {type(ps).__name__}'
assert all(isinstance(p, str) for p in ps), f'every paths entry must be a string'
"
}

@test "INVARIANT (loopback-only-dns module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the loopback-only-dns requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
req = data.get('requires')
assert isinstance(req, list), f'requires must be TOML list, got {type(req).__name__}'
for r in req:
    assert isinstance(r, dict), f'requires entry must be inline-table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'requires must have kind+value, got {r!r}'
"
}

@test "INVARIANT (loopback-only-dns module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the loopback-only-dns
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (loopback-only-dns module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the loopback-only-dns
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (loopback-only-dns module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the loopback-only-dns substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (loopback-only-dns module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (loopback-only-dns module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the loopback-only-dns substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
prof = data.get('profiles')
assert prof is not None, f'[profiles] must be present, got None'
assert isinstance(prof, dict), f'[profiles] must be TOML table, got {type(prof).__name__}'
"
}

@test "INVARIANT (loopback-only-dns module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (loopback-only-dns module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (loopback-only-dns module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (loopback-only-dns module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (loopback-only-dns module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (loopback-only-dns module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (loopback-only-dns README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (loopback-only-dns install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (loopback-only-dns install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (loopback-only-dns install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (loopback-only-dns install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (loopback-only-dns install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (loopback-only-dns install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (loopback-only-dns install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (loopback-only-dns install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (loopback-only-dns install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (loopback-only-dns install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (loopback-only-dns install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (loopback-only-dns install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (loopback-only-dns module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (loopback-only-dns module.toml exists at canonical path modules/loopback-only-dns/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (loopback-only-dns module dir is at canonical path modules/loopback-only-dns/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (loopback-only-dns install dir exists at modules/loopback-only-dns/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (loopback-only-dns install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (loopback-only-dns install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/loopback-only-dns/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}
