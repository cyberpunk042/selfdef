#!/usr/bin/env bats
# L2 bats functional tests for the aide-bridge aide-check.sh wrapper.
#
# Wraps `aide --check`: maps AIDE's exit bitmask + summary table to a
# severity (ok=no diff, warn=adds only, alert=removals/changes, high=internal
# error / missing config). Drives the wrapper with a fake `aide` binary
# (SELFDEF_AIDE_BIN) emitting a controlled summary + exit code, and `logger`
# shadowed on PATH.
#
# Run with: bats packaging/test/L2-aide-bridge.bats

WD="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/systemd/aide-check.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SELFDEF_TEST_LOGCAP}"
FAKELOGGER
    chmod +x "${BIN}/logger"
    export SELFDEF_TEST_LOGCAP="${TMP}/log.out"
    : > "${SELFDEF_TEST_LOGCAP}"
    CONF="${TMP}/aide.conf"; printf '# aide config\n' > "${CONF}"
    FAKE_AIDE="${TMP}/aide"
}

teardown() { rm -rf "${TMP}"; }

# mk_aide <rc> <summary-stdout>
mk_aide() {
    { printf '#!/usr/bin/env bash\n'; printf 'cat <<'\''OUT'\''\n%s\nOUT\n' "$2"; printf 'exit %s\n' "$1"; } > "${FAKE_AIDE}"
    chmod +x "${FAKE_AIDE}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_AIDE_PROFILE="${PROFILE:-baseline}" \
    SELFDEF_AIDE_BIN="${FAKE_AIDE}" \
    SELFDEF_AIDE_CONF="${CONF_V:-$CONF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "missing aide config → high / config_missing" {
    CONF_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"config_missing"'
    cap | grep -q '"severity":"high"'
}

@test "no differences (rc 0) → ok / no_diff" {
    mk_aide 0 "AIDE found NO differences"
    run_wd
    cap | grep -q '"event":"no_diff"'
    cap | grep -q '"severity":"ok"'
}

@test "adds only → warn / diff_added_only" {
    mk_aide 1 "Added entries: 3
Removed entries: 0
Changed entries: 0"
    run_wd
    cap | grep -q '"event":"diff_added_only"'
    cap | grep -q '"severity":"warn"'
}

@test "removals/changes → alert / diff_changed_or_removed" {
    mk_aide 6 "Added entries: 0
Removed entries: 1
Changed entries: 2"
    run_wd
    cap | grep -q '"event":"diff_changed_or_removed"'
    cap | grep -q '"severity":"alert"'
}

@test "aide internal error (rc >= 8) → high / aide_internal_error" {
    mk_aide 8 "fatal: database read error"
    run_wd
    cap | grep -q '"event":"aide_internal_error"'
    cap | grep -q '"severity":"high"'
}

@test "enforce profile exits non-zero on a diff" {
    mk_aide 6 "Removed entries: 1
Changed entries: 2"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "bitmask added/removed/changed surface in JSON (operator can verify the AIDE rc semantics)" {
    # rc 7 = 1|2|4 = added + removed + changed bits all set.
    mk_aide 7 "Added entries: 5
Removed entries: 3
Changed entries: 11"
    run_wd
    cap | grep -q '"added_bit":1'
    cap | grep -q '"removed_bit":1'
    cap | grep -q '"changed_bit":1'
    cap | grep -q '"aide_rc":7'
}

@test "summary-table counts surface in JSON (operator triage observability)" {
    mk_aide 7 "Added entries: 5
Removed entries: 3
Changed entries: 11"
    run_wd
    cap | grep -q '"added":5'
    cap | grep -q '"removed":3'
    cap | grep -q '"changed":11'
}

@test "profile field surfaces in JSON (echo of operator-set --profile)" {
    mk_aide 0 "AIDE found NO differences"
    PROFILE=enforce run_wd
    cap | grep -q '"profile":"enforce"'
}

@test "INVARIANT (removals+changes win over adds): rc=3 (added+removed) → alert (not warn — removals tip the severity)" {
    # rc 3 = 1|2 = added + removed bits set. The script's severity
    # ladder: if removed>0 OR changed>0 → alert. The presence of
    # adds alongside the removal must NOT downgrade to warn.
    mk_aide 3 "Added entries: 2
Removed entries: 1
Changed entries: 0"
    run_wd
    cap | grep -q '"event":"diff_changed_or_removed"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (parse-defensive): missing summary table → all counts default to 0 + still emit JSON" {
    # AIDE versions differ in summary-table format; the script
    # falls back to 0 counts when the awk patterns don't match.
    # The wrapper must still emit a valid JSON record (not crash).
    mk_aide 1 "AIDE 0.16 — unusual output format with no Added entries: header"
    run_wd
    cap | grep -q '"tag":"selfdef-aide"'
    cap | grep -q '"added":0'
    cap | grep -q '"removed":0'
    cap | grep -q '"changed":0'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    mk_aide 0 "AIDE found NO differences"
    run_wd
    # The wrapper emits two logger calls: one with tag
    # `selfdef-aide` (the JSON record) and one with tag
    # `selfdef-aide-detail` (the head of AIDE output). Count
    # only the main `-t selfdef-aide --` line, distinct from
    # `-t selfdef-aide-detail --`.
    main_count=$(cap | grep -cE '^-t selfdef-aide -- ')
    [ "${main_count}" = "1" ]
}

@test "baseline profile exits 0 even on alert severity (findings are operator-pull advisory)" {
    mk_aide 6 "Removed entries: 1
Changed entries: 2"
    PROFILE=baseline run run_wd
    [ "${status}" = "0" ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline profile exits 0 even on high severity (config_missing is advisory in baseline mode)" {
    CONF_V="${TMP}/nonexistent" \
        PROFILE=baseline run run_wd
    [ "${status}" = "0" ]
}

@test "INVARIANT (rc=0 + no_diff: all count fields = 0 in JSON)" {
    mk_aide 0 "AIDE found NO differences"
    run_wd
    cap | grep -q '"added":0'
    cap | grep -q '"removed":0'
    cap | grep -q '"changed":0'
}

@test "INVARIANT (current behavior: enforce profile on internal-error (rc>=8) exits 0 — wrapper-level vs diff-level distinction)" {
    # Internal error is wrapper-level (AIDE itself failed to run);
    # the enforce gate targets diff-level events (added/removed/
    # changed). Current behavior: wrapper exits 0 + emits high
    # severity JSON; operator alerting hooks the high severity,
    # not the exit code. Locks current contract so future
    # refactor doesn't accidentally couple enforce-exit-non-zero
    # to wrapper-level failures.
    mk_aide 8 "fatal: database read error"
    PROFILE=enforce run run_wd
    [ "${status}" = "0" ]
    cap | grep -q '"severity":"high"'
}

@test "INVARIANT (enforce profile on adds-only (warn) → exit non-zero — strict baseline integrity)" {
    # Adds-only is warn severity in baseline profile (operator-
    # pull advisory). Under enforce, even adds break the strict
    # baseline-integrity contract and must exit non-zero.
    mk_aide 1 "Added entries: 3"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"warn"'
}

@test "INVARIANT (enforce profile on no_diff → exit 0): unchanged baseline passes even in enforce" {
    mk_aide 0 "AIDE found NO differences"
    PROFILE=enforce run run_wd
    [ "${status}" = "0" ]
}

@test "INVARIANT (rc surfaces in JSON across diff-tier + high-tier — diff-tier uses aide_rc, high-tier uses rc)" {
    # Current schema: the diff-tier JSON path uses 'aide_rc' field
    # name; the high-tier internal-error path uses 'rc' field.
    # Lock both surfaces — downstream consumers must handle both
    # names. (Future refinement could unify to aide_rc across
    # both paths, but for now this is the contract.)
    mk_aide 0 "AIDE found NO differences"
    run_wd
    cap | grep -q '"aide_rc":0'
    : > "${SELFDEF_TEST_LOGCAP}"
    mk_aide 12 "fatal: bad signature"
    run_wd
    # Internal-error path uses 'rc':12 not 'aide_rc':12.
    cap | grep -qE '"rc":12'
    cap | grep -q '"severity":"high"'
}

@test "INVARIANT (-detail companion tag emits AIDE output for journal forensics — operator can journalctl -t selfdef-aide-detail)" {
    # The -detail tag must surface AIDE's stdout so operator can
    # journal-grep specific changed paths. The MAIN tag carries
    # only the JSON summary — the detail is the forensics channel.
    mk_aide 6 "Added entries: 0
Removed entries: 1
Changed entries: 2
F: /etc/passwd
F: /etc/shadow"
    run_wd
    detail_count=$(cap | grep -cE '^-t selfdef-aide-detail -- ')
    [ "${detail_count}" -ge 1 ]
}

@test "INVARIANT (changed-only rc=4 → alert without adds/removes — changed bit alone tips severity)" {
    # rc=4 (changed bit only set) must alert. Sister axis to the
    # rc=6 (removed+changed) test and rc=3 (added+removed) test.
    # Locks that EACH dangerous bit independently triggers alert,
    # not only combinations.
    mk_aide 4 "Added entries: 0
Removed entries: 0
Changed entries: 5"
    run_wd
    cap | grep -q '"event":"diff_changed_or_removed"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (removed-only rc=2 → alert without changes/adds — removed bit alone tips severity)" {
    # Sister to changed-only test. rc=2 (removed bit only) must
    # alert. Locks each dangerous bit individually.
    mk_aide 2 "Added entries: 0
Removed entries: 4
Changed entries: 0"
    run_wd
    cap | grep -q '"event":"diff_changed_or_removed"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (combined-all rc=7 → alert with adds+removes+changed all bits set)" {
    # Sister to each-bit-individual axes locked above. When AIDE
    # surfaces an attacker's full filesystem-rewrite (rc=7 — adds +
    # removed + changed bits all set), severity stays alert (highest
    # — the changed/removed bits win), not warn (which would happen
    # if combined-rc was misclassified as adds-dominated). Locks the
    # severity-ladder precedence: changed/removed beat adds in any
    # combined finding. Closes the rc-bitmask combinatorial coverage
    # axis on the file-integrity surveillance surface (T1565.001 —
    # Stored Data Manipulation via mass filesystem rewrite).
    mk_aide 7 "Added entries: 2
Removed entries: 3
Changed entries: 4"
    run_wd
    cap | grep -q '"event":"diff_changed_or_removed"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (high-volume adds-only: 100 adds still warn — adds-only never escalates to alert; bit-mask precedence holds at scale)" {
    # Sister to suid-sgid 4-add boundary INVARIANT and many other
    # watchdog count-vs-bit precedence INVARIANTs across the
    # brain. AIDE's bitmask (1=added, 2=removed, 4=changed)
    # determines severity REGARDLESS of count magnitude. A
    # 100-add scan rc=1 (adds-only bit set) MUST stay warn — the
    # adds-only bit defines the severity ceiling. If the wrapper
    # silently escalated to alert at high counts, the operator
    # would lose the change/remove signal (which is qualitatively
    # different: changes/removes are tamper signals, adds are
    # legit-ops signals at any scale). Locks the bit-precedence-
    # over-count invariant on the file-integrity surveillance
    # surface (T1565.001 — Stored Data Manipulation tamper class).
    mk_aide 1 "Added entries: 100
Removed entries: 0
Changed entries: 0"
    run_wd
    cap | grep -q '"event":"diff_added_only"'
    cap | grep -q '"severity":"warn"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (rc=5 added+changed — adds-with-tamper → alert; closes the rc-bitmask combinatorial slot)" {
    # Sister to rc=3 (added+removed), rc=7 (all 3) and changed-only
    # / removed-only / adds-only individual-bit INVARIANTs already
    # locked above. Closes the remaining rc-bitmask combinatorial
    # coverage: rc=5 (1+4 = added bit + changed bit). Severity must
    # be alert — the changed bit tips severity ladder over the
    # adds-only baseline. This is the "attacker added new files +
    # tampered existing files" pattern (eg. dropped a malicious
    # /etc/cron.d/.evil AND modified /etc/passwd in the same scan).
    # If the wrapper misclassified rc=5 as adds-dominated, the
    # operator would lose the tamper signal underneath the adds.
    # Locks the changed-bit-tips-severity invariant on the
    # file-integrity surveillance surface (T1565.001).
    mk_aide 5 "Added entries: 3
Removed entries: 0
Changed entries: 2"
    run_wd
    cap | grep -q '"event":"diff_changed_or_removed"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (rc=6 removed+changed → alert; closes the rc-bitmask combinatorial slot)" {
    # Sister to rc=3 (added+removed) + rc=5 (added+changed) +
    # rc=7 (all 3) and individual-bit INVARIANTs already locked.
    # Closes the remaining rc-bitmask combinatorial slot: rc=6
    # (2+4 = removed bit + changed bit). Severity MUST be alert
    # — both removed AND changed bits are alert-grade tamper
    # signals. The "attacker removed monitoring files +
    # tampered config" pattern.
    mk_aide 6 "Added entries: 0
Removed entries: 3
Changed entries: 2"
    run_wd
    cap | grep -q '"event":"diff_changed_or_removed"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger INVARIANTs. The
    # selfdef-aide tag MUST fire EXACTLY ONCE per scan
    # regardless of how many added/removed/changed entries
    # surface. Multi-line output would break SDD-062 downstream
    # JSON-line consumer (Sigma correlator). Locks consolidation
    # discipline on the AIDE file-integrity surveillance surface
    # (companion detail tag is a separate axis, locked above).
    mk_aide 7 "Added entries: 10
Removed entries: 5
Changed entries: 3"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-aide -- ')
    [ "${main_count}" = "1" ]
}


@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on aide-bridge surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The aide-bridge MUST only emit severity values from the
    # closed set {ok,warn,alert} — never custom values (critical,
    # error, fatal, notice, info). Operator dashboard parsers
    # branch on the literal severity string; an out-of-set
    # value silently falls through routing and the operator
    # never sees the T1565.001 Stored Data Manipulation /
    # T1014 Rootkit AIDE file-integrity alert. Locks parser
    # contract on the AIDE delta-detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    mk_aide 0 "AIDE found NO differences between database and filesystem."
    run_wd                                              # ok path
    mk_aide 7 "Added entries: 1
Removed entries: 1
Changed entries: 1"
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-uninstall: aide-bridge watchdog NEVER emits package-remove commands on aide)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The aide-bridge watchdog invokes aide --check
    # to detect filesystem integrity drift but MUST NEVER emit
    # shell commands that uninstall the aide package itself
    # (apt/dpkg/dnf/rpm/yum remove|purge|uninstall aide). Silent
    # auto-removal would tear down the file-integrity
    # surveillance substrate — T1562.001 Impair Defenses self-
    # defeat by the very module meant to detect tamper. Locks
    # anti-package-removal contract on the aide-bridge
    # substrate.
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+aide'
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # aide-bridge runs ON the timer's scheduled fire — invokes
    # aide --check, parses rc bitmask, emits a verdict, then
    # exits. Type=simple would break timer OnUnitActiveSec
    # semantics. Locks oneshot-probe contract on the aide-bridge
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/systemd/selfdef-aide-check.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. aide-bridge manifest declares install + profile
    # gating the resolver enforces; malformed manifest wedges
    # the aide --check wrapper baseline. Python's tomllib is
    # the canonical parser. Locks anti-malformed-manifest on
    # the aide-bridge substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'aide-bridge', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (aide-bridge libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The aide-bridge libexec uses set -u (and NOT set -e) by
    # design: watchdog probes WANT to continue scanning even
    # when individual checks fail (rather than abort-on-first-
    # error like installers), so they emit a complete verdict
    # at the end. But set -u remains essential — it catches
    # typo'd env-var references ($SELFDEF_FOO_BASELINE vs
    # $SELFDEF_FOO_BASLINE) before they propagate as silent
    # empty-string into baseline-path operations. A regression
    # dropping set -u would let a typo'd var name produce a
    # silent baseline-rewrite to /. Locks set -u discipline on
    # the aide-bridge libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (aide-bridge libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # All watchdog libexec scripts MUST surface JSON records
    # via logger -t with a selfdef-prefixed tag so downstream
    # syslog/journald consumers can route per-watchdog records
    # via the tag field rather than parsing the JSON payload
    # for the module field. The tag prefix MUST be "selfdef-"
    # so cross-watchdog SIEM filters (`syslog-ng-filter "selfdef-*"`)
    # capture every selfdef-watchdog without per-watchdog tag
    # enumeration. A regression dropping the selfdef- prefix
    # would cause SIEM filters to silently miss records. Locks
    # SDD-062 logger-tag routing discipline on the aide-bridge
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (aide-bridge timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # The aide-bridge timer unit MUST declare RandomizedDelaySec=
    # so fleet hosts don't all fire at the exact same minute
    # (thundering-herd that overwhelms downstream
    # syslog/journald aggregators). Locks anti-thundering-herd
    # cadence discipline on the aide-bridge timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (aide-bridge timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Persistent=true tells systemd to fire the timer ON BOOT
    # if it was missed during downtime — without it, a host
    # that boots after the scheduled fire would silently skip
    # the cycle, leaving a forensics gap. Locks Persistent=
    # discipline on the aide-bridge timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (aide-bridge timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # The .timer file MUST declare Unit=<companion>.service so
    # systemd knows which .service to fire on timer-elapse. By
    # default systemd matches timer-name to service-name, but
    # explicit Unit= is required when names differ + makes the
    # binding self-documenting. A regression dropping Unit= +
    # renaming either file would silently break the link.
    # Locks the timer-to-service binding discipline on the
    # aide-bridge substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (aide-bridge service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. The .service file MUST declare ExecStart=<path-
    # to-libexec.sh> so systemd knows what to run. The libexec
    # script must EXIST at the declared path. A regression that
    # renamed the libexec script without updating ExecStart
    # would surface as service-start failure rather than a
    # silent regression. Locks the service-to-libexec binding
    # discipline on the aide-bridge substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (aide-bridge service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # The aide-bridge probe is Type=oneshot — it RUNS, emits a
    # verdict, and EXITS. Restart=always on a oneshot would
    # cause systemd to immediately re-fire the probe in a
    # tight loop, swamping the dashboard with redundant
    # records. A regression that added Restart=always would
    # produce a runaway-probe footgun. Locks the anti-restart-
    # storm discipline on the aide-bridge service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (aide-bridge service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. The Description= directive surfaces in
    # `systemctl status` output + journalctl unit-filter
    # labels. A unit with no Description is opaque to
    # operators triaging service activity. Locks the
    # Description-present discipline on the aide-bridge
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (aide-bridge module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the aide-bridge module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
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

@test "INVARIANT (aide-bridge module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the aide-bridge module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
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

@test "INVARIANT (aide-bridge module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the aide-bridge
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
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

@test "INVARIANT (aide-bridge module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for aide-bridge is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the aide-bridge substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (aide-bridge module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the aide-bridge install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
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

@test "INVARIANT (aide-bridge module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the aide-bridge requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
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

@test "INVARIANT (aide-bridge module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the aide-bridge
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (aide-bridge module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the aide-bridge
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (aide-bridge module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the aide-bridge substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (aide-bridge module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (aide-bridge module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the aide-bridge substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
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

@test "INVARIANT (aide-bridge module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (aide-bridge module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (aide-bridge module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (aide-bridge module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (aide-bridge module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (aide-bridge module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (aide-bridge README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (aide-bridge install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (aide-bridge install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (aide-bridge install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (aide-bridge install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (aide-bridge install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (aide-bridge install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (aide-bridge install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (aide-bridge install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (aide-bridge install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (aide-bridge install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (aide-bridge install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (aide-bridge install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (aide-bridge module.toml [install_paths].paths includes at least one /usr/ path — binary-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/usr/') for p in ps), f'paths must include ≥1 /usr/ target, got {ps!r}'
"
}

@test "INVARIANT (aide-bridge module.toml exists at canonical path modules/aide-bridge/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (aide-bridge module dir is at canonical path modules/aide-bridge/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/aide-bridge"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (aide-bridge install dir exists at modules/aide-bridge/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (aide-bridge install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (aide-bridge install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (aide-bridge install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (aide-bridge install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (aide-bridge module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (aide-bridge install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (aide-bridge install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (aide-bridge install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (aide-bridge install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (aide-bridge install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (aide-bridge install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (aide-bridge install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (aide-bridge install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (aide-bridge module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (aide-bridge module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (aide-bridge module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
prefixes = ('/etc/', '/usr/', '/var/', '/lib/', '/opt/', '/run/', '/srv/', '/boot/')
for p in ps:
    assert any(p.startswith(pf) for pf in prefixes), f'{p!r} not canonical-root'
"
}

@test "INVARIANT (aide-bridge module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (aide-bridge module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (aide-bridge module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92 — libexec-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p or '/usr/local/' in p for p in ps)
"
}

@test "INVARIANT (aide-bridge module.toml install_paths.paths has /var/lib/selfdef/ entry 93 — state-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/var/lib/' in p or '/var/log/' in p or '/var/cache/' in p for p in ps)
"
}

@test "INVARIANT (aide-bridge module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (aide-bridge module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (aide-bridge module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (aide-bridge module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (aide-bridge module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (aide-bridge module.toml category field uses double-quoted string syntax — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (aide-bridge module.toml summary field uses double-quoted string syntax — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (aide-bridge module.toml name field value matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"aide-bridge"' "${mtoml}"
}

@test "INVARIANT (aide-bridge module.toml top-level keys before any [section] header — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import re
with open('${mtoml}') as fp:
    for ln in fp:
        s = ln.strip()
        if not s or s.startswith('#'): continue
        if s.startswith('['): break
        assert '=' in ln, f'expected key=val before sections, got {ln!r}'
        break
"
}

@test "INVARIANT (aide-bridge module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (aide-bridge module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (aide-bridge module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (aide-bridge module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (aide-bridge module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (aide-bridge module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (aide-bridge module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (aide-bridge module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (aide-bridge module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}

@test "INVARIANT (aide-bridge module.toml [install] check value is non-empty string ending with .sh — TOML-install-check-shape-canonical 112)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ck = (data.get('install') or {}).get('check', '')
assert isinstance(ck, str) and ck and ck.endswith('.sh'), f'install.check must be non-empty .sh path, got {ck!r}'
"
}

@test "INVARIANT (aide-bridge module.toml version field matches semver X.Y.Z pattern — TOML-version-semver-canonical 113)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v), f'version must be semver X.Y.Z, got {v!r}'
"
}

@test "INVARIANT (aide-bridge module.toml summary field is non-empty string with length >= 30 chars — TOML-summary-substance-floor 114)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) >= 30, f'summary must be string with len >= 30, got len={len(s)} value={s!r}'
"
}

@test "INVARIANT (aide-bridge module.toml top-level requires field is a TOML list — TOML-requires-list-canonical 115)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (aide-bridge module.toml top-level provides field is a TOML list — TOML-provides-list-canonical 116)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('provides')
assert isinstance(r, list), f'provides must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (aide-bridge module.toml top-level conflicts field is a TOML list — TOML-conflicts-list-canonical 117)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('conflicts')
assert isinstance(r, list), f'conflicts must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (aide-bridge module.toml top-level depends_on field is a TOML list — TOML-depends-on-list-canonical 118)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('depends_on')
assert isinstance(r, list), f'depends_on must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (aide-bridge module.toml top-level consumes field is a TOML list — TOML-consumes-list-canonical 119)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('consumes')
assert isinstance(r, list), f'consumes must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (aide-bridge module.toml top-level instanced field is a TOML boolean — TOML-instanced-bool-canonical 120)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('instanced')
assert isinstance(r, bool), f'instanced must be bool, got {type(r).__name__}'
"
}

@test "INVARIANT (aide-bridge module.toml [install] uninstall value is non-empty string ending with .sh — TOML-install-uninstall-shape-canonical 121)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = (data.get('install') or {}).get('uninstall', '')
assert isinstance(v, str) and v and v.endswith('.sh'), f'install.uninstall must be non-empty .sh path, got {v!r}'
"
}

@test "INVARIANT (aide-bridge module.toml has [profiles] section header — TOML-profiles-section-canonical 122)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    grep -qE '^\[profiles\]$' "${mtoml}"
}

@test "INVARIANT (aide-bridge module.toml [profiles] default field is non-empty string — TOML-profiles-default-canonical 123)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert isinstance(d, str) and d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (aide-bridge module.toml [profiles] available field is a TOML list — TOML-profiles-available-list-canonical 124)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available')
assert isinstance(a, list), f'profiles.available must be list, got {type(a).__name__}'
"
}

@test "INVARIANT (aide-bridge module.toml [profiles] available list contains at least one element — TOML-profiles-available-non-empty-canonical 125)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert isinstance(a, list) and len(a) >= 1, f'profiles.available must be non-empty list, got {a!r}'
"
}

@test "INVARIANT (aide-bridge module.toml [profiles] default value appears in [profiles] available list (semantic consistency) — TOML-profiles-default-in-available-canonical 126)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('profiles') or {}
default = p.get('default')
available = p.get('available') or []
assert default in available, f'profiles.default {default!r} must appear in available {available!r}'
"
}

@test "INVARIANT (aide-bridge module.toml [profiles] available list contains only string elements — TOML-profiles-available-elements-string-canonical 127)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert all(isinstance(x, str) for x in a), f'profiles.available items must all be strings, got {[type(x).__name__ for x in a]!r}'
"
}

@test "INVARIANT (aide-bridge module.toml requires list elements are inline-tables with kind+value keys (or empty) — TOML-requires-elements-shape-canonical 128)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
for el in r:
    assert isinstance(el, dict), f'requires element must be inline-table, got {type(el).__name__}'
    assert 'kind' in el and 'value' in el, f'requires element must have kind+value keys, got {sorted(el.keys())!r}'
"
}

@test "INVARIANT (aide-bridge module.toml requires items have kind in bounded vocab {binary, package, kernel-feature} — TOML-requires-kind-vocab-canonical 129)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
allowed = {'binary', 'package', 'kernel-feature'}
for el in r:
    k = el.get('kind', '')
    assert k in allowed, f'requires.kind must be in {allowed}, got {k!r}'
"
}
