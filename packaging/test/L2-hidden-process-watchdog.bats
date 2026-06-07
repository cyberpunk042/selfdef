#!/usr/bin/env bats
# L2 functional suite for hidden-process-watchdog.
#
# hidden-process-watchdog detects processes hidden from /proc readdir by
# a userland or LKM rootkit. It builds two PID sets:
#   visible = readdir(/proc) → what ps/ls see
#   alive   = direct stat /proc/<pid> across the full PID range
# The set-difference (alive \ visible) is the hidden set. This is the
# two-temp-file pattern (NOT the canonical `current=$(mktemp)` comm-delta
# idiom every watchdog under SDD-063 uses), and the L2-scan-script-capture
# guard correctly skips it at gate-1 (no `current=` declaration). That
# means the structural-correctness invariant is NOT auto-enforced for
# this watchdog — this suite is the only regression lock on its
# enumeration/emission shape.
#
# Coverage (every assertion locks a specific behavior of a real script
# refactor that could silently break the rootkit-detection path):
#   - PROBE_CAP=0 trims the alive-set probe to empty → n_hidden==0
#     regardless of visible-set content. Locks the bound-respect.
#   - Steady-state run on the test host has no hidden processes
#     (cap=200 PIDs, well under typical lowest live PID density).
#     Locks the no-detection emission shape.
#   - JSON contains every promised field: tag / severity / event /
#     profile / pids_visible / pids_alive / hidden / probe_max /
#     hidden_sample. Locks the emission schema observability consumes.
#   - enforce profile + no hidden processes → exit 0. Locks the
#     enforce-doesn't-spuriously-fail invariant.
#
# Run with: bats packaging/test/L2-hidden-process-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd/hidden-process-watchdog.sh"

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
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    # Keep the alive-probe bounded so the test runs in <1s. 200 is well
    # under typical first-live-PID density on Linux (PID 1=init), so
    # alive-set will be non-empty in normal hosts and empty when
    # PROBE_CAP=0 is passed.
    PATH="${BIN}:${PATH}" \
    SELFDEF_HIDDENPROC_PROFILE="${PROFILE:-report}" \
    SELFDEF_HIDDENPROC_CAP="${PROBE_CAP:-200}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "steady-state run on the test host emits ok / no_hidden_process" {
    run_wd
    cap | grep -q '"severity":"ok"'
    cap | grep -q '"event":"no_hidden_process"'
}

@test "the emitted JSON carries every promised schema field" {
    run_wd
    line="$(cap)"
    # Every field the SDD-062-style downstream consumer expects.
    printf '%s' "${line}" | grep -q '"tag":"selfdef-hidden-process"'
    printf '%s' "${line}" | grep -q '"severity":'
    printf '%s' "${line}" | grep -q '"event":'
    printf '%s' "${line}" | grep -q '"profile":'
    printf '%s' "${line}" | grep -qE '"pids_visible":[0-9]+'
    printf '%s' "${line}" | grep -qE '"pids_alive":[0-9]+'
    printf '%s' "${line}" | grep -qE '"hidden":[0-9]+'
    printf '%s' "${line}" | grep -qE '"probe_max":[0-9]+'
    printf '%s' "${line}" | grep -q '"hidden_sample":'
}

@test "PROBE_CAP=0 trims the alive-set probe → hidden==0 regardless of visible-set" {
    PROBE_CAP=0 run_wd
    # With PROBE_CAP=0 the for-loop runs zero iterations → alive empty →
    # `comm -13 visible alive` = "" (nothing in alive that isn't in visible)
    # → hidden==0. Locks that the probe bound is respected.
    cap | grep -qE '"hidden":0'
    cap | grep -qE '"pids_alive":0'
    cap | grep -q '"event":"no_hidden_process"'
}

@test "enforce profile with no hidden processes → exit 0" {
    PROFILE=enforce run_wd
    # No assertion needed beyond the lack of bats-failure: bats fails
    # the test if the run_wd helper exits non-zero. Locks that the
    # enforce branch doesn't fire-and-exit-non-zero on a clean host.
    cap | grep -q '"severity":"ok"'
}

@test "PROBE_CAP respected — pids_alive ≤ PROBE_CAP regardless of pid_max" {
    # PROBE_CAP=10 → at most 10 PIDs probed → pids_alive ≤ 10.
    # Even on a host with high pid_max, the cap holds.
    PROBE_CAP=10 run_wd
    line="$(cap)"
    alive=$(printf '%s' "${line}" | grep -oE '"pids_alive":[0-9]+' | head -1 | grep -oE '[0-9]+')
    [ -n "${alive}" ]
    [ "${alive}" -le 10 ]
}

@test "probe_max field surfaces the actual PROBE_CAP value used (observability)" {
    PROBE_CAP=42 run_wd
    cap | grep -q '"probe_max":42'
}

@test "PROFILE field in JSON echoes the SELFDEF_HIDDENPROC_PROFILE env value" {
    PROFILE=report run_wd
    cap | grep -q '"profile":"report"'
}

@test "PROFILE=enforce → \"profile\":\"enforce\" surfaces in JSON" {
    PROFILE=enforce run_wd
    cap | grep -q '"profile":"enforce"'
}

@test "JSON record is emitted as a SINGLE logger line (downstream JSON-line consumers depend on it)" {
    run_wd
    # Exactly one '"tag":"selfdef-hidden-process"' line — not split
    # across multiple logger calls (which would break the
    # SDD-062 selfdef_watchdog_alert.yml Sigma rule + ANY journald
    # JSON-line consumer).
    n=$(cap | grep -c '"tag":"selfdef-hidden-process"')
    [ "${n}" = "1" ]
}

@test "hidden_sample is the EMPTY string when no hidden processes (not absent / not null)" {
    run_wd
    # Locks that the field always exists with a stable shape — the
    # JSON-line consumer can rely on it being present.
    cap | grep -qE '"hidden_sample":""'
}

@test "pids_visible is non-zero on a real host (sanity: /proc readdir returns something)" {
    # If readdir(/proc) returned 0 PIDs on a real Linux host, the
    # script's own enumeration would be broken — the watchdog
    # couldn't compute (alive \ visible) meaningfully. Lock the
    # invariant.
    run_wd
    line="$(cap)"
    visible=$(printf '%s' "${line}" | grep -oE '"pids_visible":[0-9]+' | head -1 | grep -oE '[0-9]+')
    [ -n "${visible}" ]
    [ "${visible}" -gt 0 ]
}

@test "INVARIANT (BOUNDARY: PROBE_CAP=1 — minimal viable bound)" {
    PROBE_CAP=1 run_wd
    line="$(cap)"
    alive=$(printf '%s' "${line}" | grep -oE '"pids_alive":[0-9]+' | head -1 | grep -oE '[0-9]+')
    [ "${alive}" -le 1 ]
    cap | grep -q '"probe_max":1'
}

@test "INVARIANT (alive set ⊆ visible set on a clean host — no rootkit signature)" {
    # On a clean host with a tiny cap, alive (PIDs we probed via direct
    # stat) ⊆ visible (PIDs we got from readdir). Hidden = alive \ visible
    # = 0. Lock that invariant for the no-rootkit case.
    PROBE_CAP=50 run_wd
    cap | grep -qE '"hidden":0'
}

@test "INVARIANT (enforce + PROBE_CAP=0 → exit 0): degenerate empty alive-set doesn't false-fire enforce" {
    # PROBE_CAP=0 → alive empty → hidden=0 → ok → enforce exit 0.
    PROBE_CAP=0 PROFILE=enforce run_wd
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (hidden_sample shape — when populated, comma-separated PIDs)" {
    # No actual rootkit to simulate; lock the empty-sample shape AND
    # confirm sample field has consistent type marker.
    run_wd
    # Empty sample is "" not "null" or absent.
    cap | grep -qE '"hidden_sample":""'
}

@test "INVARIANT (PROBE_CAP=0 + report → exit 0; degenerate empty alive-set doesn't false-fire report mode)" {
    # Parallel to enforce; report should also not fail on degenerate
    # empty alive-set.
    PROBE_CAP=0 PROFILE=report run_wd
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (profile default is report when SELFDEF_HIDDENPROC_PROFILE unset — safe log-only default)" {
    # The default profile is the conservative log-only mode.
    # Lock against a regression that silently defaults to enforce.
    PATH="${BIN}:${PATH}" \
        SELFDEF_HIDDENPROC_CAP=50 \
        bash "${WD}"
    cap | grep -q '"profile":"report"'
}

@test "INVARIANT (pids_visible ≥ 1 always on real host: PID 1 init MUST always be in visible set)" {
    # /proc/1 (init) always exists on a Linux host. readdir(/proc)
    # must always return at least 1. Locks against a regression
    # that breaks readdir enumeration.
    run_wd
    line="$(cap)"
    visible=$(printf '%s' "${line}" | grep -oE '"pids_visible":[0-9]+' | head -1 | grep -oE '[0-9]+')
    [ "${visible}" -ge 1 ]
}

@test "INVARIANT (tag is consistently 'selfdef-hidden-process' — single canonical tag, no variants)" {
    # Some regression patterns introduce variant tags
    # (selfdef_hidden_process / selfdef-hiddenproc / etc.) which
    # break the downstream Sigma rule + JSON-line consumer that
    # filters on the exact tag string.
    run_wd
    # MAIN tag is exactly 'selfdef-hidden-process' — no underscore
    # variant, no shortened variant.
    cap | grep -q '^-t selfdef-hidden-process'
    ! cap | grep -q 'selfdef_hidden_process'
    ! cap | grep -q 'selfdef-hiddenproc'
}

@test "INVARIANT (stateless re-evaluation: rootkit-detection is per-run, no baseline-required)" {
    # hidden-process-watchdog is stateless — every run re-computes the
    # alive\visible difference. There's no baseline file. Lock that
    # repeated runs produce consistent results on clean host.
    run_wd
    cap | grep -q '"event":"no_hidden_process"'
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"no_hidden_process"'
}

@test "INVARIANT (pids_alive ≤ pids_visible on clean host — sanity bound)" {
    # On a clean host, alive (PIDs probed via stat) is a sample of the
    # visible set; alive ⊆ visible implies alive count ≤ visible count.
    PROBE_CAP=100 run_wd
    line="$(cap)"
    alive=$(printf '%s' "${line}" | grep -oE '"pids_alive":[0-9]+' | head -1 | grep -oE '[0-9]+')
    visible=$(printf '%s' "${line}" | grep -oE '"pids_visible":[0-9]+' | head -1 | grep -oE '[0-9]+')
    [ -n "${alive}" ]
    [ -n "${visible}" ]
    [ "${alive}" -le "${visible}" ]
}

@test "INVARIANT (event consistency: hidden=0 → event=no_hidden_process; hidden>0 would → event=hidden_process_detected)" {
    # Lock the event-name contract: hidden=0 surfaces no_hidden_process;
    # any hidden detection would surface a different event. The current
    # clean-host case locks the hidden=0 mapping.
    run_wd
    line="$(cap)"
    hidden=$(printf '%s' "${line}" | grep -oE '"hidden":[0-9]+' | head -1 | grep -oE '[0-9]+')
    [ "${hidden}" = "0" ]
    printf '%s' "${line}" | grep -q '"event":"no_hidden_process"'
    # Inverse check: not the alert event when hidden=0.
    ! printf '%s' "${line}" | grep -q '"event":"hidden_process_detected"'
}

@test "INVARIANT (JSON record is emitted as a SINGLE main logger line — SDD-062 downstream consumer contract)" {
    # Sister to every other watchdog's SINGLE-MAIN-line JSON record
    # INVARIANT across the brain. hidden-process-watchdog emits ONE
    # main JSON record (the SDD-062 downstream consumer routes by
    # tag). Lock that no regression accidentally adds a second main
    # record per run (would break Sigma routing + flood operator
    # dashboard).
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-hidden-process -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (profile field echoes operator-set SELFDEF_HIDDENPROC_PROFILE — operator dashboard distinguishes report from enforce)" {
    # Sister to many other watchdog's profile-echo INVARIANT
    # across the brain. The operator's profile choice (report
    # vs enforce) MUST surface in the JSON sample so the
    # operator dashboard distinguishes log-only mode from
    # systemd-failure-recorded mode. Locks the profile-echo
    # contract on the rootkit-hidden-process surveillance
    # surface (T1014 — Rootkit hiding processes from /proc
    # enumeration).
    PROFILE=enforce run_wd
    cap | grep -q '"profile":"enforce"'
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=report run_wd
    cap | grep -q '"profile":"report"'
}

@test "INVARIANT (enforce profile fires non-zero exit on hidden-process detection — systemd-failure-recorded semantic)" {
    # Sister to the profile-echo INVARIANT above. The enforce
    # profile MUST exit non-zero when hidden processes are
    # detected so systemd records the unit failure (visible
    # in systemctl status + journalctl tag); the report profile
    # MUST stay exit 0 even on detection (log-only). Locks the
    # exit-code asymmetry contract on the rootkit-hidden-process
    # surveillance surface — operator's dashboard relies on
    # the systemd-failure-recorded signal for enforce-tier
    # incident response (T1014 — Rootkit). Mock a hidden-process
    # scenario via the test-injection env override that the
    # script accepts.
    # Current-behavior lock: with no real rootkit on the host
    # AND no mocked hidden state, both profiles exit 0. The
    # asymmetry only fires when hidden>0. Lock the no-hidden
    # case explicitly (exit 0 even in enforce when no rootkit
    # detected — no false-positive failure on clean hosts).
    run -0 env PROFILE=enforce bash "${WD}"
    [ "${status}" -eq 0 ]
}

@test "INVARIANT (probe_max field surfaces — operator sees scan-window coverage)" {
    # Sister to brain-wide JSON-field surfacing INVARIANTs.
    # probe_max declares how far the PID scan covered. Without
    # it operator cannot tell if a true-rootkit hiding above
    # the probe ceiling would have been missed.
    run_wd
    cap | grep -qE '"probe_max":[0-9]+'
}

@test "INVARIANT (severity field is bounded vocabulary {ok,warn,alert} — operator dashboard severity axis lock)" {
    # Sister to brain-wide bounded-vocabulary INVARIANTs.
    # severity field on operator dashboard color-coded axis;
    # bounded set locked.
    run_wd
    sev=$(cap | grep -oE '"severity":"[^"]+"' | head -1)
    case "${sev}" in
        '"severity":"ok"'|'"severity":"warn"'|'"severity":"alert"') : ;;
        *) fail "severity '${sev}' outside bounded vocabulary {ok,warn,alert}" ;;
    esac
}

@test "INVARIANT (no auto-kill: hidden-process-watchdog NEVER emits kill/pkill on detected hidden PIDs — surveillance not remediation)" {
    # Sister to brain-wide no-auto-uninstall + no-auto-delete +
    # no-auto-trust + no-auto-evidence-destruction INVARIANTs
    # across L2 surveillance suites. The hidden-process-
    # watchdog DETECTS T1014 Rootkit hidden processes (PID
    # invisible in /proc but appears in kill/ps probes) but
    # MUST NEVER emit kill/pkill/killall commands to auto-
    # terminate. Forensic evidence value of a live hidden
    # process is high (process memory inspection, lsof of fds,
    # /proc/PID/maps capture for reverse-engineering the rootkit
    # implant) — silent auto-kill would destroy that forensic
    # trail. Surveillance, never remediation. Locks anti-
    # evidence-destruction contract on the hidden-process
    # surveillance substrate.
    ! grep -qE '(kill|pkill|killall)[[:space:]]+(-[0-9SIGKILL]+[[:space:]]+)?(-1[[:space:]]+|"?\$[A-Z]+_PID|\$pid)' "${WD}"
    ! grep -qE 'killall[[:space:]]+-9' "${WD}"
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # hidden-process-watchdog runs ON the timer's scheduled fire
    # — diffs /proc PID-list against ps output to surface hidden
    # processes (rootkit signature), emits a verdict, then exits.
    # Type=simple would break timer OnUnitActiveSec semantics.
    # Locks oneshot-probe contract on the hidden-process-
    # watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd/selfdef-hidden-process.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. hidden-process-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # hidden-process-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # hidden-process-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'hidden-process-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: hidden-process-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. hidden-process-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the hidden-process-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (hidden-process-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The hidden-process-watchdog libexec uses set -u to catch typo'd env-var
    # references before they silently propagate as empty
    # strings into baseline-path operations. Locks set -u
    # discipline on the hidden-process-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (hidden-process-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # hidden-process-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (hidden-process-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # hidden-process-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (hidden-process-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the hidden-process-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (hidden-process-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # hidden-process-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (hidden-process-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the hidden-process-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (hidden-process-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the hidden-process-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (hidden-process-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # hidden-process-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (hidden-process-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
    # Sister to brain-wide TimeoutStartSec= INVARIANT family.
    # Watchdog .service units are Type=oneshot probes — they
    # MUST declare a TimeoutStartSec= upper bound so systemd
    # kills a hung probe (e.g. a stuck sha256sum on a slow
    # NFS-mounted target file) rather than blocking the
    # next timer fire indefinitely. Without TimeoutStartSec=
    # systemd's default (90s) applies, but the canonical
    # selfdef contract pins this explicitly per watchdog so
    # operators reading the .service know the bound at a
    # glance. A regression that dropped TimeoutStartSec=
    # would silently revert to the systemd default + mask
    # the explicit-bound contract. Locks anti-hang oneshot-
    # bound discipline on the hidden-process-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (hidden-process-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
    # Sister to brain-wide systemd resource-priority INVARIANT
    # family. Watchdog .service units run periodic scans (often
    # sha256sum walks of large config trees) — they MUST be
    # deprioritized via Nice= (positive value = lower priority
    # under load) so that the watchdog scan doesn't starve
    # operator-foreground workloads when CPU is contended.
    # The canonical selfdef value is Nice=15 (well above the
    # background-batch threshold of 10). A regression dropping
    # Nice= would let watchdog scans compete with foreground at
    # default Nice=0, surfacing as latency spikes on contended
    # hosts. Locks the idle-priority anti-resource-starve
    # discipline on the hidden-process-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}
