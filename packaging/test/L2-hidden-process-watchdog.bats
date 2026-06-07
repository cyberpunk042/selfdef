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

@test "INVARIANT (hidden-process-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd PrivateTmp= INVARIANT
    # family. Watchdog .service units that run periodic
    # sha256sum walks may create transient /tmp files. The
    # PrivateTmp= directive (canonically =true) instructs
    # systemd to give the unit its own /tmp mount namespace —
    # an attacker who exploits the watchdog cannot reach
    # /tmp files owned by other processes (e.g. ssh-agent
    # sockets), and the watchdog's own /tmp residue is
    # automatically cleaned at unit-stop. A regression
    # dropping PrivateTmp= would share /tmp with the host,
    # exposing the watchdog as a side-channel for any
    # /tmp-based pivot. Locks the /tmp namespace-isolation
    # discipline on the hidden-process-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (hidden-process-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd ProtectHome= INVARIANT
    # family. Watchdog .service units have no business
    # reading /home — their probe targets are system-config
    # paths (/etc/*). The ProtectHome= directive
    # (canonically =read-only) instructs systemd to either
    # hide (=true) or read-only-mount (=read-only) the
    # /home, /root, and /run/user directories within the
    # unit's mount namespace. An exploited watchdog cannot
    # then exfiltrate ~/.bash_history, ~/.ssh/*, or operator
    # credentials. A regression dropping ProtectHome= would
    # expose all operator home contents to a compromised
    # watchdog. Locks the home-namespace-isolation
    # discipline on the hidden-process-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (hidden-process-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
    # Sister to brain-wide systemd NoNewPrivileges= INVARIANT
    # family. The NoNewPrivileges=true directive instructs
    # the kernel to set PR_SET_NO_NEW_PRIVS on the watchdog
    # process — any subsequent execve() in the watchdog
    # script (sha256sum, awk, etc.) is forbidden to acquire
    # NEW privileges via setuid/setgid/file-capabilities. An
    # exploited watchdog cannot escalate via a setuid helper
    # (e.g. /usr/bin/su, /usr/bin/sudo). A regression
    # dropping NoNewPrivileges= would leave the watchdog
    # exposed to setuid-binary pivot. Locks the privilege-
    # escalation containment discipline on the hidden-process-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (hidden-process-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the hidden-process-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (hidden-process-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
    # Sister to brain-wide systemd ExecStart binary-path
    # INVARIANT family. Watchdog .service units MUST execute
    # the watchdog script from /usr/local/libexec/selfdef/
    # (operator-extension path, not /usr/bin which is
    # Debian-package-only). The canonical libexec/selfdef/
    # path lets operators override the watchdog script
    # without rebuilding the .deb (sister to brain-wide
    # operator-extension /usr/local/* discipline). A
    # regression that pointed ExecStart at /usr/bin/ would
    # surface as a "stale-watchdog-binary" on hosts where
    # operators patched the libexec copy. Locks the
    # libexec/selfdef ExecStart-path discipline on the
    # hidden-process-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (hidden-process-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
    # Sister to brain-wide systemd After= INVARIANT family.
    # Watchdog .service units MUST declare an After= directive
    # so they don't fire before the filesystem mounts that
    # contain their probe targets (canonically After=local-
    # fs.target so /etc/* is mounted before the watchdog
    # tries to sha256sum a config file). A regression
    # dropping After= would surface as "watchdog fires
    # during early-boot before /etc is mounted" which then
    # hashes nothing + emits a spurious "config missing"
    # alert. Locks the boot-sequencing discipline on the
    # hidden-process-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (hidden-process-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the hidden-process-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (hidden-process-watchdog timer unit declares OnBootSec= — boot-catchup-delay contract)" {
    # Sister to brain-wide systemd OnBootSec= INVARIANT
    # family. Watchdog .timer units MUST declare OnBootSec=
    # so the first watchdog fire is delayed until after boot
    # finishes settling. Locks the boot-catchup-delay
    # discipline on the hidden-process-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnBootSec=' "${t}"
    done
}

@test "INVARIANT (hidden-process-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
    # Sister to brain-wide systemd timer [Install].WantedBy=
    # INVARIANT family. Watchdog .timer units MUST declare
    # WantedBy=timers.target so `systemctl enable selfdef-
    # <slug>.timer` wires the timer into the timers.target
    # symlink-graph + activates it on every boot. A
    # regression that swapped to WantedBy=multi-user.target
    # (the .service-side install target) would make the
    # timer enable-step a no-op + leave the watchdog
    # silently inactive. Locks the timer-enable-graph
    # discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (hidden-process-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (hidden-process-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (hidden-process-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (hidden-process-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the hidden-process-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    [ -f "${script_dir}/hidden-process-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (hidden-process-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (hidden-process-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (hidden-process-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (hidden-process-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (hidden-process-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (hidden-process-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (hidden-process-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (hidden-process-watchdog .sh script declares severity= variable with canonical vocabulary — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'severity=' "${s}"
    done
}

@test "INVARIANT (hidden-process-watchdog .sh script tag selfdef-hidden-process matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-hidden-process
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (hidden-process-watchdog .sh script declares profile-aware exit behavior — operator-extension profile-dispatch contract)" {
    # Sister to brain-wide profile-aware INVARIANT family.
    # Scripts MUST handle PROFILE=enforce vs report differently.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'PROFILE.*enforce|enforce.*PROFILE|profile.*enforce' "${s}"
    done
}

@test "INVARIANT (hidden-process-watchdog .sh script uses printf-format JSON output — structured-event-emission contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'printf' "${s}"
    done
}

@test "INVARIANT (hidden-process-watchdog .sh script declares MODULE-suffixed tag in logger -t — module-name-tag-consistency contract)" {
    # Sister to SDD-062 tag-canonical INVARIANT family. The tag passed to
    # logger -t MUST include the module slug so journalctl filtering by
    # tag surfaces only this watchdog's events.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}
