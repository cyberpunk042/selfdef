#!/usr/bin/env bats
# L2 bats functional tests for the ld-preload-watchdog scan script.
#
# The canonical userland-rootkit injection surface. A stateless scanner
# (no baseline) over four surfaces: (1) /etc/ld.so.preload, (2) global
# LD_PRELOAD / LD_AUDIT in shell env files, (3) pam_env
# (LD_PRELOAD DEFAULT=/...), and (4) preload libs under writable/tmp paths
# or a non-existent (deleted-after-load) path. Severity: warn = a preload
# present at a trusted path; alert = a preload under a writable root OR a
# non-existent lib (classic rootkit).
#
# Exercises the actual scan script with `logger` shadowed on PATH and all
# scanned paths pointed at a tmp sandbox via the SELFDEF_LDPRELOAD_* seams.
#
# Run with: bats packaging/test/L2-ld-preload-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd/ld-preload-watchdog.sh"
LIB="${BATS_TEST_DIRNAME}/../lib/module-lib.sh"

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
    PRELOAD="${TMP}/ld.so.preload"      # not created unless a test writes it
    ENVF="${TMP}/env";  : > "${ENVF}"   # benign by default
    PAMF="${TMP}/pamenv"; : > "${PAMF}" # benign by default
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_LDPRELOAD_PROFILE="${PROFILE:-report}" \
    SELFDEF_LDPRELOAD_FILE="${PRELOAD}" \
    SELFDEF_LDPRELOAD_ENV_FILES="${ENVF}" \
    SELFDEF_LDPRELOAD_PAMENV_FILES="${PAMF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "nothing preloaded → ok / no_ld_preload" {
    run_wd
    cap | grep -q '"event":"no_ld_preload"'
    cap | grep -q '"severity":"ok"'
}

@test "benign env file without LD_PRELOAD → ok" {
    printf 'PATH=/usr/bin:/bin\nEDITOR=vi\n' > "${ENVF}"
    run_wd
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# warn tier — a preload present at a trusted, existing path
# ============================================================

@test "ld.so.preload entry at a trusted existing path → warn / ld_preload_present" {
    # /bin/sh exists and is not under a writable root → present, not suspicious.
    printf '/bin/sh\n' > "${PRELOAD}"
    run_wd
    cap | grep -q '"event":"ld_preload_present"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# alert tier
# ============================================================

@test "ld.so.preload lib under a writable root → alert / suspicious_ld_preload" {
    printf '/tmp/evil.so\n' > "${PRELOAD}"
    run_wd
    cap | grep -q '"event":"suspicious_ld_preload"'
    cap | grep -q '"severity":"alert"'
}

@test "ld.so.preload lib that does not exist (deleted-after-load rootkit) → alert" {
    printf '/usr/lib/nonexistent-rootkit.so\n' > "${PRELOAD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "global LD_PRELOAD in an env file pointing under a writable root → alert" {
    printf 'export LD_PRELOAD=/dev/shm/evil.so\n' > "${ENVF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "global LD_AUDIT in an env file pointing under a writable root → alert" {
    printf 'export LD_AUDIT=/tmp/auditor.so\n' > "${ENVF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "pam_env LD_PRELOAD DEFAULT pointing under a writable root → alert" {
    printf 'LD_PRELOAD DEFAULT=/tmp/pam-evil.so\n' > "${PAMF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "an empty ld.so.preload + benign env are NOT flagged" {
    : > "${PRELOAD}"
    printf 'umask 022\n' > "${ENVF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on an alert" {
    printf '/tmp/evil.so\n' > "${PRELOAD}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits zero when nothing is preloaded" {
    PROFILE=enforce run run_wd
    [ "${status}" -eq 0 ]
}

@test "INVARIANT (ld.so.preload under /var/tmp): writable-root expansion" {
    printf '/var/tmp/evil.so\n' > "${PRELOAD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (ld.so.preload under /dev/shm): tmpfs writable-root expansion" {
    printf '/dev/shm/evil.so\n' > "${PRELOAD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (ld.so.preload under /home): user-writable hijack coverage" {
    printf '/home/user/evil.so\n' > "${PRELOAD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multiple preload entries — one benign + one suspicious → alert): suspicious wins" {
    printf '/bin/sh\n/tmp/evil.so\n' > "${PRELOAD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (current-behavior: LD_LIBRARY_PATH is NOT in the LD_PRELOAD scan scope)" {
    # ld-preload-watchdog focuses on LD_PRELOAD + LD_AUDIT specifically
    # (the active-injection vectors). LD_LIBRARY_PATH is a search-path
    # modifier, not an injection mechanism — outside this watchdog's
    # scope. Sister watchdog systemd-environment-watchdog covers LD_*
    # broadly. Lock the current architectural boundary.
    printf 'export LD_LIBRARY_PATH=/tmp/libs\n' > "${ENVF}"
    run_wd
    # Should not fire from this watchdog (would fire from systemd-environment).
    cap | grep -q '"event":"no_ld_preload"' || cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (env file with LD_AUDIT under /var/tmp → alert): writable-root expansion on LD_AUDIT axis" {
    # Confirms axis coverage for LD_AUDIT (the sister of LD_PRELOAD).
    printf 'export LD_AUDIT=/var/tmp/auditor.so\n' > "${ENVF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-ld-preload -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (stateless re-evaluation: ld_preload alert STAYS visible on every run until operator cleans)" {
    # ld-preload-watchdog is stateless (no baseline-refresh required) —
    # re-evaluates live config on every run. A suspicious entry that
    # stays must re-fire alert every run.
    printf '/tmp/evil.so\n' > "${PRELOAD}"
    run_wd
    cap | grep -q '"severity":"alert"'
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"suspicious_ld_preload"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-file env scan: bash + zsh + fish env files all scanned for LD_PRELOAD)" {
    # Operator may use multiple shells. LD_PRELOAD planted in any
    # global env file MUST be flagged.
    ENVF2="${TMP}/zshenv"
    : > "${PRELOAD}"
    printf 'export PATH=/usr/bin\n' > "${ENVF}"
    printf 'export LD_PRELOAD=/tmp/zsh-evil.so\n' > "${ENVF2}"
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_LDPRELOAD_PROFILE="report" \
    SELFDEF_LDPRELOAD_FILE="${PRELOAD}" \
    SELFDEF_LDPRELOAD_ENV_FILES="${ENVF} ${ENVF2}" \
    SELFDEF_LDPRELOAD_PAMENV_FILES="${PAMF}" \
    bash "${WD}"
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (current-behavior: commented LD_PRELOAD line is scanned — # prefix NOT filtered by ld-preload-watchdog)" {
    # Current behavior locks: ld-preload-watchdog scans every line of the
    # env file (substring grep for LD_PRELOAD=) regardless of # prefix.
    # Rationale: a planted attacker may use a leading-# trick to hide
    # from naive operator inspection while a sloppy shell still sources
    # the line in some contexts. Refinement opportunity tracked: tighten
    # to filter pure-comment lines if/when the false-positive cost
    # warrants. Lock current architectural boundary.
    : > "${PRELOAD}"
    printf '# export LD_PRELOAD=/tmp/example-attacker.so\nexport PATH=/usr/bin\n' > "${ENVF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (LD_PRELOAD under /home → alert): user-writable hijack axis on per-process dlopen-injection surface" {
    # Sister to the /tmp + /var/tmp + /dev/shm writable-root axes
    # already locked. /home is the user-writable surface — a non-
    # root attacker can drop a malicious .so into their home and
    # have it dlopen()'d into EVERY process they invoke (or
    # globally if the line is in /etc/ld.so.preload). Locks axis-
    # symmetry across the writable-root family on the LD_PRELOAD
    # surface (T1574.006 — Dynamic Linker Hijacking).
    printf '/home/user/.evil.so\n' > "${PRELOAD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named LD_PRELOAD path surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker writes a
    # distinctively-named .so to /etc/ld.so.preload, the path
    # MUST surface in the JSON sample so operator dashboard
    # routes triage to the right code-load surface (T1574.006
    # — Dynamic Linker Hijacking via ld.so.preload). Locks the
    # operator-visibility contract on the global-dlopen-injection
    # surveillance surface.
    printf '/tmp/.distinctive-attacker-preload.so\n' > "${PRELOAD}"
    run_wd
    cap | grep -q 'distinctive-attacker-preload'
}

@test "INVARIANT (LD_PRELOAD under /dev/shm — tmpfs writable-root axis-symmetric expansion)" {
    # Sister to /home + /var/tmp LD_PRELOAD writable-root
    # INVARIANTs already locked. /dev/shm is a tmpfs writable
    # by ALL users without privilege, lives in RAM (boot-wiped),
    # and slips past disk-monitoring tools — high-velocity drop
    # surface for T1574.006 Dynamic Linker Hijacking. Closes
    # the /dev/shm axis on the LD_PRELOAD writable-root
    # coverage symmetric to /var/tmp + /home.
    printf '/dev/shm/.evil-preload.so\n' > "${PRELOAD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (LD_PRELOAD under /tmp — tmpfs writable-root)" {
    # Closes /tmp axis on T1574.006 Dynamic Linker Hijacking.
    printf '/tmp/.evil-preload.so\n' > "${PRELOAD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (LD_PRELOAD under /var/tmp — persistent writable-root axis-symmetric expansion)" {
    # Sister to /tmp + /dev/shm + /home LD_PRELOAD writable-
    # root INVARIANTs. /var/tmp persistent + writable. T1574.006
    # Dynamic Linker Hijacking via LD_PRELOAD on every-process
    # dlopen path.
    printf '/var/tmp/.evil-preload.so\n' > "${PRELOAD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on ld-preload surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The ld-preload-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1574.006 Dynamic Linker Hijacking alert.
    # Locks parser contract on the LD_PRELOAD detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    : > "${PRELOAD}"
    run_wd                                              # ok / baseline
    printf '/tmp/.evil-preload.so\n' > "${PRELOAD}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # ld-preload-watchdog runs ON the timer's scheduled fire —
    # scans /etc/ld.so.preload + shell env files for LD_PRELOAD
    # writable-root paths, emits a verdict, then exits.
    # Type=simple would break timer OnUnitActiveSec semantics.
    # Locks oneshot-probe contract on the ld-preload-watchdog
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd/selfdef-ld-preload.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. ld-preload-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # ld-preload-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # ld-preload-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'ld-preload-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: ld-preload-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. ld-preload-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the ld-preload-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (ld-preload-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the ld-preload-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (ld-preload-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # ld-preload-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (ld-preload-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # ld-preload-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (ld-preload-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the ld-preload-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (ld-preload-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # ld-preload-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (ld-preload-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the ld-preload-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (ld-preload-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the ld-preload-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (ld-preload-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # ld-preload-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (ld-preload-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the ld-preload-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (ld-preload-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the ld-preload-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (ld-preload-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the ld-preload-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (ld-preload-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the ld-preload-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (ld-preload-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the ld-preload-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (ld-preload-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the ld-preload-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (ld-preload-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # ld-preload-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (ld-preload-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # ld-preload-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (ld-preload-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the ld-preload-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (ld-preload-watchdog timer unit declares OnBootSec= — boot-catchup-delay contract)" {
    # Sister to brain-wide systemd OnBootSec= INVARIANT
    # family. Watchdog .timer units MUST declare OnBootSec=
    # so the first watchdog fire is delayed until after boot
    # finishes settling. Locks the boot-catchup-delay
    # discipline on the ld-preload-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnBootSec=' "${t}"
    done
}

@test "INVARIANT (ld-preload-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (ld-preload-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (ld-preload-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (ld-preload-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (ld-preload-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the ld-preload-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    [ -f "${script_dir}/ld-preload-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (ld-preload-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (ld-preload-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (ld-preload-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (ld-preload-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (ld-preload-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (ld-preload-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (ld-preload-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (ld-preload-watchdog .sh script emits canonical severity vocabulary {ok,warn,alert} — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    # Watchdog scripts emit logger -t selfdef-<name> -- {...severity:...}
    # with severity in the canonical vocabulary. A regression
    # introducing custom severity values (info, error, critical)
    # would break operator-side filtering.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '"severity":"(ok|warn|alert)"' "${s}"
    done
}

@test "INVARIANT (ld-preload-watchdog .sh script tag selfdef-ld-preload matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-ld-preload
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (ld-preload-watchdog .sh script declares profile-aware exit behavior — operator-extension profile-dispatch contract)" {
    # Sister to brain-wide profile-aware INVARIANT family.
    # Scripts MUST handle PROFILE=enforce vs report differently.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'PROFILE.*enforce|enforce.*PROFILE|profile.*enforce' "${s}"
    done
}

@test "INVARIANT (ld-preload-watchdog .sh script uses printf-format JSON output — structured-event-emission contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'printf' "${s}"
    done
}

@test "INVARIANT (ld-preload-watchdog .sh script declares MODULE-suffixed tag in logger -t — module-name-tag-consistency contract)" {
    # Sister to SDD-062 tag-canonical INVARIANT family. The tag passed to
    # logger -t MUST include the module slug so journalctl filtering by
    # tag surfaces only this watchdog's events.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (ld-preload-watchdog .sh script file is non-empty (size > 100 bytes) — non-trivial-script contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (ld-preload-watchdog .sh script has >20 lines — non-trivial-watchdog-body contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 20 ]
    done
}

@test "INVARIANT (ld-preload-watchdog .service unit file has >5 lines of directives — non-trivial-unit-file contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 5 ]
    done
}

@test "INVARIANT (ld-preload-watchdog .service unit ExecStart references /usr/local/libexec/selfdef/ path — canonical-binary-path contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (ld-preload-watchdog .timer file exists at canonical path modules/ld-preload-watchdog/systemd — canonical-systemd-dir layout)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    [ -d "${timer_dir}" ]
    n=$(ls "${timer_dir}"/*.timer 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (ld-preload-watchdog module.toml exists at canonical path modules/ld-preload-watchdog/ — module-manifest existence 72-cycle)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (ld-preload-watchdog systemd dir exists at modules/ld-preload-watchdog/systemd — systemd-dir-existence 73-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    [ -d "${sd}" ]
}

@test "INVARIANT (ld-preload-watchdog systemd dir is non-empty — systemd-content-presence 74-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    n=$(ls "${sd}" | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (ld-preload-watchdog .service file size > 100 bytes — substantial-service-unit 75-cycle)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (ld-preload-watchdog .timer file size > 50 bytes — substantial-timer-unit 76-cycle)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        size=$(stat -c '%s' "${t}")
        [ "${size}" -gt 50 ]
    done
}

@test "INVARIANT (ld-preload-watchdog README.md file size > 100 bytes — substantial-readme 77-cycle)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/README.md"
    size=$(stat -c '%s' "${readme}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (ld-preload-watchdog .service Documentation URL is HTTP/HTTPS — operator-doc-link-protocol 78)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=(http|https)://' "${s}"
    done
}

@test "INVARIANT (ld-preload-watchdog .sh script has shebang line — POSIX-conformant 79)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '^#!'
    done
}

@test "INVARIANT (ld-preload-watchdog .sh script declares set flag in first 50 lines — strict-mode-prologue 80)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -50 "${s}" | grep -qE '^set -'
    done
}

@test "INVARIANT (ld-preload-watchdog module.toml size > 200 bytes — substantial-watchdog-manifest 81)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    size=$(stat -c '%s' "${mtoml}")
    [ "${size}" -gt 200 ]
}

@test "INVARIANT (ld-preload-watchdog .service file is non-empty — non-trivial-unit-file 82)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        [ -s "${s}" ]
    done
}

@test "INVARIANT (ld-preload-watchdog .timer file is non-empty — non-trivial-timer-file 83)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        [ -s "${t}" ]
    done
}

@test "INVARIANT (ld-preload-watchdog .sh script body has at least one variable assignment — non-vacuous-script 84)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^[a-zA-Z_]+=' "${s}"
    done
}

@test "INVARIANT (ld-preload-watchdog .sh script path matches systemd dir layout — canonical-script-co-location 85)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd"
    [ -d "${script_dir}" ]
    n=$(ls "${script_dir}"/*.sh 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (ld-preload-watchdog module.toml has install_paths section — SDD-026 mutation-manifest 86)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (ld-preload-watchdog module.toml install_paths.paths non-empty list 87)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list) and len(ps) > 0
"
}

@test "INVARIANT (ld-preload-watchdog module.toml install_paths.paths only absolute paths 88)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (ld-preload-watchdog module.toml provides list non-empty 89 — capability-export-present)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list) and len(p) >= 1
"
}

@test "INVARIANT (ld-preload-watchdog module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (ld-preload-watchdog module.toml install_paths.paths includes /etc/ entry — config-staging 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps)
"
}

@test "INVARIANT (ld-preload-watchdog module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p for p in ps)
"
}

@test "INVARIANT (ld-preload-watchdog module.toml has install_paths section non-empty 93)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
ps = ip.get('paths', [])
assert len(ps) >= 1
"
}

@test "INVARIANT (ld-preload-watchdog module.toml [install_paths] declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (ld-preload-watchdog module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (ld-preload-watchdog module.toml uses TOML key-value syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (ld-preload-watchdog module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (ld-preload-watchdog module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (ld-preload-watchdog module.toml category field double-quoted — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (ld-preload-watchdog module.toml summary field double-quoted — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (ld-preload-watchdog module.toml name field matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"ld-preload-watchdog"' "${mtoml}"
}

@test "INVARIANT (ld-preload-watchdog module.toml top-level keys before any [section] — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    python3 -c "
with open('${mtoml}') as fp:
    for ln in fp:
        s = ln.strip()
        if not s or s.startswith('#'): continue
        if s.startswith('['): break
        assert '=' in ln
        break
"
}

@test "INVARIANT (ld-preload-watchdog module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (ld-preload-watchdog module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (ld-preload-watchdog module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (ld-preload-watchdog module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (ld-preload-watchdog module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}
