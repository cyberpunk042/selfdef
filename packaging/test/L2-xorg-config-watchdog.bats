#!/usr/bin/env bats
# L2 bats functional tests for the xorg-config-watchdog scan script.
#
# On non-rootless setups the X server runs AS ROOT and loads modules (.so)
# from `Section "Files" -> ModulePath "<dir[,dir...]>"` and
# `Section "Module" -> Load "<module>"` in /etc/X11/xorg.conf and
# /etc/X11/xorg.conf.d/*.conf. A planted config with a ModulePath under a
# writable/attacker location loads attacker code into the root X server at
# the next server start (T1574 / T1547). Distinct Xorg quoted-directive
# grammar with comma-separated ModulePath dir lists.
#
# Runs the actual scan script with `logger` shadowed on PATH and the
# config + baseline in a tmp sandbox via SELFDEF_XORG_*; locks the
# `"severity":"alert"` token SDD-062 routes on + the D-6 fail-loud path.
#
# Run with: bats packaging/test/L2-xorg-config-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd/xorg-config-watchdog.sh"
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
    CONF="${TMP}/xorg.conf"
    EMPTY="${TMP}/empty"; mkdir -p "${EMPTY}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_XORG_PROFILE="${PROFILE:-report}" \
    SELFDEF_XORG_BASELINE="${BASELINE}" \
    SELFDEF_XORG_DIRS="${EMPTY}" \
    SELFDEF_XORG_FILES="${CONF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no xorg config present → ok / no_xorg_config" {
    run_wd
    cap | grep -q '"event":"no_xorg_config"'
    cap | grep -q '"severity":"ok"'
}

@test "benign ModulePath + Load, first run → ok / baseline_initial" {
    printf 'Section "Files"\n    ModulePath "/usr/lib/xorg/modules"\nEndSection\nSection "Module"\n    Load "glx"\nEndSection\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / xorg_config_intact" {
    printf 'Section "Files"\n    ModulePath "/usr/lib/xorg/modules"\nEndSection\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"xorg_config_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — the SDD-062 contract token
# ============================================================

@test "ModulePath under a writable root → alert" {
    printf 'Section "Files"\n    ModulePath "/tmp/xmods"\nEndSection\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "relative (non-absolute) ModulePath → alert" {
    printf 'Section "Files"\n    ModulePath "relmods"\nEndSection\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "comma-separated ModulePath with one writable dir → alert" {
    printf 'Section "Files"\n    ModulePath "/usr/lib/xorg/modules,/dev/shm/x"\nEndSection\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "bare writable root as ModulePath → alert (SDD-063 gap closed)" {
    # ModulePath "/tmp" itself (no trailing component) — previously missed
    # by the file helper; now caught by selfdef_is_writable_dir.
    printf 'Section "Files"\n    ModulePath "/tmp"\nEndSection\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "benign Load added after baseline → warn / xorg_config_changed" {
    printf 'Section "Module"\n    Load "glx"\nEndSection\n' > "${CONF}"
    run_wd
    printf 'Section "Module"\n    Load "glx"\n    Load "dri2"\nEndSection\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"xorg_config_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "ModulePath under /usr/lib and a named Load are NOT flagged" {
    printf 'Section "Files"\n    ModulePath "/usr/lib/xorg/modules"\nEndSection\nSection "Module"\n    Load "glx"\nEndSection\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a commented-out writable ModulePath line is NOT flagged" {
    printf 'Section "Files"\n#    ModulePath "/tmp/xmods"\n    ModulePath "/usr/lib/xorg/modules"\nEndSection\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile + SDD-061 D-6 fail-loud
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    printf 'Section "Files"\n    ModulePath "/tmp/xmods"\nEndSection\n' > "${CONF}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf 'Section "Files"\n    ModulePath "/usr/lib/xorg/modules"\nEndSection\n' > "${CONF}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# Writable-root expansion across all 3 common pivots
# ============================================================

@test "INVARIANT (ModulePath under /var/tmp): writable-root expansion on ModulePath axis" {
    printf 'Section "Files"\n    ModulePath "/var/tmp/xmods"\nEndSection\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (ModulePath under /dev/shm): writable-root expansion on ModulePath axis" {
    printf 'Section "Files"\n    ModulePath "/dev/shm/xmods"\nEndSection\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# SDD-063 bare-root variants
# ============================================================

@test "INVARIANT (bare /var/tmp as ModulePath): SDD-063 bare-root variant" {
    printf 'Section "Files"\n    ModulePath "/var/tmp"\nEndSection\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (bare /dev/shm as ModulePath): SDD-063 bare-root variant" {
    printf 'Section "Files"\n    ModulePath "/dev/shm"\nEndSection\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# xorg.conf.d drop-in axis (not only main /etc/X11/xorg.conf)
# ============================================================

@test "INVARIANT (xorg.conf.d drop-in axis: writable ModulePath in drop-in → alert; not only main xorg.conf scanned)" {
    # Attackers commonly plant a writable ModulePath in
    # /etc/X11/xorg.conf.d/00-evil.conf to avoid touching the main
    # xorg.conf (less visible). The watchdog must walk xorg.conf.d/
    # too.
    XCD="${TMP}/xorg.conf.d"
    mkdir -p "${XCD}"
    printf 'Section "Files"\n    ModulePath "/usr/lib/xorg/modules"\nEndSection\n' > "${CONF}"
    PATH="${BIN}:${PATH}" \
        SELFDEF_MODULE_LIB="${LIB}" \
        SELFDEF_XORG_PROFILE="${PROFILE:-report}" \
        SELFDEF_XORG_BASELINE="${BASELINE}" \
        SELFDEF_XORG_DIRS="${XCD}" \
        SELFDEF_XORG_FILES="${CONF}" \
        bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant the evil drop-in.
    printf 'Section "Files"\n    ModulePath "/tmp/evil"\nEndSection\n' > "${XCD}/00-evil.conf"
    PATH="${BIN}:${PATH}" \
        SELFDEF_MODULE_LIB="${LIB}" \
        SELFDEF_XORG_PROFILE="${PROFILE:-report}" \
        SELFDEF_XORG_BASELINE="${BASELINE}" \
        SELFDEF_XORG_DIRS="${XCD}" \
        SELFDEF_XORG_FILES="${CONF}" \
        bash "${WD}"
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# JSON record contract (SDD-062 single-line consumer)
# ============================================================

@test "INVARIANT (JSON record is emitted as a SINGLE main logger line — SDD-062 downstream JSON-line consumer contract)" {
    printf 'Section "Files"\n    ModulePath "/usr/lib/xorg/modules"\nEndSection\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-xorg-config -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): xorg-config-watchdog does NOT refresh baseline on suspicious-ModulePath detection — alert STAYS until operator updates" {
    # T1574/T1547 X-server root-exec module-load primitive — alert MUST
    # persist across runs until operator explicitly re-baselines.
    printf 'Section "Files"\n    ModulePath "/usr/lib/xorg/modules"\nEndSection\n' > "${CONF}"
    run_wd
    printf 'Section "Files"\n    ModulePath "/tmp/evil"\nEndSection\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (ModulePath under /home — user-writable hijack coverage)" {
    printf 'Section "Files"\n    ModulePath "/home/user/xmods"\nEndSection\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multiple comma-separated ModulePath dirs ALL evaluated: writable in middle position → alert)" {
    # Attacker may try to hide writable path in middle of comma-separated
    # list to evade naive first-or-last-only check. Lock that ALL positions
    # are evaluated.
    printf 'Section "Files"\n    ModulePath "/usr/lib/xorg/modules,/dev/shm/evil,/usr/lib/xorg/modules/extensions"\nEndSection\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (whitespace tolerance: 'ModulePath    \"/tmp/evil\"' multi-space variant still triggers alert)" {
    # Attacker may use multi-spaces between ModulePath and the path to
    # evade naive grep.
    printf 'Section "Files"\n    ModulePath    "/tmp/evil"\nEndSection\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable xorg.conf → alert): file mode IS architectural surface for X-server module-load hijack)" {
    # Sister to gss-mech / ld-preload / sudo-conf world-writable-config
    # axis already locked. Even if the xorg.conf content is benign,
    # world-writable file means any user can plant a malicious
    # ModulePath at next X server start — file mode is the
    # architectural surface, not just content. Locks coverage of
    # the world-writable file axis on the X-server module-load
    # surface (T1574 — Hijack Execution Flow via X-server module
    # load).
    printf 'Section "Files"\n    ModulePath "/usr/lib/xorg/modules"\nEndSection\n' > "${CONF}"
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (ModulePath under /home — user-writable hijack on X-server module-load axis)" {
    # Sister to many other watchdog's /home user-writable
    # INVARIANT across the brain. /home is the user-writable
    # surface — an attacker with regular user account can drop
    # a malicious X module .so into their home and have the X
    # server load it on next session start. T1574 — Hijack
    # Execution Flow via shared object substitution on the
    # graphical-session input path (X server runs with
    # graphical-display access; planted module gets keylogging
    # + screen-content read).
    printf 'Section "Files"\n  ModulePath "/home/user/.evil-xorg-modules"\nEndSection\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (ModulePath under /var/tmp — writable-root axis-symmetric expansion on X-server module-load surface)" {
    # Sister to /home + writable-ModulePath INVARIANTs already
    # locked. /var/tmp writable by ALL users + persists across
    # reboots. Closes /var/tmp axis on T1574 X-server module-
    # load Hijack Execution Flow surface — planted .so gets
    # graphical-display access (keylogging + screen-content).
    printf 'Section "Files"\n    ModulePath "/var/tmp/.evil-xorg-modules"\nEndSection\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (ModulePath under /dev/shm — tmpfs in-RAM writable-root axis-symmetric expansion on X-server module-load surface)" {
    # Sister to /home + /var/tmp ModulePath writable-root
    # INVARIANTs already locked. /dev/shm is tmpfs in-RAM
    # writable-root that survives no on-disk forensic trace.
    # X-server loads modules from ModulePath AS ROOT (Xorg
    # historically runs setuid root for input access).
    # Planted .so in /dev/shm gets graphical-display access
    # — keylogging + screen-content capture. T1574 Hijack
    # Execution Flow via X-server module-load.
    printf 'Section "Files"\n    ModulePath "/dev/shm/.evil-xorg-modules"\nEndSection\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on xorg-config surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The xorg-config-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1574 Hijack Execution Flow via X-server
    # module-load alert. Locks parser contract on the xorg.conf
    # ModulePath detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'Section "Files"\n    ModulePath "/usr/lib/xorg/modules"\nEndSection\n' > "${CONF}"
    run_wd                                              # ok path
    printf 'Section "Files"\n    ModulePath "/tmp/.evil"\nEndSection\n' > "${CONF}"
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: xorg-config-watchdog NEVER deletes xorg.conf entries — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # xorg-config-watchdog DETECTS T1574 Hijack Execution Flow
    # via X-server module-load but MUST NEVER emit sed/awk/rm
    # commands to auto-clean the ModulePath directive. The
    # detected ModulePath may be operator-legitimate (custom
    # video driver path, X11 keyboard layout extension dir).
    # Silent auto-delete would destroy operator baseline state
    # AND could break the X display server entirely.
    # Surveillance, never remediation. Locks anti-data-loss
    # contract on the xorg-config surveillance substrate.
    printf 'Section "Files"\n    ModulePath "/tmp/.evil"\nEndSection\n' > "${CONF}"
    run_wd
    [ -f "${CONF}" ]
    grep -q 'ModulePath' "${CONF}"
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*sed[[:space:]]+-i.*xorg'
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*find[[:space:]].*-delete'
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # xorg-config-watchdog runs ON the timer's scheduled fire —
    # scans /etc/X11/xorg.conf + xorg.conf.d for ModulePath +
    # LoadModule entries in writable roots, emits a verdict,
    # then exits. Type=simple would break timer OnUnitActiveSec
    # semantics. Locks oneshot-probe contract on the xorg-
    # config-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd/selfdef-xorg-config.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. xorg-config-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # xorg-config-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # xorg-config-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'xorg-config-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: xorg-config-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. xorg-config-watchdog is a DETECT-only watchdog: surveils +
    # emits verdicts, NEVER writes back. Locks no-auto-fix on
    # the xorg-config-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (xorg-config-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the xorg-config-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (xorg-config-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # xorg-config-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (xorg-config-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # xorg-config-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (xorg-config-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the xorg-config-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (xorg-config-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # xorg-config-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (xorg-config-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the xorg-config-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (xorg-config-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the xorg-config-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (xorg-config-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # xorg-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (xorg-config-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the xorg-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (xorg-config-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the xorg-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (xorg-config-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the xorg-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (xorg-config-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the xorg-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (xorg-config-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the xorg-config-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (xorg-config-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the xorg-config-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (xorg-config-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # xorg-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (xorg-config-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # xorg-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (xorg-config-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the xorg-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (xorg-config-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the xorg-config-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (xorg-config-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (xorg-config-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (xorg-config-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (xorg-config-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (xorg-config-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the xorg-config-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/xorg-config-watchdog/systemd"
    [ -f "${script_dir}/xorg-config-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}
