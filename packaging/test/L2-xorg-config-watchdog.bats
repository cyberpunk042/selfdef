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
