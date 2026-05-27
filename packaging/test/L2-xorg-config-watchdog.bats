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
