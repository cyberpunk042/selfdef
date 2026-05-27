#!/usr/bin/env bats
# L2 bats functional tests for the ld-preload-watchdog scan script.
#
# The canonical userland-rootkit injection surface. A stateless scanner
# (no baseline) over four surfaces: (1) /etc/ld.so.preload, (2) global
# LD_PRELOAD / LD_AUDIT in shell env files, (3) pam_env
# (LD_PRELOAD DEFAULT=/...), and (4) preload libs under writable/tmp paths
# or a non-existent (deleted-after-load) path. Severity: warn = a preload
# present at a trusted path; alert = a preload under a writable root OR a
# non-existent lib (classic rootkit).
#
# Exercises the actual scan script with `logger` shadowed on PATH and all
# scanned paths pointed at a tmp sandbox via the SELFDEF_LDPRELOAD_* seams.
#
# Run with: bats packaging/test/L2-ld-preload-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/ld-preload-watchdog/systemd/ld-preload-watchdog.sh"

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
    PRELOAD="${TMP}/ld.so.preload"      # not created unless a test writes it
    ENVF="${TMP}/env";  : > "${ENVF}"   # benign by default
    PAMF="${TMP}/pamenv"; : > "${PAMF}" # benign by default
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_LDPRELOAD_PROFILE="${PROFILE:-report}" \
    SELFDEF_LDPRELOAD_FILE="${PRELOAD}" \
    SELFDEF_LDPRELOAD_ENV_FILES="${ENVF}" \
    SELFDEF_LDPRELOAD_PAMENV_FILES="${PAMF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "nothing preloaded → ok / no_ld_preload" {
    run_wd
    cap | grep -q '"event":"no_ld_preload"'
    cap | grep -q '"severity":"ok"'
}

@test "benign env file without LD_PRELOAD → ok" {
    printf 'PATH=/usr/bin:/bin\nEDITOR=vi\n' > "${ENVF}"
    run_wd
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# warn tier — a preload present at a trusted, existing path
# ============================================================

@test "ld.so.preload entry at a trusted existing path → warn / ld_preload_present" {
    # /bin/sh exists and is not under a writable root → present, not suspicious.
    printf '/bin/sh\n' > "${PRELOAD}"
    run_wd
    cap | grep -q '"event":"ld_preload_present"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# alert tier
# ============================================================

@test "ld.so.preload lib under a writable root → alert / suspicious_ld_preload" {
    printf '/tmp/evil.so\n' > "${PRELOAD}"
    run_wd
    cap | grep -q '"event":"suspicious_ld_preload"'
    cap | grep -q '"severity":"alert"'
}

@test "ld.so.preload lib that does not exist (deleted-after-load rootkit) → alert" {
    printf '/usr/lib/nonexistent-rootkit.so\n' > "${PRELOAD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "global LD_PRELOAD in an env file pointing under a writable root → alert" {
    printf 'export LD_PRELOAD=/dev/shm/evil.so\n' > "${ENVF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "global LD_AUDIT in an env file pointing under a writable root → alert" {
    printf 'export LD_AUDIT=/tmp/auditor.so\n' > "${ENVF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "pam_env LD_PRELOAD DEFAULT pointing under a writable root → alert" {
    printf 'LD_PRELOAD DEFAULT=/tmp/pam-evil.so\n' > "${PAMF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "an empty ld.so.preload + benign env are NOT flagged" {
    : > "${PRELOAD}"
    printf 'umask 022\n' > "${ENVF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    printf '/tmp/evil.so\n' > "${PRELOAD}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits zero when nothing is preloaded" {
    PROFILE=enforce run run_wd
    [ "${status}" -eq 0 ]
}
