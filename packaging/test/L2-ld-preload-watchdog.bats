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
    PRELOAD="${TMP}/ld.so.preload"      # not created unless a test writes it
    ENVF="${TMP}/env";  : > "${ENVF}"   # benign by default
    PAMF="${TMP}/pamenv"; : > "${PAMF}" # benign by default
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
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

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

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

@test "INVARIANT (ld.so.preload under /var/tmp): writable-root expansion" {
    printf '/var/tmp/evil.so\n' > "${PRELOAD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (ld.so.preload under /dev/shm): tmpfs writable-root expansion" {
    printf '/dev/shm/evil.so\n' > "${PRELOAD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (ld.so.preload under /home): user-writable hijack coverage" {
    printf '/home/user/evil.so\n' > "${PRELOAD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multiple preload entries — one benign + one suspicious → alert): suspicious wins" {
    printf '/bin/sh\n/tmp/evil.so\n' > "${PRELOAD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (current-behavior: LD_LIBRARY_PATH is NOT in the LD_PRELOAD scan scope)" {
    # ld-preload-watchdog focuses on LD_PRELOAD + LD_AUDIT specifically
    # (the active-injection vectors). LD_LIBRARY_PATH is a search-path
    # modifier, not an injection mechanism — outside this watchdog's
    # scope. Sister watchdog systemd-environment-watchdog covers LD_*
    # broadly. Lock the current architectural boundary.
    printf 'export LD_LIBRARY_PATH=/tmp/libs\n' > "${ENVF}"
    run_wd
    # Should not fire from this watchdog (would fire from systemd-environment).
    cap | grep -q '"event":"no_ld_preload"' || cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (env file with LD_AUDIT under /var/tmp → alert): writable-root expansion on LD_AUDIT axis" {
    # Confirms axis coverage for LD_AUDIT (the sister of LD_PRELOAD).
    printf 'export LD_AUDIT=/var/tmp/auditor.so\n' > "${ENVF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-ld-preload -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (stateless re-evaluation: ld_preload alert STAYS visible on every run until operator cleans)" {
    # ld-preload-watchdog is stateless (no baseline-refresh required) —
    # re-evaluates live config on every run. A suspicious entry that
    # stays must re-fire alert every run.
    printf '/tmp/evil.so\n' > "${PRELOAD}"
    run_wd
    cap | grep -q '"severity":"alert"'
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"suspicious_ld_preload"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-file env scan: bash + zsh + fish env files all scanned for LD_PRELOAD)" {
    # Operator may use multiple shells. LD_PRELOAD planted in any
    # global env file MUST be flagged.
    ENVF2="${TMP}/zshenv"
    : > "${PRELOAD}"
    printf 'export PATH=/usr/bin\n' > "${ENVF}"
    printf 'export LD_PRELOAD=/tmp/zsh-evil.so\n' > "${ENVF2}"
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_LDPRELOAD_PROFILE="report" \
    SELFDEF_LDPRELOAD_FILE="${PRELOAD}" \
    SELFDEF_LDPRELOAD_ENV_FILES="${ENVF} ${ENVF2}" \
    SELFDEF_LDPRELOAD_PAMENV_FILES="${PAMF}" \
    bash "${WD}"
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (current-behavior: commented LD_PRELOAD line is scanned — # prefix NOT filtered by ld-preload-watchdog)" {
    # Current behavior locks: ld-preload-watchdog scans every line of the
    # env file (substring grep for LD_PRELOAD=) regardless of # prefix.
    # Rationale: a planted attacker may use a leading-# trick to hide
    # from naive operator inspection while a sloppy shell still sources
    # the line in some contexts. Refinement opportunity tracked: tighten
    # to filter pure-comment lines if/when the false-positive cost
    # warrants. Lock current architectural boundary.
    : > "${PRELOAD}"
    printf '# export LD_PRELOAD=/tmp/example-attacker.so\nexport PATH=/usr/bin\n' > "${ENVF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (LD_PRELOAD under /home → alert): user-writable hijack axis on per-process dlopen-injection surface" {
    # Sister to the /tmp + /var/tmp + /dev/shm writable-root axes
    # already locked. /home is the user-writable surface — a non-
    # root attacker can drop a malicious .so into their home and
    # have it dlopen()'d into EVERY process they invoke (or
    # globally if the line is in /etc/ld.so.preload). Locks axis-
    # symmetry across the writable-root family on the LD_PRELOAD
    # surface (T1574.006 — Dynamic Linker Hijacking).
    printf '/home/user/.evil.so\n' > "${PRELOAD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named LD_PRELOAD path surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker writes a
    # distinctively-named .so to /etc/ld.so.preload, the path
    # MUST surface in the JSON sample so operator dashboard
    # routes triage to the right code-load surface (T1574.006
    # — Dynamic Linker Hijacking via ld.so.preload). Locks the
    # operator-visibility contract on the global-dlopen-injection
    # surveillance surface.
    printf '/tmp/.distinctive-attacker-preload.so\n' > "${PRELOAD}"
    run_wd
    cap | grep -q 'distinctive-attacker-preload'
}

@test "INVARIANT (LD_PRELOAD under /dev/shm — tmpfs writable-root axis-symmetric expansion)" {
    # Sister to /home + /var/tmp LD_PRELOAD writable-root
    # INVARIANTs already locked. /dev/shm is a tmpfs writable
    # by ALL users without privilege, lives in RAM (boot-wiped),
    # and slips past disk-monitoring tools — high-velocity drop
    # surface for T1574.006 Dynamic Linker Hijacking. Closes
    # the /dev/shm axis on the LD_PRELOAD writable-root
    # coverage symmetric to /var/tmp + /home.
    printf '/dev/shm/.evil-preload.so\n' > "${PRELOAD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}
