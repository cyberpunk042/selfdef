#!/usr/bin/env bats
# L2 functional + capture-regression suite for ssh-authkeys-watchdog.
#
# ssh-authkeys-watchdog is the MITRE T1098.004 sentry — the single most common
# Linux persistence vector is dropping a key into a user's authorized_keys. It
# hashes the base64 key body (comment-independent) of every user's
# authorized_keys{,2} + the central authorized_keys.d into a baseline, then
# alerts on an added key. It reads /etc/passwd homes directly (no input-source
# knob), so to exercise capture deterministically this suite PLANTS a fixture
# key in the current user's own authorized_keys (only when none pre-exists —
# it never clobbers a real file) and asserts the scan captured it.
#
# This is the regression lock for the 2026-05-27 bug where `emit_keys`'s
# `printf` went to stdout instead of `$current`, leaving the baseline empty so
# a newly-added authorized key was NEVER detected.
#
# Run with: bats packaging/test/L2-ssh-authkeys-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd/ssh-authkeys-watchdog.sh"
FIXTURE_KEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISELFDEFL2FIXTUREkeyDoNotTrust selfdef-l2-fixture'

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
    BASELINE="${TMP}/ssh-authkeys-baseline.tsv"
    PLANTED=""        # path we created (removed in teardown); empty = none
    PLANTED_DIR=""    # .ssh dir we created (removed in teardown); empty = none
}

teardown() {
    # Restore the real home to its prior state — only remove what WE created.
    [ -n "${PLANTED}" ] && rm -f "${PLANTED}"
    [ -n "${PLANTED_DIR}" ] && rmdir "${PLANTED_DIR}" 2>/dev/null || true
    rm -rf "${TMP}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_AUTHKEYS_PROFILE="${PROFILE:-report}" \
    SELFDEF_AUTHKEYS_BASELINE="${BASELINE}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# Plant a fixture authorized_keys in the current user's passwd home — the exact
# path the watchdog reads — but ONLY if it can do so without clobbering a real
# file. Sets PLANTED on success; skips the test otherwise.
plant_fixture() {
    local home
    home="$(getent passwd "$(id -un)" 2>/dev/null | cut -d: -f6)"
    [ -n "${home}" ] && [ -d "${home}" ] && [ -w "${home}" ] \
        || skip "current user's home not writable — cannot plant fixture"
    local ak="${home}/.ssh/authorized_keys"
    [ -e "${ak}" ] && skip "real authorized_keys present — refusing to clobber"
    if [ ! -d "${home}/.ssh" ]; then
        mkdir -p "${home}/.ssh" || skip "cannot create ${home}/.ssh"
        PLANTED_DIR="${home}/.ssh"
    fi
    printf '%s\n' "${FIXTURE_KEY}" > "${ak}" || skip "cannot write fixture key"
    PLANTED="${ak}"
}

@test "first run captures the planted authorized key into the baseline" {
    plant_fixture
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -s "${BASELINE}" ]                                  # capture regression lock
    # The planted key's record is <user>\t<file>\t<fp> — at least one TSV row,
    # and the count must reflect it (baseline_count:0 was the bug's symptom).
    awk -F'\t' 'NF>=3{ok=1} END{exit ok?0:1}' "${BASELINE}"
    cap | grep -qE '"baseline_count":[1-9][0-9]*'
}

@test "re-adding the same key on a second run -> ok / no_delta (stable hash)" {
    plant_fixture
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}
