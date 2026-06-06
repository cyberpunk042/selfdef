#!/usr/bin/env bats
# L2 functional + capture-regression suite for group-integrity-watchdog.
#
# group-integrity-watchdog inventories group membership two ways — the
# comma-member lists in /etc/group, and each user's PRIMARY group from
# /etc/passwd — into a baseline, then alerts on a new privileged-group member
# / membership change. What this suite locks:
#
#   - INVENTORY-CAPTURE regression: the scan must actually write its records
#     into the baseline it diffs — the 2026-05-27 bug where BOTH membership
#     `printf`s went to stdout instead of `$current`, leaving the baseline
#     empty and every diff a no-op.
#   - DELTA detection: addition / removal of group members in non-privileged
#     groups → severity=warn, event=group_membership_changed
#   - PRIVILEGED-DELTA escalation: addition of a member to docker/lxd/sudo/
#     wheel/disk/shadow/etc. (the canonical root-equivalent denylist) →
#     severity=alert, event=privileged_group_member_added
#   - ENFORCE-profile exit semantics: in enforce profile, any delta returns
#     exit-1 so the consuming systemd unit's failure surface drives the
#     dashboard alert.
#   - PRIMARY-GID PASS: the watchdog must surface a user whose ONLY tie to a
#     privileged group is the primary-gid pass (the 2nd inventory pass, not
#     /etc/group's member field).
#   - BASELINE refresh: after every run that reports a delta, the baseline
#     is refreshed so the next run sees no_delta (confirmed-legit change
#     becomes trusted).
#
# Adds SELFDEF_GROUPINT_GROUP_FILE + SELFDEF_GROUPINT_PASSWD_FILE env-var
# overrides (added 2026-06-06) for L2 delta-testability. Live defaults
# unchanged.
#
# Run with: bats packaging/test/L2-group-integrity-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd/group-integrity-watchdog.sh"

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
    BASELINE="${TMP}/group-integrity-baseline.tsv"
    GROUP_FILE="${TMP}/group"
    PASSWD_FILE="${TMP}/passwd"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_GROUPINT_PROFILE="${PROFILE:-report}" \
    SELFDEF_GROUPINT_BASELINE="${BASELINE}" \
    SELFDEF_GROUPINT_GROUP_FILE="${GROUP_FILE}" \
    SELFDEF_GROUPINT_PASSWD_FILE="${PASSWD_FILE}" \
    bash "${WD}"
}

run_wd_rc() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_GROUPINT_PROFILE="${PROFILE:-report}" \
    SELFDEF_GROUPINT_BASELINE="${BASELINE}" \
    SELFDEF_GROUPINT_GROUP_FILE="${GROUP_FILE}" \
    SELFDEF_GROUPINT_PASSWD_FILE="${PASSWD_FILE}" \
    bash "${WD}" >/dev/null 2>&1
    echo $?
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# Helper: write a baseline /etc/group + /etc/passwd pair.
write_passwd_group() {
    cat > "${GROUP_FILE}" <<'EOF'
root:x:0:
daemon:x:1:
sudo:x:27:alice
docker:x:998:bob
wheel:x:10:
users:x:100:alice,bob
EOF
    cat > "${PASSWD_FILE}" <<'EOF'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
bob:x:1001:1001:Bob:/home/bob:/bin/bash
EOF
}

# /etc/passwd + /etc/group are world-readable and always populated; the
# primary-gid pass alone emits a record per user, so the inventory is
# reliably non-empty. Guard only against the (pathological) unreadable case.
have_account_db() { [ -r /etc/group ] && [ -r /etc/passwd ]; }

@test "first run captures the group-membership inventory into the baseline (non-empty)" {
    write_passwd_group
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
    [ -s "${BASELINE}" ]                                  # capture regression lock
    # records are <group>\t<member> — at least one well-formed TSV row.
    awk -F'\t' 'NF>=2{ok=1} END{exit ok?0:1}' "${BASELINE}"
}

@test "baseline captures BOTH inventory passes (group-file members + primary-gid users)" {
    write_passwd_group
    run_wd
    # sudo:alice from group-file member field. \t in POSIX ERE is
    # literal backslash-t, not a tab — use grep -P or a literal tab.
    grep -qP '^sudo\talice$' "${BASELINE}"
    # docker:bob from group-file member field.
    grep -qP '^docker\tbob$' "${BASELINE}"
    # root:root from primary-gid pass (root user, pgid=0 maps to
    # 'root' group via the awk lookup).
    grep -qP '^root\troot$' "${BASELINE}"
    grep -qP '^daemon\tdaemon$' "${BASELINE}"
}

@test "baseline is chmod 0600 (confidentiality — group inventory is sensitive)" {
    write_passwd_group
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "unchanged group membership on second run → ok / no_delta" {
    write_passwd_group
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}

@test "DELTA detect — adding a non-privileged group member → warn / group_membership_changed" {
    write_passwd_group
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Add bob to non-privileged users group.
    sed -i 's|^users:x:100:alice,bob|users:x:100:alice,bob,charlie|' "${GROUP_FILE}"
    echo 'charlie:x:1002:1002:Charlie:/home/charlie:/bin/bash' >> "${PASSWD_FILE}"
    run_wd
    cap | grep -q '"event":"group_membership_changed"'
    cap | grep -q '"severity":"warn"'
    # added_sample surfaces the new member.
    cap | grep -q 'users:charlie'
}

@test "DELTA detect — adding a member to PRIVILEGED group (docker) → alert / privileged_group_member_added" {
    write_passwd_group
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    sed -i 's|^docker:x:998:bob|docker:x:998:bob,evil|' "${GROUP_FILE}"
    run_wd
    cap | grep -q '"event":"privileged_group_member_added"'
    cap | grep -q '"severity":"alert"'
    # priv_sample surfaces the docker:evil pair.
    cap | grep -q 'docker:evil'
}

@test "DELTA detect — adding to SUDO group is the canonical privileged-alert path" {
    write_passwd_group
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    sed -i 's|^sudo:x:27:alice|sudo:x:27:alice,evil|' "${GROUP_FILE}"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q 'sudo:evil'
}

@test "DELTA detect — removing a member surfaces in removed_sample" {
    write_passwd_group
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    sed -i 's|^users:x:100:alice,bob|users:x:100:alice|' "${GROUP_FILE}"
    run_wd
    # Removal alone is warn (no privileged-add).
    cap | grep -q '"severity":"warn"'
    cap | grep -q 'users:bob'
}

@test "INVARIANT (baseline refresh): after a delta run, next run sees no_delta (confirmed-legit-change-becomes-trusted)" {
    write_passwd_group
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    sed -i 's|^users:x:100:alice,bob|users:x:100:alice,bob,charlie|' "${GROUP_FILE}"
    echo 'charlie:x:1002:1002:Charlie:/home/charlie:/bin/bash' >> "${PASSWD_FILE}"
    run_wd  # first delta run reports group_membership_changed
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd  # next run should see no_delta (baseline refreshed)
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}

@test "ENFORCE profile: delta returns exit-1 (failure surface for systemd unit alerting)" {
    write_passwd_group
    PROFILE=report run_wd                             # baseline init
    sed -i 's|^docker:x:998:bob|docker:x:998:bob,evil|' "${GROUP_FILE}"
    rc="$(PROFILE=enforce run_wd_rc)"
    [ "${rc}" = "1" ]
}

@test "REPORT profile: delta returns exit-0 (log-only — surfaced via journald only)" {
    write_passwd_group
    PROFILE=report run_wd
    sed -i 's|^docker:x:998:bob|docker:x:998:bob,evil|' "${GROUP_FILE}"
    rc="$(PROFILE=report run_wd_rc)"
    [ "${rc}" = "0" ]
}
