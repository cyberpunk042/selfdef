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

@test "INVARIANT (wheel group privileged-add → alert): per-distro coverage" {
    write_passwd_group
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    sed -i 's|^wheel:x:10:|wheel:x:10:evil|' "${GROUP_FILE}"
    run_wd
    cap | grep -q '"event":"privileged_group_member_added"'
    cap | grep -q '"severity":"alert"'
    cap | grep -q 'wheel:evil'
}

@test "INVARIANT (PRIMARY-GID pass via passwd): user joining privileged group only via pgid → alert" {
    # CRITICAL invariant — the 2nd inventory pass. A user whose
    # primary gid IS the docker group's gid will not appear in the
    # docker group's member field, but they ARE a docker member
    # by primary-gid pass.
    write_passwd_group
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # New user with pgid=998 (docker's gid).
    echo 'attacker:x:1003:998:Attacker:/home/attacker:/bin/bash' >> "${PASSWD_FILE}"
    run_wd
    cap | grep -q '"event":"privileged_group_member_added"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (shadow group also privileged → alert)" {
    # shadow group can read /etc/shadow. Adding a member = privilege escalation.
    echo 'shadow:x:42:bob' >> "${GROUP_FILE}"   # initial: bob only
    write_passwd_group
    # Re-add shadow with bob (write_passwd_group truncates).
    cat >> "${GROUP_FILE}" <<'EOF'
shadow:x:42:bob
EOF
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    sed -i 's|^shadow:x:42:bob|shadow:x:42:bob,evil|' "${GROUP_FILE}"
    run_wd
    cap | grep -qE '"severity":"alert"'
    cap | grep -q 'shadow:evil'
}

@test "INVARIANT (lxd group also privileged — container escape vector → alert)" {
    # lxd group can launch containers + escape to root.
    echo 'lxd:x:120:bob' >> "${GROUP_FILE}"
    write_passwd_group
    cat >> "${GROUP_FILE}" <<'EOF'
lxd:x:120:bob
EOF
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    sed -i 's|^lxd:x:120:bob|lxd:x:120:bob,evil|' "${GROUP_FILE}"
    run_wd
    cap | grep -qE '"severity":"alert"'
    cap | grep -q 'lxd:evil'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    write_passwd_group
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-group-integrity -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (disk group also privileged — raw disk access → alert)" {
    # disk group can read+write raw disk devices. Adding a member
    # = trivial privilege escalation via /dev/sda direct access.
    echo 'disk:x:6:' >> "${GROUP_FILE}"
    write_passwd_group
    cat >> "${GROUP_FILE}" <<'EOF'
disk:x:6:bob
EOF
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    sed -i 's|^disk:x:6:bob|disk:x:6:bob,evil|' "${GROUP_FILE}"
    run_wd
    cap | grep -qE '"severity":"alert"'
    cap | grep -q 'disk:evil'
}

@test "INVARIANT (commented group line NOT included in inventory: # prefix filtered)" {
    # /etc/group has comment support. A commented privileged-group
    # line must not surface as a real group with members.
    write_passwd_group
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Add a commented sudo-group expansion (operator note).
    cat >> "${GROUP_FILE}" <<'EOF'
# sudo:x:27:alice,evil_future_plan
EOF
    run_wd
    # Commented sudo expansion should NOT surface as a real privileged add.
    ! cap | grep -q '"event":"privileged_group_member_added"'
}

@test "INVARIANT (severity precedence: privileged-add + non-privileged change same scan → alert wins)" {
    # Mixed scan: attacker adds to privileged group AND modifies
    # non-privileged group. Severity must be alert (privileged
    # wins ladder).
    write_passwd_group
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Privileged change.
    sed -i 's|^docker:x:998:bob|docker:x:998:bob,evil|' "${GROUP_FILE}"
    # Non-privileged change.
    sed -i 's|^users:x:100:alice,bob|users:x:100:alice,bob,charlie|' "${GROUP_FILE}"
    echo 'charlie:x:1002:1002:Charlie:/home/charlie:/bin/bash' >> "${PASSWD_FILE}"
    run_wd
    cap | grep -q '"event":"privileged_group_member_added"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-priv-add same scan: 2 sudo additions both surface in priv_sample)" {
    # Mass-privilege-add scenario: attacker adds multiple users
    # to sudo group at once. All must surface.
    write_passwd_group
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    sed -i 's|^sudo:x:27:alice|sudo:x:27:alice,evil1,evil2|' "${GROUP_FILE}"
    run_wd
    cap | grep -q '"event":"privileged_group_member_added"'
    cap | grep -q '"severity":"alert"'
    cap | grep -q 'sudo:evil1'
    cap | grep -q 'sudo:evil2'
}

@test "INVARIANT (kvm group privileged add → alert — VM-launch axis to root-equivalence)" {
    # kvm group lets a user launch VMs with hypervisor access — a
    # canonical privesc vector via VM escape or guest-driver
    # exploitation. Sister axis to docker/lxd privileged-group
    # tests already locked.
    write_passwd_group
    cat >> "${GROUP_FILE}" <<'EOF'
kvm:x:36:bob
EOF
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    sed -i 's|^kvm:x:36:bob|kvm:x:36:bob,evil|' "${GROUP_FILE}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (multi-privileged-group same scan: docker+sudo grants in one delta → BOTH surface in priv_sample)" {
    # Compound privileged-grant scenario: attacker grants user
    # to BOTH docker AND sudo in same scan. Both must surface in
    # priv_sample for forensics. Sister to multi-priv-add but
    # across DIFFERENT groups.
    write_passwd_group
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    sed -i 's|^sudo:x:27:alice|sudo:x:27:alice,evil|' "${GROUP_FILE}"
    sed -i 's|^docker:x:998:bob|docker:x:998:bob,evil|' "${GROUP_FILE}"
    run_wd
    cap | grep -q '"event":"privileged_group_member_added"'
    cap | grep -q '"severity":"alert"'
    cap | grep -q 'sudo:evil'
    cap | grep -q 'docker:evil'
}

@test "INVARIANT (root user pgid change to privileged group is FLAGGED — privilege-shift axis)" {
    # If an attacker MODIFIES an existing user's /etc/passwd pgid
    # to point at a privileged group (e.g. changes alice's pgid
    # from 1000 to 998=docker), that's a primary-gid privilege
    # grant. Sister axis to existing primary-gid INVARIANT.
    write_passwd_group
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Change alice's pgid from 1000 to 998 (docker's gid).
    sed -i 's|^alice:x:1000:1000:|alice:x:1000:998:|' "${PASSWD_FILE}"
    run_wd
    cap | grep -qE '"severity":"alert"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named user to privileged group surfaces in priv_sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker adds a
    # distinctively-named user to a privileged group (sudo /
    # wheel / docker / adm), the user NAME MUST surface in the
    # JSON sample so operator dashboard routes triage to the
    # right account. Locks the operator-visibility contract on
    # the group-membership privilege-grant surface (T1098 —
    # Account Manipulation via group membership).
    write_passwd_group
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Add distinctive-attacker-grant to sudo group.
    sed -i 's|^sudo:x:27:.*|sudo:x:27:distinctive-attacker-grant|' "${GROUP_FILE}"
    run_wd
    cap | grep -q 'distinctive-attacker-grant'
}

@test "INVARIANT (shadow group privileged add → alert — /etc/shadow read-access axis to credential theft)" {
    # Sister to docker / sudo / wheel / disk / kvm / adm
    # privileged-group INVARIANTs already locked. The shadow
    # group has read access to /etc/shadow on Debian/Ubuntu
    # (mode 0640 root:shadow). Any user added to shadow can
    # read all password hashes — credential-theft primitive
    # (T1003.008 — OS Credential Dumping: /etc/passwd and
    # /etc/shadow). Offline-cracking with hashcat/john trivially
    # recovers weak passwords. The watchdog MUST treat shadow-
    # group additions as alert grade equal to sudo additions.
    # Locks the shadow group as a coverage member of the
    # privileged-group family on the T1098 Account Manipulation
    # surface.
    write_passwd_group
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Add evil to shadow group.
    echo 'shadow:x:42:evil-cred-thief' >> "${GROUP_FILE}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (kvm group privileged add → alert — VM-launch escape-to-host axis)" {
    # Sister to shadow / sudo / wheel / docker / adm / disk
    # privileged-group axes. kvm group → /dev/kvm access → VM
    # launch that mounts host filesystem r/w → T1611 Escape
    # to Host.
    write_passwd_group
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    echo 'kvm:x:103:evil-kvm-attacker' >> "${GROUP_FILE}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (wheel group privileged add → alert — RHEL/CentOS sudoers-grant axis)" {
    # Sister to sudo + docker + shadow + kvm + disk privileged-
    # group axes. wheel = RHEL/CentOS/Arch convention for
    # sudoers-grant (%wheel ALL=(ALL) ALL). Closes axis-parity
    # with sudo group on Debian/Ubuntu. T1548.003 Sudo via
    # group membership.
    write_passwd_group
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    echo 'wheel:x:10:evil-wheel-attacker' >> "${GROUP_FILE}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on group-integrity surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The group-integrity-watchdog MUST only emit severity
    # values from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers branch on the literal severity string;
    # an out-of-set value silently falls through routing and
    # the operator never sees the T1098/T1548 privileged-group
    # membership manipulation alert. Locks parser contract on
    # the /etc/group delta detection surface.
    write_passwd_group
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    echo 'sudo:x:27:alice,evil-attacker' >> "${GROUP_FILE}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # group-integrity-watchdog runs ON the timer's scheduled fire
    # — diffs /etc/group against baseline, emits a verdict on
    # privileged-group membership deltas, then exits. Type=simple
    # would break timer OnUnitActiveSec semantics. Locks oneshot-
    # probe contract on the group-integrity-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd/selfdef-group-integrity.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. group-integrity-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # group-integrity-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # group-integrity-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'group-integrity-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: group-integrity-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. group-integrity-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the group-integrity-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (group-integrity-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The group-integrity-watchdog libexec uses set -u to catch typo'd env-var
    # references before they silently propagate as empty
    # strings into baseline-path operations. Locks set -u
    # discipline on the group-integrity-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (group-integrity-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # group-integrity-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (group-integrity-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # group-integrity-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (group-integrity-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the group-integrity-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (group-integrity-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # group-integrity-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (group-integrity-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the group-integrity-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (group-integrity-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the group-integrity-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (group-integrity-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # group-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (group-integrity-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the group-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (group-integrity-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the group-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (group-integrity-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the group-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (group-integrity-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the group-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (group-integrity-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the group-integrity-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (group-integrity-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the group-integrity-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (group-integrity-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # group-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (group-integrity-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # group-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (group-integrity-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the group-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (group-integrity-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the group-integrity-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (group-integrity-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (group-integrity-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (group-integrity-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (group-integrity-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (group-integrity-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the group-integrity-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    [ -f "${script_dir}/group-integrity-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (group-integrity-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (group-integrity-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (group-integrity-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (group-integrity-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (group-integrity-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (group-integrity-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (group-integrity-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (group-integrity-watchdog .sh script emits canonical severity vocabulary {ok,warn,alert} — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    # Watchdog scripts emit logger -t selfdef-<name> -- {...severity:...}
    # with severity in the canonical vocabulary. A regression
    # introducing custom severity values (info, error, critical)
    # would break operator-side filtering.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '"severity":"(ok|warn|alert)"' "${s}"
    done
}
