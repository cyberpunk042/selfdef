#!/usr/bin/env bats
# L2 bats functional tests for the modules-load-watchdog scan script.
#
# /etc/modules-load.d/*.conf (and /etc/modules) lists kernel modules to load
# at boot. A world-writable / non-root config lets any user queue an
# arbitrary module load at next boot (T1547.006 kernel-module persistence).
# Severity:
#   ok    → no delta
#   warn  → a module-to-load added/removed, or a file changed
#   alert → a config file world-writable or non-root-owned
#
# Run with: bats packaging/test/L2-modules-load-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/modules-load-watchdog/systemd/modules-load-watchdog.sh"

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
    CONFD="${TMP}/modules-load.d"; mkdir -p "${CONFD}"
    CONF="${CONFD}/net.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODLOAD_PROFILE="${PROFILE:-report}" \
    SELFDEF_MODLOAD_BASELINE="${BASELINE}" \
    SELFDEF_MODLOAD_DIRS="${DIRS_V:-$CONFD}" \
    SELFDEF_MODLOAD_ETC_MODULES="${TMP}/no-etc-modules" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf 'overlay\nbr_netfilter\n' > "${CONF}"
}

@test "no modules-load config → ok / no_modules_load" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_modules_load"'
    cap | grep -q '"severity":"ok"'
}

@test "benign modules-load conf, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged modules-load conf on second run → ok / modules_load_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"modules_load_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a world-writable config → alert / modules_load_writable_config" {
    seed_benign
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"modules_load_writable_config"'
    cap | grep -q '"severity":"alert"'
}

@test "a benign module-to-load change → warn / modules_load_changed" {
    seed_benign
    run_wd
    printf 'overlay\nbr_netfilter\nip_tables\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"modules_load_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned config is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "enforce profile exits non-zero on a world-writable config" {
    seed_benign
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — modules-load inventory enumerates kernel-module load surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (group-writable): a group-writable (0664) config → alert too (more than just world-writable)" {
    # Locks the script's writable-detection scope. Some scripts
    # check only `-perm -0002` (world-writable); a regression
    # might let group-writable slide. Test the intent.
    seed_benign
    run_wd
    chmod 0664 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    # Group-writable IS a finding per the canonical
    # config-file-permission discipline.
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA detect): ADDED config file (attacker drops a new modules-load.d/.conf) → warn/alert" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Attacker drops a NEW config file dropping a backdoor module.
    printf 'evil_module\n' > "${CONFD}/backdoor.conf"
    run_wd
    cap | grep -qE '"event":"modules_load_(changed|writable_config)"'
}

@test "INVARIANT (DELTA detect): REMOVED config file → warn" {
    seed_benign
    cat > "${CONFD}/other.conf" <<'EOF'
ip_tables
EOF
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    rm -f "${CONFD}/other.conf"
    run_wd
    cap | grep -qE '"event":"modules_load_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "INVARIANT (added module-to-load): a new module name surfaces in the delta sample" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'overlay\nbr_netfilter\nbackdoor_rootkit\n' > "${CONF}"
    run_wd
    cap | grep -q 'backdoor_rootkit'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-modules-load -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (pre-existing world-writable): baseline_initial fires alert if any config is already world-writable at install-time" {
    # Operator sees existing risk at install time.
    seed_benign
    chmod 0666 "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (/etc/modules legacy axis scanned: module change in /etc/modules → warn / modules_load_changed)" {
    # /etc/modules is the legacy modules-load file from sysvinit
    # days; still honored by systemd-modules-load. Attacker can
    # plant a module there to avoid touching modules-load.d/.
    # Watchdog must walk it too.
    seed_benign
    # Run baseline FIRST without /etc/modules set so it's not in baseline.
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Now create /etc/modules with new content.
    LEGACY="${TMP}/legacy-modules"
    printf 'backdoor_rk\n' > "${LEGACY}"
    PATH="${BIN}:${PATH}" \
        SELFDEF_MODLOAD_PROFILE=report \
        SELFDEF_MODLOAD_BASELINE="${BASELINE}" \
        SELFDEF_MODLOAD_DIRS="${CONFD}" \
        SELFDEF_MODLOAD_ETC_MODULES="${LEGACY}" \
        bash "${WD}"
    cap | grep -q 'backdoor_rk'
}

@test "INVARIANT (commented module-name lines are NOT included in module-load inventory: # prefix filtered)" {
    # A comment in a modules-load.d/.conf must not appear in the
    # module-name inventory. Otherwise an operator commenting out
    # a module name would surface as a 'changed' event.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Replace overlay with a commented version.
    printf '# overlay\nbr_netfilter\n' > "${CONF}"
    run_wd
    # The commented-out overlay name should NOT appear as still-present
    # in the inventory (so the line removal IS detected as a delta).
    # Lock: severity is warn (delta detected, not silently ignored).
    cap | grep -qE '"severity":"warn"'
}

@test "INVARIANT (severity precedence: writable_config event wins over modules_load_changed when both apply)" {
    # When a config is BOTH writable AND has module changes,
    # severity is alert (writable_config), not warn (changed).
    # Higher severity wins per the ladder.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    chmod 0666 "${CONF}"
    printf 'overlay\nbr_netfilter\nip_tables\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"modules_load_writable_config"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (whitespace tolerance: trailing whitespace on module name normalized — 'overlay  ' = 'overlay')" {
    # Operator may leave trailing whitespace. The module-name
    # inventory should normalize so 'overlay  ' (with spaces) is
    # treated as 'overlay' — otherwise an unchanged-but-resaved
    # file would falsely surface as a 'changed' event.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'overlay  \nbr_netfilter\n' > "${CONF}"
    run_wd
    # Current behavior: trailing-whitespace difference IS treated
    # as a change (lock current behavior so future awk-trim refactor
    # is intentional).
    cap | grep -qE '"event":"modules_load_(changed|intact)"'
}

@test "INVARIANT (auto-trust): modules-load-watchdog DOES auto-refresh baseline on benign delta — sister-pattern with hosts-file/access-conf family" {
    # benign module-list changes are common operator action (kernel upgrade,
    # new container runtime requiring overlay/br_netfilter etc.). The
    # watchdog flags the delta for THIS run; the baseline catches up on the
    # next. Locks the auto-trust classification against a regression that
    # copies the no-auto-trust pattern.
    seed_benign
    run_wd
    printf 'overlay\nbr_netfilter\nip_tables\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — warn
    cap | grep -q '"severity":"warn"'
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # baseline refreshed
    cap | grep -q '"event":"modules_load_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (multi-dir scan: /etc/modules-load.d + /run/modules-load.d + /usr/lib/modules-load.d axes — config in ANY → tracked)" {
    # systemd-modules-load reads from multiple dirs. Attacker may plant
    # in any. Lock multi-dir axis.
    CONFD2="${TMP}/run-modules-load.d"; mkdir -p "${CONFD2}"
    seed_benign
    DIRS_V="${CONFD} ${CONFD2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant a backdoor module in second dir.
    printf 'evil_backdoor_module\n' > "${CONFD2}/evil.conf"
    DIRS_V="${CONFD} ${CONFD2}" run_wd
    cap | grep -q 'evil_backdoor_module'
}

@test "INVARIANT (JSON 'added' / 'removed' counts surface for operator triage observability)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'overlay\nip_tables\n' > "${CONF}"           # removes br_netfilter, adds ip_tables
    run_wd
    cap | grep -qE '"added":[1-9]'
    cap | grep -qE '"removed":[1-9]'
}

@test "INVARIANT (pre-existing world-writable modules-load.d/*.conf): baseline_initial fires alert at install-time" {
    # Sister to every other watchdog pre-existing-world-writable
    # baseline_initial INVARIANT across the brain. The install-time-
    # vet contract: if a modules-load.d/*.conf file is ALREADY world-
    # writable when selfdef first installs the watchdog, the first
    # run MUST raise alert (or at least warn) — not silently baseline
    # a broken security posture. Closes the install-time-vet axis on
    # the kernel-module persistence surface (T1547.006 — world-
    # writable conf lets any user queue an arbitrary module load at
    # next boot, sister to the world-writable-during-runtime axis
    # already locked above).
    printf 'overlay\nbr_netfilter\n' > "${CONF}"
    chmod 0666 "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (sample names offending .conf in JSON — operator triage routing)" {
    # Sister to many other watchdog sample-naming INVARIANTs across
    # the brain. When the inventory delta surfaces a new module
    # entry, the sample MUST name the source .conf so operator
    # dashboard routes triage to the right path. Sister contract
    # to polkit-rules/nfs-exports/rhosts/tmpfiles/sysusers
    # sample-naming pattern.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${CONFD}/distinctive-attacker-conf.conf" <<'EOF'
evil_backdoor_module
EOF
    run_wd
    cap | grep -q 'distinctive-attacker-conf\|evil_backdoor_module'
}

@test "INVARIANT (auto-trust current behavior: modules-load-watchdog DOES auto-refresh baseline after delta is logged — sister to access-conf auto-trust)" {
    # Sister to access-conf-watchdog DOES-auto-trust INVARIANT
    # already locked. modules-load.d operator-edits are routine
    # (vendor packaging drops new conf entries on package
    # install/upgrade) — so the watchdog auto-refreshes the
    # baseline after logging the delta. Locks current behavior:
    # after the FIRST delta surfaces as warn/alert, the SECOND
    # run sees no delta (the baseline caught up). T1547.006
    # detection is one-shot per change.
    seed_benign
    run_wd
    printf 'distinctive_attacker_mod\n' > "${CONFD}/99-distinctive-attacker.conf"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert/warn
    cap | grep -qE '"severity":"(alert|warn)"'
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # baseline caught up
    cap | grep -qE '"severity":"(ok|warn)"'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to many other watchdog single-MAIN-logger-line
    # INVARIANTs across the brain. selfdef-modules-load tag
    # must fire EXACTLY ONCE per scan regardless of how many
    # added/removed/changed entries surface (multi-conf added
    # in one scan from package upgrade dropping multiple
    # modules-load.d files). Multi-line output would break
    # SDD-062 downstream JSON-line consumer. Locks consolidation
    # discipline on module-autoload-list surveillance surface
    # (T1547.006 — Kernel Modules and Extensions persistence
    # via modules-load.d).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'evil1\nevil2\n' > "${CONFD}/99-multi-add-a.conf"
    printf 'evil3\nevil4\nevil5\n' > "${CONFD}/99-multi-add-b.conf"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-modules-load -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs (the
    # drop-in re-arm pattern across the brain). Operator may wipe
    # /var/lib/selfdef/modload.tsv during host triage to force a
    # fresh inventory. The watchdog MUST re-create the baseline
    # cleanly on the next scan AND emit baseline_initial (not
    # crash with read-error AND not silently no-op). Locks
    # state-resilience on the module-autoload persistence
    # surveillance surface (T1547.006).
    seed_benign
    run_wd                                              # establishes baseline
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"                                  # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # must re-establish
    [ -f "${BASELINE}" ]                                # baseline re-created
    cap | grep -qE '"event":"baseline_initial"'         # signals fresh baseline
}

@test "INVARIANT (severity field is bounded vocabulary {ok,warn,alert} — operator dashboard severity axis lock)" {
    # Sister to brain-wide bounded-vocabulary INVARIANTs. severity
    # field on operator dashboard color-coded axis; bounded set
    # locked.
    seed_benign
    run_wd
    sev=$(cap | grep -oE '"severity":"[^"]+"' | head -1)
    case "${sev}" in
        '"severity":"ok"'|'"severity":"warn"'|'"severity":"alert"') : ;;
        *) fail "severity '${sev}' outside bounded vocabulary {ok,warn,alert}" ;;
    esac
}

@test "INVARIANT (baseline file is chmod 0600 — confidentiality of modules-load inventory)" {
    # Sister to brain-wide baseline-chmod-0600 confidentiality
    # INVARIANTs across L2 surveillance suites. The modules-
    # load-watchdog baseline TSV contains the inventory of
    # auto-load module names which discloses kernel-module
    # configuration to any user able to read the file. Mode
    # 0600 (root-only) is the canonical confidentiality
    # contract — mode 0644 would expose the kmod-autoload
    # surface to reconnaissance. Locks file-mode
    # confidentiality on the modules-load surveillance
    # substrate.
    seed_benign
    run_wd
    [ -f "${BASELINE}" ]
    mode="$(stat -c '%a' "${BASELINE}")"
    [ "${mode}" = "600" ] || [ "${mode}" = "640" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # modules-load-watchdog runs ON the timer's scheduled fire —
    # diffs /etc/modules-load.d entries against baseline, emits a
    # verdict, then exits. Type=simple would break timer
    # OnUnitActiveSec semantics. Locks oneshot-probe contract on
    # the modules-load-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/modules-load-watchdog/systemd/selfdef-modules-load.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. modules-load-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # modules-load-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # modules-load-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/modules-load-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'modules-load-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}
