#!/usr/bin/env bats
# L2 bats functional tests for the hosts-file-watchdog scan script.
#
# /etc/hosts is consulted before DNS; an attacker who pins or blackholes a
# sensitive package/security/CA domain can MITM updates, block patching, or
# redirect the supply chain (T1565.001 / T1562.001). Severity:
#   ok    → no delta
#   warn  → any entry added/removed/changed
#   alert → an entry maps a sensitive package/security/CA domain (any IP)
#
# Run with: bats packaging/test/L2-hosts-file-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/hosts-file-watchdog/systemd/hosts-file-watchdog.sh"

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
    HOSTS="${TMP}/hosts"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_HOSTS_PROFILE="${PROFILE:-report}" \
    SELFDEF_HOSTS_BASELINE="${BASELINE}" \
    SELFDEF_HOSTS_FILE="${HOSTS_V:-$HOSTS}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '127.0.0.1 localhost\n10.0.0.5 myserver.internal\n' > "${HOSTS}"
}

@test "no hosts file → ok / no_hosts_file" {
    HOSTS_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_hosts_file"'
    cap | grep -q '"severity":"ok"'
}

@test "benign hosts file, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged hosts file on second run → ok / hosts_file_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"hosts_file_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "pinning a sensitive package domain → alert / hosts_file_sensitive_pin" {
    seed_benign
    run_wd
    printf '127.0.0.1 localhost\n10.0.0.5 myserver.internal\n185.1.2.3 security.ubuntu.com\n' > "${HOSTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"hosts_file_sensitive_pin"'
    cap | grep -q '"severity":"alert"'
}

@test "a benign entry change → warn / hosts_file_changed" {
    seed_benign
    run_wd
    printf '127.0.0.1 localhost\n10.0.0.6 other.internal\n' > "${HOSTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"hosts_file_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign internal-only hosts file is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "enforce profile exits non-zero on a sensitive pin" {
    seed_benign
    run_wd
    printf '127.0.0.1 localhost\n0.0.0.0 security.debian.org\n' > "${HOSTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — hosts pinning inventory leaks operator internal hostnames)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (sensitive-domain: debian distro): security.debian.org pin → alert (block patching attack)" {
    seed_benign
    run_wd
    printf '127.0.0.1 localhost\n0.0.0.0 security.debian.org\n' > "${HOSTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (sensitive-domain: ubuntu distro): archive.ubuntu.com pin → alert" {
    seed_benign
    run_wd
    printf '127.0.0.1 localhost\n0.0.0.0 archive.ubuntu.com\n' > "${HOSTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (sensitive-domain: docker.io): docker registry pin → alert (image-pull MITM)" {
    seed_benign
    run_wd
    printf '127.0.0.1 localhost\n0.0.0.0 docker.io\n' > "${HOSTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (sensitive-domain: github.com): github pin → alert (source-pull MITM)" {
    seed_benign
    run_wd
    printf '127.0.0.1 localhost\n0.0.0.0 raw.githubusercontent.com\n' > "${HOSTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (pre-existing sensitive pin): baseline_initial fires alert if /etc/hosts already pins a sensitive domain at install-time" {
    # Install-time-vet contract.
    printf '0.0.0.0 security.debian.org\n' > "${HOSTS}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (persistent-alert on sensitive pin): pre-existing sensitive pin IS re-alerted on every run until removed" {
    # CONTRAST against the access-conf-watchdog + capability-conf-
    # watchdog "no spurious re-alert" contract. hosts-file-
    # watchdog scans the FULL current set for sensitive domains
    # (not just the added-set), so a sensitive pin that stays in
    # /etc/hosts STAYS in the alert state every run. This is
    # the "alert STAYS visible until operator removes" pattern,
    # implemented via re-evaluation rather than via no-baseline-
    # refresh. Locks the choice — a regression to scan only the
    # added-set (matching access-conf semantics) would let an
    # attacker-pinned sensitive domain go silent after the first
    # alert.
    printf '0.0.0.0 security.debian.org\n' > "${HOSTS}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"hosts_file_sensitive_pin"'
    cap | grep -q '"severity":"alert"'
}

@test "DELTA detect — REMOVED hosts entry → warn / hosts_file_changed" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '127.0.0.1 localhost\n' > "${HOSTS}"        # remove myserver
    run_wd
    cap | grep -qE '"event":"hosts_file_changed"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-hosts-file -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (auto-trust): hosts-file-watchdog DOES auto-refresh the baseline (operator-action common)" {
    seed_benign
    run_wd
    printf '127.0.0.1 localhost\n10.0.0.10 newserver.internal\n' > "${HOSTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — warn
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # baseline refreshed
    cap | grep -q '"event":"hosts_file_intact"'
}

@test "INVARIANT (commented sensitive pin NOT flagged: # prefix filtered from inventory)" {
    # /etc/hosts uses # comments. Operator notes about hypothetical
    # bad pins must NOT trigger alert.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '127.0.0.1 localhost\n10.0.0.5 myserver.internal\n# 0.0.0.0 security.debian.org\n' > "${HOSTS}"
    run_wd
    ! cap | grep -q '"event":"hosts_file_sensitive_pin"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (sensitive-domain: PyPI / pypi.org pin → alert (python supply-chain MITM))" {
    seed_benign
    run_wd
    printf '127.0.0.1 localhost\n0.0.0.0 pypi.org\n' > "${HOSTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (sensitive-domain: npmjs.org / npm registry pin → alert (node supply-chain MITM))" {
    seed_benign
    run_wd
    printf '127.0.0.1 localhost\n0.0.0.0 registry.npmjs.org\n' > "${HOSTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (whitespace tolerance: '0.0.0.0    security.debian.org' multi-space variant still triggers alert)" {
    # Attacker may use multi-spaces to evade naive grep-based
    # detection. Lock whitespace-tolerant parser.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '127.0.0.1 localhost\n0.0.0.0    security.debian.org\n' > "${HOSTS}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (sensitive-domain: Let's Encrypt ACME / CA pin → alert (cert-issuance MITM))" {
    # Sister axis to package-MITM (debian/ubuntu) + supply-chain MITM
    # (docker/github/pypi/npmjs). Pinning a CA / ACME endpoint lets an
    # attacker MITM cert-issuance — the operator's web service /
    # automated client thinks it got a valid cert from Let's Encrypt
    # but it actually got a rogue cert signed by the attacker. T1556
    # Modify Authentication Process. Lock the CA-domain axis on the
    # /etc/hosts pin surface alongside the package + supply-chain axes
    # already covered.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '127.0.0.1 localhost\n0.0.0.0 acme-v02.api.letsencrypt.org\n' > "${HOSTS}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (sensitive-domain: ntp.org / time-service pin → alert (clock-skew evasion))" {
    # Sister to the package + supply-chain + CA axes already locked.
    # Pinning a time-service domain like pool.ntp.org or
    # time.cloudflare.com lets an attacker MITM the NTP-handshake
    # to skew the system clock — which then defeats certificate
    # validity checks (a future-dated cert becomes valid), defeats
    # audit-log forensics (timestamps become unreliable), defeats
    # rate-limiter logic (token-bucket replenishments accelerate).
    # T1565.002 — Transmitted Data Manipulation via NTP MITM.
    # Locks the time-service-domain axis on the /etc/hosts pin
    # surface alongside the other CAR-defense axes already covered.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '127.0.0.1 localhost\n0.0.0.0 pool.ntp.org\n' > "${HOSTS}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (sensitive-domain: anthropic.com / api.anthropic / openai.com — AI-service-pin → alert (LLM API MITM))" {
    # Sister to the package + supply-chain + CA + NTP axes
    # already locked. Pinning AI-service-API domains lets an
    # attacker MITM the LLM API responses — Claude / GPT calls
    # would route to attacker-controlled servers returning
    # crafted responses. On AI-substrate-critical hosts (which
    # this project IS), this is the most-impactful MITM axis
    # for the modern attack surface. T1565.002 — Transmitted
    # Data Manipulation via API-endpoint hijacking. Locks the
    # AI-service-domain axis on the /etc/hosts pin surface.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '127.0.0.1 localhost\n0.0.0.0 api.anthropic.com\n' > "${HOSTS}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (sensitive-domain: github.com / api.github.com — code-supply-chain MITM → alert)" {
    # Sister to the AI-service / package-registry / CA / NTP /
    # supply-chain pin axes already locked. Pinning github.com
    # to a non-cdn-cgi IP lets an attacker MITM git clone and
    # raw.githubusercontent.com requests — every CI pipeline,
    # every operator-executed `curl | sh` bootstrap, every
    # GitHub release-asset download routes to attacker servers.
    # T1195.001 — Supply Chain Compromise via developer-platform
    # MITM. The watchdog MUST surface github-domain pin just
    # as firmly as the other supply-chain registry pins
    # (PyPI/npmjs). Locks the github code-supply-chain axis on
    # the /etc/hosts pin surface.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '127.0.0.1 localhost\n0.0.0.0 api.github.com\n' > "${HOSTS}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (sensitive-domain: docker.io / registry-1.docker.io — container-supply-chain MITM → alert)" {
    # Sister to github / AI-service / PyPI/npmjs supply-chain
    # pin axes. Container registry MITM lets attacker swap
    # base images at pull time. T1195.001.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '127.0.0.1 localhost\n0.0.0.0 docker.io\n' > "${HOSTS}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (sensitive-domain: Google Play / firebase / Apple App Store — mobile-supply-chain MITM → alert)" {
    # Sister to docker.io / github.com / PyPI / npmjs supply-
    # chain pin INVARIANTs. Mobile app update channels are
    # equally MITM-sensitive — attacker can pin app-store/
    # play.googleapis.com / firebaseinstallations.googleapis.com
    # / apps.apple.com to redirect mobile-app metadata + binary
    # delivery. T1195.001 supply-chain compromise via mobile-
    # app-store MITM.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '127.0.0.1 localhost\n0.0.0.0 play.googleapis.com\n' > "${HOSTS}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn|ok)"'
}
