#!/usr/bin/env bash
# polarproxy — apply.
#
# Owns: systemd unit, nftables redirect (host-tls-mitm), pointer file.
# Does NOT own: the PolarProxy binary or the CA. See README.
#
# Idempotent. SELFDEF_DRY_RUN=1 aware. Final JSON status line on stdout.

set -euo pipefail

MODULE="polarproxy"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_POLARPROXY_CONFIG:-/etc/selfdef/modules/polarproxy.toml}"
TEMPLATE_DIR="${SELFDEF_POLARPROXY_TEMPLATES:-/usr/share/selfdef/modules/polarproxy/templates}"
UNIT_PATH="${SELFDEF_POLARPROXY_UNIT_PATH:-/etc/systemd/system/polarproxy.service}"
NFT_RULESET_PATH="${SELFDEF_POLARPROXY_NFT_PATH:-/etc/nftables.d/selfdef-polarproxy.conf}"

# ---------------------------------------------------------------- helpers
# shellcheck source=lib.sh
source "${BASH_SOURCE[0]%/*}/lib.sh"

# ---------------------------------------------------------------- preflight
[[ -r "$CONFIG_FILE" ]] || die "config file not readable: $CONFIG_FILE"
command -v PolarProxy >/dev/null || die "PolarProxy(1) missing; install per netresec.com first"
command -v nft        >/dev/null || die "nft(8) missing"
command -v systemctl  >/dev/null || die "systemctl missing"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "host-tls-mitm")
LISTEN_PORT=$(toml_get listen_port "$CONFIG_FILE" || echo "10443")
PCAP_PORT=$(toml_get pcap_over_ip_port "$CONFIG_FILE" || echo "4430")
CERT_HTTP_PORT=$(toml_get cert_http_port "$CONFIG_FILE" || echo "10080")
LOG_DIR=$(toml_get log_dir "$CONFIG_FILE" || echo "/var/log/polarproxy")
CA_PFX=$(toml_get ca_pfx_path "$CONFIG_FILE" || echo "/etc/polarproxy/ca.pfx")
CA_PFX_PW=$(toml_get ca_pfx_password "$CONFIG_FILE" || echo "")

case "$PROFILE" in
    host-tls-mitm|bridge-tap) ;;
    *) die "profile must be host-tls-mitm|bridge-tap, got '$PROFILE'" ;;
esac

# bridge-tap is a runtime soft-dependency on bridge-l2.
if [[ "$PROFILE" == "bridge-tap" ]]; then
    if ! nft list table inet selfdef_bridge >/dev/null 2>&1; then
        die "bridge-tap profile requires bridge-l2 to be loaded first"
    fi
fi

changes=0

# ---------------------------------------------------------------- systemd unit
UNIT_TMPL="$TEMPLATE_DIR/polarproxy.service.tmpl"
[[ -r "$UNIT_TMPL" ]] || die "template missing: $UNIT_TMPL"

cert_http_flag=""
[[ "$CERT_HTTP_PORT" != "0" && -n "$CERT_HTTP_PORT" ]] && cert_http_flag="--certhttp $CERT_HTTP_PORT"

pw_opt=""
[[ -n "$CA_PFX_PW" ]] && pw_opt="--password \"$CA_PFX_PW\""

RENDERED_UNIT=$(mktemp)
trap 'rm -f "$RENDERED_UNIT"' EXIT
sed \
    -e "s|@@LISTEN_PORT@@|${LISTEN_PORT}|g" \
    -e "s|@@PCAP_OVER_IP_PORT@@|${PCAP_PORT}|g" \
    -e "s|@@CERT_HTTP_FLAG@@|${cert_http_flag}|g" \
    -e "s|@@LOG_DIR@@|${LOG_DIR}|g" \
    -e "s|@@CA_PFX_PATH@@|${CA_PFX}|g" \
    -e "s|@@CA_PFX_PASSWORD_OPT@@|${pw_opt}|g" \
    "$UNIT_TMPL" > "$RENDERED_UNIT"

reload_systemd=0
if [[ -r "$UNIT_PATH" ]] && cmp -s "$RENDERED_UNIT" "$UNIT_PATH"; then
    log "systemd unit already at target state"
else
    run "install polarproxy.service to $UNIT_PATH" -- install -D -m 0644 "$RENDERED_UNIT" "$UNIT_PATH"
    reload_systemd=1
    changes=$((changes + 1))
fi
# F-2027-024: record the systemd unit in the manifest so
# uninstall walks the manifest. Idempotent.
module_record_file "$UNIT_PATH"

# ---------------------------------------------------------------- nftables redirect
HAVE_NFT_TABLE=0
if nft list table inet selfdef_polarproxy >/dev/null 2>&1; then
    HAVE_NFT_TABLE=1
fi

if [[ "$PROFILE" == "host-tls-mitm" ]]; then
    NAT_TMPL="$TEMPLATE_DIR/nat-redirect.rule.tmpl"
    [[ -r "$NAT_TMPL" ]] || die "template missing: $NAT_TMPL"

    RENDERED_NAT=$(mktemp)
    # extend cleanup
    trap 'rm -f "$RENDERED_UNIT" "$RENDERED_NAT"' EXIT
    sed -e "s|@@LISTEN_PORT@@|${LISTEN_PORT}|g" "$NAT_TMPL" > "$RENDERED_NAT"

    if [[ -r "$NFT_RULESET_PATH" ]] && cmp -s "$RENDERED_NAT" "$NFT_RULESET_PATH" && [[ "$HAVE_NFT_TABLE" == "1" ]]; then
        log "nftables redirect already at target state"
    else
        run "install nftables redirect to $NFT_RULESET_PATH" \
            -- install -D -m 0644 "$RENDERED_NAT" "$NFT_RULESET_PATH"
        run "load nftables redirect" -- nft -f "$NFT_RULESET_PATH"
        changes=$((changes + 2))
    fi
    # F-2027-024: record the NAT ruleset in the manifest. Only
    # under host-tls-mitm; bridge-tap profile doesn't render
    # this file (the else branch below cleans up any stale one).
    module_record_file "$NFT_RULESET_PATH"
else
    # bridge-tap profile: ensure any previous host-tls-mitm NAT table
    # is removed, otherwise we'd be double-redirecting on this host.
    if [[ "$HAVE_NFT_TABLE" == "1" ]]; then
        run "remove stale host-tls-mitm NAT table" -- nft delete table inet selfdef_polarproxy
        changes=$((changes + 1))
    fi
    if [[ -f "$NFT_RULESET_PATH" ]]; then
        run "remove stale $NFT_RULESET_PATH" -- rm -f "$NFT_RULESET_PATH"
        changes=$((changes + 1))
    fi
fi

# ---------------------------------------------------------------- service
if [[ "$reload_systemd" == "1" ]]; then
    run "systemctl daemon-reload" -- systemctl daemon-reload
fi

if systemctl is-enabled --quiet polarproxy.service 2>/dev/null; then
    log "polarproxy.service already enabled"
else
    run "enable polarproxy.service" -- systemctl enable polarproxy.service
    changes=$((changes + 1))
fi

if systemctl is-active --quiet polarproxy.service; then
    log "polarproxy.service already running — reload-or-restart"
    run "reload polarproxy.service" -- systemctl reload-or-restart polarproxy.service
else
    run "start polarproxy.service" -- systemctl start polarproxy.service
    changes=$((changes + 1))
fi

# ---------------------------------------------------------------- finalise
if [[ "$changes" -eq 0 ]]; then
    emit_status "skipped" "already at target state"
else
    emit_status "ok" "applied $changes change(s)"
fi
