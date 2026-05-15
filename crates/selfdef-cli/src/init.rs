//! `selfdefctl init` — first-run bootstrap.
//!
//! Helps operators stand up a fresh deployment without
//! hand-assembling `selfdef.toml`, `modules.toml`, or the
//! key-generation incantations. Every subcommand is
//! non-destructive by default (refuses to overwrite an existing
//! file unless `--force`).
//!
//! Three subcommands:
//!
//! - `init config` — write a starter `selfdef.toml` derived
//!   from `config/selfdef.toml.example`. The template ships
//!   with every audit-shipped security feature *off*; the
//!   operator opts in by editing the relevant section.
//! - `init modules` — write a starter `modules.toml` listing
//!   every shipped module commented out. The operator
//!   uncomments the modules they want to activate.
//! - `init checklist` — print a first-run operator checklist
//!   (install minisign, generate signing keys, deploy public
//!   key, set up kubectl access, etc). Read-only.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::paths;

/// Default target for `init config` when no `--output` is given.
/// F-2027-017: re-export from `crate::paths` so the daemon-side
/// expectation and the init-side default never drift.
pub(crate) const DEFAULT_DAEMON_CONFIG: &str = paths::DAEMON_CONFIG;

/// Default target for `init modules` — same source.
pub(crate) const DEFAULT_MODULES_CONFIG: &str = paths::MODULES_HOST_CONFIG;

/// SDD-NA: write a starter `selfdef.toml` to `output_path`.
/// Refuses to overwrite an existing file unless `force` is set.
/// Mode set to 0644 (world-readable; the daemon needs read,
/// operators inspect freely).
pub(crate) fn write_starter_config(output_path: &Path, force: bool) -> Result<()> {
    if output_path.exists() && !force {
        anyhow::bail!(
            "refusing to overwrite existing file: {}\n\
             pass --force to replace, or --output <path> to write elsewhere",
            output_path.display()
        );
    }
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    write_with_mode(output_path, STARTER_CONFIG.as_bytes(), 0o644)?;
    println!(
        "wrote {} ({} bytes)",
        output_path.display(),
        STARTER_CONFIG.len()
    );
    Ok(())
}

/// SDD-NA: write a starter `modules.toml` to `output_path`.
/// Refuses to overwrite unless `force`. The starter lists every
/// shipped module commented out with a short description so the
/// operator opts in by uncommenting.
pub(crate) fn write_starter_modules(output_path: &Path, force: bool) -> Result<()> {
    if output_path.exists() && !force {
        anyhow::bail!(
            "refusing to overwrite existing file: {}\n\
             pass --force to replace, or --output <path> to write elsewhere",
            output_path.display()
        );
    }
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    write_with_mode(output_path, STARTER_MODULES.as_bytes(), 0o644)?;
    println!(
        "wrote {} ({} bytes)",
        output_path.display(),
        STARTER_MODULES.len()
    );
    Ok(())
}

/// SDD-NA: print the first-run operator checklist to stdout.
/// Read-only; no filesystem effects.
pub(crate) fn print_checklist() {
    print!("{CHECKLIST}");
}

fn write_with_mode(path: &Path, body: &[u8], mode: u32) -> Result<()> {
    // Atomic shape: tempfile in the same dir → write → fsync →
    // rename. Matches the api-token rotation pattern from PR #44.
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let tmp = parent.join(format!(
        ".{}.init.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("starter")
    ));
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)
            .with_context(|| format!("opening tempfile {}", tmp.display()))?;
        f.write_all(body)
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp.display()))?;
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} → {}", tmp.display(), path.display()))?;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms)?;
    Ok(())
}

// --- templates -------------------------------------------------

/// Starter daemon config. Deliberately minimal: every audit
/// security feature is off; sections that need operator-supplied
/// values (rules dir, store path, api binding) are commented
/// pointers to the full example at `/usr/share/selfdef/selfdef.toml.example`.
const STARTER_CONFIG: &str = r#"# selfdef.toml — daemon configuration.
#
# Written by `selfdefctl init config`. Every value below is a
# minimal starter — every audit-shipped opt-in security feature
# (rule signing, eventstream integrity, api token, rbac probe)
# is OFF in this file. Turn each on after you've followed the
# matching docs/dev/<feature>.md runbook.
#
# For the exhaustive set of knobs see
# `/usr/share/selfdef/selfdef.toml.example` (shipped by the
# .deb) or `config/selfdef.toml.example` in the source tree.

[daemon]
log_level  = "info"
log_format = "text"

[store]
# Hot event store. Operator writable, daemon-owned.
hot_path = "/var/lib/selfdef/state.sqlite"

[correlator]
enabled   = true
rules_dir = "/etc/selfdef/rules"

[notifier]
channels = []
# Add "ntfy", "signal", "smtp" once the matching [notifier.<name>]
# block is configured (see selfdef.toml.example).

# F-2027-009: commented [notifier.ntfy] example so operators see
# the exact shape without grepping /usr/share/selfdef. To enable
# ntfy push notifications:
#   1. Pick a topic at https://ntfy.sh/<your-topic> (or self-host).
#   2. Uncomment the block below; flip channels above to ["ntfy"].
#   3. (Optional) Set token_env to the env var holding a bearer
#      token if you self-host with auth.
#
# [notifier.ntfy]
# server    = "https://ntfy.sh"
# topic     = "your-selfdef-topic"
# priority  = "default"        # one of min|low|default|high|max
# tags      = ["selfdef"]
# token_env = ""               # name of env var with bearer token, or empty

# SDD-008 D-7 Q-E: commented [notifier.smtp] example. Email
# delivery via an operator-supplied SMTP relay using STARTTLS by
# default. To enable:
#   1. Pick a relay (your provider's smtp.<isp> on port 587, or a
#      self-hosted Postfix on port 587/465).
#   2. Write the auth password to /etc/selfdef/smtp.password
#      (mode 0600 owned by the selfdef user) if the relay requires
#      it.
#   3. Uncomment the block below; flip channels above to include
#      "smtp" in the order you want it tried.
#   4. The channel refuses auth-bearing send over tls = "plain";
#      use "starttls" (port 587) or "implicit_tls" (port 465) for
#      any relay that authenticates.
#
# [notifier.smtp]
# relay_host    = "smtp.example.org"
# relay_port    = 587
# tls           = "starttls"           # starttls | implicit_tls | plain
# username      = "selfdef@example.org"
# password_file = "/etc/selfdef/smtp.password"
# from          = "selfdef-alerts@example.org"
# to            = ["ops@example.org"]
# timeout_secs  = 10

# SDD-008 Q-D: commented [notifier.twilio] example. SMS delivery
# via Twilio's REST API. To enable:
#   1. Provision a Twilio account + SMS-capable phone number.
#   2. Write the auth token to /etc/selfdef/twilio.token (mode
#      0600 owned by the selfdef user).
#   3. Uncomment the block below; flip channels above to include
#      "twilio" in the order you want it tried.
#   4. v1 ships SEND-ONLY: ack reply via inbound SMS webhook is
#      not implemented (would require exposing a public HTTPS
#      endpoint). Acks arrive via the HTTP click-link path or
#      `selfdefctl notify ack <id>` instead.
#
# [notifier.twilio]
# account_sid     = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
# auth_token_file = "/etc/selfdef/twilio.token"
# from            = "+15551234567"      # E.164, Twilio-provisioned
# to              = ["+15557654321"]    # E.164 recipients
# timeout_secs    = 10

# SDD-008 Q-C: commented [notifier.slack] example. Posts to a
# Slack channel via an incoming webhook. To enable:
#   1. Create a Slack app at https://api.slack.com/apps and add an
#      "Incoming Webhook" feature; pick the destination channel.
#   2. Copy the webhook URL into /etc/selfdef/slack.webhook.url
#      (mode 0600 owned by the selfdef user) — the URL is itself
#      the auth secret.
#   3. Uncomment the block below; flip channels above to include
#      "slack" in the order you want it tried.
#   4. The channel refuses any non-https webhook URL.
#
# [notifier.slack]
# webhook_url_file = "/etc/selfdef/slack.webhook.url"
# username         = "selfdef"
# icon_emoji       = ":shield:"

# SDD-008: commented [notifier.discord] example. Posts to a Discord
# channel via a webhook. To enable:
#   1. In Discord, server settings → integrations → webhooks → new.
#   2. Copy the webhook URL into /etc/selfdef/discord.webhook.url
#      (mode 0600). The URL is itself the auth secret.
#   3. Uncomment the block below; flip channels above to include
#      "discord".
#   4. Bodies > 1990 chars are truncated with a `…[truncated]`
#      marker (Discord caps `content` at 2000 chars).
#
# [notifier.discord]
# webhook_url_file = "/etc/selfdef/discord.webhook.url"
# username         = "selfdef"

# SDD-008 D-8: wall(1) session-attention channel. Broadcasts a
# one-line attention banner to every logged-in TTY when a
# high-severity event fires — the "talk to the bash session" path
# for operators who are at the terminal, not just at their phone.
# To enable:
#   1. Confirm /usr/bin/wall exists on the host (`which wall`).
#      Most Linux distros ship it as part of util-linux.
#   2. The daemon process needs permission to wall to user TTYs —
#      typically operator membership in the `tty` group OR running
#      as root. wall(1) silently skips TTYs it can't write to.
#   3. Uncomment the block below; flip channels above to include
#      "wall" (typically LAST in the chain — wall is loud).
#   4. severity_floor defaults to "high". Events below this severity
#      quietly skip wall to avoid bothering every TTY on routine
#      events.
#
# [notifier.wall]
# binary         = "/usr/bin/wall"
# severity_floor = "high"   # info|low|medium|high|critical|fatal

# SDD-008 D-5: path to the persistent escalation engine. When set,
# the daemon persists every outbound notification here and runs the
# wake-task escalation loop (D-5c): unacked notifications re-fire
# at their deadline, advance through rungs, and eventually close
# when max rungs are reached.
#
# Operators ack / forget / list pending escalations with:
#   selfdefctl notify ack    <event_id>
#   selfdefctl notify forget <event_id>
#   selfdefctl notify list   [--limit N] [--json]
#
# Default (unset): the daemon falls back to M4 fire-and-forget
# (no persistence, no escalation). Uncomment to enable.
#
# escalations_path = "/var/lib/selfdef/escalations.sqlite"

# SDD-008 D-6a: dispatcher operating mode. One of:
#   enforce — production; fire channels for real. The default.
#   audit   — dry-run; persist rows in the engine so audit trails +
#             ack/list/forget all work, but do NOT call channel.send.
#             Useful for pre-deployment verification that the
#             orchestrator wiring is correct without paging anyone.
# Only consulted when escalations_path is set; the M4 chain path
# always behaves as enforce.
#
# mode = "enforce"

# SDD-008 D-6b: named escalation profile. One of:
#   auto       — 2 attempts, 5-min ack window. The default. Matches
#                the D-5c hardcoded behaviour so existing operators
#                see zero change.
#   aggressive — 3 attempts at 60s / 180s / 600s. Wake-the-on-call
#                use cases where missed alerts are worse than a few
#                extra pages.
#   patient    — 4 attempts at 10/30/60/120 min. Non-critical
#                channels where rapid retries would just be noise.
# Operator-defined profiles + per-rung channel filtering ship
# under D-6c — see [notifier.profiles.*] below.
#
# profile = "auto"

# SDD-008 D-6c: operator-defined custom escalation profiles.
# Set [notifier].profile = "<name>" above to activate one defined
# here. Each rung is (channels, ack_window_secs):
#
#   channels        — allow-list of channel slugs. Empty = fire all
#                     configured channels (WUPHF semantics).
#   ack_window_secs — wait before advancing to the next rung. The
#                     wake task closes the row after the last rung's
#                     window expires unacked.
#
# Example: route to ntfy first, escalate to Twilio + Signal after
# 30 min, full WUPHF (every configured channel) after another hour.
#
# [notifier.profiles.weekend]
# rungs = [
#   { channels = ["ntfy"],              ack_window_secs = 1800 },
#   { channels = ["twilio", "signal"],  ack_window_secs = 3600 },
#   { channels = [],                    ack_window_secs = 600  },  # WUPHF
# ]

# SDD-008 D-7: severity threshold at or above which audit mode is
# bypassed (channels fire for real). The escape hatch for
# "operator misconfiguration cannot leave a blocker un-notified" —
# e.g. an operator who set mode = "audit" for a deployment-wide
# dry-run still wants `critical` and `fatal` events to actually
# page the on-call.
#
# One of: informational | low | medium | high | critical | fatal.
# Default unset = no floor (audit mode suppresses every severity).
#
# panic_floor = "critical"

# SDD-008 D-3: per-channel subscription filters. Without these
# blocks every channel sees every event (the M4 behaviour). Add a
# block per channel you want filtered:
#
#   severity_floor — one of informational|low|medium|high|critical|fatal.
#                    Events below this severity skip the channel.
#   event_kinds    — substrings matched case-insensitively against the
#                    OCSF class_uid name. e.g. ["security", "detection"]
#                    matches both "Security Finding" and "Detection
#                    Finding". Empty list = accept all kinds.
#
# Common posture: route High+ to SMS, Critical+ to phone, everything to
# email, security findings only to ntfy.
#
# IMPORTANT (Phase 6 F-2031-009): in v1 these filters apply ONLY on
# the legacy chain path (escalations_path unset). When the engine
# path is enabled (escalations_path set above), every channel sees
# every event regardless of [notifier.subscriptions.<ch>]. The
# daemon warns at startup when both knobs are set together so the
# misconfiguration is visible. Subscription-aware dispatching ships
# under the SDD-008 D-5e follow-up PR.
#
# [notifier.subscriptions.twilio]
# severity_floor = "critical"          # SMS for blockers only
#
# [notifier.subscriptions.smtp]
# severity_floor = "medium"            # email for medium+
#
# [notifier.subscriptions.ntfy]
# event_kinds    = ["security", "detection"]
#
# [notifier.subscriptions.signal]
# severity_floor = "high"

[responder]
allowed_actions = ["notify"]
dry_run         = true   # flip to false after verifying the
                          # rule + notifier chain works end-to-end

[api]
enabled    = false
# Once enabled, run `selfdefctl api rotate-token` to generate
# the bearer token at the path below (mode 0600).
# token_file = "/etc/selfdef/api.token"
# F-2027-058: read-vs-control token split. `token_file` gates
# the read endpoints (/events, /events/stream, /metrics, /status);
# the optional `control_token_file` below gates the mutating
# control endpoints (/control/* — rule reload, daemon kick).
# Leave control_token_file unset to disable the control plane
# entirely; set it to a separate 0600 file with its own rotated
# token to expose control under a stricter audience.
# control_token_file = "/etc/selfdef/api.control.token"
# SDD-007 D-4 / F-2028-037: caps on concurrent /events/stream
# subscribers. The defaults (64 global, 8 per-token) bound how
# much an authenticated bearer-holder can pin in process memory.
# Raise / lower per the deployment's audience size; leaving them
# unset falls back to the compiled-in defaults.
# max_sse_subscribers           = 64
# max_sse_subscribers_per_token = 8

[security]
# Rule signing (closes the original Known gap; see docs/dev/signing.md).
# Operator workflow:
#   1. Generate a minisign keypair offline: minisign -G -p policy.pub -s policy.key
#   2. Deploy policy.pub to /etc/selfdef/keys/policy.pub (mode 0644)
#   3. Sign every rule with minisign -S -m <rule>.yml -s policy.key
#   4. Set both knobs below to true / the key path and restart.
require_signed_rules    = false
# signing_public_key_file = "/etc/selfdef/keys/policy.pub"

[collectors.eventstream]
# Set integrity_check = true once /var/lib/selfdef/eventstream/
# is 0750 selfdef:selfdef (see docs/dev/rbac-posture.md +
# SECURITY.md hardening checklist).
# F-2027-057: integrity_check defends against TOCTOU + symlink
# swap by opening with O_NOFOLLOW + fstat-on-FD (closes
# F-2027-035). It only protects the *file open* — if `paths`
# points at a directory whose parents an attacker can rewrite
# the collector still follows the operator-supplied path. Keep
# `paths` rooted under a 0750 selfdef:selfdef dir and never list
# a symlinked target.
enabled         = false
integrity_check = false
paths           = []

# Other collectors (tetragon, suricata, ebpf, canary) live in
# the exhaustive example — copy the sections you need.
"#;

const STARTER_MODULES: &str = r#"# modules.toml — modules activated on this host.
#
# Written by `selfdefctl init modules`. Every shipped module is
# commented out below; uncomment the ones you want activated.
# Run `selfdefctl modules list` for the full per-module info,
# and `selfdefctl modules info <slug>` for a module's manifest.
#
# After editing, `selfdefctl modules apply --dry-run` shows
# what would happen.
#
# F-2027-059: every per-module `config = "..."` file below is a
# trust boundary — the daemon evaluates its contents at apply
# time. Provision each file as 0640 root:selfdef before
# uncommenting the matching block:
#     sudo install -m 0640 -o root -g selfdef \
#       /usr/share/selfdef/modules/<slug>.toml.example \
#       /etc/selfdef/modules/<slug>.toml
# A 0644 file lets any local user influence module apply
# behaviour the next time the daemon reloads.

# F-2028-022: every `config = "..."` line below must point at a
# file at 0640 root:selfdef. The header above ships the `install
# -m 0640 -o root -g selfdef ...` invocation. If you copy a
# single block here without scrolling up, this reminder will
# catch you.

# ----------------------------------------------------------------
# Detection / response modules
# ----------------------------------------------------------------

# Tetragon eBPF event substrate. Required by agent-guard.
# [modules.tetragon]
# config = "/etc/selfdef/modules/tetragon.toml"   # 0640 root:selfdef

# AI-machine hardening: agent-guard ships kernel-level policies
# (etc-write-guard, container-shell-guard, egress-guard, etc).
# Requires the tetragon module.
# [modules."agent-guard"]
# config = "/etc/selfdef/modules/agent-guard.toml"   # 0640 root:selfdef

# File-integrity baselining + drift alerts.
# [modules."integrity-sentinel"]
# config = "/etc/selfdef/modules/integrity-sentinel.toml"   # 0640 root:selfdef

# ----------------------------------------------------------------
# Network modules
# ----------------------------------------------------------------

# L2 bridge for multi-NIC inspection.
# [modules."bridge-l2"]
# config = "/etc/selfdef/modules/bridge-l2.toml"   # 0640 root:selfdef

# Suricata IDS over a bridge or NFQUEUE.
# [modules.suricata]
# config = "/etc/selfdef/modules/suricata.toml"   # 0640 root:selfdef

# PolarProxy TLS MitM for outbound visibility.
# [modules.polarproxy]
# config = "/etc/selfdef/modules/polarproxy.toml"   # 0640 root:selfdef

# Remote connectivity (relay / tailscale / cloudflare-tunnel).
# Multi-instance capable for relay-via-server only.
# [modules."vpn-bridge"]
# config = "/etc/selfdef/modules/vpn-bridge.toml"   # 0640 root:selfdef

# ----------------------------------------------------------------
# Visibility modules
# ----------------------------------------------------------------

# Prometheus + Grafana scrape config + dashboards.
# [modules.observability]
# config = "/etc/selfdef/modules/observability.toml"   # 0640 root:selfdef

# Host-baseline drift detection (passive observation).
# [modules."detect-host"]
# config = "/etc/selfdef/modules/detect-host.toml"   # 0640 root:selfdef
"#;

const CHECKLIST: &str = r#"# selfdef first-run checklist

Walk this list top-to-bottom on a fresh install. Each step links to the
runbook for the detail.

## 1. Daemon config
  $ sudo selfdefctl init config
  # Writes /etc/selfdef/selfdef.toml with a minimal starter.
  # Every security opt-in is OFF; turn them on per-section below.

## 2. Module selection
  $ sudo selfdefctl init modules
  # Writes /etc/selfdef/modules.toml with every shipped module
  # commented out. Uncomment the ones you want activated.

## 3. Start the daemon
  $ sudo systemctl enable --now selfdefd
  $ selfdefctl status

## 4. Apply modules
  $ selfdefctl modules apply --dry-run    # preview
  $ sudo selfdefctl modules apply         # live

## 5. Verify cross-cutting state
  $ selfdefctl doctor

## 6. Opt-in: rule signing (docs/dev/signing.md)
  $ minisign -G -p ./policy.pub -s ./policy.key   # offline
  $ sudo install -D -m 0644 ./policy.pub /etc/selfdef/keys/policy.pub
  # Set in /etc/selfdef/selfdef.toml:
  #   [security]
  #   require_signed_rules    = true
  #   signing_public_key_file = "/etc/selfdef/keys/policy.pub"
  $ find /etc/selfdef/rules -name '*.yml' -print0 \
        | xargs -0 -I{} minisign -S -m {} -s ./policy.key
  $ sudo systemctl restart selfdefd
  $ selfdefctl doctor

## 7. Opt-in: API + token rotation (docs/dev/signing.md)
  # In /etc/selfdef/selfdef.toml:
  #   [api]
  #   enabled    = true
  #   token_file = "/etc/selfdef/api.token"
  $ sudo selfdefctl api rotate-token
  $ sudo systemctl restart selfdefd

## 8. Opt-in: eventstream integrity (SECURITY.md Hardening checklist)
  $ sudo chown -R selfdef:selfdef /var/lib/selfdef/eventstream
  $ sudo chmod 0750 /var/lib/selfdef/eventstream
  # In /etc/selfdef/selfdef.toml:
  #   [collectors.eventstream]
  #   integrity_check = true
  $ sudo systemctl restart selfdefd

## 9. Opt-in: TracingPolicy signing (docs/dev/signing.md)
  # Sign every policy in /etc/tetragon/tetragon.tp.d/ with
  # the same minisign key as step 6.
  # In /etc/selfdef/modules/tetragon.toml:
  #   require_signed_policies = true
  $ sudo selfdefctl modules apply

## 10. Opt-in: agent-guard pod-label RBAC (k8s only, docs/dev/rbac-posture.md)
  # In /etc/selfdef/modules/agent-guard.toml:
  #   scope = "pod-label"
  #   pod_label_key   = "selfdef.io/agent"
  #   pod_label_value = "true"
  $ selfdefctl rbac check --probe

## 11. Periodic health check
  # /etc/systemd/system/selfdef-doctor.timer (hourly)
  # See docs/dev/operator-health-check.md for the unit + timer.

## Done.
You now have a deployment that opts into every audit-shipped
security feature. Re-run `selfdefctl doctor` whenever you
change config or rotate keys.
"#;
