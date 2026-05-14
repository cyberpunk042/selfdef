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
# Add "ntfy", "signal" once the matching [notifier.<name>]
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

# ----------------------------------------------------------------
# Detection / response modules
# ----------------------------------------------------------------

# Tetragon eBPF event substrate. Required by agent-guard.
# [modules.tetragon]
# config = "/etc/selfdef/modules/tetragon.toml"

# AI-machine hardening: agent-guard ships kernel-level policies
# (etc-write-guard, container-shell-guard, egress-guard, etc).
# Requires the tetragon module.
# [modules."agent-guard"]
# config = "/etc/selfdef/modules/agent-guard.toml"

# File-integrity baselining + drift alerts.
# [modules."integrity-sentinel"]
# config = "/etc/selfdef/modules/integrity-sentinel.toml"

# ----------------------------------------------------------------
# Network modules
# ----------------------------------------------------------------

# L2 bridge for multi-NIC inspection.
# [modules."bridge-l2"]
# config = "/etc/selfdef/modules/bridge-l2.toml"

# Suricata IDS over a bridge or NFQUEUE.
# [modules.suricata]
# config = "/etc/selfdef/modules/suricata.toml"

# PolarProxy TLS MitM for outbound visibility.
# [modules.polarproxy]
# config = "/etc/selfdef/modules/polarproxy.toml"

# Remote connectivity (relay / tailscale / cloudflare-tunnel).
# Multi-instance capable for relay-via-server only.
# [modules."vpn-bridge"]
# config = "/etc/selfdef/modules/vpn-bridge.toml"

# ----------------------------------------------------------------
# Visibility modules
# ----------------------------------------------------------------

# Prometheus + Grafana scrape config + dashboards.
# [modules.observability]
# config = "/etc/selfdef/modules/observability.toml"

# Host-baseline drift detection (passive observation).
# [modules."detect-host"]
# config = "/etc/selfdef/modules/detect-host.toml"
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
