//! `selfdef-ssh-wrap` — drop-in replacement for ssh that enforces
//! per-host policy and emits OCSF events for every session.
//!
//! Install with the canonical pattern:
//!
//! ```bash
//! sudo install -m 0755 target/release/selfdef-ssh-wrap /usr/local/bin/
//! ln -sf /usr/local/bin/selfdef-ssh-wrap ~/.local/bin/ssh
//! # ensure ~/.local/bin precedes /usr/bin on PATH
//! ```
//!
//! The wrapper then runs whenever you type `ssh`, applies your policy,
//! exec's the real ssh (default `/usr/bin/ssh`, override via
//! `SELFDEF_SSH_PATH`), and records session events to
//! `~/.local/share/selfdef/ssh-wrap.jsonl` (override via
//! `SELFDEF_SSH_EVENT_LOG`).

#![deny(unsafe_code)]
// Rust 2024 marked `std::env::set_var` as unsafe. The test module in
// `events.rs` localizes its single use behind an `unsafe` block; production
// code stays unsafe-free.
#![cfg_attr(test, allow(unsafe_code))]
// This is a binary crate organized into internal modules; the `pub`
// markers on items in those modules don't escape the binary boundary.
// The lint is meaningful for libraries; for this bin it's noise.
#![allow(unreachable_pub, dead_code)]
#![allow(clippy::missing_errors_doc)]

mod argv;
mod events;
mod policy;

use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use anyhow::{Context, Result};

const REAL_SSH_DEFAULT: &str = "/usr/bin/ssh";

fn main() {
    if let Err(e) = run() {
        eprintln!("selfdef-ssh-wrap: {e:#}");
        std::process::exit(255);
    }
}

fn run() -> Result<()> {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();

    // ssh stops parsing its own options at the target; everything from the
    // target onward is the remote command and is forwarded verbatim. Locate
    // the target first so we only ever inspect ssh's OWN options — never the
    // remote command (which could otherwise be mangled into ssh flags, or have
    // a word stripped because it collides with a denied flag).
    let target_idx = argv::target_index(&raw_args);

    // Help/version pass-through. Only ssh's own options count — a `--help` that
    // belongs to the remote command must not short-circuit us.
    let option_region = match target_idx {
        Some(i) => &raw_args[..i],
        None => &raw_args[..],
    };
    if option_region
        .iter()
        .any(|a| matches!(a.as_str(), "-V" | "--version" | "-h" | "--help"))
    {
        return exec_passthrough(&raw_args);
    }

    let Some(target_idx) = target_idx else {
        // No target — let real ssh print its usage error.
        return exec_passthrough(&raw_args);
    };

    let policy_file = policy::load(policy_path().as_deref()).context("loading ssh-wrap policy")?;
    let target = raw_args[target_idx].as_str();
    // Classify ONLY the options before the target. The target and remote
    // command (`raw_args[target_idx..]`) are appended untouched below.
    let tokens = argv::classify(&raw_args[..target_idx]);

    let (user, host, port) = argv::parse_target(target);
    let resolved = policy::ResolvedPolicy::resolve(&policy_file, &host);

    let denied_flags = resolved.denied_flags();
    let denied_o = resolved.denied_o_keys();

    // Track what we strip so we can record a policy-violation event.
    let stripped = compute_stripped(&tokens, &denied_flags, &denied_o);

    let filtered = argv::filter(&tokens, &denied_flags, &denied_o);
    let mut final_args = resolved.to_ssh_args();
    final_args.extend(filtered);
    // Target spec + remote command, forwarded byte-for-byte.
    final_args.extend(raw_args[target_idx..].iter().cloned());

    // Best-effort: does ~/.ssh/known_hosts contain this host?
    let first_seen = host_first_seen(&host).unwrap_or(false);

    let sink = events::EventSink::open().context("opening event sink")?;
    let _ = sink.session_start(target, &host, port, user.as_deref(), first_seen);
    if !stripped.is_empty() {
        let _ = sink.policy_strip(target, &stripped);
    }

    let ssh_path = std::env::var_os("SELFDEF_SSH_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(REAL_SSH_DEFAULT));

    let start = Instant::now();
    let status = Command::new(&ssh_path)
        .args(&final_args)
        .status()
        .with_context(|| format!("spawning {}", ssh_path.display()))?;
    let elapsed = start.elapsed().as_secs_f64();

    let _ = sink.session_end(target, elapsed, status.code());

    std::process::exit(status.code().unwrap_or(255));
}

fn exec_passthrough(args: &[String]) -> Result<()> {
    let ssh_path = std::env::var_os("SELFDEF_SSH_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(REAL_SSH_DEFAULT));
    let status = Command::new(&ssh_path)
        .args(args)
        .status()
        .with_context(|| format!("spawning {}", ssh_path.display()))?;
    std::process::exit(status.code().unwrap_or(255));
}

fn policy_path() -> Option<PathBuf> {
    std::env::var_os("SELFDEF_SSH_POLICY").map(PathBuf::from)
}

/// Returns Ok(true) if this host has NO entry in known_hosts (i.e. first
/// time we've connected). Uses `ssh-keygen -F` so hashed entries Just Work.
fn host_first_seen(host: &str) -> Result<bool> {
    let out = Command::new("ssh-keygen")
        .arg("-F")
        .arg(host)
        .output()
        .context("invoking ssh-keygen")?;
    // ssh-keygen -F prints matching entries on success, exits 0; prints
    // nothing and exits 1 when nothing matches.
    Ok(!out.status.success())
}

fn compute_stripped(
    tokens: &[argv::Token<'_>],
    denied_flags: &[char],
    denied_o: &[&str],
) -> Vec<String> {
    let mut out = Vec::new();
    for tok in tokens {
        match tok {
            argv::Token::Flag(c) if denied_flags.contains(c) => {
                out.push(format!("-{c}"));
            }
            argv::Token::Option('o', v) | argv::Token::AttachedOption('o', v) => {
                // Same key extraction as argv::filter — must stay in lock-step
                // or the event log would under-report a strip the filter made
                // (or vice-versa). Handles both `Key=Val` and `Key Val`.
                let key = argv::o_option_key(v);
                if denied_o.iter().any(|k| key.eq_ignore_ascii_case(k)) {
                    out.push(format!("-o {v}"));
                }
            }
            // A denied VALUE-option (e.g. L/R/D/W when port-forwarding is off)
            // is stripped by argv::filter; record it too so the policy_strip
            // event mirrors the action. Without this a BLOCKED tunnel attempt
            // produces no audit event — the filter prevents it but the operator
            // never sees it. ('o' is handled by the key-denylist arm above and
            // matches earlier, so it never reaches here.)
            argv::Token::Option(c, v) | argv::Token::AttachedOption(c, v)
                if denied_flags.contains(c) =>
            {
                out.push(format!("-{c} {v}"));
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_string()).collect()
    }

    #[test]
    fn compute_stripped_logs_denied_value_option_for_audit() {
        // Lock-step with argv::filter (its own comment demands it): filter
        // strips a denied value-option (e.g. -L/-R/-D/-W when port-forwarding
        // is off), so compute_stripped must record it too — else a BLOCKED
        // tunnel attempt produces no policy_strip event and the operator never
        // sees the attempt. Enforcement is unaffected; this closes the
        // audit-visibility gap.
        let argv = args(&["-L", "8080:internal-db:5432", "user@host"]);
        let idx = argv::target_index(&argv).unwrap();
        let stripped = compute_stripped(&argv::classify(&argv[..idx]), &['L'], &[]);
        assert!(
            stripped
                .iter()
                .any(|x| x.contains("-L") && x.contains("8080")),
            "denied port-forward must be recorded for the audit event, got {stripped:?}"
        );

        // Attached form too (`-L8080:...`).
        let argv = args(&["-L8080:internal-db:5432", "user@host"]);
        let idx = argv::target_index(&argv).unwrap();
        let stripped = compute_stripped(&argv::classify(&argv[..idx]), &['L'], &[]);
        assert!(
            stripped.iter().any(|x| x.contains("8080")),
            "attached denied port-forward must be recorded, got {stripped:?}"
        );

        // The existing -o key strip is still recorded (no regression).
        let argv = args(&["-o", "ProxyCommand=/x", "user@host"]);
        let idx = argv::target_index(&argv).unwrap();
        let stripped = compute_stripped(&argv::classify(&argv[..idx]), &[], &["ProxyCommand"]);
        assert!(
            stripped.iter().any(|x| x.contains("ProxyCommand")),
            "got {stripped:?}"
        );

        // A denied bare flag is still recorded (no regression).
        let argv = args(&["-A", "user@host"]);
        let idx = argv::target_index(&argv).unwrap();
        let stripped = compute_stripped(&argv::classify(&argv[..idx]), &['A'], &[]);
        assert!(stripped.iter().any(|x| x == "-A"), "got {stripped:?}");
    }
}
