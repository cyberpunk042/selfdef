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

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
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

    // Help/version pass-through without policy or event logging.
    if raw_args.iter().any(|a| matches!(a.as_str(), "-V" | "--version" | "-h" | "--help")) {
        return exec_passthrough(&raw_args);
    }

    let policy_file = policy::load(policy_path().as_deref())
        .context("loading ssh-wrap policy")?;
    let tokens = argv::classify(&raw_args);
    let target = argv::extract_target(&tokens);

    let Some(target) = target else {
        // No target — let real ssh print its usage error.
        return exec_passthrough(&raw_args);
    };

    let (user, host, port) = argv::parse_target(target);
    let resolved = policy::ResolvedPolicy::resolve(&policy_file, &host);

    let denied_flags = resolved.denied_flags();
    let denied_o = resolved.denied_o_keys();

    // Track what we strip so we can record a policy-violation event.
    let stripped = compute_stripped(&tokens, &denied_flags, &denied_o);

    let filtered = argv::filter(&tokens, &denied_flags, &denied_o);
    let mut final_args = resolved.to_ssh_args();
    final_args.extend(filtered);

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
                let key = v.split('=').next().unwrap_or("").trim();
                if denied_o.iter().any(|k| key.eq_ignore_ascii_case(k)) {
                    out.push(format!("-o {v}"));
                }
            }
            _ => {}
        }
    }
    out
}
