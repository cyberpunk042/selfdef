//! `selfdefctl ssh-wrap` — operator surface for MS014 / SDD-052
//! drop-in `ssh` replacement.

use anyhow::Result;

pub(crate) fn run_install_help() -> Result<i32> {
    println!("MS014 / SDD-052 selfdef-ssh-wrap install");
    println!();
    println!("1. Build (release for distribution):");
    println!("     cargo build --release -p selfdef-ssh-wrap");
    println!();
    println!("2. Install the binary host-wide (requires sudo):");
    println!("     sudo install -m 0755 target/release/selfdef-ssh-wrap /usr/local/bin/");
    println!();
    println!("3. PATH-shadow `ssh` for your user:");
    println!("     mkdir -p ~/.local/bin");
    println!("     ln -sf /usr/local/bin/selfdef-ssh-wrap ~/.local/bin/ssh");
    println!();
    println!("4. Verify ~/.local/bin precedes /usr/bin on PATH:");
    println!("     which ssh   # should print ~/.local/bin/ssh");
    println!();
    println!("5. Author per-host policy at ~/.config/selfdef/ssh-wrap.toml.");
    println!();
    println!("After install, every `ssh <host>` invocation transparently");
    println!("loads the policy, applies the gate, emits an OCSF event, and");
    println!("execs the real ssh binary (SELFDEF_SSH_PATH or /usr/bin/ssh).");
    Ok(0)
}

pub(crate) fn run_doctrine() -> Result<i32> {
    println!("MS014 / SDD-052 ssh-wrap doctrine");
    println!();
    println!("The wrapper is YOUR client-side defense against malicious SSH");
    println!("servers (SDD-004 adversary 4). It enforces:");
    println!();
    println!("  - per-host policy (forward_agent / forward_x11 / require_known_host)");
    println!("  - OCSF event emission per session (~/.local/share/selfdef/ssh-wrap.jsonl)");
    println!("  - refuse-to-connect on policy violation");
    println!("  - PATH-shadow drop-in install (transparent to muscle memory)");
    println!();
    println!("Policy file: ~/.config/selfdef/ssh-wrap.toml (operator-authored).");
    println!("Event log:   ~/.local/share/selfdef/ssh-wrap.jsonl (operator-owned).");
    println!();
    println!("Override the real-ssh path via SELFDEF_SSH_PATH env (default /usr/bin/ssh).");
    println!();
    println!("Run `selfdefctl ssh-wrap install` for the install steps.");
    Ok(0)
}
