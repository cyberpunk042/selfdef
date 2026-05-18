//! # `selfdef-bashrc-install`
//!
//! SD-R-BASHRC-1 — operator-facing bashrc installer harness. The
//! actual installer is a bash script at
//! `packaging/bash/selfdefctl-bashrc-install.sh`; this crate exists
//! so `cargo test --workspace` exercises it from CI.
//!
//! Cross-repo binding to **sovereign-os R447** (E11.M6, bashrc opt-in).
//! Per operator §1g verbatim:
//!
//! > "the bashrc we can offer to configure it too and we can add our
//! >  autocompletes and aliases and manual / helps and menus"
//!
//! ## Public surface
//!
//! - [`INSTALLER_REL_PATH`] — repo-relative path to the installer
//!   shell script, exposed so callers (CI, packagers, downstream
//!   tooling) can locate it deterministically.
//! - [`BLOCK_BEGIN_SENTINEL`] / [`BLOCK_END_SENTINEL`] — the exact
//!   sentinel strings the installer writes around its managed
//!   region. Stable contract.
//!
//! Operator-anti-destruction: the installer's sentinel pattern means
//! edits OUTSIDE the block survive every install/uninstall cycle.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Repo-relative path to the operator-facing bashrc installer.
pub const INSTALLER_REL_PATH: &str = "packaging/bash/selfdefctl-bashrc-install.sh";

/// Sentinel string marking the start of the managed block in the
/// operator's bashrc. Stable contract — downstream tooling may grep
/// for this to detect installation.
pub const BLOCK_BEGIN_SENTINEL: &str = "# >>> selfdef-bashrc (SD-R-BASHRC-1) begin >>>";

/// Sentinel string marking the end of the managed block.
pub const BLOCK_END_SENTINEL: &str = "# <<< selfdef-bashrc (SD-R-BASHRC-1) end <<<";

/// Operator-discoverable aliases shipped by the installer. Exposed
/// so external auditors (CI / packagers) can assert against them
/// without grepping the script directly.
pub const SHIPPED_ALIASES: &[&str] = &[
    "sdctl",
    "sdstatus",
    "sdmodules",
    "sddoctor",
    "sdcheck",
    "sdevents",
    "sdkeys",
    "sdrbac",
    "sdnotify",
    "sdinit",
];

/// Top-level selfdefctl subcommands the installer's tab-completion
/// must enumerate (matches `crates/selfdef-cli/src/main.rs`
/// `enum Command` variants).
pub const COMPLETION_TOP_VERBS: &[&str] = &[
    "status",
    "events",
    "reload",
    "rules",
    "panic",
    "forensics",
    "modules",
    "api",
    "notify",
    "keys",
    "rbac",
    "doctor",
    "init",
    "version",
];
