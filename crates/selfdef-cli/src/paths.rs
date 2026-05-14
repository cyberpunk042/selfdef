//! F-2027-017: canonical default paths for `selfdef-cli`.
//!
//! Before this module, three files (`init.rs`, `modules.rs`,
//! `main.rs`) each redefined the on-disk layout. Drift between
//! them meant `selfdefctl init config` could write to one path
//! while `selfdefctl modules apply` looked at a different one.
//! Every default path the CLI knows about lives here now.
//!
//! Layout (matches the .deb / .tar.gz packaging):
//!
//! ```text
//! /etc/selfdef/
//!   selfdef.toml              # daemon config (DAEMON_CONFIG)
//!   modules.toml              # host-level module activation (MODULES_HOST_CONFIG)
//!   rules/                    # detection-rule drop dir
//!   keys/policy.pub           # rule-signing pubkey
//!   modules/                  # per-module config files (MODULES_PER_MODULE_DIR)
//!     <slug>.toml
//!     agent-guard.toml        # `doctor` reads this for rbac scope
//! ```
//!
//! Operators can override every path on the command line; these
//! constants are only the "no flag passed" defaults.

/// Daemon config (read by every `selfdefctl` verb that needs daemon
/// state) — `/etc/selfdef/selfdef.toml`.
pub(crate) const DAEMON_CONFIG: &str = "/etc/selfdef/selfdef.toml";

/// Host-level module activation file — `/etc/selfdef/modules.toml`.
/// Lists which modules are active on this host.
pub(crate) const MODULES_HOST_CONFIG: &str = "/etc/selfdef/modules.toml";

/// Directory holding per-module config files
/// (`/etc/selfdef/modules/<slug>.toml`).
pub(crate) const MODULES_PER_MODULE_DIR: &str = "/etc/selfdef/modules";

/// Path the `doctor` rbac category looks at for agent-guard's
/// configured scope, in the absence of an env override. Lives
/// under `MODULES_PER_MODULE_DIR`.
pub(crate) const AGENT_GUARD_CONFIG: &str = "/etc/selfdef/modules/agent-guard.toml";

// F-2028-001: compile-time invariants on the path constants
// above. A future maintainer who renames the project's etc-dir
// (or accidentally drops the leading slash) gets a build error
// instead of a runtime drift discovered weeks later. The asserts
// run at compile time — zero runtime cost.
const _: () = {
    // Every default path must be under `/etc/selfdef/`.
    let dc = DAEMON_CONFIG.as_bytes();
    let mc = MODULES_HOST_CONFIG.as_bytes();
    let md = MODULES_PER_MODULE_DIR.as_bytes();
    let ag = AGENT_GUARD_CONFIG.as_bytes();
    assert!(starts_with(dc, b"/etc/selfdef/"));
    assert!(starts_with(mc, b"/etc/selfdef/"));
    assert!(starts_with(md, b"/etc/selfdef/"));
    assert!(starts_with(ag, b"/etc/selfdef/"));
    // The agent-guard config must live under the per-module dir.
    assert!(starts_with(ag, MODULES_PER_MODULE_DIR.as_bytes()));
};

#[allow(clippy::indexing_slicing, dead_code)] // const-context only.
const fn starts_with(haystack: &[u8], needle: &[u8]) -> bool {
    if haystack.len() < needle.len() {
        return false;
    }
    let mut i = 0;
    while i < needle.len() {
        if haystack[i] != needle[i] {
            return false;
        }
        i += 1;
    }
    true
}
