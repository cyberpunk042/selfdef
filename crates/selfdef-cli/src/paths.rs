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
