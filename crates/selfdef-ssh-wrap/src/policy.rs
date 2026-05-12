//! Policy: what the wrapper enforces on each ssh invocation.
//!
//! Loaded from `~/.config/selfdef/ssh-wrap.toml` (or `$SELFDEF_SSH_POLICY`).
//! Layout:
//!
//! ```toml
//! [defaults]
//! forward_agent = false
//! forward_x11 = false
//! port_forwarding = false
//! strict_host_key = "accept-new"
//! exit_on_forward_failure = true
//!
//! [hosts."myserver.example.com"]
//! forward_agent = true   # override: trusted host
//!
//! [hosts."*.internal"]
//! port_forwarding = true
//! ```
//!
//! Host pattern matching is intentionally simple: exact match, `*.suffix`
//! glob, or `prefix*` glob. No regex, no recursion, no surprises.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyFile {
    pub defaults: HostPolicy,
    #[serde(default)]
    pub hosts: HashMap<String, HostPolicy>,
}

impl Default for PolicyFile {
    fn default() -> Self {
        Self {
            defaults: HostPolicy::secure_defaults(),
            hosts: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HostPolicy {
    pub forward_agent: Option<bool>,
    pub forward_x11: Option<bool>,
    pub port_forwarding: Option<bool>,
    pub strict_host_key: Option<String>, // "yes" | "accept-new" | "no"
    pub exit_on_forward_failure: Option<bool>,
    pub connect_timeout_secs: Option<u32>,
    pub server_alive_interval_secs: Option<u32>,
}

impl Default for HostPolicy {
    fn default() -> Self {
        Self {
            forward_agent: None,
            forward_x11: None,
            port_forwarding: None,
            strict_host_key: None,
            exit_on_forward_failure: None,
            connect_timeout_secs: None,
            server_alive_interval_secs: None,
        }
    }
}

impl HostPolicy {
    /// Sensible defaults for a paranoid client.
    fn secure_defaults() -> Self {
        Self {
            forward_agent: Some(false),
            forward_x11: Some(false),
            port_forwarding: Some(false),
            strict_host_key: Some("accept-new".into()),
            exit_on_forward_failure: Some(true),
            connect_timeout_secs: Some(20),
            server_alive_interval_secs: Some(30),
        }
    }

    fn merge_over(&self, base: &Self) -> Self {
        Self {
            forward_agent: self.forward_agent.or(base.forward_agent),
            forward_x11: self.forward_x11.or(base.forward_x11),
            port_forwarding: self.port_forwarding.or(base.port_forwarding),
            strict_host_key: self
                .strict_host_key
                .clone()
                .or_else(|| base.strict_host_key.clone()),
            exit_on_forward_failure: self
                .exit_on_forward_failure
                .or(base.exit_on_forward_failure),
            connect_timeout_secs: self.connect_timeout_secs.or(base.connect_timeout_secs),
            server_alive_interval_secs: self
                .server_alive_interval_secs
                .or(base.server_alive_interval_secs),
        }
    }
}

/// Final, fully-resolved policy after merging defaults and host overrides.
#[derive(Debug, Clone)]
pub struct ResolvedPolicy {
    pub forward_agent: bool,
    pub forward_x11: bool,
    pub port_forwarding: bool,
    pub strict_host_key: String,
    pub exit_on_forward_failure: bool,
    pub connect_timeout_secs: u32,
    pub server_alive_interval_secs: u32,
}

impl ResolvedPolicy {
    pub fn resolve(file: &PolicyFile, host: &str) -> Self {
        let mut merged = HostPolicy::secure_defaults().merge_over(&file.defaults);
        for (pattern, host_policy) in &file.hosts {
            if matches_pattern(pattern, host) {
                merged = host_policy.merge_over(&merged);
            }
        }
        // Anywhere a value somehow still None, fall back to secure defaults.
        let fb = HostPolicy::secure_defaults();
        Self {
            forward_agent: merged
                .forward_agent
                .unwrap_or_else(|| fb.forward_agent.unwrap()),
            forward_x11: merged
                .forward_x11
                .unwrap_or_else(|| fb.forward_x11.unwrap()),
            port_forwarding: merged
                .port_forwarding
                .unwrap_or_else(|| fb.port_forwarding.unwrap()),
            strict_host_key: merged
                .strict_host_key
                .unwrap_or_else(|| fb.strict_host_key.unwrap()),
            exit_on_forward_failure: merged
                .exit_on_forward_failure
                .unwrap_or_else(|| fb.exit_on_forward_failure.unwrap()),
            connect_timeout_secs: merged
                .connect_timeout_secs
                .unwrap_or_else(|| fb.connect_timeout_secs.unwrap()),
            server_alive_interval_secs: merged
                .server_alive_interval_secs
                .unwrap_or_else(|| fb.server_alive_interval_secs.unwrap()),
        }
    }

    /// Render as a series of `-o key=value` ssh arguments to be prepended.
    pub fn to_ssh_args(&self) -> Vec<String> {
        let mut out = Vec::new();
        let push = |out: &mut Vec<String>, kv: String| {
            out.push("-o".into());
            out.push(kv);
        };
        push(
            &mut out,
            format!("ForwardAgent={}", yesno(self.forward_agent)),
        );
        push(&mut out, format!("ForwardX11={}", yesno(self.forward_x11)));
        push(
            &mut out,
            format!("ForwardX11Trusted={}", yesno(self.forward_x11)),
        );
        push(
            &mut out,
            format!("ClearAllForwardings={}", yesno(!self.port_forwarding)),
        );
        push(
            &mut out,
            format!(
                "ExitOnForwardFailure={}",
                yesno(self.exit_on_forward_failure)
            ),
        );
        push(
            &mut out,
            format!("StrictHostKeyChecking={}", self.strict_host_key),
        );
        push(
            &mut out,
            format!("ConnectTimeout={}", self.connect_timeout_secs),
        );
        push(
            &mut out,
            format!("ServerAliveInterval={}", self.server_alive_interval_secs),
        );
        out
    }

    /// Single-letter flags to strip from the user's argv when policy denies
    /// them (e.g. `-A` for agent fwd).
    pub fn denied_flags(&self) -> Vec<char> {
        let mut out = Vec::new();
        if !self.forward_agent {
            out.push('A');
        }
        if !self.forward_x11 {
            out.push('X');
            out.push('Y');
        }
        if !self.port_forwarding {
            out.push('L');
            out.push('R');
            out.push('D');
            out.push('W');
        }
        out
    }

    /// `-o` keys whose user-supplied values must be discarded.
    pub fn denied_o_keys(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if !self.forward_agent {
            out.push("ForwardAgent");
        }
        if !self.forward_x11 {
            out.push("ForwardX11");
            out.push("ForwardX11Trusted");
        }
        if !self.port_forwarding {
            out.push("LocalForward");
            out.push("RemoteForward");
            out.push("DynamicForward");
        }
        out
    }
}

fn yesno(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

fn matches_pattern(pattern: &str, host: &str) -> bool {
    if pattern == host {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host.ends_with(suffix) && host != suffix;
    }
    if let Some(prefix) = pattern.strip_suffix(".*") {
        return host.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return host.ends_with(suffix);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return host.starts_with(prefix);
    }
    false
}

pub fn load(path: Option<&Path>) -> anyhow::Result<PolicyFile> {
    let path = match path {
        Some(p) => p.to_path_buf(),
        None => default_path()?,
    };
    if !path.exists() {
        return Ok(PolicyFile::default());
    }
    let content = std::fs::read_to_string(&path)?;
    let file: PolicyFile = toml::from_str(&content)?;
    Ok(file)
}

fn default_path() -> anyhow::Result<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .ok_or_else(|| anyhow::anyhow!("can't determine config dir"))?;
    Ok(base.join("selfdef").join("ssh-wrap.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_deny_everything() {
        let policy = ResolvedPolicy::resolve(&PolicyFile::default(), "any.example.com");
        assert!(!policy.forward_agent);
        assert!(!policy.forward_x11);
        assert!(!policy.port_forwarding);
        assert_eq!(policy.strict_host_key, "accept-new");
    }

    #[test]
    fn per_host_override_wins() {
        let toml_str = r#"
            [defaults]
            forward_agent = false

            [hosts."trusted.example.com"]
            forward_agent = true
        "#;
        let file: PolicyFile = toml::from_str(toml_str).unwrap();
        let policy = ResolvedPolicy::resolve(&file, "trusted.example.com");
        assert!(policy.forward_agent);
        let other = ResolvedPolicy::resolve(&file, "untrusted.example.com");
        assert!(!other.forward_agent);
    }

    #[test]
    fn wildcard_suffix_match() {
        let toml_str = r#"
            [hosts."*.internal"]
            port_forwarding = true
        "#;
        let file: PolicyFile = toml::from_str(toml_str).unwrap();
        let policy = ResolvedPolicy::resolve(&file, "db.internal");
        assert!(policy.port_forwarding);
        let policy = ResolvedPolicy::resolve(&file, "db.external");
        assert!(!policy.port_forwarding);
    }

    #[test]
    fn ssh_args_carry_overrides() {
        let policy = ResolvedPolicy::resolve(&PolicyFile::default(), "h");
        let args = policy.to_ssh_args();
        assert!(args.iter().any(|s| s == "ForwardAgent=no"));
        assert!(args.iter().any(|s| s == "StrictHostKeyChecking=accept-new"));
    }
}
