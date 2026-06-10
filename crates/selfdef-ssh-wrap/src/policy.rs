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
        // A legitimate hostname never contains '@'. If the parsed host does, the
        // target was ambiguous (multi-'@', e.g. `user@trusted@evil.com`):
        // ssh-wrap split the target on the FIRST '@' to pick this host for
        // policy, but main.rs forwards the target BYTE-FOR-BYTE to the real ssh,
        // which re-parses it with ITS OWN '@' rule and may connect to a
        // different host. A host-specific override (which can RELAX a setting,
        // e.g. `[hosts."trusted*"] forward_agent = true`) would then be applied
        // for a host ssh isn't actually connecting to — a parser-differential
        // that smuggles a relaxation (agent/X11/port forwarding) onto an
        // untrusted connection. Refuse host-specific overrides for an ambiguous
        // host; only the host-independent secure defaults (+ global defaults)
        // stand. Legitimate single-'@'/no-'@' targets never reach this branch
        // (their host carries no '@'), so their behaviour is unchanged.
        if !host.contains('@') {
            for (pattern, host_policy) in &file.hosts {
                if matches_pattern(pattern, host) {
                    merged = host_policy.merge_over(&merged);
                }
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
        // `*.internal` matches a SUBDOMAIN of `internal` — the `.` is a label
        // boundary. Requiring only `ends_with("internal")` (the pre-fix
        // behaviour, which dropped the dot) also matched `eviltinternal`,
        // letting an unrelated external host borrow a trusted-subdomain
        // override (e.g. forward_agent) — a policy-scoping bypass. Match the
        // literal `.suffix` with at least one label in front.
        let dotted = format!(".{suffix}");
        return host.len() > dotted.len() && host.ends_with(&dotted);
    }
    if let Some(prefix) = pattern.strip_suffix(".*") {
        // Symmetric: `foo.*` matches `foo.bar`, not `foobar`.
        let dotted = format!("{prefix}.");
        return host.len() > dotted.len() && host.starts_with(&dotted);
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
    fn ambiguous_multi_at_host_ignores_overrides() {
        // A `trusted*` override relaxes agent forwarding. An attacker crafts a
        // multi-'@' target (`user@trusted@evil.com`); ssh-wrap's first-'@' parse
        // yields host "trusted@evil.com", which a prefix override would match —
        // but the real ssh re-parses the forwarded target and connects to
        // evil.com. The override must NOT apply to a host containing '@'
        // (fail-closed), so agent forwarding stays denied.
        let toml_str = r#"
            [hosts."trusted*"]
            forward_agent = true
            port_forwarding = true
        "#;
        let file: PolicyFile = toml::from_str(toml_str).unwrap();
        // Ambiguous host (still carries the '@') — override refused.
        let amb = ResolvedPolicy::resolve(&file, "trusted@evil.com");
        assert!(
            !amb.forward_agent,
            "override must not relax an ambiguous host"
        );
        assert!(!amb.port_forwarding);
        // Legitimate host with the same prefix — override still applies.
        let ok = ResolvedPolicy::resolve(&file, "trusted.example.com");
        assert!(ok.forward_agent);
        assert!(ok.port_forwarding);
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
    fn wildcard_suffix_requires_label_boundary() {
        // SCOPING BYPASS regression: `*.internal` is a trusted-subdomain
        // override; it must NOT leak onto an external host that merely ENDS in
        // "internal" with no dot (the pre-fix `ends_with("internal")` matched
        // `eviltinternal` → it would have borrowed port_forwarding=true).
        let file: PolicyFile = toml::from_str(
            r#"
            [hosts."*.internal"]
            port_forwarding = true
        "#,
        )
        .unwrap();
        for legit in ["db.internal", "a.b.internal"] {
            assert!(
                ResolvedPolicy::resolve(&file, legit).port_forwarding,
                "{legit} is a real subdomain and must match"
            );
        }
        for evil in ["eviltinternal", "internal", "xinternal"] {
            assert!(
                !ResolvedPolicy::resolve(&file, evil).port_forwarding,
                "{evil} must NOT borrow the *.internal override"
            );
        }
    }

    #[test]
    fn wildcard_prefix_dot_requires_label_boundary() {
        // Symmetric `prefix.*`: `foo.*` matches `foo.bar`, not `foobar`.
        let file: PolicyFile = toml::from_str(
            r#"
            [hosts."foo.*"]
            port_forwarding = true
        "#,
        )
        .unwrap();
        assert!(ResolvedPolicy::resolve(&file, "foo.bar").port_forwarding);
        assert!(!ResolvedPolicy::resolve(&file, "foobar").port_forwarding);
        assert!(!ResolvedPolicy::resolve(&file, "foo").port_forwarding);
    }

    #[test]
    fn ssh_args_carry_overrides() {
        let policy = ResolvedPolicy::resolve(&PolicyFile::default(), "h");
        let args = policy.to_ssh_args();
        assert!(args.iter().any(|s| s == "ForwardAgent=no"));
        assert!(args.iter().any(|s| s == "StrictHostKeyChecking=accept-new"));
    }
}
