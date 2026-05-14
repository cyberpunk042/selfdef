//! Layered configuration for selfdef.
//!
//! Sources, in priority order (later overrides earlier):
//! 1. Defaults baked into [`Config::default`].
//! 2. The TOML file at the path given to [`Config::load`].
//! 3. Environment variables prefixed `SELFDEF_` (`__` for nested keys,
//!    e.g. `SELFDEF_DAEMON__LOG_LEVEL=debug`).
//!
//! The loaded config is owned: nothing in the runtime reads from disk again
//! until SIGHUP triggers a fresh `Config::load`.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

use std::path::{Path, PathBuf};

use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to load configuration: {0}")]
    Figment(#[from] figment::Error),
}

// ---------------------------------------------------------------- top level

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub daemon: DaemonConfig,
    pub bus: BusConfig,
    pub store: StoreConfig,
    pub collectors: CollectorsConfig,
    pub correlator: CorrelatorConfig,
    pub notifier: NotifierConfig,
    pub responder: ResponderConfig,
    pub api: ApiConfig,
    /// SDD-004 follow-ups: opt-in cryptographic verification of
    /// detection rules and (in future) Tetragon TracingPolicies.
    /// Defaults are all "off" to preserve the existing
    /// signature-less workflow; closing the original
    /// rule-signing Known gap is opt-in.
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// When `true`, the correlator refuses to load any rule YAML
    /// that doesn't carry a valid detached minisign signature
    /// (`<rule>.minisig`) under [`signing_public_key_file`].
    /// Default `false` to preserve the existing workflow.
    pub require_signed_rules: bool,
    /// Path to the minisign-format public key used to verify
    /// rule signatures. Required when
    /// [`require_signed_rules`] is `true`; ignored otherwise.
    pub signing_public_key_file: Option<PathBuf>,
}

impl Config {
    /// Load configuration from `path` (if it exists), overlaying environment
    /// variables on top of the file and built-in defaults.
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        let mut fig = Figment::from(Serialized::defaults(Self::default()));

        if let Some(p) = path {
            if p.exists() {
                fig = fig.merge(Toml::file(p));
            }
        }

        let cfg: Self = fig.merge(Env::prefixed("SELFDEF_").split("__")).extract()?;
        Ok(cfg)
    }
}

// ---------------------------------------------------------------- daemon

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DaemonConfig {
    pub host_tag: Option<String>,
    pub log_level: String,
    /// `"text"` or `"json"`.
    pub log_format: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            host_tag: None,
            log_level: "info".into(),
            log_format: "text".into(),
        }
    }
}

// ---------------------------------------------------------------- bus

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BusConfig {
    /// **Vestigial — kept for backward-compatible deserialization of
    /// existing operator configs.** The daemon does not branch on this
    /// value: the in-proc broadcast is always the source of truth for
    /// local subscribers, and the `nats` block (when its `enabled`
    /// field is true) adds the multi-host bridge. Setting this field
    /// has no runtime effect today. Closes F-2026-053 / C-001.
    pub backend: String,
    pub inproc_capacity: usize,
    pub nats: NatsBridgeConfig,
}

impl Default for BusConfig {
    fn default() -> Self {
        Self {
            backend: "inproc".into(),
            inproc_capacity: 4096,
            nats: NatsBridgeConfig::default(),
        }
    }
}

/// NATS bridge configuration. When `enabled = true` and `url` is
/// non-empty, the daemon spawns a bridge task that:
///   - Publishes locally-originated events to `<subject_prefix>.<host_tag>`.
///   - Subscribes to `<subject_prefix>.>` and republishes inbound
///     events (with non-local host_tags) onto the local bus.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct NatsBridgeConfig {
    pub enabled: bool,
    /// `nats://host:port`. Multiple servers may be comma-separated.
    pub url: String,
    /// Subject prefix. Default `selfdef.events`.
    pub subject_prefix: String,
    pub jetstream: NatsJetStreamConfig,
}

impl Default for NatsBridgeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            subject_prefix: "selfdef.events".into(),
            jetstream: NatsJetStreamConfig::default(),
        }
    }
}

/// JetStream durability options for the NATS bridge.
///
/// When `enabled = true`, the bridge ensures a stream capturing
/// `<subject_prefix>.>` and a per-host durable consumer named
/// `<durable_consumer_prefix>-<host_tag>`. A daemon that restarts
/// resumes from its last acked message rather than starting from
/// "now".
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct NatsJetStreamConfig {
    pub enabled: bool,
    pub stream_name: String,
    pub durable_consumer_prefix: String,
    /// Retain messages no older than this many seconds. `0` = unlimited.
    pub max_age_secs: u64,
    /// Cap on stream bytes. `-1` = unlimited.
    pub max_bytes: i64,
    /// Cap on stream message count. `-1` = unlimited.
    pub max_msgs: i64,
}

impl Default for NatsJetStreamConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            stream_name: "selfdef-events".into(),
            durable_consumer_prefix: "selfdef-bridge".into(),
            max_age_secs: 7 * 24 * 3600,
            max_bytes: -1,
            max_msgs: -1,
        }
    }
}

// ---------------------------------------------------------------- store

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct StoreConfig {
    pub hot_path: PathBuf,
    pub hot_retention_days: u32,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            hot_path: PathBuf::from("/var/lib/selfdef/state.sqlite"),
            hot_retention_days: 30,
        }
    }
}

// ---------------------------------------------------------------- collectors

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct CollectorsConfig {
    pub auditd: AuditdConfig,
    pub journald: JournaldConfig,
    pub tetragon: TetragonConfig,
    pub suricata: SuricataConfig,
    pub canary: CanaryConfig,
    pub eventstream: EventstreamConfig,
    pub ebpf: EbpfCollectorConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct AuditdConfig {
    pub enabled: bool,
    pub input_path: PathBuf,
    pub read_from: String,
}

impl Default for AuditdConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            input_path: PathBuf::from("/var/log/audit/audit.log"),
            read_from: "end".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct JournaldConfig {
    pub enabled: bool,
    /// `"journalctl"` (spawn `journalctl --follow`) or `"file"` (tail a path).
    pub mode: String,
    /// Used in `file` mode.
    pub input_path: Option<PathBuf>,
    /// Used in `file` mode.
    pub read_from: String,
    /// `journalctl` binary path (subprocess mode).
    pub journalctl_path: PathBuf,
    /// Optional list of systemd units to filter to.
    pub units: Vec<String>,
}

impl Default for JournaldConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: "journalctl".into(),
            input_path: None,
            read_from: "end".into(),
            journalctl_path: PathBuf::from("/usr/bin/journalctl"),
            units: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct TetragonConfig {
    pub enabled: bool,
    pub input_path: PathBuf,
    pub read_from: String,
}

impl Default for TetragonConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            input_path: PathBuf::from("/var/log/tetragon/events.json"),
            read_from: "end".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct SuricataConfig {
    pub enabled: bool,
    pub input_path: PathBuf,
    pub read_from: String,
}

impl Default for SuricataConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            input_path: PathBuf::from("/var/log/suricata/eve.json"),
            read_from: "end".into(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct CanaryConfig {
    pub enabled: bool,
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct EventstreamConfig {
    pub enabled: bool,
    /// Paths to JSONL event files this collector tails. Each producer (e.g.
    /// selfdef-ssh-wrap) writes its own file.
    pub paths: Vec<PathBuf>,
    pub read_from: String,
    /// SDD-004 F-2026-026 follow-up (opt-in): refuse to tail a JSONL
    /// path whose ownership / mode doesn't match the trust posture
    /// the daemon expects. Defaults to `false` to preserve existing
    /// operator-owned emitters (e.g. `~/.local/share/selfdef/ssh-wrap.jsonl`),
    /// which inherit the operator's trust posture by design.
    ///
    /// When set to `true`:
    ///   - the file must not be world-writable (mode & 0o002 == 0)
    ///   - the file's owner UID must either be the daemon's
    ///     effective UID, root (UID 0), or an entry in
    ///     `allowed_owners`.
    ///
    /// Mismatches log a structured warning and the collector
    /// skips that path (the daemon stays up; other configured
    /// paths continue tailing).
    pub integrity_check: bool,
    /// Additional UIDs (numeric) accepted as writers when
    /// `integrity_check = true`. Empty = daemon-effective-uid +
    /// root only. Operators with a deliberate operator-owned
    /// emitter list its UID here.
    pub allowed_owners: Vec<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct EbpfCollectorConfig {
    pub enabled: bool,
    /// Path to the compiled BPF object. Default matches `xtask install-bpf`.
    pub program_path: PathBuf,
    pub enable_execve: bool,
    pub enable_lsm_open: bool,
    pub enable_kprobe_unlink: bool,
}

impl Default for EbpfCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            program_path: PathBuf::from("/usr/lib/selfdef/selfdef.bpf.o"),
            enable_execve: true,
            enable_lsm_open: false,
            enable_kprobe_unlink: true,
        }
    }
}

// ---------------------------------------------------------------- correlator

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CorrelatorConfig {
    pub enabled: bool,
    pub rules_dir: PathBuf,
    /// **Vestigial — kept for backward-compatible deserialization of
    /// existing operator configs.** The correlator is driven entirely
    /// by Sigma rules in `rules_dir`, each of which declares its own
    /// time window. The daemon constructor does not read this field.
    /// Closes F-2026-015 / C-002.
    pub window_secs: u64,
    /// **Vestigial — same shape as `window_secs`.** Sigma rules
    /// declare their own thresholds; the daemon does not read this
    /// field. Closes F-2026-015 / C-002.
    pub threshold: u32,
}

impl Default for CorrelatorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules_dir: PathBuf::from("/etc/selfdef/rules"),
            window_secs: 60,
            threshold: 3,
        }
    }
}

// ---------------------------------------------------------------- notifier

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct NotifierConfig {
    /// Ordered channel preferences; first that succeeds wins.
    pub channels: Vec<String>,
    pub ntfy: NtfyConfig,
    pub signal: SignalConfig,
}

impl Default for NotifierConfig {
    fn default() -> Self {
        Self {
            channels: vec![],
            ntfy: NtfyConfig::default(),
            signal: SignalConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct NtfyConfig {
    /// Base URL of the ntfy server. e.g. `https://ntfy.example.org`.
    pub url: String,
    /// Topic name. e.g. `selfdef-alerts`.
    pub topic: String,
    /// Optional file containing the bearer token.
    pub token_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct SignalConfig {
    pub binary: PathBuf,
    pub account: String,
    pub recipient: String,
}

impl Default for SignalConfig {
    fn default() -> Self {
        Self {
            binary: PathBuf::from("/usr/bin/signal-cli"),
            account: String::new(),
            recipient: String::new(),
        }
    }
}

// ---------------------------------------------------------------- responder

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ResponderConfig {
    pub dry_run: bool,
    pub allowed_actions: Vec<String>,
    /// Directory under which `snapshot_proc` writes per-event dumps.
    pub snapshot_dir: PathBuf,
    /// Script invoked by `lockdown_egress` action.
    pub lockdown_script: PathBuf,
    /// Script invoked by `revoke_session` action.
    pub revoke_session_script: PathBuf,
    /// Directory under which `forensics_bundle` writes per-event bundles.
    pub forensics_dir: PathBuf,
    /// Velociraptor CLI binary invoked by `velociraptor_escalate`.
    pub velociraptor_binary: PathBuf,
    /// Argv passed to the Velociraptor CLI. The placeholders `{event_id}`
    /// and `{host_tag}` are substituted before invocation.
    pub velociraptor_args: Vec<String>,
}

impl Default for ResponderConfig {
    fn default() -> Self {
        Self {
            dry_run: true,
            allowed_actions: vec!["notify".into()],
            snapshot_dir: PathBuf::from("/var/lib/selfdef/snapshots"),
            lockdown_script: PathBuf::from("/usr/local/sbin/selfdef-lockdown.sh"),
            revoke_session_script: PathBuf::from("/usr/local/sbin/selfdef-revoke-session.sh"),
            forensics_dir: PathBuf::from("/var/lib/selfdef/forensics"),
            velociraptor_binary: PathBuf::from("/usr/local/bin/velociraptor"),
            velociraptor_args: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------- api

/// HTTP API for the dashboard and (eventually) selfdefctl IPC.
///
/// Either transport (or both) can be enabled. UNIX socket transport is
/// trusted via filesystem permissions; TCP transport requires a bearer
/// token whose contents are loaded from `token_file`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ApiConfig {
    pub enabled: bool,
    /// UNIX socket path. Empty disables this transport.
    pub unix_socket: String,
    /// File mode (octal as decimal string, e.g. `"0660"`).
    pub unix_socket_mode: String,
    /// TCP bind address, e.g. `127.0.0.1:8443`. Empty disables this transport.
    pub tcp_addr: String,
    /// Path to a file containing the read-only bearer token. Required for TCP.
    pub token_file: String,
    /// Optional path to a file with the control token. Without it, the
    /// TCP transport refuses every control verb regardless of which
    /// token is presented — opting in is explicit.
    pub control_token_file: String,
    pub tls: ApiTlsConfig,
    /// SDD-007 D-4 / F-2028-037: cap on concurrent `/events/stream`
    /// subscribers across the whole process. Backstop for the
    /// per-token cap below. `None` (or 0) means "use the hardcoded
    /// default of 64".
    #[serde(default)]
    pub max_sse_subscribers: Option<usize>,
    /// SDD-007 D-4 / F-2028-037: per-token cap on concurrent
    /// `/events/stream` subscribers, keyed off a SHA-256 fingerprint
    /// of the presented bearer. `None` (or 0) means "use the
    /// hardcoded default of 8". Bound the abuse a single
    /// leaked/malicious token can do against legitimate operators.
    #[serde(default)]
    pub max_sse_subscribers_per_token: Option<usize>,
}

/// Optional TLS / mTLS wrapping for the TCP transport.
///
/// - When `cert_path` is empty, TLS is off — TCP serves plain HTTP and
///   only the bearer token gates access.
/// - When `cert_path` + `key_path` are set, TLS is enabled.
/// - When `client_ca` is *also* set, the listener requires client
///   certificates and validates them against that CA bundle — mTLS.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ApiTlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub client_ca: String,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            unix_socket: String::from("/run/selfdef.sock"),
            unix_socket_mode: String::from("0660"),
            tcp_addr: String::new(),
            token_file: String::from("/etc/selfdef/api.token"),
            control_token_file: String::new(),
            tls: ApiTlsConfig::default(),
            max_sse_subscribers: None,
            max_sse_subscribers_per_token: None,
        }
    }
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_load_when_no_file() {
        let cfg = Config::load(None).unwrap();
        assert_eq!(cfg.bus.backend, "inproc");
        assert_eq!(cfg.daemon.log_level, "info");
        assert!(!cfg.collectors.auditd.enabled);
    }

    #[test]
    fn toml_overrides_defaults() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"
            [daemon]
            log_level = "trace"

            [collectors.auditd]
            enabled = true
            "#,
        )
        .unwrap();

        let cfg = Config::load(Some(tmp.path())).unwrap();
        assert_eq!(cfg.daemon.log_level, "trace");
        assert!(cfg.collectors.auditd.enabled);
    }

    /// F-2029-005 + F-2029-006: end-to-end test for the SDD-007 D-4
    /// config knobs. The `[api].max_sse_subscribers` and
    /// `max_sse_subscribers_per_token` flow from the TOML file
    /// through `Config::load` into `ApiConfig`'s `Option<usize>`
    /// fields. The daemon then threads them into `ApiState` via
    /// `SseCaps`; the SubscriberGuard reads them at request time.
    /// This test pins the parse hop; the API-side handler test
    /// pins the consumption hop. Together they close both
    /// integration-audit findings.
    #[test]
    fn sse_cap_knobs_round_trip_from_toml() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"
            [api]
            enabled = true
            max_sse_subscribers           = 16
            max_sse_subscribers_per_token = 4
            "#,
        )
        .unwrap();

        let cfg = Config::load(Some(tmp.path())).unwrap();
        assert!(cfg.api.enabled, "api section must parse");
        assert_eq!(
            cfg.api.max_sse_subscribers,
            Some(16),
            "global cap override must round-trip",
        );
        assert_eq!(
            cfg.api.max_sse_subscribers_per_token,
            Some(4),
            "per-token cap override must round-trip",
        );
    }

    /// F-2029-005 + F-2029-006: pin the default-when-unset
    /// contract. When the TOML omits the cap fields entirely,
    /// `ApiConfig::default()` yields `None` for both; the
    /// daemon's `SseCaps::from(cfg.api)` then falls back to the
    /// compiled-in defaults at consumption time.
    #[test]
    fn sse_cap_knobs_default_to_none_when_unset() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"
            [api]
            enabled = true
            "#,
        )
        .unwrap();

        let cfg = Config::load(Some(tmp.path())).unwrap();
        assert!(cfg.api.enabled);
        assert_eq!(cfg.api.max_sse_subscribers, None);
        assert_eq!(cfg.api.max_sse_subscribers_per_token, None);
    }
}
