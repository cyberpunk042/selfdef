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

use std::collections::HashMap;
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
    /// SDD-008 D-7 Q-E: SMTP (email) outbound channel via lettre.
    /// Empty `relay_host` keeps the channel disabled.
    pub smtp: SmtpConfig,
    /// SDD-008 Q-D: Twilio SMS outbound channel.
    /// Empty `account_sid` keeps the channel disabled.
    pub twilio: TwilioConfig,
    /// SDD-008 Q-C: Slack incoming-webhook outbound channel.
    /// Missing `webhook_url_file` keeps the channel disabled.
    pub slack: SlackConfig,
    /// SDD-008: Discord webhook outbound channel. Missing
    /// `webhook_url_file` keeps the channel disabled.
    pub discord: DiscordConfig,
    /// SDD-008 Q-G: PagerDuty Events API v2 channel. Missing
    /// `routing_key_file` keeps the channel disabled.
    pub pagerduty: PagerDutyConfig,
    /// SDD-008 Q-G: Grafana Loki push-API channel. Empty
    /// `endpoint` keeps the channel disabled.
    pub loki: LokiConfig,
    /// SDD-008 Q-G: OpenSearch / Elasticsearch document-index
    /// channel. Empty `endpoint` keeps the channel disabled.
    pub opensearch: OpenSearchConfig,
    /// SDD-008 Q-G: TheHive incident-management alert channel.
    /// Empty `endpoint` keeps the channel disabled.
    pub thehive: TheHiveConfig,
    /// SDD-008 D-8: wall(1) session-attention channel. Broadcasts
    /// to every logged-in TTY when a high-severity event fires —
    /// the operator's "talk to the bash session" surface. Default
    /// `binary = ""` keeps the channel disabled.
    pub wall: WallConfig,
    /// SDD-008 D-5a/b/c: path to the persistent escalation engine's
    /// SQLite database. When set, the daemon opens this file at
    /// startup, persists outbound events in it, and runs the wake-
    /// task escalation loop. When `None`, the daemon falls back to
    /// the M4 fire-and-forget chain (no persistence, no escalation).
    ///
    /// Used by both the daemon and `selfdefctl notify {ack,forget,
    /// list}` (D-4) to read / mutate the same SQLite file — WAL
    /// mode handles the concurrent reader/writer cleanly.
    pub escalations_path: Option<PathBuf>,
    /// SDD-008 D-6a: operating mode of the dispatcher. One of
    /// `enforce` (default; production, fires channels for real) or
    /// `audit` (persists rows but does NOT call `channel.send` —
    /// dry-run for verifying orchestrator wiring before going live).
    ///
    /// Only consulted when `escalations_path` is set; the M4 chain
    /// path always behaves as `enforce`. Unknown strings log a
    /// warn at daemon start and fall back to `enforce`.
    pub mode: String,
    /// SDD-008 D-6b: named escalation profile. One of:
    ///   `auto`       — 2 attempts, 5-min ack window (default).
    ///   `aggressive` — 3 attempts at 60s / 180s / 600s. For
    ///                  wake-the-on-call use cases.
    ///   `patient`    — 4 attempts at 10/30/60/120 min. For
    ///                  non-critical channels where rapid retries
    ///                  would just be noise.
    ///
    /// Only consulted when `escalations_path` is set. Unknown
    /// strings log a warn and fall back to `auto`.
    pub profile: String,
    /// SDD-008 D-7: severity threshold at or above which audit mode
    /// is bypassed (channels fire for real). The escape hatch for
    /// "operator misconfiguration cannot leave a blocker un-
    /// notified".
    ///
    /// One of: `informational` | `low` | `medium` | `high` |
    /// `critical` | `fatal`. Empty / unset = no floor (audit mode
    /// suppresses every severity).
    pub panic_floor: Option<String>,
    /// SDD-008 D-6c: operator-defined custom escalation profiles
    /// keyed by name. The active profile is picked by
    /// `[notifier].profile`. When that name matches a key here,
    /// the daemon constructs a custom [`Profile`] from this
    /// configured rung sequence instead of falling back to the
    /// three built-ins (`auto`/`aggressive`/`patient`).
    ///
    /// Example:
    /// ```toml
    /// [notifier.profiles.weekend]
    /// rungs = [
    ///     { channels = ["ntfy"],   ack_window_secs = 1800 },
    ///     { channels = ["signal"], ack_window_secs = 3600 },
    ///     { channels = [],         ack_window_secs = 600  },  # WUPHF
    /// ]
    /// ```
    ///
    /// Empty `channels` list at a rung = "fire all configured
    /// channels" (WUPHF semantics).
    pub profiles: HashMap<String, ProfileConfig>,
    /// SDD-008 D-3: per-channel subscription filters keyed by
    /// channel slug (`"ntfy"`, `"signal"`, `"smtp"`, `"twilio"`,
    /// …). Missing entry = accept every event (default). See
    /// [`SubscriptionConfig`] for the per-channel field shape.
    pub subscriptions: HashMap<String, SubscriptionConfig>,
    /// SDD-008 D-4 HTTP ack: optional base URL for the
    /// click-link ack endpoint. When `Some("https://daemon.example/notify/ack")`,
    /// the dispatcher mints a per-event UUIDv7 token, appends it to
    /// this base (`<base>/<token>`), and embeds the result in each
    /// outbound payload's `ack_link`. Operators click the link →
    /// daemon's `GET /notify/ack/:token` handler records the ack.
    ///
    /// `None` (the default) disables HTTP ack: the dispatcher
    /// leaves `ack_link = None`, channels render no clickable URL,
    /// and ack is CLI-only (`selfdefctl notify ack <event-id>`).
    /// The daemon's `/notify/ack` route still exists in this mode
    /// and returns 503 — operators can flip the knob on without a
    /// route-table change.
    ///
    /// The base should NOT have a trailing slash; the dispatcher
    /// appends `/<token>` exactly.
    pub ack_link_base: Option<String>,
}

impl Default for NotifierConfig {
    fn default() -> Self {
        Self {
            channels: vec![],
            ntfy: NtfyConfig::default(),
            signal: SignalConfig::default(),
            smtp: SmtpConfig::default(),
            twilio: TwilioConfig::default(),
            slack: SlackConfig::default(),
            discord: DiscordConfig::default(),
            pagerduty: PagerDutyConfig::default(),
            loki: LokiConfig::default(),
            opensearch: OpenSearchConfig::default(),
            thehive: TheHiveConfig::default(),
            wall: WallConfig::default(),
            escalations_path: None,
            mode: "enforce".to_owned(),
            profile: "auto".to_owned(),
            panic_floor: None,
            profiles: HashMap::new(),
            subscriptions: HashMap::new(),
            ack_link_base: None,
        }
    }
}

/// SDD-008 Q-C: Slack incoming-webhook channel config.
///
/// The default `webhook_url_file = None` keeps the channel
/// disabled; the daemon builds a `SlackNotifier` only when
/// `webhook_url_file` is set AND the file is readable + contains
/// an `https://` URL after trim.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct SlackConfig {
    /// Path to a file containing the Slack incoming-webhook URL.
    /// Stored in a separate file (mode `0600` recommended) because
    /// the URL itself is the auth secret — anyone with the URL can
    /// post to the channel.
    pub webhook_url_file: Option<PathBuf>,
    /// Display name for posts. Defaults to `"selfdef"` when blank.
    pub username: String,
    /// Emoji shortcode for the post avatar. Defaults to `":shield:"`
    /// when blank.
    pub icon_emoji: String,
}

/// SDD-008: Discord webhook channel config.
///
/// Same shape as [`SlackConfig`]: the webhook URL itself is the auth
/// secret, so store it in a separate file with mode `0600`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct DiscordConfig {
    /// Path to a file containing the Discord webhook URL. The URL
    /// is itself the auth secret — anyone with it can post to the
    /// channel.
    pub webhook_url_file: Option<PathBuf>,
    /// Display name for posts. Defaults to `"selfdef"` when blank.
    pub username: String,
}

/// SDD-008 Q-G: Grafana Loki push-API channel config.
///
/// Default `endpoint = ""` keeps the channel disabled. Set to a
/// Loki push endpoint (typically
/// `https://logs-prod.grafana.net/loki/api/v1/push` for Grafana
/// Cloud, or `https://loki.internal/loki/api/v1/push` for
/// self-hosted).
///
/// Auth model:
/// - Self-hosted single-tenant: leave `tenant_id` empty, no
///   `auth_token_file`.
/// - Self-hosted multi-tenant: set `tenant_id` (sent as
///   `X-Scope-OrgID`).
/// - Grafana Cloud: set both `tenant_id` (your stack id) and
///   `auth_token_file` (your API key — sent as Bearer).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct LokiConfig {
    /// Loki push endpoint URL. Empty = channel disabled. Must be
    /// `https://` (defensive — we refuse to ship bearer tokens
    /// over plaintext).
    pub endpoint: String,
    /// `X-Scope-OrgID` header value. Empty = header not sent
    /// (single-tenant). Grafana Cloud uses the stack id here.
    pub tenant_id: String,
    /// Path to a file containing the bearer token. Empty / None =
    /// no `Authorization` header. The file's contents are sent
    /// verbatim (trimmed) as `Bearer <contents>`.
    pub auth_token_file: Option<PathBuf>,
    /// Source identifier surfaced as the `host` label in Loki.
    /// Defaults to `"selfdef"` when blank.
    pub source: String,
}

/// SDD-008 Q-G: OpenSearch / Elasticsearch document-index channel
/// config.
///
/// Default `endpoint = ""` keeps the channel disabled. Set to an
/// OS / ES cluster's REST API endpoint (typically
/// `https://opensearch.internal:9200`). Each event becomes one
/// document indexed at `<endpoint>/<index>/_doc`.
///
/// Auth model:
/// - `auth_kind = "none"`: no `Authorization` header. Use when the
///   cluster is gated by network ACLs only.
/// - `auth_kind = "basic"`: HTTP Basic. Requires `username` and
///   `auth_token_file` (the latter holds the password).
/// - `auth_kind = "apikey"`: AWS-OpenSearch / Elastic Cloud API
///   key. Requires `auth_token_file`; `username` is ignored.
///
/// Unknown auth_kind strings are rejected at startup so operators
/// see the misconfig.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct OpenSearchConfig {
    /// OpenSearch / Elasticsearch REST API endpoint. Empty =
    /// channel disabled. Must be `https://`.
    pub endpoint: String,
    /// Target index name (e.g. `"selfdef-events"`). Required when
    /// `endpoint` is set.
    pub index: String,
    /// One of `"none" | "basic" | "apikey"`. Empty parses as
    /// `none`.
    pub auth_kind: String,
    /// Username for Basic auth. Ignored when `auth_kind` ≠ basic.
    pub username: String,
    /// Path to a file containing the Basic password OR the API
    /// key. Required for basic/apikey, ignored for none.
    pub auth_token_file: Option<PathBuf>,
    /// Surfaced as the `host` field on each document. Defaults to
    /// `"selfdef"` when empty.
    pub source: String,
}

/// SDD-008 Q-G: TheHive incident-management alert-API channel
/// config.
///
/// Default `endpoint = ""` keeps the channel disabled. Set to a
/// TheHive instance (typically `https://hive.internal:9000`); the
/// channel POSTs each event to `<endpoint>/api/v1/alert`.
///
/// `api_key_file` holds the Bearer API key (one line); mode
/// `0600`. The key IS the auth.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct TheHiveConfig {
    /// TheHive base URL. Empty = channel disabled. Must be
    /// `https://`.
    pub endpoint: String,
    /// Path to a file containing the Bearer API key. Required.
    pub api_key_file: Option<PathBuf>,
    /// Alert `source` field. Defaults to `"selfdef"`.
    pub source: String,
    /// Alert `type` field. Defaults to `"selfdef"`.
    pub alert_type: String,
}

/// SDD-008 Q-G: PagerDuty Events API v2 channel config.
///
/// Default `routing_key_file = None` keeps the channel disabled.
/// Set to a path containing the 32-char hex integration key
/// (per-service routing identifier from PagerDuty's UI).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct PagerDutyConfig {
    /// Path to a file containing the PagerDuty Events API v2
    /// routing key. The key IS the auth — store the file at
    /// mode `0600`.
    pub routing_key_file: Option<PathBuf>,
    /// PagerDuty Events API v2 endpoint. Empty = use the default
    /// global US endpoint (`https://events.pagerduty.com/v2/enqueue`).
    /// Set this for staging / EU-only PD instances or for testing
    /// against a local mock server.
    pub endpoint: String,
    /// Source identifier surfaced in PagerDuty's UI as the
    /// alerting entity. Defaults to `"selfdef"` when blank;
    /// operators with multiple selfdef daemons feeding the same
    /// PagerDuty service usually want to set this to the host
    /// name so they can tell incidents apart.
    pub source: String,
}

/// SDD-008 D-8: wall(1) session-attention channel config.
///
/// Default `binary = ""` keeps the channel disabled. Set to the
/// path of the `wall` binary (typically `/usr/bin/wall`) to enable.
/// `severity_floor` defaults to `"high"` — wall is system-wide
/// broadcast, bothering every TTY on routine events is wrong.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct WallConfig {
    /// Path to the `wall(1)` binary. Empty disables the channel.
    pub binary: PathBuf,
    /// Severity threshold below which wall stays silent. One of:
    /// `informational` | `low` | `medium` | `high` | `critical` |
    /// `fatal`. Empty defaults to `high`. Unknown strings reject
    /// the config at daemon start (the wall channel is disabled
    /// rather than firing on every event).
    pub severity_floor: String,
}

/// SDD-008 D-6c: operator-defined custom escalation profile shape.
/// Mirrors `selfdef_notifier_engine::Profile`'s rung sequence with
/// only the fields operators set in TOML; the daemon translates
/// this into the typed `Profile` at startup.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ProfileConfig {
    /// Ordered rung sequence. Each rung is a (channels, ack_window)
    /// pair. Empty `channels` at a rung = "all channels" (WUPHF).
    /// Empty `rungs` list rejects the profile at daemon start; a
    /// 0-rung profile would never fire.
    pub rungs: Vec<RungConfig>,
}

/// SDD-008 D-6c: one rung of an operator-defined custom profile.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct RungConfig {
    /// Channel allow-list for this rung. Empty = fire every
    /// configured channel (WUPHF semantics).
    pub channels: Vec<String>,
    /// Seconds the wake task waits before advancing to the next
    /// rung. Defaults to `300` (5 minutes) when unset / zero.
    pub ack_window_secs: i64,
}

/// SDD-008 D-3: per-channel subscription filter.
///
/// Operators set these per channel via
/// `[notifier.subscriptions.<channel_name>]` in `selfdef.toml`.
/// Missing entry → accept every event. v1 ships the two filters
/// below; `quiet_hours` and `device_hint` from the charter follow
/// in a subsequent PR.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct SubscriptionConfig {
    /// Minimum severity to forward to this channel. One of:
    /// `informational` | `low` | `medium` | `high` | `critical` |
    /// `fatal`. Case-insensitive. Unknown strings log a warn at
    /// daemon start and are treated as "no floor".
    pub severity_floor: Option<String>,
    /// Substrings matched (case-insensitive) against
    /// `Event::class_uid::name()`. e.g. `["security", "detection"]`
    /// catches both "Security Finding" and "Detection Finding".
    /// Empty list = accept all kinds.
    pub event_kinds: Vec<String>,
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

/// SDD-008 D-7 Q-E: SMTP outbound channel config.
///
/// The default `relay_host = ""` keeps the channel disabled; the
/// daemon builds an `SmtpNotifier` only when `relay_host` is set
/// AND at least one recipient is listed. The TLS profile defaults to
/// STARTTLS, matching the most-common operator-controlled relay
/// posture (port 587 with PLAIN auth over upgraded TLS).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct SmtpConfig {
    /// Relay hostname. Empty disables the channel.
    pub relay_host: String,
    /// Relay port. 587 for STARTTLS (default), 465 for implicit TLS,
    /// 25 for plain (testing only).
    pub relay_port: u16,
    /// TLS profile: `starttls` | `implicit_tls` | `plain`.
    /// Plain refuses any auth-bearing send at construction time.
    pub tls: String,
    /// SMTP auth username. Optional; when set, `password_file` must
    /// also be set.
    pub username: Option<String>,
    /// Path to a file containing the SMTP auth password. Read on
    /// daemon start; mode-check parity with the ntfy token file path
    /// is the operator's concern today and the orchestrator's
    /// concern at SDD-008 D-5+.
    pub password_file: Option<PathBuf>,
    /// `From:` address. e.g. `selfdef-alerts@example.org`.
    pub from: String,
    /// Recipient list. Empty disables the channel.
    pub to: Vec<String>,
    /// Per-send timeout in seconds.
    pub timeout_secs: u64,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            relay_host: String::new(),
            relay_port: 587,
            tls: "starttls".to_owned(),
            username: None,
            password_file: None,
            from: String::new(),
            to: vec![],
            timeout_secs: 10,
        }
    }
}

/// SDD-008 Q-D: Twilio SMS outbound channel config.
///
/// The default `account_sid = ""` keeps the channel disabled; the
/// daemon builds a `TwilioNotifier` only when `account_sid` is set,
/// `from` is set, the recipient list is non-empty, and the
/// `auth_token_file` is readable + non-empty after trim.
///
/// Per the SDD-008 charter's Q-D working assumption: v1 ships
/// **send-only**; inbound reply webhooks for SMS ack would require
/// the daemon to expose a public HTTPS endpoint and are deferred to
/// a later D if operators ask.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct TwilioConfig {
    /// Twilio account SID. Starts with `AC`. Empty disables the
    /// channel.
    pub account_sid: String,
    /// Path to a file containing the Twilio auth token. Read on
    /// daemon start.
    pub auth_token_file: Option<PathBuf>,
    /// Twilio-provisioned `From:` number in E.164 format
    /// (e.g. `+15551234567`).
    pub from: String,
    /// Recipient list in E.164 format.
    pub to: Vec<String>,
    /// Per-send timeout in seconds.
    pub timeout_secs: u64,
}

impl Default for TwilioConfig {
    fn default() -> Self {
        Self {
            account_sid: String::new(),
            auth_token_file: None,
            from: String::new(),
            to: vec![],
            timeout_secs: 10,
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

    /// Phase 6 integration explorer: end-to-end round-trip of the
    /// SDD-008 surface. Pins the TOML → `Config::load` →
    /// `NotifierConfig` parse for the cycle's 13 new operator-facing
    /// keys (escalations_path, mode, profile, panic_floor, one
    /// channel section, one subscription, one custom profile). Any
    /// future refactor to the schema that drops a `#[serde(default)]`
    /// or renames a key gets caught at parse time.
    #[test]
    fn sdd_008_notifier_surface_round_trips_from_toml() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"
            [notifier]
            escalations_path = "/var/lib/selfdef/escalations.sqlite"
            mode             = "audit"
            profile          = "fast-rollout"
            panic_floor      = "critical"

            [notifier.ntfy]
            url        = "https://ntfy.example.org"
            topic      = "selfdef-alerts"
            token_file = "/etc/selfdef/ntfy.token"

            [notifier.subscriptions.discord]
            severity_floor = "high"
            event_kinds    = ["security", "detection"]

            [[notifier.profiles.fast-rollout.rungs]]
            channels         = ["wall"]
            ack_window_secs  = 30

            [[notifier.profiles.fast-rollout.rungs]]
            channels         = ["wall", "ntfy"]
            ack_window_secs  = 120
            "#,
        )
        .unwrap();

        let cfg = Config::load(Some(tmp.path())).unwrap();

        // Top-level dispatcher knobs.
        assert_eq!(
            cfg.notifier.escalations_path.as_deref(),
            Some(std::path::Path::new("/var/lib/selfdef/escalations.sqlite")),
        );
        assert_eq!(cfg.notifier.mode, "audit");
        assert_eq!(cfg.notifier.profile, "fast-rollout");
        assert_eq!(cfg.notifier.panic_floor.as_deref(), Some("critical"));

        // Channel section.
        assert_eq!(cfg.notifier.ntfy.url, "https://ntfy.example.org");
        assert_eq!(cfg.notifier.ntfy.topic, "selfdef-alerts");
        assert_eq!(
            cfg.notifier.ntfy.token_file.as_deref(),
            Some(std::path::Path::new("/etc/selfdef/ntfy.token")),
        );

        // Per-channel subscription.
        let sub = cfg
            .notifier
            .subscriptions
            .get("discord")
            .expect("discord subscription parsed");
        assert_eq!(sub.severity_floor.as_deref(), Some("high"));
        assert_eq!(sub.event_kinds, vec!["security", "detection"]);

        // Custom profile with per-rung filter (D-6c).
        let prof = cfg
            .notifier
            .profiles
            .get("fast-rollout")
            .expect("fast-rollout profile parsed");
        assert_eq!(prof.rungs.len(), 2);
        assert_eq!(prof.rungs[0].channels, vec!["wall"]);
        assert_eq!(prof.rungs[0].ack_window_secs, 30);
        assert_eq!(prof.rungs[1].channels, vec!["wall", "ntfy"]);
        assert_eq!(prof.rungs[1].ack_window_secs, 120);
    }

    /// Phase 6 integration explorer: pin the unset-defaults contract
    /// for the SDD-008 surface. When the operator omits every
    /// `[notifier].*` knob, defaults must produce the legacy fire-
    /// and-forget chain path (`escalations_path = None`), with
    /// builder-default `mode = "enforce"` and `profile = "auto"`.
    #[test]
    fn sdd_008_notifier_surface_defaults_when_unset() {
        let cfg = Config::load(None).unwrap();
        assert!(
            cfg.notifier.escalations_path.is_none(),
            "default omits escalations_path → legacy chain path",
        );
        assert_eq!(cfg.notifier.mode, "enforce");
        assert_eq!(cfg.notifier.profile, "auto");
        assert!(cfg.notifier.panic_floor.is_none());
        assert!(cfg.notifier.profiles.is_empty());
        assert!(cfg.notifier.subscriptions.is_empty());
    }

    /// Phase 7 integration explorer: pin the post-Phase-6
    /// notifier-surface additions — `ack_link_base` (D-4) and the
    /// 4 Q-G channel blocks (PagerDuty, Loki, OpenSearch, TheHive).
    /// Any future schema refactor that drops a `#[serde(default)]`
    /// or renames a key in these blocks gets caught at parse time.
    #[test]
    fn sdd_008_post_phase_6_surface_round_trips_from_toml() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"
            [notifier]
            ack_link_base = "https://selfdef.example/notify/ack"

            [notifier.pagerduty]
            routing_key_file = "/etc/selfdef/pd.key"
            endpoint         = "https://events.pagerduty.example/v2/enqueue"
            source           = "host-1"

            [notifier.loki]
            endpoint         = "https://logs.example/loki/api/v1/push"
            tenant_id        = "tenant-42"
            auth_token_file  = "/etc/selfdef/loki.token"
            source           = "host-1"

            [notifier.opensearch]
            endpoint         = "https://os.example:9200"
            index            = "selfdef-events"
            auth_kind        = "basic"
            username         = "selfdef"
            auth_token_file  = "/etc/selfdef/os.password"
            source           = "host-1"

            [notifier.thehive]
            endpoint     = "https://hive.example:9000"
            api_key_file = "/etc/selfdef/hive.key"
            source       = "host-1"
            alert_type   = "selfdef-detection"
            "#,
        )
        .unwrap();

        let cfg = Config::load(Some(tmp.path())).unwrap();

        assert_eq!(
            cfg.notifier.ack_link_base.as_deref(),
            Some("https://selfdef.example/notify/ack"),
        );

        assert_eq!(
            cfg.notifier.pagerduty.routing_key_file.as_deref(),
            Some(std::path::Path::new("/etc/selfdef/pd.key")),
        );
        assert_eq!(
            cfg.notifier.pagerduty.endpoint,
            "https://events.pagerduty.example/v2/enqueue",
        );
        assert_eq!(cfg.notifier.pagerduty.source, "host-1");

        assert_eq!(
            cfg.notifier.loki.endpoint,
            "https://logs.example/loki/api/v1/push",
        );
        assert_eq!(cfg.notifier.loki.tenant_id, "tenant-42");
        assert_eq!(
            cfg.notifier.loki.auth_token_file.as_deref(),
            Some(std::path::Path::new("/etc/selfdef/loki.token")),
        );

        assert_eq!(cfg.notifier.opensearch.endpoint, "https://os.example:9200");
        assert_eq!(cfg.notifier.opensearch.index, "selfdef-events");
        assert_eq!(cfg.notifier.opensearch.auth_kind, "basic");
        assert_eq!(cfg.notifier.opensearch.username, "selfdef");

        assert_eq!(cfg.notifier.thehive.endpoint, "https://hive.example:9000");
        assert_eq!(
            cfg.notifier.thehive.api_key_file.as_deref(),
            Some(std::path::Path::new("/etc/selfdef/hive.key")),
        );
        assert_eq!(cfg.notifier.thehive.alert_type, "selfdef-detection");
    }

    /// Phase 7 integration explorer: pin the defaults — every
    /// Q-G config block defaults to disabled when no operator
    /// content is present.
    #[test]
    fn sdd_008_post_phase_6_surface_defaults_when_unset() {
        let cfg = Config::load(None).unwrap();
        assert!(cfg.notifier.ack_link_base.is_none());
        assert!(cfg.notifier.pagerduty.routing_key_file.is_none());
        assert!(cfg.notifier.loki.endpoint.is_empty());
        assert!(cfg.notifier.opensearch.endpoint.is_empty());
        assert!(cfg.notifier.thehive.endpoint.is_empty());
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
