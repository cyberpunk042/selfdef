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
    /// A semantic validation failure surfaced by [`Config::validate`] —
    /// the TOML parsed fine but the values don't make sense together.
    #[error("invalid configuration: {0}")]
    Invalid(String),
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
    /// SDD-013: deployment-target switch — gates all SAIN-01-specific
    /// behavior (state paths, audit-summary channel, oracle-triage
    /// channel, perimeter coexistence). Default is `Generic`; existing
    /// configs that don't carry a `[deployment]` block parse unchanged.
    pub deployment: DeploymentConfig,
    /// SD-R21 (SDD-018 follow-up): periodic hardware probe + thermal
    /// thresholds. Default is fully disabled — operators opt in by
    /// setting `[hardware_probe].enabled = true`. When enabled, the
    /// daemon re-probes every `interval_seconds`; when
    /// `emit_thermal_events = true`, sensors crossing the configured
    /// critical threshold emit OCSF Detection Findings to the bus.
    #[serde(default)]
    pub hardware_probe: HardwareProbeConfig,
    /// SDD-015: Tetragon perimeter coexistence config — controls the
    /// boundary check between selfdef-authored agent-guard policies
    /// and sovereign-os's `sovereign-kernel-fence.yaml`. When
    /// `deployment.target = sain01`, `check_overlap_on_apply` defaults
    /// to true. When `target = generic`, this block is ignored.
    pub perimeter: PerimeterConfig,
}

// ---------------------------------------------------------------- deployment (SDD-013)

/// SDD-013: deployment-target switch.
///
/// All SAIN-01-specific behavior in selfdef forks on this enum:
/// state paths, audit-log paths, escalations DB path, the
/// shared-audit-summary notifier channel (SDD-014), perimeter
/// check-overlap (SDD-015), and the oracle-triage channel
/// (SDD-016) all read [`Config::deployment`].
///
/// Default is [`DeploymentTarget::Generic`]. Existing operator configs
/// that don't carry a `[deployment]` block parse unchanged.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct DeploymentConfig {
    pub target: DeploymentTarget,
    /// SDD-017 § 5: when `target = sain01` AND this flag is true,
    /// the daemon refuses to start unless the hardware probe returns
    /// `Sain01Verdict::FullMatch`. Default false (warn-only on
    /// mismatch). Operators on the SAIN-01 hardware should enable
    /// this once they trust the probe.
    pub sain01_strict: bool,
    /// SDD-017 § 6: when set, the daemon writes a Layer B textfile
    /// collector .prom file at this path with the per-dimension
    /// Sain01Match results. node_exporter's textfile collector picks
    /// it up. Empty = disabled. Default empty (operators opt-in by
    /// pointing at their node_exporter textfile dir, e.g.
    /// /var/lib/node_exporter/textfile_collector/selfdef-hardware.prom).
    pub hardware_metrics_path: String,

    /// SDD-017 § 7 (SD-R10): when set, the daemon writes the
    /// HardwareCapabilities JSON to this path at startup. Consumed
    /// by sovereign-os Wasm-AOT pipeline + future hardware-aware
    /// agent-guard policies. Atomic tempfile+rename. Empty = disabled.
    /// Default: empty.
    pub hardware_capabilities_path: String,

    /// M060 D-02 (R10063-R10068): when set, the daemon publishes the
    /// MS007 cross-repo mirror artifacts READ-ONLY into this directory
    /// for sovereign-os cockpit dashboards. The active authority-profile
    /// snapshot (`active-profile.json`) is projected from the live
    /// flex-profile state on a periodic timer + at startup. Atomic
    /// tempfile+rename. Empty = disabled. Default: empty. Operators on a
    /// co-located sovereign-os opt in by pointing at
    /// `/run/sovereign-os/selfdef-mirror`.
    pub selfdef_mirror_dir: String,
}

/// SD-R21: periodic hardware probe + thermal threshold config.
///
/// All fields default to disabled / safe values — an operator who
/// doesn't add a `[hardware_probe]` block gets the same behavior as
/// today (single probe at startup, no periodic re-probe, no event
/// emission). Operators opt in by setting `enabled = true`.
///
/// Thermal thresholds mirror the sovereign-os R172 defaults for the
/// `sain-01` profile (warn ≥ 85 °C, critical ≥ 95 °C). NVIDIA GPU
/// sensors are gated through the same thresholds — operators tune
/// per-host via the `gpu_critical_celsius` override when needed.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct HardwareProbeConfig {
    /// Master switch. When false, the daemon probes once at startup
    /// (existing behavior) and never re-probes.
    pub enabled: bool,
    /// Re-probe cadence in seconds. Default 300 (5 minutes).
    /// Below 30 is rejected at validation time (probe I/O is cheap
    /// but not free — sub-30s cadence yields no operator value).
    pub interval_seconds: u64,
    /// When true AND `enabled` is true, sensors crossing the
    /// critical threshold emit an OCSF Detection Finding
    /// (category_uid=2, class_uid=2004, severity=Critical) to the
    /// bus on the probe tick. Default false.
    pub emit_thermal_events: bool,
    /// Warn threshold in °C. Default 85 (sain-01 profile baseline).
    pub thermal_warn_celsius: i32,
    /// Critical threshold in °C. Default 95.
    pub thermal_critical_celsius: i32,
    /// Override for GPU sensors (sensors whose source starts with
    /// `nvidia-gpu-`). 0 means "use the same critical threshold as
    /// other sensors". Default 0 (no override).
    pub gpu_critical_celsius: i32,
}

impl Default for HardwareProbeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_seconds: 300,
            emit_thermal_events: false,
            thermal_warn_celsius: 85,
            thermal_critical_celsius: 95,
            gpu_critical_celsius: 0,
        }
    }
}

/// SD-R21: pure classification of a single thermal reading against
/// the configured thresholds. Returns `"ok"`, `"warn"`, or `"critical"`.
/// GPU sensors honor `gpu_critical_celsius` when set.
#[must_use]
pub fn classify_thermal_reading(
    cfg: &HardwareProbeConfig,
    source: &str,
    celsius: i32,
) -> &'static str {
    let is_gpu = source.starts_with("nvidia-gpu-");
    let critical = if is_gpu && cfg.gpu_critical_celsius > 0 {
        cfg.gpu_critical_celsius
    } else {
        cfg.thermal_critical_celsius
    };
    if celsius >= critical {
        "critical"
    } else if celsius >= cfg.thermal_warn_celsius {
        "warn"
    } else {
        "ok"
    }
}

/// SDD-013: target enum. New variants land via additional SDDs.
///
/// `#[serde(rename_all = "lowercase")]` so the TOML form is
/// `target = "generic"` / `target = "sain01"` — operator-readable.
/// Unknown values fail-loud at parse time (SDD-013 § Goals point 3).
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentTarget {
    /// Default — runs on any Debian/Ubuntu host without SAIN-01 hardware
    /// or ZFS state-fabric. State paths under `/var/lib/selfdef`.
    #[default]
    Generic,
    /// SAIN-01 AI workstation (per sovereign-os `profiles/sain-01.yaml`).
    /// State paths under `/mnt/vault/context` (tank/context ZFS dataset
    /// with `sync=always` + `copies=2` for durability).
    Sain01,
}

impl DeploymentTarget {
    /// Operator-readable token (matches the TOML serialization).
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::Sain01 => "sain01",
        }
    }
}

impl std::fmt::Display for DeploymentTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for DeploymentTarget {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "generic" => Ok(Self::Generic),
            "sain01" => Ok(Self::Sain01),
            other => Err(format!(
                "unknown deployment.target {other:?}: expected 'generic' or 'sain01'"
            )),
        }
    }
}

// ---------------------------------------------------------------- path resolver (SDD-013)

/// SDD-013 § 3: single source of truth for target-conditional state paths.
///
/// All callers — daemon, CLI, notifier, doctor — read paths through
/// these helpers. No path string is duplicated across crates.
///
/// Generic: `/var/lib/selfdef` (FHS-standard system-state dir).
/// SAIN-01: `/mnt/vault/context` (tank/context ZFS dataset; sync=always;
/// copies=2 per sovereign-os `profiles/sain-01.yaml § hardware.storage`).
pub fn state_dir(target: DeploymentTarget) -> &'static Path {
    match target {
        DeploymentTarget::Generic => Path::new("/var/lib/selfdef"),
        DeploymentTarget::Sain01 => Path::new("/mnt/vault/context"),
    }
}

/// Audit-log path (JSONL stream of all selfdef events). Caller appends.
pub fn audit_log_path(target: DeploymentTarget) -> PathBuf {
    state_dir(target).join("selfdef-audit.jsonl")
}

/// Escalations DB path (SQLite — operator-acknowledgements + escalation
/// state machine per the notifier channels).
pub fn escalations_path(target: DeploymentTarget) -> PathBuf {
    state_dir(target).join("selfdef-escalations.sqlite")
}

/// Shared audit log per SDD-014. ONLY meaningful when target=Sain01;
/// returns `None` on Generic deployments (no shared timeline exists).
/// Path matches sovereign-os master spec § 10.1 + § 7.1 verbatim.
pub fn shared_audit_log_path(target: DeploymentTarget) -> Option<PathBuf> {
    match target {
        DeploymentTarget::Generic => None,
        DeploymentTarget::Sain01 => Some(PathBuf::from("/mnt/vault/context/security_audit.log")),
    }
}

// ---------------------------------------------------------------- security

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
        let cfg = Self::parse(path)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Parse configuration like [`Config::load`] but WITHOUT the semantic
    /// [`Config::validate`] gate. Intended for diagnostic tools (e.g.
    /// `selfdefctl doctor`) that must be able to PARSE a semantically-broken
    /// config in order to report precisely which invariant it violates — the
    /// strict [`Config::load`] aborts at the validation gate before the
    /// diagnostic can run, which would leave the operator with a bare load
    /// error instead of the doctor's per-check report. The daemon and all
    /// mutating commands keep using [`Config::load`] (fail-fast at startup).
    pub fn load_unvalidated(path: Option<&Path>) -> Result<Self, ConfigError> {
        Self::parse(path)
    }

    /// Build the config from defaults + optional TOML file + `SELFDEF_` env,
    /// without semantic validation. Shared by [`Config::load`] (which then
    /// validates) and [`Config::load_unvalidated`] (which does not).
    fn parse(path: Option<&Path>) -> Result<Self, ConfigError> {
        let mut fig = Figment::from(Serialized::defaults(Self::default()));

        if let Some(p) = path {
            if p.exists() {
                fig = fig.merge(Toml::file(p));
            }
        }

        let cfg: Self = fig.merge(Env::prefixed("SELFDEF_").split("__")).extract()?;
        Ok(cfg)
    }

    /// Semantic validation run after a successful parse, so a
    /// misconfiguration fails fast at config-load (daemon startup)
    /// rather than late at first use. Additive: only flags combinations
    /// that are unambiguously wrong, so existing valid configs keep
    /// loading. Returns the FIRST problem found.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Rule signing: verifying signatures is impossible without the
        // public key, so requiring signed rules but omitting the key is a
        // guaranteed rule-load failure — catch it at startup instead.
        if self.security.require_signed_rules && self.security.signing_public_key_file.is_none() {
            return Err(ConfigError::Invalid(
                "[security] require_signed_rules = true but signing_public_key_file is unset — \
                 the correlator cannot verify rule signatures without a public key"
                    .into(),
            ));
        }

        // Perimeter third-party policy stance is a closed vocabulary; a typo
        // (e.g. "blok") would otherwise be silently mishandled at apply time.
        const VALID_STANCES: [&str; 3] = ["warn", "ignore", "block"];
        if !VALID_STANCES.contains(&self.perimeter.third_party_policy_stance.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "[perimeter] third_party_policy_stance must be one of {VALID_STANCES:?}, got {:?}",
                self.perimeter.third_party_policy_stance
            )));
        }

        // Collector read_from is a closed vocabulary {start, end}. Every
        // collector's `ReadFrom::parse` silently falls back to End on any
        // unrecognized value, so a typo like "begining" would make a
        // collector tail-only and silently drop the historical replay the
        // operator asked for. Fail fast instead of mis-reading at startup.
        // An empty string is the derive-Default sentinel ("unset" → end) and
        // is accepted so an untouched config keeps loading.
        const VALID_READ_FROM: [&str; 2] = ["start", "end"];
        for (section, value) in [
            ("auditd", &self.collectors.auditd.read_from),
            ("journald", &self.collectors.journald.read_from),
            ("tetragon", &self.collectors.tetragon.read_from),
            ("suricata", &self.collectors.suricata.read_from),
            ("eventstream", &self.collectors.eventstream.read_from),
        ] {
            if !value.is_empty() && !VALID_READ_FROM.contains(&value.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "[collectors.{section}] read_from must be one of {VALID_READ_FROM:?} (or unset), got {value:?} \
                     (an unrecognized value silently defaults to \"end\", dropping historical replay)"
                )));
            }
        }

        // API transport pre-flight. The api server enforces these at
        // task-start, but the task only logs "api server failed" and exits
        // while the daemon keeps running — so a misconfigured api silently
        // doesn't serve. Mirror the transport layer's NoTransport +
        // MissingToken checks here so `Config::load` (and `selfdefd
        // --validate`) fail fast instead. Defaults pass: api is disabled by
        // default, and an enabled default has a unix socket + token_file.
        if self.api.enabled {
            let has_unix = !self.api.unix_socket.trim().is_empty();
            let has_tcp = !self.api.tcp_addr.trim().is_empty();
            if !has_unix && !has_tcp {
                return Err(ConfigError::Invalid(
                    "[api] enabled = true but neither unix_socket nor tcp_addr is set — \
                     set one transport or disable the api"
                        .into(),
                ));
            }
            if has_tcp && self.api.token_file.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "[api] tcp_addr is set but token_file is empty — the TCP transport \
                     requires a bearer token_file (it refuses to serve unauthenticated)"
                        .into(),
                ));
            }
            // tcp_addr must be a literal IP:port. The daemon parses it as a std
            // `SocketAddr` (`cfg.tcp_addr.parse()`), which does NOT resolve
            // hostnames; on failure it only logs "tcp transport disabled" and
            // serves nothing while the daemon keeps running. So a hostname
            // ("localhost:8443"), a missing port ("127.0.0.1"), or stray
            // whitespace passes the non-empty check above yet leaves the operator
            // with a TCP API that silently never listens. Mirror the daemon's
            // exact (untrimmed) parse so validation and runtime agree.
            if has_tcp && self.api.tcp_addr.parse::<std::net::SocketAddr>().is_err() {
                return Err(ConfigError::Invalid(format!(
                    "[api] tcp_addr = {:?} is not a valid IP:port socket address \
                     (e.g. \"127.0.0.1:8443\"; hostnames are not resolved) — the daemon \
                     cannot bind it and would silently serve no TCP API",
                    self.api.tcp_addr
                )));
            }
            // The UNIX socket is "trusted via filesystem permissions" — its mode
            // IS the access-control boundary. The daemon parses unix_socket_mode
            // as `from_str_radix(.., 8).unwrap_or(0o660)`, so ANY value it cannot
            // parse (a typo, stray whitespace, a non-octal digit) silently
            // becomes 0660 — group-readable — *widening* access to the control
            // API instead of honoring the operator's intent. Reject exactly what
            // the daemon could not parse, mirroring its parse so validation and
            // runtime agree, and only when the unix transport is actually used.
            if has_unix
                && u32::from_str_radix(self.api.unix_socket_mode.trim_start_matches('0'), 8)
                    .is_err()
            {
                return Err(ConfigError::Invalid(format!(
                    "[api] unix_socket_mode = {:?} is not a valid octal file mode (e.g. \"0660\") — \
                     an unparseable mode silently falls back to 0660 (group-readable), widening \
                     permissions on the trusted control API socket",
                    self.api.unix_socket_mode
                )));
            }
            // TLS for the TCP transport. The daemon enables TLS only when BOTH
            // cert_path and key_path are set, and requires client certs (mTLS)
            // only when client_ca is *also* set — all inside that same TLS
            // branch (`build_api_config`). So a half-configured TLS (exactly one
            // of cert/key) or an mTLS-only block (client_ca without cert+key)
            // silently DISABLES TLS and serves the TCP control API in PLAINTEXT,
            // gated by the bearer token alone — the opposite of the operator's
            // evident intent, since they supplied a cert / key / CA precisely to
            // encrypt it. Fail fast instead of silently downgrading. Only the
            // TCP transport uses TLS, so this is gated on `has_tcp`.
            if has_tcp {
                let cert = !self.api.tls.cert_path.trim().is_empty();
                let key = !self.api.tls.key_path.trim().is_empty();
                let client_ca = !self.api.tls.client_ca.trim().is_empty();
                if cert != key {
                    return Err(ConfigError::Invalid(
                        "[api.tls] cert_path and key_path must BOTH be set (or both empty) — \
                         exactly one is set, which silently disables TLS and serves the TCP \
                         control API in plaintext (bearer token only)"
                            .into(),
                    ));
                }
                if client_ca && !(cert && key) {
                    return Err(ConfigError::Invalid(
                        "[api.tls] client_ca (mTLS) is set but cert_path/key_path are not — \
                         mTLS requires TLS, so without a cert+key the TCP control API silently \
                         serves plaintext with no client-certificate requirement"
                            .into(),
                    ));
                }
            }
        }

        // The NATS multi-host bridge only starts when it's enabled AND has a
        // non-empty url (the daemon's `enabled && !url.trim().is_empty()`
        // guard); enabling it without a url silently yields no bridge — the
        // operator thinks they have multi-host fan-out and don't. Catch it.
        if self.bus.nats.enabled && self.bus.nats.url.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "[bus.nats] enabled = true but url is empty — the NATS bridge \
                 needs a url (e.g. \"nats://host:4222\") or it silently never connects"
                    .into(),
            ));
        }

        // inproc_capacity feeds `Bus::new` → tokio `broadcast::channel`, which
        // PANICS if capacity == 0. A config typo would otherwise crash the
        // daemon at startup with a raw panic instead of an actionable error.
        if self.bus.inproc_capacity == 0 {
            return Err(ConfigError::Invalid(
                "[bus] inproc_capacity = 0 is invalid — the in-process event \
                 bus needs a positive per-subscriber backlog (default 4096); \
                 a 0 capacity would panic the daemon at startup"
                    .into(),
            ));
        }

        // journald mode selects between two entirely different collectors:
        // the daemon treats "file" as file-tail mode and ANY other value as
        // journalctl-subprocess mode (`mode == "file"` else Journalctl). So a
        // typo like "fil" silently runs journalctl and ignores the operator's
        // input_path. Closed vocabulary {journalctl, file}; empty = unset.
        const VALID_JOURNALD_MODE: [&str; 2] = ["journalctl", "file"];
        let jmode = &self.collectors.journald.mode;
        if !jmode.is_empty() && !VALID_JOURNALD_MODE.contains(&jmode.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "[collectors.journald] mode must be one of {VALID_JOURNALD_MODE:?} (or unset), got {jmode:?} \
                 (an unrecognized value silently falls back to journalctl mode, ignoring input_path)"
            )));
        }

        // responder.min_severity (F-2026-092) is the floor that stops aggressive
        // autonomous actions (e.g. kill_pid) from firing on low-confidence
        // findings. The daemon treats ANY unrecognized token as "no floor —
        // every finding processed": it logs a warn and then runs fail-OPEN, so a
        // typo ("hgih" for "high") silently DROPS the operator's opt-in safety
        // floor and lets allow-listed aggressive actions fire on low findings.
        // Catch the typo at load (and `--validate`) so the requested floor is
        // actually applied; the runtime warn stays as a backstop for the
        // unvalidated path. Empty/none/unknown legitimately mean "no floor".
        const VALID_MIN_SEVERITY: [&str; 11] = [
            "none",
            "unknown",
            "info",
            "informational",
            "low",
            "medium",
            "med",
            "high",
            "critical",
            "crit",
            "fatal",
        ];
        let min_sev = self.responder.min_severity.trim().to_ascii_lowercase();
        if !min_sev.is_empty() && !VALID_MIN_SEVERITY.contains(&min_sev.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "[responder] min_severity = {:?} is not a recognized severity floor \
                 (use one of none/info/low/medium/high/critical/fatal) — an unrecognized \
                 token silently applies NO floor, letting aggressive autonomous actions \
                 fire on low-confidence findings",
                self.responder.min_severity
            )));
        }

        // [notifier].panic_floor (SDD-008 D-7) is the audit-mode escape hatch: in
        // audit mode (notifications suppressed) a finding AT OR ABOVE this grade
        // still fires for real, so "operator misconfiguration cannot leave a
        // blocker un-notified". The daemon parses it with parse_severity_floor
        // and, on an unrecognized token, logs a warn and applies NO panic floor
        // (fail-OPEN). So a typo ("hihg" for "high") silently voids the escape
        // hatch — in audit mode even a critical finding is then suppressed. Catch
        // the typo at load; an unset/empty panic_floor legitimately means "no
        // floor". (parse_severity_floor accepts only grade tokens, so "none"/
        // "unknown" are NOT valid here — leave it unset for no floor.)
        const VALID_SEVERITY_GRADE: [&str; 9] = [
            "info",
            "informational",
            "low",
            "medium",
            "med",
            "high",
            "critical",
            "crit",
            "fatal",
        ];
        if let Some(raw) = &self.notifier.panic_floor {
            let pf = raw.trim().to_ascii_lowercase();
            if !pf.is_empty() && !VALID_SEVERITY_GRADE.contains(&pf.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "[notifier] panic_floor = {raw:?} is not a recognized severity grade \
                     (use one of informational/low/medium/high/critical/fatal, or leave it \
                     unset for no floor) — an unrecognized token silently voids the audit-mode \
                     panic escape hatch, suppressing even critical findings"
                )));
            }
        }

        // Per-channel severity floors (wall / write / per-subscription). Each is
        // parsed with the same grade vocabulary; an unrecognized token silently
        // breaks the channel — the wall/write builder REFUSES the channel
        // (fail-closed: no notifications), and a subscription floor falls open
        // (the channel fires on EVERY finding instead of its intended gate, a
        // paging storm). Catch the typo at load either way. Empty/unset is the
        // documented "use the default / no floor" sentinel and is accepted.
        let bad_grade = |value: &str| {
            let v = value.trim().to_ascii_lowercase();
            !v.is_empty() && !VALID_SEVERITY_GRADE.contains(&v.as_str())
        };
        if bad_grade(&self.notifier.wall.severity_floor) {
            return Err(ConfigError::Invalid(format!(
                "[notifier.wall] severity_floor = {:?} is not a recognized severity grade \
                 (use one of informational/low/medium/high/critical/fatal, or leave it unset \
                 for the default) — an unrecognized token makes the builder refuse the wall \
                 channel, silently disabling its broadcasts",
                self.notifier.wall.severity_floor
            )));
        }
        if bad_grade(&self.notifier.write.severity_floor) {
            return Err(ConfigError::Invalid(format!(
                "[notifier.write] severity_floor = {:?} is not a recognized severity grade \
                 (use one of informational/low/medium/high/critical/fatal, or leave it unset \
                 for the default) — an unrecognized token silently disables the write channel",
                self.notifier.write.severity_floor
            )));
        }
        for (name, sub) in &self.notifier.subscriptions {
            if let Some(raw) = &sub.severity_floor {
                if bad_grade(raw) {
                    return Err(ConfigError::Invalid(format!(
                        "[notifier.subscriptions.{name}] severity_floor = {raw:?} is not a \
                         recognized severity grade (use one of informational/low/medium/high/\
                         critical/fatal, or leave it unset) — an unrecognized token is silently \
                         dropped, so the channel fires on every finding instead of its intended gate"
                    )));
                }
            }
        }

        // The hardware-probe loop re-probes every interval_seconds, but only
        // when enabled. The loop floors the cadence at 30s
        // (`interval_seconds.max(30)`) as a runtime backstop — so a sub-30
        // value is silently clamped, not honored: the operator asks for 5s,
        // gets 30s with no signal, and the loop even logs the raw 5s while
        // ticking at 30. The field's own contract says "Below 30 is rejected
        // at validation time — sub-30s cadence yields no operator value", so
        // honor that here and fail fast with an actionable error instead of a
        // silent clamp. Only meaningful when the loop actually runs (enabled);
        // a leftover low value in a disabled block keeps loading.
        if self.hardware_probe.enabled && self.hardware_probe.interval_seconds < 30 {
            return Err(ConfigError::Invalid(format!(
                "[hardware_probe] interval_seconds = {} is below the 30s minimum — \
                 sub-30s probe cadence yields no operator value (probe I/O is cheap \
                 but not free); raise it to >= 30 (default 300) or disable the probe",
                self.hardware_probe.interval_seconds
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- daemon

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DaemonConfig {
    pub host_tag: Option<String>,
    /// Tracing verbosity as an `EnvFilter` directive (`"info"` default; also
    /// accepts per-target directives like `"info,selfdef_correlator=debug"`).
    /// Consumed by `selfdef-daemon` main `init_tracing`. Precedence:
    /// `--log-level` / `$SELFDEF_LOG` (explicit override) > this field >
    /// `$RUST_LOG` / built-in default (set this to `""` to defer to `$RUST_LOG`).
    pub log_level: String,
    /// `"text"` (default) or `"json"`. Consumed by the daemon's tracing
    /// init (`selfdef-daemon` main `init_tracing`) for the stderr fallback
    /// logger — `"json"` emits structured lines for log ingest. (Under
    /// journald the daemon logs structured fields natively, so this applies
    /// to the no-journald path.)
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
    /// F-2026-111 (c): per-event federation signing. Path to this daemon's
    /// UNENCRYPTED minisign secret key (`minisign -G -W`). When non-empty,
    /// outbound events are wrapped in a signed envelope, and inbound events are
    /// verified against `peer_keys`. A signature-verified federated finding
    /// bypasses the responder's fail-closed `act_on_federated` gate. Empty
    /// (default) ⇒ raw, unauthenticated events as before.
    pub signing_key_file: String,
    /// Trusted-peer public keys: sender `host_tag` → minisign `.pub` file path.
    /// A federated event is only `federation_verified` if its envelope verifies
    /// against the key mapped to its sender host_tag here. Empty ⇒ no peer is
    /// verifiable (every federated event stays unverified).
    pub peer_keys: std::collections::BTreeMap<String, String>,
}

impl Default for NatsBridgeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            subject_prefix: "selfdef.events".into(),
            jetstream: NatsJetStreamConfig::default(),
            signing_key_file: String::new(),
            peer_keys: std::collections::BTreeMap::new(),
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
    /// D-004 realization: write(1) per-user session-attention channel.
    /// Sibling of `wall` for operators wanting per-user opt-in
    /// (only listed users' TTYs receive escalations) instead of
    /// wall's broadcast-all-TTYs behavior. Empty `users` keeps the
    /// channel disabled.
    pub write: WriteConfig,
    /// SDD-014: shared-audit-summary channel — when on a SAIN-01
    /// deployment, selfdef appends an index line per event to
    /// /mnt/vault/context/security_audit.log (the shared cross-
    /// component operator timeline that sovereign-os guardian-core
    /// also writes to). Auto-enabled when deployment.target=sain01;
    /// operators can opt out via `enabled = false`. Never auto-
    /// enabled on generic deployments (Q-G honored).
    pub shared_audit_summary: SharedAuditSummaryConfig,
    /// SDD-016: oracle-triage channel — dispatches event payloads
    /// through the sovereign-os inference router for operator-reviewed
    /// triage suggestions. NEVER auto-enabled, even on SAIN-01
    /// (Q-D verbatim). Operator must explicitly set `enabled = true`.
    pub oracle_triage: OracleTriageConfig,
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
            write: WriteConfig::default(),
            shared_audit_summary: SharedAuditSummaryConfig::default(),
            oracle_triage: OracleTriageConfig::default(),
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
///
/// **D-004 note**: `wall(1)` does not natively filter by user.
/// Operators wanting per-user opt-in should configure the sibling
/// `[notifier.write]` channel instead — `write(1)` targets one user
/// at a time. The `wall.users` field intentionally does not exist;
/// the per-user transport is its own channel.
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

/// D-004 realization: write(1) per-user session-attention channel.
///
/// Sibling of `wall` for per-user TTY delivery. Where wall(1)
/// broadcasts to every logged-in TTY, write(1) targets one user at
/// a time. Operators who want session-attention only on a specific
/// allowlist of operator accounts wire up this channel.
///
/// Empty `binary` OR empty `users` keeps the channel disabled.
/// `severity_floor` defaults to `"high"` (same posture as wall).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct WriteConfig {
    /// Path to the `write(1)` binary. Empty disables the channel.
    pub binary: PathBuf,
    /// Severity threshold below which write stays silent. Same
    /// values as `WallConfig::severity_floor`.
    pub severity_floor: String,
    /// Target users. Each name in this list receives a per-user
    /// `write(1) <name>` invocation. Empty disables the channel.
    /// Usernames must match `[a-zA-Z0-9._-]+` — shell metacharacters
    /// are rejected at config-load time.
    pub users: Vec<String>,
}

// ---------------------------------------------------------------- perimeter (SDD-015)

/// SDD-015: Tetragon perimeter coexistence configuration.
///
/// When `deployment.target = sain01`, selfdef and sovereign-os both
/// author Tetragon TracingPolicy YAMLs into
/// `/etc/tetragon/tracing-policies/`. This config gates the boundary
/// enforcement that prevents a selfdef-authored `agent-guard-*` policy
/// from overlapping with sovereign-os's `sovereign-kernel-fence.yaml`
/// host-scoped allowlist.
///
/// On `deployment.target = generic`, this block is IGNORED entirely —
/// the boundary doesn't apply (no sovereign-os assumption).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PerimeterConfig {
    /// When true (default on sain01, false on generic),
    /// `selfdefctl modules apply` runs `perimeter check-overlap`
    /// before installing any new TracingPolicy file. Refuses to apply
    /// if overlap is detected (unless `overlap_warn_only = true`).
    pub check_overlap_on_apply: Option<bool>,
    /// Path to sovereign-os's host-scoped allowlist. selfdef reads
    /// this to know what NOT to overlap with. Empty path is treated
    /// as "no peer policy author" (overlap check vacuously passes).
    pub sovereign_kernel_fence_path: PathBuf,
    /// Directory holding all Tetragon TracingPolicy YAMLs (both
    /// authors). Default `/etc/tetragon/tracing-policies` matches
    /// Tetragon's stock load path.
    pub policies_dir: PathBuf,
    /// When true, overlap detection emits a WARN line but does NOT
    /// fail. Default false (block on overlap).
    pub overlap_warn_only: bool,
    /// SDD-015 Q15-D: stance toward THIRD-PARTY Tetragon policies
    /// (files not matching "sovereign-" or "agent-guard-" prefix).
    /// One of:
    ///   - "warn" (default): treat as opaque, log a WARN but do not
    ///     block. Operator's discretion (per Q15-D recommendation).
    ///   - "ignore": no warning, no block.
    ///   - "block": treat third-party policies the same as
    ///     agent-guard for the overlap check (refuse on host-scoped
    ///     fenced syscalls). Stricter than the spec — operator opt-in.
    pub third_party_policy_stance: String,
}

impl Default for PerimeterConfig {
    fn default() -> Self {
        Self {
            check_overlap_on_apply: None, // resolves via target at use-site
            sovereign_kernel_fence_path: PathBuf::from(
                "/etc/tetragon/tracing-policies/sovereign-kernel-fence.yaml",
            ),
            policies_dir: PathBuf::from("/etc/tetragon/tracing-policies"),
            overlap_warn_only: false,
            third_party_policy_stance: "warn".to_owned(),
        }
    }
}

/// SDD-015 § 4: resolve effective `check_overlap_on_apply` —
/// auto-true on sain01 unless explicitly overridden; auto-false on
/// generic unless explicitly overridden.
#[must_use]
pub fn resolve_perimeter_check_overlap(cfg: &Config) -> bool {
    if let Some(v) = cfg.perimeter.check_overlap_on_apply {
        return v;
    }
    matches!(cfg.deployment.target, DeploymentTarget::Sain01)
}

// ---------------------------------------------------------------- oracle-triage (SDD-016)

/// SDD-016: oracle-triage channel configuration.
///
/// NEVER auto-enabled — operator must set `enabled = true` explicitly,
/// even on SAIN-01 (SDD-012 Q-D verbatim: "selfdef stays Oracle-Core-
/// unaware in v1; opt-in `oracle-triage` notifier channel post-
/// procurement"). On generic deployments the channel can still be
/// enabled by pointing `endpoint` at a different inference router.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct OracleTriageConfig {
    /// Opt-in flag. Default `false` — operator's explicit consent
    /// required.
    pub enabled: bool,
    /// Inference-router endpoint. Default `http://127.0.0.1:8080`
    /// matches sovereign-os SDD-011's router default.
    pub endpoint: String,
    /// Model token. `"auto"` (default) lets the router's classify()
    /// pick per-request; operators can pin a specific model.
    pub model: String,
    /// Per-request timeout. Default 30s per SDD-016 § 2.
    pub timeout_seconds: u64,
    /// Env-var name carrying an optional bearer token. Empty/None =
    /// no Authorization header. Operators NEVER write the secret
    /// itself into selfdef.toml — only the variable name.
    pub api_key_env: Option<String>,
    /// Filter applied per event before dispatch (severity floor +
    /// kind allowlist).
    pub filter: OracleTriageFilterConfig,
    /// Where the triage block lands.
    /// `operator-dashboard` | `shared-audit-summary` | `both`.
    pub output_target: String,
    /// Optional path to a custom system prompt. None = use the
    /// SDD-016 § 3 default.
    pub system_prompt_path: Option<PathBuf>,
    /// SDD-016 Q16-D: cost / token-budget rate limit. The channel
    /// refuses to dispatch when it has already sent `max_events_per_hour`
    /// requests in the trailing 60-minute window — protects operator
    /// inference budgets from runaway event storms. Default 100 per
    /// SDD-016 Q16-D recommendation. Set to 0 to disable.
    pub max_events_per_hour: u32,
}

impl Default for OracleTriageConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "http://127.0.0.1:8080".to_owned(),
            model: "auto".to_owned(),
            timeout_seconds: 30,
            api_key_env: None,
            filter: OracleTriageFilterConfig::default(),
            output_target: "operator-dashboard".to_owned(),
            system_prompt_path: None,
            max_events_per_hour: 100,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct OracleTriageFilterConfig {
    /// Severity floor (token: `informational` / `low` / `medium` /
    /// `high` / `critical` / `fatal`). Default `medium`.
    pub min_severity: String,
    /// Kind allowlist. Empty = all kinds pass.
    pub kinds: Vec<String>,
}

impl Default for OracleTriageFilterConfig {
    fn default() -> Self {
        Self {
            min_severity: "medium".to_owned(),
            kinds: Vec::new(),
        }
    }
}

/// SDD-014: shared-audit-summary channel configuration.
///
/// Most operators on SAIN-01 will leave this entirely default — the
/// channel auto-enables at `deployment.target=sain01` (see
/// [`resolve_shared_audit_summary_enabled`]) and routes to
/// `/mnt/vault/context/security_audit.log`. The config block exists so
/// operators can:
///   - opt out with `enabled = false`
///   - override the path for testing
///   - override the selfdef-audit pointer target
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct SharedAuditSummaryConfig {
    /// Operator-explicit on/off. `None` = "use the SAIN-01 default"
    /// (auto-enable on sain01, never on generic). `Some(true)` =
    /// force-enable; `Some(false)` = force-disable (operator can opt
    /// out on SAIN-01 with this).
    pub enabled: Option<bool>,
    /// Override path. `None` = use the resolver default
    /// `/mnt/vault/context/security_audit.log` (SDD-014 § 2 default).
    pub path: Option<PathBuf>,
    /// Override selfdef-audit pointer target. `None` = use the
    /// resolver default (target-driven, per SDD-013).
    pub selfdef_audit_path: Option<PathBuf>,
    /// SDD-014 Q14-C: emit a JSONL twin under
    /// `/mnt/vault/context/security_audit.jsonl` alongside the text
    /// summary. Machine readers (dashboards, fleet aggregators)
    /// consume the JSONL; operators read the text log. Default false
    /// — opt-in per Q14-C "DEFER" recommendation; operators enable
    /// only when they have a machine reader.
    pub jsonl_twin: bool,
    /// Override JSONL twin path. `None` = derive from `path` by
    /// swapping `.log` → `.jsonl`. Only used when `jsonl_twin = true`.
    pub jsonl_twin_path: Option<PathBuf>,
}

/// SDD-014 § 2: resolve the effective enabled-state for the
/// shared-audit-summary channel. Single source of truth for both the
/// daemon's `build_channel_set` and `selfdefctl doctor`.
///
/// Logic:
///   - generic target  → never auto-enable; respect explicit override
///   - sain01 target   → auto-enable; respect explicit override
#[must_use]
pub fn resolve_shared_audit_summary_enabled(cfg: &Config) -> bool {
    if let Some(v) = cfg.notifier.shared_audit_summary.enabled {
        return v;
    }
    matches!(cfg.deployment.target, DeploymentTarget::Sain01)
}

/// SDD-014 § 2: resolve the effective shared-audit-log path.
/// Override > resolver default (per target).
#[must_use]
pub fn resolve_shared_audit_summary_path(cfg: &Config) -> Option<PathBuf> {
    if let Some(p) = &cfg.notifier.shared_audit_summary.path {
        return Some(p.clone());
    }
    shared_audit_log_path(cfg.deployment.target)
}

/// SDD-014 § 2: resolve the effective selfdef-audit pointer target.
/// Override > resolver default (per target).
#[must_use]
pub fn resolve_shared_audit_summary_pointer(cfg: &Config) -> PathBuf {
    if let Some(p) = &cfg.notifier.shared_audit_summary.selfdef_audit_path {
        return p.clone();
    }
    audit_log_path(cfg.deployment.target)
}

/// SDD-014 Q14-C: resolve the effective JSONL twin path. Returns
/// `None` when `jsonl_twin = false` (the Q14-C default). When enabled,
/// returns either the explicit `jsonl_twin_path` override, or the
/// shared-log path with `.log` swapped to `.jsonl`.
#[must_use]
pub fn resolve_shared_audit_summary_jsonl_twin(cfg: &Config) -> Option<PathBuf> {
    if !cfg.notifier.shared_audit_summary.jsonl_twin {
        return None;
    }
    if let Some(p) = &cfg.notifier.shared_audit_summary.jsonl_twin_path {
        return Some(p.clone());
    }
    // Derive from shared-log path: foo/security_audit.log →
    // foo/security_audit.jsonl. When the resolver returns None (generic
    // target, no override), we have nothing to derive from.
    let base = resolve_shared_audit_summary_path(cfg)?;
    let mut s = base.clone();
    s.set_extension("jsonl");
    Some(s)
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
    /// Autonomous-response severity floor (F-2026-092). Findings graded below
    /// this are not auto-dispatched on the bus path — a guard against an
    /// allow-listed aggressive action (e.g. `kill_pid`) firing on a
    /// low-confidence finding. Accepts `none` / `unknown` (no floor — every
    /// finding is processed, the default) or a grade token (`info`, `low`,
    /// `medium`, `high`, `critical`, `fatal`). Operator-commanded paths
    /// (`selfdefctl panic`, the authenticated `/actions/{name}/run` API) bypass
    /// the floor by design.
    pub min_severity: String,
    /// Burst-dedup window in SECONDS for destructive actions (decision-discipline).
    /// When > 0, a destructive action (kill / quarantine / block / isolate / …)
    /// repeated on the same target (pid|src-ip|user) within this many seconds is
    /// suppressed — a guard against a finding burst hammering the same action on
    /// the same target. Notify / snapshot / forensic actions are never deduped
    /// (every alert + evidence capture is kept). Default `0` = disabled (exact
    /// pre-dedup behavior); operators opt in.
    pub dedup_window_secs: u64,
    /// Circuit-breaker: max DESTRUCTIVE actions dispatched per rolling 60s
    /// (decision-discipline). When > 0, once this many destructive actions have
    /// fired in the last minute, further destructive actions are suppressed
    /// until the window drains — a guard against an event FLOOD (many distinct
    /// targets, which per-target dedup can't catch) driving the IPS into mass
    /// destruction. Notify / snapshot / forensic actions are never capped.
    /// Default `0` = disabled (no cap); operators opt in.
    pub max_destructive_actions_per_min: u32,
    /// Federation trust boundary (F-2026-111). When `true` (default), findings
    /// triggered by events received from OTHER hosts via the NATS bridge drive
    /// destructive response exactly like local findings — the prior behavior.
    /// Set `false` to FAIL CLOSED: a destructive action (kill / quarantine /
    /// isolate / egress-lockdown) is refused for a federated-origin finding,
    /// since a compromised broker or peer could forge a finding naming a local
    /// pid/user. Recommended `false` for any deployment NOT relying on
    /// cross-host response. Alerts / evidence / escalation are never refused, and
    /// operator-commanded `selfdefctl` actions always act.
    pub act_on_federated: bool,
    /// Directory under which `snapshot_proc` writes per-event dumps.
    pub snapshot_dir: PathBuf,
    /// Script invoked by `lockdown_egress` action.
    pub lockdown_script: PathBuf,
    /// Script invoked by `revoke_session` action.
    pub revoke_session_script: PathBuf,
    /// Usernames the `revoke_session` action must NEVER revoke — the self-lockout
    /// guard (F-2026-121). `event.actor.user` is attacker-influenceable, so
    /// populate this with the operator account and any break-glass admin to stop
    /// a crafted event from stripping the operator's sessions mid-incident.
    /// Empty by default (no protection — set it for any host running autonomous
    /// session revocation).
    pub revoke_session_excluded_users: Vec<String>,
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
            // No floor by default: matches the pre-F-2026-092 behavior where
            // every finding is processed. Operators opt into a higher floor.
            min_severity: "none".to_owned(),
            // Disabled by default — no behavior change vs the pre-dedup responder.
            dedup_window_secs: 0,
            // Disabled by default — no destructive-action rate cap.
            max_destructive_actions_per_min: 0,
            // Default `true` preserves prior cross-host-response behavior; set
            // `false` to fail closed on federated-origin destructive triggers.
            act_on_federated: true,
            snapshot_dir: PathBuf::from("/var/lib/selfdef/snapshots"),
            lockdown_script: PathBuf::from("/usr/local/sbin/selfdef-lockdown.sh"),
            revoke_session_script: PathBuf::from("/usr/local/sbin/selfdef-revoke-session.sh"),
            revoke_session_excluded_users: Vec::new(),
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
    fn validate_rejects_signed_rules_without_key() {
        let mut cfg = Config::default();
        cfg.security.require_signed_rules = true;
        cfg.security.signing_public_key_file = None;
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)), "got {err:?}");
        assert!(err.to_string().contains("signing_public_key_file"));
        // Providing the key makes it valid.
        cfg.security.signing_public_key_file = Some(PathBuf::from("/etc/selfdef/keys/policy.pub"));
        cfg.validate().unwrap();
    }

    #[test]
    fn defaults_validate_and_load() {
        // The default config (require_signed_rules=false) must pass validate.
        Config::default().validate().unwrap();
    }

    #[test]
    fn validate_api_transport_preflight() {
        // Default (api disabled) validates.
        Config::default().validate().unwrap();

        // Enabled with neither transport → rejected.
        let mut cfg = Config::default();
        cfg.api.enabled = true;
        cfg.api.unix_socket = String::new();
        cfg.api.tcp_addr = String::new();
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("neither unix_socket nor tcp_addr"),
            "{err:?}"
        );

        // Enabled with a TCP bind but no token → rejected.
        let mut cfg = Config::default();
        cfg.api.enabled = true;
        cfg.api.unix_socket = String::new();
        cfg.api.tcp_addr = "127.0.0.1:8443".to_owned();
        cfg.api.token_file = String::new();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("token_file"), "{err:?}");

        // Enabled with TCP + token → valid. Enabled with just the default
        // unix socket → valid.
        cfg.api.token_file = "/etc/selfdef/api.token".to_owned();
        cfg.validate().unwrap();
        let mut cfg = Config::default();
        cfg.api.enabled = true; // default unix_socket + token_file present
        cfg.validate().unwrap();
    }

    #[test]
    fn validate_rejects_nats_enabled_without_url() {
        let mut cfg = Config::default();
        cfg.bus.nats.enabled = true;
        cfg.bus.nats.url = "   ".to_owned(); // whitespace-only counts as empty
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)), "got {err:?}");
        assert!(err.to_string().contains("[bus.nats]"));
        // A real url makes it valid; disabled-with-empty-url stays valid.
        cfg.bus.nats.url = "nats://localhost:4222".to_owned();
        cfg.validate().unwrap();
        cfg.bus.nats.enabled = false;
        cfg.bus.nats.url = String::new();
        cfg.validate().unwrap();
    }

    #[test]
    fn validate_rejects_zero_inproc_capacity() {
        // inproc_capacity == 0 → tokio broadcast::channel(0) panics; validate
        // must surface it as an actionable config error, not a daemon crash.
        let mut cfg = Config::default();
        cfg.bus.inproc_capacity = 0;
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)), "got {err:?}");
        assert!(err.to_string().contains("inproc_capacity"));
        // Any positive value is fine (default is 4096).
        cfg.bus.inproc_capacity = 1;
        cfg.validate().unwrap();
    }

    #[test]
    fn validate_rejects_invalid_unix_socket_mode() {
        // The daemon parses unix_socket_mode with `unwrap_or(0o660)`, so an
        // unparseable mode silently widens the trusted control socket to
        // group-readable. validate must reject it (when the unix transport is
        // used) so the operator gets an actionable error, not a silent widening.
        let mut cfg = Config::default();
        cfg.api.enabled = true;
        cfg.api.unix_socket = "/run/selfdef/api.sock".into();
        for bad in ["xyz", "0o660", "rw-", "0660 ", "", "099", "0"] {
            cfg.api.unix_socket_mode = bad.into();
            let err = cfg.validate().unwrap_err();
            assert!(matches!(err, ConfigError::Invalid(_)), "{bad:?} → {err:?}");
            assert!(
                err.to_string().contains("unix_socket_mode"),
                "msg should name the field for {bad:?}: {err}"
            );
        }
        // Valid octal modes pass (with or without the leading zero).
        for good in ["0600", "0660", "0640", "660", "700", "0700"] {
            cfg.api.unix_socket_mode = good.into();
            cfg.validate()
                .unwrap_or_else(|e| panic!("mode {good:?} must be valid, got {e:?}"));
        }
        // A bad mode in a config whose unix transport is unused does not block
        // loading (only TCP enabled), matching the gating of the other checks.
        cfg.api.unix_socket = String::new();
        cfg.api.tcp_addr = "127.0.0.1:8443".into();
        cfg.api.token_file = "/run/selfdef/token".into();
        cfg.api.unix_socket_mode = "garbage".into();
        cfg.validate().unwrap();
    }

    #[test]
    fn validate_rejects_unknown_channel_severity_floors() {
        // wall / write / per-subscription severity floors are grade vocabularies;
        // a typo silently breaks the channel (wall/write refuse → no
        // notifications; subscription falls open → fires on everything).
        let mut cfg = Config::default();
        // wall typo.
        cfg.notifier.wall.severity_floor = "hihg".into();
        assert!(
            cfg.validate()
                .unwrap_err()
                .to_string()
                .contains("notifier.wall")
        );
        cfg.notifier.wall.severity_floor = "high".into();
        // write typo.
        cfg.notifier.write.severity_floor = "kritical".into();
        assert!(
            cfg.validate()
                .unwrap_err()
                .to_string()
                .contains("notifier.write")
        );
        cfg.notifier.write.severity_floor = "critical".into();
        cfg.validate().unwrap(); // wall+write now valid
        // subscription typo names the channel.
        let sub = SubscriptionConfig {
            severity_floor: Some("hi".into()),
            ..Default::default()
        };
        cfg.notifier.subscriptions.insert("ntfy".into(), sub);
        assert!(
            cfg.validate()
                .unwrap_err()
                .to_string()
                .contains("notifier.subscriptions.ntfy")
        );
        // valid subscription floor + an unset one both pass.
        let sub_ok = SubscriptionConfig {
            severity_floor: Some("high".into()),
            ..Default::default()
        };
        cfg.notifier.subscriptions.insert("ntfy".into(), sub_ok);
        cfg.notifier
            .subscriptions
            .insert("signal".into(), SubscriptionConfig::default()); // floor None
        cfg.validate().unwrap();
        // empty wall floor (= default) is accepted.
        cfg.notifier.wall.severity_floor = String::new();
        cfg.validate().unwrap();
    }

    #[test]
    fn validate_rejects_unknown_notifier_panic_floor() {
        // A typo in the audit-mode panic escape hatch silently voids it (no
        // floor → audit mode suppresses even critical findings). validate must
        // reject an unrecognized grade. Unset/empty legitimately means no floor.
        let mut cfg = Config::default();
        for bad in ["hihg", "none", "unknown", "warn", "5", "high!"] {
            cfg.notifier.panic_floor = Some(bad.into());
            let err = cfg.validate().unwrap_err();
            assert!(matches!(err, ConfigError::Invalid(_)), "{bad:?} → {err:?}");
            assert!(
                err.to_string().contains("panic_floor"),
                "msg should name the field for {bad:?}: {err}"
            );
        }
        // Unset and every recognized grade/alias (any case) and empty pass.
        cfg.notifier.panic_floor = None;
        cfg.validate().unwrap();
        for good in [
            "informational",
            "info",
            "low",
            "medium",
            "med",
            "high",
            "HIGH",
            "critical",
            "crit",
            "fatal",
            "",
        ] {
            cfg.notifier.panic_floor = Some(good.into());
            cfg.validate()
                .unwrap_or_else(|e| panic!("panic_floor {good:?} must be valid, got {e:?}"));
        }
    }

    #[test]
    fn validate_rejects_unknown_responder_min_severity() {
        // A typo in the autonomous-response floor silently runs fail-open (no
        // floor → every finding processed, aggressive actions can fire on low
        // findings). validate must reject an unrecognized token.
        let mut cfg = Config::default();
        for bad in ["hgih", "severe", "warn", "9", "high!", "none "] {
            // note: "none " has trailing space but trims to "none" — valid; keep
            // it out of the bad set below by testing real typos only.
            if bad.trim().eq_ignore_ascii_case("none") {
                continue;
            }
            cfg.responder.min_severity = bad.into();
            let err = cfg.validate().unwrap_err();
            assert!(matches!(err, ConfigError::Invalid(_)), "{bad:?} → {err:?}");
            assert!(
                err.to_string().contains("min_severity"),
                "msg should name the field for {bad:?}: {err}"
            );
        }
        // Recognized tokens (any case), the aliases, empty, and the default all pass.
        for good in [
            "none",
            "unknown",
            "",
            "info",
            "informational",
            "low",
            "medium",
            "med",
            "high",
            "HIGH",
            "critical",
            "crit",
            "fatal",
        ] {
            cfg.responder.min_severity = good.into();
            cfg.validate()
                .unwrap_or_else(|e| panic!("min_severity {good:?} must be valid, got {e:?}"));
        }
    }

    #[test]
    fn validate_rejects_half_configured_api_tls() {
        // A cert without a key (or vice versa), or client_ca without cert+key,
        // makes the daemon silently disable TLS and serve the TCP control API in
        // plaintext. validate must reject these — but only when TCP is in use.
        let base = || {
            let mut c = Config::default();
            c.api.enabled = true;
            c.api.tcp_addr = "127.0.0.1:8443".into();
            c.api.token_file = "/run/selfdef/token".into();
            c
        };
        // cert without key → rejected.
        let mut cfg = base();
        cfg.api.tls.cert_path = "/etc/selfdef/api.crt".into();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("cert_path and key_path"), "{err}");
        // key without cert → rejected.
        let mut cfg = base();
        cfg.api.tls.key_path = "/etc/selfdef/api.key".into();
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));
        // client_ca (mTLS) without cert+key → rejected.
        let mut cfg = base();
        cfg.api.tls.client_ca = "/etc/selfdef/ca.crt".into();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("client_ca"), "{err}");
        // cert+key → valid TLS; adding client_ca → valid mTLS.
        let mut cfg = base();
        cfg.api.tls.cert_path = "/etc/selfdef/api.crt".into();
        cfg.api.tls.key_path = "/etc/selfdef/api.key".into();
        cfg.validate().unwrap();
        cfg.api.tls.client_ca = "/etc/selfdef/ca.crt".into();
        cfg.validate().unwrap();
        // Neither set → TLS off, valid (plain HTTP + bearer, the documented default).
        base().validate().unwrap();
        // A half-TLS config with NO TCP transport (unix only) is not a plaintext
        // hazard — there is no TCP listener — so it must still load.
        let mut cfg = Config::default();
        cfg.api.enabled = true;
        cfg.api.unix_socket = "/run/selfdef/api.sock".into();
        cfg.api.tcp_addr = String::new();
        cfg.api.tls.cert_path = "/etc/selfdef/api.crt".into(); // key intentionally empty
        cfg.validate().unwrap();
    }

    #[test]
    fn validate_rejects_unparseable_tcp_addr() {
        // The daemon parses tcp_addr as a std SocketAddr (no hostname
        // resolution) and silently disables the TCP transport on failure — so a
        // hostname, a missing port, or stray whitespace passes the non-empty
        // check yet never listens. validate must reject it. A unix socket +
        // token are set so only tcp_addr validity is under test.
        let mut cfg = Config::default();
        cfg.api.enabled = true;
        cfg.api.unix_socket = "/run/selfdef/api.sock".into();
        cfg.api.token_file = "/run/selfdef/token".into();
        for bad in [
            "localhost:8443",
            "127.0.0.1",
            ":8443",
            "127.0.0.1:8443 ",
            "not-an-addr",
            "256.0.0.1:1",
        ] {
            cfg.api.tcp_addr = bad.into();
            let err = cfg.validate().unwrap_err();
            assert!(matches!(err, ConfigError::Invalid(_)), "{bad:?} → {err:?}");
            assert!(
                err.to_string().contains("tcp_addr"),
                "msg should name the field for {bad:?}: {err}"
            );
        }
        // Valid IPv4 and IPv6 socket addresses pass.
        for good in ["127.0.0.1:8443", "0.0.0.0:9000", "[::1]:8443"] {
            cfg.api.tcp_addr = good.into();
            cfg.validate()
                .unwrap_or_else(|e| panic!("addr {good:?} must be valid, got {e:?}"));
        }
    }

    #[test]
    fn validate_rejects_subthreshold_hardware_probe_interval() {
        // The loop clamps interval_seconds to >= 30 at runtime, so a sub-30
        // value is silently honored as 30 — validate must reject it (when the
        // probe is enabled) so the operator gets an actionable error instead.
        let mut cfg = Config::default();
        cfg.hardware_probe.enabled = true;
        for bad in [0_u64, 1, 5, 29] {
            cfg.hardware_probe.interval_seconds = bad;
            let err = cfg.validate().unwrap_err();
            assert!(matches!(err, ConfigError::Invalid(_)), "got {err:?}");
            assert!(
                err.to_string().contains("interval_seconds"),
                "msg should name the field: {err}"
            );
        }
        // >= 30 is accepted; the default (300) is accepted.
        for good in [30_u64, 60, 300] {
            cfg.hardware_probe.interval_seconds = good;
            cfg.validate()
                .unwrap_or_else(|e| panic!("interval {good} must be valid, got {e:?}"));
        }
        // A sub-30 value in a DISABLED probe block keeps loading — the loop
        // never runs, so the cadence is irrelevant.
        cfg.hardware_probe.enabled = false;
        cfg.hardware_probe.interval_seconds = 1;
        cfg.validate()
            .expect("disabled probe with low interval must still load");
    }

    #[test]
    fn validate_rejects_unknown_journald_mode() {
        let mut cfg = Config::default();
        cfg.collectors.journald.mode = "fil".to_owned();
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)), "got {err:?}");
        assert!(err.to_string().contains("mode"));
        assert!(err.to_string().contains("journald"));
        for mode in ["journalctl", "file", ""] {
            let mut c = Config::default();
            c.collectors.journald.mode = mode.to_owned();
            c.validate()
                .unwrap_or_else(|e| panic!("mode {mode:?} must be valid, got {e:?}"));
        }
    }

    #[test]
    fn validate_rejects_unknown_collector_read_from() {
        let mut cfg = Config::default();
        // A plausible typo for "start".
        cfg.collectors.journald.read_from = "begining".to_owned();
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)), "got {err:?}");
        assert!(err.to_string().contains("read_from"));
        assert!(err.to_string().contains("journald"));
        // Both documented values validate, for every collector.
        for from in ["start", "end"] {
            let mut c = Config::default();
            c.collectors.auditd.read_from = from.to_owned();
            c.collectors.journald.read_from = from.to_owned();
            c.collectors.tetragon.read_from = from.to_owned();
            c.collectors.suricata.read_from = from.to_owned();
            c.collectors.eventstream.read_from = from.to_owned();
            c.validate()
                .unwrap_or_else(|e| panic!("read_from {from:?} must be valid, got {e:?}"));
        }
    }

    #[test]
    fn validate_rejects_unknown_perimeter_stance() {
        let mut cfg = Config::default();
        cfg.perimeter.third_party_policy_stance = "panic".to_owned();
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)), "got {err:?}");
        assert!(err.to_string().contains("third_party_policy_stance"));
        // All three documented stances validate.
        for stance in ["warn", "ignore", "block"] {
            cfg.perimeter.third_party_policy_stance = stance.to_owned();
            cfg.validate()
                .unwrap_or_else(|e| panic!("stance {stance:?} must be valid, got {e:?}"));
        }
    }

    #[test]
    fn defaults_load_when_no_file() {
        let cfg = Config::load(None).unwrap();
        assert_eq!(cfg.bus.backend, "inproc");
        assert_eq!(cfg.daemon.log_level, "info");
        assert!(!cfg.collectors.auditd.enabled);
    }

    // ----- SD-R21 hardware-probe config -----------------------------

    #[test]
    fn sdr21_hardware_probe_defaults_are_disabled() {
        let cfg = HardwareProbeConfig::default();
        assert!(!cfg.enabled, "must be opt-in");
        assert!(!cfg.emit_thermal_events);
        assert_eq!(cfg.interval_seconds, 300);
        assert_eq!(cfg.thermal_warn_celsius, 85);
        assert_eq!(cfg.thermal_critical_celsius, 95);
        assert_eq!(cfg.gpu_critical_celsius, 0);
    }

    #[test]
    fn sdr21_hardware_probe_block_parses_when_set() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"
            [hardware_probe]
            enabled = true
            interval_seconds = 60
            emit_thermal_events = true
            thermal_warn_celsius = 75
            thermal_critical_celsius = 90
            gpu_critical_celsius = 95
            "#,
        )
        .unwrap();
        let cfg = Config::load(Some(tmp.path())).unwrap();
        assert!(cfg.hardware_probe.enabled);
        assert_eq!(cfg.hardware_probe.interval_seconds, 60);
        assert!(cfg.hardware_probe.emit_thermal_events);
        assert_eq!(cfg.hardware_probe.thermal_warn_celsius, 75);
        assert_eq!(cfg.hardware_probe.thermal_critical_celsius, 90);
        assert_eq!(cfg.hardware_probe.gpu_critical_celsius, 95);
    }

    #[test]
    fn sdr21_classify_below_warn_returns_ok() {
        let cfg = HardwareProbeConfig::default();
        assert_eq!(classify_thermal_reading(&cfg, "k10temp/Tctl", 60), "ok");
    }

    #[test]
    fn sdr21_classify_at_warn_returns_warn() {
        let cfg = HardwareProbeConfig::default();
        assert_eq!(classify_thermal_reading(&cfg, "k10temp/Tctl", 85), "warn");
        assert_eq!(classify_thermal_reading(&cfg, "k10temp/Tctl", 94), "warn");
    }

    #[test]
    fn sdr21_classify_at_critical_returns_critical() {
        let cfg = HardwareProbeConfig::default();
        assert_eq!(
            classify_thermal_reading(&cfg, "k10temp/Tctl", 95),
            "critical"
        );
        assert_eq!(
            classify_thermal_reading(&cfg, "k10temp/Tctl", 110),
            "critical"
        );
    }

    #[test]
    fn sdr21_classify_gpu_uses_gpu_threshold_when_set() {
        let cfg = HardwareProbeConfig {
            thermal_critical_celsius: 95,
            gpu_critical_celsius: 85,
            ..Default::default()
        };
        // CPU sensor: 90 → warn (under critical 95)
        assert_eq!(classify_thermal_reading(&cfg, "k10temp/Tctl", 90), "warn");
        // GPU sensor: 90 → critical (under default critical 95 but
        // over GPU-specific 85).
        assert_eq!(
            classify_thermal_reading(&cfg, "nvidia-gpu-0", 90),
            "critical"
        );
    }

    #[test]
    fn sdr21_classify_gpu_falls_back_when_override_zero() {
        let cfg = HardwareProbeConfig {
            thermal_critical_celsius: 95,
            gpu_critical_celsius: 0, // disabled
            ..Default::default()
        };
        assert_eq!(classify_thermal_reading(&cfg, "nvidia-gpu-0", 90), "warn");
        assert_eq!(
            classify_thermal_reading(&cfg, "nvidia-gpu-0", 95),
            "critical"
        );
    }

    #[test]
    fn sdr21_classify_handles_custom_thresholds() {
        let cfg = HardwareProbeConfig {
            thermal_warn_celsius: 50,
            thermal_critical_celsius: 70,
            ..Default::default()
        };
        assert_eq!(classify_thermal_reading(&cfg, "x", 49), "ok");
        assert_eq!(classify_thermal_reading(&cfg, "x", 50), "warn");
        assert_eq!(classify_thermal_reading(&cfg, "x", 69), "warn");
        assert_eq!(classify_thermal_reading(&cfg, "x", 70), "critical");
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

    // ----------------------------------------------------------------
    // SDD-013 regression-prevention tests
    // ----------------------------------------------------------------

    /// SDD-013 § 6: target defaults to Generic when the [deployment]
    /// block is absent. Existing operator configs must parse unchanged.
    #[test]
    fn sdd_013_target_defaults_to_generic_when_absent() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "").unwrap();
        let cfg = Config::load(Some(tmp.path())).unwrap();
        assert_eq!(cfg.deployment.target, DeploymentTarget::Generic);
    }

    /// SDD-013 § 6: explicit `target = "generic"` parses to Generic.
    #[test]
    fn sdd_013_target_parses_generic() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"
            [deployment]
            target = "generic"
            "#,
        )
        .unwrap();
        let cfg = Config::load(Some(tmp.path())).unwrap();
        assert_eq!(cfg.deployment.target, DeploymentTarget::Generic);
    }

    /// SDD-013 § 6: explicit `target = "sain01"` parses to Sain01.
    #[test]
    fn sdd_013_target_parses_sain01() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"
            [deployment]
            target = "sain01"
            "#,
        )
        .unwrap();
        let cfg = Config::load(Some(tmp.path())).unwrap();
        assert_eq!(cfg.deployment.target, DeploymentTarget::Sain01);
    }

    /// SDD-013 § Goals point 3: unknown values fail-loud at parse time.
    /// No silent fallback — operator typos become hard errors.
    #[test]
    fn sdd_013_target_rejects_unknown_value() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"
            [deployment]
            target = "bogus"
            "#,
        )
        .unwrap();
        let r = Config::load(Some(tmp.path()));
        assert!(r.is_err(), "unknown target value must fail-loud");
    }

    /// SDD-013 § 3: state_dir for Generic is FHS-standard.
    #[test]
    fn sdd_013_generic_target_uses_var_lib_selfdef() {
        assert_eq!(
            state_dir(DeploymentTarget::Generic),
            Path::new("/var/lib/selfdef")
        );
    }

    /// SDD-013 § 3: state_dir for SAIN-01 is the ZFS tank/context mount.
    #[test]
    fn sdd_013_sain01_target_uses_mnt_vault_context() {
        assert_eq!(
            state_dir(DeploymentTarget::Sain01),
            Path::new("/mnt/vault/context")
        );
    }

    /// SDD-013 § 3: audit_log_path threads through state_dir.
    #[test]
    fn sdd_013_audit_log_paths_match_target() {
        assert_eq!(
            audit_log_path(DeploymentTarget::Generic),
            PathBuf::from("/var/lib/selfdef/selfdef-audit.jsonl")
        );
        assert_eq!(
            audit_log_path(DeploymentTarget::Sain01),
            PathBuf::from("/mnt/vault/context/selfdef-audit.jsonl")
        );
    }

    /// SDD-013 § 3: escalations_path threads through state_dir.
    #[test]
    fn sdd_013_escalations_paths_match_target() {
        assert_eq!(
            escalations_path(DeploymentTarget::Generic),
            PathBuf::from("/var/lib/selfdef/selfdef-escalations.sqlite")
        );
        assert_eq!(
            escalations_path(DeploymentTarget::Sain01),
            PathBuf::from("/mnt/vault/context/selfdef-escalations.sqlite")
        );
    }

    /// SDD-014 wire: shared_audit_log_path returns Some only on SAIN-01.
    /// Generic deployments have no shared timeline (selfdef alone owns
    /// its audit log).
    #[test]
    fn sdd_013_shared_audit_log_is_sain01_only() {
        assert!(shared_audit_log_path(DeploymentTarget::Generic).is_none());
        assert_eq!(
            shared_audit_log_path(DeploymentTarget::Sain01),
            Some(PathBuf::from("/mnt/vault/context/security_audit.log"))
        );
    }

    /// DeploymentTarget round-trips through TOML serialize/deserialize
    /// (operator can write what they read; agent emitters round-trip).
    #[test]
    fn sdd_013_deployment_target_toml_roundtrip() {
        for t in [DeploymentTarget::Generic, DeploymentTarget::Sain01] {
            let cfg = Config {
                deployment: DeploymentConfig {
                    target: t,
                    ..DeploymentConfig::default()
                },
                ..Config::default()
            };
            let toml_str = toml::to_string(&cfg).unwrap();
            let parsed: Config = toml::from_str(&toml_str).unwrap();
            assert_eq!(parsed.deployment.target, t);
        }
    }

    /// SDD-013 ergonomics: as_str matches the TOML serialization form
    /// (operator tooling that prints the target uses one token).
    #[test]
    fn sdd_013_deployment_target_as_str_matches_serde() {
        assert_eq!(DeploymentTarget::Generic.as_str(), "generic");
        assert_eq!(DeploymentTarget::Sain01.as_str(), "sain01");
        assert_eq!(format!("{}", DeploymentTarget::Sain01), "sain01");
    }

    /// FromStr parses both the canonical tokens; unknown is rejected.
    #[test]
    fn sdd_013_deployment_target_from_str() {
        use std::str::FromStr;
        assert_eq!(
            DeploymentTarget::from_str("generic").unwrap(),
            DeploymentTarget::Generic
        );
        assert_eq!(
            DeploymentTarget::from_str("sain01").unwrap(),
            DeploymentTarget::Sain01
        );
        assert!(DeploymentTarget::from_str("bogus").is_err());
        assert!(DeploymentTarget::from_str("SAIN01").is_err()); // case-sensitive per serde rename_all
    }

    // ----------------------------------------------------------------
    // SDD-014 resolver tests
    // ----------------------------------------------------------------

    /// SDD-014 § 2: on Generic, channel never auto-enables.
    #[test]
    fn sdd_014_generic_target_does_not_auto_enable_shared_audit_summary() {
        let cfg = Config {
            deployment: DeploymentConfig {
                target: DeploymentTarget::Generic,
                ..DeploymentConfig::default()
            },
            ..Config::default()
        };
        assert!(!resolve_shared_audit_summary_enabled(&cfg));
    }

    /// SDD-014 § 2: on SAIN-01, channel auto-enables.
    #[test]
    fn sdd_014_sain01_target_auto_enables_shared_audit_summary() {
        let cfg = Config {
            deployment: DeploymentConfig {
                target: DeploymentTarget::Sain01,
                ..DeploymentConfig::default()
            },
            ..Config::default()
        };
        assert!(resolve_shared_audit_summary_enabled(&cfg));
    }

    /// SDD-014 § 2 + Q14-B: explicit `enabled = false` overrides
    /// the auto-enable on SAIN-01.
    #[test]
    fn sdd_014_explicit_disable_overrides_auto_enable_on_sain01() {
        let cfg = Config {
            deployment: DeploymentConfig {
                target: DeploymentTarget::Sain01,
                ..DeploymentConfig::default()
            },
            notifier: NotifierConfig {
                shared_audit_summary: SharedAuditSummaryConfig {
                    enabled: Some(false),
                    ..SharedAuditSummaryConfig::default()
                },
                ..NotifierConfig::default()
            },
            ..Config::default()
        };
        assert!(!resolve_shared_audit_summary_enabled(&cfg));
    }

    /// SDD-014 § 2: explicit `enabled = true` force-enables on Generic
    /// (operator override path — they get to opt-in to the shared log
    /// even on a generic deployment if they really want).
    #[test]
    fn sdd_014_explicit_enable_overrides_auto_disable_on_generic() {
        let cfg = Config {
            deployment: DeploymentConfig {
                target: DeploymentTarget::Generic,
                ..DeploymentConfig::default()
            },
            notifier: NotifierConfig {
                shared_audit_summary: SharedAuditSummaryConfig {
                    enabled: Some(true),
                    ..SharedAuditSummaryConfig::default()
                },
                ..NotifierConfig::default()
            },
            ..Config::default()
        };
        assert!(resolve_shared_audit_summary_enabled(&cfg));
    }

    /// SDD-014 § 2: path resolver — default routes to
    /// /mnt/vault/context on SAIN-01, None on Generic.
    #[test]
    fn sdd_014_path_resolution() {
        let g = Config::default();
        assert!(resolve_shared_audit_summary_path(&g).is_none());
        let s = Config {
            deployment: DeploymentConfig {
                target: DeploymentTarget::Sain01,
                ..DeploymentConfig::default()
            },
            ..Config::default()
        };
        assert_eq!(
            resolve_shared_audit_summary_path(&s),
            Some(PathBuf::from("/mnt/vault/context/security_audit.log"))
        );
    }

    /// SDD-014 § 2: operator-supplied path overrides the resolver.
    #[test]
    fn sdd_014_path_override_wins() {
        let cfg = Config {
            deployment: DeploymentConfig {
                target: DeploymentTarget::Generic,
                ..DeploymentConfig::default()
            },
            notifier: NotifierConfig {
                shared_audit_summary: SharedAuditSummaryConfig {
                    enabled: Some(true),
                    path: Some(PathBuf::from("/var/log/custom-shared.log")),
                    selfdef_audit_path: None,
                    ..SharedAuditSummaryConfig::default()
                },
                ..NotifierConfig::default()
            },
            ..Config::default()
        };
        assert_eq!(
            resolve_shared_audit_summary_path(&cfg),
            Some(PathBuf::from("/var/log/custom-shared.log"))
        );
    }

    /// SDD-014 § 2: selfdef-audit pointer override.
    #[test]
    fn sdd_014_pointer_override_wins() {
        let cfg = Config {
            deployment: DeploymentConfig {
                target: DeploymentTarget::Sain01,
                ..DeploymentConfig::default()
            },
            notifier: NotifierConfig {
                shared_audit_summary: SharedAuditSummaryConfig {
                    enabled: None,
                    path: None,
                    selfdef_audit_path: Some(PathBuf::from("/srv/audit.jsonl")),
                    ..SharedAuditSummaryConfig::default()
                },
                ..NotifierConfig::default()
            },
            ..Config::default()
        };
        assert_eq!(
            resolve_shared_audit_summary_pointer(&cfg),
            PathBuf::from("/srv/audit.jsonl")
        );
    }

    // ----------------------------------------------------------------
    // SDD-015 perimeter coexistence resolver tests
    // ----------------------------------------------------------------

    /// SDD-015 § 4: on Generic, check_overlap_on_apply auto-false.
    #[test]
    fn sdd_015_generic_target_check_overlap_off_by_default() {
        let cfg = Config::default();
        assert!(!resolve_perimeter_check_overlap(&cfg));
    }

    /// SDD-015 § 4: on SAIN-01, check_overlap_on_apply auto-true.
    #[test]
    fn sdd_015_sain01_target_check_overlap_on_by_default() {
        let cfg = Config {
            deployment: DeploymentConfig {
                target: DeploymentTarget::Sain01,
                ..DeploymentConfig::default()
            },
            ..Config::default()
        };
        assert!(resolve_perimeter_check_overlap(&cfg));
    }

    /// SDD-015 § 4: explicit Some(false) on SAIN-01 disables the check
    /// (operator opt-out path — e.g. they're maintaining the boundary
    /// by hand during migration).
    #[test]
    fn sdd_015_explicit_disable_overrides_auto_enable_on_sain01() {
        let cfg = Config {
            deployment: DeploymentConfig {
                target: DeploymentTarget::Sain01,
                ..DeploymentConfig::default()
            },
            perimeter: PerimeterConfig {
                check_overlap_on_apply: Some(false),
                ..PerimeterConfig::default()
            },
            ..Config::default()
        };
        assert!(!resolve_perimeter_check_overlap(&cfg));
    }

    /// SDD-015 § 4: explicit Some(true) on Generic enables the check
    /// (operator override path — e.g. multi-author Tetragon setup not
    /// involving sovereign-os).
    #[test]
    fn sdd_015_explicit_enable_overrides_auto_disable_on_generic() {
        let cfg = Config {
            perimeter: PerimeterConfig {
                check_overlap_on_apply: Some(true),
                ..PerimeterConfig::default()
            },
            ..Config::default()
        };
        assert!(resolve_perimeter_check_overlap(&cfg));
    }

    /// SDD-015 § 4: default perimeter paths point at the Tetragon
    /// stock load directory.
    #[test]
    fn sdd_015_default_perimeter_paths() {
        let p = PerimeterConfig::default();
        assert_eq!(
            p.policies_dir,
            PathBuf::from("/etc/tetragon/tracing-policies")
        );
        assert_eq!(
            p.sovereign_kernel_fence_path,
            PathBuf::from("/etc/tetragon/tracing-policies/sovereign-kernel-fence.yaml")
        );
        assert!(!p.overlap_warn_only);
        assert!(p.check_overlap_on_apply.is_none());
    }

    // ----------------------------------------------------------------
    // SDD-016 oracle-triage config tests
    // ----------------------------------------------------------------

    /// SDD-016 § 2 + Q-D verbatim: channel is OFF by default, even
    /// on SAIN-01. Opt-in is operator-explicit.
    #[test]
    fn sdd_016_oracle_triage_disabled_by_default() {
        let cfg = Config::default();
        assert!(!cfg.notifier.oracle_triage.enabled);
        let s = Config {
            deployment: DeploymentConfig {
                target: DeploymentTarget::Sain01,
                ..DeploymentConfig::default()
            },
            ..Config::default()
        };
        assert!(!s.notifier.oracle_triage.enabled);
    }

    /// SDD-016 § 2: default endpoint matches SDD-011 router.
    #[test]
    fn sdd_016_default_endpoint_matches_sdd_011_router() {
        let cfg = OracleTriageConfig::default();
        assert_eq!(cfg.endpoint, "http://127.0.0.1:8080");
        assert_eq!(cfg.model, "auto");
        assert_eq!(cfg.timeout_seconds, 30);
        assert!(cfg.api_key_env.is_none());
        assert_eq!(cfg.output_target, "operator-dashboard");
    }

    /// SDD-016 § 2: configured via TOML; round-trip.
    #[test]
    fn sdd_016_config_parses_from_toml() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"
            [notifier.oracle_triage]
            enabled = true
            endpoint = "http://10.0.100.50:8080"
            model = "auto"
            timeout_seconds = 45
            output_target = "both"

            [notifier.oracle_triage.filter]
            min_severity = "high"
            kinds = ["POLICY_VIOLATION", "CONN_ANOMALY"]
            "#,
        )
        .unwrap();
        let cfg = Config::load(Some(tmp.path())).unwrap();
        assert!(cfg.notifier.oracle_triage.enabled);
        assert_eq!(
            cfg.notifier.oracle_triage.endpoint,
            "http://10.0.100.50:8080"
        );
        assert_eq!(cfg.notifier.oracle_triage.timeout_seconds, 45);
        assert_eq!(cfg.notifier.oracle_triage.output_target, "both");
        assert_eq!(cfg.notifier.oracle_triage.filter.min_severity, "high");
        assert_eq!(
            cfg.notifier.oracle_triage.filter.kinds,
            vec!["POLICY_VIOLATION".to_owned(), "CONN_ANOMALY".to_owned()]
        );
    }

    /// F-2026-092: the responder autonomous-response severity floor defaults to
    /// `none` (no floor) and is overridable from `[responder] min_severity`.
    #[test]
    fn responder_min_severity_defaults_none_and_parses_from_toml() {
        // Default: no floor.
        assert_eq!(ResponderConfig::default().min_severity, "none");

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"
            [responder]
            dry_run = false
            allowed_actions = ["notify", "kill_pid"]
            min_severity = "high"
            "#,
        )
        .unwrap();
        let cfg = Config::load(Some(tmp.path())).unwrap();
        assert_eq!(cfg.responder.min_severity, "high");
        assert!(!cfg.responder.dry_run);
        // Unset fields still fall back to the struct default (serde(default)).
        assert_eq!(
            cfg.responder.snapshot_dir,
            ResponderConfig::default().snapshot_dir
        );
        // Security default: a config that does not mention act_on_federated
        // preserves prior cross-host-response behavior (true), never silently
        // failing closed on upgrade. (F-2026-111.)
        assert!(
            cfg.responder.act_on_federated,
            "act_on_federated must default true when omitted"
        );
    }

    #[test]
    fn responder_act_on_federated_defaults_true_and_parses_fail_closed() {
        // The default is the prior behavior (act on federated findings)...
        assert!(ResponderConfig::default().act_on_federated);

        // ...and an operator can explicitly fail closed. Locking this guards the
        // security knob against a serde-rename / default regression silently
        // flipping the federation trust boundary (F-2026-111).
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"
            [responder]
            act_on_federated = false
            "#,
        )
        .unwrap();
        let cfg = Config::load(Some(tmp.path())).unwrap();
        assert!(
            !cfg.responder.act_on_federated,
            "act_on_federated = false must parse to fail-closed"
        );
    }

    // ----------------------------------------------------------------
    // SD-R6 follow-up tests (Q14-C JSONL twin, Q15-D third-party,
    // Q16-D rate-limit)
    // ----------------------------------------------------------------

    /// SDD-014 Q14-C: jsonl_twin defaults to false (deferred per Q14-C
    /// recommendation; opt-in only).
    #[test]
    fn sdd_014_jsonl_twin_defaults_false() {
        let cfg = Config::default();
        assert!(!cfg.notifier.shared_audit_summary.jsonl_twin);
    }

    /// SDD-014 Q14-C: jsonl_twin opt-in via TOML.
    #[test]
    fn sdd_014_jsonl_twin_parses_from_toml() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"
            [notifier.shared_audit_summary]
            jsonl_twin = true
            jsonl_twin_path = "/var/log/custom.jsonl"
            "#,
        )
        .unwrap();
        let cfg = Config::load(Some(tmp.path())).unwrap();
        assert!(cfg.notifier.shared_audit_summary.jsonl_twin);
        assert_eq!(
            cfg.notifier.shared_audit_summary.jsonl_twin_path,
            Some(PathBuf::from("/var/log/custom.jsonl"))
        );
    }

    /// SDD-015 Q15-D: third_party_policy_stance defaults to "warn".
    #[test]
    fn sdd_015_third_party_stance_defaults_to_warn() {
        let p = PerimeterConfig::default();
        assert_eq!(p.third_party_policy_stance, "warn");
    }

    /// SDD-015 Q15-D: third_party_policy_stance accepts "warn",
    /// "ignore", "block" — operators express stricter postures
    /// without changing the default.
    #[test]
    fn sdd_015_third_party_stance_parses_from_toml() {
        for stance in ["warn", "ignore", "block"] {
            let tmp = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(
                tmp.path(),
                format!(
                    r#"
                    [perimeter]
                    third_party_policy_stance = "{stance}"
                    "#
                ),
            )
            .unwrap();
            let cfg = Config::load(Some(tmp.path())).unwrap();
            assert_eq!(cfg.perimeter.third_party_policy_stance, stance);
        }
    }

    /// SDD-016 Q16-D: max_events_per_hour defaults to 100.
    #[test]
    fn sdd_016_rate_limit_defaults_to_100() {
        let cfg = OracleTriageConfig::default();
        assert_eq!(cfg.max_events_per_hour, 100);
    }

    /// SDD-017 § 5: sain01_strict defaults to false (warn-only).
    #[test]
    fn sdd_017_sain01_strict_defaults_false() {
        let cfg = Config::default();
        assert!(!cfg.deployment.sain01_strict);
    }

    /// SDD-017 § 5: explicit sain01_strict=true parses.
    #[test]
    fn sdd_017_sain01_strict_parses_from_toml() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"
            [deployment]
            target = "sain01"
            sain01_strict = true
            "#,
        )
        .unwrap();
        let cfg = Config::load(Some(tmp.path())).unwrap();
        assert_eq!(cfg.deployment.target, DeploymentTarget::Sain01);
        assert!(cfg.deployment.sain01_strict);
    }

    /// SDD-017 § 6: hardware_metrics_path empty by default; opt-in
    /// via config.
    #[test]
    fn sdd_017_hardware_metrics_path_defaults_empty() {
        let cfg = Config::default();
        assert!(cfg.deployment.hardware_metrics_path.is_empty());
    }

    /// SDD-017 § 7 (SD-R10): hardware_capabilities_path defaults to empty.
    #[test]
    fn sdr10_hardware_capabilities_path_defaults_empty() {
        let cfg = Config::default();
        assert!(cfg.deployment.hardware_capabilities_path.is_empty());
    }

    /// SDD-017 § 7 (SD-R10): hardware_capabilities_path TOML parse.
    #[test]
    fn sdr10_hardware_capabilities_path_parses_from_toml() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"
            [deployment]
            hardware_capabilities_path = "/var/lib/selfdef/hardware-capabilities.json"
            "#,
        )
        .unwrap();
        let cfg = Config::load(Some(tmp.path())).unwrap();
        assert_eq!(
            cfg.deployment.hardware_capabilities_path,
            "/var/lib/selfdef/hardware-capabilities.json"
        );
    }

    /// M060 D-02: selfdef_mirror_dir defaults to empty (disabled).
    #[test]
    fn m060_selfdef_mirror_dir_defaults_empty() {
        let cfg = Config::default();
        assert!(cfg.deployment.selfdef_mirror_dir.is_empty());
    }

    /// M060 D-02: selfdef_mirror_dir TOML parse.
    #[test]
    fn m060_selfdef_mirror_dir_parses_from_toml() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"
            [deployment]
            selfdef_mirror_dir = "/run/sovereign-os/selfdef-mirror"
            "#,
        )
        .unwrap();
        let cfg = Config::load(Some(tmp.path())).unwrap();
        assert_eq!(
            cfg.deployment.selfdef_mirror_dir,
            "/run/sovereign-os/selfdef-mirror"
        );
    }

    #[test]
    fn sdd_017_hardware_metrics_path_parses_from_toml() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"
            [deployment]
            hardware_metrics_path = "/var/lib/node_exporter/textfile_collector/selfdef-hardware.prom"
            "#,
        )
        .unwrap();
        let cfg = Config::load(Some(tmp.path())).unwrap();
        assert_eq!(
            cfg.deployment.hardware_metrics_path,
            "/var/lib/node_exporter/textfile_collector/selfdef-hardware.prom"
        );
    }

    /// SDD-016 Q16-D: rate-limit configurable; 0 disables.
    #[test]
    fn sdd_016_rate_limit_parses_from_toml() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"
            [notifier.oracle_triage]
            max_events_per_hour = 0
            "#,
        )
        .unwrap();
        let cfg = Config::load(Some(tmp.path())).unwrap();
        assert_eq!(cfg.notifier.oracle_triage.max_events_per_hour, 0);
    }

    /// SDD-013 § Goals point 2 (zero regression): a fully-populated
    /// pre-SDD-013 config (without [deployment]) loads identically to
    /// before. Snapshot: the daemon paths reach the legacy Generic
    /// values; no field other than `cfg.deployment` is touched.
    #[test]
    fn sdd_013_legacy_config_parses_with_generic_target_only() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"
            [daemon]
            log_level = "debug"

            [api]
            enabled = true
            "#,
        )
        .unwrap();
        let cfg = Config::load(Some(tmp.path())).unwrap();
        assert_eq!(cfg.daemon.log_level, "debug");
        assert!(cfg.api.enabled);
        assert_eq!(cfg.deployment.target, DeploymentTarget::Generic);
        assert_eq!(
            state_dir(cfg.deployment.target),
            Path::new("/var/lib/selfdef")
        );
    }
}
