//! Correlator: subscribes to the bus, evaluates events against Sigma-style
//! rules, emits Detection Finding events back onto the bus.
//!
//! ## Surface highlights
//!
//! - **Rule loading**: [`Correlator::new`] returns a correlator
//!   pointing at a rules directory. [`Correlator::load_rules`]
//!   reads every `*.yml` file in the directory, compiles each to
//!   a [`CompiledRule`], and atomically swaps the in-memory
//!   engine. Failure keeps the previous rule set in place.
//! - **Hot reload via SIGHUP**: the daemon's SIGHUP handler calls
//!   [`Correlator::load_rules`] mid-flight. Rule files added,
//!   removed, or edited on disk take effect on the next reload.
//! - **Optional rule signing** (SDD-004): when constructed with
//!   [`Correlator::with_verifier`], every load refuses any rule
//!   file lacking a valid sibling `<file>.minisig` under the
//!   verifier's public key. Wired from
//!   `[security].require_signed_rules` in the daemon config.
//! - **Hot rotation of the signing key via SIGUSR2** (F-2027-005,
//!   PR #58): [`Correlator::reload_verifier`] re-reads the
//!   configured public-key file off disk without restarting the
//!   daemon. The daemon's SIGUSR2 handler fans out to
//!   `reload_verifier` plus an immediate `load_rules` so rules
//!   signed by a rotated key get picked up.
//! - **Operator introspection** (F-2027-021):
//!   [`Correlator::verifier_source`] returns the path the
//!   currently-loaded public key came from, for `selfdefctl
//!   doctor` / dashboards / "which `policy.pub` is the daemon
//!   trusting right now?" investigations.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

pub mod lint;
pub mod sigma;

pub use sigma::{AttackCoverage, CompiledRule, Engine, SigmaError, SigmaLevel};

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::AtomicU64;

use selfdef_bus::{BusError, Publisher, Subscriber};
use selfdef_core::category::CategoryUid;
use selfdef_core::prelude::*;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// F-2027-005: failure modes for `Correlator::reload_verifier`.
/// The two cases need to be distinguishable so the daemon's
/// SIGUSR2 handler can log "no verifier attached, ignoring"
/// without scaring the operator with a malformed-key message.
#[derive(Debug, thiserror::Error)]
pub enum ReloadVerifierError {
    #[error("no signing verifier is currently attached; verifier reload is a no-op")]
    NoVerifierConfigured,
    #[error("loading public key from {0}: {1}")]
    Load(PathBuf, selfdef_signing::SigningError),
}

#[derive(Debug)]
pub struct Correlator {
    publisher: Publisher,
    host_tag: String,
    engine: Arc<RwLock<Arc<Engine>>>,
    rules_dir: PathBuf,
    sequence: AtomicU64,
    /// SDD-004: optional minisign verifier. When present,
    /// `load_rules` calls `Engine::load_dir_verified` and refuses
    /// to compile any rule lacking a valid sibling `.minisig`.
    /// Wired from `[security].require_signed_rules` in the daemon.
    ///
    /// F-2027-005: wrapped in `Arc<RwLock<>>` so SIGUSR2 can
    /// re-load the public key off disk without restarting the
    /// daemon. The path the verifier was loaded from is read
    /// back from `Verifier::source()` to reload from the same
    /// place.
    verifier: Arc<RwLock<Option<selfdef_signing::Verifier>>>,
}

impl Correlator {
    #[must_use]
    pub fn new(publisher: Publisher, host_tag: String, rules_dir: PathBuf) -> Self {
        Self {
            publisher,
            host_tag,
            engine: Arc::new(RwLock::new(Arc::new(Engine::empty()))),
            rules_dir,
            sequence: AtomicU64::new(0),
            verifier: Arc::new(RwLock::new(None)),
        }
    }

    /// Attach a minisign verifier — every subsequent `load_rules`
    /// will refuse any rule file lacking a valid sibling
    /// `<file>.minisig` under this verifier's public key.
    /// Chainable.
    #[must_use]
    pub fn with_verifier(self, verifier: selfdef_signing::Verifier) -> Self {
        {
            let mut guard = self.verifier.write().unwrap_or_else(|p| p.into_inner());
            *guard = Some(verifier);
        }
        self
    }

    /// F-2027-005: re-load the configured signing public key off
    /// disk. Returns the absolute path the key was loaded from
    /// (so the caller can log it) or an error if no verifier was
    /// ever attached, or the on-disk file is now malformed.
    ///
    /// Re-loads from `Verifier::source()` — the same path the
    /// initial load used. Atomic: on parse failure the previous
    /// verifier stays in place, mirroring `load_rules`' failure
    /// semantics.
    pub fn reload_verifier(&self) -> Result<PathBuf, ReloadVerifierError> {
        let path = {
            let guard = self.verifier.read().unwrap_or_else(|p| p.into_inner());
            guard
                .as_ref()
                .ok_or(ReloadVerifierError::NoVerifierConfigured)?
                .source()
                .to_path_buf()
        };
        let fresh = selfdef_signing::Verifier::load(&path)
            .map_err(|e| ReloadVerifierError::Load(path.clone(), e))?;
        let mut guard = self.verifier.write().unwrap_or_else(|p| p.into_inner());
        *guard = Some(fresh);
        Ok(path)
    }

    /// F-2027-005: whether a verifier is currently attached.
    /// Used by the daemon's SIGUSR2 handler to decide whether to
    /// reload it.
    #[must_use]
    pub fn has_verifier(&self) -> bool {
        let guard = self.verifier.read().unwrap_or_else(|p| p.into_inner());
        guard.is_some()
    }

    /// F-2027-021: the absolute path the currently-loaded public
    /// key came from, or `None` if no verifier is attached
    /// (signing is opt-in). Used by `selfdefctl doctor` to
    /// surface "trusted policy.pub: …" in its signing category,
    /// and by `/status` dashboards.
    ///
    /// Returns an owned `PathBuf` because the verifier may be
    /// hot-rotated under the read lock — callers can't hold a
    /// reference to the inner path across awaits.
    #[must_use]
    pub fn verifier_source(&self) -> Option<PathBuf> {
        let guard = self.verifier.read().unwrap_or_else(|p| p.into_inner());
        guard.as_ref().map(|v| v.source().to_path_buf())
    }

    /// Load (or reload) rules from disk. Atomically swaps the engine on
    /// success; on failure leaves the previous rule set in place.
    ///
    /// F-2027-020: when a verifier is attached, logs the public-key
    /// path the rules were verified against at `info`. Operators
    /// who SIGUSR2-rotate the key (F-2027-005) use this log line to
    /// confirm the swap actually picked up the new key.
    pub fn load_rules(&self) -> Result<usize, SigmaError> {
        let (new_engine, verifier_key) = {
            let guard = self.verifier.read().unwrap_or_else(|p| p.into_inner());
            match guard.as_ref() {
                Some(v) => (
                    Engine::load_dir_verified(&self.rules_dir, v)?,
                    Some(v.source().to_path_buf()),
                ),
                None => (Engine::load_dir(&self.rules_dir)?, None),
            }
        };
        let new_engine = Arc::new(new_engine);
        let count = new_engine.rule_count();
        let mut guard = self.engine.write().unwrap_or_else(|p| p.into_inner());
        *guard = new_engine;
        if let Some(key) = verifier_key {
            info!(
                rules = count,
                verifier_key = %key.display(),
                "rules loaded under signing verifier"
            );
        }
        Ok(count)
    }

    /// Number of currently-loaded rules.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        let guard = self.engine.read().unwrap_or_else(|p| p.into_inner());
        guard.rule_count()
    }

    /// Run until `shutdown` is cancelled.
    pub async fn run(&self, mut sub: Subscriber, shutdown: CancellationToken) {
        info!(
            rules_dir = %self.rules_dir.display(),
            rule_count = self.rule_count(),
            "correlator starting"
        );
        loop {
            tokio::select! {
                () = shutdown.cancelled() => {
                    info!("correlator shutting down");
                    return;
                }
                res = sub.recv() => {
                    match res {
                        Ok(event) => self.process(&event),
                        Err(BusError::Lagged(n)) => warn!(missed = n, "correlator lagged"),
                        Err(BusError::Closed) => {
                            info!("correlator: bus closed");
                            return;
                        }
                        Err(e) => error!(error = %e, "correlator bus error"),
                    }
                }
            }
        }
    }

    fn process(&self, event: &Event) {
        // Never reprocess findings — would loop.
        if event.category_uid == CategoryUid::Findings {
            return;
        }
        let engine = {
            let guard = self.engine.read().unwrap_or_else(|p| p.into_inner());
            Arc::clone(&guard)
        };
        for finding in engine.process(event, &self.host_tag, &self.sequence) {
            if let Err(e) = self.publisher.publish(finding) {
                warn!(error = %e, "finding publish failed");
            }
        }
    }
}
