//! Correlator: subscribes to the bus, evaluates events against Sigma-style
//! rules, emits Detection Finding events back onto the bus.
//!
//! M5: the hardcoded `SshBruteforceRule` is gone. The engine loads YAML
//! rules from a directory and supports atomic hot reload (SIGHUP from the
//! daemon).

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
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

#[derive(Debug)]
pub struct Correlator {
    publisher: Publisher,
    host_tag: String,
    engine: Arc<RwLock<Arc<Engine>>>,
    rules_dir: PathBuf,
    sequence: AtomicU64,
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
        }
    }

    /// Load (or reload) rules from disk. Atomically swaps the engine on
    /// success; on failure leaves the previous rule set in place.
    pub fn load_rules(&self) -> Result<usize, SigmaError> {
        let new_engine = Arc::new(Engine::load_dir(&self.rules_dir)?);
        let count = new_engine.rule_count();
        let mut guard = self.engine.write().unwrap_or_else(|p| p.into_inner());
        *guard = new_engine;
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
