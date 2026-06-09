//! Action runner.
//!
//! M8: subscribes to the bus, watches for Findings events, dispatches each
//! to every configured [`Action`] whose name is in the allowlist. Actions
//! are independent; one failing doesn't stop the others.
//!
//! Built-in actions:
//! - [`actions::NotifyAction`] — sends to the configured [`Notifier`].
//! - [`actions::SnapshotProcAction`] — dumps `/proc/<pid>/...` to disk.
//! - [`actions::KillPidAction`] — `kill -TERM` on the actor pid.
//! - [`actions::LockdownEgressAction`] — invokes a configured shell script
//!   (typically `/usr/local/sbin/selfdef-lockdown.sh`). Operator owns the
//!   actual nftables logic.
//! - [`actions::RevokeSessionAction`] — invokes a configured script
//!   (typically wrapping `loginctl terminate-user`).
//! - [`actions::ForensicsBundleAction`] — writes a forensic bundle
//!   (event JSON, system metadata, dmesg, journalctl, /proc state) to a
//!   per-event directory under `forensics_dir`.
//! - [`actions::VelociraptorEscalateAction`] — invokes a configured
//!   Velociraptor CLI with templated args (`{event_id}`, `{host_tag}`),
//!   so an operator can plug in client-side artifact collection or
//!   server-side hunt creation without rebuilding selfdef.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

pub mod actions;

use std::collections::HashSet;
use std::sync::Arc;

use selfdef_bus::{BusError, Subscriber};
use selfdef_core::category::CategoryUid;
use selfdef_core::prelude::*;
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::actions::Action;

#[derive(Debug, Error)]
pub enum ResponderError {
    #[error("action error: {0}")]
    Action(#[from] actions::ActionError),
}

pub struct Responder {
    actions: Vec<Arc<dyn Action>>,
    allowed_actions: HashSet<String>,
    dry_run: bool,
    /// Autonomous-response severity floor (F-2026-092). Findings whose
    /// `severity_id` is strictly below this are not auto-dispatched on the bus
    /// path — a guard against destructive actions (e.g. `kill_pid`) firing on
    /// low-confidence findings. Defaults to [`SeverityId::Unknown`] (the lowest
    /// grade), so the bare [`Responder::new`] processes every finding exactly as
    /// before; raise it with [`Responder::with_min_severity`]. The floor gates
    /// only the autonomous bus path; [`Responder::dispatch_single`] (explicit,
    /// operator-authenticated) and [`Responder::fire`] are unaffected.
    min_severity: SeverityId,
    /// Optional cumulative counter of findings this responder missed because it
    /// lagged the broadcast bus. A lagging responder means findings were
    /// dropped before *any* action ran — a silent security-relevant failure (no
    /// notify / kill / quarantine fired) distinct from the metrics ingest task's
    /// lag. The daemon wires this to `selfdef_responder_lag_events_total` via
    /// [`Responder::with_lag_counter`]. `None` ⇒ not metered (e.g. in tests).
    lag_counter: Option<Arc<std::sync::atomic::AtomicU64>>,
}

impl std::fmt::Debug for Responder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Responder")
            .field(
                "actions",
                &self.actions.iter().map(|a| a.name()).collect::<Vec<_>>(),
            )
            .field("allowed_actions", &self.allowed_actions)
            .field("dry_run", &self.dry_run)
            .field("min_severity", &self.min_severity)
            .finish()
    }
}

impl Responder {
    pub fn new(actions: Vec<Arc<dyn Action>>, allowed_actions: Vec<String>, dry_run: bool) -> Self {
        Self {
            actions,
            allowed_actions: allowed_actions.into_iter().collect(),
            dry_run,
            // Lowest grade: every finding is processed, preserving the
            // pre-floor behavior for callers that don't opt in.
            min_severity: SeverityId::Unknown,
            lag_counter: None,
        }
    }

    /// Attach a cumulative lag counter (bumped by the missed-finding count each
    /// time the responder lags the bus). Chainable. The daemon wires this to
    /// `selfdef_responder_lag_events_total` so dropped-before-action findings
    /// become visible instead of living only in a warn log.
    #[must_use]
    pub fn with_lag_counter(mut self, counter: Arc<std::sync::atomic::AtomicU64>) -> Self {
        self.lag_counter = Some(counter);
        self
    }

    /// Set the autonomous-response severity floor (F-2026-092). Findings below
    /// `floor` are not auto-dispatched on the bus path. Builder-style; chain
    /// onto [`Responder::new`]. Example: `Responder::new(..).with_min_severity(
    /// SeverityId::High)` so only High/Critical/Fatal findings trigger
    /// autonomous actions.
    #[must_use]
    pub fn with_min_severity(mut self, floor: SeverityId) -> Self {
        self.min_severity = floor;
        self
    }

    /// Direct-fire: dispatch all allowed actions for a single event without
    /// going through the bus. Used by `selfdefctl panic`.
    pub async fn fire(&self, event: &Event) {
        self.handle_finding(event).await;
    }

    /// Run a single named action against the given event, bypassing the
    /// allowlist. Returns `None` if no action with that name is
    /// registered, or `Some(Err)` if the action errored. Used by the API
    /// `/actions/{name}/run` endpoint where the caller has already
    /// authenticated against the control token.
    pub async fn dispatch_single(
        &self,
        name: &str,
        event: &Event,
    ) -> Option<Result<actions::ActionOutcome, actions::ActionError>> {
        for action in &self.actions {
            if action.name() == name {
                return Some(action.execute(event, self.dry_run).await);
            }
        }
        None
    }

    /// Names of all built-in actions, in registration order. Useful for
    /// `/actions` discovery endpoints and audit logging.
    #[must_use]
    pub fn action_names(&self) -> Vec<&'static str> {
        self.actions.iter().map(|a| a.name()).collect()
    }

    /// Run until `shutdown` is cancelled.
    pub async fn run(&self, mut sub: Subscriber, shutdown: CancellationToken) {
        info!(
            dry_run = self.dry_run,
            actions = ?self.allowed_actions,
            available = ?self.actions.iter().map(|a| a.name()).collect::<Vec<_>>(),
            "responder starting"
        );
        loop {
            tokio::select! {
                () = shutdown.cancelled() => {
                    info!("responder shutting down");
                    return;
                }
                res = sub.recv() => {
                    match res {
                        Ok(event) if event.category_uid == CategoryUid::Findings => {
                            // F-2026-092: autonomous-response severity floor.
                            // Below the floor we do not auto-dispatch — keeps
                            // destructive actions (e.g. kill_pid) off low-
                            // confidence findings on the autonomous path. The
                            // default floor is `Unknown`, so this never trips
                            // unless a caller opted in via `with_min_severity`.
                            // Operator-commanded paths (`fire`, `dispatch_single`)
                            // deliberately bypass this gate.
                            if event.severity_id < self.min_severity {
                                debug!(
                                    event_id = %event.id,
                                    severity = %event.severity_id,
                                    floor = %self.min_severity,
                                    "finding below autonomous-response floor; not dispatching"
                                );
                            } else {
                                self.handle_finding(&event).await;
                            }
                        }
                        Ok(_) => {}
                        Err(BusError::Lagged(n)) => {
                            if let Some(c) = &self.lag_counter {
                                c.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                            }
                            warn!(missed = n, "responder lagged");
                        }
                        Err(BusError::Closed) => {
                            info!("responder: bus closed");
                            return;
                        }
                        Err(e) => error!(error = %e, "responder bus error"),
                    }
                }
            }
        }
    }

    async fn handle_finding(&self, event: &Event) {
        debug!(event_id = %event.id, severity = %event.severity_id, "handling finding");

        for action in &self.actions {
            let name = action.name();
            if !self.allowed_actions.contains(name) {
                continue;
            }
            match action.execute(event, self.dry_run).await {
                Ok(outcome) => match outcome.status {
                    actions::Status::Success => {
                        info!(action = name, notes = outcome.notes, "action ran")
                    }
                    actions::Status::DryRun => {
                        info!(action = name, notes = outcome.notes, "DRY RUN")
                    }
                    actions::Status::Skipped => {
                        debug!(action = name, notes = outcome.notes, "action skipped")
                    }
                },
                Err(e) => warn!(action = name, error = %e, "action failed"),
            }
        }
    }
}
