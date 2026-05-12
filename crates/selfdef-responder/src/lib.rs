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

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
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
}

impl std::fmt::Debug for Responder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Responder")
            .field("actions", &self.actions.iter().map(|a| a.name()).collect::<Vec<_>>())
            .field("allowed_actions", &self.allowed_actions)
            .field("dry_run", &self.dry_run)
            .finish()
    }
}

impl Responder {
    pub fn new(
        actions: Vec<Arc<dyn Action>>,
        allowed_actions: Vec<String>,
        dry_run: bool,
    ) -> Self {
        Self {
            actions,
            allowed_actions: allowed_actions.into_iter().collect(),
            dry_run,
        }
    }

    /// Direct-fire: dispatch all allowed actions for a single event without
    /// going through the bus. Used by `selfdefctl panic`.
    pub async fn fire(&self, event: &Event) {
        self.handle_finding(event).await;
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
                            self.handle_finding(&event).await;
                        }
                        Ok(_) => {}
                        Err(BusError::Lagged(n)) => warn!(missed = n, "responder lagged"),
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
