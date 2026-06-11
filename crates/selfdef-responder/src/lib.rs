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

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
    /// Hard ceiling on ONE action execution. Actions shell out to operator
    /// scripts (lockdown), `loginctl` wrappers, `journalctl`/`dmesg`
    /// (forensics) and the Velociraptor CLI (network) — any of which can
    /// wedge — and the dispatch loop awaits actions SEQUENTIALLY before the
    /// bus loop receives the next finding. Without a deadline, one hung
    /// subprocess stalls the ENTIRE autonomous-response engine while
    /// findings pile up (and eventually drop as bus lag). On expiry the
    /// action is logged as failed and dispatch continues; the action
    /// subprocesses are spawned `kill_on_drop`, so a timed-out future takes
    /// its child with it.
    action_deadline: Duration,
    /// Burst-dedup window for DESTRUCTIVE actions (decision-discipline, opt-in).
    /// When > 0, a destructive action whose `(name, event-target)` was already
    /// fired within this window is suppressed — guarding against a finding burst
    /// hammering the same kill/quarantine on the same target. Defaults to
    /// [`Duration::ZERO`] (disabled): the bare [`Responder::new`] behaves exactly
    /// as before. Enable with [`Responder::with_dedup_window`]. Notify / snapshot
    /// / forensic actions are never deduped — every alert and evidence capture is
    /// preserved.
    dedup_window: Duration,
    /// `(action.name | target-key)` -> last-fire instant, backing the dedup gate.
    /// Locked only synchronously (check + prune + insert), never across an
    /// `.await`. Pruned to in-window entries on each check, so it can't grow
    /// unbounded.
    recent_fires: Mutex<HashMap<String, Instant>>,
    /// Circuit-breaker: max DESTRUCTIVE actions dispatched per rolling 60s
    /// (decision-discipline, opt-in). When > 0, once this many destructive
    /// actions have fired in the last minute, further destructive actions are
    /// suppressed until the window drains — a guard against a poisoned / noisy
    /// event FLOOD (many distinct targets, which dedup can't catch) driving the
    /// IPS into mass destruction. Defaults to `0` (disabled). Enable with
    /// [`Responder::with_destructive_cap_per_min`]. Like dedup, only destructive
    /// actions count; notify/snapshot/forensic are never capped.
    destructive_cap_per_min: u32,
    /// Timestamps of recent destructive fires, backing the rate cap above.
    /// Synchronously locked (prune + count + push), never across an `.await`;
    /// pruned to the last 60s so it stays bounded.
    destructive_fire_log: Mutex<Vec<Instant>>,
    /// Optional cumulative counter of destructive actions SUPPRESSED by EITHER
    /// gate (dedup OR rate-cap). The daemon wires this to a `/metrics` counter
    /// (`selfdef_responder_suppressed_destructive_total`) — an aggregate
    /// "how much is being suppressed" signal for dashboards. `None` ⇒ not
    /// metered (e.g. in tests).
    suppressed_counter: Option<Arc<std::sync::atomic::AtomicU64>>,
    /// Optional cumulative counter of rate-cap circuit-breaker trips ONLY (the
    /// global flood breaker), distinct from routine per-target dedup. Wired to
    /// `selfdef_responder_ratecap_tripped_total`. This is the signal the
    /// `SelfdefResponderCircuitBreakerTripped` alert keys on: a non-zero rate
    /// means the daemon hit its destructive-action ceiling (a genuine flood),
    /// whereas dedup suppressing a duplicate finding is routine and must NOT
    /// raise a circuit-breaker alert. `None` ⇒ not metered.
    ratecap_tripped_counter: Option<Arc<std::sync::atomic::AtomicU64>>,

    /// Federation trust-boundary policy (F-2026-111). When `false`, a DESTRUCTIVE
    /// action is NOT auto-fired for a finding whose trigger came from another
    /// host via the NATS bridge (`event.federated`) — a compromised broker or
    /// peer can forge a finding carrying a local pid/user, so fail-closed refuses
    /// to act on remote-driven destructive triggers. Defaults to `true`
    /// (act-on-federated = the prior behavior; cross-host response preserved);
    /// set `false` to fail closed. Autonomous path only — operator `fire`/panic
    /// always acts. Notify/snapshot/forensic/escalation are never refused.
    act_on_federated: bool,
    /// Counter bumped when a destructive action is refused because its finding
    /// was federated-origin and `act_on_federated` is off. Distinct from the
    /// circuit-breaker counters — this is a trust-boundary refusal, not a flood.
    /// Wired to `selfdef_responder_federated_refused_total`.
    federated_refused_counter: Option<Arc<std::sync::atomic::AtomicU64>>,
}

/// Default per-action execution ceiling. Generous — a forensics bundle
/// legitimately takes seconds and a Velociraptor escalation tens of
/// seconds — while still bounding a wedged script to one minute instead of
/// forever.
pub const DEFAULT_ACTION_DEADLINE: Duration = Duration::from_secs(60);

/// Actions whose repeated firing on the SAME target within a short window is
/// always a wasteful duplicate (re-killing an already-killed pid, re-blocking an
/// already-blocked IP), never an intentional repeat — so they are eligible for
/// burst-dedup. Notify, snapshot, and forensic-bundle actions are intentionally
/// EXCLUDED: every alert and every evidence capture must be preserved.
/// Whether an action mutates target/host state (so the decision-discipline
/// circuit-breakers — burst-dedup + rate-cap — apply to it). Evidence/escalation
/// actions (`notify`, `snapshot_proc`, `forensics_bundle`, `velociraptor_escalate`)
/// are NOT destructive: every finding must produce its alert/evidence/escalation,
/// so they are never suppressed (same rationale as "notify is never deduped").
///
/// This is the single source of truth for destructiveness; it MUST stay complete
/// relative to the `Action` impls in [`actions`], because an unrecognized
/// destructive action silently escapes BOTH circuit-breakers (a finding burst
/// could then hammer it). The `action_name_classification_is_complete` unit test
/// gates drift: it fails if any known action name is left unclassified.
fn is_destructive_action(name: &str) -> bool {
    matches!(
        name,
        "kill_pid"
            | "lockdown_egress"
            | "revoke_session"
            | "block_ip"
            | "quarantine_process"
            | "session_revocation"
            | "api_token_revocation"
            | "mfa_grant_revocation"
            | "netns_isolation"
            | "mount_binding_unbind"
            | "process_tree_freeze"
            | "socket_fd_revocation"
            | "process_env_scrub"
            | "capability_drop"
            // Built effectors not yet wired into the daemon action vec, but
            // destructive — classified now so they cannot silently escape the
            // circuit-breakers if a future wiring registers them. Inert today
            // (the live gate only sees registered actions).
            | "kernel_keyring_eviction"  // revokes kernel keyring keys
            | "apparmor_profile_pivot"   // confines a process into a stricter MAC profile
            | "bpf_map_element_clear"    // wipes kernel BPF map state
    )
}

/// Stable per-event target signature for the dedup key: actor pid + source IP +
/// user. Two findings aimed at the same process / host / user collapse to the
/// same signature, so the same destructive action against that target is
/// deduped across a finding burst. Mirrors the per-action target extraction the
/// actions themselves use (`pid_from_event` / `source_ip_from_event` / user).
fn event_target_sig(event: &Event) -> String {
    let pid = event
        .actor
        .as_ref()
        .and_then(|a| a.process.as_ref())
        .map(|p| p.pid)
        .or_else(|| event.process.as_ref().map(|p| p.pid))
        .unwrap_or(0);
    let ip = event
        .src_endpoint
        .as_ref()
        .and_then(|e| e.ip)
        .map(|i| i.to_string())
        .unwrap_or_default();
    let user = event
        .actor
        .as_ref()
        .and_then(|a| a.user.as_ref())
        .and_then(|u| u.name.clone())
        .unwrap_or_default();
    format!("{pid}|{ip}|{user}")
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
            action_deadline: DEFAULT_ACTION_DEADLINE,
            // Disabled by default — no behavior change vs the pre-dedup
            // responder. Opt in with `with_dedup_window`.
            dedup_window: Duration::ZERO,
            recent_fires: Mutex::new(HashMap::new()),
            destructive_cap_per_min: 0,
            destructive_fire_log: Mutex::new(Vec::new()),
            suppressed_counter: None,
            ratecap_tripped_counter: None,
            // Default preserves prior behavior: federated findings DO drive
            // response. Operators opt into fail-closed via with_act_on_federated.
            act_on_federated: true,
            federated_refused_counter: None,
        }
    }

    /// Attach a cumulative counter bumped each time a destructive action is
    /// suppressed by the dedup or rate-cap gate. The daemon wires it to
    /// `selfdef_responder_suppressed_destructive_total`. Chainable.
    #[must_use]
    pub fn with_suppressed_counter(
        mut self,
        counter: Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        self.suppressed_counter = Some(counter);
        self
    }

    /// Set the counter bumped ONLY when the rate-cap circuit-breaker trips (the
    /// global flood breaker), as opposed to routine per-target dedup. The daemon
    /// wires it to `selfdef_responder_ratecap_tripped_total`, which the
    /// circuit-breaker alert keys on. Chainable.
    #[must_use]
    pub fn with_ratecap_counter(mut self, counter: Arc<std::sync::atomic::AtomicU64>) -> Self {
        self.ratecap_tripped_counter = Some(counter);
        self
    }

    /// Set the federation trust-boundary policy (F-2026-111). `true` (default)
    /// keeps prior behavior — federated-origin findings drive destructive
    /// response. `false` fails closed: destructive actions are refused for
    /// findings whose trigger arrived from another host via NATS. Chainable.
    #[must_use]
    pub fn with_act_on_federated(mut self, act: bool) -> Self {
        self.act_on_federated = act;
        self
    }

    /// Set the counter bumped when a destructive action is refused due to the
    /// federation trust boundary (`act_on_federated` off + a federated finding).
    /// Wired to `selfdef_responder_federated_refused_total`. Chainable.
    #[must_use]
    pub fn with_federated_refused_counter(
        mut self,
        counter: Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        self.federated_refused_counter = Some(counter);
        self
    }

    /// Enable destructive-action burst-dedup with the given window (opt-in;
    /// the default is disabled). A destructive action repeated on the same
    /// `(action, event-target)` within `window` is suppressed; notify / snapshot
    /// / forensic actions are never deduped. Builder-style.
    #[must_use]
    pub fn with_dedup_window(mut self, window: Duration) -> Self {
        self.dedup_window = window;
        self
    }

    /// Enable the destructive-action rate-cap circuit-breaker: at most `cap`
    /// destructive actions per rolling 60s (opt-in; `0` = disabled, the default).
    /// Once `cap` destructive actions have fired in the last minute, further
    /// destructive actions are suppressed until the window drains — a guard
    /// against an event FLOOD (many distinct targets) driving mass destruction.
    /// Notify/snapshot/forensic actions are never capped. Builder-style.
    #[must_use]
    pub fn with_destructive_cap_per_min(mut self, cap: u32) -> Self {
        self.destructive_cap_per_min = cap;
        self
    }

    /// Set the per-action execution ceiling ([`DEFAULT_ACTION_DEADLINE`]).
    /// Builder-style. Tests use a short value with a stalling stub action to
    /// lock the engine's no-hang contract.
    #[must_use]
    pub fn with_action_deadline(mut self, deadline: Duration) -> Self {
        self.action_deadline = deadline;
        self
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
    /// going through the bus. Used by `selfdefctl panic` — an operator-commanded
    /// emergency, so it bypasses the autonomous-only decision-discipline gates
    /// (dedup / rate-cap), exactly as it bypasses the severity floor: when the
    /// operator hits panic they want every allowed action to fire, not be
    /// throttled.
    pub async fn fire(&self, event: &Event) {
        self.handle_finding(event, false).await;
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
                let run = action.execute(event, self.dry_run);
                return Some(
                    match tokio::time::timeout(self.action_deadline, run).await {
                        Ok(result) => result,
                        Err(_) => Err(actions::ActionError::Exec(format!(
                            "action {name:?} timed out after {}s (deadline; child killed via kill_on_drop)",
                            self.action_deadline.as_secs_f64()
                        ))),
                    },
                );
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

    /// Allowlisted action names (`[responder].allowed_actions`) that match NO
    /// registered action — sorted, de-duplicated. The dispatch loop only runs an
    /// action whose name is in the allowlist, so such an entry is inert: almost
    /// always an operator typo (e.g. `kil_pid`) that silently means the intended
    /// response never fires on a real threat. A forward-compatible entry for an
    /// action not yet built would also appear here, so callers surface this as a
    /// warning rather than a hard error.
    #[must_use]
    pub fn unknown_allowed_actions(&self) -> Vec<String> {
        let known: HashSet<&str> = self.actions.iter().map(|a| a.name()).collect();
        let mut unknown: Vec<String> = self
            .allowed_actions
            .iter()
            .filter(|n| !known.contains(n.as_str()))
            .cloned()
            .collect();
        unknown.sort();
        unknown.dedup();
        unknown
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
                                // Bus path = autonomous: subject to the
                                // decision-discipline gates (dedup / rate-cap).
                                self.handle_finding(&event, true).await;
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

    /// `autonomous` = this dispatch came from the bus path (subject to the
    /// decision-discipline gates), vs an operator-commanded `fire`/panic (which
    /// bypasses them, like the severity floor).
    async fn handle_finding(&self, event: &Event, autonomous: bool) {
        debug!(event_id = %event.id, severity = %event.severity_id, "handling finding");

        for action in &self.actions {
            let name = action.name();
            if !self.allowed_actions.contains(name) {
                continue;
            }
            // Federation trust boundary (F-2026-111). When fail-closed
            // (`act_on_federated` off), refuse a DESTRUCTIVE action whose finding
            // came from another host via NATS — a compromised broker/peer could
            // forge a finding naming a local pid/user. Checked before the
            // circuit-breakers (a refused action need not consume dedup/cap
            // budget). Autonomous path only; non-destructive actions (alert /
            // evidence / escalation) are always delivered.
            //
            // EXCEPTION (option c): a finding whose triggering event carried a
            // valid signature from a CONFIGURED TRUSTED PEER (`federation_verified`)
            // is authenticated — it bypasses the fail-closed refusal and is acted
            // on like a local finding. Unverified (raw / forged / unknown-peer)
            // federated findings stay refused.
            if autonomous
                && !self.act_on_federated
                && event.federated
                && !event.federation_verified
                && is_destructive_action(name)
            {
                warn!(
                    action = name,
                    event_id = %event.id,
                    "refusing destructive action for a federated-origin finding \
                     ([responder].act_on_federated is off — fail-closed)"
                );
                if let Some(c) = &self.federated_refused_counter {
                    c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                continue;
            }
            // Burst-dedup gate (opt-in; disabled when dedup_window == 0, the
            // default). Suppress a DESTRUCTIVE action already fired on the same
            // target within the window — guards against a finding burst hammering
            // the same kill/quarantine. The lock is held only for the synchronous
            // prune + check, and dropped before the `.await` below.
            //
            // The record is committed only when the action SUCCEEDS (see the
            // dispatch match below), not optimistically here: a destructive
            // action that failed or timed out must stay retryable on the next
            // finding — otherwise a kill_pid that lost the race would be
            // dedup-suppressed forever within the window and the attacker process
            // would survive. The rate-cap below still counts the *attempt*, so a
            // permanently-failing action can't hammer unbounded.
            let mut dedup_key_to_record: Option<String> = None;
            if autonomous && !self.dedup_window.is_zero() && is_destructive_action(name) {
                let key = format!("{name}|{}", event_target_sig(event));
                let now = Instant::now();
                let mut recent = self
                    .recent_fires
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                // Prune expired entries so the map can't grow unbounded.
                recent.retain(|_, t| now.duration_since(*t) < self.dedup_window);
                if recent.contains_key(&key) {
                    debug!(
                        action = name,
                        target = %event_target_sig(event),
                        "suppressed duplicate destructive action within dedup window"
                    );
                    if let Some(c) = &self.suppressed_counter {
                        c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    continue;
                }
                drop(recent);
                // Defer the insert until the action actually succeeds.
                dedup_key_to_record = Some(key);
            }
            // Rate-cap circuit-breaker (opt-in; disabled when cap == 0). Once
            // `cap` destructive actions have fired in the last 60s, suppress
            // further destructive actions until the window drains — catches a
            // multi-target FLOOD that per-target dedup can't. Lock held only for
            // the synchronous prune + count + push, never across the `.await`.
            if autonomous && self.destructive_cap_per_min > 0 && is_destructive_action(name) {
                let now = Instant::now();
                let window = Duration::from_secs(60);
                let mut log = self
                    .destructive_fire_log
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                log.retain(|t| now.duration_since(*t) < window);
                if log.len() as u32 >= self.destructive_cap_per_min {
                    warn!(
                        action = name,
                        cap = self.destructive_cap_per_min,
                        "destructive-action rate cap reached (circuit breaker) — \
                         suppressing further destructive actions until the 60s window drains"
                    );
                    if let Some(c) = &self.suppressed_counter {
                        c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    // Distinct from dedup: only the rate-cap trip raises the
                    // circuit-breaker alert (a genuine flood), not a routine
                    // duplicate suppression.
                    if let Some(c) = &self.ratecap_tripped_counter {
                        c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    continue;
                }
                log.push(now);
                drop(log);
            }
            // Per-action deadline: actions run SEQUENTIALLY and this loop
            // sits between the bus and the next finding — one wedged
            // subprocess (operator lockdown script, loginctl, journalctl,
            // Velociraptor CLI) would otherwise stall the entire
            // autonomous-response engine forever. On expiry: log, move to
            // the NEXT action (same posture as an action error).
            let run = action.execute(event, self.dry_run);
            match tokio::time::timeout(self.action_deadline, run).await {
                Ok(Ok(outcome)) => match outcome.status {
                    actions::Status::Success => {
                        // Commit the dedup record now that the destructive
                        // action has actually fired — a later identical finding
                        // on the same target is suppressed within the window.
                        if let Some(key) = dedup_key_to_record {
                            self.recent_fires
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .insert(key, Instant::now());
                        }
                        info!(action = name, notes = outcome.notes, "action ran")
                    }
                    actions::Status::DryRun => {
                        info!(action = name, notes = outcome.notes, "DRY RUN")
                    }
                    actions::Status::Skipped => {
                        debug!(action = name, notes = outcome.notes, "action skipped")
                    }
                },
                Ok(Err(e)) => warn!(action = name, error = %e, "action failed"),
                Err(_) => error!(
                    action = name,
                    deadline_secs = self.action_deadline.as_secs_f64(),
                    "action timed out (deadline); continuing with remaining actions"
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_destructive_action;

    /// Anti-drift gate for the circuit-breaker coverage. Every `Action` impl's
    /// `name()` in `actions.rs` MUST appear here with its destructiveness, so a
    /// destructive action can never be added without a conscious classification
    /// — an unclassified destructive action would silently escape BOTH the
    /// burst-dedup and the rate-cap gate.
    ///
    /// To regenerate the name list after adding/removing an action:
    ///   grep -nA1 'fn name(&self)' crates/selfdef-responder/src/actions.rs
    /// Destructive = mutates target/host state. Non-destructive = produces an
    /// alert / evidence / external escalation that must never be suppressed.
    #[test]
    fn action_name_classification_is_complete() {
        // (name, expected_is_destructive)
        let known: &[(&str, bool)] = &[
            // --- destructive: subject to dedup + rate-cap ---
            ("kill_pid", true),
            ("lockdown_egress", true),
            ("revoke_session", true),
            ("block_ip", true),
            ("quarantine_process", true),
            ("session_revocation", true),
            ("api_token_revocation", true),
            ("mfa_grant_revocation", true),
            ("netns_isolation", true),
            ("mount_binding_unbind", true),
            ("process_tree_freeze", true),
            ("socket_fd_revocation", true),
            ("process_env_scrub", true),
            ("capability_drop", true),
            ("kernel_keyring_eviction", true),
            ("apparmor_profile_pivot", true),
            ("bpf_map_element_clear", true),
            // --- non-destructive: alert / evidence / escalation, never suppressed ---
            ("notify", false),
            ("snapshot_proc", false),
            ("forensics_bundle", false),
            ("velociraptor_escalate", false),
        ];
        for (name, expected) in known {
            assert_eq!(
                is_destructive_action(name),
                *expected,
                "classification drift for action {name:?}: a new/destructive action \
                 must be added to is_destructive_action (else it escapes the circuit-breakers)"
            );
        }
    }
}
