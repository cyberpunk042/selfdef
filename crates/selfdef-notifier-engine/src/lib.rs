//! Persistent escalation engine for the SDD-008 notifier orchestrator.
//!
//! D-5a (this crate, first ship): SQLite-backed persistence layer +
//! enqueue / record_ack / take_due / next_pending_at / close_event
//! APIs. The wake task (loop on next_pending_at, fan out to
//! channels, advance to next rung on timeout) lands in D-5b together
//! with the NotifierChain integration.
//!
//! This crate is deliberately kept separate from the trait crate
//! [`selfdef_notifier_orchestrator`] so the per-service integration
//! crates (`selfdef-integration-ntfy`, `-signal`, `-smtp`, `-twilio`)
//! don't transitively pull rusqlite. Integrations stay slim;
//! persistence is the daemon's concern.
//!
//! ## Schema
//!
//! ```sql
//! CREATE TABLE notification_escalations (
//!     event_id    TEXT PRIMARY KEY,    -- uuid string; one row per
//!                                      --   originating Event.
//!     payload_id  TEXT NOT NULL,       -- uuid string; per-attempt id.
//!     title       TEXT NOT NULL,
//!     body        TEXT NOT NULL,
//!     severity    INTEGER NOT NULL,    -- SeverityId as u32.
//!     ack_link    TEXT NULL,
//!     rung_index  INTEGER NOT NULL DEFAULT 0,
//!     deadline_at INTEGER NOT NULL,    -- unix seconds.
//!     acked_at    INTEGER NULL,        -- unix seconds; NULL = pending.
//!     created_at  INTEGER NOT NULL
//! );
//! CREATE INDEX idx_escalations_deadline
//!   ON notification_escalations(deadline_at)
//!   WHERE acked_at IS NULL;
//! ```
//!
//! Daemon-restart safety: every API method is one SQLite transaction;
//! crash mid-call leaves the DB consistent. The wake task (D-5b) does
//! a startup pass over `take_due(now, large_limit)` to resume any
//! escalations that were due during the downtime.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

mod dispatcher;
pub mod wake_task;
pub use dispatcher::{DispatchOutcome, Mode, PayloadDispatcher};

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use selfdef_notifier_orchestrator::{EventId, Payload, PayloadId, SeverityId};
use thiserror::Error;
use tracing::{debug, info};
use uuid::Uuid;

/// Errors from the escalation engine.
#[derive(Debug, Error)]
pub enum EngineError {
    /// rusqlite-level error.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Tokio join error from a spawn_blocking task.
    #[error("blocking task join error: {0}")]
    Join(#[from] tokio::task::JoinError),
    /// Filesystem error opening the database.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// `Payload::event_id` was `None`. Only events with a stable id
    /// can be persisted (escalation rows are keyed by event_id).
    #[error("cannot enqueue payload without an event_id")]
    PayloadMissingEventId,
    /// SQLite returned a severity id that doesn't map to a known
    /// [`SeverityId`] variant. Indicates schema corruption or a
    /// rogue writer.
    #[error("unknown severity id in row: {0}")]
    UnknownSeverity(u32),
    /// Schema migration tripped over a user_version higher than the
    /// engine knows how to migrate. Refuse to clobber.
    #[error("escalation schema at version {found} > engine support {supported}")]
    SchemaTooNew { found: u32, supported: u32 },
}

/// One pending escalation row, materialised from the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEscalation {
    /// Event the escalation tracks.
    pub event_id: EventId,
    /// Per-attempt id from the originating [`Payload`].
    pub payload_id: PayloadId,
    /// Pre-rendered notification title.
    pub title: String,
    /// Pre-rendered notification body.
    pub body: String,
    /// Severity of the underlying event.
    pub severity: SeverityId,
    /// Optional ack-link the orchestrator embedded in the payload.
    pub ack_link: Option<String>,
    /// Which rung this row is currently on. 0 = first rung.
    pub rung_index: u32,
    /// Unix seconds when this rung's ack window expires.
    pub deadline_at: i64,
}

/// The schema version this crate writes. Bumped whenever a schema
/// migration ships.
pub const SCHEMA_VERSION: u32 = 1;

/// Persistent escalation engine backed by SQLite.
pub struct EscalationEngine {
    conn: Arc<Mutex<Connection>>,
    path: PathBuf,
}

impl std::fmt::Debug for EscalationEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EscalationEngine")
            .field("path", &self.path)
            .field("schema_version", &SCHEMA_VERSION)
            .finish()
    }
}

impl EscalationEngine {
    /// Open (or create) an engine at `path`. Runs schema migrations
    /// on open; production-friendly pragmas (WAL, NORMAL sync, 5s
    /// busy timeout) match `selfdef-store`'s posture.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EngineError> {
        let path = path.as_ref().to_path_buf();
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
        {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "busy_timeout", 5_000_i64)?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        Self::migrate(&conn)?;
        info!(
            path = %path.display(),
            schema = SCHEMA_VERSION,
            "escalation engine opened",
        );
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            path,
        })
    }

    fn migrate(conn: &Connection) -> Result<(), EngineError> {
        let current: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if current > SCHEMA_VERSION {
            return Err(EngineError::SchemaTooNew {
                found: current,
                supported: SCHEMA_VERSION,
            });
        }
        if current < 1 {
            conn.execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS notification_escalations (
                    event_id    TEXT PRIMARY KEY,
                    payload_id  TEXT NOT NULL,
                    title       TEXT NOT NULL,
                    body        TEXT NOT NULL,
                    severity    INTEGER NOT NULL,
                    ack_link    TEXT NULL,
                    rung_index  INTEGER NOT NULL DEFAULT 0,
                    deadline_at INTEGER NOT NULL,
                    acked_at    INTEGER NULL,
                    created_at  INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_escalations_deadline
                  ON notification_escalations(deadline_at)
                  WHERE acked_at IS NULL;
                "#,
            )?;
            conn.pragma_update(None, "user_version", 1_i64)?;
            debug!("escalation schema migrated to v1");
        }
        Ok(())
    }

    /// Path the engine is backed by. Test-friendly accessor.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Enqueue a new escalation row. `payload.event_id` MUST be
    /// `Some`; the persistence schema is keyed by event id.
    ///
    /// Returns `Ok(())` on success, or `EngineError::PayloadMissingEventId`
    /// if the payload carries no event id. Idempotent against retries
    /// for the same event_id — the row is `INSERT OR REPLACE`d.
    pub async fn enqueue(
        &self,
        payload: &Payload,
        deadline_at: i64,
        now: i64,
    ) -> Result<(), EngineError> {
        let event_id = payload.event_id.ok_or(EngineError::PayloadMissingEventId)?;
        let row = StoredRow {
            event_id: event_id.0.to_string(),
            payload_id: payload.id.0.to_string(),
            title: payload.title.clone(),
            body: payload.body.clone(),
            severity: payload.severity as u32,
            ack_link: payload.ack_link.clone(),
            deadline_at,
            created_at: now,
        };
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> Result<(), EngineError> {
            let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
            guard.execute(
                r#"
                INSERT INTO notification_escalations (
                    event_id, payload_id, title, body, severity, ack_link,
                    rung_index, deadline_at, acked_at, created_at
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, NULL, ?8)
                ON CONFLICT(event_id) DO UPDATE SET
                    payload_id  = excluded.payload_id,
                    title       = excluded.title,
                    body        = excluded.body,
                    severity    = excluded.severity,
                    ack_link    = excluded.ack_link,
                    rung_index  = 0,
                    deadline_at = excluded.deadline_at,
                    acked_at    = NULL
                "#,
                params![
                    row.event_id,
                    row.payload_id,
                    row.title,
                    row.body,
                    row.severity,
                    row.ack_link,
                    row.deadline_at,
                    row.created_at,
                ],
            )?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    /// Mark an escalation as acked. Returns `Ok(true)` if a row was
    /// updated, `Ok(false)` if the event was unknown or already
    /// acked. Idempotent.
    pub async fn record_ack(&self, event_id: EventId, acked_at: i64) -> Result<bool, EngineError> {
        let event_id = event_id.0.to_string();
        let conn = Arc::clone(&self.conn);
        let changed = tokio::task::spawn_blocking(move || -> Result<usize, EngineError> {
            let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
            Ok(guard.execute(
                "UPDATE notification_escalations
                   SET acked_at = ?1
                 WHERE event_id = ?2 AND acked_at IS NULL",
                params![acked_at, event_id],
            )?)
        })
        .await??;
        Ok(changed > 0)
    }

    /// Mark an event closed: remove the row entirely. Useful when
    /// the operator dismisses without acknowledging (e.g. via a CLI
    /// `selfdefctl notify forget <event_id>` verb).
    pub async fn close_event(&self, event_id: EventId) -> Result<bool, EngineError> {
        let event_id = event_id.0.to_string();
        let conn = Arc::clone(&self.conn);
        let changed = tokio::task::spawn_blocking(move || -> Result<usize, EngineError> {
            let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
            Ok(guard.execute(
                "DELETE FROM notification_escalations WHERE event_id = ?1",
                params![event_id],
            )?)
        })
        .await??;
        Ok(changed > 0)
    }

    /// Advance a row to the next escalation rung. Sets
    /// `rung_index = new_rung` and `deadline_at = new_deadline` for
    /// the row keyed by `event_id`, ONLY when `acked_at IS NULL` (an
    /// operator ack that lands between `take_due` and `advance_rung`
    /// must short-circuit further escalation). Returns `Ok(true)` if
    /// a row was advanced, `Ok(false)` if the event was unknown,
    /// already acked, or already past `new_rung`.
    pub async fn advance_rung(
        &self,
        event_id: EventId,
        new_rung: u32,
        new_deadline: i64,
    ) -> Result<bool, EngineError> {
        let event_id = event_id.0.to_string();
        let conn = Arc::clone(&self.conn);
        let changed = tokio::task::spawn_blocking(move || -> Result<usize, EngineError> {
            let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
            Ok(guard.execute(
                "UPDATE notification_escalations
                   SET rung_index = ?1, deadline_at = ?2
                 WHERE event_id = ?3 AND acked_at IS NULL AND rung_index < ?1",
                params![new_rung, new_deadline, event_id],
            )?)
        })
        .await??;
        Ok(changed > 0)
    }

    /// Earliest pending-row deadline (unix seconds), or `None` if
    /// the engine has no pending rows. The wake task (D-5b) uses
    /// this to schedule itself.
    pub async fn next_pending_at(&self) -> Result<Option<i64>, EngineError> {
        let conn = Arc::clone(&self.conn);
        let next = tokio::task::spawn_blocking(move || -> Result<Option<i64>, EngineError> {
            let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
            let result: Option<i64> = guard
                .query_row(
                    "SELECT MIN(deadline_at) FROM notification_escalations
                      WHERE acked_at IS NULL",
                    [],
                    |row| row.get(0),
                )
                .optional()?
                .flatten();
            Ok(result)
        })
        .await??;
        Ok(next)
    }

    /// Pull up to `limit` rows whose `deadline_at <= now` and that
    /// are not yet acked. Returned in deadline-ascending order so
    /// the wake task processes oldest-due first.
    pub async fn take_due(
        &self,
        now: i64,
        limit: usize,
    ) -> Result<Vec<PendingEscalation>, EngineError> {
        let conn = Arc::clone(&self.conn);
        let rows =
            tokio::task::spawn_blocking(move || -> Result<Vec<PendingEscalation>, EngineError> {
                let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                let mut stmt = guard.prepare(
                    "SELECT event_id, payload_id, title, body, severity, ack_link, \
                            rung_index, deadline_at
                     FROM notification_escalations
                     WHERE acked_at IS NULL AND deadline_at <= ?1
                     ORDER BY deadline_at ASC
                     LIMIT ?2",
                )?;
                let mapped = stmt
                    .query_map(params![now, limit as i64], |row| {
                        let event_id: String = row.get(0)?;
                        let payload_id: String = row.get(1)?;
                        let title: String = row.get(2)?;
                        let body: String = row.get(3)?;
                        let severity: u32 = row.get(4)?;
                        let ack_link: Option<String> = row.get(5)?;
                        let rung_index: u32 = row.get(6)?;
                        let deadline_at: i64 = row.get(7)?;
                        Ok((
                            event_id,
                            payload_id,
                            title,
                            body,
                            severity,
                            ack_link,
                            rung_index,
                            deadline_at,
                        ))
                    })?
                    .collect::<Result<Vec<_>, rusqlite::Error>>()?;
                let mut out = Vec::with_capacity(mapped.len());
                for (eid, pid, title, body, sev, ack, rung, deadline) in mapped {
                    let event_id = parse_uuid(&eid).map(EventId)?;
                    let payload_id = parse_uuid(&pid).map(PayloadId)?;
                    let severity = severity_from_u32(sev)?;
                    out.push(PendingEscalation {
                        event_id,
                        payload_id,
                        title,
                        body,
                        severity,
                        ack_link: ack,
                        rung_index: rung,
                        deadline_at: deadline,
                    });
                }
                Ok(out)
            })
            .await??;
        Ok(rows)
    }

    /// Test/diagnostic helper: count rows in the engine (all states).
    pub async fn row_count(&self) -> Result<i64, EngineError> {
        let conn = Arc::clone(&self.conn);
        let n = tokio::task::spawn_blocking(move || -> Result<i64, EngineError> {
            let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
            Ok(
                guard.query_row("SELECT COUNT(*) FROM notification_escalations", [], |row| {
                    row.get(0)
                })?,
            )
        })
        .await??;
        Ok(n)
    }
}

/// Internal row shape used by enqueue; not exposed.
struct StoredRow {
    event_id: String,
    payload_id: String,
    title: String,
    body: String,
    severity: u32,
    ack_link: Option<String>,
    deadline_at: i64,
    created_at: i64,
}

fn parse_uuid(s: &str) -> Result<Uuid, rusqlite::Error> {
    Uuid::parse_str(s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn severity_from_u32(v: u32) -> Result<SeverityId, EngineError> {
    match v {
        0 => Ok(SeverityId::Unknown),
        1 => Ok(SeverityId::Informational),
        2 => Ok(SeverityId::Low),
        3 => Ok(SeverityId::Medium),
        4 => Ok(SeverityId::High),
        5 => Ok(SeverityId::Critical),
        6 => Ok(SeverityId::Fatal),
        99 => Ok(SeverityId::Other),
        n => Err(EngineError::UnknownSeverity(n)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_payload(title: &str, severity: SeverityId) -> Payload {
        Payload {
            id: PayloadId::new(),
            event_id: Some(EventId::from(Uuid::now_v7())),
            title: title.to_owned(),
            body: format!("body for {title}"),
            severity,
            ack_link: Some(format!("https://selfdef.example/ack/{title}")),
        }
    }

    async fn fresh_engine() -> (EscalationEngine, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("escalations.sqlite");
        let eng = EscalationEngine::open(&path).expect("open");
        (eng, dir)
    }

    #[tokio::test]
    async fn open_creates_empty_engine() {
        let (eng, _dir) = fresh_engine().await;
        assert_eq!(eng.row_count().await.unwrap(), 0);
        assert!(eng.next_pending_at().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn enqueue_then_take_due_returns_row() {
        let (eng, _dir) = fresh_engine().await;
        let p = mk_payload("alert-1", SeverityId::High);
        let event_id = p.event_id.unwrap();
        eng.enqueue(&p, 100, 0).await.expect("enqueue");
        assert_eq!(eng.row_count().await.unwrap(), 1);

        // not yet due
        let due = eng.take_due(99, 10).await.expect("take_due");
        assert!(due.is_empty(), "should not yet be due: {due:?}");

        // due at the boundary
        let due = eng.take_due(100, 10).await.expect("take_due");
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].event_id, event_id);
        assert_eq!(due[0].title, "alert-1");
        assert_eq!(due[0].severity, SeverityId::High);
        assert_eq!(due[0].rung_index, 0);
    }

    #[tokio::test]
    async fn record_ack_short_circuits_take_due() {
        let (eng, _dir) = fresh_engine().await;
        let p = mk_payload("alert-acked", SeverityId::Critical);
        let event_id = p.event_id.unwrap();
        eng.enqueue(&p, 100, 0).await.expect("enqueue");

        let acked = eng.record_ack(event_id, 50).await.expect("ack");
        assert!(acked, "first ack should report changed=true");

        // even past deadline, no row comes out
        let due = eng.take_due(200, 10).await.expect("take_due");
        assert!(due.is_empty(), "acked row should not be due: {due:?}");

        // second ack is a no-op
        let acked_again = eng.record_ack(event_id, 60).await.expect("re-ack");
        assert!(!acked_again, "second ack should report changed=false");
    }

    #[tokio::test]
    async fn record_ack_unknown_event_is_noop() {
        let (eng, _dir) = fresh_engine().await;
        let fake = EventId::from(Uuid::now_v7());
        let changed = eng.record_ack(fake, 100).await.expect("ack");
        assert!(!changed);
    }

    #[tokio::test]
    async fn take_due_returns_rows_in_deadline_order() {
        let (eng, _dir) = fresh_engine().await;
        let p1 = mk_payload("late", SeverityId::High);
        let p2 = mk_payload("early", SeverityId::High);
        let p3 = mk_payload("middle", SeverityId::High);
        eng.enqueue(&p1, 300, 0).await.unwrap();
        eng.enqueue(&p2, 100, 0).await.unwrap();
        eng.enqueue(&p3, 200, 0).await.unwrap();

        let due = eng.take_due(1_000, 10).await.expect("take_due");
        assert_eq!(due.len(), 3);
        assert_eq!(due[0].title, "early");
        assert_eq!(due[1].title, "middle");
        assert_eq!(due[2].title, "late");
    }

    #[tokio::test]
    async fn take_due_respects_limit() {
        let (eng, _dir) = fresh_engine().await;
        for i in 0..5 {
            let p = mk_payload(&format!("a-{i}"), SeverityId::High);
            eng.enqueue(&p, i64::from(i), 0).await.unwrap();
        }
        let due = eng.take_due(1_000, 2).await.expect("take_due");
        assert_eq!(due.len(), 2);
    }

    #[tokio::test]
    async fn next_pending_at_returns_earliest() {
        let (eng, _dir) = fresh_engine().await;
        let p1 = mk_payload("a", SeverityId::High);
        let p2 = mk_payload("b", SeverityId::High);
        eng.enqueue(&p1, 500, 0).await.unwrap();
        eng.enqueue(&p2, 200, 0).await.unwrap();
        assert_eq!(eng.next_pending_at().await.unwrap(), Some(200));
    }

    #[tokio::test]
    async fn next_pending_at_ignores_acked_rows() {
        let (eng, _dir) = fresh_engine().await;
        let p = mk_payload("a", SeverityId::High);
        let eid = p.event_id.unwrap();
        eng.enqueue(&p, 200, 0).await.unwrap();
        eng.record_ack(eid, 50).await.unwrap();
        assert!(eng.next_pending_at().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn close_event_removes_row() {
        let (eng, _dir) = fresh_engine().await;
        let p = mk_payload("a", SeverityId::High);
        let eid = p.event_id.unwrap();
        eng.enqueue(&p, 200, 0).await.unwrap();
        assert_eq!(eng.row_count().await.unwrap(), 1);

        let removed = eng.close_event(eid).await.unwrap();
        assert!(removed);
        assert_eq!(eng.row_count().await.unwrap(), 0);

        // idempotent
        let removed_again = eng.close_event(eid).await.unwrap();
        assert!(!removed_again);
    }

    #[tokio::test]
    async fn payload_missing_event_id_is_rejected() {
        let (eng, _dir) = fresh_engine().await;
        let p = Payload {
            id: PayloadId::new(),
            event_id: None,
            title: "no-id".into(),
            body: "no-id".into(),
            severity: SeverityId::High,
            ack_link: None,
        };
        let err = eng.enqueue(&p, 100, 0).await.expect_err("must reject");
        assert!(matches!(err, EngineError::PayloadMissingEventId));
    }

    #[tokio::test]
    async fn persistence_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("escalations.sqlite");
        let event_id;
        {
            let eng = EscalationEngine::open(&path).expect("open 1");
            let p = mk_payload("survives", SeverityId::Critical);
            event_id = p.event_id.unwrap();
            eng.enqueue(&p, 999, 0).await.unwrap();
        } // drop closes the connection
        let eng = EscalationEngine::open(&path).expect("open 2");
        assert_eq!(eng.row_count().await.unwrap(), 1);
        let due = eng.take_due(1_000, 10).await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].event_id, event_id);
        assert_eq!(due[0].title, "survives");
        assert_eq!(due[0].severity, SeverityId::Critical);
    }

    #[tokio::test]
    async fn enqueue_is_idempotent_per_event_id() {
        let (eng, _dir) = fresh_engine().await;
        let mut p = mk_payload("idem", SeverityId::High);
        eng.enqueue(&p, 100, 0).await.unwrap();
        // Mutate the payload's title + bump the deadline; re-enqueue
        // for the same event_id must REPLACE in place, not duplicate.
        p.title = "idem-v2".into();
        eng.enqueue(&p, 200, 1).await.unwrap();
        assert_eq!(eng.row_count().await.unwrap(), 1);
        let due = eng.take_due(1_000, 10).await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].title, "idem-v2");
        assert_eq!(due[0].deadline_at, 200);
    }

    #[tokio::test]
    async fn advance_rung_updates_index_and_deadline() {
        let (eng, _dir) = fresh_engine().await;
        let p = mk_payload("rung", SeverityId::High);
        let eid = p.event_id.unwrap();
        eng.enqueue(&p, 100, 0).await.unwrap();

        let changed = eng.advance_rung(eid, 1, 300).await.unwrap();
        assert!(changed);
        let due = eng.take_due(1_000, 10).await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].rung_index, 1);
        assert_eq!(due[0].deadline_at, 300);
    }

    #[tokio::test]
    async fn advance_rung_refuses_after_ack() {
        let (eng, _dir) = fresh_engine().await;
        let p = mk_payload("acked-before-advance", SeverityId::High);
        let eid = p.event_id.unwrap();
        eng.enqueue(&p, 100, 0).await.unwrap();
        eng.record_ack(eid, 50).await.unwrap();

        // Even though the row exists, it's acked; advance_rung must
        // refuse to clobber the operator's ack.
        let changed = eng.advance_rung(eid, 1, 300).await.unwrap();
        assert!(!changed);
    }

    #[tokio::test]
    async fn advance_rung_refuses_backward_or_same_rung() {
        let (eng, _dir) = fresh_engine().await;
        let p = mk_payload("monotonic", SeverityId::High);
        let eid = p.event_id.unwrap();
        eng.enqueue(&p, 100, 0).await.unwrap();

        // bump to rung 2 first
        assert!(eng.advance_rung(eid, 2, 200).await.unwrap());
        // attempting to set rung back to 1 must not succeed
        let changed = eng.advance_rung(eid, 1, 300).await.unwrap();
        assert!(!changed);
        // attempting to set the same rung (2) again must also not succeed
        let same = eng.advance_rung(eid, 2, 400).await.unwrap();
        assert!(!same);
    }

    #[tokio::test]
    async fn advance_rung_unknown_event_is_noop() {
        let (eng, _dir) = fresh_engine().await;
        let fake = EventId::from(Uuid::now_v7());
        let changed = eng.advance_rung(fake, 1, 100).await.unwrap();
        assert!(!changed);
    }
}
