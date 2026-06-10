//! SQLite-backed event store.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use selfdef_core::{Event, SCHEMA_VERSION};
use tracing::{debug, error, info};
use uuid::Uuid;

use crate::StoreError;

/// All migrations, in order. Each `&str` is the body of `migrations/NNNN_*.sql`.
/// The migration count must equal `selfdef_core::SCHEMA_VERSION`. When that
/// constant bumps, add the migration here in the same PR.
const MIGRATIONS: &[&str] = &[include_str!("../migrations/0001_initial.sql")];

#[derive(Debug)]
pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
    path: PathBuf,
}

impl SqliteStore {
    /// Open (or create) a SQLite store at `path`. Runs pending migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }

        let conn = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;

        // Production-friendly pragmas.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "busy_timeout", 5_000_i64)?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;

        // SDD: integrity check on startup — a silently-corrupt forensic store is
        // a security problem (recent events may be unrecoverable and the
        // operator wouldn't know). `quick_check` (fast structural check; the
        // full `integrity_check` can be very slow on a large hot store) runs on
        // open. On failure we alert LOUDLY to the journal but CONTINUE: bricking
        // the whole IPS daemon over a degraded forensic DB would be a worse
        // failure than running with a flagged store (availability > a degraded
        // store; the operator now knows to investigate).
        if let Err(detail) = Self::integrity_check(&conn) {
            error!(
                path = %path.display(),
                detail = %detail,
                "store DB integrity check FAILED on open — the forensic event \
                 record may be corrupt; recent events may be unrecoverable. \
                 Investigate / restore from cold archive."
            );
        }

        Self::migrate(&conn)?;

        info!(path = %path.display(), schema = SCHEMA_VERSION, "store opened");

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            path,
        })
    }

    /// SQLite `quick_check` structural integrity probe. Returns `Err(detail)`
    /// when the DB reports anything other than `"ok"` — i.e. the forensic store
    /// is structurally corrupt. Used at [`SqliteStore::open`] and exposed for
    /// tests. `quick_check` is preferred over `integrity_check` at startup
    /// because it is dramatically faster on a large hot store while still
    /// catching the page/structure corruption that matters.
    pub(crate) fn integrity_check(conn: &Connection) -> Result<(), String> {
        let result: String = conn
            .pragma_query_value(None, "quick_check", |row| row.get(0))
            .map_err(|e| format!("quick_check query failed: {e}"))?;
        if result == "ok" { Ok(()) } else { Err(result) }
    }

    fn migrate(conn: &Connection) -> Result<(), StoreError> {
        let mut current: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;

        if current > SCHEMA_VERSION {
            return Err(StoreError::BadMigration {
                applied: current,
                current: SCHEMA_VERSION,
            });
        }

        while (current as usize) < MIGRATIONS.len() {
            let sql = MIGRATIONS[current as usize];
            debug!(version = current + 1, "applying migration");
            conn.execute_batch(sql)?;
            current += 1;
            conn.pragma_update(None, "user_version", current)?;
        }
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Insert one event.
    pub async fn insert(&self, event: &Event) -> Result<(), StoreError> {
        let conn = Arc::clone(&self.conn);
        let id_bytes = *event.id.as_bytes();
        let schema = event.schema;
        let time_ns = event.time_dt.unix_timestamp_nanos() as i64;
        let category_uid = event.category_uid as u32;
        let class_uid = event.class_uid.0;
        let activity_id = event.activity_id;
        let type_uid = event.type_uid as i64;
        let severity_id = event.severity_id as u32;
        let status_id: Option<u32> = event.status_id.map(|s| s as u32);
        let host_tag = event.host_tag.clone();
        let source = event.source.clone();
        let sequence = event.metadata.sequence as i64;
        let payload = serde_json::to_string(event)?;

        tokio::task::spawn_blocking(move || -> Result<(), StoreError> {
            let conn = conn.lock().unwrap_or_else(|p| p.into_inner());
            conn.execute(
                "INSERT INTO events
                    (id, schema, time_ns, category_uid, class_uid, activity_id,
                     type_uid, severity_id, status_id, host_tag, source, sequence, payload)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    id_bytes.to_vec(),
                    schema,
                    time_ns,
                    category_uid,
                    class_uid,
                    activity_id,
                    type_uid,
                    severity_id,
                    status_id,
                    host_tag,
                    source,
                    sequence,
                    payload,
                ],
            )?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    /// Total event count.
    pub async fn count(&self) -> Result<u64, StoreError> {
        let conn = Arc::clone(&self.conn);
        let n = tokio::task::spawn_blocking(move || -> Result<i64, rusqlite::Error> {
            let conn = conn.lock().unwrap_or_else(|p| p.into_inner());
            conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        })
        .await??;
        Ok(n as u64)
    }

    /// Fetch the most recent `limit` events, newest first.
    pub async fn recent(&self, limit: u32) -> Result<Vec<Event>, StoreError> {
        let conn = Arc::clone(&self.conn);
        let rows = tokio::task::spawn_blocking(move || -> Result<Vec<String>, rusqlite::Error> {
            let conn = conn.lock().unwrap_or_else(|p| p.into_inner());
            let mut stmt = conn.prepare(
                "SELECT payload FROM events ORDER BY time_ns DESC, sequence DESC LIMIT ?1",
            )?;
            let iter = stmt.query_map(params![limit], |row| row.get::<_, String>(0))?;
            iter.collect()
        })
        .await??;

        rows.into_iter()
            .map(|s| serde_json::from_str(&s).map_err(Into::into))
            .collect()
    }

    /// Fetch the most recent `limit` findings (category_uid = 2), newest first.
    pub async fn recent_findings(&self, limit: u32) -> Result<Vec<Event>, StoreError> {
        let conn = Arc::clone(&self.conn);
        let rows = tokio::task::spawn_blocking(move || -> Result<Vec<String>, rusqlite::Error> {
            let conn = conn.lock().unwrap_or_else(|p| p.into_inner());
            let mut stmt = conn.prepare(
                "SELECT payload FROM events
                 WHERE category_uid = 2
                 ORDER BY time_ns DESC, sequence DESC LIMIT ?1",
            )?;
            let iter = stmt.query_map(params![limit], |row| row.get::<_, String>(0))?;
            iter.collect()
        })
        .await??;

        rows.into_iter()
            .map(|s| serde_json::from_str(&s).map_err(Into::into))
            .collect()
    }

    /// Fetch one event by id.
    pub async fn get(&self, id: Uuid) -> Result<Option<Event>, StoreError> {
        let conn = Arc::clone(&self.conn);
        let bytes = id.as_bytes().to_vec();
        let row =
            tokio::task::spawn_blocking(move || -> Result<Option<String>, rusqlite::Error> {
                let conn = conn.lock().unwrap_or_else(|p| p.into_inner());
                conn.query_row(
                    "SELECT payload FROM events WHERE id = ?1",
                    params![bytes],
                    |r| r.get::<_, String>(0),
                )
                .optional()
            })
            .await??;
        match row {
            None => Ok(None),
            Some(s) => Ok(Some(serde_json::from_str(&s)?)),
        }
    }

    /// Delete every event whose `time_ns` is strictly older than
    /// `cutoff_ns` (an absolute unix-nanoseconds instant). Returns the
    /// number of rows deleted. This is the enforcement primitive behind
    /// `StoreConfig::hot_retention_days` (SDD-081) — without it the hot
    /// store grows unbounded and the retention knob is dead config.
    pub async fn prune_older_than(&self, cutoff_ns: i64) -> Result<u64, StoreError> {
        let conn = Arc::clone(&self.conn);
        let deleted = tokio::task::spawn_blocking(move || -> Result<usize, rusqlite::Error> {
            let conn = conn.lock().unwrap_or_else(|p| p.into_inner());
            conn.execute("DELETE FROM events WHERE time_ns < ?1", params![cutoff_ns])
        })
        .await??;
        Ok(deleted as u64)
    }
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_core::category::ClassUid;
    use selfdef_core::prelude::*;
    use tempfile::tempdir;

    fn make_event(seq: u64, severity: SeverityId) -> Event {
        Event::new(
            ClassUid::AUTHENTICATION,
            1,
            severity,
            "test-host",
            "test",
            seq,
        )
    }

    #[tokio::test]
    async fn open_creates_schema() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.sqlite");
        let store = SqliteStore::open(&path).unwrap();
        assert_eq!(store.count().await.unwrap(), 0);
    }

    #[test]
    fn integrity_check_passes_on_valid_db() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ok.sqlite");
        let store = SqliteStore::open(&path).unwrap();
        drop(store);
        let conn = Connection::open(&path).unwrap();
        assert!(SqliteStore::integrity_check(&conn).is_ok());
    }

    #[tokio::test]
    async fn integrity_check_detects_corrupt_page() {
        // The store claims "DB integrity checked on startup; corruption alerts
        // loudly". This locks the integrity_check that backs it: a structurally
        // corrupt forensic DB must be detected (not silently opened).
        let dir = tempdir().unwrap();
        let path = dir.path().join("corrupt.sqlite");
        {
            let store = SqliteStore::open(&path).unwrap();
            for i in 0..400 {
                store
                    .insert(&make_event(i, SeverityId::Medium))
                    .await
                    .unwrap();
            }
            // Flush WAL into the main db file so corrupting it is detectable.
            {
                let c = store.conn.lock().unwrap();
                c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
            }
        }
        // Mangle a data page header (page 3 starts at offset 8192 with the
        // default 4096-byte page size) — well past the 100-byte file header +
        // schema page 1, so `open` still succeeds but the structure is broken.
        let mut bytes = std::fs::read(&path).unwrap();
        assert!(
            bytes.len() > 8448,
            "expected a multi-page db, got {} bytes",
            bytes.len()
        );
        for b in bytes.iter_mut().skip(8192).take(256) {
            *b = 0xFF;
        }
        std::fs::write(&path, &bytes).unwrap();
        // A fresh open must detect the corruption via quick_check.
        let conn = Connection::open(&path).unwrap();
        assert!(
            SqliteStore::integrity_check(&conn).is_err(),
            "quick_check should report corruption on a mangled data page"
        );
    }

    #[tokio::test]
    async fn insert_count_recent_round_trip() {
        let dir = tempdir().unwrap();
        let store = SqliteStore::open(dir.path().join("state.sqlite")).unwrap();

        for i in 0..5 {
            store
                .insert(&make_event(i, SeverityId::Medium))
                .await
                .unwrap();
        }
        assert_eq!(store.count().await.unwrap(), 5);

        let recent = store.recent(10).await.unwrap();
        assert_eq!(recent.len(), 5);
        // Recent ordering: highest sequence first (newest first).
        assert_eq!(recent[0].metadata.sequence, 4);
        assert_eq!(recent[4].metadata.sequence, 0);
    }

    #[tokio::test]
    async fn prune_older_than_deletes_only_events_before_cutoff() {
        use time::{Duration, OffsetDateTime};
        let dir = tempdir().unwrap();
        let store = SqliteStore::open(dir.path().join("state.sqlite")).unwrap();

        let now = OffsetDateTime::now_utc();
        // 3 old events (40 days ago) + 2 fresh events (1 hour ago).
        for i in 0..3 {
            let mut e = make_event(i, SeverityId::Low);
            e.time_dt = now - Duration::days(40);
            store.insert(&e).await.unwrap();
        }
        for i in 3..5 {
            let mut e = make_event(i, SeverityId::Low);
            e.time_dt = now - Duration::hours(1);
            store.insert(&e).await.unwrap();
        }
        assert_eq!(store.count().await.unwrap(), 5);

        // Cutoff at 30 days ago: the 3 old events are pruned, 2 fresh kept.
        let cutoff_ns = (now - Duration::days(30)).unix_timestamp_nanos() as i64;
        let deleted = store.prune_older_than(cutoff_ns).await.unwrap();
        assert_eq!(deleted, 3);
        assert_eq!(store.count().await.unwrap(), 2);

        // Idempotent: a second prune at the same cutoff deletes nothing.
        assert_eq!(store.prune_older_than(cutoff_ns).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn get_by_id_round_trip() {
        let dir = tempdir().unwrap();
        let store = SqliteStore::open(dir.path().join("state.sqlite")).unwrap();
        let e = make_event(1, SeverityId::High);
        let id = e.id;
        store.insert(&e).await.unwrap();
        let back = store.get(id).await.unwrap().unwrap();
        assert_eq!(back.id, id);
        assert_eq!(back.severity_id, SeverityId::High);
    }

    #[tokio::test]
    async fn reopening_preserves_data() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.sqlite");
        {
            let store = SqliteStore::open(&path).unwrap();
            store.insert(&make_event(1, SeverityId::Low)).await.unwrap();
        }
        let store2 = SqliteStore::open(&path).unwrap();
        assert_eq!(store2.count().await.unwrap(), 1);
    }
}
