//! Hot event store backed by SQLite (WAL mode).
//!
//! Cheap async wrapper around `rusqlite`: blocking calls run on
//! `tokio::task::spawn_blocking`, results returned via `.await`. Schema
//! migrations are baked into the binary and applied on `open`.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

mod sqlite;

pub use sqlite::SqliteStore;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("background task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("schema migration failed: applied {applied}, current code version {current}")]
    BadMigration { applied: u32, current: u32 },
}
