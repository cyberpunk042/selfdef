//! Shared state passed into every handler.

use std::sync::Arc;
use std::time::Instant;

use selfdef_bus::Bus;
use selfdef_store::SqliteStore;

#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<SqliteStore>,
    pub bus: Arc<Bus>,
    pub host_tag: String,
    pub schema_version: u32,
    pub crate_version: &'static str,
    pub started_at: Instant,
}

impl ApiState {
    #[must_use]
    pub fn new(store: Arc<SqliteStore>, bus: Arc<Bus>, host_tag: String) -> Self {
        Self {
            store,
            bus,
            host_tag,
            schema_version: selfdef_core::SCHEMA_VERSION,
            crate_version: env!("CARGO_PKG_VERSION"),
            started_at: Instant::now(),
        }
    }
}
