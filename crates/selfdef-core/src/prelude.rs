//! Convenience re-exports for downstream crates.
//!
//! ```ignore
//! use selfdef_core::prelude::*;
//! ```

pub use crate::SCHEMA_VERSION;
pub use crate::activity::{
    AccountChangeActivity, AuthenticationActivity, FileSystemActivity, NetworkActivity,
    ProcessActivity, SshActivity,
};
pub use crate::attack::{Tactic, TechniqueRef};
pub use crate::category::{CategoryUid, ClassUid};
pub use crate::envelope::Event;
pub use crate::error::Error;
pub use crate::metadata::{Metadata, Product};
pub use crate::observable::{
    Actor, Direction, Endpoint, File, FileType, Hash, HashAlgorithm, NetworkConnection, Process,
    Session, User,
};
pub use crate::severity::SeverityId;
pub use crate::status::StatusId;
