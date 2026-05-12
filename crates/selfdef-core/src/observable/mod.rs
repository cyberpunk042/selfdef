//! Typed observables — the entities an event refers to.
//!
//! Each observable is its own optional field on [`crate::Event`]. Every field
//! is independently nullable so collectors only fill what they actually
//! observed; correlator rules match on what's present.

pub mod actor;
pub mod hash;
pub mod network;
pub mod resource;

pub use actor::{Actor, Process, Session, User};
pub use hash::{Hash, HashAlgorithm};
pub use network::{Direction, Endpoint, NetworkConnection};
pub use resource::{File, FileType};
