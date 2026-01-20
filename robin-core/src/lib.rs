//! Robin×SMESH Core - Signal types and domain model for dark web OSINT
//!
//! This crate provides the foundational primitives:
//! - SMESH-inspired signals with decay and reinforcement
//! - OSINT-specific signal payloads
//! - Artifact extraction types (IOCs, TTPs, threat actors)
//! - Search engine registry

pub mod signals;
pub mod artifacts;
pub mod search_engines;
pub mod field;

pub use signals::*;
pub use artifacts::*;
pub use search_engines::*;
pub use field::*;

/// Default signal TTL in seconds
pub const DEFAULT_TTL: f64 = 60.0;

/// Default decay rate (exponential)
pub const DEFAULT_DECAY_RATE: f64 = 0.1;

/// Default trust score for unknown nodes
pub const DEFAULT_TRUST: f64 = 0.5;

/// Minimum trust score
pub const MIN_TRUST: f64 = 0.0;

/// Maximum trust score  
pub const MAX_TRUST: f64 = 1.0;
