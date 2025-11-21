//! ZK Brownian Forward Protocol
//!
//! A zero-knowledge message forwarding protocol where nodes forward packets
//! through a network and prove correct forwarding behavior without revealing
//! routing information.

pub mod types;
pub mod crypto;
pub mod proving;
pub mod protocol;

pub use types::*;
pub use protocol::{forward, spawn, verify};

/// Maximum number of hops a message can take
pub const MAX_HOPS: usize = 10;

/// Number of nodes in the network
pub const NUM_NODES: usize = 256; // Configurable, spec says "hundreds"

/// Maximum out-degree per node
pub const MAX_OUT_DEGREE: usize = 32; // Configurable, spec says "tens"

/// Weight sum (2^32)
pub const WEIGHT_SUM: u64 = 1u64 << 32;
