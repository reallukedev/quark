//! Core types for Quark: an XML tree and stream parser, JIDs, and stanza helpers.

pub mod jid;
pub mod ns;
pub mod stanza;
pub mod time;
pub mod xml;

pub use jid::Jid;
pub use stanza::{Condition, ErrorType, StanzaError};
pub use xml::{Element, Node};

use std::sync::atomic::{AtomicU64, Ordering};

/// A short unique id for stanzas and streams: process start nanos mixed with a counter.
pub fn new_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    static SEED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    let seed = *SEED.get_or_init(|| {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0);
        t ^ (std::process::id() as u64) << 32
    });
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    // splitmix64: cheap and well distributed, so ids don't look sequential.
    let mut z = seed.wrapping_add(n.wrapping_mul(0x9E3779B97F4A7C15));
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^= z >> 31;
    format!("{z:016x}")
}
