//! Core types for Quark: an XML tree and stream parser, JIDs, and stanza helpers.

pub mod jid;
pub mod ns;
pub mod stanza;
pub mod time;
pub mod xml;

pub use jid::Jid;
pub use stanza::{Condition, ErrorType, StanzaError};
pub use xml::{Element, Node};

/// A short unique id for stanzas and streams: 64 random bits as 16 hex digits.
///
/// Drawn from the thread-local CSPRNG (ChaCha, seeded from the OS), so ids can't be guessed:
/// RFC 6120 §4.7.3 wants unpredictable stream ids, and guessable server IQ ids would let a
/// third party answer requests it never saw.
pub fn new_id() -> String {
    format!("{:016x}", rand::random::<u64>())
}

#[cfg(test)]
mod tests {
    #[test]
    fn ids_are_hex_and_distinct() {
        let ids: std::collections::HashSet<String> = (0..1000).map(|_| super::new_id()).collect();
        assert_eq!(ids.len(), 1000);
        assert!(ids.iter().all(|a| a.len() == 16 && a.bytes().all(|c| c.is_ascii_hexdigit())));
    }
}
