//! Server Dialback (XEP-0220) keys and elements. Keys follow XEP-0185: an HMAC-SHA256 of the
//! receiving domain, originating domain and stream id under a hash of our secret, so any node
//! holding the secret can verify a key without keeping state.

use hmac::{Hmac, Mac};
use quark_core::{ns, Element};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Longest key we bother checking (ours are 64 hex digits).
const MAX_KEY: usize = 1024;

/// The dialback key for a stream from `originating` to `receiving` with id `stream_id`.
pub fn key(secret: &[u8], receiving: &str, originating: &str, stream_id: &str) -> String {
    let k = hex::encode(Sha256::digest(secret));
    let mut mac = <Hmac<Sha256>>::new_from_slice(k.as_bytes()).expect("HMAC takes keys of any length");
    mac.update(receiving.as_bytes());
    mac.update(b" ");
    mac.update(originating.as_bytes());
    mac.update(b" ");
    mac.update(stream_id.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Whether `given` is the key we'd have made, compared in constant time.
pub fn check(secret: &[u8], receiving: &str, originating: &str, stream_id: &str, given: &str) -> bool {
    let given = given.trim();
    if given.is_empty() || given.len() > MAX_KEY {
        return false;
    }
    key(secret, receiving, originating, stream_id).as_bytes().ct_eq(given.as_bytes()).into()
}

/// `<db:result/>` or `<db:verify/>`.
pub fn element(name: &str, from: &str, to: &str) -> Element {
    Element::new(name, ns::DIALBACK).attr_set("from", from).attr_set("to", to)
}

/// A dialback answer: `type='valid'`, `'invalid'`, or `'error'` with a stanza error inside.
pub fn answer(name: &str, from: &str, to: &str, id: Option<&str>, outcome: Outcome) -> Element {
    let mut e = element(name, from, to).attr_opt("id", id);
    match outcome {
        Outcome::Valid => e.set_attr("type", "valid"),
        Outcome::Invalid => e.set_attr("type", "invalid"),
        Outcome::Error(err) => {
            e.set_attr("type", "error");
            e.append(err.to_element());
        }
    }
    e
}

#[derive(Debug, Clone)]
pub enum Outcome {
    Valid,
    Invalid,
    Error(quark_core::StanzaError),
}

/// Writes a dialback element with the `db:` prefix the stream header declared: namespace-aware
/// peers read it either way, and a few old ones only match the prefixed name.
pub fn to_stream_xml(el: &Element) -> String {
    let mut s = String::with_capacity(160);
    s.push_str("<db:");
    s.push_str(el.name());
    el.write_attrs(&mut s);
    let text = el.text_content();
    let children: Vec<&Element> = el.children().collect();
    if text.is_empty() && children.is_empty() {
        s.push_str("/>");
        return s;
    }
    s.push('>');
    quark_core::xml::escape_text(&mut s, &text);
    for c in children {
        c.write_into_stream(&mut s, ns::SERVER);
    }
    s.push_str("</db:");
    s.push_str(el.name());
    s.push('>');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_match_the_xep_0185_example() {
        // XEP-0185 §3 example values.
        let k = key(b"s3cr3tf0rd14lb4ck", "xmpp.example.com", "example.org", "D60000229F");
        assert_eq!(k, "37c69b1cf07a3f67c04a5ef5902fa5114f2c76fe4a2686482ba5b89323075643");
        assert!(check(b"s3cr3tf0rd14lb4ck", "xmpp.example.com", "example.org", "D60000229F", &k));
    }

    #[test]
    fn keys_depend_on_every_input() {
        let k = key(b"secret", "b.test", "a.test", "id1");
        assert!(!check(b"secret", "b.test", "a.test", "id2", &k));
        assert!(!check(b"secret", "c.test", "a.test", "id1", &k));
        assert!(!check(b"other", "b.test", "a.test", "id1", &k));
        assert!(!check(b"secret", "b.test", "a.test", "id1", ""));
        assert!(!check(b"secret", "b.test", "a.test", "id1", &"0".repeat(5000)));
    }

    #[test]
    fn elements_use_the_db_prefix() {
        let e = element("result", "a.test", "b.test").text("abc");
        assert_eq!(to_stream_xml(&e), "<db:result from='a.test' to='b.test'>abc</db:result>");
        let a = answer("verify", "b.test", "a.test", Some("x'1"), Outcome::Valid);
        assert_eq!(to_stream_xml(&a), "<db:verify from='b.test' to='a.test' id='x&apos;1' type='valid'/>");
        let err = answer("result", "b.test", "a.test", None, Outcome::Error(quark_core::StanzaError::item_not_found()));
        assert!(to_stream_xml(&err).contains("<error type='cancel'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>"));
    }
}
