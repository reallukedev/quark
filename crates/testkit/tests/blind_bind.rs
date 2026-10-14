//! Black-box conformance: resource binding (RFC 6120 §7, RFC 7622) and the legacy session IQ
//! (RFC 3921 §3, draft-cridland-xmpp-session). Written from the specifications only.

use crate::blind_common;

use blind_common::*;
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{message, TestServer, DOMAIN};

async fn server() -> anyhow::Result<TestServer> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password1").await?;
    s.add_user("bob", "password1").await?;
    Ok(s)
}

fn bind_request(resource: Option<&str>) -> Element {
    let mut b = Element::new("bind", ns::BIND);
    if let Some(r) = resource {
        b.append(Element::new("resource", ns::BIND).text(r));
    }
    b
}

#[tokio::test]
async fn bind_with_a_requested_resource() -> anyhow::Result<()> {
    // RFC 6120 §7.7.
    let s = server().await?;
    let mut c = authed_client(&s, "alice", "password1").await?;
    let r = c.iq_set(None, bind_request(Some("Phone"))).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let jid = r.get_child("bind", ns::BIND).and_then(|b| b.child_text("jid", ns::BIND));
    assert_eq!(jid.as_deref(), Some("alice@quark.test/Phone"), "{r}");
    Ok(())
}

#[tokio::test]
async fn bind_without_resource_gets_a_server_generated_one() -> anyhow::Result<()> {
    // RFC 6120 §7.6.
    let s = server().await?;
    let mut a = authed_client(&s, "alice", "password1").await?;
    let mut b = authed_client(&s, "alice", "password1").await?;
    let ja = a.bind(None).await?;
    let jb = b.bind(None).await?;
    for j in [&ja, &jb] {
        let (bare, res) = j.split_once('/').unwrap_or_else(|| panic!("not a full JID: {j}"));
        assert_eq!(bare, "alice@quark.test");
        assert!(!res.is_empty());
    }
    assert_ne!(ja, jb, "two generated resources are the same");
    Ok(())
}

#[tokio::test]
async fn bind_with_too_long_resource_is_bad_request() -> anyhow::Result<()> {
    // RFC 7622 §3.4: a resourcepart is at most 1023 octets; RFC 6120 §7.7.2.1 → <bad-request/>.
    let s = server().await?;
    let mut c = authed_client(&s, "alice", "password1").await?;
    let r = c.iq_set(None, bind_request(Some(&"r".repeat(1024)))).await?;
    assert_eq!(r.attr("type"), Some("error"), "{r}");
    let (kind, cond) = stanza_error(&r).expect("error condition");
    assert!(cond == "bad-request" || cond == "not-allowed", "{r}");
    assert!(kind == "modify" || kind == "cancel", "{r}");
    // The stream is still usable: a valid bind works afterwards.
    c.bind(Some("ok")).await?;
    Ok(())
}

#[tokio::test]
async fn bind_with_control_character_in_resource_is_bad_request() -> anyhow::Result<()> {
    // RFC 7622 §3.4 / RFC 8264 OpaqueString: control characters (U+0085 is Cc) are disallowed.
    let s = server().await?;
    let mut c = authed_client(&s, "alice", "password1").await?;
    let r = c.iq_set(None, bind_request(Some("bad\u{0085}res"))).await?;
    assert_eq!(r.attr("type"), Some("error"), "{r}");
    let (_, cond) = stanza_error(&r).expect("error condition");
    assert!(cond == "bad-request" || cond == "not-allowed", "{r}");
    Ok(())
}

#[tokio::test]
async fn bind_same_resource_twice_follows_one_of_the_rfc_policies() -> anyhow::Result<()> {
    // RFC 6120 §7.7.2.2: on a resource conflict the server either (a) terminates the old session
    // with a <conflict/> stream error and binds the new one, (b) refuses the new bind with a
    // <conflict/> stanza error, or (c) binds the new session to a different resource.
    let s = server().await?;
    let mut old = s.login_as("alice", "password1", "phone").await?;
    let mut new = authed_client(&s, "alice", "password1").await?;
    let r = new.iq_set(None, bind_request(Some("phone"))).await?;
    let jid = r.get_child("bind", ns::BIND).and_then(|b| b.child_text("jid", ns::BIND));
    match (r.attr("type"), jid.as_deref()) {
        (Some("result"), Some("alice@quark.test/phone")) => {
            eprintln!("policy (a): old session replaced");
            expect_stream_error(&mut old, &["conflict"]).await?;
        }
        (Some("result"), Some(other)) => {
            eprintln!("policy (c): new resource {other}");
            assert!(other.starts_with("alice@quark.test/"));
            let pong = old.iq_get(Some(DOMAIN), Element::new("ping", ns::PING)).await?;
            assert_eq!(pong.attr("type"), Some("result"));
        }
        (Some("error"), _) => {
            eprintln!("policy (b): new bind refused");
            assert_eq!(stanza_error(&r).map(|e| e.1).as_deref(), Some("conflict"), "{r}");
            let pong = old.iq_get(Some(DOMAIN), Element::new("ping", ns::PING)).await?;
            assert_eq!(pong.attr("type"), Some("result"));
        }
        _ => panic!("unexpected bind reply {r}"),
    }
    Ok(())
}

#[tokio::test]
async fn replaced_session_gets_conflict_and_new_session_receives_messages() -> anyhow::Result<()> {
    // The behaviour the lead asked for: policy (a) of RFC 6120 §7.7.2.2.
    let s = server().await?;
    let mut old = s.login_as("alice", "password1", "phone").await?;
    let mut new = s.login_as("alice", "password1", "phone").await?;
    assert_eq!(new.jid.as_deref(), Some("alice@quark.test/phone"));
    expect_stream_error(&mut old, &["conflict"]).await?;
    let mut bob = s.login("bob", "password1").await?;
    bob.send(&message("alice@quark.test/phone", "chat", "to the new one")).await?;
    let m = new.expect(|e| e.name() == "message").await?;
    assert_eq!(m.child_text("body", ns::CLIENT).as_deref(), Some("to the new one"));
    Ok(())
}

#[tokio::test]
async fn legacy_session_iq_is_answered_with_result() -> anyhow::Result<()> {
    // RFC 3921 §3 / draft-cridland-xmpp-session: old clients send it; servers answer result.
    let s = server().await?;
    let mut c = s.login("alice", "password1").await?;
    let r = c.iq_set(None, Element::new("session", ns::SESSION)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    Ok(())
}

#[tokio::test]
async fn session_feature_if_advertised_is_optional() -> anyhow::Result<()> {
    // draft-cridland-xmpp-session: a server that advertises <session/> marks it <optional/> so
    // modern clients can skip it.
    let s = server().await?;
    let c = authed_client(&s, "alice", "password1").await?;
    if let Some(sess) = feature(&c, "session", ns::SESSION) {
        assert!(sess.has_child("optional", ns::SESSION), "session feature without <optional/>: {sess}");
    }
    Ok(())
}

#[tokio::test]
async fn bound_jid_is_stamped_as_from() -> anyhow::Result<()> {
    // RFC 6120 §8.1.2.1: the server stamps (or checks) 'from' with the client's full JID.
    let s = server().await?;
    let mut a = s.login_as("alice", "password1", "desk").await?;
    let mut b = s.login("bob", "password1").await?;
    a.send(&message(b.jid.as_deref().unwrap_or_default(), "chat", "hello")).await?;
    let m = b.expect(|e| e.name() == "message").await?;
    assert_eq!(m.attr("from"), Some("alice@quark.test/desk"), "{m}");
    Ok(())
}

#[tokio::test]
async fn spoofed_from_is_never_delivered_as_is() -> anyhow::Result<()> {
    // RFC 6120 §8.1.2.1: a 'from' that is not the client's own JID is either rejected with an
    // <invalid-from/> stream error or overwritten; it never reaches the recipient unchanged.
    let s = server().await?;
    s.add_user("carol", "password1").await?;
    let mut a = s.login_as("alice", "password1", "desk").await?;
    let mut b = s.login("bob", "password1").await?;
    let to = b.jid.clone().unwrap_or_default();
    a.send_raw(&format!("<message from='carol@quark.test/x' to='{to}' type='chat' id='spoof'><body>it is carol</body></message>")).await?;
    match b.recv_within(QUIET).await? {
        Some(m) => assert_eq!(m.attr("from"), Some("alice@quark.test/desk"), "spoofed from delivered: {m}"),
        None => {
            expect_stream_error(&mut a, &["invalid-from"]).await?;
        }
    }
    Ok(())
}
