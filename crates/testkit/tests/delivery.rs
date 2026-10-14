//! Where messages to local accounts go: refused ones leave no trace, offline messages wait for
//! a device that takes them.

use std::time::Duration;

use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{message, Client, TestServer, DOMAIN};

use crate::common;

const PW: &str = "password-1";
const QUIET: Duration = Duration::from_millis(400);

/// The bodies in the account's archive.
async fn archived(c: &mut Client) -> anyhow::Result<Vec<String>> {
    let id = quark_testkit::quark_core::new_id();
    c.send(&quark_testkit::quark_core::stanza::iq("set", &id, None, None, Element::new("query", ns::MAM).attr_set("queryid", "q"))).await?;
    let mut out = Vec::new();
    loop {
        let e = c.recv().await?;
        if e.name() == "iq" && e.attr("id") == Some(&id) {
            anyhow::ensure!(e.attr("type") == Some("result"), "query failed: {e}");
            return Ok(out);
        }
        if let Some(b) = e
            .get_child("result", ns::MAM)
            .and_then(|r| r.get_child("forwarded", ns::FORWARD))
            .and_then(|f| f.get_child("message", ns::CLIENT))
            .and_then(|m| m.child_text("body", ns::CLIENT))
        {
            out.push(b);
        }
    }
}

fn priority(p: i8) -> Element {
    Element::new("presence", ns::CLIENT).text_child("priority", ns::CLIENT, p.to_string())
}

#[tokio::test]
async fn a_normal_message_to_an_offline_device_is_refused_and_not_archived() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", PW).await?;
    s.add_user("bob", PW).await?;
    let mut alice = s.online("alice", PW, "phone").await?;
    let mut bob = s.online("bob", PW, "desk").await?;

    // RFC 6121 §8.5.3.2.1: type normal to a full JID with no session is refused.
    bob.send(&message(&format!("alice@{DOMAIN}/gone"), "normal", "refused")).await?;
    let err = bob.expect(|e| e.name() == "message" && e.attr("type") == Some("error")).await?;
    assert_eq!(common::condition(&err), "service-unavailable", "{err}");
    // Chat to one is taken by the account instead.
    bob.send(&message(&format!("alice@{DOMAIN}/gone"), "chat", "taken")).await?;
    alice.expect(|e| e.child_text("body", ns::CLIENT).as_deref() == Some("taken")).await?;

    assert_eq!(archived(&mut alice).await?, ["taken"], "the refused message left nothing in alice's history");
    assert_eq!(archived(&mut bob).await?, ["refused", "taken"], "the sender's own copy is kept");
    Ok(())
}

#[tokio::test]
async fn offline_messages_wait_for_a_presence_with_priority() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", PW).await?;
    s.add_user("bob", PW).await?;
    let mut bob = s.online("bob", PW, "desk").await?;
    bob.send(&message(&format!("alice@{DOMAIN}"), "chat", "while away")).await?;
    bob.expect_silence(QUIET).await?;

    let mut alice = s.login_as("alice", PW, "phone").await?;
    // Hidden at first (negative priority): nothing yet.
    alice.send(&priority(-1)).await?;
    let mut got = Vec::new();
    while let Some(e) = alice.recv_within(QUIET).await? {
        got.push(e);
    }
    assert!(!got.iter().any(|e| e.name() == "message"), "no messages to a hidden device: {got:?}");

    // The first presence with priority ≥ 0 gets them, once.
    alice.send(&priority(1)).await?;
    let m = alice.expect(|e| e.child_text("body", ns::CLIENT).as_deref() == Some("while away")).await?;
    assert!(m.has_child("delay", ns::DELAY), "{m}");
    alice.send(&priority(-1)).await?;
    alice.send(&priority(2)).await?;
    while let Some(e) = alice.recv_within(QUIET).await? {
        assert!(e.name() != "message", "delivered once: {e}");
    }
    Ok(())
}
