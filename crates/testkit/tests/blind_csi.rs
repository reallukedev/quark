//! Black-box conformance: client state indication (XEP-0352) and the optimisations its
//! §4 / §5 describe (hold presence and chat states, deliver important messages at once).
//! Written from the specification only.

use crate::blind_common;

use blind_common::*;
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{message, presence, Client, TestServer, DOMAIN};

async fn server() -> anyhow::Result<TestServer> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password1").await?;
    s.add_user("bob", "password1").await?;
    Ok(s)
}

fn chat_state(to: &str, state: &str) -> Element {
    Element::new("message", ns::CLIENT).attr_set("to", to).attr_set("type", "chat").child(Element::new(state, CHAT_STATES))
}

/// Alice and Bob online, Alice subscribed to Bob's presence; both quiet.
async fn friends(s: &TestServer) -> anyhow::Result<(Client, Client)> {
    let mut a = s.online("alice", "password1", "phone").await?;
    let mut b = s.online("bob", "password1", "desk").await?;
    a.send(&presence(Some("bob@quark.test"), Some("subscribe"))).await?;
    b.expect(|e| e.name() == "presence" && e.attr("type") == Some("subscribe")).await?;
    b.send(&presence(Some("alice@quark.test"), Some("subscribed"))).await?;
    a.expect(|e| e.name() == "presence" && e.attr("from").is_some_and(|f| f.starts_with("bob@quark.test/")) && e.attr("type").is_none())
        .await?;
    for c in [&mut a, &mut b] {
        for e in drain(c).await? {
            if e.name() == "iq" && e.attr("type") == Some("set") {
                c.answer(&e).await?;
            }
        }
    }
    Ok((a, b))
}

#[tokio::test]
async fn csi_is_advertised_after_authentication() -> anyhow::Result<()> {
    // XEP-0352 §2.
    let s = server().await?;
    let c = authed_client(&s, "alice", "password1").await?;
    assert!(has_feature(&c, "csi", CSI), "no <csi xmlns='urn:xmpp:csi:0'/>: {:?}", c.features);
    Ok(())
}

#[tokio::test]
async fn inactive_holds_chat_states_and_active_releases_them() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", "password1", "phone").await?;
    drain(&mut a).await?;
    let mut bob = s.login("bob", "password1").await?;
    a.send(&Element::new("inactive", CSI)).await?;
    bob.send(&chat_state("alice@quark.test/phone", "composing")).await?;
    a.expect_silence(QUIET).await.map_err(|e| anyhow::anyhow!("chat state delivered while inactive: {e}"))?;
    a.send(&Element::new("active", CSI)).await?;
    let m = a.expect(|e| e.name() == "message").await?;
    assert!(m.has_child("composing", CHAT_STATES), "{m}");
    Ok(())
}

#[tokio::test]
async fn inactive_delivers_messages_with_a_body_immediately() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", "password1", "phone").await?;
    drain(&mut a).await?;
    let mut bob = s.login("bob", "password1").await?;
    a.send(&Element::new("inactive", CSI)).await?;
    // Make sure <inactive/> is processed before bob's message arrives.
    a.iq_get(Some(DOMAIN), Element::new("ping", ns::PING)).await?;
    bob.send(&message("alice@quark.test/phone", "chat", "wake up")).await?;
    let m = a
        .recv_within(std::time::Duration::from_secs(2))
        .await?
        .expect("a message with a body was held while inactive (XEP-0352 §5: deliver important stanzas at once)");
    // A server may flush what it held first; the body message must be among what arrives.
    let mut got = vec![m];
    while !got.iter().any(|e| e.child_text("body", ns::CLIENT).as_deref() == Some("wake up")) {
        got.push(a.recv().await?);
    }
    Ok(())
}

#[tokio::test]
async fn inactive_holds_presence_updates_and_active_releases_them() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, mut b) = friends(&s).await?;
    a.send(&Element::new("inactive", CSI)).await?;
    a.iq_get(Some(DOMAIN), Element::new("ping", ns::PING)).await?;
    b.send(&Element::new("presence", ns::CLIENT).text_child("show", ns::CLIENT, "away")).await?;
    a.expect_silence(QUIET).await.map_err(|e| anyhow::anyhow!("presence update delivered while inactive: {e}"))?;
    a.send(&Element::new("active", CSI)).await?;
    let p = a.expect(|e| e.name() == "presence" && e.attr("from") == Some("bob@quark.test/desk")).await?;
    assert_eq!(p.child_text("show", ns::CLIENT).as_deref(), Some("away"), "latest presence expected: {p}");
    Ok(())
}

#[tokio::test]
async fn inactive_does_not_delay_iq_replies() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", "password1", "phone").await?;
    a.send(&Element::new("inactive", CSI)).await?;
    let started = std::time::Instant::now();
    let pong = a.iq_get(Some(DOMAIN), Element::new("ping", ns::PING)).await?;
    assert_eq!(pong.attr("type"), Some("result"));
    assert!(started.elapsed() < std::time::Duration::from_secs(1), "IQ reply held while inactive");
    Ok(())
}
