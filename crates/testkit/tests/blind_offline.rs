//! Black-box offline message tests (XEP-0160, XEP-0203, XEP-0334), from the specs.

use crate::blind_util;

use blind_util::*;
use quark_testkit::message;
use quark_testkit::quark_core::{ns, Element};

#[tokio::test]
async fn offline_messages_wait_for_initial_presence_and_carry_a_delay() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut b = s.online("bob", PW, "desk").await?;
    b.send(&message(&bare("alice"), "chat", "first")).await?;
    b.send(&message(&bare("alice"), "normal", "second")).await?;
    assert_none(&mut b, "an error (alice exists, storage is allowed)", |e| e.name() == "message").await?;

    let mut a = s.login_as("alice", PW, "phone").await?;
    fetch_roster_quietly(&mut a).await?;
    // XEP-0160 §3: delivered when the user sends initial presence, not before.
    assert_none(&mut a, "offline messages before initial presence", |e| e.name() == "message").await?;

    a.send(&Element::new("presence", ns::CLIENT)).await?;
    let first = expect_body(&mut a, "first").await?;
    let second = expect_body(&mut a, "second").await?;
    for m in [&first, &second] {
        assert_eq!(m.attr("from"), Some(full("bob", "desk").as_str()), "{m}");
        let d = delay(m).unwrap_or_else(|| panic!("XEP-0160 §3/XEP-0203: stored messages carry <delay xmlns='urn:xmpp:delay'/>: {m}"));
        assert!(d.attr("stamp").is_some_and(|t| t.ends_with('Z') && t.contains('T')), "delay has a UTC XEP-0082 stamp: {d}");
    }
    Ok(())
}

#[tokio::test]
async fn messages_are_stored_while_the_only_session_is_not_available() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    // Connected and interested in the roster, but no presence sent yet: not an available resource.
    let mut a = s.login_as("alice", PW, "phone").await?;
    fetch_roster_quietly(&mut a).await?;
    let mut b = s.online("bob", PW, "desk").await?;
    b.send(&message(&bare("alice"), "chat", "while away")).await?;
    assert_none(&mut a, "a message before becoming available", |e| is_message_with_body(e, "while away")).await?;

    a.send(&Element::new("presence", ns::CLIENT)).await?;
    let m = expect_body(&mut a, "while away").await?;
    assert!(delay(&m).is_some(), "stored message has a delay: {m}");
    Ok(())
}

#[tokio::test]
async fn offline_messages_are_delivered_once() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut b = s.online("bob", PW, "desk").await?;
    b.send(&message(&bare("alice"), "chat", "only once")).await?;
    settle(&mut b).await?;

    let mut a = s.online("alice", PW, "phone").await?;
    expect_body(&mut a, "only once").await?;
    a.close().await?;
    tokio::time::sleep(QUIET).await;

    // XEP-0160: once delivered, the server deletes them.
    let mut a = s.online("alice", PW, "phone").await?;
    assert_none(&mut a, "the same offline message again", |e| is_message_with_body(e, "only once")).await?;
    Ok(())
}

#[tokio::test]
async fn chat_states_without_body_are_not_stored() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut b = s.online("bob", PW, "desk").await?;
    let typing = Element::new("message", ns::CLIENT)
        .attr_set("to", bare("alice"))
        .attr_set("type", "chat")
        .attr_set("id", "cs1")
        .child(Element::new("composing", ns::CHAT_STATES));
    b.send(&typing).await?;
    b.send(&message(&bare("alice"), "chat", "marker")).await?;
    settle(&mut b).await?;

    let mut a = s.online("alice", PW, "phone").await?;
    expect_body(&mut a, "marker").await?;
    // XEP-0085 §5.6 / XEP-0160: standalone chat state notifications are not stored offline.
    assert_none(&mut a, "a stored chat state", |e| e.name() == "message" && e.get_child("composing", ns::CHAT_STATES).is_some()).await?;
    Ok(())
}

#[tokio::test]
async fn no_store_hint_is_respected() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut b = s.online("bob", PW, "desk").await?;
    b.send(&message(&bare("alice"), "chat", "ephemeral").child(Element::new("no-store", ns::HINTS))).await?;
    b.send(&message(&bare("alice"), "chat", "marker")).await?;
    settle(&mut b).await?;

    let mut a = s.online("alice", PW, "phone").await?;
    expect_body(&mut a, "marker").await?;
    // XEP-0334 §4.3: <no-store/> — "the message shouldn't be stored in any permanent or semi-permanent storage".
    assert_none(&mut a, "a <no-store/> message from storage", |e| is_message_with_body(e, "ephemeral")).await?;
    Ok(())
}
