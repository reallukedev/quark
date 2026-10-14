//! Black-box conformance: stream management (XEP-0198 v1.6). Written from the specification only.

use crate::blind_common;

use blind_common::*;
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{message, Client, TestServer, DOMAIN};

async fn server() -> anyhow::Result<TestServer> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password1").await?;
    s.add_user("bob", "password1").await?;
    Ok(s)
}

/// Alice online (presence sent, roster fetched), quiet, then SM enabled. Returns the `<enabled/>`.
async fn alice_with_sm(s: &TestServer, resume: bool) -> anyhow::Result<(Client, Element)> {
    let mut a = s.online("alice", "password1", "phone").await?;
    drain(&mut a).await?;
    let en = sm_enable(&mut a, resume).await?;
    assert!(en.is("enabled", SM), "enable failed: {en}");
    Ok((a, en))
}

async fn ping(c: &mut Client) -> anyhow::Result<()> {
    let r = c.iq_get(Some(DOMAIN), Element::new("ping", ns::PING)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    Ok(())
}

fn body(m: &Element) -> Option<String> {
    m.child_text("body", ns::CLIENT)
}

fn is_message_with(body_text: &'static str) -> impl FnMut(&Element) -> bool {
    move |e| e.name() == "message" && body(e).as_deref() == Some(body_text)
}

/// A new connection that authenticates and sends `<resume/>`; returns the client and the answer.
async fn resume_on_new_connection(s: &TestServer, user: &str, previd: &str, h: u32) -> anyhow::Result<(Client, Element)> {
    let mut c = authed_client(s, user, "password1").await?;
    c.send(&Element::new("resume", SM).attr_set("previd", previd).attr_set("h", h.to_string())).await?;
    let r = c.expect(|e| e.ns() == SM && (e.name() == "resumed" || e.name() == "failed")).await?;
    Ok((c, r))
}

#[tokio::test]
async fn sm_is_advertised_after_authentication() -> anyhow::Result<()> {
    // XEP-0198 §2.
    let s = server().await?;
    let c = authed_client(&s, "alice", "password1").await?;
    assert!(has_feature(&c, "sm", SM), "no <sm xmlns='urn:xmpp:sm:3'/>: {:?}", c.features);
    Ok(())
}

#[tokio::test]
async fn enable_with_resume_returns_an_id() -> anyhow::Result<()> {
    // XEP-0198 §3, §5: <enabled id=… resume='true'/>.
    let s = server().await?;
    let (_a, en) = alice_with_sm(&s, true).await?;
    assert!(en.attr("id").is_some_and(|i| !i.is_empty()), "no id: {en}");
    assert!(is_true(en.attr("resume")), "resume not granted: {en}");
    if let Some(max) = en.attr("max") {
        max.parse::<u32>().unwrap_or_else(|_| panic!("max is not an integer: {en}"));
    }
    Ok(())
}

#[tokio::test]
async fn enable_without_resume_still_acks() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, en) = alice_with_sm(&s, false).await?;
    assert!(!is_true(en.attr("resume")), "resume granted although not asked: {en}");
    assert_eq!(sm_request_ack(&mut a).await?, 0);
    Ok(())
}

#[tokio::test]
async fn ack_h_counts_stanzas_handled_from_the_client() -> anyhow::Result<()> {
    // XEP-0198 §4: h = number of stanzas handled; <r/> and <a/> are not counted.
    let s = server().await?;
    let (mut a, _) = alice_with_sm(&s, false).await?;
    assert_eq!(sm_request_ack(&mut a).await?, 0);
    for _ in 0..3 {
        ping(&mut a).await?;
    }
    assert_eq!(sm_request_ack(&mut a).await?, 3);
    assert_eq!(sm_request_ack(&mut a).await?, 3, "<r/> must not be counted");
    a.send(&Element::new("presence", ns::CLIENT)).await?;
    a.send(&message("bob@quark.test", "chat", "counted")).await?;
    assert_eq!(sm_request_ack(&mut a).await?, 5);
    Ok(())
}

#[tokio::test]
async fn server_requests_acks_for_what_it_sends() -> anyhow::Result<()> {
    // XEP-0198 §4: either side MAY send <r/>; a server needs acks to drop its unacked queue and
    // must accept a client's <a/> for what it sent. We expect it to ask at some point after
    // delivering stanzas.
    let s = server().await?;
    let (mut a, _) = alice_with_sm(&s, true).await?;
    let mut bob = s.login("bob", "password1").await?;
    for i in 0..5 {
        bob.send(&message("alice@quark.test/phone", "chat", &format!("m{i}"))).await?;
    }
    let mut got = 0u32;
    a.expect(|e| {
        if matches!(e.name(), "message" | "presence" | "iq") {
            got += 1;
        }
        e.is("r", SM)
    })
    .await
    .map_err(|e| anyhow::anyhow!("the server never sent <r/> after delivering stanzas: {e}"))?;
    // Answer with what was received before the <r/>; the stream must stay up.
    a.send(&Element::new("a", SM).attr_set("h", got.to_string())).await?;
    ping(&mut a).await?;
    Ok(())
}

#[tokio::test]
async fn client_ack_for_delivered_stanzas_is_accepted() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, _) = alice_with_sm(&s, true).await?;
    let mut bob = s.login("bob", "password1").await?;
    bob.send(&message("alice@quark.test/phone", "chat", "one")).await?;
    bob.send(&message("alice@quark.test/phone", "chat", "two")).await?;
    a.expect(is_message_with("one")).await?;
    a.expect(is_message_with("two")).await?;
    a.send(&Element::new("a", SM).attr_set("h", "2")).await?;
    ping(&mut a).await?;
    Ok(())
}

#[tokio::test]
async fn ack_higher_than_sent_closes_the_stream() -> anyhow::Result<()> {
    // XEP-0198 §5 (Error Handling): an <a/> acknowledging more than was sent closes the stream
    // with <undefined-condition/> and <handled-count-too-high/>.
    let s = server().await?;
    let (mut a, _) = alice_with_sm(&s, false).await?;
    a.send(&Element::new("a", SM).attr_set("h", "42")).await?;
    let e = expect_stream_error(&mut a, &["undefined-condition", "policy-violation"]).await?;
    if stream_error_condition(&e).as_deref() == Some("undefined-condition") {
        assert!(e.has_child("handled-count-too-high", SM), "missing <handled-count-too-high/>: {e}");
    }
    Ok(())
}

#[tokio::test]
async fn enable_twice_fails_with_unexpected_request() -> anyhow::Result<()> {
    // XEP-0198 §3: a second <enable/> gets <failed/> with <unexpected-request/>.
    let s = server().await?;
    let (mut a, _) = alice_with_sm(&s, false).await?;
    let f = sm_enable(&mut a, false).await?;
    assert!(f.is("failed", SM), "second enable accepted: {f}");
    assert!(f.has_child("unexpected-request", ns::STANZAS), "{f}");
    Ok(())
}

#[tokio::test]
async fn enable_before_bind_fails() -> anyhow::Result<()> {
    // XEP-0198 §3: enabling before resource binding is refused (<failed><unexpected-request/>).
    let s = server().await?;
    let mut c = authed_client(&s, "alice", "password1").await?;
    c.send(&Element::new("enable", SM)).await?;
    let r = c.recv().await?;
    if r.is("failed", SM) {
        assert!(r.has_child("unexpected-request", ns::STANZAS), "{r}");
    } else {
        let cond = stream_error_condition(&r).unwrap_or_else(|| panic!("SM enabled before bind: {r}"));
        assert!(["not-authorized", "unsupported-stanza-type", "policy-violation"].contains(&cond.as_str()), "{r}");
    }
    Ok(())
}

#[tokio::test]
async fn resume_redelivers_unacked_stanzas_including_ones_sent_while_away() -> anyhow::Result<()> {
    // XEP-0198 §5: after <resumed/>, the server re-sends everything not acknowledged.
    let s = server().await?;
    let (mut a, en) = alice_with_sm(&s, true).await?;
    let id = en.attr("id").expect("id").to_string();
    let mut bob = s.login("bob", "password1").await?;
    bob.send(&message("alice@quark.test/phone", "chat", "before drop")).await?;
    a.expect(is_message_with("before drop")).await?;
    a.drop_connection();
    bob.send(&message("alice@quark.test/phone", "chat", "while away")).await?;
    // Give the server a moment to route it into the detached session.
    bob.iq_get(Some(DOMAIN), Element::new("ping", ns::PING)).await?;

    let (mut a2, r) = resume_on_new_connection(&s, "alice", &id, 0).await?;
    assert!(r.is("resumed", SM), "resume failed: {r}");
    assert_eq!(r.attr("previd"), Some(id.as_str()), "{r}");
    assert_eq!(r.attr("h"), Some("0"), "alice sent nothing after enabling: {r}");
    a2.expect(is_message_with("before drop")).await?;
    a2.expect(is_message_with("while away")).await?;
    Ok(())
}

#[tokio::test]
async fn resume_with_h_skips_what_the_client_already_handled() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, en) = alice_with_sm(&s, true).await?;
    let id = en.attr("id").expect("id").to_string();
    let mut bob = s.login("bob", "password1").await?;
    bob.send(&message("alice@quark.test/phone", "chat", "first")).await?;
    a.expect(is_message_with("first")).await?;
    a.drop_connection();
    bob.send(&message("alice@quark.test/phone", "chat", "second")).await?;
    bob.iq_get(Some(DOMAIN), Element::new("ping", ns::PING)).await?;

    let (mut a2, r) = resume_on_new_connection(&s, "alice", &id, 1).await?;
    assert!(r.is("resumed", SM), "resume failed: {r}");
    let m = a2.expect(|e| e.name() == "message").await?;
    assert_eq!(body(&m).as_deref(), Some("second"), "{m}");
    let again = a2.recv_within(QUIET).await?;
    assert!(again.is_none_or(|e| body(&e).as_deref() != Some("first")), "acked stanza re-sent");
    Ok(())
}

#[tokio::test]
async fn resumed_h_reports_stanzas_received_from_the_client() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, en) = alice_with_sm(&s, true).await?;
    let id = en.attr("id").expect("id").to_string();
    ping(&mut a).await?;
    ping(&mut a).await?;
    a.drop_connection();
    let (_a2, r) = resume_on_new_connection(&s, "alice", &id, 2).await?;
    assert!(r.is("resumed", SM), "resume failed: {r}");
    assert_eq!(r.attr("h"), Some("2"), "{r}");
    Ok(())
}

#[tokio::test]
async fn resumed_session_keeps_its_full_jid() -> anyhow::Result<()> {
    let s = server().await?;
    let (a, en) = alice_with_sm(&s, true).await?;
    let id = en.attr("id").expect("id").to_string();
    a.drop_connection();
    let (mut a2, r) = resume_on_new_connection(&s, "alice", &id, 0).await?;
    assert!(r.is("resumed", SM), "resume failed: {r}");
    let mut bob = s.login("bob", "password1").await?;
    bob.send(&message("alice@quark.test/phone", "chat", "after resume")).await?;
    a2.expect(is_message_with("after resume")).await?;
    ping(&mut a2).await?;
    Ok(())
}

#[tokio::test]
async fn resume_with_unknown_id_fails_with_item_not_found_and_bind_still_works() -> anyhow::Result<()> {
    // XEP-0198 §5: <failed><item-not-found/></failed>; the client may then bind normally.
    let s = server().await?;
    let (mut c, r) = resume_on_new_connection(&s, "alice", "no-such-session-id", 0).await?;
    assert!(r.is("failed", SM), "{r}");
    assert!(r.has_child("item-not-found", ns::STANZAS), "{r}");
    c.bind(Some("fresh")).await?;
    Ok(())
}

#[tokio::test]
async fn another_user_cannot_resume_alices_session() -> anyhow::Result<()> {
    // XEP-0198 §5 / §8 (Security): the server checks the resumed session belongs to the user.
    let s = server().await?;
    let (a, en) = alice_with_sm(&s, true).await?;
    let id = en.attr("id").expect("id").to_string();
    a.drop_connection();
    let (_b, r) = resume_on_new_connection(&s, "bob", &id, 0).await?;
    assert!(r.is("failed", SM), "bob resumed alice's session: {r}");
    Ok(())
}

#[tokio::test]
async fn cleanly_closed_session_cannot_be_resumed() -> anyhow::Result<()> {
    // XEP-0198 §5: closing the stream ends the session; there is nothing to resume.
    let s = server().await?;
    let (mut a, en) = alice_with_sm(&s, true).await?;
    let id = en.attr("id").expect("id").to_string();
    a.send_raw("</stream:stream>").await?;
    let _ = a.recv().await;
    let (_a2, r) = resume_on_new_connection(&s, "alice", &id, 0).await?;
    assert!(r.is("failed", SM), "resumed a cleanly closed session: {r}");
    Ok(())
}

#[tokio::test]
async fn a_session_can_be_resumed_again_after_resumption() -> anyhow::Result<()> {
    // Phones lose signal more than once; the same id (or the one in <resumed/>) keeps working.
    let s = server().await?;
    let (a, en) = alice_with_sm(&s, true).await?;
    let id = en.attr("id").expect("id").to_string();
    a.drop_connection();
    let (a2, r) = resume_on_new_connection(&s, "alice", &id, 0).await?;
    assert!(r.is("resumed", SM), "{r}");
    a2.drop_connection();
    let (mut a3, r) = resume_on_new_connection(&s, "alice", &id, 0).await?;
    assert!(r.is("resumed", SM), "second resumption failed: {r}");
    ping(&mut a3).await?;
    Ok(())
}
