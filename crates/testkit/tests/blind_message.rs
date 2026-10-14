//! Black-box message routing tests (RFC 6121 §8.5, RFC 6120 §8.1.2.1), from the spec.

use crate::blind_util;

use blind_util::*;
use quark_testkit::message;
use quark_testkit::quark_core::Element;

fn msg_from(e: &Element, from: &str) -> bool {
    e.name() == "message" && e.attr("from") == Some(from)
}

#[tokio::test]
async fn message_to_an_online_full_jid_goes_only_to_that_resource() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut phone = s.online("alice", PW, "phone").await?;
    let mut laptop = s.online("alice", PW, "laptop").await?;
    let mut b = s.online("bob", PW, "desk").await?;
    settle(&mut laptop).await?;

    let m = message(&full("alice", "phone"), "chat", "just the phone");
    b.send(&m).await?;
    let got = expect_body(&mut phone, "just the phone").await?;
    assert_eq!(got.attr("from"), Some(full("bob", "desk").as_str()));
    assert_eq!(got.attr("id"), m.attr("id"), "the id is kept");
    assert_none(&mut laptop, "a message for the phone", |e| e.name() == "message").await?;
    Ok(())
}

#[tokio::test]
async fn message_to_bare_jid_goes_to_highest_non_negative_and_never_negative_priority() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut high = online_with_priority(&s, "alice", "high", 5).await?;
    let mut low = online_with_priority(&s, "alice", "low", 1).await?;
    let mut hidden = online_with_priority(&s, "alice", "hidden", -1).await?;
    let mut b = s.online("bob", PW, "desk").await?;
    settle(&mut hidden).await?;
    settle(&mut low).await?;

    for kind in ["chat", "normal"] {
        b.send(&message(&bare("alice"), kind, &format!("{kind} to bare"))).await?;
        // §8.5.2.1.1: the "most available" resource(s) — or all non-negative ones — get it.
        expect_body(&mut high, &format!("{kind} to bare")).await?;
    }
    // "the server MUST NOT deliver the stanza to any available resource with a negative priority"
    assert_none(&mut hidden, "a message to the bare JID (negative priority)", |e| e.name() == "message").await?;
    // `low` may or may not get them; either is allowed.
    settle(&mut low).await?;
    Ok(())
}

#[tokio::test]
async fn message_to_bare_jid_with_only_negative_priority_is_stored_or_refused() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut hidden = online_with_priority(&s, "alice", "hidden", -1).await?;
    let mut b = s.online("bob", PW, "desk").await?;
    settle(&mut hidden).await?;

    b.send(&message(&bare("alice"), "chat", "for later")).await?;
    // §8.5.2.1.1: treated as if there were no available resource: stored offline or an error.
    assert_none(&mut hidden, "a message (negative priority)", |e| e.name() == "message").await?;
    let bounced = settle(&mut b).await?.into_iter().any(|e| e.name() == "message" && e.attr("type") == Some("error"));
    if !bounced {
        let mut phone = s.online("alice", PW, "phone").await?;
        expect_body(&mut phone, "for later").await?;
    }
    Ok(())
}

#[tokio::test]
async fn chat_to_an_offline_full_jid_goes_to_another_available_resource() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut phone = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "desk").await?;
    b.send(&message(&full("alice", "gone"), "chat", "wherever you are")).await?;
    // §8.5.3.2.1: type chat with a non-negative resource online is delivered to it.
    let got = expect_body(&mut phone, "wherever you are").await?;
    assert_eq!(got.attr("from"), Some(full("bob", "desk").as_str()));
    Ok(())
}

#[tokio::test]
async fn chat_to_an_offline_full_jid_with_nobody_online_is_stored_or_refused() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut b = s.online("bob", PW, "desk").await?;
    b.send(&message(&full("alice", "gone"), "chat", "stored for alice")).await?;
    // §8.5.3.2.1: "store the message offline for later delivery or return an error".
    let bounced = settle(&mut b).await?.into_iter().any(|e| e.name() == "message" && e.attr("type") == Some("error"));
    if !bounced {
        let mut phone = s.online("alice", PW, "phone").await?;
        expect_body(&mut phone, "stored for alice").await?;
    }
    Ok(())
}

async fn not_redirected(kind: &str) -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut phone = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "desk").await?;
    settle(&mut phone).await?;
    b.send(&message(&full("alice", "gone"), kind, &format!("{kind} for gone"))).await?;
    // §8.5.3.2.1: normal/groupchat/headline: silently ignore or error — not delivered elsewhere.
    assert_none(&mut phone, "a message addressed to another resource", |e| e.name() == "message").await?;
    for e in settle(&mut b).await? {
        if e.name() == "message" && e.attr("type") == Some("error") {
            assert_eq!(e.attr("from"), Some(full("alice", "gone").as_str()), "error comes from the addressee: {e}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn normal_to_an_offline_full_jid_is_not_redirected() -> anyhow::Result<()> {
    not_redirected("normal").await
}

#[tokio::test]
async fn headline_to_an_offline_full_jid_is_not_redirected() -> anyhow::Result<()> {
    not_redirected("headline").await
}

#[tokio::test]
async fn message_to_a_nonexistent_account_is_ignored_or_service_unavailable() -> anyhow::Result<()> {
    let s = server(&["bob"]).await?;
    let mut b = s.online("bob", PW, "desk").await?;
    settle(&mut b).await?;
    let m = message(&bare("nobody"), "chat", "anyone?");
    b.send(&m).await?;
    // RFC 6121 §8.5.1: silently ignore or <service-unavailable/>.
    for e in settle(&mut b).await? {
        if e.name() == "message" {
            assert_error(&e, &["service-unavailable"]);
            assert_eq!(e.attr("id"), m.attr("id"));
            assert_eq!(e.attr("from"), Some(bare("nobody").as_str()));
        }
    }
    Ok(())
}

#[tokio::test]
async fn groupchat_to_a_bare_account_jid_is_an_error() -> anyhow::Result<()> {
    let s = server(&["alice", "bob", "carol"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "desk").await?;
    settle(&mut a).await?;

    // With an available resource (§8.5.2.1.1) …
    let m = message(&bare("alice"), "groupchat", "not a room");
    b.send(&m).await?;
    let err = b.expect(|e| e.name() == "message" && e.attr("id") == m.attr("id")).await?;
    assert_error(&err, &["service-unavailable", "bad-request", "not-acceptable", "not-allowed", "feature-not-implemented"]);
    assert_none(&mut a, "a groupchat message to her bare JID", |e| e.name() == "message").await?;

    // … and without one (§8.5.2.2.1: "the server MUST return an error").
    let m = message(&bare("carol"), "groupchat", "not a room either");
    b.send(&m).await?;
    let err = b.expect(|e| e.name() == "message" && e.attr("id") == m.attr("id")).await?;
    assert_error(&err, &["service-unavailable", "bad-request", "not-acceptable", "not-allowed", "feature-not-implemented"]);
    Ok(())
}

#[tokio::test]
async fn headline_to_an_offline_account_is_dropped_silently() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut b = s.online("bob", PW, "desk").await?;
    b.send(&message(&bare("alice"), "headline", "breaking news")).await?;
    // §8.5.2.2.1: "the server MUST silently ignore the message".
    assert_none(&mut b, "an error for a headline", |e| e.name() == "message").await?;
    let mut a = s.online("alice", PW, "phone").await?;
    assert_none(&mut a, "a stored headline", |e| is_message_with_body(e, "breaking news")).await?;
    Ok(())
}

#[tokio::test]
async fn server_stamps_from_with_the_senders_full_jid() -> anyhow::Result<()> {
    let s = server(&["alice", "bob", "mallory"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "desk").await?;

    let spoofed = message(&full("alice", "phone"), "chat", "trust me").attr_set("from", full("mallory", "evil"));
    b.send(&spoofed).await?;
    let honest = message(&full("alice", "phone"), "chat", "no from at all");
    b.send(&honest).await?;
    // RFC 6120 §8.1.2.1: the server stamps the full JID (or kills the stream with <invalid-from/>).
    let got = expect_body(&mut a, "no from at all").await?;
    assert_eq!(got.attr("from"), Some(full("bob", "desk").as_str()));
    for e in settle(&mut a).await? {
        assert!(!msg_from(&e, &full("mallory", "evil")), "a spoofed from got through: {e}");
        if is_message_with_body(&e, "trust me") {
            assert_eq!(e.attr("from"), Some(full("bob", "desk").as_str()), "{e}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn message_to_own_bare_jid_is_delivered_to_self() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut phone = s.online("alice", PW, "phone").await?;
    phone.send(&message(&bare("alice"), "chat", "note to self")).await?;
    let got = expect_body(&mut phone, "note to self").await?;
    assert_eq!(got.attr("from"), Some(full("alice", "phone").as_str()));
    Ok(())
}

#[tokio::test]
async fn message_between_own_resources() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut phone = s.online("alice", PW, "phone").await?;
    let mut laptop = s.online("alice", PW, "laptop").await?;
    phone.send(&message(&full("alice", "laptop"), "chat", "to my laptop")).await?;
    let got = expect_body(&mut laptop, "to my laptop").await?;
    assert_eq!(got.attr("from"), Some(full("alice", "phone").as_str()));
    Ok(())
}
