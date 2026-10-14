//! Black-box presence subscription tests between local accounts (RFC 6121 §3), from the spec.
//!
//! Each test checks the presence side first and the roster side (pushes, `subscription`/`ask`)
//! last, so a roster bug does not hide a presence bug.

use crate::blind_util;

use blind_util::*;
use quark_testkit::quark_core::{ns, Element};

fn is_from(e: &Element, from: &str) -> bool {
    e.name() == "presence" && e.attr("from") == Some(from)
}

#[tokio::test]
async fn subscribe_delivers_request_from_bare_jid_and_pushes_ask() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "laptop").await?;

    send_presence(&mut a, &bare("bob"), "subscribe").await?;

    // §3.1.2/§3.1.3: the request is stamped with the user's bare JID.
    let req = b.expect(|e| e.name() == "presence" && ptype(e) == "subscribe").await?;
    assert_eq!(req.attr("from"), Some(bare("alice").as_str()), "subscription requests come from the bare JID: {req}");

    // §3.1.2: the user's server pushes the item with ask='subscribe' (creating it if needed).
    let pushed = expect_push(&mut a, &bare("bob")).await?;
    assert_eq!((pushed.subscription.as_str(), pushed.ask.as_deref()), ("none", Some("subscribe")));
    let it = roster_item(&mut a, &bare("bob")).await?.expect("bob is in alice's roster");
    assert_eq!((it.subscription.as_str(), it.ask.as_deref()), ("none", Some("subscribe")));
    Ok(())
}

#[tokio::test]
async fn approving_starts_presence_flow_one_way() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    send_presence(&mut a, &bare("bob"), "subscribe").await?;
    expect_presence(&mut b, &bare("alice"), "subscribe").await?;
    settle(&mut a).await?;

    send_presence(&mut b, &bare("alice"), "subscribed").await?;
    // §3.1.6: the user receives 'subscribed' from the contact's bare JID …
    expect_presence(&mut a, &bare("bob"), "subscribed").await?;
    // … and (§3.1.5) the contact's current presence from each available resource.
    expect_presence(&mut a, &full("bob", "laptop"), "available").await?;

    // From now on bob's presence reaches alice …
    settle(&mut a).await?;
    b.send(&Element::new("presence", ns::CLIENT).text_child("show", ns::CLIENT, "away")).await?;
    let p = expect_presence(&mut a, &full("bob", "laptop"), "available").await?;
    assert_eq!(p.child_text("show", ns::CLIENT).as_deref(), Some("away"));

    // … but alice's does not reach bob (bob only has 'from').
    settle(&mut b).await?;
    a.send(&Element::new("presence", ns::CLIENT).text_child("show", ns::CLIENT, "dnd")).await?;
    assert_none(&mut b, "alice's presence (bob is not subscribed to her)", |e| is_from(e, &full("alice", "phone"))).await?;
    Ok(())
}

#[tokio::test]
async fn approving_pushes_to_and_from_to_both_rosters() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    send_presence(&mut a, &bare("bob"), "subscribe").await?;
    expect_presence(&mut b, &bare("alice"), "subscribe").await?;
    expect_push(&mut a, &bare("bob")).await?;

    send_presence(&mut b, &bare("alice"), "subscribed").await?;
    // §3.1.5: the contact's roster gets the user with 'from'; §3.1.6: the user's gets 'to', no ask.
    let pb = expect_push(&mut b, &bare("alice")).await?;
    assert_eq!((pb.subscription.as_str(), pb.ask.as_deref()), ("from", None));
    let pa = expect_push(&mut a, &bare("bob")).await?;
    assert_eq!((pa.subscription.as_str(), pa.ask.as_deref()), ("to", None));
    assert_eq!(roster_item(&mut a, &bare("bob")).await?.map(|i| i.subscription), Some("to".into()));
    assert_eq!(roster_item(&mut b, &bare("alice")).await?.map(|i| i.subscription), Some("from".into()));
    Ok(())
}

#[tokio::test]
async fn pending_request_is_delivered_when_the_contact_comes_online() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    send_presence(&mut a, &bare("bob"), "subscribe").await?;
    settle(&mut a).await?;

    // §3.1.3: delivered whenever the contact creates an available resource.
    let mut b = s.online("bob", PW, "laptop").await?;
    expect_presence(&mut b, &bare("alice"), "subscribe").await?;
    Ok(())
}

#[tokio::test]
async fn pending_request_is_redelivered_at_every_initial_presence_until_answered() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    send_presence(&mut a, &bare("bob"), "subscribe").await?;
    expect_presence(&mut b, &bare("alice"), "subscribe").await?;
    b.close().await?;
    tokio::time::sleep(QUIET).await;

    let mut b = s.online("bob", PW, "laptop").await?;
    expect_presence(&mut b, &bare("alice"), "subscribe").await?;
    Ok(())
}

#[tokio::test]
async fn denying_a_request_informs_the_user_and_is_not_redelivered() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    send_presence(&mut a, &bare("bob"), "subscribe").await?;
    expect_presence(&mut b, &bare("alice"), "subscribe").await?;

    send_presence(&mut b, &bare("alice"), "unsubscribed").await?;
    // §3.2.3: the user gets 'unsubscribed' from the contact's bare JID.
    expect_presence(&mut a, &bare("bob"), "unsubscribed").await?;

    b.close().await?;
    tokio::time::sleep(QUIET).await;
    let mut b = s.online("bob", PW, "laptop").await?;
    assert_none(&mut b, "a denied subscription request", |e| e.name() == "presence" && ptype(e) == "subscribe").await?;

    // The user's roster shows the contact with neither subscription nor ask.
    let it = roster_item(&mut a, &bare("bob")).await?.expect("bob stays in alice's roster");
    assert_eq!((it.subscription.as_str(), it.ask.as_deref()), ("none", None));
    Ok(())
}

#[tokio::test]
async fn unsubscribe_stops_presence_and_updates_both_rosters() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    subscribe(&mut a, &mut b).await?;

    send_presence(&mut a, &bare("bob"), "unsubscribe").await?;
    // §3.3.3: the contact gets 'unsubscribe' from the bare JID, and the contact's server sends
    // unavailable presence from the contact's resources to the user.
    expect_presence(&mut b, &bare("alice"), "unsubscribe").await?;
    expect_presence(&mut a, &full("bob", "laptop"), "unavailable").await?;

    settle(&mut a).await?;
    b.send(&Element::new("presence", ns::CLIENT).text_child("show", ns::CLIENT, "xa")).await?;
    assert_none(&mut a, "bob's presence after unsubscribing", |e| is_from(e, &full("bob", "laptop"))).await?;

    // §3.3.2/§3.3.3: both rosters go back to 'none'.
    let ai = roster_item(&mut a, &bare("bob")).await?.expect("bob in alice's roster");
    assert_eq!((ai.subscription.as_str(), ai.ask.as_deref()), ("none", None));
    let bi = roster_item(&mut b, &bare("alice")).await?.expect("alice in bob's roster");
    assert_eq!(bi.subscription, "none");
    Ok(())
}

#[tokio::test]
async fn revoking_a_subscription_stops_presence_and_updates_both_rosters() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    subscribe(&mut a, &mut b).await?;

    // bob cancels alice's subscription to him.
    send_presence(&mut b, &bare("alice"), "unsubscribed").await?;
    // §3.2.3: the user gets 'unsubscribed' and unavailable from the contact's resources.
    expect_presence(&mut a, &bare("bob"), "unsubscribed").await?;
    expect_presence(&mut a, &full("bob", "laptop"), "unavailable").await?;

    settle(&mut a).await?;
    b.send(&Element::new("presence", ns::CLIENT).text_child("show", ns::CLIENT, "chat")).await?;
    assert_none(&mut a, "bob's presence after he revoked", |e| is_from(e, &full("bob", "laptop"))).await?;

    // §3.2.2/§3.2.3: both rosters go to 'none'.
    let bi = roster_item(&mut b, &bare("alice")).await?.expect("alice in bob's roster");
    assert_eq!(bi.subscription, "none");
    let ai = roster_item(&mut a, &bare("bob")).await?.expect("bob in alice's roster");
    assert_eq!((ai.subscription.as_str(), ai.ask.as_deref()), ("none", None));
    Ok(())
}

#[tokio::test]
async fn mutual_subscription_is_both_and_presence_flows_both_ways() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    mutual(&mut a, &mut b).await?;

    a.send(&Element::new("presence", ns::CLIENT).text_child("status", ns::CLIENT, "from alice")).await?;
    let p = expect_presence(&mut b, &full("alice", "phone"), "available").await?;
    assert_eq!(p.child_text("status", ns::CLIENT).as_deref(), Some("from alice"));
    b.send(&Element::new("presence", ns::CLIENT).text_child("status", ns::CLIENT, "from bob")).await?;
    let p = expect_presence(&mut a, &full("bob", "laptop"), "available").await?;
    assert_eq!(p.child_text("status", ns::CLIENT).as_deref(), Some("from bob"));

    assert_eq!(roster_item(&mut a, &bare("bob")).await?.map(|i| i.subscription), Some("both".into()));
    assert_eq!(roster_item(&mut b, &bare("alice")).await?.map(|i| i.subscription), Some("both".into()));
    Ok(())
}

#[tokio::test]
async fn pre_approval_is_advertised() -> anyhow::Result<()> {
    let s = server(&["bob"]).await?;
    let b = s.login("bob", PW).await?;
    let f = b.features.as_ref().expect("features");
    assert!(f.get_child("sub", ns::PRE_APPROVAL).is_some(), "RFC 6121 §3.4.1: <sub xmlns='urn:xmpp:features:pre-approval'/> in {f}");
    Ok(())
}

#[tokio::test]
async fn pre_approved_subscription_is_approved_automatically() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "laptop").await?;

    // §3.4.2: bob pre-approves alice; nothing is sent to her.
    send_presence(&mut b, &bare("alice"), "subscribed").await?;
    assert_none(&mut a, "anything from a pre-approval", |e| is_from(e, &bare("bob"))).await?;

    // §3.1.3: alice's later request is answered on bob's behalf, and bob's presence follows.
    send_presence(&mut a, &bare("bob"), "subscribe").await?;
    expect_presence(&mut a, &bare("bob"), "subscribed").await?;
    expect_presence(&mut a, &full("bob", "laptop"), "available").await?;

    assert_eq!(roster_item(&mut a, &bare("bob")).await?.map(|i| i.subscription), Some("to".into()));
    let bi = roster_item(&mut b, &bare("alice")).await?.expect("alice in bob's roster");
    assert_eq!(bi.subscription, "from");
    Ok(())
}

#[tokio::test]
async fn pre_approval_is_pushed_with_approved_true() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    send_presence(&mut b, &bare("alice"), "subscribed").await?;
    // §3.4.2: the contact's server adds the user with approved='true' and pushes it.
    let pb = expect_push(&mut b, &bare("alice")).await?;
    assert!(pb.approved, "pre-approved item has approved='true': {pb:?}");
    assert_eq!((pb.subscription.as_str(), pb.ask.as_deref()), ("none", None));
    let bi = roster_item(&mut b, &bare("alice")).await?.expect("alice in bob's roster");
    assert!(bi.approved, "{bi:?}");
    Ok(())
}

#[tokio::test]
async fn subscribing_again_when_already_subscribed_is_auto_approved() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    subscribe(&mut a, &mut b).await?;

    send_presence(&mut a, &bare("bob"), "subscribe").await?;
    // §3.1.3: the contact's server MUST auto-reply 'subscribed'; the request is not delivered.
    expect_presence(&mut a, &bare("bob"), "subscribed").await?;
    assert_none(&mut b, "a second subscription request", |e| e.name() == "presence" && ptype(e) == "subscribe").await?;
    Ok(())
}

#[tokio::test]
async fn removing_a_roster_item_cancels_subscriptions_both_ways() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    mutual(&mut a, &mut b).await?;

    let r = roster_set(&mut a, item(&bare("bob")).attr_set("subscription", "remove")).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");

    // §2.5.2: the server sends unsubscribe and unsubscribed to the contact …
    expect_presence(&mut b, &bare("alice"), "unsubscribe").await?;
    expect_presence(&mut b, &bare("alice"), "unsubscribed").await?;
    // … who sees the user go unavailable, and the user sees the contact go unavailable.
    expect_presence(&mut b, &full("alice", "phone"), "unavailable").await?;
    expect_presence(&mut a, &full("bob", "laptop"), "unavailable").await?;
    settle(&mut a).await?;
    b.send(&Element::new("presence", ns::CLIENT)).await?;
    assert_none(&mut a, "bob's presence after removal", |e| is_from(e, &full("bob", "laptop"))).await?;

    // The contact's item stays, with subscription 'none'; the user's is gone.
    settle(&mut b).await?;
    let bi = roster_item(&mut b, &bare("alice")).await?.expect("bob keeps alice in his roster");
    assert_eq!((bi.subscription.as_str(), bi.ask.as_deref()), ("none", None));
    assert!(roster_item(&mut a, &bare("bob")).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn subscription_request_to_a_nonexistent_account_gets_no_error() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    settle(&mut a).await?;
    send_presence(&mut a, &bare("nobody"), "subscribe").await?;
    // RFC 6121 §8.5.1: presence to a non-existent account is silently ignored
    // (§3.1.3 also allows answering with 'unsubscribed'); never a presence error.
    assert_none(&mut a, "a presence error", |e| e.name() == "presence" && ptype(e) == "error").await?;
    Ok(())
}
