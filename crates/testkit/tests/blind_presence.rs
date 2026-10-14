//! Black-box presence tests (RFC 6121 §4), from the spec.

mod blind_util;

use blind_util::*;
use quark_testkit::quark_core::{ns, Element};

#[tokio::test]
async fn initial_presence_goes_to_subscribers_and_own_resources_only() -> anyhow::Result<()> {
    let s = server(&["alice", "bob", "carol"]).await?;
    let mut phone = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    let mut c = s.online("carol", PW, "desk").await?;
    mutual(&mut phone, &mut b).await?;
    settle(&mut c).await?;

    let mut tablet = s.online("alice", PW, "tablet").await?;
    // §4.2.2: to contacts with 'from'/'both' …
    expect_presence(&mut b, &full("alice", "tablet"), "available").await?;
    // … and to the user's other available resources.
    expect_presence(&mut phone, &full("alice", "tablet"), "available").await?;
    settle(&mut tablet).await?;
    // Not to people without a subscription.
    assert_none(&mut c, "alice's presence (no subscription)", |e| {
        e.name() == "presence" && e.attr("from") == Some(&full("alice", "tablet"))
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn initial_presence_is_echoed_to_the_sending_resource() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    // `online()` itself waits for this echo, so send initial presence by hand here.
    let mut phone = s.login_as("alice", PW, "phone").await?;
    phone.send(&Element::new("presence", ns::CLIENT)).await?;
    // §4.2.2: "to all of the user's available resources, including the resource that generated
    // the presence notification in the first place".
    expect_presence(&mut phone, &full("alice", "phone"), "available").await?;
    let mut tablet = s.login_as("alice", PW, "tablet").await?;
    tablet.send(&Element::new("presence", ns::CLIENT)).await?;
    expect_presence(&mut tablet, &full("alice", "tablet"), "available").await?;
    expect_presence(&mut phone, &full("alice", "tablet"), "available").await?;
    Ok(())
}

#[tokio::test]
async fn new_resource_receives_contacts_current_presence() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut phone = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    mutual(&mut phone, &mut b).await?;
    b.send(&Element::new("presence", ns::CLIENT).text_child("show", ns::CLIENT, "dnd").text_child("status", ns::CLIENT, "busy")).await?;
    expect_presence(&mut phone, &full("bob", "laptop"), "available").await?;

    // §4.3.2: probes are answered with the full last presence of each available resource.
    let mut tablet = s.online("alice", PW, "tablet").await?;
    let p = expect_presence(&mut tablet, &full("bob", "laptop"), "available").await?;
    assert_eq!(p.child_text("show", ns::CLIENT).as_deref(), Some("dnd"), "{p}");
    assert_eq!(p.child_text("status", ns::CLIENT).as_deref(), Some("busy"), "{p}");
    Ok(())
}

#[tokio::test]
async fn closing_the_stream_broadcasts_unavailable() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut phone = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    mutual(&mut phone, &mut b).await?;
    let mut tablet = s.online("alice", PW, "tablet").await?;
    expect_presence(&mut b, &full("alice", "tablet"), "available").await?;
    expect_presence(&mut phone, &full("alice", "tablet"), "available").await?;
    settle(&mut tablet).await?;

    tablet.close().await?;
    // §4.5.2: the server broadcasts unavailable to contacts and the user's other resources.
    expect_presence(&mut b, &full("alice", "tablet"), "unavailable").await?;
    expect_presence(&mut phone, &full("alice", "tablet"), "unavailable").await?;
    Ok(())
}

#[tokio::test]
async fn dropped_connection_broadcasts_unavailable() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut phone = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    mutual(&mut phone, &mut b).await?;

    phone.drop_connection();
    // §4.5.2: "the server MUST generate the unavailable presence broadcast on the user's behalf".
    expect_presence(&mut b, &full("alice", "phone"), "unavailable").await?;
    Ok(())
}

#[tokio::test]
async fn explicit_unavailable_is_broadcast_with_status() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut phone = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    mutual(&mut phone, &mut b).await?;

    phone
        .send(&Element::new("presence", ns::CLIENT).attr_set("type", "unavailable").text_child("status", ns::CLIENT, "gone fishing"))
        .await?;
    let p = expect_presence(&mut b, &full("alice", "phone"), "unavailable").await?;
    assert_eq!(p.child_text("status", ns::CLIENT).as_deref(), Some("gone fishing"));
    Ok(())
}

#[tokio::test]
async fn directed_presence_to_a_non_contact_gets_unavailable_on_logout() -> anyhow::Result<()> {
    let s = server(&["alice", "carol"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let mut c = s.online("carol", PW, "desk").await?;
    settle(&mut a).await?;

    a.send(&Element::new("presence", ns::CLIENT).attr_set("to", full("carol", "desk")).text_child("status", ns::CLIENT, "hi carol"))
        .await?;
    let p = expect_presence(&mut c, &full("alice", "phone"), "available").await?;
    assert_eq!(p.child_text("status", ns::CLIENT).as_deref(), Some("hi carol"));

    a.close().await?;
    // §4.6.3: the server routes unavailable to entities that got directed presence.
    expect_presence(&mut c, &full("alice", "phone"), "unavailable").await?;
    Ok(())
}

#[tokio::test]
async fn directed_presence_to_a_bare_jid_reaches_its_available_resources() -> anyhow::Result<()> {
    let s = server(&["alice", "carol"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let mut c1 = s.online("carol", PW, "desk").await?;
    let mut c2 = s.online("carol", PW, "mobile").await?;
    settle(&mut c1).await?;

    a.send(&Element::new("presence", ns::CLIENT).attr_set("to", bare("carol"))).await?;
    // RFC 6121 §8.5.2.1.2: presence to a bare JID goes to all available resources.
    expect_presence(&mut c1, &full("alice", "phone"), "available").await?;
    expect_presence(&mut c2, &full("alice", "phone"), "available").await?;
    Ok(())
}

#[tokio::test]
async fn directed_unavailable_is_not_repeated_on_logout() -> anyhow::Result<()> {
    let s = server(&["alice", "carol"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let mut c = s.online("carol", PW, "desk").await?;
    a.send(&Element::new("presence", ns::CLIENT).attr_set("to", full("carol", "desk"))).await?;
    expect_presence(&mut c, &full("alice", "phone"), "available").await?;
    send_presence(&mut a, &full("carol", "desk"), "unavailable").await?;
    expect_presence(&mut c, &full("alice", "phone"), "unavailable").await?;

    a.close().await?;
    // §4.6.3: unless directed unavailable was already sent, which removes carol from the list.
    assert_none(&mut c, "a second unavailable", |e| is_presence(e, &full("alice", "phone"), "unavailable")).await?;
    Ok(())
}

#[tokio::test]
async fn presence_to_a_nonexistent_account_is_silently_ignored() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    settle(&mut a).await?;
    a.send(&Element::new("presence", ns::CLIENT).attr_set("to", bare("nobody"))).await?;
    a.send(&Element::new("presence", ns::CLIENT).attr_set("to", full("nobody", "x"))).await?;
    // RFC 6121 §8.5.1: available presence to a non-existent user is silently ignored.
    assert_none(&mut a, "a reply to presence sent to nobody", |e| {
        e.name() == "presence" && e.attr("from").is_some_and(|f| f.starts_with("nobody@"))
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn presence_errors_from_a_contact_are_delivered() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    settle(&mut a).await?;
    // A presence error (e.g. bob's client rejecting directed presence) is routed like any presence.
    let err = Element::new("presence", ns::CLIENT)
        .attr_set("to", full("alice", "phone"))
        .attr_set("type", "error")
        .child(Element::new("error", ns::CLIENT).attr_set("type", "cancel").child(Element::new("service-unavailable", ns::STANZAS)));
    b.send(&err).await?;
    let got = expect_presence(&mut a, &full("bob", "laptop"), "error").await?;
    assert_eq!(error_condition(&got).as_deref(), Some("service-unavailable"), "{got}");
    // And the server never answers a presence error with another error.
    assert_none(&mut b, "an error in reply to a presence error", |e| ptype(e) == "error").await?;
    Ok(())
}
