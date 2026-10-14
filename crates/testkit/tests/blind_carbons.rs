//! Black-box Message Carbons tests (XEP-0280), from the spec.

mod blind_util;

use blind_util::*;
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{message, Client};

/// The forwarded message inside a carbon of `kind` ("received" or "sent"), if `e` is one.
fn carbon<'a>(e: &'a Element, kind: &str) -> Option<&'a Element> {
    if e.name() != "message" {
        return None;
    }
    e.get_child(kind, ns::CARBONS)?.get_child("forwarded", ns::FORWARD)?.get_child("message", ns::CLIENT)
}

fn is_carbon(e: &Element) -> bool {
    carbon(e, "received").is_some() || carbon(e, "sent").is_some()
}

async fn expect_carbon(c: &mut Client, kind: &str, body: &str) -> anyhow::Result<Element> {
    let k = kind.to_string();
    let b = body.to_string();
    let e = c.expect(move |e| carbon(e, &k).is_some_and(|m| m.child_text("body", ns::CLIENT).as_deref() == Some(b.as_str()))).await?;
    // §7/§11: the wrapper comes from the user's own bare JID, to the receiving full JID.
    assert_eq!(e.attr("from"), c.bare().as_deref(), "carbon wrapper must come from the bare JID: {e}");
    assert_eq!(e.attr("to"), c.jid.as_deref(), "carbon wrapper is addressed to the receiving resource: {e}");
    Ok(e)
}

#[tokio::test]
async fn carbons_are_advertised_and_can_be_enabled() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let info = a.iq_get(Some(s.domain()), Element::new("query", ns::DISCO_INFO)).await?;
    let q = info.get_child("query", ns::DISCO_INFO).expect("disco#info result");
    assert!(
        q.children().any(|f| f.name() == "feature" && f.attr("var") == Some(ns::CARBONS)),
        "XEP-0280 §3: feature {} in {info}",
        ns::CARBONS
    );
    enable_carbons(&mut a).await?;
    let r = a.iq_set(None, Element::new("disable", ns::CARBONS)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    Ok(())
}

#[tokio::test]
async fn received_carbons_go_to_other_enabled_resources() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut phone = s.online("alice", PW, "phone").await?;
    let mut laptop = s.online("alice", PW, "laptop").await?;
    let mut tablet = s.online("alice", PW, "tablet").await?; // never enables carbons
    enable_carbons(&mut phone).await?;
    enable_carbons(&mut laptop).await?;
    let mut b = s.online("bob", PW, "desk").await?;
    settle(&mut tablet).await?;

    b.send(&message(&full("alice", "phone"), "chat", "hello phone")).await?;
    expect_body(&mut phone, "hello phone").await?;
    let c = expect_carbon(&mut laptop, "received", "hello phone").await?;
    let inner = carbon(&c, "received").expect("inner");
    assert_eq!(inner.attr("from"), Some(full("bob", "desk").as_str()));
    assert_eq!(inner.attr("to"), Some(full("alice", "phone").as_str()));
    assert_none(&mut tablet, "a carbon (carbons not enabled)", |e| is_carbon(e) || e.name() == "message").await?;
    assert_none(&mut phone, "a carbon of a message it received itself", is_carbon).await?;
    Ok(())
}

#[tokio::test]
async fn sent_carbons_go_to_other_enabled_resources_not_the_sender() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut phone = s.online("alice", PW, "phone").await?;
    let mut laptop = s.online("alice", PW, "laptop").await?;
    enable_carbons(&mut phone).await?;
    enable_carbons(&mut laptop).await?;
    let mut b = s.online("bob", PW, "desk").await?;

    phone.send(&message(&bare("bob"), "chat", "from my phone")).await?;
    expect_body(&mut b, "from my phone").await?;
    let c = expect_carbon(&mut laptop, "sent", "from my phone").await?;
    let inner = carbon(&c, "sent").expect("inner");
    assert_eq!(inner.attr("from"), Some(full("alice", "phone").as_str()), "the original from is the sender: {c}");
    assert_eq!(inner.attr("to"), Some(bare("bob").as_str()));
    // §8: "SHOULD NOT copy to the sending full JID".
    assert_none(&mut phone, "a sent carbon of its own message", is_carbon).await?;
    Ok(())
}

#[tokio::test]
async fn private_messages_are_not_carbon_copied() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut phone = s.online("alice", PW, "phone").await?;
    let mut laptop = s.online("alice", PW, "laptop").await?;
    enable_carbons(&mut phone).await?;
    enable_carbons(&mut laptop).await?;
    let mut b = s.online("bob", PW, "desk").await?;
    settle(&mut laptop).await?;

    let private = |to: &str, body: &str| {
        message(to, "chat", body).child(Element::new("private", ns::CARBONS)).child(Element::new("no-copy", ns::HINTS))
    };
    phone.send(&private(&bare("bob"), "secret out")).await?;
    expect_body(&mut b, "secret out").await?;
    b.send(&private(&full("alice", "phone"), "secret in")).await?;
    expect_body(&mut phone, "secret in").await?;
    // §9: neither the sender's nor the recipient's server copies it.
    assert_none(&mut laptop, "a carbon of a <private/> message", |e| e.name() == "message").await?;
    Ok(())
}

#[tokio::test]
async fn groupchat_messages_are_not_carbon_copied() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut phone = s.online("alice", PW, "phone").await?;
    let mut laptop = s.online("alice", PW, "laptop").await?;
    enable_carbons(&mut phone).await?;
    enable_carbons(&mut laptop).await?;
    let mut b = s.online("bob", PW, "desk").await?;
    settle(&mut laptop).await?;

    b.send(&message(&full("alice", "phone"), "groupchat", "room chatter")).await?;
    expect_body(&mut phone, "room chatter").await?;
    // §6.1: "A <message/> of type "groupchat" SHOULD NOT be carbon-copied."
    assert_none(&mut laptop, "a carbon of a groupchat message", |e| e.name() == "message").await?;
    Ok(())
}

#[tokio::test]
async fn message_to_bare_jid_reaches_each_enabled_resource_exactly_once() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut phone = s.online("alice", PW, "phone").await?;
    let mut laptop = s.online("alice", PW, "laptop").await?;
    enable_carbons(&mut phone).await?;
    enable_carbons(&mut laptop).await?;
    let mut b = s.online("bob", PW, "desk").await?;
    settle(&mut phone).await?;
    settle(&mut laptop).await?;

    b.send(&message(&bare("alice"), "chat", "to everyone")).await?;
    // §7: a copy goes to each enabled resource that did not already receive the original.
    for c in [&mut phone, &mut laptop] {
        let who = me(c);
        let got: Vec<Element> = settle(c)
            .await?
            .into_iter()
            .filter(|e| {
                is_message_with_body(e, "to everyone")
                    || carbon(e, "received").is_some_and(|m| m.child_text("body", ns::CLIENT).as_deref() == Some("to everyone"))
            })
            .collect();
        assert_eq!(got.len(), 1, "{who} should get the message exactly once (directly or as a carbon), got {got:?}");
    }
    Ok(())
}
