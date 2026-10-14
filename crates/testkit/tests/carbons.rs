//! Message Carbons (XEP-0280) and the Client State Indication feature, end to end.

use std::time::Duration;

use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{message, Client, TestServer, DOMAIN};

const QUIET: Duration = Duration::from_millis(300);

async fn carbons_on(c: &mut Client) -> anyhow::Result<()> {
    let r = c.iq_set(None, Element::new("enable", ns::CARBONS)).await?;
    anyhow::ensure!(r.attr("type") == Some("result"), "enable failed: {r}");
    Ok(())
}

fn carbon<'a>(e: &'a Element, dir: &str) -> Option<&'a Element> {
    e.get_child(dir, ns::CARBONS)?.get_child("forwarded", ns::FORWARD)?.get_child("message", ns::CLIENT)
}

#[tokio::test]
async fn features_and_who_may_turn_carbons_on() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    s.add_user("bob", "password-b").await?;
    let mut alice = s.login("alice", "password-a").await?;
    let features = alice.features.clone().expect("stream features");
    assert!(features.has_child("csi", ns::CSI), "{features}");

    let info = alice.iq_get(Some(DOMAIN), Element::new("query", ns::DISCO_INFO)).await?;
    assert!(info.to_xml().contains(ns::CARBONS), "{info}");

    carbons_on(&mut alice).await?;
    let r = alice.iq_set(None, Element::new("disable", ns::CARBONS)).await?;
    assert_eq!(r.attr("type"), Some("result"));
    let r = alice.iq_get(None, Element::new("enable", ns::CARBONS)).await?;
    assert_eq!(r.attr("type"), Some("error"));
    let r = alice.iq_set(Some(&format!("bob@{DOMAIN}")), Element::new("enable", ns::CARBONS)).await?;
    assert_eq!(r.attr("type"), Some("error"));
    Ok(())
}

#[tokio::test]
async fn every_device_follows_the_conversation() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    s.add_user("bob", "password-b").await?;
    let mut phone = s.online("alice", "password-a", "phone").await?;
    let mut laptop = s.online("alice", "password-a", "laptop").await?;
    let mut bob = s.online("bob", "password-b", "desk").await?;
    carbons_on(&mut phone).await?;
    carbons_on(&mut laptop).await?;

    // Sent from the phone: the laptop gets a "sent" copy.
    phone.send(&message(&format!("bob@{DOMAIN}"), "chat", "from my phone")).await?;
    let c = laptop.expect(|e| e.has_child("sent", ns::CARBONS)).await?;
    assert_eq!(c.attr("from"), Some(&*format!("alice@{DOMAIN}")));
    assert_eq!(carbon(&c, "sent").and_then(|m| m.child_text("body", ns::CLIENT)).as_deref(), Some("from my phone"));
    let got = bob.expect(|e| e.name() == "message").await?;
    // Alice's archive id stays with Alice.
    let alice_bare = format!("alice@{DOMAIN}");
    assert!(!got.children().any(|c| c.is("stanza-id", ns::SID) && c.attr("by") == Some(&alice_bare)), "{got}");

    // To the phone's full JID: the laptop gets a "received" copy.
    bob.send(&message(&format!("alice@{DOMAIN}/phone"), "chat", "just to your phone")).await?;
    phone.expect(|e| e.name() == "message" && e.has_child("body", ns::CLIENT)).await?;
    let c = laptop.expect(|e| e.has_child("received", ns::CARBONS)).await?;
    assert_eq!(carbon(&c, "received").and_then(|m| m.child_text("body", ns::CLIENT)).as_deref(), Some("just to your phone"));

    // Receipts count as conversation too.
    let receipt = Element::new("message", ns::CLIENT)
        .attr_set("to", format!("alice@{DOMAIN}/phone"))
        .child(Element::new("received", ns::RECEIPTS).attr_set("id", "x"));
    bob.send(&receipt).await?;
    laptop.expect(|e| carbon(e, "received").is_some_and(|m| m.has_child("received", ns::RECEIPTS))).await?;

    // Marked private: no copies.
    let mut private = message(&format!("bob@{DOMAIN}"), "chat", "between us");
    private.append(Element::new("private", ns::CARBONS));
    phone.send(&private).await?;
    bob.expect(|e| e.name() == "message").await?;
    while let Some(e) = laptop.recv_within(QUIET).await? {
        assert!(e.child_ns(ns::CARBONS).is_none(), "a private message was copied: {e}");
    }
    Ok(())
}

#[tokio::test]
async fn hidden_devices_with_carbons_still_get_copies() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    s.add_user("bob", "password-b").await?;
    let mut phone = s.online("alice", "password-a", "phone").await?;
    // Signed in, carbons on, but never sent presence (a background sync client).
    let mut watcher = s.login_as("alice", "password-a", "watcher").await?;
    carbons_on(&mut watcher).await?;
    let mut bob = s.online("bob", "password-b", "desk").await?;

    bob.send(&message(&format!("alice@{DOMAIN}"), "chat", "hi alice")).await?;
    phone.expect(|e| e.name() == "message" && e.has_child("body", ns::CLIENT)).await?;
    let c = watcher.expect(|e| e.has_child("received", ns::CARBONS)).await?;
    assert_eq!(carbon(&c, "received").and_then(|m| m.child_text("body", ns::CLIENT)).as_deref(), Some("hi alice"));
    Ok(())
}
