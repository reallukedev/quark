//! XEP-0280 Message Carbons across three devices, with XEP-0313 / XEP-0359 ids consistent between
//! the original, the carbon copies and the archive.

use crate::blind_xep;

use std::time::Duration;

use blind_xep::*;
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::Client;

const SHORT: Duration = Duration::from_millis(300);

async fn enable_carbons(c: &mut Client) -> anyhow::Result<()> {
    let r = c.iq_set(None, Element::new("enable", ns::CARBONS)).await?;
    anyhow::ensure!(r.attr("type") == Some("result"), "carbons enable failed: {r}");
    Ok(())
}

/// The message inside `<received/>` or `<sent/>` of a carbon copy.
fn carbon_inner<'a>(el: &'a Element, kind: &str) -> Option<&'a Element> {
    el.get_child(kind, ns::CARBONS)?.get_child("forwarded", ns::FORWARD)?.get_child("message", ns::CLIENT)
}

fn is_carbon(el: &Element, kind: &str, body: &str) -> bool {
    el.name() == "message" && carbon_inner(el, kind).and_then(|m| m.child_text("body", ns::CLIENT)).as_deref() == Some(body)
}

#[tokio::test]
async fn three_devices_received_and_sent_carbons_match_archive() -> anyhow::Result<()> {
    let s = server().await?;
    s.make_contacts("alice", "bob").await?;
    let mut phone = s.online("alice", PW, "phone").await?;
    let mut laptop = s.online("alice", PW, "laptop").await?;
    let mut tablet = s.online("alice", PW, "tablet").await?;
    for c in [&mut phone, &mut laptop, &mut tablet] {
        enable_carbons(c).await?;
    }
    let mut bob = s.online("bob", PW, "pc").await?;
    for c in [&mut phone, &mut laptop, &mut tablet] {
        drain(c, SHORT).await?;
    }
    let me = bare("alice");

    // Incoming, to the phone's full JID.
    let m = quark_testkit::message(phone.jid.as_deref().unwrap_or_default(), "chat", "to your phone");
    bob.send(&m).await?;
    let orig = phone.expect(|e| e.name() == "message" && e.child_text("body", ns::CLIENT).as_deref() == Some("to your phone")).await?;
    let sid = stanza_id_by(&orig, &me).unwrap_or_else(|| panic!("XEP-0359: no stanza-id by {me} on delivery: {orig}"));
    for (name, c) in [("laptop", &mut laptop), ("tablet", &mut tablet)] {
        let cc = c.expect(|e| is_carbon(e, "received", "to your phone")).await?;
        assert_eq!(cc.attr("from"), Some(me.as_str()), "XEP-0280 §6 carbon must come from the bare JID ({name}): {cc}");
        assert_eq!(cc.attr("to"), c.jid.as_deref(), "{name}: {cc}");
        let inner = carbon_inner(&cc, "received").expect("inner");
        assert_eq!(stanza_id_by(inner, &me).as_deref(), Some(sid.as_str()), "{name}: carbon's stanza-id differs from the original's: {cc}");
        c.expect_silence(SHORT).await?;
    }
    phone.expect_silence(SHORT).await?;

    // Outgoing, from the laptop.
    let m = quark_testkit::message(&bare("bob"), "chat", "from my laptop").attr_set("id", "out-1");
    laptop.send(&m).await?;
    bob.expect(|e| e.child_text("body", ns::CLIENT).as_deref() == Some("from my laptop")).await?;
    let mut sent_sids = Vec::new();
    for (name, c) in [("phone", &mut phone), ("tablet", &mut tablet)] {
        let cc = c.expect(|e| is_carbon(e, "sent", "from my laptop")).await?;
        assert_eq!(cc.attr("from"), Some(me.as_str()), "{name}: {cc}");
        let inner = carbon_inner(&cc, "sent").expect("inner");
        assert_eq!(inner.attr("id"), Some("out-1"), "{name}: sent carbon must keep the id: {cc}");
        assert_eq!(inner.attr("from"), laptop.jid.as_deref(), "{name}: {cc}");
        if let Some(id) = stanza_id_by(inner, &me) {
            sent_sids.push(id);
        }
    }
    laptop.expect_silence(SHORT).await?;

    // The archive has each message once, with matching ids.
    let page = mam_all(&mut tablet, None).await?;
    assert!(page.ok(), "{}", page.iq);
    assert_eq!(page.bodies(), vec!["to your phone", "from my laptop"], "archive: {:?}", page.wrappers);
    let ids = page.ids();
    assert_eq!(ids[0], sid, "archive id of the received message differs from its stanza-id");
    for id in &sent_sids {
        assert_eq!(id, &ids[1], "sent carbon stanza-id differs from the archive id");
    }
    // XEP-0313 §3.5: the server SHOULD include the stanza-id in the forwarded message of carbons.
    assert_eq!(sent_sids.len(), 2, "XEP-0313 §3.5 SHOULD: sent carbons lack <stanza-id by={me}>");
    Ok(())
}

#[tokio::test]
async fn bare_jid_message_reaches_all_and_is_archived_once() -> anyhow::Result<()> {
    let s = server().await?;
    s.make_contacts("alice", "bob").await?;
    let mut devices = Vec::new();
    for res in ["phone", "laptop", "tablet"] {
        let mut c = s.online("alice", PW, res).await?;
        enable_carbons(&mut c).await?;
        devices.push(c);
    }
    let mut bob = s.online("bob", PW, "pc").await?;
    for c in devices.iter_mut() {
        drain(c, SHORT).await?;
    }
    let me = bare("alice");
    bob.send(&quark_testkit::message(&me, "chat", "to everyone")).await?;
    let mut seen = Vec::new();
    for c in devices.iter_mut() {
        // Each device gets it exactly once: either directly or as a received carbon.
        let e = c
            .expect(|e| {
                e.name() == "message"
                    && (e.child_text("body", ns::CLIENT).as_deref() == Some("to everyone") || is_carbon(e, "received", "to everyone"))
            })
            .await?;
        let m = carbon_inner(&e, "received").cloned().unwrap_or(e);
        seen.push(stanza_id_by(&m, &me).unwrap_or_else(|| panic!("no stanza-id by {me}: {m}")));
        c.expect_silence(SHORT).await?;
    }
    assert!(seen.windows(2).all(|w| w[0] == w[1]), "devices saw different stanza-ids: {seen:?}");
    let page = mam_all(&mut devices[0], None).await?;
    assert_eq!(page.bodies(), vec!["to everyone"], "archived more than once: {:?}", page.wrappers);
    assert_eq!(page.ids(), vec![seen[0].clone()]);
    Ok(())
}

#[tokio::test]
async fn private_hint_skips_carbons() -> anyhow::Result<()> {
    let s = server().await?;
    s.make_contacts("alice", "bob").await?;
    let mut phone = s.online("alice", PW, "phone").await?;
    let mut laptop = s.online("alice", PW, "laptop").await?;
    enable_carbons(&mut phone).await?;
    enable_carbons(&mut laptop).await?;
    let mut bob = s.online("bob", PW, "pc").await?;
    drain(&mut laptop, SHORT).await?;
    drain(&mut phone, SHORT).await?;
    let m = quark_testkit::message(phone.jid.as_deref().unwrap_or_default(), "chat", "just the phone")
        .child(Element::new("private", ns::CARBONS))
        .child(Element::new("no-copy", ns::HINTS));
    bob.send(&m).await?;
    phone.expect(|e| e.child_text("body", ns::CLIENT).as_deref() == Some("just the phone")).await?;
    laptop.expect_silence(SHORT).await?;
    Ok(())
}

#[tokio::test]
async fn disabled_device_gets_no_carbons() -> anyhow::Result<()> {
    let s = server().await?;
    s.make_contacts("alice", "bob").await?;
    let mut phone = s.online("alice", PW, "phone").await?;
    let mut laptop = s.online("alice", PW, "laptop").await?;
    let mut tablet = s.online("alice", PW, "tablet").await?;
    enable_carbons(&mut phone).await?;
    enable_carbons(&mut laptop).await?;
    enable_carbons(&mut tablet).await?;
    let r = tablet.iq_set(None, Element::new("disable", ns::CARBONS)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let mut bob = s.online("bob", PW, "pc").await?;
    for c in [&mut phone, &mut laptop, &mut tablet] {
        drain(c, SHORT).await?;
    }
    bob.send(&quark_testkit::message(phone.jid.as_deref().unwrap_or_default(), "chat", "carbon?")).await?;
    phone.expect(|e| e.child_text("body", ns::CLIENT).as_deref() == Some("carbon?")).await?;
    laptop.expect(|e| is_carbon(e, "received", "carbon?")).await?;
    tablet.expect_silence(SHORT).await?;
    Ok(())
}
