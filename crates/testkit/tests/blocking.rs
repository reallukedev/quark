//! Blocking Command (XEP-0191) and spam reports (XEP-0377), end to end.

use std::time::Duration;

use quark::modules::roster::{self, Item, Subscription};
use quark_testkit::quark_core::{ns, Element, Jid};
use quark_testkit::{message, presence, TestServer, DOMAIN};

const QUIET: Duration = Duration::from_millis(300);

fn items(name: &str, jids: &[&str]) -> Element {
    Element::new(name, ns::BLOCKING).children_from(jids.iter().map(|j| Element::new("item", ns::BLOCKING).attr_set("jid", *j)))
}

fn listed(iq: &Element) -> Vec<String> {
    iq.get_child("blocklist", ns::BLOCKING)
        .map(|l| l.children().filter_map(|i| i.attr("jid").map(String::from)).collect())
        .unwrap_or_default()
}

/// Makes `a` and `b` see each other's presence.
async fn befriend(s: &TestServer, a: &str, b: &str) -> anyhow::Result<()> {
    for (user, contact) in [(a, b), (b, a)] {
        let mut it = Item::new(Jid::parse(&format!("{contact}@{DOMAIN}"))?);
        it.subscription = Subscription::Both;
        roster::save(&s.srv, DOMAIN, user, &it).await?;
    }
    Ok(())
}

#[tokio::test]
async fn block_list_round_trip_with_pushes_to_devices_that_asked() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    let mut phone = s.login_as("alice", "password-a", "phone").await?;
    let mut laptop = s.login_as("alice", "password-a", "laptop").await?;
    let mut tablet = s.login_as("alice", "password-a", "tablet").await?;

    let r = phone.iq_get(None, Element::new("blocklist", ns::BLOCKING)).await?;
    assert_eq!(r.attr("type"), Some("result"));
    assert!(listed(&r).is_empty());
    laptop.iq_get(None, Element::new("blocklist", ns::BLOCKING)).await?;

    let r = phone.iq_set(None, items("block", &["Eve@Evil.Example", "spam.example"])).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    for dev in [&mut phone, &mut laptop] {
        let push = dev.expect(|e| e.name() == "iq" && e.has_child("block", ns::BLOCKING)).await?;
        assert_eq!(push.attr("type"), Some("set"));
        let got: Vec<_> =
            push.get_child("block", ns::BLOCKING).unwrap().children().filter_map(|i| i.attr("jid")).map(String::from).collect();
        assert_eq!(got, ["eve@evil.example", "spam.example"]);
    }
    // The tablet never fetched the list, so it gets no pushes.
    tablet.expect_silence(QUIET).await?;

    let r = laptop.iq_get(Some(&format!("alice@{DOMAIN}")), Element::new("blocklist", ns::BLOCKING)).await?;
    let mut got = listed(&r);
    got.sort();
    assert_eq!(got, ["eve@evil.example", "spam.example"]);

    phone.iq_set(None, items("unblock", &["spam.example"])).await?;
    let push = laptop.expect(|e| e.name() == "iq" && e.has_child("unblock", ns::BLOCKING)).await?;
    assert_eq!(push.get_child("unblock", ns::BLOCKING).unwrap().children().count(), 1);
    assert_eq!(listed(&phone.iq_get(None, Element::new("blocklist", ns::BLOCKING)).await?), ["eve@evil.example"]);

    // An empty unblock clears everything.
    phone.iq_set(None, Element::new("unblock", ns::BLOCKING)).await?;
    assert!(listed(&phone.iq_get(None, Element::new("blocklist", ns::BLOCKING)).await?).is_empty());

    // An empty block, a bad address and someone else's list are refused.
    let r = phone.iq_set(None, Element::new("block", ns::BLOCKING)).await?;
    assert_eq!(r.attr("type"), Some("error"));
    let r = phone.iq_set(None, items("block", &["a@@b"])).await?;
    assert!(r.get_child("error", ns::CLIENT).unwrap().has_child("jid-malformed", ns::STANZAS), "{r}");
    s.add_user("bob", "password-b").await?;
    let r = phone.iq_get(Some(&format!("bob@{DOMAIN}")), Element::new("blocklist", ns::BLOCKING)).await?;
    assert_eq!(r.attr("type"), Some("error"));
    Ok(())
}

#[tokio::test]
async fn blocked_contacts_get_nothing_through_either_way() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    s.add_user("eve", "password-e").await?;
    let mut alice = s.online("alice", "password-a", "phone").await?;
    let mut eve = s.online("eve", "password-e", "laptop").await?;
    alice.iq_set(None, items("block", &[&format!("eve@{DOMAIN}")])).await?;

    // Eve's message bounces as if Alice weren't there; Alice sees nothing.
    let m = message(&format!("alice@{DOMAIN}"), "chat", "hello?");
    eve.send(&m).await?;
    let err = eve.expect(|e| e.name() == "message" && e.attr("type") == Some("error")).await?;
    assert!(err.get_child("error", ns::CLIENT).unwrap().has_child("service-unavailable", ns::STANZAS), "{err}");
    alice.expect_silence(QUIET).await?;

    // Eve's IQs are refused too.
    let r = eve.iq_get(Some(&format!("alice@{DOMAIN}/phone")), Element::new("ping", ns::PING)).await?;
    assert_eq!(r.attr("type"), Some("error"));
    alice.expect_silence(QUIET).await?;

    // Alice can't write to Eve while she's blocked, and is told why.
    alice.send(&message(&format!("eve@{DOMAIN}"), "chat", "go away")).await?;
    let err = alice.expect(|e| e.name() == "message" && e.attr("type") == Some("error")).await?;
    let e = err.get_child("error", ns::CLIENT).unwrap();
    assert!(e.has_child("not-acceptable", ns::STANZAS), "{err}");
    assert!(e.has_child("blocked", ns::BLOCKING_ERRORS), "{err}");
    eve.expect_silence(QUIET).await?;

    // Unblocked, messages flow again.
    alice.iq_set(None, Element::new("unblock", ns::BLOCKING)).await?;
    eve.send(&message(&format!("alice@{DOMAIN}"), "chat", "friends?")).await?;
    let got = alice.expect(|e| e.name() == "message" && e.has_child("body", ns::CLIENT)).await?;
    assert_eq!(got.child_text("body", ns::CLIENT).as_deref(), Some("friends?"));
    Ok(())
}

#[tokio::test]
async fn blocking_hides_presence_and_unblocking_shows_it_again() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    s.add_user("bob", "password-b").await?;
    befriend(&s, "alice", "bob").await?;
    let mut bob = s.online("bob", "password-b", "laptop").await?;
    let mut alice = s.online("alice", "password-a", "phone").await?;
    let from_alice = format!("alice@{DOMAIN}/phone");
    let bob_jid = format!("bob@{DOMAIN}/laptop");
    alice.expect(|e| e.name() == "presence" && e.attr("from") == Some(&bob_jid)).await?;
    let p = bob.expect(|e| e.name() == "presence" && e.attr("from") == Some(&from_alice)).await?;
    assert_eq!(p.attr("type"), None);

    alice.iq_set(None, items("block", &[&format!("bob@{DOMAIN}")])).await?;
    let p = bob.expect(|e| e.name() == "presence" && e.attr("from") == Some(&from_alice)).await?;
    assert_eq!(p.attr("type"), Some("unavailable"));

    // Presence changes no longer reach Bob, and Bob's no longer reach Alice.
    let mut away = presence(None, None);
    away.append(Element::new("show", ns::CLIENT).text("away"));
    alice.send(&away).await?;
    bob.expect_silence(QUIET).await?;
    bob.send(&presence(None, None)).await?;
    assert!(alice.recv_within(QUIET).await?.filter(|e| e.attr("from") == Some(&bob_jid)).is_none());

    alice.iq_set(None, items("unblock", &[&format!("bob@{DOMAIN}")])).await?;
    let p = bob.expect(|e| e.name() == "presence" && e.attr("from") == Some(&from_alice)).await?;
    assert_eq!(p.attr("type"), None);
    assert_eq!(p.child_text("show", ns::CLIENT).as_deref(), Some("away"));
    Ok(())
}

#[tokio::test]
async fn spam_reports_are_kept_with_the_block() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    let mut alice = s.login("alice", "password-a").await?;

    let info = alice.iq_get(Some(DOMAIN), Element::new("query", ns::DISCO_INFO)).await?;
    let features: Vec<_> = info
        .get_child("query", ns::DISCO_INFO)
        .unwrap()
        .children()
        .filter(|c| c.name() == "feature")
        .filter_map(|c| c.attr("var"))
        .collect();
    assert!(features.contains(&ns::BLOCKING) && features.contains(&ns::SPAM_REPORTING), "{features:?}");

    let report = Element::new("report", ns::SPAM_REPORTING)
        .attr_set("reason", "urn:xmpp:reporting:spam")
        .child(Element::new("stanza-id", ns::SID).attr_set("by", format!("alice@{DOMAIN}")).attr_set("id", "x1"))
        .text_child("text", ns::SPAM_REPORTING, "Selling things");
    let block =
        Element::new("block", ns::BLOCKING).child(Element::new("item", ns::BLOCKING).attr_set("jid", "spammer@junk.example").child(report));
    let r = alice.iq_set(None, block).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");

    let rows: Vec<(String, String, Option<String>, String)> = s
        .srv
        .db
        .read(|c| {
            let mut st = c.prepare("SELECT jid, reason, text, stanza_ids FROM spam_reports")?;
            let rows = st.query_map(quark::db::params![], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
            rows.collect()
        })
        .await?;
    assert_eq!(rows, [("spammer@junk.example".into(), "urn:xmpp:reporting:spam".into(), Some("Selling things".into()), "x1".into())]);

    let bad = Element::new("block", ns::BLOCKING).child(
        Element::new("item", ns::BLOCKING)
            .attr_set("jid", "x@junk.example")
            .child(Element::new("report", ns::SPAM_REPORTING).attr_set("reason", "boring")),
    );
    assert_eq!(alice.iq_set(None, bad).await?.attr("type"), Some("error"));
    Ok(())
}
