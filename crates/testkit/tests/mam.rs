//! Message Archive Management (XEP-0313) with stanza ids (XEP-0359), preferences and full-text
//! search, end to end.

use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{message, Client, TestServer, DOMAIN};

fn field(var: &str, value: &str) -> Element {
    Element::new("field", ns::DATA_FORMS).attr_set("var", var).text_child("value", ns::DATA_FORMS, value)
}

fn query(fields: &[(&str, &str)], rsm: Option<Element>) -> Element {
    let mut x = Element::new("x", ns::DATA_FORMS).attr_set("type", "submit").child(field("FORM_TYPE", ns::MAM));
    for (k, v) in fields {
        x.append(field(k, v));
    }
    let mut q = Element::new("query", ns::MAM).attr_set("queryid", "q1").child(x);
    if let Some(r) = rsm {
        q.append(r);
    }
    q
}

fn page(max: usize, after: Option<&str>) -> Element {
    let mut s = Element::new("set", ns::RSM).text_child("max", ns::RSM, max.to_string());
    if let Some(a) = after {
        s.append(Element::new("after", ns::RSM).text(a));
    }
    s
}

/// Runs a query and returns the archived messages' (id, body) and the `<fin/>`.
async fn run(c: &mut Client, q: Element) -> anyhow::Result<(Vec<(String, Option<String>)>, Element)> {
    let id = quark_testkit::quark_core::new_id();
    c.send(&quark_testkit::quark_core::stanza::iq("set", &id, None, None, q)).await?;
    let mut out = Vec::new();
    loop {
        let e = c.recv().await?;
        if e.name() == "iq" && e.attr("id") == Some(&id) {
            anyhow::ensure!(e.attr("type") == Some("result"), "query failed: {e}");
            let fin = e.get_child("fin", ns::MAM).cloned().ok_or_else(|| anyhow::anyhow!("no fin: {e}"))?;
            return Ok((out, fin));
        }
        if let Some(r) = e.get_child("result", ns::MAM) {
            let m = r.get_child("forwarded", ns::FORWARD).and_then(|f| f.get_child("message", ns::CLIENT));
            out.push((r.attr("id").unwrap_or_default().to_string(), m.and_then(|m| m.child_text("body", ns::CLIENT))));
        }
    }
}

fn bodies(r: &[(String, Option<String>)]) -> Vec<&str> {
    r.iter().filter_map(|(_, b)| b.as_deref()).collect()
}

#[tokio::test]
async fn messages_are_archived_with_ids_and_page_both_ways() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    s.add_user("bob", "password-b").await?;
    let mut alice = s.online("alice", "password-a", "phone").await?;
    let mut bob = s.online("bob", "password-b", "desk").await?;

    let bob_bare = format!("bob@{DOMAIN}");
    let mut ids = Vec::new();
    for body in ["one", "two", "three"] {
        let mut m = message(&bob_bare, "chat", body);
        // A sender can't plant an id in Bob's archive.
        m.append(Element::new("stanza-id", ns::SID).attr_set("by", &*bob_bare).attr_set("id", "forged"));
        alice.send(&m).await?;
        let got = bob.expect(|e| e.name() == "message").await?;
        let sids: Vec<_> = got.children().filter(|c| c.is("stanza-id", ns::SID) && c.attr("by") == Some(&bob_bare)).collect();
        assert_eq!(sids.len(), 1, "{got}");
        assert_ne!(sids[0].attr("id"), Some("forged"));
        ids.push(sids[0].attr("id").unwrap_or_default().to_string());
    }

    let (all, fin) = run(&mut bob, query(&[], None)).await?;
    assert_eq!(bodies(&all), ["one", "two", "three"]);
    assert_eq!(all.iter().map(|(i, _)| i.clone()).collect::<Vec<_>>(), ids, "result ids are the stanza ids");
    assert_eq!(fin.attr("complete"), Some("true"));

    let (p1, fin) = run(&mut bob, query(&[], Some(page(2, None)))).await?;
    assert_eq!(bodies(&p1), ["one", "two"]);
    assert_ne!(fin.attr("complete"), Some("true"));
    let last = fin.get_child("set", ns::RSM).and_then(|s| s.child_text("last", ns::RSM)).unwrap_or_default();
    let (p2, fin) = run(&mut bob, query(&[], Some(page(2, Some(&last))))).await?;
    assert_eq!(bodies(&p2), ["three"]);
    assert_eq!(fin.attr("complete"), Some("true"));

    // The newest page first, with `<before/>`.
    let mut before = page(1, None);
    before.append(Element::new("before", ns::RSM));
    let (newest, _) = run(&mut bob, query(&[], Some(before))).await?;
    assert_eq!(bodies(&newest), ["three"]);

    // Alice has her own copy, filtered by contact.
    let (mine, _) = run(&mut alice, query(&[("with", &bob_bare)], None)).await?;
    assert_eq!(bodies(&mine), ["one", "two", "three"]);
    let (none, _) = run(&mut alice, query(&[("with", &format!("carol@{DOMAIN}"))], None)).await?;
    assert!(none.is_empty());
    Ok(())
}

#[tokio::test]
async fn full_text_search_finds_words() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    s.add_user("bob", "password-b").await?;
    let mut alice = s.online("alice", "password-a", "phone").await?;
    let mut bob = s.online("bob", "password-b", "desk").await?;
    for body in ["Pizza tonight?", "No, sushi", "Fine, pizzas it is"] {
        alice.send(&message(&format!("bob@{DOMAIN}"), "chat", body)).await?;
        bob.expect(|e| e.name() == "message").await?;
    }
    let (hits, _) = run(&mut bob, query(&[("{urn:xmpp:fulltext:0}fulltext", "pizza")], None)).await?;
    assert_eq!(bodies(&hits), ["Pizza tonight?", "Fine, pizzas it is"]);
    let (hits, _) = run(&mut bob, query(&[("{urn:xmpp:fulltext:0}fulltext", "sushi no")], None)).await?;
    assert_eq!(bodies(&hits), ["No, sushi"]);
    Ok(())
}

#[tokio::test]
async fn preferences_and_the_history_setting_are_respected() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    s.add_user("bob", "password-b").await?;
    let mut alice = s.online("alice", "password-a", "phone").await?;
    let mut bob = s.online("bob", "password-b", "desk").await?;

    let r = bob.iq_set(None, Element::new("prefs", ns::MAM).attr_set("default", "never")).await?;
    assert_eq!(r.get_child("prefs", ns::MAM).and_then(|p| p.attr("default")), Some("never"), "{r}");
    alice.send(&message(&format!("bob@{DOMAIN}"), "chat", "not kept")).await?;
    let got = bob.expect(|e| e.name() == "message").await?;
    assert!(!got.has_child("stanza-id", ns::SID) || got.children().all(|c| c.attr("by") != Some(&*format!("bob@{DOMAIN}"))));
    let (none, _) = run(&mut bob, query(&[], None)).await?;
    assert!(none.is_empty());

    // Someone else's archive is off limits.
    let r = alice.iq_set(Some(&format!("bob@{DOMAIN}")), query(&[], None)).await?;
    assert_eq!(r.attr("type"), Some("error"));

    s.set_settings(|st| st.history = quark::settings::History::Off).await?;
    let r = bob.iq_set(None, query(&[], None)).await?;
    assert_eq!(r.attr("type"), Some("error"));
    let info = bob.iq_get(Some(&format!("bob@{DOMAIN}")), Element::new("query", ns::DISCO_INFO)).await?;
    assert!(!info.to_xml().contains(ns::MAM), "{info}");
    Ok(())
}
