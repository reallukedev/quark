//! Personal Eventing (XEP-0163) end to end: publishing, notifications filtered by caps, access
//! models, publish-options, item limits, last items on coming online, and the conversions to
//! vCard avatars and legacy bookmarks.

use std::time::Duration;

use base64::Engine;
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{presence, Client, TestServer, DOMAIN};

const PW: &str = "password-1";
const NICK: &str = "http://jabber.org/protocol/nick";
const NICK_NOTIFY: &str = "http://jabber.org/protocol/nick+notify";
const DEVICES: &str = "eu.siacs.conversations.axolotl.devicelist";
const DEVICES_NOTIFY: &str = "eu.siacs.conversations.axolotl.devicelist+notify";
const BOOKMARKS: &str = "urn:xmpp:bookmarks:1";
const BOOKMARKS_NOTIFY: &str = "urn:xmpp:bookmarks:1+notify";
const AVATAR_DATA: &str = "urn:xmpp:avatar:data";
const AVATAR_META: &str = "urn:xmpp:avatar:metadata";
const SETTLE: Duration = Duration::from_millis(400);
const QUIET: Duration = Duration::from_millis(400);

async fn server(users: &[&str]) -> anyhow::Result<TestServer> {
    let s = TestServer::start().await?;
    for u in users {
        s.add_user(u, PW).await?;
    }
    Ok(s)
}

fn jid(user: &str) -> String {
    format!("{user}@{DOMAIN}")
}

/// Signs in, fetches the roster and goes online advertising `features`, answering the server's
/// caps query.
async fn online(s: &TestServer, user: &str, resource: &str, features: &[&str]) -> anyhow::Result<Client> {
    let mut c = s.login_as(user, PW, resource).await?;
    c.iq_get(None, Element::new("query", ns::ROSTER)).await?;
    let caps = c.caps(features);
    c.send(&presence(None, None).child(caps)).await?;
    c.pump(SETTLE).await?;
    Ok(c)
}

fn pubsub(op: Element) -> Element {
    Element::new("pubsub", ns::PUBSUB).child(op)
}

fn publish(node: &str, id: Option<&str>, payload: Element) -> Element {
    pubsub(
        Element::new("publish", ns::PUBSUB)
            .attr_set("node", node)
            .child(Element::new("item", ns::PUBSUB).attr_opt("id", id).child(payload)),
    )
}

fn form(form_type: &str, fields: &[(&str, &str)]) -> Element {
    let mut x = Element::new("x", ns::DATA_FORMS).attr_set("type", "submit");
    let field = |var: &str, v: &str| {
        Element::new("field", ns::DATA_FORMS).attr_set("var", var).child(Element::new("value", ns::DATA_FORMS).text(v.to_string()))
    };
    x.append(field("FORM_TYPE", form_type).attr_set("type", "hidden"));
    for (k, v) in fields {
        x.append(field(k, v));
    }
    x
}

fn with_options(mut ps: Element, fields: &[(&str, &str)]) -> Element {
    ps.append(Element::new("publish-options", ns::PUBSUB).child(form("http://jabber.org/protocol/pubsub#publish-options", fields)));
    ps
}

fn items(node: &str) -> Element {
    pubsub(Element::new("items", ns::PUBSUB).attr_set("node", node))
}

fn nick(n: &str) -> Element {
    Element::new("nick", NICK).text(n)
}

fn devices(ids: &[u32]) -> Element {
    let mut l = Element::new("list", "eu.siacs.conversations.axolotl");
    for i in ids {
        l.append(Element::new("device", "eu.siacs.conversations.axolotl").attr_set("id", i.to_string()));
    }
    l
}

/// The `<items/>` of a PEP notification about `node`.
fn event_items<'a>(m: &'a Element, node: &str) -> Option<&'a Element> {
    if m.name() != "message" {
        return None;
    }
    m.get_child("event", ns::PUBSUB_EVENT)?.get_child("items", ns::PUBSUB_EVENT).filter(|i| i.attr("node") == Some(node))
}

fn is_event(node: &str) -> impl Fn(&Element) -> bool + '_ {
    move |m| event_items(m, node).is_some()
}

/// Fails if a PEP notification arrives soon; anything else (presence) is fine.
async fn no_events(c: &mut Client) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + QUIET;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match c.recv_within(left).await? {
            None => return Ok(()),
            Some(e) if e.has_child("event", ns::PUBSUB_EVENT) => anyhow::bail!("expected no notification, got {e}"),
            Some(_) if left.is_zero() => return Ok(()),
            Some(_) => {}
        }
    }
}

/// The result's `<items/>`, or a failure naming the error.
fn result_items(r: &Element) -> anyhow::Result<Vec<Element>> {
    anyhow::ensure!(r.attr("type") == Some("result"), "expected a result, got {r}");
    let items = r
        .get_child("pubsub", ns::PUBSUB)
        .and_then(|p| p.get_child("items", ns::PUBSUB))
        .ok_or_else(|| anyhow::anyhow!("no items in {r}"))?;
    Ok(items.children().cloned().collect())
}

fn ids(items: &[Element]) -> Vec<&str> {
    items.iter().filter_map(|i| i.attr("id")).collect()
}

/// (condition, pubsub application condition) of an error reply.
fn error_of(r: &Element) -> (String, String) {
    let e = r.get_child("error", ns::CLIENT);
    let cond = e.and_then(|e| e.children().find(|c| c.ns() == ns::STANZAS && c.name() != "text")).map(|c| c.name().to_string());
    let app = e.and_then(|e| e.child_ns(ns::PUBSUB_ERRORS)).map(|c| c.name().to_string());
    (cond.unwrap_or_default(), app.unwrap_or_default())
}

#[tokio::test]
async fn accounts_and_the_server_advertise_pep() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut alice = s.login("alice", PW).await?;
    for to in [jid("alice"), DOMAIN.to_string()] {
        let r = alice.iq_get(Some(&to), Element::new("query", ns::DISCO_INFO)).await?;
        let q = r.get_child("query", ns::DISCO_INFO).expect("disco#info result");
        assert!(
            q.children().any(|c| c.name() == "identity" && c.attr("category") == Some("pubsub") && c.attr("type") == Some("pep")),
            "{q}"
        );
        let features: Vec<&str> = q.children().filter_map(|c| c.attr("var")).collect();
        for f in ["publish-options", "auto-create", "config-node-max", "last-published", "multi-items", "item-ids", "access-whitelist"] {
            assert!(features.contains(&format!("http://jabber.org/protocol/pubsub#{f}").as_str()), "{f} missing on {to}");
        }
        assert!(features.contains(&"urn:xmpp:pep-vcard-conversion:0"));
        assert!(features.contains(&"urn:xmpp:bookmarks:1#compat"));
    }
    Ok(())
}

#[tokio::test]
async fn notifications_follow_notify_caps_and_presence_subscriptions() -> anyhow::Result<()> {
    let s = server(&["alice", "bob", "carol", "dave"]).await?;
    s.make_contacts("alice", "bob").await?;
    s.make_contacts("alice", "carol").await?;
    // Dave sees nothing of Alice: she follows him, not the other way round.
    s.roster_set("alice", &jid("dave"), "to").await?;
    s.roster_set("dave", &jid("alice"), "from").await?;
    let mut alice = online(&s, "alice", "phone", &[NICK_NOTIFY]).await?;
    let mut alice2 = online(&s, "alice", "laptop", &[]).await?;
    let mut bob = online(&s, "bob", "pc", &[NICK_NOTIFY]).await?;
    let mut carol = online(&s, "carol", "pc", &[]).await?;
    let mut dave = online(&s, "dave", "pc", &[NICK_NOTIFY]).await?;

    let r = alice.iq_set(None, publish(NICK, None, nick("Alice"))).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let id = r
        .get_child("pubsub", ns::PUBSUB)
        .and_then(|p| p.get_child("publish", ns::PUBSUB))
        .and_then(|p| p.first_child())
        .and_then(|i| i.attr("id"));
    assert!(id.is_some_and(|i| !i.is_empty()), "the server picks an id: {r}");

    let m = bob.expect(is_event(NICK)).await?;
    assert_eq!(m.attr("from"), Some(jid("alice").as_str()));
    assert_eq!(m.attr("type"), Some("headline"));
    let item = event_items(&m, NICK).and_then(|i| i.first_child()).expect("item");
    assert_eq!(item.child_text("nick", NICK).as_deref(), Some("Alice"));
    // The owner's own device asked for it too.
    alice.expect(is_event(NICK)).await?;

    no_events(&mut carol).await?;
    no_events(&mut dave).await?;
    no_events(&mut alice2).await?;
    Ok(())
}

#[tokio::test]
async fn caps_are_looked_up_once_per_ver() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let a = online(&s, "alice", "one", &[NICK_NOTIFY]).await?;
    let b = online(&s, "bob", "one", &[NICK_NOTIFY]).await?;
    assert_eq!(a.disco_queries, 1);
    assert_eq!(b.disco_queries, 0, "the verified answer is reused for the same ver");
    Ok(())
}

#[tokio::test]
async fn a_contact_coming_online_gets_the_last_items() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    s.make_contacts("alice", "bob").await?;
    let mut alice = online(&s, "alice", "phone", &[]).await?;
    alice.iq_set(None, publish(NICK, Some("current"), nick("Old"))).await?;
    alice.iq_set(None, publish(NICK, Some("current"), nick("Alice"))).await?;

    let mut bob = online(&s, "bob", "pc", &[NICK_NOTIFY]).await?;
    let m = bob.expect(is_event(NICK)).await?;
    let item = event_items(&m, NICK).and_then(|i| i.first_child()).expect("item");
    assert_eq!(item.attr("id"), Some("current"));
    assert_eq!(item.child_text("nick", NICK).as_deref(), Some("Alice"));
    assert!(m.has_child("delay", ns::DELAY), "last items carry when they were published");
    // Only the last one, once.
    no_events(&mut bob).await?;

    // Updating presence with the same caps doesn't send them again; new interests do.
    let caps = bob.caps(&[NICK_NOTIFY]);
    bob.send(&presence(None, None).child(caps).text_child("status", ns::CLIENT, "away")).await?;
    no_events(&mut bob).await?;
    Ok(())
}

#[tokio::test]
async fn a_new_subscriber_gets_the_last_items() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut alice = online(&s, "alice", "phone", &[]).await?;
    alice.iq_set(None, publish(NICK, Some("current"), nick("Alice"))).await?;
    let mut bob = online(&s, "bob", "pc", &[NICK_NOTIFY]).await?;
    no_events(&mut bob).await?;

    // Bob asks, Alice approves: Bob now sees her presence and her nickname.
    bob.send(&presence(Some(&jid("alice")), Some("subscribe"))).await?;
    alice.expect(|e| e.name() == "presence" && e.attr("type") == Some("subscribe")).await?;
    alice.send(&presence(Some(&jid("bob")), Some("subscribed"))).await?;
    let m = bob.expect(is_event(NICK)).await?;
    assert_eq!(m.attr("from"), Some(jid("alice").as_str()));
    Ok(())
}

#[tokio::test]
async fn presence_access_keeps_strangers_out() -> anyhow::Result<()> {
    let s = server(&["alice", "bob", "eve"]).await?;
    s.make_contacts("alice", "bob").await?;
    let mut alice = online(&s, "alice", "phone", &[]).await?;
    alice.iq_set(None, publish(NICK, Some("current"), nick("Alice"))).await?;

    let mut bob = online(&s, "bob", "pc", &[]).await?;
    let got = result_items(&bob.iq_get(Some(&jid("alice")), items(NICK)).await?)?;
    assert_eq!(ids(&got), ["current"]);

    let mut eve = online(&s, "eve", "pc", &[]).await?;
    let r = eve.iq_get(Some(&jid("alice")), items(NICK)).await?;
    assert_eq!(error_of(&r), ("not-authorized".into(), "presence-subscription-required".into()));
    let r = eve.iq_get(Some(&jid("alice")), items("no-such-node")).await?;
    assert_eq!(error_of(&r).0, "item-not-found");
    // Nor can anyone publish on Alice's behalf.
    let r = eve.iq_set(Some(&jid("alice")), publish(NICK, None, nick("Eve"))).await?;
    assert_eq!(error_of(&r).0, "forbidden");
    Ok(())
}

#[tokio::test]
async fn omemo_device_lists_are_open_to_non_contacts() -> anyhow::Result<()> {
    let s = server(&["alice", "eve"]).await?;
    let mut alice = online(&s, "alice", "phone", &[]).await?;
    let r =
        alice.iq_set(None, with_options(publish(DEVICES, Some("current"), devices(&[1, 2])), &[("pubsub#access_model", "open")])).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");

    let mut eve = online(&s, "eve", "pc", &[DEVICES_NOTIFY]).await?;
    let got = result_items(&eve.iq_get(Some(&jid("alice")), items(DEVICES)).await?)?;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].first_child().map(|l| l.children().count()), Some(2));
    // Open to read, but notifications are still for contacts only.
    alice.iq_set(None, publish(DEVICES, Some("current"), devices(&[1, 2, 3]))).await?;
    no_events(&mut eve).await?;

    // An explicit subscription delivers anyway, starting with the last item.
    let sub = pubsub(Element::new("subscribe", ns::PUBSUB).attr_set("node", DEVICES).attr_set("jid", jid("eve")));
    let r = eve.iq_set(Some(&jid("alice")), sub).await?;
    let st = r.get_child("pubsub", ns::PUBSUB).and_then(|p| p.get_child("subscription", ns::PUBSUB)).and_then(|s| s.attr("subscription"));
    assert_eq!(st, Some("subscribed"), "{r}");
    eve.expect(is_event(DEVICES)).await?;
    alice.iq_set(None, publish(DEVICES, Some("current"), devices(&[4]))).await?;
    let m = eve.expect(is_event(DEVICES)).await?;
    assert!(m.attr("to").is_some_and(|t| t.starts_with(&jid("eve"))), "{m}");
    Ok(())
}

#[tokio::test]
async fn bookmarks_stay_private_and_reach_only_the_owner() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    s.make_contacts("alice", "bob").await?;
    let mut alice = online(&s, "alice", "phone", &[BOOKMARKS_NOTIFY]).await?;
    let mut bob = online(&s, "bob", "pc", &[BOOKMARKS_NOTIFY]).await?;
    let conf = Element::new("conference", BOOKMARKS).attr_set("autojoin", "true").attr_set("name", "Room");
    let opts = [
        ("pubsub#persist_items", "true"),
        ("pubsub#max_items", "max"),
        ("pubsub#send_last_published_item", "never"),
        ("pubsub#access_model", "whitelist"),
    ];
    let r = alice.iq_set(None, with_options(publish(BOOKMARKS, Some("room@rooms.example"), conf), &opts)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    alice.expect(is_event(BOOKMARKS)).await?;
    no_events(&mut bob).await?;
    let r = bob.iq_get(Some(&jid("alice")), items(BOOKMARKS)).await?;
    assert_eq!(error_of(&r), ("not-allowed".into(), "closed-node".into()));

    // A client that forgets the options still gets a private node.
    let r =
        alice.iq_set(None, publish("urn:xmpp:mds:displayed:0", Some("x@y"), Element::new("displayed", "urn:xmpp:mds:displayed:0"))).await?;
    assert_eq!(r.attr("type"), Some("result"));
    let r = bob.iq_get(Some(&jid("alice")), items("urn:xmpp:mds:displayed:0")).await?;
    assert_eq!(error_of(&r).0, "not-allowed");
    Ok(())
}

#[tokio::test]
async fn publish_options_are_preconditions_on_existing_nodes() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut alice = online(&s, "alice", "phone", &[]).await?;
    alice.iq_set(None, publish(NICK, Some("current"), nick("A"))).await?;

    let r = alice.iq_set(None, with_options(publish(NICK, Some("current"), nick("B")), &[("pubsub#access_model", "open")])).await?;
    assert_eq!(error_of(&r), ("conflict".into(), "precondition-not-met".into()));
    // Matching options (in any spelling) are fine.
    let r = alice
        .iq_set(
            None,
            with_options(publish(NICK, Some("current"), nick("B")), &[("pubsub#persist_items", "1"), ("pubsub#access_model", "presence")]),
        )
        .await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");

    // What Conversations does next: change the node, then publish again.
    let cfg = alice
        .iq_get(None, Element::new("pubsub", ns::PUBSUB_OWNER).child(Element::new("configure", ns::PUBSUB_OWNER).attr_set("node", NICK)))
        .await?;
    let x = cfg
        .get_child("pubsub", ns::PUBSUB_OWNER)
        .and_then(|p| p.get_child("configure", ns::PUBSUB_OWNER))
        .and_then(|c| c.get_child("x", ns::DATA_FORMS));
    let access = x
        .and_then(|x| x.children().find(|f| f.attr("var") == Some("pubsub#access_model")))
        .and_then(|f| f.child_text("value", ns::DATA_FORMS));
    assert_eq!(access.as_deref(), Some("presence"));
    let set = Element::new("pubsub", ns::PUBSUB_OWNER).child(
        Element::new("configure", ns::PUBSUB_OWNER)
            .attr_set("node", NICK)
            .child(form("http://jabber.org/protocol/pubsub#node_config", &[("pubsub#access_model", "open")])),
    );
    assert_eq!(alice.iq_set(None, set).await?.attr("type"), Some("result"));
    let r = alice.iq_set(None, with_options(publish(NICK, Some("current"), nick("C")), &[("pubsub#access_model", "open")])).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");

    // Values the server can't do are refused, not ignored.
    let r = alice.iq_set(None, with_options(publish("urn:example:new", None, nick("D")), &[("pubsub#access_model", "authorize")])).await?;
    assert_eq!(error_of(&r).1, "precondition-not-met");
    Ok(())
}

#[tokio::test]
async fn max_items_keeps_the_newest_and_items_can_be_asked_by_id() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut alice = online(&s, "alice", "phone", &[]).await?;
    for i in 1..=5 {
        let id = i.to_string();
        let r = alice.iq_set(None, with_options(publish("urn:example:log", Some(&id), nick(&id)), &[("pubsub#max_items", "3")])).await?;
        assert_eq!(r.attr("type"), Some("result"), "{r}");
    }
    assert_eq!(ids(&result_items(&alice.iq_get(None, items("urn:example:log")).await?)?), ["3", "4", "5"]);
    let newest = pubsub(Element::new("items", ns::PUBSUB).attr_set("node", "urn:example:log").attr_set("max_items", "2"));
    assert_eq!(ids(&result_items(&alice.iq_get(None, newest).await?)?), ["4", "5"]);
    let by_id = pubsub(
        Element::new("items", ns::PUBSUB)
            .attr_set("node", "urn:example:log")
            .child(Element::new("item", ns::PUBSUB).attr_set("id", "4"))
            .child(Element::new("item", ns::PUBSUB).attr_set("id", "1")),
    );
    assert_eq!(ids(&result_items(&alice.iq_get(None, by_id).await?)?), ["4"]);

    // disco#items on the node lists the ids.
    let r = alice.iq_get(Some(&jid("alice")), Element::new("query", ns::DISCO_ITEMS).attr_set("node", "urn:example:log")).await?;
    let names: Vec<&str> =
        r.get_child("query", ns::DISCO_ITEMS).map(|q| q.children().filter_map(|i| i.attr("name")).collect()).unwrap_or_default();
    assert_eq!(names, ["3", "4", "5"]);

    let r = alice.iq_set(None, pubsub(Element::new("publish", ns::PUBSUB).attr_set("node", "urn:example:log"))).await?;
    assert_eq!(error_of(&r), ("bad-request".into(), "item-required".into()));
    let two = Element::new("item", ns::PUBSUB).child(nick("a")).child(nick("b"));
    let r = alice.iq_set(None, pubsub(Element::new("publish", ns::PUBSUB).attr_set("node", "urn:example:log").child(two))).await?;
    assert_eq!(error_of(&r), ("bad-request".into(), "invalid-payload".into()));
    Ok(())
}

#[tokio::test]
async fn retract_purge_and_delete_notify_contacts() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    s.make_contacts("alice", "bob").await?;
    let mut alice = online(&s, "alice", "phone", &[]).await?;
    let mut bob = online(&s, "bob", "pc", &["urn:example:log+notify"]).await?;
    for id in ["a", "b"] {
        alice.iq_set(None, with_options(publish("urn:example:log", Some(id), nick(id)), &[("pubsub#max_items", "10")])).await?;
        bob.expect(is_event("urn:example:log")).await?;
    }

    let retract = pubsub(
        Element::new("retract", ns::PUBSUB).attr_set("node", "urn:example:log").child(Element::new("item", ns::PUBSUB).attr_set("id", "a")),
    );
    assert_eq!(alice.iq_set(None, retract.clone()).await?.attr("type"), Some("result"));
    let m = bob.expect(is_event("urn:example:log")).await?;
    let r = event_items(&m, "urn:example:log").and_then(|i| i.get_child("retract", ns::PUBSUB_EVENT)).and_then(|r| r.attr("id"));
    assert_eq!(r, Some("a"));
    assert_eq!(error_of(&alice.iq_set(None, retract).await?).0, "item-not-found");

    let owner =
        |op: &str| Element::new("pubsub", ns::PUBSUB_OWNER).child(Element::new(op, ns::PUBSUB_OWNER).attr_set("node", "urn:example:log"));
    assert_eq!(alice.iq_set(None, owner("purge")).await?.attr("type"), Some("result"));
    let m = bob.expect(|m| m.get_child("event", ns::PUBSUB_EVENT).is_some_and(|e| e.has_child("purge", ns::PUBSUB_EVENT))).await?;
    assert_eq!(m.attr("from"), Some(jid("alice").as_str()));
    assert!(result_items(&alice.iq_get(None, items("urn:example:log")).await?)?.is_empty());

    assert_eq!(alice.iq_set(None, owner("delete")).await?.attr("type"), Some("result"));
    bob.expect(|m| m.get_child("event", ns::PUBSUB_EVENT).is_some_and(|e| e.has_child("delete", ns::PUBSUB_EVENT))).await?;
    assert_eq!(error_of(&alice.iq_get(None, items("urn:example:log")).await?).0, "item-not-found");
    // Only the owner manages nodes.
    assert_eq!(error_of(&bob.iq_set(Some(&jid("alice")), owner("delete")).await?).0, "forbidden");
    Ok(())
}

#[tokio::test]
async fn disco_items_lists_only_the_nodes_the_asker_may_see() -> anyhow::Result<()> {
    let s = server(&["alice", "eve"]).await?;
    let mut alice = online(&s, "alice", "phone", &[]).await?;
    alice.iq_set(None, publish(NICK, Some("current"), nick("Alice"))).await?;
    alice.iq_set(None, publish(DEVICES, Some("current"), devices(&[1]))).await?;
    let nodes = |r: &Element| -> Vec<String> {
        r.get_child("query", ns::DISCO_ITEMS)
            .map(|q| q.children().filter_map(|i| i.attr("node").map(String::from)).collect())
            .unwrap_or_default()
    };
    let mine = nodes(&alice.iq_get(Some(&jid("alice")), Element::new("query", ns::DISCO_ITEMS)).await?);
    assert_eq!(mine, [DEVICES, NICK]);
    let mut eve = online(&s, "eve", "pc", &[]).await?;
    let theirs = nodes(&eve.iq_get(Some(&jid("alice")), Element::new("query", ns::DISCO_ITEMS)).await?);
    assert_eq!(theirs, [DEVICES]);
    Ok(())
}

#[tokio::test]
async fn a_pep_avatar_shows_up_in_the_vcard_and_presence() -> anyhow::Result<()> {
    let s = server(&["alice", "bob", "eve"]).await?;
    s.make_contacts("alice", "bob").await?;
    let mut alice = online(&s, "alice", "phone", &[]).await?;
    let mut bob = online(&s, "bob", "pc", &[]).await?;
    bob.pump(SETTLE).await?;

    let png = [0x89u8, b'P', b'N', b'G', 1, 2, 3, 4];
    let b64 = base64::engine::general_purpose::STANDARD.encode(png);
    let id = "0123456789abcdef0123456789abcdef01234567";
    let open = [("pubsub#access_model", "open")];
    let r = alice
        .iq_set(None, with_options(publish(AVATAR_DATA, Some(id), Element::new("data", AVATAR_DATA).text(b64.clone())), &open))
        .await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let meta = Element::new("metadata", AVATAR_META)
        .child(Element::new("info", AVATAR_META).attr_set("id", id).attr_set("bytes", "8").attr_set("type", "image/png"));
    let r = alice.iq_set(None, with_options(publish(AVATAR_META, Some(id), meta), &open)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");

    // Bob's older client learns of it from presence, then fetches the vCard.
    let p = bob
        .expect(|e| {
            e.name() == "presence"
                && e.get_child("x", ns::VCARD_UPDATE).is_some_and(|x| x.child_text("photo", ns::VCARD_UPDATE).as_deref() == Some(id))
        })
        .await?;
    assert_eq!(p.attr("from"), Some(format!("{}/phone", jid("alice")).as_str()));
    let mut eve = online(&s, "eve", "pc", &[]).await?;
    let v = eve.iq_get(Some(&jid("alice")), Element::new("vCard", ns::VCARD)).await?;
    let photo = v.get_child("vCard", ns::VCARD).and_then(|v| v.get_child("PHOTO", ns::VCARD)).expect("a photo in the vCard");
    assert_eq!(photo.child_text("BINVAL", ns::VCARD), Some(b64));
    assert_eq!(photo.child_text("TYPE", ns::VCARD).as_deref(), Some("image/png"));

    // Turning the avatar off empties the photo.
    alice.iq_set(None, publish(AVATAR_META, Some("none"), Element::new("metadata", AVATAR_META))).await?;
    let v = eve.iq_get(Some(&jid("alice")), Element::new("vCard", ns::VCARD)).await?;
    assert!(!v.get_child("vCard", ns::VCARD).is_some_and(|v| v.has_child("PHOTO", ns::VCARD)), "{v}");
    Ok(())
}

#[tokio::test]
async fn a_vcard_photo_becomes_the_pep_avatar() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    s.make_contacts("alice", "bob").await?;
    let mut alice = online(&s, "alice", "phone", &[]).await?;
    let mut bob = online(&s, "bob", "pc", &["urn:xmpp:avatar:metadata+notify"]).await?;

    let jpeg = [0xFFu8, 0xD8, 0xFF, 0xE0, 9, 9];
    let b64 = base64::engine::general_purpose::STANDARD.encode(jpeg);
    let vcard = Element::new("vCard", ns::VCARD).text_child("FN", ns::VCARD, "Alice").child(Element::new("PHOTO", ns::VCARD).text_child(
        "BINVAL",
        ns::VCARD,
        b64.clone(),
    ));
    assert_eq!(alice.iq_set(None, vcard).await?.attr("type"), Some("result"));

    let m = bob.expect(is_event(AVATAR_META)).await?;
    let info = event_items(&m, AVATAR_META)
        .and_then(|i| i.first_child())
        .and_then(|i| i.first_child())
        .and_then(|m| m.first_child())
        .expect("info");
    let sha: String = <sha1::Sha1 as sha1::Digest>::digest(jpeg).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(info.attr("id"), Some(sha.as_str()));
    assert_eq!(info.attr("type"), Some("image/jpeg"));
    assert_eq!(info.attr("bytes"), Some("6"));
    let data = result_items(&bob.iq_get(Some(&jid("alice")), items(AVATAR_DATA)).await?)?;
    assert_eq!(data.first().and_then(|i| i.child_text("data", AVATAR_DATA)), Some(b64));
    Ok(())
}

#[tokio::test]
async fn legacy_and_modern_bookmarks_stay_in_step() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut alice = online(&s, "alice", "phone", &[]).await?;
    // An old client stores bookmarks in private XML storage…
    let legacy = Element::new("storage", "storage:bookmarks").child(
        Element::new("conference", "storage:bookmarks")
            .attr_set("jid", "old@rooms.example")
            .attr_set("autojoin", "true")
            .attr_set("name", "Old")
            .text_child("nick", "storage:bookmarks", "al"),
    );
    let r = alice.iq_set(None, Element::new("query", ns::PRIVATE).child(legacy)).await?;
    assert_eq!(r.attr("type"), Some("result"));
    // …and a new one sees them as bookmarks 2.
    let got = result_items(&alice.iq_get(None, items(BOOKMARKS)).await?)?;
    assert_eq!(ids(&got), ["old@rooms.example"]);
    let c = got[0].get_child("conference", BOOKMARKS).expect("conference");
    assert_eq!(c.attr("name"), Some("Old"));
    assert_eq!(c.attr("autojoin"), Some("true"));
    assert_eq!(c.child_text("nick", BOOKMARKS).as_deref(), Some("al"));

    // The new client adds a room; the old one sees both.
    let conf = Element::new("conference", BOOKMARKS).attr_set("name", "New");
    alice.iq_set(None, publish(BOOKMARKS, Some("new@rooms.example"), conf)).await?;
    let r = alice.iq_get(None, Element::new("query", ns::PRIVATE).child(Element::new("storage", "storage:bookmarks"))).await?;
    let stored = r.get_child("query", ns::PRIVATE).and_then(|q| q.get_child("storage", "storage:bookmarks")).expect("storage");
    let jids: Vec<&str> = stored.children().filter_map(|c| c.attr("jid")).collect();
    assert_eq!(jids, ["old@rooms.example", "new@rooms.example"]);
    // So does a client reading the legacy PEP node.
    let pep = result_items(&alice.iq_get(None, items("storage:bookmarks")).await?)?;
    assert_eq!(pep.first().and_then(|i| i.get_child("storage", "storage:bookmarks")).map(|s| s.children().count()), Some(2));

    // Removing a room in the old client removes it in the new one.
    let only_new = Element::new("storage", "storage:bookmarks")
        .child(Element::new("conference", "storage:bookmarks").attr_set("jid", "new@rooms.example"));
    alice.iq_set(None, Element::new("query", ns::PRIVATE).child(only_new)).await?;
    assert_eq!(ids(&result_items(&alice.iq_get(None, items(BOOKMARKS)).await?)?), ["new@rooms.example"]);
    Ok(())
}

#[tokio::test]
async fn deleting_an_account_removes_its_nodes() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut alice = online(&s, "alice", "phone", &[]).await?;
    alice.iq_set(None, publish(NICK, None, nick("Alice"))).await?;
    alice.drop_connection();
    assert!(s.srv.accounts.delete(DOMAIN, "alice").await?);
    let left: i64 = s.srv.db.read(|c| c.query_row("SELECT COUNT(*) FROM pep_nodes", [], |r| r.get(0))).await?;
    assert_eq!(left, 0);
    Ok(())
}

#[tokio::test]
async fn remote_contacts_online_with_notify_caps_get_notifications() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    s.roster_set("alice", "zed@remote.example", "both").await?;
    let mut alice = online(&s, "alice", "phone", &[]).await?;
    // Bob's client has the same caps as Zed's, so the server already knows that `ver`.
    let mut bob = s.login_as("bob", PW, "pc").await?;
    let caps = bob.caps(&[NICK_NOTIFY]);
    bob.send(&presence(None, None).child(caps.clone())).await?;
    bob.pump(SETTLE).await?;

    // Zed's server tells Alice he's online.
    let zed = "zed@remote.example/laptop";
    s.srv.route(presence(Some(&jid("alice")), None).attr_set("from", zed).child(caps)).await;
    alice.expect(|e| e.name() == "presence" && e.attr("from") == Some(zed)).await?;

    // The notification heads to Zed's server; with no federation in tests it bounces back.
    alice.iq_set(None, publish(NICK, Some("current"), nick("Alice"))).await?;
    alice.expect(|e| e.name() == "message" && e.attr("type") == Some("error") && e.attr("from") == Some(zed)).await?;

    // Once he's offline nothing is sent.
    s.srv.route(presence(Some(&jid("alice")), Some("unavailable")).attr_set("from", zed)).await;
    alice.iq_set(None, publish(NICK, Some("current"), nick("Alice 2"))).await?;
    loop {
        match alice.recv_within(QUIET).await? {
            None => break,
            Some(e) => assert!(e.name() != "message" || e.attr("type") != Some("error"), "{e}"),
        }
    }
    Ok(())
}
