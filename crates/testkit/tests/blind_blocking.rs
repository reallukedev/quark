//! XEP-0191 Blocking Command. Black-box: written from the XEP only.

mod blind_xep;

use anyhow::{bail, ensure, Context as _};
use blind_xep::*;
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{message, presence, Client, TestServer};

async fn server(users: &[&str]) -> anyhow::Result<TestServer> {
    let s = TestServer::start().await?;
    for u in users {
        s.add_user(u, PW).await?;
    }
    Ok(s)
}

fn items(el: &Element, jids: &[&str]) -> Element {
    let mut el = el.clone();
    for j in jids {
        el.append(Element::new("item", ns::BLOCKING).attr_set("jid", *j));
    }
    el
}

fn block(jids: &[&str]) -> Element {
    items(&Element::new("block", ns::BLOCKING), jids)
}

fn unblock(jids: &[&str]) -> Element {
    items(&Element::new("unblock", ns::BLOCKING), jids)
}

async fn blocklist(c: &mut Client) -> anyhow::Result<Vec<String>> {
    let r = c.iq_get(None, Element::new("blocklist", ns::BLOCKING)).await?;
    ensure!(is_result(&r), "blocklist get failed: {r}");
    let list = r.get_child("blocklist", ns::BLOCKING).with_context(|| format!("no <blocklist/>: {r}"))?;
    let mut v: Vec<String> =
        list.children().filter(|i| i.is("item", ns::BLOCKING)).filter_map(|i| i.attr("jid")).map(str::to_string).collect();
    v.sort();
    Ok(v)
}

async fn set_ok(c: &mut Client, payload: Element) -> anyhow::Result<()> {
    let r = c.iq_set(None, payload).await?;
    ensure!(is_result(&r), "blocking set failed: {r}");
    Ok(())
}

/// Reads for a while; fails on any message (or presence, with `presences`) from `from_bare`.
async fn nothing_from(c: &mut Client, from_bare: &str, presences: bool) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + QUIET;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Some(e) = c.recv_within(left).await? else { return Ok(()) };
        let from = e.attr("from").unwrap_or("");
        let matches = from == from_bare || from.starts_with(&format!("{from_bare}/"));
        if matches && (e.name() == "message" || (presences && e.name() == "presence")) {
            bail!("expected nothing from {from_bare}, got {e}");
        }
    }
}

/// §3.1: the server advertises `urn:xmpp:blocking`.
#[tokio::test]
async fn server_advertises_blocking() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut a = s.login("alice", PW).await?;
    let info = disco_info(&mut a, Some(s.domain())).await?;
    ensure!(disco_features(&info).iter().any(|f| f == ns::BLOCKING), "{info}");
    Ok(())
}

/// §3.2–§3.5: get, block, unblock, unblock all; the list survives a new session.
#[tokio::test]
async fn block_unblock_unblock_all() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut a = s.login("alice", PW).await?;
    assert!(blocklist(&mut a).await?.is_empty());

    set_ok(&mut a, block(&["carol@quark.test", "dave@quark.test"])).await?;
    assert_eq!(blocklist(&mut a).await?, ["carol@quark.test", "dave@quark.test"]);

    let mut again = s.login_as("alice", PW, "again").await?;
    assert_eq!(blocklist(&mut again).await?, ["carol@quark.test", "dave@quark.test"], "the blocklist is stored");

    set_ok(&mut a, unblock(&["carol@quark.test"])).await?;
    assert_eq!(blocklist(&mut a).await?, ["dave@quark.test"]);

    set_ok(&mut a, block(&["erin@quark.test"])).await?;
    set_ok(&mut a, unblock(&[])).await?;
    assert!(blocklist(&mut a).await?.is_empty(), "an empty <unblock/> unblocks everything");
    Ok(())
}

/// §3.3: a `<block/>` with no items is a bad request.
#[tokio::test]
async fn empty_block_is_bad_request() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut a = s.login("alice", PW).await?;
    let r = a.iq_set(None, block(&[])).await?;
    assert_eq!(r.attr("type"), Some("error"), "{r}");
    assert_eq!(condition(&r).as_deref(), Some("bad-request"), "{r}");
    Ok(())
}

/// §3.3–§3.5: block, unblock and unblock-all are pushed to the user's resources that have
/// requested the blocklist (and not to those that haven't).
#[tokio::test]
async fn changes_are_pushed_to_interested_resources() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut one = s.login_as("alice", PW, "one").await?;
    let mut two = s.login_as("alice", PW, "two").await?;
    let mut three = s.login_as("alice", PW, "three").await?;
    blocklist(&mut one).await?;
    blocklist(&mut two).await?;

    let push = |kind: &'static str| move |e: &Element| e.name() == "iq" && e.attr("type") == Some("set") && e.has_child(kind, ns::BLOCKING);

    set_ok(&mut one, block(&["carol@quark.test"])).await?;
    let p = two.expect(push("block")).await?;
    let jids: Vec<_> = p.get_child("block", ns::BLOCKING).into_iter().flat_map(|b| b.children()).filter_map(|i| i.attr("jid")).collect();
    assert_eq!(jids, ["carol@quark.test"], "{p}");
    ensure!(p.attr("from").is_none_or(|f| f == "alice@quark.test"), "pushes come from the account: {p}");
    two.answer(&p).await?;

    set_ok(&mut one, unblock(&["carol@quark.test"])).await?;
    let p = two.expect(push("unblock")).await?;
    let jids: Vec<_> = p.get_child("unblock", ns::BLOCKING).into_iter().flat_map(|b| b.children()).filter_map(|i| i.attr("jid")).collect();
    assert_eq!(jids, ["carol@quark.test"], "{p}");
    two.answer(&p).await?;

    set_ok(&mut one, block(&["dave@quark.test"])).await?;
    let p = two.expect(push("block")).await?;
    two.answer(&p).await?;
    set_ok(&mut one, unblock(&[])).await?;
    let p = two.expect(push("unblock")).await?;
    ensure!(p.get_child("unblock", ns::BLOCKING).is_some_and(|u| u.children().next().is_none()), "unblock-all push is empty: {p}");
    two.answer(&p).await?;

    // `three` never asked for the blocklist.
    let deadline = tokio::time::Instant::now() + QUIET;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Some(e) = three.recv_within(left).await? else { break };
        ensure!(e.child_ns(ns::BLOCKING).is_none(), "a resource that never requested the blocklist got a push: {e}");
    }
    Ok(())
}

/// §3.3: messages and IQs from a blocked JID aren't delivered and get an error (SHOULD be
/// service-unavailable); presence from it is dropped without an error.
#[tokio::test]
async fn blocked_contact_cannot_reach_user() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut alice = s.online("alice", PW, "one").await?;
    let mut bob = s.online("bob", PW, "b").await?;
    set_ok(&mut alice, block(&["bob@quark.test"])).await?;

    let m = message("alice@quark.test", "chat", "can you hear me?");
    let id = m.attr("id").map(str::to_string);
    bob.send(&m).await?;
    let err = bob.expect(|e| e.name() == "message" && e.attr("type") == Some("error")).await.context("no error for a blocked message")?;
    assert_eq!(err.attr("id"), id.as_deref(), "{err}");
    assert_eq!(condition(&err).as_deref(), Some("service-unavailable"), "SHOULD be service-unavailable: {err}");

    bob.send(&message("alice@quark.test/one", "chat", "full jid")).await?;
    let err = bob.expect(|e| e.name() == "message" && e.attr("type") == Some("error")).await?;
    ensure!(condition(&err).is_some(), "{err}");

    let r = bob.iq_get(Some("alice@quark.test/one"), Element::new("ping", ns::PING)).await?;
    assert_eq!(r.attr("type"), Some("error"), "IQs from a blocked JID MUST get an error: {r}");

    bob.send(&presence(Some("alice@quark.test"), None)).await?;
    nothing_from(&mut alice, "bob@quark.test", true).await?;
    // No error for the presence.
    let deadline = tokio::time::Instant::now() + QUIET;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Some(e) = bob.recv_within(left).await? else { break };
        ensure!(!(e.name() == "presence" && e.attr("type") == Some("error")), "presence from a blocked JID must not bounce: {e}");
    }
    Ok(())
}

/// §6: a full JID item blocks only that resource.
#[tokio::test]
async fn full_jid_item_blocks_only_that_resource() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut alice = s.online("alice", PW, "one").await?;
    let mut b1 = s.online("bob", PW, "b1").await?;
    let mut b2 = s.online("bob", PW, "b2").await?;
    set_ok(&mut alice, block(&["bob@quark.test/b1"])).await?;

    b1.send(&message("alice@quark.test/one", "chat", "from b1")).await?;
    b2.send(&message("alice@quark.test/one", "chat", "from b2")).await?;
    let got = alice.expect(|e| e.name() == "message" && e.attr("type") == Some("chat")).await?;
    assert_eq!(got.child_text("body", ns::CLIENT).as_deref(), Some("from b2"), "{got}");
    let deadline = tokio::time::Instant::now() + QUIET;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Some(e) = alice.recv_within(left).await? else { break };
        ensure!(e.child_text("body", ns::CLIENT).as_deref() != Some("from b1"), "blocked resource got through: {e}");
    }
    Ok(())
}

/// §3.3 / §3.4: blocking a contact sends it unavailable presence and stops presence updates;
/// unblocking sends current presence again.
#[tokio::test]
async fn blocked_contact_stops_seeing_presence() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    s.make_contacts("alice", "bob").await?;
    let mut bob = s.online("bob", PW, "b").await?;
    let mut alice = s.online("alice", PW, "one").await?;
    bob.expect(|e| e.name() == "presence" && e.attr("from") == Some("alice@quark.test/one") && e.attr("type").is_none()).await?;

    set_ok(&mut alice, block(&["bob@quark.test"])).await?;
    bob.expect(|e| e.name() == "presence" && e.attr("from") == Some("alice@quark.test/one") && e.attr("type") == Some("unavailable"))
        .await
        .context("blocking MUST send unavailable presence to the contact")?;

    alice.send(&presence(None, None).text_child("status", ns::CLIENT, "busy")).await?;
    nothing_from(&mut bob, "alice@quark.test", true).await?;

    set_ok(&mut alice, unblock(&["bob@quark.test"])).await?;
    let p = bob
        .expect(|e| e.name() == "presence" && e.attr("from") == Some("alice@quark.test/one") && e.attr("type").is_none())
        .await
        .context("unblocking MUST send current presence")?;
    assert_eq!(p.child_text("status", ns::CLIENT).as_deref(), Some("busy"), "the *current* presence: {p}");
    Ok(())
}

/// §3.3: the user sending to a blocked JID gets `<not-acceptable/>` with
/// `<blocked xmlns='urn:xmpp:blocking:errors'/>`; nothing is routed.
#[tokio::test]
async fn sending_to_blocked_jid_is_refused() -> anyhow::Result<()> {
    let s = server(&["alice", "carol"]).await?;
    let mut carol = s.online("carol", PW, "c").await?;
    let mut alice = s.online("alice", PW, "one").await?;
    set_ok(&mut alice, block(&["carol@quark.test"])).await?;

    let m = message("carol@quark.test", "chat", "oops");
    let id = m.attr("id").map(str::to_string);
    alice.send(&m).await?;
    let err = alice.expect(|e| e.name() == "message" && e.attr("type") == Some("error")).await?;
    assert_eq!(err.attr("id"), id.as_deref(), "{err}");
    assert_eq!(condition(&err).as_deref(), Some("not-acceptable"), "{err}");
    ensure!(app_error(&err, ns::BLOCKING_ERRORS).is_some_and(|b| b.name() == "blocked"), "no <blocked/>: {err}");

    let r = alice.iq_get(Some("carol@quark.test/c"), Element::new("ping", ns::PING)).await?;
    assert_eq!(r.attr("type"), Some("error"), "{r}");
    assert_eq!(condition(&r).as_deref(), Some("not-acceptable"), "{r}");
    ensure!(app_error(&r, ns::BLOCKING_ERRORS).is_some(), "{r}");

    nothing_from(&mut carol, "alice@quark.test", false).await?;
    Ok(())
}

/// §3.3: a blocked contact gets nothing from the user, PEP events included, and can't read
/// the user's presence-model PEP items.
#[tokio::test]
async fn blocked_contact_gets_no_pep_events() -> anyhow::Result<()> {
    const TUNE: &str = "http://jabber.org/protocol/tune";
    let s = server(&["alice", "bob"]).await?;
    s.make_contacts("alice", "bob").await?;
    let mut bob = online_caps(&s, "bob", "b", &["http://jabber.org/protocol/tune+notify"]).await?;
    let mut alice = s.online("alice", PW, "one").await?;
    set_ok(&mut alice, block(&["bob@quark.test"])).await?;
    let r = alice.iq_set(None, publish(TUNE, Some("t1"), Element::new("tune", TUNE), &[])).await?;
    ensure!(is_result(&r), "{r}");
    nothing_from(&mut bob, "alice@quark.test", false).await?;
    let r = bob.iq_get(Some("alice@quark.test"), items_request(TUNE, &[])).await?;
    ensure!(r.attr("type") == Some("error") && items_of(&r).is_empty(), "a blocked contact read PEP items: {r}");
    Ok(())
}

/// §3.3: messages from a blocked JID to an offline user aren't stored for later either.
#[tokio::test]
async fn blocked_messages_are_not_stored_offline() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut alice = s.online("alice", PW, "one").await?;
    set_ok(&mut alice, block(&["bob@quark.test"])).await?;
    alice.close().await?;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let mut bob = s.online("bob", PW, "b").await?;
    bob.send(&message("alice@quark.test", "chat", "while you were out")).await?;
    bob.expect(|e| e.name() == "message" && e.attr("type") == Some("error")).await?;

    let mut alice = s.online("alice", PW, "one").await?;
    nothing_from(&mut alice, "bob@quark.test", false).await?;
    Ok(())
}
