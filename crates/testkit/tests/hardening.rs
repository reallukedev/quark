//! Limits and checks that keep one party from hurting others: forged IQ answers, presence
//! leaking past block lists, replaced sessions, request floods, storage caps, bad characters.

use std::time::Duration;

use quark::modules::roster;
use quark_testkit::quark_core::{ns, Element, Jid};
use quark_testkit::{presence, Client, Options, TestServer, DOMAIN};

const PW: &str = "password-1";
const QUIET: Duration = Duration::from_millis(500);

fn jid(user: &str) -> String {
    format!("{user}@{DOMAIN}")
}

fn block(j: &str) -> Element {
    Element::new("block", ns::BLOCKING).child(Element::new("item", ns::BLOCKING).attr_set("jid", j))
}

/// Everything that arrives within `QUIET`.
async fn drain(c: &mut Client) -> anyhow::Result<Vec<Element>> {
    let mut got = Vec::new();
    while let Some(e) = c.recv_within(QUIET).await? {
        got.push(e);
    }
    Ok(got)
}

fn presence_from<'a>(got: &'a [Element], from_bare: &str) -> Vec<&'a Element> {
    got.iter().filter(|e| e.name() == "presence" && e.attr("from").is_some_and(|f| f.split('/').next() == Some(from_bare))).collect()
}

#[tokio::test]
async fn only_the_entity_asked_can_answer_a_server_request() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", PW).await?;
    s.add_user("bob", PW).await?;
    let mut alice = s.login_as("alice", PW, "phone").await?;
    let mut bob = s.login_as("bob", PW, "phone").await?;
    let srv = s.srv.clone();
    let ask = quark_testkit::quark_core::stanza::iq(
        "get",
        "",
        Some(DOMAIN),
        Some(&format!("{}/phone", jid("bob"))),
        Element::new("ping", ns::PING),
    );
    let pending = tokio::spawn(async move { srv.request(ask, Duration::from_secs(10)).await });
    let got = bob.expect(|e| e.name() == "iq" && e.has_child("ping", ns::PING)).await?;
    let id = got.attr("id").unwrap_or_default().to_string();
    // Alice learned (or guessed) the id and answers first: that answer is ignored.
    let forged = Element::new("iq", ns::CLIENT).attr_set("type", "error").attr_set("id", id.as_str()).attr_set("to", DOMAIN);
    alice.send(&forged).await?;
    tokio::time::sleep(QUIET).await;
    assert!(!pending.is_finished(), "a third party's answer was taken");
    bob.answer(&got).await?;
    let r = tokio::time::timeout(Duration::from_secs(5), pending).await??;
    assert!(r.is_ok(), "{r:?}");
    Ok(())
}

#[tokio::test]
async fn contacts_presence_at_sign_in_respects_block_lists() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    for u in ["alice", "bob", "carol"] {
        s.add_user(u, PW).await?;
    }
    s.make_contacts("alice", "bob").await?;
    s.make_contacts("alice", "carol").await?;
    // Bob blocked Alice; Alice blocked Carol. Both are online when Alice signs in.
    let mut bob = s.online("bob", PW, "phone").await?;
    bob.iq_set(None, block(&jid("alice"))).await?;
    let _carol = s.online("carol", PW, "phone").await?;
    let mut alice = s.login_as("alice", PW, "phone").await?;
    alice.iq_set(None, block(&jid("carol"))).await?;
    drain(&mut alice).await?;
    alice.send(&presence(None, None)).await?;
    let got = drain(&mut alice).await?;
    assert!(presence_from(&got, &jid("bob")).is_empty(), "Bob blocked Alice but she saw his presence: {got:?}");
    assert!(presence_from(&got, &jid("carol")).is_empty(), "Alice blocked Carol but saw her presence: {got:?}");
    Ok(())
}

#[tokio::test]
async fn a_replaced_session_does_not_take_the_new_one_offline() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", PW).await?;
    s.add_user("bob", PW).await?;
    s.make_contacts("alice", "bob").await?;
    let mut bob = s.online("bob", PW, "laptop").await?;
    let _old = s.online("alice", PW, "phone").await?;
    bob.expect(|e| e.name() == "presence" && e.attr("from") == Some(&format!("{}/phone", jid("alice"))) && e.attr("type").is_none())
        .await?;
    // The same resource signs in again: the old session is closed with a conflict.
    let _new = s.online("alice", PW, "phone").await?;
    tokio::time::sleep(QUIET).await;
    let got = drain(&mut bob).await?;
    let gone: Vec<_> = presence_from(&got, &jid("alice")).into_iter().filter(|p| p.attr("type") == Some("unavailable")).collect();
    assert!(gone.is_empty(), "Bob was told the active device went offline: {gone:?}");
    let full = Jid::parse(&format!("{}/phone", jid("alice")))?;
    assert!(s.srv.sessions.get(&full).is_some_and(|h| h.available()));
    Ok(())
}

#[tokio::test]
async fn subscription_requests_are_capped_and_trimmed() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", PW).await?;
    let me = jid("alice");
    let ask = |i: usize| {
        Element::new("presence", ns::CLIENT)
            .attr_set("from", format!("u{i}@flood.example"))
            .attr_set("to", me.as_str())
            .attr_set("type", "subscribe")
            .text_child("status", ns::CLIENT, "hi")
            .child(Element::new("junk", "urn:x:junk").text("x".repeat(10_000)))
    };
    for i in 0..quark::modules::presence::MAX_PENDING + 20 {
        s.srv.route(ask(i)).await;
    }
    assert_eq!(roster::count_pending(&s.srv, DOMAIN, "alice").await?, quark::modules::presence::MAX_PENDING);
    let first = roster::item(&s.srv, DOMAIN, "alice", &Jid::parse("u0@flood.example")?).await?.and_then(|i| i.pending_in);
    let stored = Element::parse(&first.unwrap_or_default())?;
    assert_eq!(stored.child_text("status", ns::CLIENT).as_deref(), Some("hi"));
    assert!(stored.get_child("junk", "urn:x:junk").is_none(), "{stored}");
    // Someone already waiting can still ask again.
    s.srv.route(ask(0)).await;
    assert_eq!(roster::count_pending(&s.srv, DOMAIN, "alice").await?, quark::modules::presence::MAX_PENDING);
    Ok(())
}

#[tokio::test]
async fn private_storage_is_capped_per_account() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", PW).await?;
    let mut a = s.login("alice", PW).await?;
    let item = |i: usize| Element::new("query", ns::PRIVATE).child(Element::new("data", format!("urn:example:{i}")).text("x"));
    for i in 0..256 {
        let r = a.iq_set(None, item(i)).await?;
        assert_eq!(r.attr("type"), Some("result"), "{i}: {r}");
    }
    let r = a.iq_set(None, item(256)).await?;
    assert_eq!(r.attr("type"), Some("error"), "{r}");
    let e = r.get_child("error", ns::CLIENT).expect("error");
    assert!(e.has_child("resource-constraint", ns::STANZAS), "{r}");
    // Changing something already stored still works.
    let r = a.iq_set(None, item(3)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    Ok(())
}

#[tokio::test]
async fn control_characters_end_the_stream_and_go_nowhere() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", PW).await?;
    s.add_user("bob", PW).await?;
    let mut bob = s.online("bob", PW, "phone").await?;
    let mut alice = s.login("alice", PW).await?;
    alice.send_raw(&format!("<message to='{}' type='chat'><body>a&#1;b</body></message>", jid("bob"))).await?;
    let el = alice.recv().await?;
    assert!(el.is("error", ns::STREAM) && el.has_child("not-well-formed", ns::STREAMS), "{el}");
    bob.expect_silence(QUIET).await?;
    // A namespaced attribute travels with its declaration, so the receiver can read it.
    let mut alice = s.login_as("alice", PW, "two").await?;
    alice.send_raw(&format!("<message to='{}' type='chat' xmlns:p='urn:example:p' p:x='1'><body>ok</body></message>", jid("bob"))).await?;
    let got = bob.expect(|e| e.name() == "message").await?;
    assert_eq!(got.attr_ns("urn:example:p", "x"), Some("1"), "{got}");
    Ok(())
}

#[tokio::test]
async fn connections_signing_in_are_capped_per_address() -> anyhow::Result<()> {
    let s =
        TestServer::start_with(Options { extra_config: "[limits]\nmax_unauthenticated_per_ip = 2\n".into(), ..Default::default() }).await?;
    s.add_user("alice", PW).await?;
    let first = Client::connect(s.c2s(), s.domain()).await?;
    let _second = Client::connect(s.c2s(), s.domain()).await?;
    assert!(Client::connect(s.c2s(), s.domain()).await.is_err(), "a third connection signing in from one address is refused");
    // Ending one gives its place back, and a signed-in session doesn't hold one.
    drop(first);
    let mut alice = None;
    for _ in 0..50 {
        if let Ok(c) = s.login("alice", PW).await {
            alice = Some(c);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut alice = alice.expect("signing in works again once a place is free");
    let _third = Client::connect(s.c2s(), s.domain()).await?;
    let r = alice.iq_get(Some(s.domain()), Element::new("ping", ns::PING)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    Ok(())
}
