//! XEP-0357 Push Notifications, with a second local account's resource standing in for the
//! app server. Black-box: written from the XEP only.

mod blind_xep;

use std::time::Duration;

use anyhow::{bail, ensure, Context as _};
use blind_xep::*;
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{message, Client, TestServer};

const APP: &str = "pushsvc@quark.test/app";
const PUBLISH_OPTIONS: &str = "http://jabber.org/protocol/pubsub#publish-options";
const SUMMARY: &str = "urn:xmpp:push:summary";

async fn server() -> anyhow::Result<TestServer> {
    let s = TestServer::start().await?;
    for u in ["alice", "bob", "pushsvc"] {
        s.add_user(u, PW).await?;
    }
    s.make_contacts("alice", "bob").await?;
    Ok(s)
}

fn enable(node: &str, options: &[(&str, &str)]) -> Element {
    let mut e = Element::new("enable", ns::PUSH).attr_set("jid", APP).attr_set("node", node);
    if !options.is_empty() {
        e.append(form("submit", PUBLISH_OPTIONS, options));
    }
    e
}

async fn enable_ok(c: &mut Client, node: &str, options: &[(&str, &str)]) -> anyhow::Result<()> {
    let r = c.iq_set(None, enable(node, options)).await?;
    ensure!(is_result(&r), "enable failed: {r}");
    Ok(())
}

fn is_push(e: &Element) -> bool {
    e.name() == "iq" && e.attr("type") == Some("set") && e.has_child("pubsub", ns::PUBSUB)
}

/// The next push the app server receives; it answers with a result.
async fn next_push(app: &mut Client) -> anyhow::Result<Element> {
    let p = app.expect(is_push).await.context("the app server got no push notification")?;
    app.answer(&p).await?;
    Ok(p)
}

async fn no_push(app: &mut Client) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + QUIET;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match app.recv_within(left).await? {
            None => return Ok(()),
            Some(e) if is_push(&e) => bail!("expected no push, got {e}"),
            Some(_) => {}
        }
    }
}

/// Goes offline cleanly and gives the server a moment to notice.
async fn go_offline(c: Client) -> anyhow::Result<()> {
    c.close().await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    Ok(())
}

/// §4.1: the account advertises push support.
#[tokio::test]
async fn account_advertises_push() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.login("alice", PW).await?;
    let info = disco_info(&mut a, Some(&jid("alice"))).await?;
    ensure!(disco_features(&info).iter().any(|f| f == ns::PUSH), "{info}");
    Ok(())
}

/// §5 / §7: after enabling, a message for an offline account is published to the push
/// service: an IQ set from the user's server (or account) to the service JID with
/// `<publish node>` + `<notification/>`, the enable form echoed as publish-options, and a
/// summary form (if any) carrying only §11.3.1 fields.
#[tokio::test]
async fn offline_message_publishes_notification() -> anyhow::Result<()> {
    let s = server().await?;
    let mut app = s.online("pushsvc", PW, "app").await?;
    let mut alice = s.online("alice", PW, "phone").await?;
    enable_ok(&mut alice, "node-1", &[("secret", "s3cr3t")]).await?;
    go_offline(alice).await?;

    let mut bob = s.online("bob", PW, "b").await?;
    bob.send(&message(&jid("alice"), "chat", "wake up")).await?;

    let p = next_push(&mut app).await?;
    assert_eq!(p.attr("to"), Some(APP), "{p}");
    let from = p.attr("from").unwrap_or("");
    ensure!(from == s.domain() || from == jid("alice"), "the publish comes from the user's server/account, got from={from}: {p}");
    let ps = p.get_child("pubsub", ns::PUBSUB).context("no pubsub")?;
    let publish = ps.get_child("publish", ns::PUBSUB).context("no publish")?;
    assert_eq!(publish.attr("node"), Some("node-1"), "{p}");
    let notification = publish
        .get_child("item", ns::PUBSUB)
        .and_then(|i| i.get_child("notification", ns::PUSH))
        .with_context(|| format!("no <item><notification/></item>: {p}"))?;

    let opts = ps
        .get_child("publish-options", ns::PUBSUB)
        .and_then(|o| o.get_child("x", ns::DATA_FORMS))
        .with_context(|| format!("§7: the enable form SHOULD come back as publish-options: {p}"))?;
    assert_eq!(form_type(opts).as_deref(), Some(PUBLISH_OPTIONS), "{p}");
    assert_eq!(field_values(opts, "secret"), ["s3cr3t"], "{p}");

    if let Some(summary) = notification.get_child("x", ns::DATA_FORMS) {
        assert_eq!(form_type(summary).as_deref(), Some(SUMMARY), "{p}");
        let allowed = ["FORM_TYPE", "message-count", "pending-subscription-count", "last-message-sender", "last-message-body"];
        for f in summary.children().filter(|c| c.is("field", ns::DATA_FORMS)) {
            let var = f.attr("var").unwrap_or("");
            ensure!(allowed.contains(&var), "summary field {var:?} isn't defined by §11.3.1: {p}");
        }
        for n in field_values(summary, "message-count") {
            ensure!(n.parse::<u64>().is_ok_and(|n| n >= 1), "message-count {n:?}: {p}");
        }
        for j in field_values(summary, "last-message-sender") {
            ensure!(j == jid("bob") || j.starts_with(&format!("{}/", jid("bob"))), "last-message-sender {j}: {p}");
        }
        for b in field_values(summary, "last-message-body") {
            assert_eq!(b, "wake up", "{p}");
        }
    }
    Ok(())
}

/// §7: nothing is published while the account is online and gets the message itself.
#[tokio::test]
async fn no_notification_while_online() -> anyhow::Result<()> {
    let s = server().await?;
    let mut app = s.online("pushsvc", PW, "app").await?;
    let mut alice = s.online("alice", PW, "phone").await?;
    enable_ok(&mut alice, "node-1", &[]).await?;

    let mut bob = s.online("bob", PW, "b").await?;
    bob.send(&message(&jid("alice"), "chat", "you there?")).await?;
    alice.expect(|e| e.name() == "message" && e.child_text("body", ns::CLIENT).as_deref() == Some("you there?")).await?;
    no_push(&mut app).await
}

/// §7 with XEP-0198: a phone whose connection dropped (session waiting to resume) is woken.
#[tokio::test]
async fn hibernated_session_gets_notification() -> anyhow::Result<()> {
    let s = server().await?;
    let mut app = s.online("pushsvc", PW, "app").await?;
    let mut alice = s.online("alice", PW, "phone").await?;
    alice.send(&Element::new("enable", ns::SM).attr_set("resume", "true")).await?;
    let en = alice.expect(|e| e.ns() == ns::SM && matches!(e.name(), "enabled" | "failed")).await?;
    ensure!(en.name() == "enabled" && matches!(en.attr("resume"), Some("true" | "1")), "stream management with resumption: {en}");
    enable_ok(&mut alice, "node-1", &[]).await?;
    alice.drop_connection();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut bob = s.online("bob", PW, "b").await?;
    bob.send(&message(&jid("alice"), "chat", "ring ring")).await?;
    let p = next_push(&mut app).await?;
    let node = p.get_child("pubsub", ns::PUBSUB).and_then(|ps| ps.get_child("publish", ns::PUBSUB)).and_then(|pb| pb.attr("node"));
    assert_eq!(node, Some("node-1"), "{p}");
    Ok(())
}

/// §5 / §7: every enabled (jid, node) pair is notified.
#[tokio::test]
async fn each_enabled_node_is_notified() -> anyhow::Result<()> {
    let s = server().await?;
    let mut app = s.online("pushsvc", PW, "app").await?;
    let mut alice = s.online("alice", PW, "phone").await?;
    enable_ok(&mut alice, "node-a", &[]).await?;
    enable_ok(&mut alice, "node-b", &[]).await?;
    go_offline(alice).await?;

    let mut bob = s.online("bob", PW, "b").await?;
    bob.send(&message(&jid("alice"), "chat", "hello")).await?;
    let mut nodes = Vec::new();
    for _ in 0..2 {
        let p = next_push(&mut app).await?;
        let n = p.get_child("pubsub", ns::PUBSUB).and_then(|ps| ps.get_child("publish", ns::PUBSUB)).and_then(|pb| pb.attr("node"));
        nodes.push(n.unwrap_or_default().to_string());
    }
    nodes.sort();
    assert_eq!(nodes, ["node-a", "node-b"]);
    Ok(())
}

/// §6: disabling a (jid, node) pair stops notifications for it.
#[tokio::test]
async fn disable_stops_notifications() -> anyhow::Result<()> {
    let s = server().await?;
    let mut app = s.online("pushsvc", PW, "app").await?;
    let mut alice = s.online("alice", PW, "phone").await?;
    enable_ok(&mut alice, "node-1", &[]).await?;
    let r = alice.iq_set(None, Element::new("disable", ns::PUSH).attr_set("jid", APP).attr_set("node", "node-1")).await?;
    ensure!(is_result(&r), "disable failed: {r}");
    go_offline(alice).await?;

    let mut bob = s.online("bob", PW, "b").await?;
    bob.send(&message(&jid("alice"), "chat", "hello?")).await?;
    no_push(&mut app).await
}

/// §6: disabling with only `jid` disables every node of that service (SHOULD).
#[tokio::test]
async fn disable_without_node_disables_all_nodes() -> anyhow::Result<()> {
    let s = server().await?;
    let mut app = s.online("pushsvc", PW, "app").await?;
    let mut alice = s.online("alice", PW, "phone").await?;
    enable_ok(&mut alice, "node-a", &[]).await?;
    enable_ok(&mut alice, "node-b", &[]).await?;
    let r = alice.iq_set(None, Element::new("disable", ns::PUSH).attr_set("jid", APP)).await?;
    ensure!(is_result(&r), "disable failed: {r}");
    go_offline(alice).await?;

    let mut bob = s.online("bob", PW, "b").await?;
    bob.send(&message(&jid("alice"), "chat", "hello?")).await?;
    no_push(&mut app).await
}

/// §5: `jid` is required on enable.
#[tokio::test]
async fn enable_without_jid_is_refused() -> anyhow::Result<()> {
    let s = server().await?;
    let mut alice = s.login("alice", PW).await?;
    let r = alice.iq_set(None, Element::new("enable", ns::PUSH).attr_set("node", "n")).await?;
    assert_eq!(r.attr("type"), Some("error"), "{r}");
    Ok(())
}
