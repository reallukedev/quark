//! Push Notifications (XEP-0357), end to end. The "app server" is another account's device: the
//! server publishes to whatever JID the app registered.

use std::time::Duration;

use quark_testkit::quark_core::stanza::iq_result;
use quark_testkit::quark_core::{ns, Element, Jid};
use quark_testkit::{message, Client, TestServer, DOMAIN};

const QUIET: Duration = Duration::from_millis(400);
const PRIORITY: &str = "tigase:push:priority:0";

fn field(var: &str, value: &str) -> Element {
    Element::new("field", ns::DATA_FORMS).attr_set("var", var).text_child("value", ns::DATA_FORMS, value)
}

fn form_value(x: &Element, var: &str) -> Option<String> {
    x.children().find(|f| f.attr("var") == Some(var)).and_then(|f| f.child_text("value", ns::DATA_FORMS))
}

fn enable(service: &str, node: &str, secret: &str) -> Element {
    Element::new("enable", ns::PUSH).attr_set("jid", service).attr_set("node", node).child(
        Element::new("x", ns::DATA_FORMS)
            .attr_set("type", "submit")
            .child(field("FORM_TYPE", "http://jabber.org/protocol/pubsub#publish-options"))
            .child(field("secret", secret)),
    )
}

fn is_publish(e: &Element) -> bool {
    e.name() == "iq" && e.attr("type") == Some("set") && e.has_child("pubsub", ns::PUBSUB)
}

async fn wait_offline(s: &TestServer, jid: &str) -> anyhow::Result<()> {
    let j = Jid::parse(jid)?;
    for _ in 0..100 {
        if s.srv.sessions.get(&j).is_none() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!("{jid} is still online")
}

async fn wait_hibernating(s: &TestServer, jid: &str) -> anyhow::Result<()> {
    let j = Jid::parse(jid)?;
    for _ in 0..100 {
        if s.srv.sessions.get(&j).is_some_and(|x| x.flags.lock().hibernating) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!("{jid} never started waiting for resumption")
}

async fn registrations(s: &TestServer) -> anyhow::Result<i64> {
    Ok(s.srv.db.read(|c| c.query_row("SELECT COUNT(*) FROM push_registrations", quark::db::params![], |r| r.get(0))).await?)
}

struct Setup {
    s: TestServer,
    alice: Client,
    app: Client,
    app_jid: String,
}

async fn setup() -> anyhow::Result<Setup> {
    let s = TestServer::start().await?;
    for u in ["alice", "bob", "app"] {
        s.add_user(u, &format!("password-{u}")).await?;
    }
    let alice = s.online("alice", "password-alice", "laptop").await?;
    let app = s.login_as("app", "password-app", "svc").await?;
    Ok(Setup { s, alice, app, app_jid: format!("app@{DOMAIN}/svc") })
}

#[tokio::test]
async fn an_offline_device_is_woken_without_revealing_the_message() -> anyhow::Result<()> {
    let Setup { s, mut alice, mut app, app_jid } = setup().await?;
    let mut bob = s.online("bob", "password-bob", "phone").await?;

    let info = bob.iq_get(Some(&format!("bob@{DOMAIN}")), Element::new("query", ns::DISCO_INFO)).await?;
    let features: Vec<_> =
        info.get_child("query", ns::DISCO_INFO).unwrap().children().filter_map(|c| c.attr("var")).map(String::from).collect();
    assert!(features.iter().any(|f| f == ns::PUSH) && features.iter().any(|f| f == PRIORITY), "{features:?}");

    let r = bob.iq_set(None, enable(&app_jid, "node-1", "s3cret")).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");

    // While the phone is connected, nothing is pushed.
    alice.send(&message(&format!("bob@{DOMAIN}"), "chat", "are you there?")).await?;
    bob.expect(|e| e.name() == "message").await?;
    app.expect_silence(QUIET).await?;

    bob.close().await?;
    wait_offline(&s, &format!("bob@{DOMAIN}/phone")).await?;
    alice.send(&message(&format!("bob@{DOMAIN}"), "chat", "the secret plan is…")).await?;
    let iq = app.expect(is_publish).await?;
    assert_eq!(iq.attr("from"), Some(&*format!("bob@{DOMAIN}")));
    let pubsub = iq.get_child("pubsub", ns::PUBSUB).unwrap();
    let publish = pubsub.get_child("publish", ns::PUBSUB).unwrap();
    assert_eq!(publish.attr("node"), Some("node-1"));
    let note = publish.get_child("item", ns::PUBSUB).unwrap().get_child("notification", ns::PUSH).unwrap();
    assert_eq!(note.child_text("priority", PRIORITY).as_deref(), Some("high"));
    assert!(!iq.to_xml().contains("secret plan"), "{iq}");
    assert!(!iq.to_xml().contains("alice"), "{iq}");
    let opts = pubsub.get_child("publish-options", ns::PUBSUB).unwrap().get_child("x", ns::DATA_FORMS).unwrap();
    assert_eq!(form_value(opts, "secret").as_deref(), Some("s3cret"));
    app.send(&iq_result(&iq)).await?;

    // Read markers wake the app quietly; typing notifications don't wake it at all.
    let marker = Element::new("message", ns::CLIENT)
        .attr_set("to", format!("bob@{DOMAIN}"))
        .attr_set("type", "chat")
        .child(Element::new("displayed", ns::CHAT_MARKERS).attr_set("id", "m1"));
    alice.send(&marker).await?;
    let iq = app.expect(is_publish).await?;
    assert!(iq.to_xml().contains(">normal<"), "{iq}");
    app.send(&iq_result(&iq)).await?;
    let typing = Element::new("message", ns::CLIENT)
        .attr_set("to", format!("bob@{DOMAIN}"))
        .attr_set("type", "chat")
        .child(Element::new("composing", ns::CHAT_STATES));
    alice.send(&typing).await?;
    app.expect_silence(QUIET).await?;
    Ok(())
}

#[tokio::test]
async fn a_dropped_connection_waiting_to_resume_is_woken() -> anyhow::Result<()> {
    let Setup { s, mut alice, mut app, app_jid } = setup().await?;
    let mut bob = s.online("bob", "password-bob", "phone").await?;
    bob.iq_set(None, enable(&app_jid, "node-1", "x")).await?;
    bob.send_raw("<enable xmlns='urn:xmpp:sm:3' resume='true'/>").await?;
    bob.expect(|e| e.is("enabled", ns::SM)).await?;
    bob.drop_connection();
    wait_hibernating(&s, &format!("bob@{DOMAIN}/phone")).await?;

    alice.send(&message(&format!("bob@{DOMAIN}"), "chat", "wake up")).await?;
    let iq = app.expect(is_publish).await?;
    app.send(&iq_result(&iq)).await?;
    Ok(())
}

#[tokio::test]
async fn disabling_or_a_refusing_app_server_stops_pushes() -> anyhow::Result<()> {
    let Setup { s, mut alice, mut app, app_jid } = setup().await?;
    let mut bob = s.login_as("bob", "password-bob", "phone").await?;
    bob.iq_set(None, enable(&app_jid, "node-1", "x")).await?;
    bob.iq_set(None, enable(&app_jid, "node-2", "y")).await?;
    assert_eq!(registrations(&s).await?, 2);

    // Disabling one node leaves the other.
    let r = bob.iq_set(None, Element::new("disable", ns::PUSH).attr_set("jid", &*app_jid).attr_set("node", "node-1")).await?;
    assert_eq!(r.attr("type"), Some("result"));
    assert_eq!(registrations(&s).await?, 1);
    bob.close().await?;
    wait_offline(&s, &format!("bob@{DOMAIN}/phone")).await?;

    alice.send(&message(&format!("bob@{DOMAIN}"), "chat", "one")).await?;
    let iq = app.expect(is_publish).await?;
    assert!(iq.to_xml().contains("node-2"));
    app.expect_silence(QUIET).await?;

    // The app was uninstalled: the app server says the node is gone, and the server forgets it.
    let err = Element::new("iq", ns::CLIENT)
        .attr_set("type", "error")
        .attr_set("id", iq.attr("id").unwrap_or_default())
        .attr_set("to", iq.attr("from").unwrap_or_default())
        .child(Element::new("error", ns::CLIENT).attr_set("type", "cancel").child(Element::new("item-not-found", ns::STANZAS)));
    app.send(&err).await?;
    for _ in 0..100 {
        if registrations(&s).await? == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(registrations(&s).await?, 0);
    alice.send(&message(&format!("bob@{DOMAIN}"), "chat", "two")).await?;
    app.expect_silence(QUIET).await?;
    Ok(())
}

#[tokio::test]
async fn push_can_be_turned_off_for_the_domain() -> anyhow::Result<()> {
    let Setup { s, mut alice, mut app, app_jid } = setup().await?;
    let mut bob = s.login_as("bob", "password-bob", "phone").await?;
    bob.iq_set(None, enable(&app_jid, "node-1", "x")).await?;
    s.set_settings(|st| st.push = false).await?;

    let r = bob.iq_set(None, enable(&app_jid, "node-2", "x")).await?;
    assert_eq!(r.attr("type"), Some("error"));
    let info = bob.iq_get(Some(&format!("bob@{DOMAIN}")), Element::new("query", ns::DISCO_INFO)).await?;
    assert!(!info.to_xml().contains(ns::PUSH), "{info}");

    bob.close().await?;
    wait_offline(&s, &format!("bob@{DOMAIN}/phone")).await?;
    alice.send(&message(&format!("bob@{DOMAIN}"), "chat", "hi")).await?;
    app.expect_silence(QUIET).await?;

    // Bad requests: no node, someone else's account.
    s.set_settings(|st| st.push = true).await?;
    let r = alice.iq_set(None, Element::new("enable", ns::PUSH).attr_set("jid", &*app_jid)).await?;
    assert_eq!(r.attr("type"), Some("error"));
    let r = alice.iq_set(Some(&format!("bob@{DOMAIN}")), enable(&app_jid, "n", "x")).await?;
    assert_eq!(r.attr("type"), Some("error"));
    Ok(())
}
