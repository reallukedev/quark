//! Helpers shared by the black-box `blind_*` conformance tests. Written from the RFCs/XEPs only.
#![allow(dead_code)]

use std::time::Duration;

use anyhow::{bail, Context as _};
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{Client, TestServer, DOMAIN};

/// The password every test account uses.
pub const PW: &str = "password1";

/// How long we listen to conclude that something did not arrive.
pub const QUIET: Duration = Duration::from_millis(400);

/// `user@quark.test`.
pub fn bare(user: &str) -> String {
    format!("{user}@{DOMAIN}")
}

/// `user@quark.test/res`.
pub fn full(user: &str, res: &str) -> String {
    format!("{user}@{DOMAIN}/{res}")
}

/// A server with these accounts (all with [`PW`]).
pub async fn server(users: &[&str]) -> anyhow::Result<TestServer> {
    let s = TestServer::start().await?;
    for u in users {
        s.add_user(u, PW).await?;
    }
    Ok(s)
}

/// The full JID a client bound.
pub fn me(c: &Client) -> String {
    c.jid.clone().unwrap_or_default()
}

/// The presence `type`, with the absent attribute meaning "available".
pub fn ptype(e: &Element) -> &str {
    e.attr("type").unwrap_or("available")
}

pub fn is_presence(e: &Element, from: &str, kind: &str) -> bool {
    e.name() == "presence" && e.attr("from") == Some(from) && ptype(e) == kind
}

pub fn is_message_with_body(e: &Element, body: &str) -> bool {
    e.name() == "message" && e.child_text("body", ns::CLIENT).as_deref() == Some(body)
}

pub fn is_roster_push(e: &Element) -> bool {
    e.name() == "iq" && e.attr("type") == Some("set") && e.get_child("query", ns::ROSTER).is_some()
}

/// The defined condition of a stanza error (`<error><cond xmlns='…stanzas'/></error>`).
pub fn error_condition(e: &Element) -> Option<String> {
    let err = e.get_child("error", ns::CLIENT)?;
    err.children().find(|c| c.ns() == ns::STANZAS && c.name() != "text").map(|c| c.name().to_string())
}

/// Asserts `e` is a stanza error with one of `conds`.
pub fn assert_error(e: &Element, conds: &[&str]) {
    assert_eq!(e.attr("type"), Some("error"), "expected an error, got {e}");
    let c = error_condition(e);
    assert!(c.as_deref().is_some_and(|c| conds.contains(&c)), "expected one of {conds:?}, got {c:?} in {e}");
}

/// A roster item as the client sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub jid: String,
    pub name: Option<String>,
    pub subscription: String,
    pub ask: Option<String>,
    pub approved: bool,
    pub groups: Vec<String>,
}

pub fn items(query: &Element) -> Vec<Item> {
    query
        .children()
        .filter(|c| c.is("item", ns::ROSTER))
        .map(|c| {
            let mut groups: Vec<String> = c.children().filter(|g| g.is("group", ns::ROSTER)).map(|g| g.text_content()).collect();
            groups.sort();
            Item {
                jid: c.attr("jid").unwrap_or_default().to_string(),
                name: c.attr("name").map(str::to_string),
                subscription: c.attr("subscription").unwrap_or("none").to_string(),
                ask: c.attr("ask").map(str::to_string),
                approved: matches!(c.attr("approved"), Some("true" | "1")),
                groups,
            }
        })
        .collect()
}

/// Fetches the roster and returns its items.
pub async fn roster(c: &mut Client) -> anyhow::Result<Vec<Item>> {
    let r = c.iq_get(None, Element::new("query", ns::ROSTER)).await?;
    if r.attr("type") != Some("result") {
        bail!("roster get failed: {r}");
    }
    Ok(r.get_child("query", ns::ROSTER).map(items).unwrap_or_default())
}

/// Fetches the roster like a client does after login, without caring about the answer (for
/// tests about something else, so a roster bug does not mask their own result).
pub async fn fetch_roster_quietly(c: &mut Client) -> anyhow::Result<()> {
    c.iq_get(None, Element::new("query", ns::ROSTER)).await?;
    Ok(())
}

/// The roster item for `jid`, if any.
pub async fn roster_item(c: &mut Client, jid: &str) -> anyhow::Result<Option<Item>> {
    Ok(roster(c).await?.into_iter().find(|i| i.jid == jid))
}

/// `<item jid=…/>` in the roster namespace.
pub fn item(jid: &str) -> Element {
    Element::new("item", ns::ROSTER).attr_set("jid", jid)
}

/// `<query xmlns='jabber:iq:roster'>{item}</query>`.
pub fn roster_query(item: Element) -> Element {
    Element::new("query", ns::ROSTER).child(item)
}

/// Sends a roster set with one item and returns the reply.
pub async fn roster_set(c: &mut Client, item: Element) -> anyhow::Result<Element> {
    c.iq_set(None, roster_query(item)).await
}

/// Waits for a roster push about `jid`, checks it is from the account itself (RFC 6121 §2.1.6),
/// answers it, and returns the pushed item.
pub async fn expect_push(c: &mut Client, jid: &str) -> anyhow::Result<Item> {
    let bare_me = c.bare().unwrap_or_default();
    let push = c
        .expect(|e| is_roster_push(e) && e.get_child("query", ns::ROSTER).is_some_and(|q| items(q).iter().any(|i| i.jid == jid)))
        .await
        .with_context(|| format!("no roster push for {jid}"))?;
    let from = push.attr("from");
    assert!(from.is_none() || from == Some(bare_me.as_str()), "roster push from someone else: {push}");
    c.answer(&push).await?;
    let q = push.get_child("query", ns::ROSTER).context("query")?;
    let all = items(q);
    assert_eq!(all.len(), 1, "a roster push carries exactly one item: {push}");
    all.into_iter().next().context("item")
}

/// Waits for a presence of `kind` from `from`.
pub async fn expect_presence(c: &mut Client, from: &str, kind: &str) -> anyhow::Result<Element> {
    c.expect(|e| is_presence(e, from, kind)).await.with_context(|| format!("no presence type={kind} from {from} at {}", me(c)))
}

/// Waits for a message with this body.
pub async fn expect_body(c: &mut Client, body: &str) -> anyhow::Result<Element> {
    c.expect(|e| is_message_with_body(e, body)).await.with_context(|| format!("no message '{body}' at {}", me(c)))
}

/// Reads everything that arrives until the stream is quiet for [`QUIET`], answering roster pushes.
pub async fn settle(c: &mut Client) -> anyhow::Result<Vec<Element>> {
    let mut got = Vec::new();
    while let Some(e) = c.recv_within(QUIET).await? {
        if is_roster_push(&e) {
            c.answer(&e).await?;
        }
        got.push(e);
    }
    Ok(got)
}

/// Asserts nothing matching `f` arrives (reading until quiet).
pub async fn assert_none(c: &mut Client, what: &str, f: impl Fn(&Element) -> bool) -> anyhow::Result<()> {
    let who = me(c);
    for e in settle(c).await? {
        assert!(!f(&e), "{who} should not have received {what}, got {e}");
    }
    Ok(())
}

/// Sends a presence with a type to someone.
pub async fn send_presence(c: &mut Client, to: &str, kind: &str) -> anyhow::Result<()> {
    c.send(&Element::new("presence", ns::CLIENT).attr_set("to", to).attr_set("type", kind)).await
}

/// `sub` subscribes to `target`'s presence and `target` approves. Afterwards `sub` has
/// subscription 'to' (or 'both') and `target` has 'from' (or 'both'). Both streams are settled.
pub async fn subscribe(sub: &mut Client, target: &mut Client) -> anyhow::Result<()> {
    let (s, t) = (sub.bare().context("bound")?, target.bare().context("bound")?);
    send_presence(sub, &t, "subscribe").await?;
    expect_presence(target, &s, "subscribe").await?;
    send_presence(target, &s, "subscribed").await?;
    expect_presence(sub, &t, "subscribed").await?;
    settle(sub).await?;
    settle(target).await?;
    Ok(())
}

/// Mutual ('both') subscription between two online clients.
pub async fn mutual(a: &mut Client, b: &mut Client) -> anyhow::Result<()> {
    subscribe(a, b).await?;
    subscribe(b, a).await?;
    Ok(())
}

/// `<presence>` with a priority (and optionally a show).
pub fn presence_with_priority(prio: i32) -> Element {
    Element::new("presence", ns::CLIENT).text_child("priority", ns::CLIENT, prio.to_string())
}

/// Logs in, fetches the roster and sends an initial presence with this priority.
pub async fn online_with_priority(s: &TestServer, user: &str, res: &str, prio: i32) -> anyhow::Result<Client> {
    let mut c = s.login_as(user, PW, res).await?;
    fetch_roster_quietly(&mut c).await?;
    c.send(&presence_with_priority(prio)).await?;
    Ok(c)
}

/// The `<delay xmlns='urn:xmpp:delay'/>` child, if any.
pub fn delay(e: &Element) -> Option<&Element> {
    e.get_child("delay", ns::DELAY)
}

/// Enables carbons (XEP-0280) and asserts the server accepted.
pub async fn enable_carbons(c: &mut Client) -> anyhow::Result<()> {
    let r = c.iq_set(None, Element::new("enable", ns::CARBONS)).await?;
    assert_eq!(r.attr("type"), Some("result"), "carbons enable IQ (XEP-0280 §4) must succeed, got {r}");
    Ok(())
}

/// A raw `<iq/>` with the given id, type, optional `to` and children.
pub fn raw_iq(kind: &str, id: &str, to: Option<&str>, children: Vec<Element>) -> Element {
    let mut iq = Element::new("iq", ns::CLIENT).attr_set("type", kind).attr_set("id", id).attr_opt("to", to);
    for c in children {
        iq.append(c);
    }
    iq
}
