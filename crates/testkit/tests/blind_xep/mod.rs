//! Small helpers shared by the `blind_pep`, `blind_web`, `blind_upload`, `blind_calls`,
//! `blind_blocking` and `blind_push` suites. Written from the specifications only.
#![allow(dead_code)]

use std::time::Duration;

use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{presence, Client, TestServer, DOMAIN};

pub const PW: &str = "password1";

/// A short wait used to show that something does *not* happen.
pub const QUIET: Duration = Duration::from_millis(800);

pub fn jid(user: &str) -> String {
    format!("{user}@{DOMAIN}")
}

/// The defined condition of a stanza error (RFC 6120 §8.3.3), with its type.
pub fn error_of(stanza: &Element) -> Option<(String, String)> {
    let e = stanza.get_child("error", ns::CLIENT)?;
    let kind = e.attr("type").unwrap_or("").to_string();
    let cond = e.children().find(|c| c.ns() == ns::STANZAS && c.name() != "text")?.name().to_string();
    Some((kind, cond))
}

pub fn condition(stanza: &Element) -> Option<String> {
    error_of(stanza).map(|(_, c)| c)
}

/// An application-specific child of `<error/>` in namespace `app_ns`.
pub fn app_error<'a>(stanza: &'a Element, app_ns: &str) -> Option<&'a Element> {
    stanza.get_child("error", ns::CLIENT)?.children().find(|c| c.ns() == app_ns)
}

pub fn is_result(iq: &Element) -> bool {
    iq.name() == "iq" && iq.attr("type") == Some("result")
}

/// Signs in, fetches the roster, then sends initial presence carrying XEP-0115 caps for
/// `features`. Waits for the presence echo and lets the server finish its caps lookup.
pub async fn online_caps(s: &TestServer, user: &str, resource: &str, features: &[&str]) -> anyhow::Result<Client> {
    let mut c = s.login_as(user, PW, resource).await?;
    c.iq_get(None, Element::new("query", ns::ROSTER)).await?;
    let caps = c.caps(features);
    c.send(&presence(None, None).child(caps)).await?;
    let me = c.jid.clone();
    c.expect(|e| e.name() == "presence" && e.attr("from") == me.as_deref() && e.attr("type").is_none()).await?;
    c.pump(Duration::from_millis(300)).await?;
    Ok(c)
}

/// A `jabber:x:data` form.
pub fn form(kind: &str, form_type: &str, fields: &[(&str, &str)]) -> Element {
    let mut x = Element::new("x", ns::DATA_FORMS).attr_set("type", kind);
    x.append(Element::new("field", ns::DATA_FORMS).attr_set("var", "FORM_TYPE").attr_set("type", "hidden").text_child(
        "value",
        ns::DATA_FORMS,
        form_type,
    ));
    for (var, value) in fields {
        x.append(Element::new("field", ns::DATA_FORMS).attr_set("var", *var).text_child("value", ns::DATA_FORMS, *value));
    }
    x
}

/// The value(s) of a form field.
pub fn field_values(form: &Element, var: &str) -> Vec<String> {
    form.children()
        .filter(|f| f.is("field", ns::DATA_FORMS) && f.attr("var") == Some(var))
        .flat_map(|f| f.children().filter(|v| v.is("value", ns::DATA_FORMS)).map(Element::text_content).collect::<Vec<_>>())
        .collect()
}

/// The FORM_TYPE of a form.
pub fn form_type(form: &Element) -> Option<String> {
    field_values(form, "FORM_TYPE").into_iter().next()
}

pub fn disco_features(info: &Element) -> Vec<String> {
    info.get_child("query", ns::DISCO_INFO)
        .map(|q| q.children().filter(|c| c.is("feature", ns::DISCO_INFO)).filter_map(|f| f.attr("var")).map(str::to_string).collect())
        .unwrap_or_default()
}

pub fn has_identity(info: &Element, category: &str, kind: &str) -> bool {
    info.get_child("query", ns::DISCO_INFO).is_some_and(|q| {
        q.children().any(|i| i.is("identity", ns::DISCO_INFO) && i.attr("category") == Some(category) && i.attr("type") == Some(kind))
    })
}

pub async fn disco_info(c: &mut Client, to: Option<&str>) -> anyhow::Result<Element> {
    c.iq_get(to, Element::new("query", ns::DISCO_INFO)).await
}

pub async fn disco_items(c: &mut Client, to: Option<&str>) -> anyhow::Result<Vec<String>> {
    let r = c.iq_get(to, Element::new("query", ns::DISCO_ITEMS)).await?;
    Ok(r.get_child("query", ns::DISCO_ITEMS)
        .map(|q| q.children().filter(|c| c.is("item", ns::DISCO_ITEMS)).filter_map(|i| i.attr("jid")).map(str::to_string).collect())
        .unwrap_or_default())
}

// ---- XEP-0060 builders ----

pub fn pubsub(child: Element) -> Element {
    Element::new("pubsub", ns::PUBSUB).child(child)
}

/// `<pubsub><publish node><item id?>payload</item></publish><publish-options?/></pubsub>`.
pub fn publish(node: &str, id: Option<&str>, payload: Element, options: &[(&str, &str)]) -> Element {
    let item = Element::new("item", ns::PUBSUB).attr_opt("id", id).child(payload);
    let mut ps = pubsub(Element::new("publish", ns::PUBSUB).attr_set("node", node).child(item));
    if !options.is_empty() {
        ps.append(Element::new("publish-options", ns::PUBSUB).child(form(
            "submit",
            "http://jabber.org/protocol/pubsub#publish-options",
            options,
        )));
    }
    ps
}

pub fn items_request(node: &str, ids: &[&str]) -> Element {
    let mut items = Element::new("items", ns::PUBSUB).attr_set("node", node);
    for id in ids {
        items.append(Element::new("item", ns::PUBSUB).attr_set("id", *id));
    }
    pubsub(items)
}

/// The `<item/>`s of an items result (or of an event).
pub fn items_of(el: &Element) -> Vec<Element> {
    let holder = el.get_child("pubsub", ns::PUBSUB).or_else(|| el.get_child("event", ns::PUBSUB_EVENT));
    let Some(holder) = holder else { return Vec::new() };
    holder
        .children()
        .filter(|c| c.name() == "items")
        .flat_map(|i| i.children().filter(|c| c.name() == "item").cloned().collect::<Vec<_>>())
        .collect()
}

pub fn item_ids(el: &Element) -> Vec<String> {
    items_of(el).iter().filter_map(|i| i.attr("id")).map(str::to_string).collect()
}

/// A PEP event message for `node`.
pub fn is_event_for(el: &Element, node: &str) -> bool {
    el.name() == "message" && el.get_child("event", ns::PUBSUB_EVENT).is_some_and(|ev| ev.children().any(|c| c.attr("node") == Some(node)))
}

/// A tiny payload in a test namespace.
pub fn payload(ns_: &str, text: &str) -> Element {
    Element::new("data", ns_).text(text)
}
