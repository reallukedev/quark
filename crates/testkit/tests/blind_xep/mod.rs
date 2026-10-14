//! Helpers shared by the black-box MUC / MAM / carbons tests (written from the XEPs).
#![allow(dead_code)]

use std::time::Duration;

use anyhow::{bail, Context as _};
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{Client, TestServer, DOMAIN};

pub const PW: &str = "password1";
pub const MUC: &str = "rooms.quark.test";
pub const MUC_ROOMCONFIG: &str = "http://jabber.org/protocol/muc#roomconfig";
pub const MUC_ROOMINFO: &str = "http://jabber.org/protocol/muc#roominfo";
pub const MUC_REQUEST: &str = "http://jabber.org/protocol/muc#request";

/// A server with alice, bob, carol and dave.
pub async fn server() -> anyhow::Result<TestServer> {
    let s = TestServer::start().await?;
    for u in ["alice", "bob", "carol", "dave"] {
        s.add_user(u, PW).await?;
    }
    Ok(s)
}

pub fn bare(user: &str) -> String {
    format!("{user}@{DOMAIN}")
}

pub fn room(name: &str) -> String {
    format!("{name}@{MUC}")
}

pub fn occ(room: &str, nick: &str) -> String {
    format!("{room}/{nick}")
}

pub fn id_of(el: &Element) -> Option<String> {
    el.attr("id").map(str::to_string)
}

/// The defined condition of a stanza error (`<error><cond xmlns=stanzas/></error>`) and the type.
pub fn error_of(el: &Element) -> Option<(String, String)> {
    let e = el.get_child("error", ns::CLIENT)?;
    let cond = e.children().find(|c| c.ns() == ns::STANZAS && c.name() != "text")?.name().to_string();
    Some((cond, e.attr("type").unwrap_or("").to_string()))
}

pub fn cond(el: &Element) -> String {
    error_of(el).map(|(c, _)| c).unwrap_or_default()
}

/// `<x xmlns=muc#user>` of a stanza.
pub fn muc_x(el: &Element) -> Option<&Element> {
    el.get_child("x", ns::MUC_USER)
}

/// Status codes in `<x xmlns=muc#user>`.
pub fn codes(el: &Element) -> Vec<String> {
    muc_x(el)
        .map(|x| x.children().filter(|c| c.is("status", ns::MUC_USER)).filter_map(|c| c.attr("code")).map(str::to_string).collect())
        .unwrap_or_default()
}

pub fn has_code(el: &Element, code: &str) -> bool {
    codes(el).iter().any(|c| c == code)
}

/// `<item/>` of `<x xmlns=muc#user>`.
pub fn muc_item(el: &Element) -> Option<&Element> {
    muc_x(el)?.get_child("item", ns::MUC_USER)
}

pub fn is_presence_from(el: &Element, from: &str) -> bool {
    el.name() == "presence" && el.attr("from") == Some(from)
}

pub fn is_unavailable_from(el: &Element, from: &str) -> bool {
    is_presence_from(el, from) && el.attr("type") == Some("unavailable")
}

pub fn is_groupchat_body(el: &Element, body: &str) -> bool {
    el.name() == "message" && el.attr("type") == Some("groupchat") && el.child_text("body", ns::CLIENT).as_deref() == Some(body)
}

pub fn is_subject(el: &Element) -> bool {
    el.name() == "message"
        && el.attr("type") == Some("groupchat")
        && el.has_child("subject", ns::CLIENT)
        && !el.has_child("body", ns::CLIENT)
}

/// Join request (`<presence to=room/nick><x xmlns=muc>…</x></presence>`).
pub fn join_presence(room: &str, nick: &str, password: Option<&str>, maxstanzas: Option<u32>) -> Element {
    let mut x = Element::new("x", ns::MUC);
    if let Some(n) = maxstanzas {
        x.append(Element::new("history", ns::MUC).attr_set("maxstanzas", n.to_string()));
    }
    if let Some(p) = password {
        x.append(Element::new("password", ns::MUC).text(p));
    }
    Element::new("presence", ns::CLIENT).attr_set("to", occ(room, nick)).child(x)
}

/// What a join returned, in arrival order.
#[derive(Debug, Default)]
pub struct Joined {
    /// Every stanza from the room, in order, up to and including the subject (or the error).
    pub all: Vec<Element>,
    /// The self-presence (status 110), when the join worked.
    pub own: Option<Element>,
    /// The presence error, when it didn't.
    pub error: Option<Element>,
}

impl Joined {
    pub fn presences(&self) -> Vec<&Element> {
        self.all.iter().filter(|e| e.name() == "presence").collect()
    }
    pub fn history(&self) -> Vec<&Element> {
        self.all.iter().filter(|e| e.name() == "message" && e.has_child("body", ns::CLIENT)).collect()
    }
    pub fn subject(&self) -> Option<&Element> {
        self.all.iter().find(|e| is_subject(e))
    }
}

fn from_room(e: &Element, room: &str) -> bool {
    e.attr("from").is_some_and(|f| f == room || f.starts_with(&format!("{room}/")))
}

/// Sends a join and reads what the room sends: occupants, self-presence, history and the subject
/// (waits up to a second for a subject; the strict test checks it separately).
pub async fn join_with(c: &mut Client, room: &str, nick: &str, password: Option<&str>, maxstanzas: Option<u32>) -> anyhow::Result<Joined> {
    c.send(&join_presence(room, nick, password, maxstanzas)).await?;
    let mut j = Joined::default();
    let me = occ(room, nick);
    loop {
        let e = c.expect(|e| from_room(e, room)).await?;
        j.all.push(e.clone());
        if e.name() == "presence" && e.attr("type") == Some("error") {
            j.error = Some(e);
            return Ok(j);
        }
        if e.name() == "presence" && has_code(&e, "110") && e.attr("type").is_none() {
            j.own = Some(e);
            break;
        }
        if e.name() == "presence" && e.attr("from") == Some(&me) && e.attr("type").is_none() {
            // A self-presence without 110: keep it, and stop waiting for it.
            j.own = Some(e);
            break;
        }
    }
    // History, then the subject.
    while let Some(e) = recv_from(c, room, Duration::from_millis(1000)).await? {
        let subj = is_subject(&e);
        j.all.push(e);
        if subj {
            break;
        }
    }
    Ok(j)
}

/// Waits up to `wait` for the next stanza from `room` (others are kept for later).
pub async fn recv_from(c: &mut Client, room: &str, wait: Duration) -> anyhow::Result<Option<Element>> {
    let deadline = tokio::time::Instant::now() + wait;
    let mut kept = Vec::new();
    let mut found = None;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break;
        }
        match c.recv_within(left).await? {
            None => break,
            Some(e) if from_room(&e, room) => {
                found = Some(e);
                break;
            }
            Some(e) => kept.push(e),
        }
    }
    // Stanzas not from the room are dropped (the kit has no public push-back).
    requeue(c, kept).await?;
    Ok(found)
}

/// There is no public "push back" on Client; stanzas read and not wanted are dropped, except
/// IQ requests from the server, which we answer so nothing stalls.
async fn requeue(c: &mut Client, kept: Vec<Element>) -> anyhow::Result<()> {
    for e in kept {
        if e.name() == "iq" && matches!(e.attr("type"), Some("get" | "set")) {
            c.answer(&e).await?;
        }
    }
    Ok(())
}

pub async fn join(c: &mut Client, room: &str, nick: &str) -> anyhow::Result<Joined> {
    let j = join_with(c, room, nick, None, None).await?;
    if let Some(e) = &j.error {
        bail!("joining {room} as {nick} failed: {e}");
    }
    Ok(j)
}

/// Creates a room as an instant room (XEP-0045 §10.1.2) and returns the join result.
pub async fn create_instant(c: &mut Client, room: &str, nick: &str) -> anyhow::Result<Joined> {
    let j = join(c, room, nick).await?;
    let own = j.own.as_ref().context("no self-presence")?;
    if !has_code(own, "201") {
        bail!("creating {room}: self-presence without status 201: {own}");
    }
    let form = Element::new("x", ns::DATA_FORMS).attr_set("type", "submit");
    let r = c.iq_set(Some(room), Element::new("query", ns::MUC_OWNER).child(form)).await?;
    if r.attr("type") != Some("result") {
        bail!("instant room submit failed: {r}");
    }
    drain(c, Duration::from_millis(150)).await?;
    Ok(j)
}

/// A data form field with values.
pub fn field(var: &str, values: &[&str]) -> Element {
    let mut f = Element::new("field", ns::DATA_FORMS).attr_set("var", var);
    for v in values {
        f.append(Element::new("value", ns::DATA_FORMS).text(*v));
    }
    f
}

/// A submit form with a FORM_TYPE.
pub fn submit_form(form_type: &str, fields: &[(&str, &[&str])]) -> Element {
    let mut x =
        Element::new("x", ns::DATA_FORMS).attr_set("type", "submit").child(field("FORM_TYPE", &[form_type]).attr_set("type", "hidden"));
    for (var, vals) in fields {
        x.append(field(var, vals));
    }
    x
}

/// Values of a field in a data form.
pub fn form_values(form: &Element, var: &str) -> Option<Vec<String>> {
    let f = form.children().find(|c| c.is("field", ns::DATA_FORMS) && c.attr("var") == Some(var))?;
    Some(f.children().filter(|c| c.is("value", ns::DATA_FORMS)).map(|v| v.text_content()).collect())
}

/// The data form with this FORM_TYPE in `parent`.
pub fn form_of_type<'a>(parent: &'a Element, form_type: &str) -> Option<&'a Element> {
    parent
        .children()
        .filter(|c| c.is("x", ns::DATA_FORMS))
        .find(|x| form_values(x, "FORM_TYPE").is_some_and(|v| v.first().map(String::as_str) == Some(form_type)))
}

/// Creates a reserved room: join, fetch the configuration form, submit these fields.
pub async fn create_configured(c: &mut Client, room: &str, nick: &str, fields: &[(&str, &[&str])]) -> anyhow::Result<Joined> {
    let j = join(c, room, nick).await?;
    let own = j.own.as_ref().context("no self-presence")?;
    if !has_code(own, "201") {
        bail!("creating {room}: self-presence without status 201: {own}");
    }
    configure(c, room, fields).await?;
    Ok(j)
}

/// Fetches the room configuration form (owner) and submits these fields.
pub async fn configure(c: &mut Client, room: &str, fields: &[(&str, &[&str])]) -> anyhow::Result<()> {
    let r = c.iq_get(Some(room), Element::new("query", ns::MUC_OWNER)).await?;
    if r.attr("type") != Some("result") {
        bail!("config form request failed: {r}");
    }
    let q = r.get_child("query", ns::MUC_OWNER).context("no owner query")?;
    let form = q.get_child("x", ns::DATA_FORMS).context("no config form")?;
    for (var, _) in fields {
        if form_values(form, var).is_none() && !form.children().any(|f| f.attr("var") == Some(*var)) {
            bail!("the configuration form has no field {var}: {form}");
        }
    }
    let r = c.iq_set(Some(room), Element::new("query", ns::MUC_OWNER).child(submit_form(MUC_ROOMCONFIG, fields))).await?;
    if r.attr("type") != Some("result") {
        bail!("config submit failed: {r}");
    }
    drain(c, Duration::from_millis(150)).await?;
    Ok(())
}

/// Reads and drops everything for `wait` (answering server IQ requests).
pub async fn drain(c: &mut Client, wait: Duration) -> anyhow::Result<Vec<Element>> {
    let deadline = tokio::time::Instant::now() + wait;
    let mut got = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return Ok(got);
        }
        match c.recv_within(left).await? {
            None => return Ok(got),
            Some(e) => {
                if e.name() == "iq" && matches!(e.attr("type"), Some("get" | "set")) {
                    c.answer(&e).await?;
                }
                got.push(e);
            }
        }
    }
}

/// `muc#admin` request with one item.
pub fn admin_item(attrs: &[(&str, &str)], reason: Option<&str>) -> Element {
    let mut item = Element::new("item", ns::MUC_ADMIN);
    for (k, v) in attrs {
        item.set_attr(k, *v);
    }
    if let Some(r) = reason {
        item.append(Element::new("reason", ns::MUC_ADMIN).text(r));
    }
    Element::new("query", ns::MUC_ADMIN).child(item)
}

pub async fn disco_info(c: &mut Client, to: &str) -> anyhow::Result<Element> {
    c.iq_get(Some(to), Element::new("query", ns::DISCO_INFO)).await
}

pub fn features(info: &Element) -> Vec<String> {
    info.get_child("query", ns::DISCO_INFO)
        .map(|q| q.children().filter(|c| c.is("feature", ns::DISCO_INFO)).filter_map(|f| f.attr("var")).map(str::to_string).collect())
        .unwrap_or_default()
}

pub fn has_feature(info: &Element, var: &str) -> bool {
    features(info).iter().any(|f| f == var)
}

pub fn groupchat(room: &str, body: &str) -> Element {
    quark_testkit::message(room, "groupchat", body)
}

/// `<stanza-id/>` elements (XEP-0359) of a message, as (by, id).
pub fn stanza_ids(el: &Element) -> Vec<(String, String)> {
    el.children()
        .filter(|c| c.is("stanza-id", ns::SID))
        .map(|c| (c.attr("by").unwrap_or("").to_string(), c.attr("id").unwrap_or("").to_string()))
        .collect()
}

pub fn stanza_id_by(el: &Element, by: &str) -> Option<String> {
    stanza_ids(el).into_iter().find(|(b, _)| b == by).map(|(_, i)| i)
}

// ---------------------------------------------------------------------------------------------
// MAM (XEP-0313)

/// One MAM query's outcome.
#[derive(Debug)]
pub struct MamPage {
    /// The `<message>` wrappers that carried results for our queryid, in order.
    pub wrappers: Vec<Element>,
    /// The IQ reply (result or error).
    pub iq: Element,
    /// Whether every result arrived before the IQ reply (always true here: we stop at the IQ;
    /// results after it are caught by `late`).
    pub late: Vec<Element>,
}

impl MamPage {
    pub fn ok(&self) -> bool {
        self.iq.attr("type") == Some("result")
    }
    pub fn results(&self) -> Vec<&Element> {
        self.wrappers.iter().filter_map(|w| w.get_child("result", ns::MAM)).collect()
    }
    /// Archive ids of the results.
    pub fn ids(&self) -> Vec<String> {
        self.results().iter().filter_map(|r| r.attr("id")).map(str::to_string).collect()
    }
    /// The forwarded messages.
    pub fn messages(&self) -> Vec<&Element> {
        self.results()
            .into_iter()
            .filter_map(|r| r.get_child("forwarded", ns::FORWARD))
            .filter_map(|f| f.get_child("message", ns::CLIENT))
            .collect()
    }
    pub fn bodies(&self) -> Vec<String> {
        self.messages().iter().map(|m| m.child_text("body", ns::CLIENT).unwrap_or_default()).collect()
    }
    pub fn fin(&self) -> Option<&Element> {
        self.iq.get_child("fin", ns::MAM)
    }
    pub fn complete(&self) -> bool {
        self.fin().and_then(|f| f.attr("complete")) == Some("true")
    }
    pub fn rsm(&self, name: &str) -> Option<String> {
        self.fin()?.get_child("set", ns::RSM)?.child_text(name, ns::RSM)
    }
    pub fn count(&self) -> Option<usize> {
        self.rsm("count").and_then(|c| c.trim().parse().ok())
    }
}

/// RSM `<set/>`.
pub fn rsm(max: Option<u32>, after: Option<&str>, before: Option<&str>) -> Element {
    let mut s = Element::new("set", ns::RSM);
    if let Some(m) = max {
        s.append(Element::new("max", ns::RSM).text(m.to_string()));
    }
    if let Some(a) = after {
        s.append(Element::new("after", ns::RSM).text(a));
    }
    if let Some(b) = before {
        let mut e = Element::new("before", ns::RSM);
        if !b.is_empty() {
            e = e.text(b);
        }
        s.append(e);
    }
    s
}

/// Runs a MAM query: sends `<iq type=set><query queryid>…</query></iq>` to `to` (None = own
/// account), collects result messages for the queryid until the IQ reply, then 300 ms more to
/// catch results sent after the reply.
pub async fn mam_query(
    c: &mut Client,
    to: Option<&str>,
    fields: &[(&str, &[&str])],
    set: Option<Element>,
    flip: bool,
) -> anyhow::Result<MamPage> {
    let qid = quark_testkit::quark_core::new_id();
    let mut q = Element::new("query", ns::MAM).attr_set("queryid", &qid);
    if !fields.is_empty() {
        q.append(submit_form(ns::MAM, fields));
    }
    if let Some(s) = set {
        q.append(s);
    }
    if flip {
        q.append(Element::new("flip-page", ns::MAM));
    }
    let id = quark_testkit::quark_core::new_id();
    let iq = quark_testkit::quark_core::stanza::iq("set", &id, None, to, q);
    c.send(&iq).await?;
    let mut wrappers = Vec::new();
    let is_ours =
        |e: &Element| e.name() == "message" && e.get_child("result", ns::MAM).is_some_and(|r| r.attr("queryid") == Some(qid.as_str()));
    let reply = loop {
        let e = c.recv().await?;
        if is_ours(&e) {
            wrappers.push(e);
        } else if e.name() == "iq" && e.attr("id") == Some(id.as_str()) {
            break e;
        } else if e.name() == "iq" && matches!(e.attr("type"), Some("get" | "set")) {
            c.answer(&e).await?;
        }
    };
    let mut late = Vec::new();
    while let Some(e) = c.recv_within(Duration::from_millis(100)).await? {
        if is_ours(&e) {
            late.push(e);
        }
    }
    Ok(MamPage { wrappers, iq: reply, late })
}

/// Query everything in the archive (no RSM limit given).
pub async fn mam_all(c: &mut Client, to: Option<&str>) -> anyhow::Result<MamPage> {
    mam_query(c, to, &[], None, false).await
}

/// Sends a chat message and waits until the recipient has it (so the archive is written).
pub async fn chat(from: &mut Client, to: &mut Client, body: &str) -> anyhow::Result<Element> {
    let target = to.jid.clone().context("no jid")?;
    let m = quark_testkit::message(&target, "chat", body);
    from.send(&m).await?;
    to.expect(|e| e.name() == "message" && e.child_text("body", ns::CLIENT).as_deref() == Some(body)).await
}
