//! Blocking Command (XEP-0191) and spam reports (XEP-0377).
//!
//! A blocked JID matches like a privacy list item (XEP-0016 §2.1): `user@domain/resource`,
//! `user@domain` (any resource), `domain/resource` or `domain` (everyone there). Nothing from a
//! blocked JID reaches the account, and nothing the account sends, or the server sends for it
//! (presence, PEP), reaches the blocked JID.

use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::sync::Arc;

use async_trait::async_trait;
use lru::LruCache;
use parking_lot::Mutex;
use quark_core::stanza::IqType;
use quark_core::{ns, Condition, Element, Jid, StanzaError};

use super::{ok, ok_empty, Event, Flow, IqCtx, IqResult, IqTarget, Module, StanzaCtx};
use crate::db::{params, DbError, Migration};
use crate::server::{Host, Server};

pub static MIGRATION: Migration = Migration {
    module: "blocking",
    steps: &["CREATE TABLE blocklist (
        host TEXT NOT NULL,
        user TEXT NOT NULL,
        jid TEXT NOT NULL,
        added INTEGER NOT NULL,
        PRIMARY KEY (host, user, jid),
        FOREIGN KEY (host, user) REFERENCES accounts(host, user) ON DELETE CASCADE
    ) WITHOUT ROWID;
    CREATE TABLE spam_reports (
        id INTEGER PRIMARY KEY,
        host TEXT NOT NULL,
        user TEXT NOT NULL,
        jid TEXT NOT NULL,
        reason TEXT NOT NULL,
        text TEXT,
        -- Space-separated stanza ids the reporter pointed at.
        stanza_ids TEXT NOT NULL,
        stamp INTEGER NOT NULL,
        FOREIGN KEY (host, user) REFERENCES accounts(host, user) ON DELETE CASCADE
    );
    CREATE INDEX spam_reports_by_jid ON spam_reports (host, jid);"],
};

/// Most JIDs one account can block.
const MAX_ITEMS: usize = 10_000;
/// Reports kept per account; the oldest go first.
const MAX_REPORTS: i64 = 500;
const MAX_REPORT_TEXT: usize = 4_096;

pub const REASON_SPAM: &str = "urn:xmpp:reporting:spam";
pub const REASON_ABUSE: &str = "urn:xmpp:reporting:abuse";

pub struct Blocking;

/// Block lists kept in memory, least recently used dropped first. Only lists of accounts that
/// exist are kept; one dropped is read again from the database when next needed.
const CACHED_LISTS: NonZeroUsize = match NonZeroUsize::new(20_000) {
    Some(n) => n,
    None => NonZeroUsize::MIN,
};

struct State {
    /// Blocked JIDs (normalized strings) by account.
    lists: Mutex<LruCache<Jid, Arc<HashSet<String>>>>,
    /// Devices (full JIDs) that fetched the blocklist and so get pushes (XEP-0191 §3.2).
    interested: Mutex<HashSet<Jid>>,
}

impl Default for State {
    fn default() -> Self {
        State { lists: Mutex::new(LruCache::new(CACHED_LISTS)), interested: Mutex::default() }
    }
}

fn db_error(e: DbError) -> StanzaError {
    tracing::warn!(error = %e, "blocklist storage");
    StanzaError::internal().with_text("The block list couldn't be read or saved right now.")
}

/// Whether `j` matches anything in `list` (XEP-0016 §2.1 order: full, bare, domain/resource, domain).
fn matches(list: &HashSet<String>, j: &Jid) -> bool {
    if list.is_empty() {
        return false;
    }
    let full = j.to_string();
    if list.contains(&full) {
        return true;
    }
    if j.node().is_some() && list.contains(&j.bare_str()) {
        return true;
    }
    if let Some(r) = j.resource() {
        if list.contains(&format!("{}/{r}", j.domain())) {
            return true;
        }
    }
    list.contains(j.domain())
}

async fn list(srv: &Server, account: &Jid) -> Result<Arc<HashSet<String>>, DbError> {
    let account = account.to_bare();
    let st = srv.ext::<State>();
    if let Some(l) = st.lists.lock().get(&account) {
        return Ok(l.clone());
    }
    let (h, u) = (account.domain().to_string(), account.node().unwrap_or_default().to_string());
    // No such account (a made-up name someone wrote to): nothing blocked, and nothing cached.
    if !srv.accounts.exists(&h, &u).await? {
        return Ok(Arc::default());
    }
    let items: HashSet<String> = srv
        .db
        .read(move |c| {
            let mut s = c.prepare_cached("SELECT jid FROM blocklist WHERE host = ?1 AND user = ?2")?;
            let rows = s.query_map(params![h, u], |r| r.get(0))?;
            rows.collect()
        })
        .await?;
    // A block saved while this was loading already put the newer list in place.
    let l = st.lists.lock().get_or_insert(account, || Arc::new(items)).clone();
    Ok(l)
}

/// Whether `account` (a local account) has blocked `other`.
pub async fn is_blocked(srv: &Server, account: &Jid, other: &Jid) -> bool {
    match list(srv, account).await {
        Ok(l) => matches(&l, other),
        Err(e) => {
            tracing::warn!(error = %e, "couldn't read a block list");
            false
        }
    }
}

/// The local account a JID belongs to, if any.
fn local_account(srv: &Server, j: &Jid) -> Option<Jid> {
    (j.node().is_some() && srv.host(j.domain()).is_some()).then(|| j.to_bare())
}

/// Whether a stanza from `from` may go to `to`: false when `from` is a local account that
/// blocked `to`. Called by the router for everything it routes, so presence broadcasts and PEP
/// notifications never reach a blocked contact. What a client sends itself is refused earlier,
/// with an error, in [`Blocking::stanza_out`]. Errors still go out: they are how a blocked
/// contact learns its message wasn't taken (`service-unavailable`, XEP-0191 §3.5).
pub async fn outbound_allowed(srv: &Server, from: &Jid, to: &Jid, el: &Element) -> bool {
    if el.attr("type") == Some("error") {
        return true;
    }
    let Some(account) = local_account(srv, from) else { return true };
    if to.to_bare() == account || (to.node().is_none() && srv.host(to.domain()).is_some()) {
        return true;
    }
    !is_blocked(srv, &account, to).await
}

/// Both block lists for a stanza the server hands a session itself instead of routing it (a
/// contact's presence at sign-in): the sender's ([`outbound_allowed`]) and the recipient's, as
/// [`Blocking::stanza_in`] would check it.
pub async fn allowed_between(srv: &Server, from: &Jid, to: &Jid, el: &Element) -> bool {
    if !outbound_allowed(srv, from, to, el).await {
        return false;
    }
    if from.node().is_none() && srv.host(from.domain()).is_some() {
        return true;
    }
    match local_account(srv, to) {
        Some(account) if account != from.to_bare() => !is_blocked(srv, &account, from).await,
        _ => true,
    }
}

fn blocked_error() -> StanzaError {
    StanzaError::new(Condition::NotAcceptable)
        .with_text("You've blocked this contact. Unblock them to send them anything.")
        .with_app(Element::new("blocked", ns::BLOCKING_ERRORS))
}

fn parse_items(payload: &Element) -> Result<Vec<Jid>, StanzaError> {
    let mut out = Vec::new();
    for it in payload.children().filter(|c| c.is("item", ns::BLOCKING)) {
        let j = it.attr("jid").ok_or_else(|| StanzaError::bad_request().with_text("Each item needs a 'jid'."))?;
        let j = Jid::parse(j).map_err(|_| StanzaError::new(Condition::JidMalformed).with_text(format!("'{j}' isn't a valid address.")))?;
        if !out.contains(&j) {
            out.push(j);
        }
    }
    Ok(out)
}

fn items_element(name: &str, jids: &[Jid]) -> Element {
    Element::new(name, ns::BLOCKING).children_from(jids.iter().map(|j| Element::new("item", ns::BLOCKING).attr_set("jid", j.to_string())))
}

/// A spam or abuse report attached to a block item (XEP-0377).
struct Report {
    jid: String,
    reason: &'static str,
    text: Option<String>,
    stanza_ids: Vec<String>,
}

fn parse_report(item: &Element, jid: &Jid) -> Result<Option<Report>, StanzaError> {
    let Some(r) = item.get_child("report", ns::SPAM_REPORTING) else { return Ok(None) };
    let reason = match r.attr("reason") {
        Some(REASON_SPAM) => REASON_SPAM,
        Some(REASON_ABUSE) => REASON_ABUSE,
        _ => return Err(StanzaError::bad_request().with_text("A report's reason must be spam or abuse.")),
    };
    let mut text = r.child_text("text", ns::SPAM_REPORTING).filter(|t| !t.trim().is_empty());
    if let Some(t) = text.as_mut() {
        if t.len() > MAX_REPORT_TEXT {
            let mut cut = MAX_REPORT_TEXT;
            while !t.is_char_boundary(cut) {
                cut -= 1;
            }
            t.truncate(cut);
        }
    }
    let stanza_ids =
        r.children().filter(|c| c.is("stanza-id", ns::SID)).filter_map(|c| c.attr("id")).take(50).map(str::to_string).collect();
    Ok(Some(Report { jid: jid.to_string(), reason, text, stanza_ids }))
}

/// Sends a block or unblock push to the account's devices that asked for the list.
fn push(srv: &Server, account: &Jid, payload: Element) {
    let interested = srv.ext::<State>().interested.lock().clone();
    for s in srv.sessions.of(account) {
        if interested.contains(&s.jid) {
            let iq =
                quark_core::stanza::iq("set", &quark_core::new_id(), Some(&account.to_string()), Some(&s.jid.to_string()), payload.clone());
            s.send(iq);
        }
    }
}

/// Contacts who may currently see the account's presence: roster subscribers and anyone a
/// device sent directed presence to.
async fn presence_audience(srv: &Server, account: &Jid) -> Vec<Jid> {
    let (h, u) = (account.domain(), account.node().unwrap_or_default());
    let mut out: HashSet<Jid> = super::roster::items(srv, h, u)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|i| i.subscription.sends_to_contact())
        .map(|i| i.contact)
        .collect();
    for s in srv.sessions.of(account) {
        out.extend(s.presence.lock().directed.iter().cloned());
    }
    out.into_iter().collect()
}

async fn block(cx: &IqCtx<'_>, account: &Jid) -> IqResult {
    let jids = parse_items(cx.payload)?;
    if jids.is_empty() {
        return Err(StanzaError::bad_request().with_text("Say who to block."));
    }
    let mut reports = Vec::new();
    for it in cx.payload.children().filter(|c| c.is("item", ns::BLOCKING)) {
        if let Some(j) = it.attr("jid").and_then(|j| Jid::parse(j).ok()) {
            if let Some(r) = parse_report(it, &j)? {
                reports.push(r);
            }
        }
    }
    let srv = cx.srv;
    let old = list(srv, account).await.map_err(db_error)?;
    let fresh: Vec<Jid> = jids.iter().filter(|j| !old.contains(&j.to_string())).cloned().collect();
    if old.len() + fresh.len() > MAX_ITEMS {
        return Err(StanzaError::new(Condition::ResourceConstraint).with_text("The block list is full."));
    }

    let (h, u) = (account.domain().to_string(), account.node().unwrap_or_default().to_string());
    let add: Vec<String> = fresh.iter().map(Jid::to_string).collect();
    let now = quark_core::time::now_ms();
    let reported = reports.len();
    let updated: HashSet<String> = srv
        .db
        .write(move |t| {
            for j in &add {
                t.execute(
                    "INSERT INTO blocklist (host, user, jid, added) VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING",
                    params![h, u, j, now],
                )?;
            }
            for r in &reports {
                t.execute(
                    "INSERT INTO spam_reports (host, user, jid, reason, text, stanza_ids, stamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![h, u, r.jid, r.reason, r.text, r.stanza_ids.join(" "), now],
                )?;
            }
            if !reports.is_empty() {
                t.execute(
                    "DELETE FROM spam_reports WHERE host = ?1 AND user = ?2 AND id NOT IN \
                     (SELECT id FROM spam_reports WHERE host = ?1 AND user = ?2 ORDER BY id DESC LIMIT ?3)",
                    params![h, u, MAX_REPORTS],
                )?;
            }
            let mut s = t.prepare_cached("SELECT jid FROM blocklist WHERE host = ?1 AND user = ?2")?;
            let rows = s.query_map(params![h, u], |r| r.get(0))?;
            rows.collect()
        })
        .await
        .map_err(db_error)?;
    if reported > 0 {
        tracing::info!(account = %account, reports = reported, "spam report received");
    }

    // XEP-0191 §3.3: contacts who saw the account online now see it go offline. Sent while the
    // old list is still in force, so the filter lets these through.
    let newly: HashSet<String> = fresh.iter().map(Jid::to_string).collect();
    let audience: Vec<Jid> = presence_audience(srv, account).await.into_iter().filter(|c| matches(&newly, c)).collect();
    for c in &audience {
        for s in srv.sessions.available_of(account) {
            let p = Element::new("presence", ns::CLIENT)
                .attr_set("from", s.jid.to_string())
                .attr_set("to", c.to_string())
                .attr_set("type", "unavailable");
            srv.route(p).await;
        }
    }
    srv.ext::<State>().lists.lock().put(account.clone(), Arc::new(updated));
    push(srv, account, items_element("block", &jids));
    ok_empty()
}

async fn unblock(cx: &IqCtx<'_>, account: &Jid) -> IqResult {
    let jids = parse_items(cx.payload)?;
    let srv = cx.srv;
    let old = list(srv, account).await.map_err(db_error)?;
    let (h, u) = (account.domain().to_string(), account.node().unwrap_or_default().to_string());
    let all = jids.is_empty();
    let remove: Vec<String> = jids.iter().map(Jid::to_string).collect();
    let updated: HashSet<String> = srv
        .db
        .write(move |t| {
            if all {
                t.execute("DELETE FROM blocklist WHERE host = ?1 AND user = ?2", params![h, u])?;
            } else {
                for j in &remove {
                    t.execute("DELETE FROM blocklist WHERE host = ?1 AND user = ?2 AND jid = ?3", params![h, u, j])?;
                }
            }
            let mut s = t.prepare_cached("SELECT jid FROM blocklist WHERE host = ?1 AND user = ?2")?;
            let rows = s.query_map(params![h, u], |r| r.get(0))?;
            rows.collect()
        })
        .await
        .map_err(db_error)?;
    srv.ext::<State>().lists.lock().put(account.clone(), Arc::new(updated.clone()));

    // Contacts who may see the account's presence again get its current presence (§3.4).
    let gone: HashSet<String> = old.difference(&updated).cloned().collect();
    if !gone.is_empty() {
        let audience = presence_audience(srv, account).await;
        for c in audience.iter().filter(|c| matches(&gone, c) && !matches(&updated, c)) {
            for s in srv.sessions.available_of(account) {
                if let Some(mut p) = s.last_presence() {
                    p.set_attr("from", s.jid.to_string());
                    p.set_attr("to", c.to_string());
                    srv.route(p).await;
                }
            }
        }
    }
    push(srv, account, items_element("unblock", &jids));
    ok_empty()
}

#[async_trait]
impl Module for Blocking {
    fn name(&self) -> &'static str {
        "blocklist"
    }

    fn migrations(&self) -> Vec<&'static Migration> {
        vec![&MIGRATION]
    }

    fn snapshot_names(&self, _host: &Host) -> Vec<&'static str> {
        vec!["blocklist"]
    }

    fn server_features(&self, _host: &Host) -> Vec<&'static str> {
        vec![ns::BLOCKING, ns::SPAM_REPORTING]
    }

    fn account_features(&self, _host: &Host) -> Vec<&'static str> {
        vec![ns::BLOCKING]
    }

    fn iq_namespaces(&self) -> &'static [(&'static str, IqTarget)] {
        &[(ns::BLOCKING, IqTarget::Server), (ns::BLOCKING, IqTarget::Account)]
    }

    async fn handle_iq(&self, cx: &IqCtx<'_>) -> IqResult {
        // Only the account itself reads or changes its block list.
        let Some(account) = cx.local_sender() else {
            return Err(StanzaError::service_unavailable());
        };
        if cx.to.node().is_some() && !cx.from_self() {
            return Err(StanzaError::forbidden().with_text("Only the account itself can see or change its block list."));
        }
        match (cx.payload.name(), cx.kind) {
            ("blocklist", IqType::Get) => {
                let (h, u) = (account.domain().to_string(), account.node().unwrap_or_default().to_string());
                let jids: Vec<String> = cx
                    .srv
                    .db
                    .read(move |c| {
                        let mut s = c.prepare_cached("SELECT jid FROM blocklist WHERE host = ?1 AND user = ?2 ORDER BY added, jid")?;
                        let rows = s.query_map(params![h, u], |r| r.get(0))?;
                        rows.collect()
                    })
                    .await
                    .map_err(db_error)?;
                if cx.from.is_full() {
                    cx.srv.ext::<State>().interested.lock().insert(cx.from.clone());
                }
                ok(Element::new("blocklist", ns::BLOCKING)
                    .children_from(jids.into_iter().map(|j| Element::new("item", ns::BLOCKING).attr_set("jid", j))))
            }
            ("block", IqType::Set) => block(cx, &account).await,
            ("unblock", IqType::Set) => unblock(cx, &account).await,
            _ => Err(StanzaError::bad_request()),
        }
    }

    async fn stanza_out(&self, cx: &StanzaCtx<'_>, stanza: &mut Element) -> Flow {
        if matches!(stanza.attr("type"), Some("error" | "result")) {
            return Flow::Continue;
        }
        let me = cx.from.to_bare();
        if cx.to.to_bare() == me || cx.to.node().is_none() && cx.srv.host(cx.to.domain()).is_some() {
            return Flow::Continue;
        }
        if is_blocked(cx.srv, &me, cx.to).await {
            return Flow::Reject(blocked_error());
        }
        Flow::Continue
    }

    async fn stanza_in(&self, cx: &StanzaCtx<'_>, stanza: &mut Element) -> Flow {
        // The account's own server is never blocked (it would cut the account off).
        if cx.from.node().is_none() && cx.srv.host(cx.from.domain()).is_some() {
            return Flow::Continue;
        }
        if !is_blocked(cx.srv, &cx.to.to_bare(), cx.from).await {
            return Flow::Continue;
        }
        let kind = stanza.attr("type").unwrap_or("");
        // XEP-0191 §3.5: presence is dropped silently; messages and IQ requests get
        // service-unavailable, so the blocked contact learns nothing more than from an offline one.
        match stanza.name() {
            "message" if !matches!(kind, "error" | "groupchat" | "headline") => Flow::Reject(StanzaError::service_unavailable()),
            "iq" if matches!(kind, "get" | "set") => Flow::Reject(StanzaError::service_unavailable()),
            _ => Flow::Stop,
        }
    }

    async fn on_event(&self, srv: &Arc<Server>, ev: &Event) {
        match ev {
            Event::SessionStarted { jid } => {
                // A new session on the same resource hasn't asked for the list yet.
                srv.ext::<State>().interested.lock().remove(jid);
            }
            Event::SessionEnded { jid } => {
                let st = srv.ext::<State>();
                st.interested.lock().remove(jid);
                let bare = jid.to_bare();
                if !srv.sessions.is_online(&bare) {
                    st.lists.lock().pop(&bare);
                }
            }
            Event::AccountDeleted { jid } => {
                srv.ext::<State>().lists.lock().pop(&jid.to_bare());
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> HashSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn j(s: &str) -> Jid {
        Jid::parse(s).unwrap()
    }

    #[test]
    fn matching_follows_privacy_list_rules() {
        let l = set(&["eve@evil.example", "spam.example", "x.example/bot", "carol@ok.example/phone"]);
        assert!(matches(&l, &j("eve@evil.example")));
        assert!(matches(&l, &j("eve@evil.example/laptop")));
        assert!(matches(&l, &j("anyone@spam.example/r")));
        assert!(matches(&l, &j("spam.example")));
        assert!(matches(&l, &j("x.example/bot")));
        // `domain/resource` matches that resource of any account there (XEP-0016 §2.1).
        assert!(matches(&l, &j("someone@x.example/bot")));
        assert!(!matches(&l, &j("someone@x.example/phone")));
        assert!(matches(&l, &j("carol@ok.example/phone")));
        assert!(!matches(&l, &j("carol@ok.example/laptop")));
        assert!(!matches(&l, &j("carol@ok.example")));
        assert!(!matches(&l, &j("bob@good.example")));
        assert!(!matches(&HashSet::new(), &j("eve@evil.example")));
    }

    #[tokio::test]
    async fn made_up_accounts_leave_no_cached_lists() {
        let dir = tempfile::tempdir().unwrap();
        let srv = crate::run::test_server(dir.path(), "");
        srv.accounts.create("a.test", "sam", "correct horse", crate::accounts::Role::Member).await.unwrap();
        for i in 0..200 {
            let ghost = j(&format!("ghost{i}@a.test"));
            // Through the router (stanza_in) and asked directly.
            let m = Element::new("message", ns::CLIENT).attr_set("from", "eve@evil.example/x").attr_set("to", ghost.to_string());
            srv.route(m).await;
            assert!(!is_blocked(&srv, &ghost, &j("eve@evil.example")).await);
        }
        assert_eq!(srv.ext::<State>().lists.lock().len(), 0, "nothing kept for accounts that don't exist");
        assert!(!is_blocked(&srv, &j("sam@a.test"), &j("eve@evil.example")).await);
        assert_eq!(srv.ext::<State>().lists.lock().len(), 1);
        assert_eq!(srv.ext::<State>().lists.lock().cap(), CACHED_LISTS);
    }

    #[test]
    fn items_are_normalized_and_deduplicated() {
        let p = Element::parse(
            "<block xmlns='urn:xmpp:blocking'><item jid='Eve@Evil.Example'/><item jid='eve@evil.example'/><item jid='spam.example'/></block>",
        )
        .unwrap();
        let got: Vec<String> = parse_items(&p).unwrap().iter().map(Jid::to_string).collect();
        assert_eq!(got, ["eve@evil.example", "spam.example"]);
        let bad = Element::parse("<block xmlns='urn:xmpp:blocking'><item jid='a@@b'/></block>").unwrap();
        assert_eq!(parse_items(&bad).unwrap_err().condition, Condition::JidMalformed);
        let none = Element::parse("<block xmlns='urn:xmpp:blocking'><item/></block>").unwrap();
        assert_eq!(parse_items(&none).unwrap_err().condition, Condition::BadRequest);
    }

    #[test]
    fn reports_need_a_known_reason() {
        let it = Element::parse(
            "<item xmlns='urn:xmpp:blocking' jid='eve@evil.example'><report xmlns='urn:xmpp:reporting:1' reason='urn:xmpp:reporting:spam'>\
             <stanza-id xmlns='urn:xmpp:sid:0' by='eve@evil.example' id='abc'/><text>buy now</text></report></item>",
        )
        .unwrap();
        let r = parse_report(&it, &j("eve@evil.example")).unwrap().unwrap();
        assert_eq!(r.reason, REASON_SPAM);
        assert_eq!(r.text.as_deref(), Some("buy now"));
        assert_eq!(r.stanza_ids, ["abc"]);
        let bad =
            Element::parse("<item xmlns='urn:xmpp:blocking' jid='e@x.example'><report xmlns='urn:xmpp:reporting:1' reason='meh'/></item>")
                .unwrap();
        assert!(parse_report(&bad, &j("e@x.example")).is_err());
        let plain = Element::parse("<item xmlns='urn:xmpp:blocking' jid='e@x.example'/>").unwrap();
        assert!(parse_report(&plain, &j("e@x.example")).unwrap().is_none());
    }
}
