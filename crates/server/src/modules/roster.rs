//! Rosters (RFC 6121 §2): storage, versioning (§2.6), pre-approvals (§3.4) and roster pushes.
//! The subscription state machine that changes them lives in `presence`.

use std::sync::Arc;

use async_trait::async_trait;
use quark_core::stanza::IqType;
use quark_core::{ns, Element, Jid, StanzaError};

use super::{ok, ok_empty, IqCtx, IqResult, IqTarget, Module};
use crate::db::{params, DbError, Migration, OptionalExtension};
use crate::server::{Host, Server};

pub static MIGRATION: Migration = Migration {
    module: "roster",
    steps: &["CREATE TABLE roster (
        host TEXT NOT NULL,
        user TEXT NOT NULL,
        contact TEXT NOT NULL,
        name TEXT,
        subscription TEXT NOT NULL DEFAULT 'none',
        ask INTEGER NOT NULL DEFAULT 0,
        approved INTEGER NOT NULL DEFAULT 0,
        groups TEXT NOT NULL DEFAULT '[]',
        -- In the roster the person sees; false for rows that only hold a pending request.
        visible INTEGER NOT NULL DEFAULT 1,
        -- A subscription request waiting for an answer, kept to show again at sign-in.
        pending_in TEXT,
        PRIMARY KEY (host, user, contact),
        FOREIGN KEY (host, user) REFERENCES accounts(host, user) ON DELETE CASCADE
    ) WITHOUT ROWID;
    CREATE TABLE roster_versions (
        host TEXT NOT NULL,
        user TEXT NOT NULL,
        version INTEGER NOT NULL,
        PRIMARY KEY (host, user),
        FOREIGN KEY (host, user) REFERENCES accounts(host, user) ON DELETE CASCADE
    ) WITHOUT ROWID;"],
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subscription {
    None,
    /// The account sees the contact's presence.
    To,
    /// The contact sees the account's presence.
    From,
    Both,
}

impl Subscription {
    pub fn as_str(self) -> &'static str {
        match self {
            Subscription::None => "none",
            Subscription::To => "to",
            Subscription::From => "from",
            Subscription::Both => "both",
        }
    }
    fn parse(s: &str) -> Self {
        match s {
            "to" => Subscription::To,
            "from" => Subscription::From,
            "both" => Subscription::Both,
            _ => Subscription::None,
        }
    }
    /// The contact gets the account's presence.
    pub fn sends_to_contact(self) -> bool {
        matches!(self, Subscription::From | Subscription::Both)
    }
    /// The account gets the contact's presence.
    pub fn receives_from_contact(self) -> bool {
        matches!(self, Subscription::To | Subscription::Both)
    }
    pub fn with_to(self, on: bool) -> Self {
        match (self, on) {
            (Subscription::None, true) => Subscription::To,
            (Subscription::From, true) => Subscription::Both,
            (Subscription::To, false) => Subscription::None,
            (Subscription::Both, false) => Subscription::From,
            (s, _) => s,
        }
    }
    pub fn with_from(self, on: bool) -> Self {
        match (self, on) {
            (Subscription::None, true) => Subscription::From,
            (Subscription::To, true) => Subscription::Both,
            (Subscription::From, false) => Subscription::None,
            (Subscription::Both, false) => Subscription::To,
            (s, _) => s,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Item {
    pub contact: Jid,
    pub name: Option<String>,
    pub subscription: Subscription,
    /// We asked to see the contact's presence and wait for the answer.
    pub ask: bool,
    /// Pre-approved: a request from the contact will be accepted right away.
    pub approved: bool,
    pub groups: Vec<String>,
    pub visible: bool,
    pub pending_in: Option<String>,
}

impl Item {
    pub fn new(contact: Jid) -> Self {
        Item {
            contact,
            name: None,
            subscription: Subscription::None,
            ask: false,
            approved: false,
            groups: Vec::new(),
            visible: true,
            pending_in: None,
        }
    }

    pub fn to_element(&self) -> Element {
        let mut e =
            Element::new("item", ns::ROSTER).attr_set("jid", self.contact.to_string()).attr_set("subscription", self.subscription.as_str());
        if let Some(n) = &self.name {
            e.set_attr("name", n.clone());
        }
        if self.ask {
            e.set_attr("ask", "subscribe");
        }
        if self.approved {
            e.set_attr("approved", "true");
        }
        for g in &self.groups {
            e.append(Element::new("group", ns::ROSTER).text(g.clone()));
        }
        e
    }
}

fn row_item(r: &rusqlite::Row<'_>) -> rusqlite::Result<Option<Item>> {
    let contact: String = r.get(0)?;
    let Ok(contact) = Jid::parse(&contact) else { return Ok(None) };
    let groups: String = r.get(5)?;
    Ok(Some(Item {
        contact,
        name: r.get(1)?,
        subscription: Subscription::parse(&r.get::<_, String>(2)?),
        ask: r.get(3)?,
        approved: r.get(4)?,
        groups: serde_json::from_str(&groups).unwrap_or_default(),
        visible: r.get(6)?,
        pending_in: r.get(7)?,
    }))
}

const COLS: &str = "contact, name, subscription, ask, approved, groups, visible, pending_in";

/// Every roster row of an account (visible or not).
pub async fn items(srv: &Server, host: &str, user: &str) -> Result<Vec<Item>, DbError> {
    let (h, u) = (host.to_string(), user.to_string());
    srv.db
        .read(move |c| {
            let mut st = c.prepare_cached(&format!("SELECT {COLS} FROM roster WHERE host = ?1 AND user = ?2"))?;
            let rows = st.query_map(params![h, u], row_item)?;
            Ok(rows.filter_map(|r| r.ok().flatten()).collect())
        })
        .await
}

/// The rows presence needs: contacts who see the account (`from`/`both`), and with `initial`
/// also the ones it follows (`to`) and pending requests. Filtered in SQL, as presence is sent
/// often and most of a big roster may be neither.
pub async fn presence_items(srv: &Server, host: &str, user: &str, initial: bool) -> Result<Vec<Item>, DbError> {
    let (h, u) = (host.to_string(), user.to_string());
    let filter = if initial { "(subscription <> 'none' OR pending_in IS NOT NULL)" } else { "subscription IN ('from', 'both')" };
    srv.db
        .read(move |c| {
            let mut st = c.prepare_cached(&format!("SELECT {COLS} FROM roster WHERE host = ?1 AND user = ?2 AND {filter}"))?;
            let rows = st.query_map(params![h, u], row_item)?;
            Ok(rows.filter_map(|r| r.ok().flatten()).collect())
        })
        .await
}

/// How many contacts the account sees in its roster.
pub async fn count_visible(srv: &Server, host: &str, user: &str) -> Result<usize, DbError> {
    count(srv, host, user, "visible = 1").await
}

/// How many subscription requests wait for an answer.
pub async fn count_pending(srv: &Server, host: &str, user: &str) -> Result<usize, DbError> {
    count(srv, host, user, "pending_in IS NOT NULL").await
}

async fn count(srv: &Server, host: &str, user: &str, filter: &'static str) -> Result<usize, DbError> {
    let (h, u) = (host.to_string(), user.to_string());
    srv.db
        .read(move |c| {
            c.query_row(&format!("SELECT COUNT(*) FROM roster WHERE host = ?1 AND user = ?2 AND {filter}"), params![h, u], |r| {
                r.get::<_, i64>(0)
            })
        })
        .await
        .map(|n| usize::try_from(n).unwrap_or(usize::MAX))
}

pub async fn item(srv: &Server, host: &str, user: &str, contact: &Jid) -> Result<Option<Item>, DbError> {
    let (h, u, c) = (host.to_string(), user.to_string(), contact.to_bare().to_string());
    srv.db
        .read(move |db| {
            db.query_row(&format!("SELECT {COLS} FROM roster WHERE host = ?1 AND user = ?2 AND contact = ?3"), params![h, u, c], row_item)
                .optional()
                .map(Option::flatten)
        })
        .await
}

/// Saves an item and bumps the roster version. Returns the new version.
pub async fn save(srv: &Server, host: &str, user: &str, it: &Item) -> Result<i64, DbError> {
    let (h, u) = (host.to_string(), user.to_string());
    let it = it.clone();
    srv.db
        .write(move |t| {
            t.execute(
                "INSERT INTO roster (host, user, contact, name, subscription, ask, approved, groups, visible, pending_in) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(host, user, contact) DO UPDATE SET name = excluded.name, subscription = excluded.subscription, ask = excluded.ask,
                    approved = excluded.approved, groups = excluded.groups, visible = excluded.visible, pending_in = excluded.pending_in",
                params![
                    h,
                    u,
                    it.contact.to_bare().to_string(),
                    it.name,
                    it.subscription.as_str(),
                    it.ask,
                    it.approved,
                    serde_json::to_string(&it.groups).unwrap_or_else(|_| "[]".into()),
                    it.visible,
                    it.pending_in
                ],
            )?;
            bump(t, &h, &u)
        })
        .await
}

/// Deletes an item and bumps the version.
pub async fn delete(srv: &Server, host: &str, user: &str, contact: &Jid) -> Result<i64, DbError> {
    let (h, u, c) = (host.to_string(), user.to_string(), contact.to_bare().to_string());
    srv.db
        .write(move |t| {
            t.execute("DELETE FROM roster WHERE host = ?1 AND user = ?2 AND contact = ?3", params![h, u, c])?;
            bump(t, &h, &u)
        })
        .await
}

fn bump(t: &rusqlite::Transaction<'_>, h: &str, u: &str) -> rusqlite::Result<i64> {
    t.query_row(
        "INSERT INTO roster_versions (host, user, version) VALUES (?1, ?2, 1) ON CONFLICT(host, user) DO UPDATE SET version = version + 1 RETURNING version",
        params![h, u],
        |r| r.get(0),
    )
}

pub async fn version(srv: &Server, host: &str, user: &str) -> Result<i64, DbError> {
    let (h, u) = (host.to_string(), user.to_string());
    srv.db
        .read(move |c| {
            c.query_row("SELECT version FROM roster_versions WHERE host = ?1 AND user = ?2", params![h, u], |r| r.get(0))
                .optional()
                .map(|v| v.unwrap_or(0))
        })
        .await
}

/// Tells the account's interested sessions about a changed item (RFC 6121 §2.1.6).
pub fn push(srv: &Server, account: &Jid, it: &Item, version: i64, removed: bool) {
    let mut el = it.to_element();
    if removed {
        el = Element::new("item", ns::ROSTER).attr_set("jid", it.contact.to_string()).attr_set("subscription", "remove");
    }
    for s in srv.sessions.of(&account.to_bare()) {
        if !s.presence.lock().interested {
            continue;
        }
        let iq = quark_core::stanza::iq(
            "set",
            &quark_core::new_id(),
            Some(&account.to_bare().to_string()),
            Some(&s.jid.to_string()),
            Element::new("query", ns::ROSTER).attr_set("ver", version.to_string()).child(el.clone()),
        );
        s.send(iq);
    }
}

/// Saves and pushes in one go, the common case after a subscription change.
pub async fn save_and_push(srv: &Server, host: &Host, user: &str, it: &Item) -> Result<(), DbError> {
    let v = save(srv, &host.domain, user, it).await?;
    if it.visible {
        push(srv, &Jid::bare_unchecked(user, &host.domain), it, v, false);
    }
    Ok(())
}

pub struct Roster;

const MAX_ITEMS: usize = 2_000;
const MAX_NAME: usize = 256;
const MAX_GROUPS: usize = 32;

#[async_trait]
impl Module for Roster {
    fn name(&self) -> &'static str {
        "roster"
    }

    fn migrations(&self) -> Vec<&'static Migration> {
        vec![&MIGRATION]
    }

    fn snapshot_names(&self, _host: &Host) -> Vec<&'static str> {
        vec!["roster"]
    }

    fn stream_features(&self, _host: &Host) -> Vec<Element> {
        vec![Element::new("ver", ns::ROSTER_VER), Element::new("sub", ns::PRE_APPROVAL)]
    }

    fn iq_namespaces(&self) -> &'static [(&'static str, IqTarget)] {
        &[(ns::ROSTER, IqTarget::Account)]
    }

    async fn handle_iq(&self, cx: &IqCtx<'_>) -> IqResult {
        // Only the account itself reads or changes its roster.
        if !cx.from_self() {
            return Err(StanzaError::forbidden());
        }
        let user = cx.to.node().unwrap_or_default();
        let db = |e: DbError| {
            tracing::warn!(error = %e, "roster storage");
            StanzaError::internal()
        };
        match cx.kind {
            IqType::Get => {
                if let Some(s) = cx.session {
                    s.presence.lock().interested = true;
                }
                let ver = version(cx.srv, &cx.host.domain, user).await.map_err(db)?;
                if cx.payload.attr("ver") == Some(ver.to_string().as_str()) {
                    // Unchanged: the client's cached copy is current; pushes follow from here.
                    return ok_empty();
                }
                let all = items(cx.srv, &cx.host.domain, user).await.map_err(db)?;
                let q = Element::new("query", ns::ROSTER)
                    .attr_set("ver", ver.to_string())
                    .children_from(all.iter().filter(|i| i.visible).map(Item::to_element));
                ok(q)
            }
            IqType::Set => {
                let mut list = cx.payload.children().filter(|c| c.is("item", ns::ROSTER));
                let (Some(el), None) = (list.next(), list.next()) else {
                    return Err(StanzaError::bad_request().with_text("A roster set has exactly one item."));
                };
                let contact = el
                    .attr("jid")
                    .and_then(|j| Jid::parse(j).ok())
                    .ok_or_else(|| StanzaError::new(quark_core::Condition::JidMalformed))?
                    .to_bare();
                if el.attr("subscription") == Some("remove") {
                    // RFC 6121 §2.5.3: removing something that isn't there is an error.
                    if item(cx.srv, &cx.host.domain, user, &contact).await.map_err(db)?.is_none_or(|i| !i.visible) {
                        return Err(StanzaError::item_not_found());
                    }
                    remove(cx.srv, cx.host, user, &contact).await.map_err(db)?;
                    return ok_empty();
                }
                let name = el.attr("name").map(str::to_string).filter(|n| !n.is_empty());
                if name.as_ref().is_some_and(|n| n.len() > MAX_NAME) {
                    return Err(StanzaError::new(quark_core::Condition::NotAcceptable).with_text("That name is too long."));
                }
                let mut groups: Vec<String> = Vec::new();
                for g in el.children().filter(|c| c.is("group", ns::ROSTER)) {
                    let g = g.text_content();
                    if g.is_empty() || g.len() > MAX_NAME {
                        return Err(
                            StanzaError::new(quark_core::Condition::NotAcceptable).with_text("Group names can't be empty or too long.")
                        );
                    }
                    if groups.contains(&g) {
                        return Err(StanzaError::bad_request().with_text("A group is listed twice."));
                    }
                    groups.push(g);
                }
                if groups.len() > MAX_GROUPS {
                    return Err(StanzaError::new(quark_core::Condition::NotAcceptable).with_text("Too many groups."));
                }
                let mut it = match item(cx.srv, &cx.host.domain, user, &contact).await.map_err(db)? {
                    Some(it) => it,
                    None => {
                        if count_visible(cx.srv, &cx.host.domain, user).await.map_err(db)? >= MAX_ITEMS {
                            return Err(StanzaError::new(quark_core::Condition::NotAllowed).with_text("The roster is full."));
                        }
                        Item::new(contact)
                    }
                };
                // Clients set names and groups; subscription state only changes through presence.
                it.name = name;
                it.groups = groups;
                it.visible = true;
                save_and_push(cx.srv, cx.host, user, &it).await.map_err(db)?;
                ok_empty()
            }
            _ => Err(StanzaError::bad_request()),
        }
    }

    async fn on_event(&self, _srv: &Arc<Server>, _ev: &super::Event) {}
}

/// Removes a contact (RFC 6121 §2.5): cancels subscriptions both ways first.
pub async fn remove(srv: &Arc<Server>, host: &Arc<Host>, user: &str, contact: &Jid) -> Result<(), DbError> {
    let Some(it) = item(srv, &host.domain, user, contact).await? else {
        return Ok(());
    };
    let me = Jid::bare_unchecked(user, &host.domain);
    let pres = |kind: &str| {
        Element::new("presence", ns::CLIENT).attr_set("from", me.to_string()).attr_set("to", contact.to_string()).attr_set("type", kind)
    };
    if it.subscription.receives_from_contact() || it.ask {
        srv.route(pres("unsubscribe")).await;
    }
    if it.subscription.sends_to_contact() || it.pending_in.is_some() {
        srv.route(pres("unsubscribed")).await;
        super::presence::send_unavailable_to(srv, &me, contact).await;
    }
    let v = delete(srv, &host.domain, user, contact).await?;
    push(srv, &me, &it, v, true);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_transitions() {
        assert_eq!(Subscription::None.with_to(true), Subscription::To);
        assert_eq!(Subscription::From.with_to(true), Subscription::Both);
        assert_eq!(Subscription::Both.with_from(false), Subscription::To);
        assert_eq!(Subscription::To.with_from(true), Subscription::Both);
        assert_eq!(Subscription::None.with_from(false), Subscription::None);
    }

    #[test]
    fn item_xml() {
        let mut it = Item::new(Jid::parse("a@b").unwrap());
        it.ask = true;
        it.groups = vec!["Friends".into()];
        let e = it.to_element();
        assert_eq!(e.attr("ask"), Some("subscribe"));
        assert_eq!(e.child_text("group", ns::ROSTER).as_deref(), Some("Friends"));
    }
}
