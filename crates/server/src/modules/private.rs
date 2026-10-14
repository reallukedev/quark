//! Private XML Storage (XEP-0049): small per-account data clients keep on the server.

use async_trait::async_trait;
use quark_core::stanza::IqType;
use quark_core::{ns, Element, StanzaError};

use super::{ok, ok_empty, IqCtx, IqResult, IqTarget, Module};
use crate::db::{params, Migration, OptionalExtension};
use crate::server::Host;

pub static MIGRATION: Migration = Migration {
    module: "private",
    steps: &["CREATE TABLE private_xml (
        host TEXT NOT NULL,
        user TEXT NOT NULL,
        ns TEXT NOT NULL,
        name TEXT NOT NULL,
        xml TEXT NOT NULL,
        PRIMARY KEY (host, user, ns, name),
        FOREIGN KEY (host, user) REFERENCES accounts(host, user) ON DELETE CASCADE
    ) WITHOUT ROWID"],
};

const MAX_BYTES: usize = 64 * 1024;
/// Distinct elements one account may keep, and their total size: clients store a handful
/// (bookmarks, a few app settings); without a cap an account could fill the disk.
const MAX_ITEMS: i64 = 256;
const MAX_TOTAL_BYTES: i64 = 1024 * 1024;

/// What an account stored under `ns` and element `name`, inside a database closure.
pub fn load(c: &rusqlite::Connection, host: &str, user: &str, ns: &str, name: &str) -> rusqlite::Result<Option<Element>> {
    let xml: Option<String> = c
        .prepare_cached("SELECT xml FROM private_xml WHERE host = ?1 AND user = ?2 AND ns = ?3 AND name = ?4")?
        .query_row(params![host, user, ns, name], |r| r.get(0))
        .optional()?;
    Ok(xml.and_then(|x| Element::parse(&x).ok()))
}

/// What [`store`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stored {
    Yes,
    /// The element alone is over the size limit.
    TooBig,
    /// The account's storage is full (items or total size).
    Full,
}

/// Stores `data` (whitespace stripped) under its namespace and name, inside a database
/// closure. The account's quota is counted in the same transaction, so parallel sets can't
/// overshoot it.
pub fn store(c: &rusqlite::Connection, host: &str, user: &str, data: &Element) -> rusqlite::Result<Stored> {
    let mut v = data.clone();
    v.strip_whitespace();
    let xml = v.to_xml();
    if xml.len() > MAX_BYTES {
        return Ok(Stored::TooBig);
    }
    let (count, total): (i64, i64) = c.query_row(
        "SELECT COUNT(*), COALESCE(SUM(length(CAST(xml AS BLOB))), 0) FROM private_xml
         WHERE host = ?1 AND user = ?2 AND NOT (ns = ?3 AND name = ?4)",
        params![host, user, v.ns(), v.name()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if count >= MAX_ITEMS || total + xml.len() as i64 > MAX_TOTAL_BYTES {
        return Ok(Stored::Full);
    }
    c.prepare_cached(
        "INSERT INTO private_xml (host, user, ns, name, xml) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(host, user, ns, name) DO UPDATE SET xml = excluded.xml",
    )?
    .execute(params![host, user, v.ns(), v.name(), xml])?;
    Ok(Stored::Yes)
}

pub struct Private;

#[async_trait]
impl Module for Private {
    fn name(&self) -> &'static str {
        "private"
    }
    fn migrations(&self) -> Vec<&'static Migration> {
        vec![&MIGRATION]
    }
    fn snapshot_names(&self, _host: &Host) -> Vec<&'static str> {
        vec!["private"]
    }
    fn iq_namespaces(&self) -> &'static [(&'static str, IqTarget)] {
        // XEP-0049 storage is the account's own, asked for without a `to` (which reaches the
        // sender's bare JID). The server domain has none: a query to it is refused by the router.
        &[(ns::PRIVATE, IqTarget::Account)]
    }

    async fn handle_iq(&self, cx: &IqCtx<'_>) -> IqResult {
        let Some(me) = cx.local_sender().filter(|_| cx.from_self()) else {
            return Err(StanzaError::forbidden().with_text("Only the account itself can use its private storage."));
        };
        let (h, u) = (cx.host.domain.clone(), me.node().unwrap_or_default().to_string());
        let mut children = cx.payload.children();
        let (Some(item), None) = (children.next(), children.next()) else {
            return Err(StanzaError::bad_request().with_text("Private storage takes exactly one element."));
        };
        if item.ns() == ns::PRIVATE || item.ns().is_empty() || item.ns() == ns::CLIENT {
            return Err(StanzaError::new(quark_core::Condition::NotAcceptable));
        }
        let (n, name) = (item.ns().to_string(), item.name().to_string());
        match cx.kind {
            IqType::Get => {
                let stored = cx.srv.db.read(move |c| load(c, &h, &u, &n, &name)).await.map_err(|_| StanzaError::internal())?;
                ok(Element::new("query", ns::PRIVATE).child(stored.unwrap_or_else(|| item.clone())))
            }
            IqType::Set => {
                let mut v = item.clone();
                v.strip_whitespace();
                let data = v.clone();
                match cx.srv.db.write(move |t| store(t, &h, &u, &data)).await.map_err(|_| StanzaError::internal())? {
                    Stored::Yes => {}
                    Stored::TooBig => {
                        return Err(StanzaError::new(quark_core::Condition::NotAcceptable).with_text("That's too much to store."))
                    }
                    Stored::Full => {
                        return Err(StanzaError::new(quark_core::Condition::ResourceConstraint)
                            .with_text("Private storage for this account is full. Remove something first."))
                    }
                }
                cx.srv.emit(&super::Event::PrivateChanged { jid: me, data: v }).await;
                ok_empty()
            }
            _ => Err(StanzaError::bad_request()),
        }
    }
}
