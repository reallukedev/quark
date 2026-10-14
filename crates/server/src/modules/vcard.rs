//! vcard-temp (XEP-0054): one vCard per account, readable by anyone, changed by its owner.

use async_trait::async_trait;
use quark_core::stanza::IqType;
use quark_core::{ns, Element, Jid, StanzaError};

use super::{ok, ok_empty, IqCtx, IqResult, IqTarget, Module};
use crate::db::{params, Migration, OptionalExtension};
use crate::server::Host;

pub static MIGRATION: Migration = Migration {
    module: "vcard",
    steps: &["CREATE TABLE vcards (
        host TEXT NOT NULL,
        user TEXT NOT NULL,
        xml TEXT NOT NULL,
        PRIMARY KEY (host, user),
        FOREIGN KEY (host, user) REFERENCES accounts(host, user) ON DELETE CASCADE
    ) WITHOUT ROWID"],
};

/// vCards carry avatars; this is plenty for a photo and keeps the table sane.
const MAX_BYTES: usize = 192 * 1024;

/// An account's stored vCard, inside a database closure.
pub fn load(c: &rusqlite::Connection, host: &str, user: &str) -> rusqlite::Result<Option<Element>> {
    let xml: Option<String> = c
        .prepare_cached("SELECT xml FROM vcards WHERE host = ?1 AND user = ?2")?
        .query_row(params![host, user], |r| r.get(0))
        .optional()?;
    Ok(xml.and_then(|x| Element::parse(&x).ok()))
}

/// Stores an account's vCard (whitespace stripped), inside a database closure. False, with
/// nothing stored, when it's over the size limit.
pub fn store(c: &rusqlite::Connection, host: &str, user: &str, vcard: &Element) -> rusqlite::Result<bool> {
    let mut v = vcard.clone();
    v.strip_whitespace();
    let xml = v.to_xml();
    if xml.len() > MAX_BYTES {
        return Ok(false);
    }
    c.prepare_cached("INSERT INTO vcards (host, user, xml) VALUES (?1, ?2, ?3) ON CONFLICT(host, user) DO UPDATE SET xml = excluded.xml")?
        .execute(params![host, user, xml])?;
    Ok(true)
}

pub struct VCard;

#[async_trait]
impl Module for VCard {
    fn name(&self) -> &'static str {
        "vcard_legacy"
    }
    fn migrations(&self) -> Vec<&'static Migration> {
        vec![&MIGRATION]
    }
    fn snapshot_names(&self, _host: &Host) -> Vec<&'static str> {
        vec!["vcard_legacy"]
    }
    fn server_features(&self, _host: &Host) -> Vec<&'static str> {
        vec![ns::VCARD]
    }
    fn iq_namespaces(&self) -> &'static [(&'static str, IqTarget)] {
        &[(ns::VCARD, IqTarget::Account), (ns::VCARD, IqTarget::Server)]
    }

    async fn handle_iq(&self, cx: &IqCtx<'_>) -> IqResult {
        // A vCard IQ without `to` reaches the sender's own bare JID, so it's about the account.
        // One addressed to the domain is about the server, which has an empty vCard nobody sets.
        let Some(owner) = cx.to.node().map(str::to_string) else {
            return match cx.kind {
                IqType::Get => ok(Element::new("vCard", ns::VCARD)),
                _ => Err(StanzaError::new(quark_core::Condition::NotAllowed).with_text("The server's own profile can't be changed.")),
            };
        };
        let h = cx.host.domain.clone();
        match cx.kind {
            IqType::Get => {
                let u = owner.clone();
                let v = cx.srv.db.read(move |c| load(c, &h, &u)).await.map_err(|_| StanzaError::internal())?;
                ok(v.unwrap_or_else(|| Element::new("vCard", ns::VCARD)))
            }
            IqType::Set => {
                if cx.local_sender().and_then(|j| j.node().map(str::to_string)).as_deref() != Some(owner.as_str()) {
                    return Err(StanzaError::forbidden());
                }
                let mut v = cx.payload.clone();
                v.strip_whitespace();
                let jid = Jid::bare_unchecked(&owner, &h);
                let stored = v.clone();
                let fits = cx.srv.db.write(move |t| store(t, &h, &owner, &stored)).await.map_err(|_| StanzaError::internal())?;
                if !fits {
                    return Err(StanzaError::new(quark_core::Condition::NotAcceptable)
                        .with_text("That profile is too big (a smaller photo helps)."));
                }
                cx.srv.emit(&super::Event::VCardChanged { jid, vcard: v }).await;
                ok_empty()
            }
            _ => Err(StanzaError::bad_request()),
        }
    }
}
