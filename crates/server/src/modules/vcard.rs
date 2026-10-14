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
        // A vCard IQ without `to` is about the sender's own account.
        let owner = match cx.to.node() {
            Some(n) => n.to_string(),
            None if cx.kind == IqType::Set || cx.local_sender().is_some() => match cx.local_sender() {
                Some(j) => j.node().unwrap_or_default().to_string(),
                None => return Err(StanzaError::forbidden()),
            },
            None => return Err(StanzaError::item_not_found()),
        };
        let h = cx.host.domain.clone();
        match cx.kind {
            IqType::Get => {
                let u = owner.clone();
                let xml: Option<String> = cx
                    .srv
                    .db
                    .read(move |c| {
                        c.query_row("SELECT xml FROM vcards WHERE host = ?1 AND user = ?2", params![h, u], |r| r.get(0)).optional()
                    })
                    .await
                    .map_err(|_| StanzaError::internal())?;
                match xml.and_then(|x| Element::parse(&x).ok()) {
                    Some(v) => ok(v),
                    None => ok(Element::new("vCard", ns::VCARD)),
                }
            }
            IqType::Set => {
                if cx.local_sender().and_then(|j| j.node().map(str::to_string)).as_deref() != Some(owner.as_str()) {
                    return Err(StanzaError::forbidden());
                }
                let mut v = cx.payload.clone();
                v.strip_whitespace();
                let xml = v.to_xml();
                if xml.len() > MAX_BYTES {
                    return Err(StanzaError::new(quark_core::Condition::NotAcceptable)
                        .with_text("That profile is too big (a smaller photo helps)."));
                }
                let jid = Jid::bare_unchecked(&owner, &h);
                cx.srv
                    .db
                    .write(move |t| t.execute("INSERT INTO vcards (host, user, xml) VALUES (?1, ?2, ?3) ON CONFLICT(host, user) DO UPDATE SET xml = excluded.xml", params![h, owner, xml]))
                    .await
                    .map_err(|_| StanzaError::internal())?;
                cx.srv.emit(&super::Event::VCardChanged { jid, vcard: v }).await;
                ok_empty()
            }
            _ => Err(StanzaError::bad_request()),
        }
    }
}
