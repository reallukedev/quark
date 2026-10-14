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
        &[(ns::PRIVATE, IqTarget::Account), (ns::PRIVATE, IqTarget::Server)]
    }

    async fn handle_iq(&self, cx: &IqCtx<'_>) -> IqResult {
        let Some(me) = cx.local_sender() else { return Err(StanzaError::forbidden()) };
        if cx.to.node().is_some_and(|n| Some(n) != me.node()) {
            return Err(StanzaError::forbidden());
        }
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
                let xml: Option<String> = cx
                    .srv
                    .db
                    .read(move |c| {
                        c.query_row(
                            "SELECT xml FROM private_xml WHERE host = ?1 AND user = ?2 AND ns = ?3 AND name = ?4",
                            params![h, u, n, name],
                            |r| r.get(0),
                        )
                        .optional()
                    })
                    .await
                    .map_err(|_| StanzaError::internal())?;
                let stored = xml.and_then(|x| Element::parse(&x).ok()).unwrap_or_else(|| item.clone());
                ok(Element::new("query", ns::PRIVATE).child(stored))
            }
            IqType::Set => {
                let mut v = item.clone();
                v.strip_whitespace();
                let xml = v.to_xml();
                if xml.len() > MAX_BYTES {
                    return Err(StanzaError::new(quark_core::Condition::NotAcceptable).with_text("That's too much to store."));
                }
                cx.srv
                    .db
                    .write(move |t| {
                        t.execute(
                            "INSERT INTO private_xml (host, user, ns, name, xml) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(host, user, ns, name) DO UPDATE SET xml = excluded.xml",
                            params![h, u, n, name, xml],
                        )
                    })
                    .await
                    .map_err(|_| StanzaError::internal())?;
                cx.srv.emit(&super::Event::PrivateChanged { jid: me, data: v }).await;
                ok_empty()
            }
            _ => Err(StanzaError::bad_request()),
        }
    }
}
