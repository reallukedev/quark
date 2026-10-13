//! Last Activity (XEP-0012): server uptime, and when a contact was last online.

use std::sync::Arc;

use async_trait::async_trait;
use quark_core::stanza::IqType;
use quark_core::{ns, Element, Jid, StanzaError};

use super::{ok, Event, IqCtx, IqResult, IqTarget, Module};
use crate::db::{params, DbError, Migration, OptionalExtension};
use crate::server::{Host, Server};

pub static MIGRATION: Migration = Migration {
    module: "last",
    steps: &["CREATE TABLE last_activity (
        host TEXT NOT NULL,
        user TEXT NOT NULL,
        at INTEGER NOT NULL,
        status TEXT,
        PRIMARY KEY (host, user),
        FOREIGN KEY (host, user) REFERENCES accounts(host, user) ON DELETE CASCADE
    ) WITHOUT ROWID"],
};

/// When the account last went offline (ms), if ever.
pub async fn last_seen(srv: &Server, host: &str, user: &str) -> Result<Option<i64>, DbError> {
    let (h, u) = (host.to_string(), user.to_string());
    srv.db
        .read(move |c| c.query_row("SELECT at FROM last_activity WHERE host = ?1 AND user = ?2", params![h, u], |r| r.get(0)).optional())
        .await
}

pub struct Last;

#[async_trait]
impl Module for Last {
    fn name(&self) -> &'static str {
        "lastactivity"
    }
    fn migrations(&self) -> Vec<&'static Migration> {
        vec![&MIGRATION]
    }
    fn snapshot_names(&self, _host: &Host) -> Vec<&'static str> {
        vec!["lastactivity", "uptime"]
    }
    fn server_features(&self, _host: &Host) -> Vec<&'static str> {
        vec![ns::LAST]
    }
    fn iq_namespaces(&self) -> &'static [(&'static str, IqTarget)] {
        &[(ns::LAST, IqTarget::Server), (ns::LAST, IqTarget::Account)]
    }

    async fn handle_iq(&self, cx: &IqCtx<'_>) -> IqResult {
        if cx.kind != IqType::Get {
            return Err(StanzaError::bad_request());
        }
        let now = quark_core::time::now_ms();
        let Some(user) = cx.to.node() else {
            let up = (now - cx.srv.started_at) / 1000;
            return ok(Element::new("query", ns::LAST).attr_set("seconds", up.to_string()));
        };
        // Only people who may see the account's presence learn when it was last around.
        if !cx.from_self() {
            let it = super::roster::item(cx.srv, &cx.host.domain, user, &cx.from.to_bare()).await.map_err(|_| StanzaError::internal())?;
            if !it.is_some_and(|i| i.subscription.sends_to_contact()) {
                return Err(StanzaError::forbidden());
            }
        }
        if cx.srv.sessions.is_online(&cx.to.to_bare()) {
            return ok(Element::new("query", ns::LAST).attr_set("seconds", "0"));
        }
        let (h, u) = (cx.host.domain.clone(), user.to_string());
        let row: Option<(i64, Option<String>)> = cx
            .srv
            .db
            .read(move |c| {
                c.query_row("SELECT at, status FROM last_activity WHERE host = ?1 AND user = ?2", params![h, u], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()
            })
            .await
            .map_err(|_| StanzaError::internal())?;
        let Some((at, status)) = row else { return Err(StanzaError::service_unavailable()) };
        ok(Element::new("query", ns::LAST).attr_set("seconds", ((now - at) / 1000).max(0).to_string()).text(status.unwrap_or_default()))
    }

    async fn on_event(&self, srv: &Arc<Server>, ev: &Event) {
        let Event::SessionEnded { jid } = ev else { return };
        let bare: Jid = jid.to_bare();
        if srv.sessions.is_online(&bare) {
            return;
        }
        let (Some(u), h) = (bare.node().map(str::to_string), bare.domain().to_string()) else { return };
        let now = quark_core::time::now_ms();
        let r = srv
            .db
            .write(move |t| {
                t.execute(
                    "INSERT INTO last_activity (host, user, at) SELECT ?1, ?2, ?3 WHERE EXISTS (SELECT 1 FROM accounts WHERE host = ?1 AND user = ?2)
                     ON CONFLICT(host, user) DO UPDATE SET at = excluded.at",
                    params![h, u, now],
                )
            })
            .await;
        if let Err(e) = r {
            tracing::warn!(error = %e, "couldn't record last activity");
        }
    }
}
