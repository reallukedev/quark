//! Offline messages (XEP-0160): kept while every device is away, handed over at the next
//! sign-in with a delay stamp, and dropped after a while.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use quark_core::{ns, Element};

use super::{Flow, Module, StanzaCtx};
use crate::db::{params, Migration};
use crate::server::{Host, Server};
use crate::sessions::SessionHandle;

pub static MIGRATION: Migration = Migration {
    module: "offline",
    steps: &["CREATE TABLE offline (
        id INTEGER PRIMARY KEY,
        host TEXT NOT NULL,
        user TEXT NOT NULL,
        stamp INTEGER NOT NULL,
        xml TEXT NOT NULL,
        FOREIGN KEY (host, user) REFERENCES accounts(host, user) ON DELETE CASCADE
    );
    CREATE INDEX offline_by_user ON offline (host, user, id);"],
};

/// Messages kept per account; the oldest go first.
const MAX_PER_ACCOUNT: i64 = 1_000;
const KEEP_MS: i64 = 30 * 86_400_000;

/// Messages worth keeping: something a person reads, or an explicit `<store/>` hint.
pub fn storable(msg: &Element) -> bool {
    if msg.has_child("no-store", ns::HINTS) || msg.has_child("no-permanent-store", ns::HINTS) {
        return false;
    }
    if !matches!(msg.attr("type"), None | Some("chat" | "normal")) {
        return false;
    }
    msg.has_child("body", ns::CLIENT)
        || msg.has_child("store", ns::HINTS)
        || msg.has_child("encrypted", ns::OMEMO)
        || msg.has_child("encrypted", "urn:xmpp:omemo:2")
        || msg.has_child("x", "jabber:x:conference")
        || msg.get_child("x", ns::MUC_USER).is_some_and(|x| x.has_child("invite", ns::MUC_USER))
}

/// Hands stored messages to a session that just came online, oldest first.
pub async fn flush(srv: &Arc<Server>, host: &Arc<Host>, session: &Arc<SessionHandle>) {
    let Some(user) = session.jid.node().map(str::to_string) else { return };
    let h = host.domain.clone();
    let rows: Vec<(i64, i64, String)> = match srv
        .db
        .write(move |t| {
            let mut st = t.prepare_cached("DELETE FROM offline WHERE host = ?1 AND user = ?2 RETURNING id, stamp, xml")?;
            let rows = st.query_map(params![h, user], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect()
        })
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "couldn't read offline messages");
            return;
        }
    };
    let mut rows = rows;
    rows.sort_by_key(|r| r.0);
    for (_, stamp, xml) in rows {
        let Ok(mut m) = Element::parse(&xml) else { continue };
        m.set_attr("to", session.jid.to_string());
        if !m.has_child("delay", ns::DELAY) {
            m.append(quark_core::stanza::delay(&host.domain, stamp));
        }
        session.send(m);
    }
}

pub struct Offline;

#[async_trait]
impl Module for Offline {
    fn name(&self) -> &'static str {
        "offline"
    }
    fn migrations(&self) -> Vec<&'static Migration> {
        vec![&MIGRATION]
    }
    fn snapshot_names(&self, _host: &Host) -> Vec<&'static str> {
        vec!["offline"]
    }
    fn server_features(&self, _host: &Host) -> Vec<&'static str> {
        vec!["msgoffline"]
    }

    fn start(&self, srv: &Arc<Server>) {
        let db = srv.db.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(3600));
            loop {
                tick.tick().await;
                let cutoff = quark_core::time::now_ms() - KEEP_MS;
                if let Err(e) = db.write(move |t| t.execute("DELETE FROM offline WHERE stamp < ?1", [cutoff])).await {
                    tracing::warn!(error = %e, "offline message expiry failed");
                }
            }
        });
    }

    async fn message_undelivered(&self, cx: &StanzaCtx<'_>, msg: &Element) -> Flow {
        if !storable(msg) {
            return Flow::Continue;
        }
        let Some(user) = cx.to.node().map(str::to_string) else { return Flow::Continue };
        let h = cx.host.domain.clone();
        let xml = msg.to_xml();
        let now = quark_core::time::now_ms();
        let r = cx
            .srv
            .db
            .write(move |t| {
                t.execute("INSERT INTO offline (host, user, stamp, xml) VALUES (?1, ?2, ?3, ?4)", params![h, user, now, xml])?;
                t.execute(
                    "DELETE FROM offline WHERE host = ?1 AND user = ?2 AND id NOT IN (SELECT id FROM offline WHERE host = ?1 AND user = ?2 ORDER BY id DESC LIMIT ?3)",
                    params![h, user, MAX_PER_ACCOUNT],
                )
            })
            .await;
        match r {
            Ok(_) => Flow::Stop,
            Err(e) => {
                tracing::warn!(error = %e, "couldn't store an offline message");
                Flow::Continue
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_bodies_but_not_chat_states_or_no_store() {
        assert!(storable(&Element::parse("<message xmlns='jabber:client' type='chat'><body>hi</body></message>").unwrap()));
        assert!(!storable(
            &Element::parse("<message xmlns='jabber:client' type='chat'><active xmlns='http://jabber.org/protocol/chatstates'/></message>")
                .unwrap()
        ));
        assert!(!storable(
            &Element::parse("<message xmlns='jabber:client'><body>x</body><no-store xmlns='urn:xmpp:hints'/></message>").unwrap()
        ));
        assert!(!storable(&Element::parse("<message xmlns='jabber:client' type='headline'><body>x</body></message>").unwrap()));
    }
}
