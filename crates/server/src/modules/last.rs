//! Last Activity (XEP-0012): server uptime, and when a contact was last online.

use async_trait::async_trait;
use quark_core::stanza::IqType;
use quark_core::{ns, Element, StanzaError};

use super::{ok, IqCtx, IqResult, IqTarget, Module};
use crate::db::{DbError, Migration};
use crate::server::{Host, Server};

pub static MIGRATION: Migration = Migration {
    module: "last",
    steps: &[
        "CREATE TABLE last_activity (
        host TEXT NOT NULL,
        user TEXT NOT NULL,
        at INTEGER NOT NULL,
        status TEXT,
        PRIMARY KEY (host, user),
        FOREIGN KEY (host, user) REFERENCES accounts(host, user) ON DELETE CASCADE
    ) WITHOUT ROWID",
        // The time also lived in `accounts.last_active` (written when a session ends, shown in
        // the admin API); that is the one place now. `status` was never filled in.
        "UPDATE accounts SET last_active = (SELECT l.at FROM last_activity l WHERE l.host = accounts.host AND l.user = accounts.user)
         WHERE EXISTS (SELECT 1 FROM last_activity l WHERE l.host = accounts.host AND l.user = accounts.user
                       AND (accounts.last_active IS NULL OR l.at > accounts.last_active));
         DROP TABLE last_activity;",
    ],
};

/// When the account last went offline (ms), if ever: `accounts.last_active`, set as each
/// session ends.
pub async fn last_seen(srv: &Server, host: &str, user: &str) -> Result<Option<i64>, DbError> {
    Ok(srv.accounts.info(host, user).await?.and_then(|i| i.last_active))
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
        let at = last_seen(cx.srv, &cx.host.domain, user).await.map_err(|_| StanzaError::internal())?;
        let Some(at) = at else { return Err(StanzaError::service_unavailable()) };
        ok(Element::new("query", ns::LAST).attr_set("seconds", ((now - at) / 1000).max(0).to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{params, Db};

    #[tokio::test]
    async fn migration_keeps_the_later_time() {
        let db = Db::memory().unwrap();
        db.migrate(&[&crate::accounts::MIGRATION]).unwrap();
        let first = Migration { module: "last", steps: &MIGRATION.steps[..1] };
        db.migrate(&[&first]).unwrap();
        db.write(|t| {
            for (u, last) in [("a", None), ("b", Some(50)), ("c", Some(500))] {
                t.execute(
                    "INSERT INTO accounts (host, user, created, password_changed, salt, iterations, last_active, sha1_stored, sha1_server, sha256_stored, sha256_server, sha512_stored, sha512_server)
                     VALUES ('h', ?1, 0, 0, x'00', 1, ?2, x'00', x'00', x'00', x'00', x'00', x'00')",
                    params![u, last],
                )?;
                t.execute("INSERT INTO last_activity (host, user, at) VALUES ('h', ?1, 100)", params![u])?;
            }
            Ok(())
        })
        .await
        .unwrap();
        db.migrate(&[&MIGRATION]).unwrap();
        let rows: Vec<(String, Option<i64>)> = db
            .read(|c| {
                let mut st = c.prepare("SELECT user, last_active FROM accounts ORDER BY user")?;
                let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
                rows.collect()
            })
            .await
            .unwrap();
        assert_eq!(rows, vec![("a".into(), Some(100)), ("b".into(), Some(100)), ("c".into(), Some(500))]);
        let gone: i64 =
            db.read(|c| c.query_row("SELECT COUNT(*) FROM sqlite_master WHERE name = 'last_activity'", [], |r| r.get(0))).await.unwrap();
        assert_eq!(gone, 0);
    }
}
