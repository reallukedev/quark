//! Push Notifications (XEP-0357): apps register an app server (`<enable/>`), and when a message
//! arrives for a device that's offline or whose connection dropped (waiting for stream
//! resumption), the server publishes a notification to that app server, which wakes the app.
//!
//! Notifications say only that something arrived: no sender and no text, since they pass through
//! the app vendor's servers and the phone maker's. Each carries a priority
//! (`tigase:push:priority:0`): `high` for what a person should see (a message, a call), `normal`
//! for things that only change what's already shown (read markers, reactions, retractions), so
//! apps can sync those silently. `normal` ones are sent at most once a minute per registration.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use quark_core::stanza::{ErrorType, IqType};
use quark_core::{ns, Condition, Element, Jid, StanzaError};

use super::mam::form;
use super::{ok_empty, Event, Flow, IqCtx, IqResult, IqTarget, Module, StanzaCtx};
use crate::db::{params, DbError, Migration};
use crate::server::{Host, Server};

pub static MIGRATION: Migration = Migration {
    module: "push",
    steps: &["CREATE TABLE push_registrations (
        host TEXT NOT NULL,
        user TEXT NOT NULL,
        service TEXT NOT NULL,
        node TEXT NOT NULL,
        -- The device that registered, so it isn't woken while it's connected.
        resource TEXT,
        -- The publish-options form (the app server's secret), as XML.
        options TEXT,
        created INTEGER NOT NULL,
        PRIMARY KEY (host, user, service, node),
        FOREIGN KEY (host, user) REFERENCES accounts(host, user) ON DELETE CASCADE
    ) WITHOUT ROWID;"],
};

/// The priority extension Monal, Siskin and Prosody's `mod_cloud_notify_priority_tag` use.
pub const PRIORITY: &str = "tigase:push:priority:0";
pub const SUMMARY: &str = "urn:xmpp:push:summary";
pub const PUBLISH_OPTIONS: &str = "http://jabber.org/protocol/pubsub#publish-options";

/// Registrations kept per account; the oldest go first.
const MAX_PER_ACCOUNT: usize = 20;
const MAX_OPTIONS_BYTES: usize = 4 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);
/// Least time between two `normal` notifications to one registration.
const NORMAL_EVERY_MS: i64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    High,
    Normal,
}

impl Priority {
    pub fn as_str(self) -> &'static str {
        match self {
            Priority::High => "high",
            Priority::Normal => "normal",
        }
    }
}

/// Whether a message is worth a notification, and how urgent it is. Follows Prosody's
/// `mod_cloud_notify`: bodies, encrypted messages and call invitations are high; group chat
/// subjects, headlines and errors get nothing.
pub fn priority(msg: &Element) -> Option<Priority> {
    let kind = msg.attr("type").unwrap_or("normal");
    if matches!(kind, "headline" | "error") || msg.child_ns(ns::CARBONS).is_some() || msg.has_child("result", ns::MAM) {
        return None;
    }
    if kind == "groupchat" && msg.get_child("subject", ns::CLIENT).is_some() {
        return None;
    }
    let important = msg.has_child("encrypted", ns::OMEMO)
        || msg.has_child("encrypted", "urn:xmpp:omemo:2")
        || msg.has_child("x", "jabber:x:encrypted")
        || msg.has_child("openpgp", "urn:xmpp:openpgp:0")
        || msg.has_child("propose", "urn:xmpp:jingle-message:0")
        || msg.child_text("body", ns::CLIENT).is_some_and(|b| !b.trim().is_empty());
    if important {
        return Some(Priority::High);
    }
    // In a busy room every reaction would wake every phone.
    if kind != "groupchat" && super::mam::archivable(msg) {
        return Some(Priority::Normal);
    }
    None
}

/// One app's registration (XEP-0357 §5).
#[derive(Debug, Clone, PartialEq)]
pub struct Registration {
    pub service: Jid,
    pub node: String,
    pub resource: Option<String>,
    pub options: Option<Element>,
}

#[derive(Default)]
struct State {
    /// Registrations by account; absent until first needed.
    regs: Mutex<HashMap<Jid, Arc<Vec<Registration>>>>,
    /// When each registration last got a `normal` notification.
    last_normal: Mutex<HashMap<(Jid, Jid, String), i64>>,
}

fn db_error(e: DbError) -> StanzaError {
    tracing::warn!(error = %e, "push registration storage");
    StanzaError::internal().with_text("Push notifications couldn't be set up right now.")
}

fn read_rows(c: &rusqlite::Connection, h: &str, u: &str) -> rusqlite::Result<Vec<Registration>> {
    let mut s =
        c.prepare_cached("SELECT service, node, resource, options FROM push_registrations WHERE host = ?1 AND user = ?2 ORDER BY created")?;
    let rows = s.query_map(params![h, u], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?, r.get::<_, Option<String>>(3)?))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (service, node, resource, options) = row?;
        let Ok(service) = Jid::parse(&service) else { continue };
        out.push(Registration { service, node, resource, options: options.and_then(|x| Element::parse(&x).ok()) });
    }
    Ok(out)
}

/// The account's registrations, from the cache or the database.
pub async fn registrations(srv: &Server, account: &Jid) -> Result<Arc<Vec<Registration>>, DbError> {
    let account = account.to_bare();
    let st = srv.ext::<State>();
    if let Some(r) = st.regs.lock().get(&account) {
        return Ok(r.clone());
    }
    let (h, u) = (account.domain().to_string(), account.node().unwrap_or_default().to_string());
    let regs = srv.db.read(move |c| read_rows(c, &h, &u)).await?;
    // A change saved while this was loading already put the newer list in place.
    let r = st.regs.lock().entry(account).or_insert_with(|| Arc::new(regs)).clone();
    Ok(r)
}

fn bad(text: &str) -> StanzaError {
    StanzaError::bad_request().with_text(text.to_string())
}

fn service_attr(payload: &Element) -> Result<Jid, StanzaError> {
    let j = payload.attr("jid").ok_or_else(|| bad("Say which app server to use ('jid')."))?;
    Jid::parse(j).map_err(|_| StanzaError::new(Condition::JidMalformed).with_text(format!("'{j}' isn't a valid address.")))
}

/// Reads an `<enable/>`: the app server, its node and the publish options.
fn parse_enable(payload: &Element) -> Result<(Jid, String, Option<Element>), StanzaError> {
    let service = service_attr(payload)?;
    let node = payload.attr("node").filter(|n| !n.is_empty()).ok_or_else(|| bad("Say which node to publish to ('node')."))?;
    let options = match payload.get_child("x", ns::DATA_FORMS) {
        None => None,
        Some(x) => {
            if form::value(x, "FORM_TYPE").as_deref() != Some(PUBLISH_OPTIONS) {
                return Err(bad("The form must be pubsub#publish-options."));
            }
            let mut x = x.clone();
            x.set_attr("type", "submit");
            x.strip_whitespace();
            if x.to_xml().len() > MAX_OPTIONS_BYTES {
                return Err(StanzaError::new(Condition::NotAcceptable).with_text("The publish options are too large."));
            }
            Some(x)
        }
    };
    Ok((service, node.to_string(), options))
}

/// The publish IQ for one notification (XEP-0357 §7).
pub fn notification(account: &Jid, reg: &Registration, prio: Priority) -> Element {
    let summary = Element::new("x", ns::DATA_FORMS)
        .attr_set("type", "submit")
        .child(form::field("FORM_TYPE", SUMMARY))
        .child(form::field("message-count", "1"));
    let note = Element::new("notification", ns::PUSH).child(summary).child(Element::new("priority", PRIORITY).text(prio.as_str()));
    let mut pubsub = Element::new("pubsub", ns::PUBSUB)
        .child(Element::new("publish", ns::PUBSUB).attr_set("node", reg.node.clone()).child(Element::new("item", ns::PUBSUB).child(note)));
    if let Some(o) = &reg.options {
        pubsub.append(Element::new("publish-options", ns::PUBSUB).child(o.clone()));
    }
    Element::new("iq", ns::CLIENT)
        .attr_set("type", "set")
        .attr_set("from", account.to_string())
        .attr_set("to", reg.service.to_string())
        .child(pubsub)
}

/// Whether an app server's answer means the registration is dead (the app was removed or the
/// token revoked). Errors from the way there (unreachable server, timeouts) don't count.
fn is_permanent(e: &StanzaError) -> bool {
    matches!(e.kind, ErrorType::Cancel | ErrorType::Auth)
        && matches!(
            e.condition,
            Condition::ItemNotFound | Condition::NotAuthorized | Condition::Forbidden | Condition::RegistrationRequired | Condition::Gone
        )
}

async fn remove(srv: &Server, account: &Jid, service: &Jid, node: Option<&str>) -> Result<(), DbError> {
    let (h, u, s, n) =
        (account.domain().to_string(), account.node().unwrap_or_default().to_string(), service.to_string(), node.map(str::to_string));
    let regs = srv
        .db
        .write(move |t| {
            match &n {
                Some(n) => t.execute(
                    "DELETE FROM push_registrations WHERE host = ?1 AND user = ?2 AND service = ?3 AND node = ?4",
                    params![h, u, s, n],
                )?,
                None => t.execute("DELETE FROM push_registrations WHERE host = ?1 AND user = ?2 AND service = ?3", params![h, u, s])?,
            };
            read_rows(t, &h, &u)
        })
        .await?;
    srv.ext::<State>().regs.lock().insert(account.to_bare(), Arc::new(regs));
    Ok(())
}

/// A push notification this server sends to an app server (a pubsub publish of
/// `<notification xmlns='urn:xmpp:push:0'/>`).
pub fn is_notification(el: &Element) -> bool {
    el.name() == "iq"
        && el.attr("type") == Some("set")
        && el
            .get_child("pubsub", ns::PUBSUB)
            .and_then(|p| p.get_child("publish", ns::PUBSUB))
            .and_then(|p| p.get_child("item", ns::PUBSUB))
            .is_some_and(|i| i.has_child("notification", ns::PUSH))
}

/// Sends one notification and drops the registration if the app server says it's gone.
async fn notify(srv: Arc<Server>, account: Jid, reg: Registration, prio: Priority) {
    let iq = notification(&account, &reg, prio);
    match srv.request(iq, TIMEOUT).await {
        Ok(_) => {}
        Err(e) if is_permanent(&e) => {
            tracing::info!(account = %account, service = %reg.service, error = %e, "app server refused a push; removing the registration");
            if let Err(e) = remove(&srv, &account, &reg.service, Some(&reg.node)).await {
                tracing::warn!(error = %e, "couldn't remove a push registration");
            }
        }
        Err(e) => tracing::debug!(account = %account, service = %reg.service, error = %e, "push notification failed"),
    }
}

/// Whether the device behind `reg` needs waking for a message to `to`: it's not connected, or
/// its connection dropped and the session waits to be resumed.
fn needs_wake(srv: &Server, account: &Jid, reg: &Registration, to: &Jid, msg: &Element) -> bool {
    // Group chat traffic only goes to the device that joined.
    let room_traffic = msg.attr("type") == Some("groupchat") || to.is_full() && msg.has_child("x", ns::MUC_USER);
    if room_traffic && to.resource() != reg.resource.as_deref() {
        return false;
    }
    let Some(r) = reg.resource.as_deref() else { return true };
    let Ok(full) = account.with_resource(r) else { return true };
    match srv.sessions.get(&full) {
        None => true,
        Some(s) => s.flags.lock().hibernating,
    }
}

pub struct Push;

#[async_trait]
impl Module for Push {
    fn name(&self) -> &'static str {
        "cloud_notify"
    }

    fn migrations(&self) -> Vec<&'static Migration> {
        vec![&MIGRATION]
    }

    fn snapshot_names(&self, host: &Host) -> Vec<&'static str> {
        if host.settings().push {
            vec!["cloud_notify"]
        } else {
            Vec::new()
        }
    }

    fn account_features(&self, host: &Host) -> Vec<&'static str> {
        if host.settings().push {
            vec![ns::PUSH, PRIORITY]
        } else {
            Vec::new()
        }
    }

    /// XEP-0357 puts the feature on the account, but some clients (ChatSecure) only look at the
    /// server's disco#info and report "no push support" without it, so it's listed there too,
    /// as ejabberd and Prosody do.
    fn server_features(&self, host: &Host) -> Vec<&'static str> {
        self.account_features(host)
    }

    fn iq_namespaces(&self) -> &'static [(&'static str, IqTarget)] {
        &[(ns::PUSH, IqTarget::Account), (ns::PUSH, IqTarget::Server)]
    }

    async fn handle_iq(&self, cx: &IqCtx<'_>) -> IqResult {
        let Some(account) = cx.local_sender() else { return Err(StanzaError::service_unavailable()) };
        if cx.to.node().is_some() && !cx.from_self() {
            return Err(StanzaError::forbidden().with_text("Only the account itself can set up its push notifications."));
        }
        if cx.kind != IqType::Set {
            return Err(StanzaError::bad_request());
        }
        let (h, u) = (account.domain().to_string(), account.node().unwrap_or_default().to_string());
        match cx.payload.name() {
            "enable" => {
                if !cx.host.settings().push {
                    return Err(StanzaError::service_unavailable().with_text("Push notifications are turned off on this server."));
                }
                let (service, node, options) = parse_enable(cx.payload)?;
                let (s, resource, xml) = (service.to_string(), cx.from.resource().map(str::to_string), options.map(|o| o.to_xml()));
                let now = quark_core::time::now_ms();
                let regs = cx
                    .srv
                    .db
                    .write(move |t| {
                        t.execute(
                            "INSERT INTO push_registrations (host, user, service, node, resource, options, created) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                             ON CONFLICT(host, user, service, node) DO UPDATE SET resource = excluded.resource, options = excluded.options, created = excluded.created",
                            params![h, u, s, node, resource, xml, now],
                        )?;
                        t.execute(
                            "DELETE FROM push_registrations WHERE host = ?1 AND user = ?2 AND (service, node) NOT IN
                             (SELECT service, node FROM push_registrations WHERE host = ?1 AND user = ?2 ORDER BY created DESC LIMIT ?3)",
                            params![h, u, MAX_PER_ACCOUNT as i64],
                        )?;
                        read_rows(t, &h, &u)
                    })
                    .await
                    .map_err(db_error)?;
                cx.srv.ext::<State>().regs.lock().insert(account, Arc::new(regs));
                ok_empty()
            }
            "disable" => {
                let service = service_attr(cx.payload)?;
                let node = cx.payload.attr("node").filter(|n| !n.is_empty());
                remove(cx.srv, &account, &service, node).await.map_err(db_error)?;
                ok_empty()
            }
            _ => Err(StanzaError::bad_request()),
        }
    }

    async fn message_in(&self, cx: &StanzaCtx<'_>, msg: &mut Element) -> Flow {
        if !cx.host.settings().push {
            return Flow::Continue;
        }
        let account = cx.to.to_bare();
        // What the account sends itself (notes to self) already shows on the sending device.
        if cx.from.to_bare() == account {
            return Flow::Continue;
        }
        let Some(prio) = priority(msg) else { return Flow::Continue };
        let regs = match registrations(cx.srv, &account).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "couldn't read push registrations");
                return Flow::Continue;
            }
        };
        if regs.is_empty() {
            return Flow::Continue;
        }
        let now = quark_core::time::now_ms();
        for reg in regs.iter() {
            if !needs_wake(cx.srv, &account, reg, cx.to, msg) {
                continue;
            }
            if prio == Priority::Normal {
                let st = cx.srv.ext::<State>();
                let mut last = st.last_normal.lock();
                let key = (account.clone(), reg.service.clone(), reg.node.clone());
                if last.get(&key).is_some_and(|t| now - t < NORMAL_EVERY_MS) {
                    continue;
                }
                last.insert(key, now);
            }
            // In the background: the app server may be slow, and delivery mustn't wait for it.
            tokio::spawn(notify(cx.srv.clone(), account.clone(), reg.clone(), prio));
        }
        Flow::Continue
    }

    async fn on_event(&self, srv: &Arc<Server>, ev: &Event) {
        if let Event::AccountDeleted { jid } = ev {
            let bare = jid.to_bare();
            let st = srv.ext::<State>();
            st.regs.lock().remove(&bare);
            st.last_normal.lock().retain(|(a, _, _), _| *a != bare);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(xml: &str) -> Element {
        Element::parse(xml).unwrap()
    }

    #[test]
    fn priorities_follow_what_people_see() {
        assert_eq!(priority(&msg("<message xmlns='jabber:client' type='chat'><body>hi</body></message>")), Some(Priority::High));
        assert_eq!(
            priority(&msg("<message xmlns='jabber:client' type='chat'><encrypted xmlns='eu.siacs.conversations.axolotl'/></message>")),
            Some(Priority::High)
        );
        assert_eq!(
            priority(&msg("<message xmlns='jabber:client'><propose xmlns='urn:xmpp:jingle-message:0' id='c1'/></message>")),
            Some(Priority::High)
        );
        assert_eq!(
            priority(&msg("<message xmlns='jabber:client' type='chat'><displayed xmlns='urn:xmpp:chat-markers:0' id='m1'/></message>")),
            Some(Priority::Normal)
        );
        assert_eq!(
            priority(&msg(
                "<message xmlns='jabber:client' type='chat'><composing xmlns='http://jabber.org/protocol/chatstates'/></message>"
            )),
            None
        );
        // An empty body is nothing to read, but still part of the conversation.
        assert_eq!(priority(&msg("<message xmlns='jabber:client' type='chat'><body>  </body></message>")), Some(Priority::Normal));
        assert_eq!(priority(&msg("<message xmlns='jabber:client' type='headline'><body>x</body></message>")), None);
        assert_eq!(priority(&msg("<message xmlns='jabber:client' type='groupchat'><subject>t</subject><body>x</body></message>")), None);
        assert_eq!(priority(&msg("<message xmlns='jabber:client' type='groupchat'><body>x</body></message>")), Some(Priority::High));
        assert_eq!(
            priority(&msg("<message xmlns='jabber:client' type='groupchat'><reactions xmlns='urn:xmpp:reactions:0' id='a'/></message>")),
            None
        );
    }

    #[test]
    fn enable_needs_a_service_node_and_the_right_form() {
        let e = msg("<enable xmlns='urn:xmpp:push:0' jid='Push.Example' node='n1'><x xmlns='jabber:x:data' type='submit'>\
             <field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field>\
             <field var='secret'><value>s3</value></field></x></enable>");
        let (service, node, options) = parse_enable(&e).unwrap();
        assert_eq!(service.to_string(), "push.example");
        assert_eq!(node, "n1");
        assert_eq!(options.as_ref().and_then(|o| form::value(o, "secret")).as_deref(), Some("s3"));
        assert!(parse_enable(&msg("<enable xmlns='urn:xmpp:push:0' jid='push.example'/>")).is_err());
        assert!(parse_enable(&msg("<enable xmlns='urn:xmpp:push:0' node='n'/>")).is_err());
        assert!(parse_enable(&msg(
            "<enable xmlns='urn:xmpp:push:0' jid='p.example' node='n'><x xmlns='jabber:x:data'><field var='FORM_TYPE'><value>other</value></field></x></enable>"
        ))
        .is_err());
    }

    #[test]
    fn notifications_carry_no_content_but_do_carry_the_secret_and_priority() {
        let reg = Registration {
            service: Jid::parse("push.example").unwrap(),
            node: "n1".into(),
            resource: Some("phone".into()),
            options: Some(msg("<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field><field var='secret'><value>s3</value></field></x>")),
        };
        let iq = notification(&Jid::parse("bob@quark.test").unwrap(), &reg, Priority::High);
        assert_eq!(iq.attr("to"), Some("push.example"));
        assert_eq!(iq.attr("from"), Some("bob@quark.test"));
        let pubsub = iq.get_child("pubsub", ns::PUBSUB).unwrap();
        let publish = pubsub.get_child("publish", ns::PUBSUB).unwrap();
        assert_eq!(publish.attr("node"), Some("n1"));
        let note = publish.get_child("item", ns::PUBSUB).unwrap().get_child("notification", ns::PUSH).unwrap();
        assert_eq!(note.child_text("priority", PRIORITY).as_deref(), Some("high"));
        let summary = note.get_child("x", ns::DATA_FORMS).unwrap();
        assert_eq!(form::value(summary, "FORM_TYPE").as_deref(), Some(SUMMARY));
        assert!(form::value(summary, "last-message-body").is_none());
        assert!(form::value(summary, "last-message-sender").is_none());
        let opts = pubsub.get_child("publish-options", ns::PUBSUB).unwrap().get_child("x", ns::DATA_FORMS).unwrap();
        assert_eq!(form::value(opts, "secret").as_deref(), Some("s3"));
    }

    #[test]
    fn only_the_app_servers_own_refusals_remove_a_registration() {
        assert!(is_permanent(&StanzaError::item_not_found()));
        assert!(is_permanent(&StanzaError::new(Condition::NotAuthorized)));
        assert!(!is_permanent(&StanzaError::new(Condition::RemoteServerNotFound)));
        assert!(!is_permanent(&StanzaError::new(Condition::RemoteServerTimeout)));
        assert!(!is_permanent(&StanzaError::item_not_found().with_type(ErrorType::Wait)));
        assert!(!is_permanent(&StanzaError::internal()));
    }
}
