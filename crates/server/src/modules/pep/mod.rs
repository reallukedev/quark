//! Personal Eventing (XEP-0163) on XEP-0060 nodes: avatars, OMEMO keys, bookmarks, nicknames.
//!
//! Every account is a pubsub service at its bare JID (IQs without `to` from the account itself
//! address it too). Items are stored per node; notifications go to the owner's devices and to
//! contacts that see the owner's presence, filtered by the `+notify` features in their entity
//! capabilities (XEP-0115), which are looked up once per `ver` and cached. Contacts coming
//! online get the last item of each node they care about.
//!
//! Extras: smart defaults for well-known nodes (bookmarks private, OMEMO keys open), vCard
//! avatars mirrored to and from PEP (XEP-0398), and legacy bookmarks kept in step with
//! bookmarks 2 (XEP-0402 compat, XEP-0411).

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use quark_core::{ns, Element, Jid, StanzaError};

use super::{Event, Flow, Identity, IqCtx, IqResult, IqTarget, Module, StanzaCtx};
use crate::db::Migration;
use crate::server::{Host, Server};
use crate::sessions::SessionHandle;

mod avatar;
mod bookmarks;
mod caps;
mod config;
mod deliver;
mod iq;
mod store;

use caps::{Bounded, Caps, CapsCache};

/// Largest item payload, in bytes of XML.
const MAX_ITEM_BYTES: usize = 256 * 1024;
/// Payload bytes one account may keep in all its nodes.
const MAX_ACCOUNT_BYTES: i64 = 16 * 1024 * 1024;
const MAX_NODES: u32 = 512;
/// Longest node name or item id.
const MAX_NAME: usize = 1024;
/// Explicit subscriptions and affiliations per node.
const MAX_PER_NODE: u32 = 1024;

const FEATURES: &[&str] = &[
    ns::PUBSUB,
    "http://jabber.org/protocol/pubsub#access-open",
    "http://jabber.org/protocol/pubsub#access-presence",
    "http://jabber.org/protocol/pubsub#access-roster",
    "http://jabber.org/protocol/pubsub#access-whitelist",
    "http://jabber.org/protocol/pubsub#auto-create",
    "http://jabber.org/protocol/pubsub#auto-subscribe",
    "http://jabber.org/protocol/pubsub#config-node",
    "http://jabber.org/protocol/pubsub#config-node-max",
    "http://jabber.org/protocol/pubsub#create-and-configure",
    "http://jabber.org/protocol/pubsub#create-nodes",
    "http://jabber.org/protocol/pubsub#delete-items",
    "http://jabber.org/protocol/pubsub#delete-nodes",
    "http://jabber.org/protocol/pubsub#filtered-notifications",
    "http://jabber.org/protocol/pubsub#instant-nodes",
    "http://jabber.org/protocol/pubsub#item-ids",
    "http://jabber.org/protocol/pubsub#last-published",
    "http://jabber.org/protocol/pubsub#manage-subscriptions",
    "http://jabber.org/protocol/pubsub#member-affiliation",
    "http://jabber.org/protocol/pubsub#modify-affiliations",
    "http://jabber.org/protocol/pubsub#multi-items",
    "http://jabber.org/protocol/pubsub#outcast-affiliation",
    "http://jabber.org/protocol/pubsub#persistent-items",
    "http://jabber.org/protocol/pubsub#presence-notifications",
    "http://jabber.org/protocol/pubsub#presence-subscribe",
    "http://jabber.org/protocol/pubsub#publish",
    "http://jabber.org/protocol/pubsub#publish-options",
    "http://jabber.org/protocol/pubsub#purge-nodes",
    "http://jabber.org/protocol/pubsub#retract-items",
    "http://jabber.org/protocol/pubsub#retrieve-affiliations",
    "http://jabber.org/protocol/pubsub#retrieve-default",
    "http://jabber.org/protocol/pubsub#retrieve-items",
    "http://jabber.org/protocol/pubsub#retrieve-subscriptions",
    "http://jabber.org/protocol/pubsub#subscribe",
    avatar::CONVERSION,
    bookmarks::COMPAT,
    bookmarks::COMPAT_PEP,
];

pub struct Pep {
    st: Arc<State>,
}

impl Default for Pep {
    fn default() -> Self {
        Pep { st: Arc::new(State::default()) }
    }
}

/// A remote contact's resource that's online for a local account.
struct RemoteResource {
    ver: String,
    /// The caps whose last items it already got.
    acted: Option<Arc<Caps>>,
}

/// Remote resources tracked per local account, and in all.
const REMOTE_PER_ACCOUNT: usize = 256;
const REMOTE_TOTAL: usize = 100_000;
const AVATAR_CACHE: usize = 8192;

/// What PEP keeps in memory; all of it can be rebuilt from presence and the database.
pub(crate) struct State {
    caps: CapsCache,
    /// Local sessions, by full JID: the caps whose last items they already got.
    local: Mutex<HashMap<Jid, Arc<Caps>>>,
    /// Remote contacts' resources online, per local account (bare JID).
    remote: Mutex<HashMap<Jid, HashMap<Jid, RemoteResource>>>,
    /// Avatar hashes for presence (XEP-0398), by account: None when the account has no public
    /// avatar to advertise.
    avatars: Mutex<Bounded<Jid, Option<String>>>,
}

impl Default for State {
    fn default() -> Self {
        State {
            caps: CapsCache::default(),
            local: Mutex::new(HashMap::new()),
            remote: Mutex::new(HashMap::new()),
            avatars: Mutex::new(Bounded::new(AVATAR_CACHE)),
        }
    }
}

/// Who changed a node: a client, or the server keeping two representations in step (which
/// must not trigger the reverse conversion).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    Client,
    Sync,
}

fn db_err(e: crate::db::DbError) -> StanzaError {
    tracing::warn!(error = %e, "pep: storage");
    StanzaError::internal()
}

#[async_trait]
impl Module for Pep {
    fn name(&self) -> &'static str {
        "pep"
    }

    fn migrations(&self) -> Vec<&'static Migration> {
        vec![&store::MIGRATION]
    }

    fn snapshot_names(&self, _host: &Host) -> Vec<&'static str> {
        vec!["pep", "bookmarks"]
    }

    // Older clients look for PEP on the server rather than the account.
    fn server_features(&self, _host: &Host) -> Vec<&'static str> {
        FEATURES.to_vec()
    }

    fn server_identities(&self, _host: &Host) -> Vec<Identity> {
        vec![Identity { category: "pubsub", kind: "pep", name: None }]
    }

    fn account_features(&self, _host: &Host) -> Vec<&'static str> {
        FEATURES.to_vec()
    }

    fn account_identities(&self, _host: &Host) -> Vec<Identity> {
        vec![Identity { category: "pubsub", kind: "pep", name: None }]
    }

    async fn account_items(&self, cx: &IqCtx<'_>) -> Vec<Element> {
        self.st.disco_items(cx).await
    }

    fn iq_namespaces(&self) -> &'static [(&'static str, IqTarget)] {
        &[
            (ns::PUBSUB, IqTarget::Account),
            (ns::PUBSUB_OWNER, IqTarget::Account),
            // No `to`: the sender's own PEP service.
            (ns::PUBSUB, IqTarget::Server),
            (ns::PUBSUB_OWNER, IqTarget::Server),
        ]
    }

    async fn handle_iq(&self, cx: &IqCtx<'_>) -> IqResult {
        self.st.handle_iq(cx).await
    }

    async fn stanza_out(&self, cx: &StanzaCtx<'_>, stanza: &mut Element) -> Flow {
        // Directed presence (group chat joins) carries the avatar hash too.
        if stanza.name() == "presence" && stanza.attr("type").is_none() {
            self.st.decorate(cx.srv, cx.from, stanza).await;
        }
        Flow::Continue
    }

    async fn stanza_in(&self, cx: &StanzaCtx<'_>, stanza: &mut Element) -> Flow {
        if stanza.name() == "presence" && !cx.srv.is_local(cx.from.domain()) {
            self.st.remote_presence(cx.srv, &cx.to.to_bare(), cx.from, stanza).await;
        }
        Flow::Continue
    }

    async fn presence_out(&self, srv: &Arc<Server>, session: &Arc<SessionHandle>, presence: &mut Element) {
        match presence.attr("type") {
            None => self.st.decorate(srv, &session.jid, presence).await,
            Some("unavailable") => {
                // Coming back later counts as coming online again (XEP-0163 §6.2).
                self.st.local.lock().remove(&session.jid);
            }
            _ => {}
        }
    }

    async fn on_event(&self, srv: &Arc<Server>, ev: &Event) {
        match ev {
            Event::Available { jid, presence } => {
                let (st, srv, jid, presence) = (self.st.clone(), srv.clone(), jid.clone(), presence.clone());
                // Off the presence path: this may wait on the client's disco#info answer.
                tokio::spawn(async move { st.local_available(&srv, jid, &presence).await });
            }
            Event::SessionEnded { jid } => {
                self.st.local.lock().remove(jid);
            }
            Event::SubscriptionApproved { user, contact } => {
                let (st, srv, user, contact) = (self.st.clone(), srv.clone(), user.clone(), contact.clone());
                tokio::spawn(async move { st.subscription_approved(&srv, &user, &contact).await });
            }
            Event::SubscriptionRevoked { user, contact } => {
                if let Some(m) = self.st.remote.lock().get_mut(user) {
                    m.retain(|j, _| j.to_bare() != *contact);
                }
            }
            Event::AccountDeleted { jid } => self.st.forget(jid),
            Event::VCardChanged { jid, vcard } => self.st.vcard_changed(srv, jid, vcard).await,
            Event::PrivateChanged { jid, data } => self.st.private_changed(srv, jid, data).await,
            _ => {}
        }
    }
}

impl State {
    /// Drops everything kept in memory for an account.
    fn forget(&self, bare: &Jid) {
        self.local.lock().retain(|j, _| j.to_bare() != *bare);
        self.remote.lock().remove(bare);
        self.avatars.lock().remove(bare);
    }
}
