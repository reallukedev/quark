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
use std::time::{Duration, Instant};

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
mod pie;
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
    /// The caps it presents (node, ver and hash), as sent.
    node: String,
    ver: String,
    hash: Option<String>,
    /// The caps it was last known to have: what its notifications are filtered by, and whose
    /// last items it already got. Kept here rather than looked up in the shared caches, which
    /// anyone can churn.
    caps: Option<Arc<Caps>>,
}

/// Remote resources online, per local account, with a running total so the global limit is
/// checked without walking every account.
#[derive(Default)]
struct Remote {
    by_owner: HashMap<Jid, HashMap<Jid, RemoteResource>>,
    total: usize,
}

impl Remote {
    /// Records the caps `from` presents to `owner`. False when it's new and there's no room.
    fn update(&mut self, owner: &Jid, from: &Jid, node: &str, ver: &str, hash: Option<&str>) -> bool {
        let (node, ver, hash) = (node.to_string(), ver.to_string(), hash.map(str::to_string));
        if let Some(r) = self.get_mut(owner, from) {
            (r.node, r.ver, r.hash) = (node, ver, hash);
            return true;
        }
        if self.total >= REMOTE_TOTAL || self.by_owner.get(owner).is_some_and(|m| m.len() >= REMOTE_PER_ACCOUNT) {
            return false;
        }
        self.by_owner.entry(owner.clone()).or_default().insert(from.clone(), RemoteResource { node, ver, hash, caps: None });
        self.total += 1;
        true
    }

    fn get(&self, owner: &Jid, from: &Jid) -> Option<&RemoteResource> {
        self.by_owner.get(owner)?.get(from)
    }

    fn get_mut(&mut self, owner: &Jid, from: &Jid) -> Option<&mut RemoteResource> {
        self.by_owner.get_mut(owner)?.get_mut(from)
    }

    /// The account's remote resources with known caps.
    fn with_caps(&self, owner: &Jid) -> Vec<(Jid, Arc<Caps>)> {
        let Some(m) = self.by_owner.get(owner) else { return Vec::new() };
        m.iter().filter_map(|(j, r)| Some((j.clone(), r.caps.clone()?))).collect()
    }

    fn remove(&mut self, owner: &Jid, from: &Jid) {
        let Some(m) = self.by_owner.get_mut(owner) else { return };
        if m.remove(from).is_some() {
            self.total -= 1;
        }
        if m.is_empty() {
            self.by_owner.remove(owner);
        }
    }

    fn remove_owner(&mut self, owner: &Jid) {
        if let Some(m) = self.by_owner.remove(owner) {
            self.total -= m.len();
        }
    }
}

/// Remote resources tracked per local account, and in all.
const REMOTE_PER_ACCOUNT: usize = 256;
const REMOTE_TOTAL: usize = 100_000;
const AVATAR_CACHE: usize = 8192;
/// Whether a remote JID is a contact of an account, remembered so presence from it doesn't
/// read the roster every time; briefly, as roster changes don't reach PEP.
const CONTACT_CACHE: usize = 16_384;
const CONTACT_TTL: Duration = Duration::from_secs(60);

/// What PEP keeps in memory; all of it can be rebuilt from presence and the database.
pub(crate) struct State {
    caps: CapsCache,
    /// Local sessions, by full JID: the caps they were last known to have (what notifications
    /// are filtered by, and whose last items they already got).
    local: Mutex<HashMap<Jid, Arc<Caps>>>,
    /// Remote contacts' resources online, per local account (bare JID).
    remote: Mutex<Remote>,
    /// (account, remote bare JID) → is it a contact, and since when that's known.
    contacts: Mutex<Bounded<(Jid, Jid), (bool, Instant)>>,
    /// Avatar hashes for presence (XEP-0398), by account: None when the account has no public
    /// avatar to advertise.
    avatars: Mutex<Bounded<Jid, Option<String>>>,
}

impl Default for State {
    fn default() -> Self {
        State {
            caps: CapsCache::default(),
            local: Mutex::new(HashMap::new()),
            remote: Mutex::new(Remote::default()),
            contacts: Mutex::new(Bounded::new(CONTACT_CACHE)),
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

    async fn export_account(&self, srv: &Arc<Server>, host: &Host, user: &str) -> Result<Vec<Element>, crate::db::DbError> {
        let o = store::Owner { host: host.domain.clone(), user: user.to_string() };
        srv.db.read(move |c| pie::export(c, &o)).await
    }

    async fn import_account(&self, srv: &Arc<Server>, host: &Host, user: &str, data: &Element) -> Result<Vec<String>, crate::db::DbError> {
        if !data.has_child("pubsub", ns::PUBSUB) && !data.has_child("pubsub", ns::PUBSUB_OWNER) {
            return Ok(Vec::new());
        }
        let (o, data) = (store::Owner { host: host.domain.clone(), user: user.to_string() }, data.clone());
        let notes = srv.db.write(move |t| pie::import(t, &o, &data)).await?;
        // The avatar hash for presence comes from the database again.
        self.st.avatars.lock().remove(&Jid::bare_unchecked(user, &host.domain));
        Ok(notes)
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
                self.st.contacts.lock().remove(&(user.clone(), contact.to_bare()));
                let (st, srv, user, contact) = (self.st.clone(), srv.clone(), user.clone(), contact.clone());
                tokio::spawn(async move { st.subscription_approved(&srv, &user, &contact).await });
            }
            // Its resources stay tracked while their presence still reaches the account: every
            // notification checks the roster, and a later approval needs to know them.
            Event::SubscriptionRevoked { user, contact } => {
                self.st.contacts.lock().remove(&(user.clone(), contact.to_bare()));
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
        self.remote.lock().remove_owner(bare);
        self.avatars.lock().remove(bare);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use sha1::Digest;

    fn j(s: &str) -> Jid {
        Jid::parse(s).unwrap()
    }

    #[test]
    fn remote_resources_keep_a_running_total() {
        let mut r = Remote::default();
        let (a, b) = (j("a@here"), j("b@here"));
        assert!(r.update(&a, &j("z@there/1"), "n", "v", None));
        assert!(r.update(&a, &j("z@there/1"), "n", "w", Some("sha-1")));
        assert!(r.update(&a, &j("z@there/2"), "n", "v", None));
        assert!(r.update(&b, &j("y@there/1"), "n", "v", None));
        assert_eq!(r.total, 3);
        assert_eq!(r.get(&a, &j("z@there/1")).map(|x| x.ver.as_str()), Some("w"));
        r.remove(&a, &j("z@there/1"));
        r.remove(&a, &j("z@there/1"));
        assert_eq!(r.total, 2);
        r.remove_owner(&a);
        assert_eq!(r.total, 1);
        for i in 0..REMOTE_PER_ACCOUNT {
            assert!(r.update(&a, &j(&format!("z@there/{i}")), "n", "v", None));
        }
        assert!(!r.update(&a, &j("z@there/more"), "n", "v", None));
        assert_eq!(r.total, 1 + REMOTE_PER_ACCOUNT);
    }

    /// Notifications go by the caps stored with each session, so someone flooding the shared
    /// caps cache with new `ver`s can't make others lose theirs.
    #[test]
    fn session_caps_outlive_the_shared_cache() {
        let st = State::default();
        let ver_of =
            |q: &Element| base64::engine::general_purpose::STANDARD.encode(sha1::Sha1::digest(caps::ver_string(q).unwrap().as_bytes()));
        let learn = |w: &caps::Waiter, q: &Element| {
            let ver = ver_of(q);
            if let caps::Lookup::Ask(key) = st.caps.lookup("n", &ver, Some("sha-1"), w.clone()) {
                st.caps.resolve(&key, w.entity(), &ver, Some("sha-1"), Some(q));
            }
        };
        let me = caps::Waiter::Local(j("a@here/phone"));
        let mine = Element::parse("<query xmlns='http://jabber.org/protocol/disco#info'><feature var='n+notify'/></query>").unwrap();
        learn(&me, &mine);
        let known = st.caps.get(me.entity(), &ver_of(&mine)).unwrap();
        st.local.lock().insert(me.entity().clone(), known);
        let eve = caps::Waiter::Local(j("eve@here/1"));
        for i in 0..5000 {
            learn(
                &eve,
                &Element::parse(&format!("<query xmlns='http://jabber.org/protocol/disco#info'><feature var='f{i}'/></query>")).unwrap(),
            );
        }
        assert!(st.caps.get(me.entity(), &ver_of(&mine)).is_none(), "the shared cache was churned");
        assert!(st.local_caps_of(me.entity()).is_some_and(|c| c.wants("n")));
    }
}
