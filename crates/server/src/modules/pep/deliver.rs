//! Who gets notifications (XEP-0163 §4.3): the owner's devices and contacts with a presence
//! subscription, each filtered by `+notify` in its caps, plus explicit subscribers. Also the
//! last items sent when someone comes online (§6.2) or is newly approved, and the caps lookups
//! behind all of it.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use quark_core::{ns, Element, Jid};

use super::caps::{Caps, Lookup, Waiter};
use super::config::NodeConfig;
use super::iq::access;
use super::store::{self, Affiliation, Item, Owner};
use super::{RemoteResource, State, REMOTE_PER_ACCOUNT, REMOTE_TOTAL};
use crate::modules::roster;
use crate::server::Server;
use crate::sessions::SessionHandle;

/// How long a client gets to answer the caps disco#info query.
const CAPS_TIMEOUT: Duration = Duration::from_secs(10);

fn event_message(from: &Jid, to: &Jid, cfg: &NodeConfig, event: Element) -> Element {
    Element::new("message", ns::CLIENT)
        .attr_set("from", from.to_string())
        .attr_set("to", to.to_string())
        .attr_set("type", cfg.notification_type.as_str())
        .attr_set("id", quark_core::new_id())
        .child(event)
}

/// `<event><items node><item/></items></event>` for a stored item, as sent when someone comes
/// online, with the time it was published.
fn last_item_event(node: &str, cfg: &NodeConfig, it: &Item) -> Element {
    let mut item = it.to_element(ns::PUBSUB_EVENT, cfg.deliver_payloads);
    if cfg.itemreply != super::config::ItemReply::Publisher {
        item.remove_attr("publisher");
    }
    Element::new("event", ns::PUBSUB_EVENT).child(Element::new("items", ns::PUBSUB_EVENT).attr_set("node", node).child(item))
}

impl State {
    /// The caps a local session presented, if they're known.
    fn session_caps(&self, s: &SessionHandle) -> Option<Arc<Caps>> {
        let ver = s.presence.lock().caps.as_ref().map(|(_, v)| v.clone())?;
        self.caps.get(&s.jid, &ver)
    }

    /// Everyone who should hear about a change to `node` right now (full JIDs, or the JIDs
    /// explicit subscribers gave).
    pub(super) async fn recipients(&self, srv: &Arc<Server>, o: &Owner, node: &str, cfg: &NodeConfig) -> Vec<Jid> {
        let owner = o.jid();
        let mut out: Vec<Jid> = Vec::new();
        for s in srv.sessions.available_of(&owner) {
            if self.session_caps(&s).is_some_and(|c| c.wants(node)) {
                out.push(s.jid.clone());
            }
        }
        let roster = match roster::items(srv, &o.host, &o.user).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "pep: roster for notifications");
                Vec::new()
            }
        };
        let (oo, n) = (o.clone(), node.to_string());
        let (affs, subs) =
            srv.db.read(move |c| Ok((store::affiliations(c, &oo, &n)?, store::subscribers(c, &oo, &n)?))).await.unwrap_or_else(|e| {
                tracing::warn!(error = %e, "pep: subscribers for notifications");
                (Vec::new(), Vec::new())
            });
        let affs: HashMap<String, Affiliation> = affs.into_iter().collect();
        let contacts: HashMap<&Jid, &roster::Item> =
            roster.iter().filter(|i| i.subscription.sends_to_contact()).map(|i| (&i.contact, i)).collect();
        let allowed = |bare: &Jid| {
            let it = contacts.get(bare).copied();
            access(cfg, *bare == owner, it, affs.get(&bare.to_string()).copied()).is_ok()
        };

        // Local contacts: their sessions' caps are right here.
        for c in contacts.keys().filter(|c| srv.host(c.domain()).is_some()) {
            if !allowed(c) {
                continue;
            }
            for s in srv.sessions.available_of(c) {
                if self.session_caps(&s).is_some_and(|caps| caps.wants(node)) {
                    out.push(s.jid.clone());
                }
            }
        }
        // Remote contacts: the resources whose presence reached the account.
        let remote: Vec<(Jid, String)> =
            self.remote.lock().get(&owner).map(|m| m.iter().map(|(j, r)| (j.clone(), r.ver.clone())).collect()).unwrap_or_default();
        for (j, ver) in remote {
            let bare = j.to_bare();
            if contacts.contains_key(&bare) && allowed(&bare) && self.caps.get(&j, &ver).is_some_and(|c| c.wants(node)) {
                out.push(j);
            }
        }
        // Explicit subscribers, whatever their caps say.
        let mut seen: HashSet<Jid> = out.iter().cloned().collect();
        for s in subs {
            let Ok(j) = Jid::parse(&s) else { continue };
            if allowed(&j.to_bare()) && seen.insert(j.clone()) {
                out.push(j);
            }
        }
        out
    }

    /// Sends `event` about `node` to everyone who should get it.
    pub(super) async fn notify(&self, srv: &Arc<Server>, o: &Owner, node: &str, cfg: &NodeConfig, event: Element) {
        let to = self.recipients(srv, o, node, cfg).await;
        self.send_event(srv, o, cfg, &event, to).await;
    }

    pub(super) async fn send_event(&self, srv: &Arc<Server>, o: &Owner, cfg: &NodeConfig, event: &Element, to: Vec<Jid>) {
        let from = o.jid();
        for j in to {
            srv.route(event_message(&from, &j, cfg, event.clone())).await;
        }
    }

    /// The node's last item to one subscriber.
    pub(super) async fn send_last_item(&self, srv: &Arc<Server>, o: &Owner, node: &str, cfg: &NodeConfig, to: &Jid) {
        let (oo, n) = (o.clone(), node.to_string());
        match srv.db.read(move |c| store::last_item(c, &oo, &n)).await {
            Ok(Some(it)) => {
                let mut m = event_message(&o.jid(), to, cfg, last_item_event(node, cfg, &it));
                m.append(quark_core::stanza::delay(&o.jid().to_string(), it.updated));
                srv.route(m).await;
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(error = %e, "pep: last item"),
        }
    }

    /// Sends `to` the last item of each of `nodes` at each of `owners` it may see (`viewer` is
    /// `to`'s bare JID).
    async fn send_last_items(&self, srv: &Arc<Server>, owners: Vec<Owner>, viewer: &Jid, to: &Jid, nodes: Vec<String>) {
        if nodes.is_empty() || owners.is_empty() {
            return;
        }
        let v = viewer.to_string();
        let found = srv
            .db
            .read(move |c| {
                let wanted: HashSet<&str> = nodes.iter().map(String::as_str).collect();
                let mut out = Vec::new();
                for o in owners {
                    for (n, cfg) in store::nodes(c, &o)? {
                        if !wanted.contains(n.as_str()) || !cfg.send_last.on_presence() || !cfg.deliver_notifications {
                            continue;
                        }
                        let Some(it) = store::last_item(c, &o, &n)? else { continue };
                        let aff = store::affiliation(c, &o, &n, &v)?;
                        out.push((o.clone(), n, cfg, aff, it));
                    }
                }
                Ok(out)
            })
            .await;
        let found = match found {
            Ok(f) => f,
            Err(e) => return tracing::warn!(error = %e, "pep: last items"),
        };
        // The owner's own roster decides, looked up once per owner that has something to send.
        let mut contacts: HashMap<Owner, Option<roster::Item>> = HashMap::new();
        for (o, n, cfg, aff, it) in found {
            let is_owner = o.jid() == *viewer;
            if !is_owner && !contacts.contains_key(&o) {
                let item = roster::item(srv, &o.host, &o.user, viewer).await.unwrap_or_default();
                contacts.insert(o.clone(), item);
            }
            let contact = contacts.get(&o).and_then(Option::as_ref);
            if access(&cfg, is_owner, contact, aff).is_err() {
                continue;
            }
            // Contacts only get presence-based delivery while they see the owner's presence.
            if !is_owner && aff.is_none() && !contact.is_some_and(|c| c.subscription.sends_to_contact()) {
                continue;
            }
            let mut m = event_message(&o.jid(), to, &cfg, last_item_event(&n, &cfg, &it));
            m.append(quark_core::stanza::delay(&o.jid().to_string(), it.updated));
            srv.route(m).await;
        }
    }

    /// A local client sent available presence (initial or update).
    pub(super) async fn local_available(self: &Arc<Self>, srv: &Arc<Server>, jid: Jid, presence: &Element) {
        let Some(c) = presence.get_child("c", ns::CAPS) else {
            // No caps: it gets no notifications, and its last items when caps show up.
            self.local.lock().remove(&jid);
            return;
        };
        let (Some(node), Some(ver)) = (c.attr("node"), c.attr("ver")) else { return };
        let hash = c.attr("hash");
        match self.caps.lookup(&jid, ver, hash, Waiter::Local(jid.clone())) {
            Lookup::Known(caps) => self.local_caps(srv, &jid, caps).await,
            Lookup::Ask(key) => {
                let from = Jid::domain_jid(jid.domain()).ok();
                self.ask(srv, key, from, jid.clone(), node, ver, hash).await;
            }
            Lookup::Queued | Lookup::Busy => {}
        }
    }

    /// A local session's caps are known: last items for the nodes it newly cares about.
    async fn local_caps(&self, srv: &Arc<Server>, jid: &Jid, caps: Arc<Caps>) {
        let added: Vec<String> = {
            let mut m = self.local.lock();
            let prev = m.insert(jid.clone(), caps.clone());
            caps.added_since(prev.as_deref()).into_iter().map(String::from).collect()
        };
        if added.is_empty() {
            return;
        }
        let bare = jid.to_bare();
        let Some(me) = Owner::of(&bare) else { return };
        // Its own account, and every local contact whose presence it sees.
        let mut owners = vec![me.clone()];
        match roster::items(srv, &me.host, &me.user).await {
            Ok(items) => owners.extend(
                items
                    .iter()
                    .filter(|i| i.subscription.receives_from_contact() && i.contact != bare && srv.host(i.contact.domain()).is_some())
                    .filter_map(|i| Owner::of(&i.contact)),
            ),
            Err(e) => tracing::warn!(error = %e, "pep: roster for last items"),
        }
        self.send_last_items(srv, owners, &bare, jid, added).await;
    }

    /// Asks `to` for the disco#info behind its caps and hands the answer to everyone waiting.
    #[allow(clippy::too_many_arguments)]
    async fn ask(self: &Arc<Self>, srv: &Arc<Server>, key: String, from: Option<Jid>, to: Jid, node: &str, ver: &str, hash: Option<&str>) {
        let (st, srv) = (self.clone(), srv.clone());
        let (ver, hash) = (ver.to_string(), hash.map(str::to_string));
        let query = Element::new("query", ns::DISCO_INFO).attr_set("node", format!("{node}#{ver}"));
        let iq = quark_core::stanza::iq("get", "", from.map(|f| f.to_string()).as_deref(), Some(&to.to_string()), query);
        tokio::spawn(async move {
            let answer = match srv.request(iq, CAPS_TIMEOUT).await {
                Ok(r) => r.get_child("query", ns::DISCO_INFO).cloned(),
                Err(e) => {
                    tracing::debug!(jid = %to, error = %e, "pep: caps query failed");
                    None
                }
            };
            let (caps, waiters) = st.caps.resolve(&key, &to, &ver, hash.as_deref(), answer.as_ref());
            for w in waiters {
                match w {
                    Waiter::Local(j) => {
                        // Only if it still presents the same caps.
                        let current = srv.sessions.get(&j).and_then(|s| s.presence.lock().caps.as_ref().map(|(_, v)| v.clone()));
                        if current.as_deref() == Some(ver.as_str()) {
                            st.local_caps(&srv, &j, caps.clone()).await;
                        }
                    }
                    Waiter::Remote { owner, entity } => st.remote_caps(&srv, &owner, &entity, &ver, caps.clone()).await,
                }
            }
        });
    }

    /// Presence from another server's user to a local account: tracks which of the account's
    /// remote contacts are online, with what caps.
    pub(super) async fn remote_presence(self: &Arc<Self>, srv: &Arc<Server>, owner: &Jid, from: &Jid, p: &Element) {
        if from.resource().is_none() || owner.node().is_none() {
            return;
        }
        match p.attr("type") {
            None => {}
            Some("unavailable" | "error") => return self.drop_remote(owner, from),
            Some(_) => return,
        }
        // Group chat occupants aren't contacts, whatever their caps.
        if p.has_child("x", ns::MUC_USER) {
            return;
        }
        let Some(c) = p.get_child("c", ns::CAPS) else { return self.drop_remote(owner, from) };
        let (Some(node), Some(ver)) = (c.attr("node"), c.attr("ver")) else { return };
        let hash = c.attr("hash");
        let Some(o) = Owner::of(owner) else { return };
        // Only contacts who see the account's presence get its notifications.
        match roster::item(srv, &o.host, &o.user, from).await {
            Ok(Some(it)) if it.subscription.sends_to_contact() => {}
            _ => return self.drop_remote(owner, from),
        }
        {
            let mut all = self.remote.lock();
            let total: usize = all.values().map(HashMap::len).sum();
            let m = all.entry(owner.clone()).or_default();
            let room = m.len() < REMOTE_PER_ACCOUNT && total < REMOTE_TOTAL;
            match m.get_mut(from) {
                Some(r) if r.ver == ver => {}
                Some(r) => r.ver = ver.to_string(),
                None if room => {
                    m.insert(from.clone(), RemoteResource { ver: ver.to_string(), acted: None });
                }
                None => return,
            }
        }
        match self.caps.lookup(from, ver, hash, Waiter::Remote { owner: owner.clone(), entity: from.clone() }) {
            Lookup::Known(caps) => {
                let (st, srv, owner, from, ver) = (self.clone(), srv.clone(), owner.clone(), from.clone(), ver.to_string());
                tokio::spawn(async move { st.remote_caps(&srv, &owner, &from, &ver, caps).await });
            }
            // Asked from the account: their client knows it as a contact, not the server.
            Lookup::Ask(key) => self.ask(srv, key, Some(owner.clone()), from.clone(), node, ver, hash).await,
            Lookup::Queued | Lookup::Busy => {}
        }
    }

    fn drop_remote(&self, owner: &Jid, from: &Jid) {
        let mut all = self.remote.lock();
        if let Some(m) = all.get_mut(owner) {
            m.remove(from);
            if m.is_empty() {
                all.remove(owner);
            }
        }
    }

    /// A remote resource's caps are known: last items for what it newly cares about.
    async fn remote_caps(&self, srv: &Arc<Server>, owner: &Jid, entity: &Jid, ver: &str, caps: Arc<Caps>) {
        let added: Vec<String> = {
            let mut all = self.remote.lock();
            let Some(r) = all.get_mut(owner).and_then(|m| m.get_mut(entity)) else { return };
            if r.ver != ver {
                // It changed caps since; the newer presence takes care of it.
                return;
            }
            let prev = r.acted.replace(caps.clone());
            caps.added_since(prev.as_deref()).into_iter().map(String::from).collect()
        };
        let Some(o) = Owner::of(owner) else { return };
        self.send_last_items(srv, vec![o], &entity.to_bare(), entity, added).await;
    }

    /// `contact` was just allowed to see `user`'s presence: it gets `user`'s last items.
    pub(super) async fn subscription_approved(&self, srv: &Arc<Server>, user: &Jid, contact: &Jid) {
        let Some(o) = Owner::of(user) else { return };
        let mut targets: Vec<(Jid, Vec<String>)> = Vec::new();
        if srv.host(contact.domain()).is_some() {
            for s in srv.sessions.available_of(contact) {
                if let Some(c) = self.session_caps(&s) {
                    targets.push((s.jid.clone(), c.nodes().map(String::from).collect()));
                }
            }
        } else {
            let remote: Vec<(Jid, String)> = self
                .remote
                .lock()
                .get(user)
                .map(|m| m.iter().filter(|(j, _)| j.to_bare() == *contact).map(|(j, r)| (j.clone(), r.ver.clone())).collect())
                .unwrap_or_default();
            for (j, ver) in remote {
                if let Some(c) = self.caps.get(&j, &ver) {
                    targets.push((j, c.nodes().map(String::from).collect()));
                }
            }
        }
        for (to, nodes) in targets {
            self.send_last_items(srv, vec![o.clone()], &contact.to_bare(), &to, nodes).await;
        }
    }
}
