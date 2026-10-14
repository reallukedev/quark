//! Who gets notifications (XEP-0163 §4.3): the owner's devices and contacts with a presence
//! subscription, each filtered by `+notify` in its caps, plus explicit subscribers. Also the
//! last items sent when someone comes online (§6.2) or is newly approved, and the caps lookups
//! behind all of it.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quark_core::{ns, Element, Jid};

use super::caps::{Caps, Lookup, Waiter, MAX_CAPS_FIELD};
use super::config::NodeConfig;
use super::iq::access;
use super::store::{self, Affiliation, Item, Owner};
use super::{State, CONTACT_TTL};
use crate::modules::roster;
use crate::server::Server;

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

/// `<event><items node><item/></items></event>` for a stored item, as notifications carry it.
pub(super) fn item_event(node: &str, cfg: &NodeConfig, it: &Item) -> Element {
    let item = it.shown(ns::PUBSUB_EVENT, cfg, cfg.deliver_payloads);
    Element::new("event", ns::PUBSUB_EVENT).child(Element::new("items", ns::PUBSUB_EVENT).attr_set("node", node).child(item))
}

/// A last item sent to someone coming online or subscribing, with when it was published.
fn last_item_message(o: &Owner, to: &Jid, node: &str, cfg: &NodeConfig, it: &Item) -> Element {
    let from = o.jid();
    let mut m = event_message(&from, to, cfg, item_event(node, cfg, it));
    m.append(quark_core::stanza::delay(&from.to_string(), it.updated));
    m
}

/// The node, ver and hash of a `<c/>`, when they're there and of a sane size.
fn caps_attrs(c: &Element) -> Option<(&str, &str, Option<&str>)> {
    let (node, ver) = (c.attr("node")?, c.attr("ver")?);
    let hash = c.attr("hash").filter(|h| h.len() <= 32);
    (node.len() <= MAX_CAPS_FIELD && ver.len() <= MAX_CAPS_FIELD).then_some((node, ver, hash))
}

impl State {
    /// The caps a local session was last known to have.
    pub(super) fn local_caps_of(&self, jid: &Jid) -> Option<Arc<Caps>> {
        self.local.lock().get(jid).cloned()
    }

    /// Everyone who should hear about a change to `node` right now (full JIDs, or the JIDs
    /// explicit subscribers gave).
    pub(super) async fn recipients(&self, srv: &Arc<Server>, o: &Owner, node: &str, cfg: &NodeConfig) -> Vec<Jid> {
        let owner = o.jid();
        let mut out: Vec<Jid> = Vec::new();
        for s in srv.sessions.available_of(&owner) {
            if self.local_caps_of(&s.jid).is_some_and(|c| c.wants(node)) {
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
                if self.local_caps_of(&s.jid).is_some_and(|caps| caps.wants(node)) {
                    out.push(s.jid.clone());
                }
            }
        }
        // Remote contacts: the resources whose presence reached the account.
        let remote = self.remote.lock().with_caps(&owner);
        for (j, caps) in remote {
            let bare = j.to_bare();
            if contacts.contains_key(&bare) && allowed(&bare) && caps.wants(node) {
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
            Ok(Some(it)) => srv.route(last_item_message(o, to, node, cfg, &it)).await,
            Ok(None) => {}
            Err(e) => tracing::warn!(error = %e, "pep: last item"),
        }
    }

    /// Sends `to` the last item of each of `nodes` at each of `owners` it may see (`viewer` is
    /// `to`'s bare JID). One trip to the database: per owner, one query for just those nodes
    /// and one roster lookup.
    async fn send_last_items(&self, srv: &Arc<Server>, owners: Vec<Owner>, viewer: &Jid, to: &Jid, nodes: Vec<String>) {
        if nodes.is_empty() || owners.is_empty() {
            return;
        }
        let v = viewer.clone();
        let found = srv
            .db
            .read(move |c| {
                let vs = v.to_string();
                let mut out = Vec::new();
                for o in owners {
                    let mut items = store::last_items(c, &o, &nodes, &vs)?;
                    items.retain(|(_, cfg, _, _)| cfg.send_last.on_presence() && cfg.deliver_notifications);
                    if items.is_empty() {
                        continue;
                    }
                    let contact = if o.jid() == v { None } else { roster::item_in(c, &o.host, &o.user, &v)? };
                    out.push((o, contact, items));
                }
                Ok(out)
            })
            .await;
        let found = match found {
            Ok(f) => f,
            Err(e) => return tracing::warn!(error = %e, "pep: last items"),
        };
        for (o, contact, items) in found {
            let is_owner = o.jid() == *viewer;
            for (n, cfg, aff, it) in items {
                if access(&cfg, is_owner, contact.as_ref(), aff).is_err() {
                    continue;
                }
                // Contacts only get presence-based delivery while they see the owner's presence.
                if !is_owner && aff.is_none() && !contact.as_ref().is_some_and(|c| c.subscription.sends_to_contact()) {
                    continue;
                }
                srv.route(last_item_message(&o, to, &n, &cfg, &it)).await;
            }
        }
    }

    /// A local client sent available presence (initial or update).
    pub(super) async fn local_available(self: &Arc<Self>, srv: &Arc<Server>, jid: Jid, presence: &Element) {
        let Some(c) = presence.get_child("c", ns::CAPS) else {
            // No caps: it gets no notifications, and its last items when caps show up.
            self.local.lock().remove(&jid);
            return;
        };
        let Some((node, ver, hash)) = caps_attrs(c) else { return };
        self.lookup_caps(srv, Waiter::Local(jid), node, ver, hash);
    }

    /// Finds the caps `waiter` presents: known ones are acted on, unknown ones asked about (or
    /// queued behind whoever asked already), and when too much is in flight, tried later.
    fn lookup_caps(self: &Arc<Self>, srv: &Arc<Server>, waiter: Waiter, node: &str, ver: &str, hash: Option<&str>) {
        match self.caps.lookup(node, ver, hash, waiter.clone()) {
            Lookup::Known(caps) => {
                let (st, srv, ver) = (self.clone(), srv.clone(), ver.to_string());
                // Off the presence path: this reads the database.
                tokio::spawn(async move { st.caps_known(&srv, waiter, &ver, caps).await });
            }
            Lookup::Ask(key) => self.ask(srv, key, waiter, node.to_string(), ver.to_string(), hash.map(str::to_string)),
            Lookup::Queued => {}
            Lookup::Busy => self.retry_later(srv, waiter),
        }
    }

    /// `waiter`'s caps for `ver` are known: if it still presents them, it's acted on.
    async fn caps_known(&self, srv: &Arc<Server>, waiter: Waiter, ver: &str, caps: Arc<Caps>) {
        self.caps.succeeded(&waiter);
        match waiter {
            Waiter::Local(j) => {
                let current = srv.sessions.get(&j).and_then(|s| s.presence.lock().caps.as_ref().map(|(_, v)| v.clone()));
                if current.as_deref() == Some(ver) {
                    self.local_caps(srv, &j, caps).await;
                }
            }
            Waiter::Remote { owner, entity } => self.remote_caps(srv, &owner, &entity, ver, caps).await,
        }
    }

    /// Looks `waiter` up again after a while, if it has tries left.
    fn retry_later(self: &Arc<Self>, srv: &Arc<Server>, waiter: Waiter) {
        let Some(wait) = self.caps.schedule_retry(&waiter) else { return };
        let (st, srv) = (self.clone(), srv.clone());
        tokio::spawn(async move {
            tokio::time::sleep(wait).await;
            st.caps.retry_due(&waiter);
            st.relookup(&srv, waiter);
        });
    }

    /// Looks up the caps `waiter` presents now, if it's still around.
    fn relookup(self: &Arc<Self>, srv: &Arc<Server>, waiter: Waiter) {
        let current = match &waiter {
            Waiter::Local(j) => {
                let Some(p) = srv.sessions.get(j).filter(|s| s.available()).and_then(|s| s.last_presence()) else { return };
                let Some((node, ver, hash)) = p.get_child("c", ns::CAPS).and_then(caps_attrs) else { return };
                (node.to_string(), ver.to_string(), hash.map(str::to_string))
            }
            Waiter::Remote { owner, entity } => {
                let all = self.remote.lock();
                let Some(r) = all.get(owner, entity) else { return };
                (r.node.clone(), r.ver.clone(), r.hash.clone())
            }
        };
        self.lookup_caps(srv, waiter, &current.0, &current.1, current.2.as_deref());
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

    /// Asks `first` for the disco#info behind its caps and hands the answer to everyone
    /// waiting. When it doesn't answer (or its answer only holds for itself), the next waiter
    /// on the same `ver` is asked, and whoever is left without caps tries again later.
    fn ask(self: &Arc<Self>, srv: &Arc<Server>, key: String, first: Waiter, node: String, ver: String, hash: Option<String>) {
        let (st, srv) = (self.clone(), srv.clone());
        tokio::spawn(async move {
            let (mut asked, mut node) = (first, node);
            loop {
                // A contact's client knows the account, not its server: remote ones are asked
                // from the account.
                let (from, to) = match &asked {
                    Waiter::Local(j) => (Jid::domain_jid(j.domain()).ok(), j.clone()),
                    Waiter::Remote { owner, entity } => (Some(owner.clone()), entity.clone()),
                };
                let query = Element::new("query", ns::DISCO_INFO).attr_set("node", format!("{node}#{ver}"));
                let iq = quark_core::stanza::iq("get", "", from.map(|f| f.to_string()).as_deref(), Some(&to.to_string()), query);
                let answer = match srv.request(iq, CAPS_TIMEOUT).await {
                    Ok(r) => r.get_child("query", ns::DISCO_INFO).cloned(),
                    Err(e) => {
                        tracing::debug!(jid = %to, error = %e, "pep: caps query failed");
                        None
                    }
                };
                let r = st.caps.resolve(&key, &to, &ver, hash.as_deref(), answer.as_ref());
                if let Some(caps) = &r.caps {
                    for w in r.done {
                        st.caps_known(&srv, w, &ver, caps.clone()).await;
                    }
                }
                for w in r.retry {
                    st.retry_later(&srv, w);
                }
                let Some((next, next_node)) = r.next else { break };
                (asked, node) = (next, next_node);
            }
        });
    }

    /// Whether `from` is on `owner`'s roster with a presence subscription either way, from a
    /// short-lived cache so a chatty contact's presence doesn't read the roster every time.
    async fn is_contact(&self, srv: &Arc<Server>, o: &Owner, owner: &Jid, from: &Jid) -> bool {
        let key = (owner.clone(), from.to_bare());
        if let Some((yes, at)) = self.contacts.lock().get(&key).copied() {
            if at.elapsed() < CONTACT_TTL {
                return yes;
            }
        }
        let yes = match roster::item(srv, &o.host, &o.user, from).await {
            Ok(it) => it.is_some_and(|i| i.subscription.receives_from_contact() || i.subscription.sends_to_contact()),
            Err(e) => {
                tracing::warn!(error = %e, "pep: roster for remote presence");
                return false;
            }
        };
        self.contacts.lock().put(key, (yes, Instant::now()));
        yes
    }

    /// Presence from another server's user to a local account: tracks which of the account's
    /// remote contacts are online, with what caps. Any contact whose presence the account gets
    /// is tracked, whichever way the subscription goes: notifications and last items check the
    /// roster themselves, and a contact the account approves later is then already known.
    pub(super) async fn remote_presence(self: &Arc<Self>, srv: &Arc<Server>, owner: &Jid, from: &Jid, p: &Element) {
        if from.resource().is_none() || owner.node().is_none() {
            return;
        }
        match p.attr("type") {
            None => {}
            Some("unavailable" | "error") => return self.remote.lock().remove(owner, from),
            Some(_) => return,
        }
        // Group chat occupants aren't contacts, whatever their caps.
        if p.has_child("x", ns::MUC_USER) {
            return;
        }
        let Some(c) = p.get_child("c", ns::CAPS) else { return self.remote.lock().remove(owner, from) };
        let Some((node, ver, hash)) = caps_attrs(c) else { return };
        let Some(o) = Owner::of(owner) else { return };
        if !self.is_contact(srv, &o, owner, from).await {
            return self.remote.lock().remove(owner, from);
        }
        if !self.remote.lock().update(owner, from, node, ver, hash) {
            return;
        }
        self.lookup_caps(srv, Waiter::Remote { owner: owner.clone(), entity: from.clone() }, node, ver, hash);
    }

    /// A remote resource's caps are known: last items for what it newly cares about.
    async fn remote_caps(&self, srv: &Arc<Server>, owner: &Jid, entity: &Jid, ver: &str, caps: Arc<Caps>) {
        let added: Vec<String> = {
            let mut all = self.remote.lock();
            let Some(r) = all.get_mut(owner, entity) else { return };
            if r.ver != ver {
                // It changed caps since; the newer presence takes care of it.
                return;
            }
            let prev = r.caps.replace(caps.clone());
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
                if let Some(c) = self.local_caps_of(&s.jid) {
                    targets.push((s.jid.clone(), c.nodes().map(String::from).collect()));
                }
            }
        } else {
            let remote = self.remote.lock().with_caps(user);
            for (j, c) in remote.into_iter().filter(|(j, _)| j.to_bare() == *contact) {
                targets.push((j, c.nodes().map(String::from).collect()));
            }
        }
        for (to, nodes) in targets {
            self.send_last_items(srv, vec![o.clone()], &contact.to_bare(), &to, nodes).await;
        }
    }
}
