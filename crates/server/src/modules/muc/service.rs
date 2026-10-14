//! The group chat service on `groups.host`: finds (or loads, or makes) the room a stanza is
//! for, lets the room handle it under the room's lock, then delivers, saves and archives what
//! came out.
//!
//! Delivery to people on this server goes straight to their sessions: one clone per device,
//! no routing or database work per recipient, so a message to a big room costs little more
//! than serializing it for each device. Everything the room sends under its lock is
//! synchronous, which keeps every occupant's view in order and means a reply that loops back
//! into the room can't deadlock it.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use quark_core::stanza::{error_reply, iq_result, iq_type, IqType};
use quark_core::{ns, Condition, Element, Jid, StanzaError};
use tokio::sync::OwnedMutexGuard;

use super::config::{AllowPm, Config, ROOMINFO};
use super::room::{Affiliation, Join, Out, Prepared, Role, Room, FASTEN, MSG_MODERATE_0, MSG_MODERATE_1};
use super::store;
use crate::modules::forms::{self as form, Form, Values};
use crate::modules::{mam, Component, Flow, IqReply, StanzaCtx};
use crate::server::{Dest, Server};

pub const MUC_UNIQUE: &str = "http://jabber.org/protocol/muc#unique";
const MUC_REQUEST: &str = "http://jabber.org/protocol/muc#request";
const MUC_REGISTER: &str = "http://jabber.org/protocol/muc#register";

/// Rooms one person (not an admin) can have created on a service.
const MAX_ROOMS_PER_CREATOR: usize = 100;
/// Temporary rooms a service holds in memory at once.
const MAX_TEMPORARY_ROOMS: usize = 10_000;
/// A new room nobody finished setting up is removed after this.
pub const LOCK_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// An empty persistent room leaves memory after this (it's read back when needed).
pub const IDLE_UNLOAD: Duration = Duration::from_secs(10 * 60);
const MAX_VCARD_BYTES: usize = 192 * 1024;
const MAX_LISTED: usize = 1000;

/// What listings need, kept outside the room's lock so they never wait on it.
#[derive(Debug, Clone, Default)]
pub struct Summary {
    pub name: Option<String>,
    pub description: Option<String>,
    pub public: bool,
    pub members_only: bool,
    pub persistent: bool,
    pub locked: bool,
    pub occupants: usize,
    pub creator: Option<String>,
}

impl Summary {
    fn of(r: &Room) -> Summary {
        Summary {
            name: r.config.name.clone(),
            description: r.config.description.clone(),
            public: r.config.public,
            members_only: r.config.members_only,
            persistent: r.config.persistent,
            locked: r.locked_since.is_some(),
            occupants: r.occupant_count(),
            creator: r.creator.as_ref().map(Jid::to_string),
        }
    }

    /// What a persistent room looks like while it's only in storage.
    fn stored(r: &Room) -> Summary {
        Summary { locked: false, occupants: 0, ..Summary::of(r) }
    }

    fn from_config(json: &str) -> Summary {
        let c: Config = serde_json::from_str(json).unwrap_or_default();
        Summary {
            name: c.name,
            description: c.description,
            public: c.public,
            members_only: c.members_only,
            persistent: true,
            locked: false,
            occupants: 0,
            creator: None,
        }
    }
}

/// Rooms `creator` has made: those in storage plus the temporary ones in memory (persistent
/// rooms in memory are in storage too, so they're counted once).
fn rooms_created_by<'a>(in_memory: impl IntoIterator<Item = &'a Summary>, creator: &str, stored: usize) -> usize {
    stored + in_memory.into_iter().filter(|s| !s.persistent && s.creator.as_deref() == Some(creator)).count()
}

pub struct RoomCell {
    pub node: String,
    pub jid: Jid,
    pub state: Arc<tokio::sync::Mutex<Room>>,
    pub summary: Mutex<Summary>,
}

impl RoomCell {
    fn new(room: Room) -> Arc<RoomCell> {
        let summary = Summary::of(&room);
        Arc::new(RoomCell {
            node: room.jid.node().unwrap_or_default().to_string(),
            jid: room.jid.clone(),
            summary: Mutex::new(summary),
            state: Arc::new(tokio::sync::Mutex::new(room)),
        })
    }
}

pub struct Service {
    pub domain: String,
    pub jid: Jid,
    /// The domain whose accounts, admins and settings this service belongs to.
    pub host: String,
    rooms: RwLock<HashMap<String, Arc<RoomCell>>>,
    /// Every persistent room as stored, read from the database once and kept up to date as
    /// rooms are saved, so listing rooms (anyone may ask for the public ones) never reads or
    /// parses every room's configuration again. None until first needed.
    index: tokio::sync::Mutex<Option<BTreeMap<String, Summary>>>,
}

fn err(c: Condition, text: &str) -> StanzaError {
    StanzaError::new(c).with_text(text)
}

fn no_room(jid: &str) -> StanzaError {
    err(Condition::ItemNotFound, &format!("There's no group chat called {jid}."))
}

impl Service {
    pub fn new(domain: &str, jid: Jid, host: &str) -> Service {
        Service {
            domain: domain.to_string(),
            jid,
            host: host.to_string(),
            rooms: RwLock::new(HashMap::new()),
            index: tokio::sync::Mutex::new(None),
        }
    }

    /// Runs `f` on the index of stored rooms, reading it first if this is the first time.
    async fn with_index<T>(&self, srv: &Arc<Server>, f: impl FnOnce(&BTreeMap<String, Summary>) -> T) -> T {
        let mut idx = self.index.lock().await;
        if idx.is_none() {
            match store::list(&srv.db, &self.domain).await {
                Ok(rows) => *idx = Some(rows.into_iter().map(|(node, json)| (node, Summary::from_config(&json))).collect()),
                Err(e) => {
                    tracing::warn!(error = %e, "couldn't list group chats");
                    return f(&BTreeMap::new());
                }
            }
        }
        f(idx.as_ref().unwrap_or(&BTreeMap::new()))
    }

    /// A room was saved: `Some` with how it's stored now, `None` when it's no longer stored.
    async fn index_update(&self, node: &str, stored: Option<Summary>) {
        // Not read yet: the first read will find the change in the database.
        let mut idx = self.index.lock().await;
        let Some(idx) = idx.as_mut() else { return };
        match stored {
            Some(s) => idx.insert(node.to_string(), s),
            None => idx.remove(node),
        };
    }

    pub fn cells(&self) -> Vec<Arc<RoomCell>> {
        self.rooms.read().values().cloned().collect()
    }

    fn is_admin(&self, srv: &Arc<Server>, j: &Jid) -> bool {
        srv.host(&self.host).is_some_and(|h| h.is_admin_jid(j))
    }

    fn history_on(&self, srv: &Arc<Server>) -> bool {
        srv.host(&self.host).is_some_and(|h| h.settings().history.on())
    }

    /// The room for `node`, loading a persistent one from storage when it isn't in memory.
    pub async fn lookup(&self, srv: &Arc<Server>, node: &str) -> Result<Option<Arc<RoomCell>>, StanzaError> {
        if let Some(c) = self.rooms.read().get(node) {
            return Ok(Some(c.clone()));
        }
        let snap = store::load(&srv.db, &self.domain, node).await.map_err(|e| {
            tracing::warn!(error = %e, room = node, "couldn't load a group chat");
            StanzaError::internal()
        })?;
        let Some(snap) = snap else { return Ok(None) };
        let jid = Jid::from_parts(Some(node), &self.domain, None).map_err(|_| StanzaError::internal())?;
        let cell = RoomCell::new(Room::from_snapshot(jid, snap));
        Ok(Some(self.rooms.write().entry(node.to_string()).or_insert(cell).clone()))
    }

    /// Locks a room that's still live (it may have closed while we waited for it).
    async fn open(&self, srv: &Arc<Server>, node: &str) -> Result<Option<(Arc<RoomCell>, OwnedMutexGuard<Room>)>, StanzaError> {
        for _ in 0..3 {
            let Some(cell) = self.lookup(srv, node).await? else { return Ok(None) };
            let mut guard = cell.state.clone().lock_owned().await;
            if !guard.destroyed {
                guard.logging = guard.config.archive && self.history_on(srv);
                return Ok(Some((cell, guard)));
            }
            drop(guard);
            self.forget(&cell);
        }
        Ok(None)
    }

    fn forget(&self, cell: &Arc<RoomCell>) {
        let mut m = self.rooms.write();
        if m.get(&cell.node).is_some_and(|c| Arc::ptr_eq(c, cell)) {
            m.remove(&cell.node);
        }
    }

    /// Delivers what a room says to the people in it: straight to local sessions, through s2s
    /// for others. Returns the local devices that turned out to be gone.
    ///
    /// The shortcut to local sessions keeps what the normal path would do for room traffic:
    /// nothing reaches someone who blocked the room or the occupant it's from (XEP-0191), and
    /// messages for a device that's asleep (its connection waiting to be resumed, or its app in
    /// the background) go through the message hooks, so push can wake the phone. Messages to a
    /// person rather than to the room's occupants (private messages, invitations) aren't sent
    /// this way at all but routed (see [`Out::route`]).
    async fn deliver(&self, srv: &Arc<Server>, stanzas: Vec<Element>) -> Vec<Jid> {
        let mut gone = Vec::new();
        // Most of a batch comes from one occupant: parse its address once.
        let mut last_from: Option<(String, Jid)> = None;
        for mut el in stanzas {
            let Some(to) = el.attr("to").and_then(|t| Jid::parse(t).ok()) else { continue };
            match srv.resolve(to.domain()) {
                Dest::Local(host) if to.is_full() => {
                    let Some(s) = srv.sessions.get(&to) else {
                        gone.push(to);
                        continue;
                    };
                    let Some(f) = el.attr("from") else { continue };
                    if last_from.as_ref().is_none_or(|(raw, _)| raw != f) {
                        let Ok(j) = Jid::parse(f) else { continue };
                        last_from = Some((f.to_string(), j));
                    }
                    let Some((_, from)) = &last_from else { continue };
                    if crate::modules::blocking::is_blocked(srv, &to.to_bare(), from).await {
                        continue;
                    }
                    let asleep = el.name() == "message" && {
                        let f = s.flags.lock();
                        f.hibernating || f.inactive
                    };
                    if asleep && !self.message_hooks(srv, &host, from, &to, &mut el).await {
                        continue;
                    }
                    s.send(el);
                }
                // To an account (a relayed vCard request) or another component: through the
                // router, off this task, since the answer may come back to this very room.
                Dest::Local(_) | Dest::Component(_) => {
                    let srv = srv.clone();
                    tokio::spawn(async move { srv.route(el).await });
                }
                Dest::Remote => self.send_remote(srv, &to, el),
            }
        }
        gone
    }

    /// Runs the message hooks (archive, push) for room traffic to a local device, as the router
    /// would. False when a hook took the message.
    async fn message_hooks(&self, srv: &Arc<Server>, host: &Arc<crate::server::Host>, from: &Jid, to: &Jid, el: &mut Element) -> bool {
        let cx = StanzaCtx { srv, host, from, to, session: None };
        for m in &srv.modules {
            if !matches!(m.message_in(&cx, el).await, Flow::Continue) {
                return false;
            }
        }
        true
    }

    /// Sends an answer to whoever asked (they asked, so no block list or push applies).
    fn reply(&self, srv: &Arc<Server>, el: Element) {
        let Some(to) = el.attr("to").and_then(|t| Jid::parse(t).ok()) else { return };
        match srv.resolve(to.domain()) {
            Dest::Local(_) if to.is_full() => {
                if let Some(s) = srv.sessions.get(&to) {
                    s.send(el);
                }
            }
            Dest::Local(_) | Dest::Component(_) => {
                let srv = srv.clone();
                tokio::spawn(async move { srv.route(el).await });
            }
            Dest::Remote => self.send_remote(srv, &to, el),
        }
    }

    fn send_remote(&self, srv: &Arc<Server>, to: &Jid, el: Element) {
        let allowed =
            srv.host(&self.host).is_some_and(|h| h.settings().federation) && !srv.config().s2s.blocked.iter().any(|b| b == to.domain());
        if let (true, Some(r)) = (allowed, srv.remote()) {
            r.send(&self.domain, to.domain(), el);
        }
    }

    /// Delivers, saves and cleans up after a room handled something. The room stays locked
    /// until everything it said has been queued, so occupants see things in order.
    async fn finish(&self, srv: &Arc<Server>, cell: &Arc<RoomCell>, mut room: OwnedMutexGuard<Room>, mut out: Out) {
        // Devices that vanished without saying goodbye leave (status 333), a few rounds at most.
        for _ in 0..3 {
            let gone = self.deliver(srv, std::mem::take(&mut out.send)).await;
            if gone.is_empty() {
                break;
            }
            for g in gone {
                room.leave(&g, None, &[333], &mut out);
            }
        }
        self.deliver(srv, std::mem::take(&mut out.send)).await;
        let ops = std::mem::take(&mut out.db);
        if !ops.is_empty() {
            let deleted = ops.iter().any(|o| matches!(o, store::Op::Delete));
            match store::apply(&srv.db, &self.domain, &cell.node, ops).await {
                Ok(()) => {
                    let keep = (room.config.persistent && !deleted).then(|| Summary::stored(&room));
                    self.index_update(&cell.node, keep).await;
                }
                Err(e) => tracing::warn!(error = %e, room = %cell.jid, "couldn't save a group chat"),
            }
        }
        room.logging = room.config.archive && self.history_on(srv);
        *cell.summary.lock() = Summary::of(&room);
        if out.closed {
            room.destroyed = true;
            self.forget(cell);
        }
        drop(room);
        if out.delete_archive {
            if let Err(e) = mam::delete_archive(srv, &cell.jid).await {
                tracing::debug!(error = %e, room = %cell.jid, "couldn't delete a group chat archive");
            }
        }
        for el in out.route {
            srv.route(el).await;
        }
    }

    fn reply_error(&self, srv: &Arc<Server>, el: &Element, e: StanzaError) {
        if let Some(mut r) = error_reply(el, &e) {
            if el.name() == "presence" {
                r.prepend(Element::new("x", ns::MUC));
            }
            self.reply(srv, r);
        }
    }

    // ---------------------------------------------------------------- the service itself

    async fn handle_service(&self, srv: &Arc<Server>, el: Element) {
        match el.name() {
            "iq" => {}
            "message" if el.attr("type") != Some("error") => {
                return self.reply_error(srv, &el, err(Condition::ServiceUnavailable, "Send messages to a group chat, not to the service."))
            }
            _ => return,
        }
        let Some(kind) = iq_type(&el) else { return self.reply_error(srv, &el, StanzaError::bad_request()) };
        if matches!(kind, IqType::Result | IqType::Error) {
            return;
        }
        let Some(p) = el.first_child() else { return self.reply_error(srv, &el, StanzaError::bad_request()) };
        let payload = match (kind, p.ns()) {
            (IqType::Get, ns::DISCO_INFO) if p.attr("node").is_none() => {
                let mut q = Element::new("query", ns::DISCO_INFO).child(
                    Element::new("identity", ns::DISCO_INFO)
                        .attr_set("category", "conference")
                        .attr_set("type", "text")
                        .attr_set("name", "Group chats"),
                );
                for f in [ns::DISCO_INFO, ns::DISCO_ITEMS, ns::MUC, MUC_UNIQUE, ns::PING, ns::MUC_STABLE_ID, ns::OCCUPANT_ID] {
                    q.append(Element::new("feature", ns::DISCO_INFO).attr_set("var", f));
                }
                Some(q)
            }
            (IqType::Get, ns::DISCO_ITEMS) if p.attr("node").is_none() => Some(self.public_items(srv).await),
            (IqType::Get, ns::PING) => None,
            (IqType::Get, MUC_UNIQUE) => Some(Element::new("unique", MUC_UNIQUE).text(quark_core::new_id())),
            (_, ns::DISCO_INFO | ns::DISCO_ITEMS) => return self.reply_error(srv, &el, StanzaError::item_not_found()),
            _ => return self.reply_error(srv, &el, StanzaError::service_unavailable()),
        };
        let mut r = iq_result(&el);
        if let Some(p) = payload {
            r.append(p);
        }
        self.reply(srv, r);
    }

    /// Every room on the service, from memory and storage: (node, summary).
    pub async fn all_rooms(&self, srv: &Arc<Server>) -> Vec<(String, Summary)> {
        self.rooms_where(srv, usize::MAX, |_| true).await
    }

    /// Rooms whose summary passes `keep`, by name, at most `max`: live ones from memory, the
    /// rest from the index.
    async fn rooms_where(&self, srv: &Arc<Server>, max: usize, keep: impl Fn(&Summary) -> bool) -> Vec<(String, Summary)> {
        let live: BTreeMap<String, Summary> = self.cells().into_iter().map(|c| (c.node.clone(), c.summary.lock().clone())).collect();
        self.with_index(srv, |stored| {
            let rest = stored.iter().filter(|(n, s)| !live.contains_key(*n) && keep(s));
            let mut v: Vec<(String, Summary)> =
                live.iter().filter(|(_, s)| keep(s)).chain(rest).map(|(n, s)| (n.clone(), s.clone())).collect();
            v.sort_by(|a, b| a.0.cmp(&b.0));
            v.truncate(max);
            v
        })
        .await
    }

    async fn public_items(&self, srv: &Arc<Server>) -> Element {
        let rooms = self.rooms_where(srv, MAX_LISTED, |s| s.public && !s.locked).await;
        let items = rooms.into_iter().map(|(node, s)| {
            Element::new("item", ns::DISCO_ITEMS).attr_set("jid", format!("{node}@{}", self.domain)).attr_opt("name", s.name)
        });
        Element::new("query", ns::DISCO_ITEMS).children_from(items)
    }

    // ---------------------------------------------------------------- rooms

    async fn may_create(&self, srv: &Arc<Server>, from: &Jid) -> Result<(), StanzaError> {
        let host = srv.host(&self.host).ok_or_else(StanzaError::service_unavailable)?;
        let bare = from.to_bare();
        if host.is_admin_jid(from) {
            return Ok(());
        }
        if host.settings().groups.who_creates == crate::settings::WhoCreates::Admins {
            return Err(err(Condition::NotAllowed, "Only admins can create group chats here."));
        }
        if from.domain() != host.domain || from.node().is_none() {
            return Err(err(
                Condition::NotAllowed,
                &format!("Only people with an account on {} can create group chats here.", host.domain),
            ));
        }
        let creator = bare.to_string();
        let stored = store::count_created_by(&srv.db, &self.domain, &creator).await.map_err(|_| StanzaError::internal())?;
        let summaries: Vec<Summary> = self.cells().iter().map(|c| c.summary.lock().clone()).collect();
        if rooms_created_by(&summaries, &creator, stored) >= MAX_ROOMS_PER_CREATOR {
            return Err(err(Condition::ResourceConstraint, "You've created as many group chats as you can; remove one first."));
        }
        if self.rooms.read().len() >= MAX_TEMPORARY_ROOMS {
            return Err(err(Condition::ResourceConstraint, "There are too many group chats right now; try again later."));
        }
        Ok(())
    }

    /// A presence for a room that doesn't exist yet: make it (locked until its owner configures
    /// it, unless the client is too old to know how, §10.1).
    async fn create(&self, srv: &Arc<Server>, from: &Jid, node: &str, el: &Element) -> Result<(Arc<RoomCell>, bool), StanzaError> {
        self.may_create(srv, from).await?;
        let jid = Jid::from_parts(Some(node), &self.domain, None).map_err(|_| StanzaError::new(Condition::JidMalformed))?;
        let bare = from.to_bare();
        let mut room = Room::new(jid, Config::default(), Some(bare.clone()), quark_core::time::now_ms());
        room.affiliations
            .insert(bare, super::room::AffEntry { affiliation: Affiliation::Owner, reason: None, nick: None, last_nick: None });
        if el.has_child("x", ns::MUC) {
            room.locked_since = Some(std::time::Instant::now());
        }
        let cell = RoomCell::new(room);
        let mut m = self.rooms.write();
        match m.get(node) {
            Some(existing) => Ok((existing.clone(), false)),
            None => {
                m.insert(node.to_string(), cell.clone());
                Ok((cell, true))
            }
        }
    }

    async fn handle_room(&self, srv: &Arc<Server>, from: &Jid, to: &Jid, node: &str, el: Element) {
        let kind = el.attr("type").map(str::to_string);
        let nick = to.resource().map(str::to_string);
        if el.name() == "presence" && kind.is_none() && nick.is_none() {
            return self.reply_error(srv, &el, err(Condition::JidMalformed, "Say which nickname to join with."));
        }
        let opened = match self.open(srv, node).await {
            Ok(o) => o,
            Err(e) => return self.reply_error(srv, &el, e),
        };
        let (cell, room, created) = match opened {
            Some((c, r)) => (c, r, false),
            None => {
                let joining = el.name() == "presence" && kind.is_none() && nick.is_some();
                if !joining {
                    if el.name() != "presence" {
                        self.reply_error(srv, &el, no_room(&to.to_bare().to_string()));
                    }
                    return;
                }
                let (cell, created) = match self.create(srv, from, node, &el).await {
                    Ok(c) => c,
                    Err(e) => return self.reply_error(srv, &el, e),
                };
                let mut guard = cell.state.clone().lock_owned().await;
                if guard.destroyed {
                    return self.reply_error(srv, &el, no_room(&to.to_bare().to_string()));
                }
                guard.logging = guard.config.archive && self.history_on(srv);
                (cell, guard, created)
            }
        };
        let admin = self.is_admin(srv, from);
        let out = Out::default();
        match el.name() {
            "presence" => self.room_presence(from, nick.as_deref(), kind.as_deref(), admin, created, room, &cell, srv, el, out).await,
            "message" => self.room_message(srv, &cell, room, from, nick.as_deref(), kind.as_deref(), admin, el, out).await,
            "iq" => self.room_iq(srv, &cell, room, from, nick.as_deref(), admin, el, out).await,
            _ => {}
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn room_presence(
        &self,
        from: &Jid,
        nick: Option<&str>,
        kind: Option<&str>,
        admin: bool,
        created: bool,
        mut room: OwnedMutexGuard<Room>,
        cell: &Arc<RoomCell>,
        srv: &Arc<Server>,
        el: Element,
        mut out: Out,
    ) {
        match kind {
            None => {
                let Some(nick) = nick else {
                    self.reply_error(srv, &el, err(Condition::JidMalformed, "Say which nickname to join with."));
                    return self.finish(srv, cell, room, out).await;
                };
                let r = if room.occupant_of(from).is_some() {
                    room.presence_from_occupant(from, nick, &el, quark_core::time::now_ms(), &mut out)
                } else {
                    room.join(Join { from, nick, presence: &el, admin, created, now: quark_core::time::now_ms() }, &mut out)
                };
                if let Err(e) = r {
                    self.reply_error(srv, &el, e);
                    if created {
                        // Nobody got in: don't leave an empty room behind.
                        room.destroyed = true;
                        out.closed = true;
                    }
                }
            }
            Some("unavailable") => room.leave(from, Some(&el), &[], &mut out),
            Some("error") => room.leave(from, None, &[333], &mut out),
            _ => {}
        }
        self.finish(srv, cell, room, out).await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn room_message(
        &self,
        srv: &Arc<Server>,
        cell: &Arc<RoomCell>,
        mut room: OwnedMutexGuard<Room>,
        from: &Jid,
        nick: Option<&str>,
        kind: Option<&str>,
        admin: bool,
        el: Element,
        mut out: Out,
    ) {
        if room.locked_since.is_some() && room.aff(&from.to_bare(), admin) != Affiliation::Owner {
            if kind != Some("error") {
                self.reply_error(srv, &el, no_room(&cell.jid.to_string()));
            }
            return self.finish(srv, cell, room, out).await;
        }
        let r: Result<(), StanzaError> = match (nick, kind) {
            (None, Some("groupchat")) => match room.prepare_message(from, &el) {
                Ok(Some(p)) => {
                    self.publish(srv, &mut room, p, &mut out).await;
                    Ok(())
                }
                Ok(None) => Ok(()),
                Err(e) => Err(e),
            },
            (_, Some("error")) => {
                // A device whose server bounces what the room sends it isn't really there (§7.2.?).
                // Devices on this server are known to be there or not, and their errors can
                // mean something else (a private message to someone who blocked its sender).
                if nick.is_some()
                    && srv.host(from.domain()).is_none()
                    && room.occupant_of(from).is_some()
                    && el.get_child("error", ns::CLIENT).and_then(|e| e.attr("type")) == Some("cancel")
                {
                    room.leave(from, None, &[333], &mut out);
                }
                Ok(())
            }
            (None, _) => self.room_normal_message(&mut room, from, admin, &el, &mut out),
            (Some(_), Some("groupchat")) => Err(err(Condition::BadRequest, "Group chat messages go to the room, not to one person.")),
            (Some(n), _) => room.private_message(from, n, &el, &mut out),
        };
        if let Err(e) = r {
            self.reply_error(srv, &el, e);
        }
        self.finish(srv, cell, room, out).await;
    }

    /// Invitations, declines and voice requests: non-groupchat messages to the room itself.
    fn room_normal_message(&self, room: &mut Room, from: &Jid, admin: bool, el: &Element, out: &mut Out) -> Result<(), StanzaError> {
        if let Some(x) = el.get_child("x", ns::MUC_USER) {
            return room.invitations(from, admin, x, out);
        }
        if let Some(x) = form::find(el) {
            let v = Values::parse(x);
            if v.form_type() == Some(MUC_REQUEST) {
                if v.has("muc#request_allow") && v.has("muc#roomnick") && room.role_of(from) == Role::Moderator {
                    if v.boolean("muc#request_allow").ok().flatten() == Some(true) {
                        let nick = v.get("muc#roomnick").unwrap_or_default().to_string();
                        return room.voice_approval(from, admin, &nick, out);
                    }
                    return Ok(());
                }
                return room.voice_request(from, out);
            }
        }
        Err(err(Condition::BadRequest, "Messages to a group chat need to be of type groupchat."))
    }

    /// Archives a prepared message (for its stanza id) and sends it to everyone.
    async fn publish(&self, srv: &Arc<Server>, room: &mut Room, mut p: Prepared, out: &mut Out) {
        let tombstone = p.tombstone.take();
        let mut sid = None;
        if p.archive && room.logging {
            let with = p.msg.attr("from").and_then(|f| Jid::parse(f).ok()).unwrap_or_else(|| room.jid.clone());
            match mam::store(srv, &room.jid, &with, &p.msg).await {
                Ok(id) => sid = Some(id),
                Err(e) if e.condition == Condition::FeatureNotImplemented => {}
                Err(e) => tracing::debug!(error = %e, room = %room.jid, "couldn't archive a group chat message"),
            }
        }
        // Without an archive the id still identifies the message for retractions, moderation
        // and de-duplication of what people saw live and in the join history.
        if p.archive && sid.is_none() {
            sid = Some(quark_core::new_id());
        }
        room.commit_message(p, sid, quark_core::time::now_ms(), out);
        // A retracted or moderated message leaves the archive too, with a tombstone in its
        // place, so reading back doesn't bring it back.
        if let Some(t) = tombstone.filter(|_| room.logging) {
            let sid = t.sid.clone();
            if let Err(e) = mam::tombstone(srv, &room.jid, &sid, move |orig| t.apply(orig)).await {
                tracing::debug!(error = %e, room = %room.jid, "couldn't replace an archived group chat message");
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn room_iq(
        &self,
        srv: &Arc<Server>,
        cell: &Arc<RoomCell>,
        mut room: OwnedMutexGuard<Room>,
        from: &Jid,
        nick: Option<&str>,
        admin: bool,
        el: Element,
        mut out: Out,
    ) {
        let Some(kind) = iq_type(&el) else {
            self.reply_error(srv, &el, StanzaError::bad_request());
            return self.finish(srv, cell, room, out).await;
        };
        let owner = room.aff(&from.to_bare(), admin) == Affiliation::Owner;
        if room.locked_since.is_some() && !owner {
            if matches!(kind, IqType::Get | IqType::Set) {
                self.reply_error(srv, &el, no_room(&cell.jid.to_string()));
            }
            return self.finish(srv, cell, room, out).await;
        }
        if let Some(nick) = nick {
            match kind {
                IqType::Result | IqType::Error => {
                    if let Some(back) = room.relay_answer(from, nick, &el) {
                        out.send.push(back);
                    }
                }
                IqType::Get | IqType::Set => {
                    let self_ping = el.first_child().is_some_and(|p| p.is("ping", ns::PING)) && room.nick_of(from) == Some(nick);
                    if self_ping {
                        // XEP-0410: the room answers for the client, which is still joined.
                        out.send.push(iq_result(&el));
                    } else {
                        match room.relay_iq(from, nick, &el) {
                            Ok(fwd) => out.send.push(fwd),
                            Err(e) => self.reply_error(srv, &el, e),
                        }
                    }
                }
            }
            return self.finish(srv, cell, room, out).await;
        }
        if matches!(kind, IqType::Result | IqType::Error) {
            return self.finish(srv, cell, room, out).await;
        }
        let Some(p) = el.first_child() else {
            self.reply_error(srv, &el, StanzaError::bad_request());
            return self.finish(srv, cell, room, out).await;
        };
        let get = kind == IqType::Get;
        let r: Result<Option<Element>, StanzaError> = match p.ns() {
            ns::DISCO_INFO if get => self.room_info(&room, p.attr("node"), from).map(Some),
            ns::DISCO_ITEMS if get => Ok(Some(Element::new("query", ns::DISCO_ITEMS).attr_opt("node", p.attr("node")))),
            ns::PING if get => Ok(None),
            ns::MUC_ADMIN if get => room.admin_get(from, admin, p).map(Some),
            ns::MUC_ADMIN => room.admin_set(from, admin, p, &mut out).map(|_| None),
            ns::MUC_OWNER if !owner => Err(err(Condition::Forbidden, "Only owners can change this group chat's settings.")),
            ns::MUC_OWNER if get => {
                let admins = room.with_affiliation(Affiliation::Admin);
                Ok(Some(Element::new("query", ns::MUC_OWNER).child(room.config.form(&room.owners(), &admins))))
            }
            ns::MUC_OWNER => self.owner_set(&mut room, p, &mut out).map(|_| None),
            ns::REGISTER if get => room.register_get(from, admin).map(Some),
            ns::REGISTER => room.register_set(from, admin, p, &mut out).map(|_| None),
            ns::VCARD if get => {
                Ok(Some(room.vcard.as_deref().and_then(|v| Element::parse(v).ok()).unwrap_or_else(|| Element::new("vCard", ns::VCARD))))
            }
            ns::VCARD if !owner => Err(err(Condition::Forbidden, "Only owners can change the group chat's picture.")),
            ns::VCARD => {
                let mut v = p.clone();
                v.strip_whitespace();
                let xml = v.to_xml();
                if xml.len() > MAX_VCARD_BYTES {
                    Err(err(Condition::NotAcceptable, "That picture is too big."))
                } else {
                    let empty = v.children().next().is_none();
                    room.set_vcard((!empty).then_some(xml), &mut out);
                    Ok(None)
                }
            }
            // Only a room that says it keeps an archive answers queries on it.
            ns::MAM if !room.logging => Err(StanzaError::service_unavailable().with_text("This group chat keeps no message archive.")),
            ns::MAM => {
                // Only a room that advertises MAM (it keeps a log, see disco#info) answers
                // queries; the archive of one that stopped logging isn't served either.
                let allowed = if room.logging {
                    room.may_read_archive(from, admin)
                } else {
                    Err(StanzaError::feature_not_implemented().with_text("This group chat doesn't keep its history."))
                };
                return match allowed {
                    Err(e) => {
                        self.reply_error(srv, &el, e);
                        self.finish(srv, cell, room, out).await
                    }
                    Ok(()) => {
                        // The query sends its results itself; don't hold the room meanwhile.
                        self.finish(srv, cell, room, out).await;
                        match mam::query(srv, &cell.jid, &el, from).await {
                            Ok(IqReply::Handled) => {}
                            Ok(IqReply::Result(p)) => {
                                let mut r = iq_result(&el);
                                if let Some(p) = p {
                                    r.append(p);
                                }
                                self.reply(srv, r);
                            }
                            Err(e) => self.reply_error(srv, &el, e),
                        }
                    }
                };
            }
            MSG_MODERATE_1 if !get && p.name() == "moderate" => {
                let sid = p.attr("id").map(str::to_string);
                self.moderate(srv, &mut room, from, admin, sid, p.child_text("reason", MSG_MODERATE_1), &mut out).await
            }
            FASTEN if !get && p.has_child("moderate", MSG_MODERATE_0) => {
                let sid = p.attr("id").map(str::to_string);
                let reason = p.get_child("moderate", MSG_MODERATE_0).and_then(|m| m.child_text("reason", MSG_MODERATE_0));
                self.moderate(srv, &mut room, from, admin, sid, reason, &mut out).await
            }
            _ => Err(StanzaError::service_unavailable()),
        };
        match r {
            Ok(payload) => {
                let mut res = iq_result(&el);
                if let Some(p) = payload {
                    res.append(p);
                }
                out.send.push(res);
            }
            Err(e) => {
                if let Some(r) = error_reply(&el, &e) {
                    out.send.push(r);
                }
            }
        }
        self.finish(srv, cell, room, out).await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn moderate(
        &self,
        srv: &Arc<Server>,
        room: &mut Room,
        from: &Jid,
        admin: bool,
        sid: Option<String>,
        reason: Option<String>,
        out: &mut Out,
    ) -> Result<Option<Element>, StanzaError> {
        let sid = sid.filter(|s| !s.is_empty()).ok_or_else(|| err(Condition::BadRequest, "Say which message to remove."))?;
        let p = room.moderate(from, admin, &sid, reason.as_deref(), out)?;
        self.publish(srv, room, p, out).await;
        Ok(None)
    }

    fn owner_set(&self, room: &mut Room, q: &Element, out: &mut Out) -> Result<(), StanzaError> {
        if let Some(d) = q.get_child("destroy", ns::MUC_OWNER) {
            let alt = d.attr("jid").and_then(|j| Jid::parse(j).ok()).map(|j| j.to_string());
            room.destroy(alt.as_deref(), d.child_text("reason", ns::MUC_OWNER).as_deref(), out);
            return Ok(());
        }
        let Some(x) = form::find(q) else { return Err(err(Condition::BadRequest, "Send a settings form, or destroy the room.")) };
        match x.attr("type") {
            Some("cancel") => {
                if room.locked_since.is_some() {
                    room.destroy(None, None, out);
                }
                Ok(())
            }
            Some("submit") => {
                let v = Values::parse(x);
                if v.form_type().is_some_and(|t| t != super::config::ROOMCONFIG) {
                    return Err(err(Condition::BadRequest, "That isn't a group chat settings form."));
                }
                if v.is_empty() {
                    room.unlock(out);
                    return Ok(());
                }
                room.configure(&v, out)
            }
            _ => Err(err(Condition::BadRequest, "Settings forms are submitted or cancelled.")),
        }
    }

    fn room_info(&self, room: &Room, node: Option<&str>, from: &Jid) -> Result<Element, StanzaError> {
        let mut q = Element::new("query", ns::DISCO_INFO).attr_opt("node", node);
        match node {
            None => {}
            Some("x-roomuser-item") => {
                if let Some(n) = room.reserved_nick(&from.to_bare()) {
                    q.append(
                        Element::new("identity", ns::DISCO_INFO)
                            .attr_set("category", "conference")
                            .attr_set("type", "text")
                            .attr_set("name", n),
                    );
                }
                return Ok(q);
            }
            Some(_) => return Err(StanzaError::item_not_found()),
        }
        let c = &room.config;
        let name = c.name.clone().unwrap_or_else(|| room.jid.node().unwrap_or_default().to_string());
        q.append(
            Element::new("identity", ns::DISCO_INFO)
                .attr_set("category", "conference")
                .attr_set("type", "text")
                .attr_set("name", name.as_str()),
        );
        let mut features: Vec<&str> = vec![
            ns::DISCO_INFO,
            ns::DISCO_ITEMS,
            ns::MUC,
            ns::MUC_STABLE_ID,
            ns::MUC_SELF_PING,
            ns::OCCUPANT_ID,
            ns::SID,
            ns::REGISTER,
            ns::VCARD,
            MUC_REQUEST,
            MUC_REGISTER,
            MSG_MODERATE_0,
            MSG_MODERATE_1,
        ];
        if room.logging {
            features.push(ns::MAM);
        }
        features.extend(c.features());
        features.sort_unstable();
        for f in features {
            q.append(Element::new("feature", ns::DISCO_INFO).attr_set("var", f));
        }
        let pm = match c.allow_pm {
            AllowPm::Anyone => "anyone",
            AllowPm::Participants => "participants",
            AllowPm::Moderators => "moderators",
            AllowPm::None => "none",
        };
        let count = room.occupant_count().to_string();
        let mut f = Form::new("result", ROOMINFO)
            .field("muc#roomconfig_roomname", "text-single", "Name", Some(&name))
            .field("muc#roominfo_description", "text-single", "Description", Some(c.description.as_deref().unwrap_or("")))
            .field("muc#roominfo_occupants", "text-single", "People here", Some(&count))
            .field("muc#roominfo_subject", "text-single", "Subject", Some(room.subject.as_ref().map(|s| s.text.as_str()).unwrap_or("")))
            .boolean("muc#roominfo_subjectmod", "Anyone can change the subject", c.change_subject)
            .field("muc#roomconfig_allowpm", "list-single", "Who can send private messages", Some(pm))
            .boolean("muc#roomconfig_allowinvites", "Anyone can invite people", c.allow_invites);
        if let Some(l) = &c.language {
            f = f.field("muc#roominfo_lang", "text-single", "Language", Some(l));
        }
        if let Some(h) = &room.avatar_hash {
            f = f.field("muc#roominfo_avatarhash", "text-multi", "Avatar", Some(h));
        }
        q.append(f.build());
        Ok(q)
    }

    // ---------------------------------------------------------------- admin functions

    /// Runs `f` on a room under its lock, then finishes as for a stanza.
    pub async fn with_room<T>(
        &self,
        srv: &Arc<Server>,
        node: &str,
        f: impl FnOnce(&mut Room, &mut Out) -> T,
    ) -> Result<Option<T>, StanzaError> {
        let Some((cell, mut room)) = self.open(srv, node).await? else { return Ok(None) };
        let mut out = Out::default();
        let t = f(&mut room, &mut out);
        self.finish(srv, &cell, room, out).await;
        Ok(Some(t))
    }

    /// Posts a message from the server under `nick`.
    pub async fn post(&self, srv: &Arc<Server>, node: &str, nick: &str, body: &str) -> Result<bool, StanzaError> {
        let Some((cell, mut room)) = self.open(srv, node).await? else { return Ok(false) };
        let mut out = Out::default();
        let p = room.prepare_post(nick, body);
        match p {
            Ok(p) => self.publish(srv, &mut room, p, &mut out).await,
            Err(e) => {
                self.finish(srv, &cell, room, out).await;
                return Err(e);
            }
        }
        self.finish(srv, &cell, room, out).await;
        Ok(true)
    }

    /// Adds a room made through the admin API. False when the name is taken.
    pub async fn insert_new(&self, srv: &Arc<Server>, room: Room) -> Result<bool, StanzaError> {
        let node = room.jid.node().unwrap_or_default().to_string();
        if self.lookup(srv, &node).await?.is_some() {
            return Ok(false);
        }
        let snap = room.snapshot();
        let persistent = room.config.persistent;
        let stored = Summary::stored(&room);
        let cell = RoomCell::new(room);
        {
            let mut m = self.rooms.write();
            if m.contains_key(&node) {
                return Ok(false);
            }
            m.insert(node.clone(), cell);
        }
        if persistent {
            store::apply(&srv.db, &self.domain, &node, vec![store::Op::Snapshot(Box::new(snap))]).await.map_err(|e| {
                tracing::warn!(error = %e, "couldn't save a new group chat");
                StanzaError::internal()
            })?;
            self.index_update(&node, Some(stored)).await;
        }
        Ok(true)
    }

    /// Housekeeping: rooms nobody finished setting up, idle persistent rooms, stale relays.
    pub async fn sweep(&self, srv: &Arc<Server>) {
        for cell in self.cells() {
            let Ok(mut room) = cell.state.clone().try_lock_owned() else { continue };
            room.expire();
            let mut out = Out::default();
            if room.locked_since.is_some_and(|t| t.elapsed() > LOCK_TIMEOUT) {
                room.destroy(None, Some("Nobody finished setting up this group chat."), &mut out);
                self.finish(srv, &cell, room, out).await;
            } else if room.is_empty() && room.config.persistent && room.empty_since.is_some_and(|t| t.elapsed() > IDLE_UNLOAD) {
                // Everything is saved already; it comes back from storage when needed.
                room.destroyed = true;
                drop(room);
                self.forget(&cell);
            }
        }
    }

    /// The service is going away (group chats turned off or moved): everyone leaves.
    pub async fn shut_down(&self, srv: &Arc<Server>) {
        for cell in self.cells() {
            let mut room = cell.state.clone().lock_owned().await;
            let mut out = Out::default();
            room.shut_down(&mut out);
            room.destroyed = true;
            self.deliver(srv, out.send).await;
            drop(room);
            self.forget(&cell);
        }
    }
}

#[async_trait]
impl Component for Service {
    fn domain(&self) -> &str {
        &self.domain
    }

    async fn handle(&self, srv: &Arc<Server>, from: Jid, to: Jid, mut stanza: Element) {
        stanza.set_attr("from", from.to_string());
        stanza.set_attr("to", to.to_string());
        match to.node() {
            None => self.handle_service(srv, stanza).await,
            Some(node) => {
                let node = node.to_string();
                self.handle_room(srv, &from, &to, &node, stanza).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rooms_created_count_stored_and_temporary_ones_once() {
        let mine = |persistent: bool| Summary { persistent, creator: Some("a@x".into()), ..Summary::default() };
        // Two stored rooms (one of them loaded), and two temporary ones in memory.
        let memory = [mine(true), mine(false), mine(false), Summary { creator: Some("b@x".into()), ..Summary::default() }];
        assert_eq!(rooms_created_by(&memory, "a@x", 2), 4);
        assert_eq!(rooms_created_by(&memory, "b@x", 0), 1);
    }
}
