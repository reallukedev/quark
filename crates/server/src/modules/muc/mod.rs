//! Group chats (XEP-0045) on `groups.host`, with room archives (XEP-0313), occupant ids
//! (XEP-0421), self-ping (XEP-0410) and moderation (XEP-0425).
//!
//! The service's state lives here, outside the component, so it survives the component being
//! rebuilt whenever a domain's settings change. Rooms are loaded from storage when first
//! needed and leave memory again once they've been empty for a while.

use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::RwLock;
use quark_core::{ns, Element, Jid};
use serde::Serialize;

use super::{Component, Event, Module};
use crate::db::Migration;
use crate::server::{Host, Server};

mod config;
mod form;
mod room;
mod service;
mod store;

pub use service::Service;

/// How often idle rooms and unfinished new rooms are looked at.
const SWEEP_EVERY: Duration = Duration::from_secs(30);

#[derive(Default)]
pub struct Muc {
    /// By service domain.
    services: RwLock<HashMap<String, Arc<Service>>>,
}

impl Muc {
    pub fn new() -> Muc {
        Muc::default()
    }

    fn service(&self, domain: &str) -> Option<Arc<Service>> {
        self.services.read().get(domain).cloned()
    }

    fn all(&self) -> Vec<Arc<Service>> {
        self.services.read().values().cloned().collect()
    }
}

/// This server's group chat module.
fn state(srv: &Server) -> Option<&Muc> {
    srv.modules.iter().find_map(|m| m.as_any()?.downcast_ref::<Muc>())
}

#[async_trait]
impl Module for Muc {
    fn name(&self) -> &'static str {
        "muc"
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }

    fn migrations(&self) -> Vec<&'static Migration> {
        vec![&store::MIGRATION]
    }

    fn snapshot_names(&self, host: &Host) -> Vec<&'static str> {
        let s = host.settings();
        match (s.groups.on, s.history.on()) {
            (true, true) => vec!["muc", "muc_mam"],
            (true, false) => vec!["muc"],
            _ => Vec::new(),
        }
    }

    fn server_items(&self, host: &Host) -> Vec<Element> {
        let s = host.settings();
        if !s.groups.on {
            return Vec::new();
        }
        vec![Element::new("item", ns::DISCO_ITEMS).attr_set("jid", s.groups.host.as_str()).attr_set("name", "Group chats")]
    }

    fn components(&self, _srv: &Arc<Server>, host: &Arc<Host>) -> Vec<Arc<dyn Component>> {
        let s = host.settings();
        if !s.groups.on {
            return Vec::new();
        }
        let Ok(jid) = Jid::domain_jid(&s.groups.host) else { return Vec::new() };
        let mut m = self.services.write();
        let svc = match m.get(&s.groups.host) {
            Some(existing) if existing.host == host.domain => existing.clone(),
            _ => {
                let svc = Arc::new(Service::new(&s.groups.host, jid, &host.domain));
                m.insert(s.groups.host.clone(), svc.clone());
                svc
            }
        };
        vec![svc]
    }

    fn start(&self, srv: &Arc<Server>) {
        let weak: Weak<Server> = Arc::downgrade(srv);
        let mut stop = srv.shutdown_signal();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(SWEEP_EVERY);
            tick.tick().await;
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = stop.changed() => return,
                }
                let Some(srv) = weak.upgrade() else { return };
                let Some(muc) = state(&srv) else { return };
                for svc in muc.all() {
                    svc.sweep(&srv).await;
                }
            }
        });
    }

    async fn on_event(&self, srv: &Arc<Server>, ev: &Event) {
        match ev {
            Event::SettingsChanged { .. } => {
                // Services whose domain no longer has group chats there close their rooms.
                let live: Vec<(String, String)> = srv
                    .hosts()
                    .iter()
                    .filter_map(|h| Some(h.settings()).filter(|s| s.groups.on).map(|s| (s.groups.host.clone(), h.domain.clone())))
                    .collect();
                let stale: Vec<Arc<Service>> = {
                    let mut m = self.services.write();
                    let gone: Vec<String> =
                        m.iter().filter(|(d, s)| !live.iter().any(|(ld, lh)| ld == *d && *lh == s.host)).map(|(d, _)| d.clone()).collect();
                    gone.into_iter().filter_map(|d| m.remove(&d)).collect()
                };
                for svc in stale {
                    svc.shut_down(srv).await;
                }
            }
            Event::AccountDeleted { jid } => {
                if let Err(e) = store::forget(&srv.db, &jid.to_string()).await {
                    tracing::warn!(error = %e, "couldn't remove a deleted account's group chat affiliations");
                }
                for svc in self.all() {
                    for cell in svc.cells() {
                        cell.state.lock().await.affiliations.remove(jid);
                    }
                }
            }
            _ => {}
        }
    }
}

/// A room, as the admin API lists it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoomInfo {
    pub jid: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub public: bool,
    pub members_only: bool,
    pub persistent: bool,
    pub occupants: usize,
}

/// What admin operations on rooms can say went wrong (shown to people as is).
#[derive(Debug, thiserror::Error)]
pub enum RoomError {
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Exists(String),
    #[error("{0}")]
    Invalid(String),
}

fn unavailable(service: &str) -> RoomError {
    RoomError::Invalid(format!("Group chats aren't available on {service}."))
}

fn not_found(jid: &str) -> RoomError {
    RoomError::NotFound(format!("There's no group chat called {jid}."))
}

fn internal(e: quark_core::StanzaError) -> RoomError {
    RoomError::Invalid(e.text.unwrap_or_else(|| "Something went wrong on the server; try again.".into()))
}

/// Splits `room@service` into the service and the room's local part.
fn split(srv: &Server, jid: &str) -> Result<(Arc<Service>, String), RoomError> {
    let j = Jid::parse(jid).map_err(|_| RoomError::Invalid(format!("\"{jid}\" isn't a group chat address.")))?;
    let node = j.node().ok_or_else(|| RoomError::Invalid(format!("\"{jid}\" isn't a group chat address.")))?.to_string();
    let svc = state(srv).and_then(|m| m.service(j.domain())).ok_or_else(|| not_found(jid))?;
    Ok((svc, node))
}

/// Rooms on a group chat service.
pub async fn list_rooms(srv: &Arc<Server>, service: &str) -> Vec<RoomInfo> {
    let Some(svc) = state(srv).and_then(|m| m.service(service)) else { return Vec::new() };
    svc.all_rooms(srv)
        .await
        .into_iter()
        .filter(|(_, s)| !s.locked)
        .map(|(node, s)| RoomInfo {
            jid: format!("{node}@{service}"),
            name: s.name,
            description: s.description,
            public: s.public,
            members_only: s.members_only,
            persistent: s.persistent,
            occupants: s.occupants,
        })
        .collect()
}

pub struct NewRoom<'a> {
    pub service: &'a str,
    /// The local part, e.g. `family`.
    pub room: &'a str,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub public: bool,
    pub members_only: bool,
    /// Bare JID made owner.
    pub owner: Option<&'a str>,
}

/// Creates a persistent room. Returns its JID.
pub async fn create_room(srv: &Arc<Server>, r: NewRoom<'_>) -> Result<String, RoomError> {
    let svc = state(srv).and_then(|m| m.service(r.service)).ok_or_else(|| unavailable(r.service))?;
    let jid = Jid::from_parts(Some(r.room), r.service, None)
        .map_err(|_| RoomError::Invalid(format!("\"{}\" can't be used as a group chat address.", r.room)))?;
    let owner = match r.owner {
        Some(o) => Some(Jid::parse(o).map_err(|_| RoomError::Invalid(format!("\"{o}\" isn't a chat address.")))?.to_bare()),
        None => None,
    };
    let name = r.name.trim();
    let config = config::Config {
        name: Some(name.to_string()).filter(|n| !n.is_empty()),
        description: r.description.map(str::trim).filter(|d| !d.is_empty()).map(str::to_string),
        persistent: true,
        public: r.public,
        members_only: r.members_only,
        ..config::Config::default()
    };
    let mut room = room::Room::new(jid.clone(), config, owner.clone(), quark_core::time::now_ms());
    if let Some(o) = owner {
        room.affiliations.insert(o, room::AffEntry { affiliation: room::Affiliation::Owner, reason: None, nick: None, last_nick: None });
    }
    if !svc.insert_new(srv, room).await.map_err(internal)? {
        return Err(RoomError::Exists(format!("There's already a group chat called {jid}.")));
    }
    Ok(jid.to_string())
}

/// Destroys a room, telling occupants why.
pub async fn destroy_room(srv: &Arc<Server>, jid: &str, reason: Option<&str>) -> Result<(), RoomError> {
    let (svc, node) = split(srv, jid)?;
    match svc.with_room(srv, &node, |room, out| room.destroy(None, reason, out)).await.map_err(internal)? {
        Some(()) => Ok(()),
        None => Err(not_found(jid)),
    }
}

/// Posts a message into a room under `nick`, as the server (Gluon notifications).
pub async fn post(srv: &Arc<Server>, room: &str, nick: &str, body: &str) -> Result<(), RoomError> {
    let (svc, node) = split(srv, room)?;
    match svc.post(srv, &node, nick, body).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(not_found(room)),
        Err(e) => Err(RoomError::Invalid(e.text.unwrap_or_else(|| "That message can't be posted.".into()))),
    }
}
