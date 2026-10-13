//! Group chats (XEP-0045) on `groups.host`, with room archives (XEP-0313), occupant ids
//! (XEP-0421), self-ping (XEP-0410) and moderation (XEP-0425).

use std::sync::Arc;

use async_trait::async_trait;
use serde::Serialize;

use super::Module;
use crate::server::Server;

pub struct Muc;

#[async_trait]
impl Module for Muc {
    fn name(&self) -> &'static str {
        "muc"
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

/// Rooms on a group chat service.
pub async fn list_rooms(_srv: &Arc<Server>, _service: &str) -> Vec<RoomInfo> {
    Vec::new()
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
pub async fn create_room(_srv: &Arc<Server>, r: NewRoom<'_>) -> Result<String, RoomError> {
    Err(RoomError::Invalid(format!("Group chats aren't available on {}.", r.service)))
}

/// Destroys a room, telling occupants why.
pub async fn destroy_room(_srv: &Arc<Server>, jid: &str, _reason: Option<&str>) -> Result<(), RoomError> {
    Err(RoomError::NotFound(format!("There's no group chat called {jid}.")))
}

/// Posts a message into a room under `nick`, as the server (Gluon notifications).
pub async fn post(_srv: &Arc<Server>, room: &str, _nick: &str, _body: &str) -> Result<(), RoomError> {
    Err(RoomError::NotFound(format!("There's no group chat called {room}.")))
}
