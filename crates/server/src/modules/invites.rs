//! Invitations (XEP-0401 / XEP-0379): links that create an account, or add a contact, in one tap.

use std::sync::Arc;

use async_trait::async_trait;
use serde::Serialize;

use super::Module;
use crate::accounts::Role;
use crate::server::Server;

pub struct Invites;

#[async_trait]
impl Module for Invites {
    fn name(&self) -> &'static str {
        "invites"
    }
}

/// An invite as the admin API returns it (docs/admin-api.md).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Invite {
    pub token: String,
    pub username: Option<String>,
    pub role: Role,
    pub created: i64,
    pub expires: i64,
    pub uri: String,
    pub page: Option<String>,
    pub reusable: bool,
    pub reset: bool,
}

pub async fn list(_srv: &Arc<Server>, _host: &str) -> Vec<Invite> {
    Vec::new()
}

/// Web routes for invite landing pages (`/invite/<token>`), merged into the web listener.
pub fn router(_srv: &Arc<Server>) -> axum::Router {
    axum::Router::new()
}
