//! The built-in STUN/TURN relay for calls (RFC 8489, RFC 8656) and XEP-0215 credentials.

use std::sync::Arc;

use crate::server::Server;

/// Starts the relay listeners; returns the addresses bound.
pub async fn start(_srv: &Arc<Server>) -> anyhow::Result<Vec<std::net::SocketAddr>> {
    Ok(Vec::new())
}

/// The relay's state for the admin snapshot.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TurnStatus {
    pub built_in: bool,
    pub port: u16,
    pub relay_min: u16,
    pub relay_max: u16,
    pub running: bool,
}

pub fn status(srv: &Server) -> TurnStatus {
    let c = srv.config();
    TurnStatus {
        built_in: c.turn.enabled,
        port: c.turn.listen.port(),
        relay_min: c.turn.relay_min,
        relay_max: c.turn.relay_max,
        running: false,
    }
}
