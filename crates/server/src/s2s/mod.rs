//! Server-to-server links (RFC 6120, XEP-0220 dialback, XEP-0368 direct TLS).

use std::sync::Arc;

use crate::server::Server;

/// Starts the server-to-server listeners; returns the addresses bound.
pub async fn start(_srv: &Arc<Server>) -> anyhow::Result<Vec<std::net::SocketAddr>> {
    Ok(Vec::new())
}
