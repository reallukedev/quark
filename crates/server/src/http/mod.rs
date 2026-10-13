//! The web listener: WebSocket (RFC 7395), BOSH (XEP-0206), file uploads (XEP-0363), invite
//! pages, host-meta (XEP-0156), metrics and the admin API over HTTP.

use std::sync::Arc;

use crate::server::Server;

/// Starts the web listeners; returns the addresses bound.
pub async fn start(_srv: &Arc<Server>) -> anyhow::Result<Vec<std::net::SocketAddr>> {
    Ok(Vec::new())
}
