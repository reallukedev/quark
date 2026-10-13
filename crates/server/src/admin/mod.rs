//! The admin API (docs/admin-api.md) over a Unix socket and `quark ctl`.

use std::sync::Arc;

use crate::server::Server;

/// Starts the admin socket listeners; returns the addresses bound.
pub async fn start(_srv: &Arc<Server>) -> anyhow::Result<Vec<std::net::SocketAddr>> {
    Ok(Vec::new())
}

/// `quark ctl`: one JSON request from stdin to the admin socket, one JSON line out.
pub async fn ctl(_config: &std::path::Path) -> i32 {
    eprintln!("quark ctl isn't available in this build yet");
    2
}

/// `POST /admin/api` for the web listener, when `http.admin_api` is on.
pub fn http_router(_srv: &Arc<Server>) -> axum::Router {
    axum::Router::new()
}
