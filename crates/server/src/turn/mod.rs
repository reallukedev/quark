//! The built-in STUN/TURN relay for calls (RFC 8489, RFC 8656) and XEP-0215 credentials.
//!
//! Credentials follow the TURN REST scheme (coturn's `use-auth-secret`): the username is
//! `<expiry unix seconds>:<account>` and the password `base64(HMAC-SHA1(secret, username))`, so
//! the relay checks them without storing anything per user. The built-in relay's secret is made
//! on first start and kept in the kv store (scope `turn_builtin`, key `secret`).
//!
//! An external relay (set with the admin API's `turn.set`) lives in the kv store under scope
//! `turn`: keys `secret`, `host` and `port`, each UTF-8 text (the port in decimal). When a secret
//! is there, clients get credentials for that relay instead of the built-in one.

mod io;
mod policy;
mod relay;
pub mod stun;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use anyhow::Context as _;

pub use policy::{Cidr, PeerPolicy};
pub use relay::{long_term_key, rest_password, Relay};

use crate::server::Server;

/// The relay's place in the server: set once the listeners are bound.
#[derive(Debug, Default)]
pub struct TurnState {
    relay: OnceLock<Arc<Relay>>,
    addrs: OnceLock<(SocketAddr, SocketAddr)>,
    running: AtomicBool,
}

impl TurnState {
    pub fn relay(&self) -> Option<&Arc<Relay>> {
        self.relay.get()
    }

    /// The UDP and TCP addresses the built-in relay listens on.
    pub fn addrs(&self) -> Option<(SocketAddr, SocketAddr)> {
        self.addrs.get().copied()
    }

    pub fn running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    fn set_running(&self, on: bool) {
        self.running.store(on, Ordering::Relaxed);
    }
}

/// Starts the relay listeners; returns the addresses bound (UDP, then TCP on the same port).
/// Does nothing when `turn.enabled` is off. The ports are bound before this returns.
pub async fn start(srv: &Arc<Server>) -> anyhow::Result<Vec<SocketAddr>> {
    let cfg = srv.config();
    let t = &cfg.turn;
    if !t.enabled {
        return Ok(Vec::new());
    }
    if let Some((u, tc)) = srv.turn.addrs() {
        return Ok(vec![u, tc]);
    }
    let secret = builtin_secret(srv).await?;
    let (udp, tcp) = io::bind(t.listen).with_context(|| format!("starting the call relay on {}", t.listen))?;
    let (u, tc) = (udp.local_addr()?, tcp.local_addr()?);
    let realm = t.public_host.clone().or_else(|| srv.hosts().first().map(|h| h.domain.clone())).unwrap_or_else(|| "quark".into());
    let relay = Arc::new(Relay::new(
        &secret,
        &realm,
        t.listen.ip(),
        (t.relay_min, t.relay_max),
        Arc::new(udp),
        relay::Limits::new(t),
        srv.shutdown_signal(),
    ));
    if srv.turn.relay.set(relay.clone()).is_err() || srv.turn.addrs.set((u, tc)).is_err() {
        anyhow::bail!("the call relay was started twice");
    }
    srv.turn.set_running(true);
    io::spawn(srv, relay, tcp);
    tracing::info!(udp = %u, tcp = %tc, "call relay listening");
    Ok(vec![u, tc])
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
        port: srv.turn.addrs().map_or(c.turn.listen.port(), |(u, _)| u.port()),
        relay_min: c.turn.relay_min,
        relay_max: c.turn.relay_max,
        running: srv.turn.running(),
    }
}

const BUILTIN_SCOPE: &str = "turn_builtin";

/// The built-in relay's shared secret, made on first use.
async fn builtin_secret(srv: &Server) -> anyhow::Result<String> {
    if let Some(v) = srv.kv_get(BUILTIN_SCOPE, "secret").await? {
        if let Ok(s) = String::from_utf8(v) {
            if s.len() >= 32 {
                return Ok(s);
            }
        }
    }
    let s = hex::encode(rand::random::<[u8; 32]>());
    srv.kv_set(BUILTIN_SCOPE, "secret", Some(s.clone().into_bytes())).await?;
    Ok(s)
}

/// Time-limited relay credentials (TURN REST scheme).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    /// When they stop working, in milliseconds since the epoch.
    pub expires_ms: i64,
}

/// Credentials for `user` (any string without meaning to the relay, e.g. a bare JID) valid for
/// `ttl_secs` from `now_ms`.
pub fn rest_credentials(secret: &str, user: &str, ttl_secs: u64, now_ms: i64) -> Credentials {
    let expiry = (now_ms / 1000).max(0) as u64 + ttl_secs;
    let username = format!("{expiry}:{user}");
    let password = rest_password(secret, &username);
    Credentials { username, password, expires_ms: (expiry * 1000) as i64 }
}

/// An external relay set through the admin API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalRelay {
    pub secret: String,
    pub host: Option<String>,
    pub port: Option<u16>,
}

const EXTERNAL_SCOPE: &str = "turn";

/// The external relay, when one has a secret set.
pub async fn external(srv: &Server) -> Result<Option<ExternalRelay>, crate::db::DbError> {
    let text = |v: Option<Vec<u8>>| v.and_then(|b| String::from_utf8(b).ok()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let Some(secret) = text(srv.kv_get(EXTERNAL_SCOPE, "secret").await?) else { return Ok(None) };
    let host = text(srv.kv_get(EXTERNAL_SCOPE, "host").await?);
    let port = text(srv.kv_get(EXTERNAL_SCOPE, "port").await?).and_then(|p| p.parse::<u16>().ok()).filter(|p| *p != 0);
    Ok(Some(ExternalRelay { secret, host, port }))
}

/// Stores (or with no secret, clears) the external relay, in the shape [`external`] reads.
pub async fn set_external(srv: &Server, secret: Option<&str>, host: Option<&str>, port: Option<u16>) -> Result<(), crate::db::DbError> {
    let val = |s: Option<&str>| s.map(str::trim).filter(|s| !s.is_empty()).map(|s| s.as_bytes().to_vec());
    srv.kv_set(EXTERNAL_SCOPE, "secret", val(secret)).await?;
    srv.kv_set(EXTERNAL_SCOPE, "host", val(host)).await?;
    srv.kv_set(EXTERNAL_SCOPE, "port", port.filter(|p| *p != 0).map(|p| p.to_string().into_bytes())).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rest_credentials_carry_the_expiry_and_check_out() {
        let c = rest_credentials("secret", "alice@quark.test", 86_400, 1_700_000_000_123);
        assert_eq!(c.username, "1700086400:alice@quark.test");
        assert_eq!(c.expires_ms, 1_700_086_400_000);
        assert_eq!(c.password, rest_password("secret", &c.username));
        assert_ne!(c.password, rest_password("other", &c.username));
    }
}
