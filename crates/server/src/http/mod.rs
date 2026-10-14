//! The web listener: WebSocket (RFC 7395), BOSH (XEP-0206), file uploads (XEP-0363), invite
//! pages, host-meta (XEP-0156), metrics and the admin API over HTTP.
//!
//! Connections are served with hyper directly (not `axum::serve`) so every one gets a header
//! timeout against slowloris, an overall connection cap, optional TLS of its own, and its peer
//! facts in the request extensions.

mod bosh;
mod files;
pub mod jpeg;
mod websocket;

use std::convert::Infallible;
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Extension, Router};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tower::ServiceExt as _;

use crate::modules::Module;
use crate::sasl::ChannelBindings;
use crate::server::{Host, Server};

/// Time a client has to send a request's headers.
const HEADER_TIMEOUT: Duration = Duration::from_secs(20);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Open HTTP connections at once, across listeners. WebSockets count until they close.
const MAX_CONNECTIONS: usize = 20_000;
/// Request bodies for everything but uploads (which stream to disk with their own limit).
const BODY_LIMIT: usize = 1 << 20;
/// How long open requests get to finish when the server stops.
const DRAIN: Duration = Duration::from_secs(10);

/// Facts about the TCP (or TLS) connection a request came in on.
#[derive(Clone)]
pub(crate) struct Conn {
    pub peer: SocketAddr,
    /// Set when this listener did the TLS handshake itself.
    pub tls: Option<Arc<TlsFacts>>,
}

pub(crate) struct TlsFacts {
    pub sni: Option<String>,
    pub cb: ChannelBindings,
}

/// Who is really on the other end, after trusted proxies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Peer {
    pub ip: IpAddr,
    /// TLS all the way to us, or to a trusted proxy that said so.
    pub secure: bool,
    /// The request came through a trusted proxy (so channel binding doesn't apply).
    pub proxied: bool,
}

/// Loopback, private and unique-local addresses: where a reverse proxy can be, and who may see
/// metrics.
pub(crate) fn is_private(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// The client behind a request. `X-Forwarded-For` and `X-Forwarded-Proto` count only when the
/// connection comes from a trusted (loopback or private) proxy; anyone else could forge them.
pub(crate) fn peer(conn: &Conn, headers: &HeaderMap) -> Peer {
    let direct = conn.peer.ip().to_canonical();
    let own_tls = conn.tls.is_some();
    if !is_private(direct) {
        return Peer { ip: direct, secure: own_tls, proxied: false };
    }
    let forwarded: Vec<IpAddr> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .map(|ip| ip.to_canonical())
        .collect();
    // Walk back from the nearest hop: the first address that isn't one of our proxies is the client.
    let ip = forwarded.iter().rev().copied().find(|ip| !is_private(*ip)).or_else(|| forwarded.first().copied());
    let proto_https = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .is_some_and(|p| p.trim().eq_ignore_ascii_case("https"));
    let proxied = ip.is_some() || headers.contains_key("x-forwarded-proto");
    Peer { ip: ip.unwrap_or(direct), secure: own_tls || proto_https, proxied }
}

/// Counters for things only the web side sees.
#[derive(Default)]
pub(crate) struct WebStats {
    pub requests: AtomicU64,
    pub websockets: AtomicU64,
    pub bosh_sessions: AtomicU64,
    pub uploads: AtomicU64,
    pub upload_bytes: AtomicU64,
}

pub(crate) struct WebState {
    pub srv: Arc<Server>,
    pub bosh: bosh::Registry,
    pub stats: WebStats,
}

type AppState = State<Arc<WebState>>;

/// Starts the web listeners; returns the addresses bound.
pub async fn start(srv: &Arc<Server>) -> anyhow::Result<Vec<std::net::SocketAddr>> {
    let cfg = srv.config();
    if cfg.listen.http.is_empty() {
        return Ok(Vec::new());
    }
    let dir = crate::modules::upload::dir(srv);
    tokio::fs::create_dir_all(&dir).await.with_context(|| format!("creating {}", dir.display()))?;
    let state = Arc::new(WebState { srv: srv.clone(), bosh: bosh::Registry::default(), stats: WebStats::default() });
    let app = router(srv, state.clone());
    let tls = cfg.http.tls.then(|| srv.certs.server_config(&[b"http/1.1"]));
    let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut out = Vec::new();
    for addr in cfg.listen.http.iter().copied() {
        let listener = TcpListener::bind(addr).await.with_context(|| format!("listening on {addr}"))?;
        let bound = listener.local_addr()?;
        out.push(bound);
        tracing::info!(addr = %bound, tls = tls.is_some(), "listening for web clients");
        tokio::spawn(accept_loop(state.clone(), listener, app.clone(), tls.clone(), limit.clone()));
    }
    bosh::spawn_reaper(state);
    Ok(out)
}

fn router(srv: &Arc<Server>, state: Arc<WebState>) -> Router {
    let web = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/.well-known/host-meta", get(host_meta))
        .route("/.well-known/host-meta.json", get(host_meta_json))
        .route("/xmpp-websocket", get(websocket::handler))
        .route("/http-bind", post(bosh::handler).get(bosh::info).options(bosh::preflight))
        .route("/http-bind/", post(bosh::handler).get(bosh::info).options(bosh::preflight))
        .route("/upload/{token}/{name}", put(files::put).get(files::get).options(files::preflight).layer(DefaultBodyLimit::disable()))
        .with_state(state);
    web.merge(crate::modules::invites::router(srv))
        .merge(crate::admin::http_router(srv))
        .fallback(|| async { (StatusCode::NOT_FOUND, "Nothing here.\n") })
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
}

async fn accept_loop(
    state: Arc<WebState>,
    listener: TcpListener,
    app: Router,
    tls: Option<Arc<rustls::ServerConfig>>,
    limit: Arc<Semaphore>,
) {
    let mut shutdown = state.srv.shutdown_signal();
    loop {
        let (tcp, addr) = tokio::select! {
            r = listener.accept() => match r {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            },
            _ = shutdown.changed() => return,
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            tracing::debug!(%addr, "too many web connections; refusing one");
            continue;
        };
        let (state, app, tls, shutdown) = (state.clone(), app.clone(), tls.clone(), state.srv.shutdown_signal());
        tokio::spawn(async move {
            let _permit = permit;
            let _ = tcp.set_nodelay(true);
            let peer = SocketAddr::new(addr.ip().to_canonical(), addr.port());
            match tls {
                None => serve_conn(TokioIo::new(tcp), Conn { peer, tls: None }, app, state, shutdown).await,
                Some(cfg) => {
                    let Some(stream) = handshake(tcp, cfg).await else { return };
                    let (sni, _, cb) = crate::tls::session_facts(&stream, &state.srv.certs);
                    let conn = Conn { peer, tls: Some(Arc::new(TlsFacts { sni, cb })) };
                    serve_conn(TokioIo::new(stream), conn, app, state, shutdown).await
                }
            }
        });
    }
}

async fn handshake(tcp: TcpStream, cfg: Arc<rustls::ServerConfig>) -> Option<tokio_rustls::server::TlsStream<TcpStream>> {
    match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, tokio_rustls::TlsAcceptor::from(cfg).accept(tcp)).await {
        Ok(Ok(s)) => Some(s),
        _ => None,
    }
}

async fn serve_conn<I>(io: I, conn: Conn, app: Router, state: Arc<WebState>, mut shutdown: watch::Receiver<bool>)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let svc = hyper::service::service_fn(move |mut req: Request<hyper::body::Incoming>| {
        req.extensions_mut().insert(conn.clone());
        state.stats.requests.fetch_add(1, Ordering::Relaxed);
        let app = app.clone();
        async move { Ok::<_, Infallible>(app.oneshot(req.map(Body::new)).await.unwrap_or_else(|e| match e {})) }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder.timer(TokioTimer::new()).header_read_timeout(HEADER_TIMEOUT).keep_alive(true).max_buf_size(64 * 1024);
    let c = builder.serve_connection(io, svc).with_upgrades();
    tokio::pin!(c);
    tokio::select! {
        r = c.as_mut() => {
            if let Err(e) = r {
                tracing::trace!(error = %e, "web connection ended with an error");
            }
        }
        _ = shutdown.changed() => {
            c.as_mut().graceful_shutdown();
            let _ = tokio::time::timeout(DRAIN, c).await;
        }
    }
}

// -------------------------------------------------------------------- small pages

/// The domain a request is about: its `Host` header when that's one of ours, else the first
/// domain served.
pub(crate) fn host_for(srv: &Server, headers: &HeaderMap) -> Option<Arc<Host>> {
    let named = headers.get(header::HOST).and_then(|v| v.to_str().ok()).map(|h| {
        // Drop the port (IPv6 literals keep their brackets and never match a domain anyway).
        let h = if h.ends_with(']') { h } else { h.rsplit_once(':').map_or(h, |(n, _)| n) };
        h.trim_end_matches('.').to_ascii_lowercase()
    });
    named.and_then(|n| srv.host(&n).or_else(|| srv.component_host(&n))).or_else(|| srv.hosts().into_iter().next())
}

/// Where clients reach the web listener: `http.public_url`, or `https://<domain>`.
pub fn public_base(srv: &Server, domain: &str) -> String {
    match srv.config().http.public_url.as_deref().map(|u| u.trim_end_matches('/')).filter(|u| !u.is_empty()) {
        Some(u) => u.to_string(),
        None => format!("https://{domain}"),
    }
}

/// The WebSocket and BOSH addresses for a domain (XEP-0156), when web clients are on.
fn alt_connections(srv: &Server, host: &Host) -> Vec<(&'static str, String)> {
    if !host.settings().web {
        return Vec::new();
    }
    let base = public_base(srv, &host.domain);
    let ws = match base.split_once("://") {
        Some(("http", rest)) => format!("ws://{rest}"),
        Some((_, rest)) => format!("wss://{rest}"),
        None => format!("wss://{base}"),
    };
    vec![
        ("urn:xmpp:alt-connections:websocket", format!("{ws}/xmpp-websocket")),
        ("urn:xmpp:alt-connections:xbosh", format!("{base}/http-bind")),
    ]
}

fn cors(mut r: Response) -> Response {
    r.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    r
}

async fn host_meta(State(st): AppState, headers: HeaderMap) -> Response {
    let mut xml = String::from("<?xml version='1.0' encoding='utf-8'?>\n<XRD xmlns='http://docs.oasis-open.org/ns/xri/xrd-1.0'>\n");
    if let Some(h) = host_for(&st.srv, &headers) {
        for (rel, href) in alt_connections(&st.srv, &h) {
            let _ = writeln!(xml, "  <Link rel='{rel}' href='{}'/>", quark_core::xml::escape(&href));
        }
    }
    xml.push_str("</XRD>\n");
    cors(([(header::CONTENT_TYPE, "application/xrd+xml; charset=utf-8"), (header::CACHE_CONTROL, "max-age=3600")], xml).into_response())
}

async fn host_meta_json(State(st): AppState, headers: HeaderMap) -> Response {
    let links: Vec<serde_json::Value> = host_for(&st.srv, &headers)
        .map(|h| alt_connections(&st.srv, &h).into_iter().map(|(rel, href)| serde_json::json!({ "rel": rel, "href": href })).collect())
        .unwrap_or_default();
    let body = serde_json::json!({ "links": links }).to_string();
    cors(([(header::CONTENT_TYPE, "application/json"), (header::CACHE_CONTROL, "max-age=3600")], body).into_response())
}

async fn health() -> Response {
    ([(header::CACHE_CONTROL, "no-store")], "ok\n").into_response()
}

async fn index(State(st): AppState, headers: HeaderMap) -> Response {
    let domain = host_for(&st.srv, &headers).map(|h| h.domain.clone()).unwrap_or_else(|| "this server".into());
    let d = quark_core::xml::escape(&domain);
    let html = format!(
        "<!doctype html>\n<html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>\
         <title>{d}</title><style>body{{font:16px/1.5 system-ui,sans-serif;max-width:34em;margin:4em auto;padding:0 1em;color:#222}}\
         @media (prefers-color-scheme:dark){{body{{background:#111;color:#ddd}}}}h1{{font-size:1.6em;margin-bottom:.2em}}p{{color:#666}}</style></head>\
         <body><h1>{d}</h1><p>This is a chat server. Sign in with any XMPP app, such as Conversations, Monal, Gajim or Dino, \
         using an address like <b>you@{d}</b>.</p></body></html>\n"
    );
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CONTENT_SECURITY_POLICY, "default-src 'none'; style-src 'unsafe-inline'"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        html,
    )
        .into_response()
}

/// Prometheus text format, for loopback and private-network scrapers only.
async fn metrics(State(st): AppState, Extension(conn): Extension<Conn>, headers: HeaderMap) -> Response {
    let srv = &st.srv;
    if !srv.config().http.metrics || !is_private(peer(&conn, &headers).ip) {
        return (StatusCode::NOT_FOUND, "Nothing here.\n").into_response();
    }
    let mut by_transport: Vec<(&'static str, u64)> = Vec::new();
    for h in srv.hosts() {
        for s in srv.sessions.on_host(&h.domain) {
            match by_transport.iter_mut().find(|(t, _)| *t == s.info.transport) {
                Some((_, n)) => *n += 1,
                None => by_transport.push((s.info.transport, 1)),
            }
        }
    }
    let (stored_files, stored_bytes) = crate::modules::upload::stored(srv).await;
    let (s2s_in, s2s_out) = srv.remote().map_or((0, 0), |r| r.counts());
    let s = &srv.stats;
    let w = &st.stats;
    let load = |a: &AtomicU64| a.load(Ordering::Relaxed);
    let mut out = String::with_capacity(2048);
    let mut metric = |name: &str, kind: &str, help: &str, samples: &[(&str, u64)]| {
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
        for (labels, v) in samples {
            let _ = writeln!(out, "{name}{labels} {v}");
        }
    };
    metric("quark_build_info", "gauge", "Quark version.", &[(&format!("{{version=\"{}\"}}", env!("CARGO_PKG_VERSION")), 1)]);
    metric("quark_start_time_seconds", "gauge", "When the server started.", &[("", (srv.started_at / 1000).max(0) as u64)]);
    let sessions: Vec<(String, u64)> = by_transport.iter().map(|(t, n)| (format!("{{transport=\"{t}\"}}"), *n)).collect();
    let sessions: Vec<(&str, u64)> = sessions.iter().map(|(l, n)| (l.as_str(), *n)).collect();
    metric("quark_sessions", "gauge", "Signed-in client sessions.", if sessions.is_empty() { &[("", 0)] } else { &sessions });
    metric("quark_c2s_connections_total", "counter", "Client connections accepted.", &[("", load(&s.c2s_connections))]);
    metric("quark_stanzas_in_total", "counter", "Stanzas received from clients.", &[("", load(&s.stanzas_in))]);
    metric("quark_stanzas_out_total", "counter", "Stanzas sent to clients.", &[("", load(&s.stanzas_out))]);
    metric("quark_auth_failures_total", "counter", "Failed sign-ins.", &[("", load(&s.auth_failures))]);
    metric(
        "quark_s2s_links",
        "gauge",
        "Server-to-server links.",
        &[("{direction=\"in\"}", s2s_in as u64), ("{direction=\"out\"}", s2s_out as u64)],
    );
    metric("quark_http_requests_total", "counter", "Web requests served.", &[("", load(&w.requests))]);
    metric("quark_websocket_connections_total", "counter", "WebSocket connections opened.", &[("", load(&w.websockets))]);
    metric("quark_bosh_sessions", "gauge", "Open BOSH sessions.", &[("", st.bosh.len() as u64)]);
    metric("quark_bosh_sessions_total", "counter", "BOSH sessions created.", &[("", load(&w.bosh_sessions))]);
    metric("quark_uploads_total", "counter", "Files uploaded.", &[("", load(&w.uploads))]);
    metric("quark_upload_bytes_total", "counter", "Bytes uploaded.", &[("", load(&w.upload_bytes))]);
    metric("quark_upload_stored_files", "gauge", "Uploaded files kept.", &[("", stored_files)]);
    metric("quark_upload_stored_bytes", "gauge", "Bytes of uploaded files kept.", &[("", stored_bytes)]);
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8"), (header::CACHE_CONTROL, "no-store")], out).into_response()
}

// -------------------------------------------------------------------- snapshot names

/// Reports the web transports in the admin snapshot (Prosody's module names).
pub struct Web;

#[async_trait]
impl Module for Web {
    fn name(&self) -> &'static str {
        "web"
    }
    fn snapshot_names(&self, host: &Host) -> Vec<&'static str> {
        if host.settings().web {
            vec!["websocket", "bosh"]
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(ip: &str) -> Conn {
        Conn { peer: SocketAddr::new(ip.parse().unwrap(), 4000), tls: None }
    }

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, HeaderValue::from_static(v));
        }
        h
    }

    #[test]
    fn forwarded_headers_count_only_from_private_proxies() {
        let h = headers(&[("x-forwarded-for", "203.0.113.7"), ("x-forwarded-proto", "https")]);
        let p = peer(&conn("127.0.0.1"), &h);
        assert_eq!(p, Peer { ip: "203.0.113.7".parse().unwrap(), secure: true, proxied: true });
        let p = peer(&conn("198.51.100.1"), &h);
        assert_eq!(p, Peer { ip: "198.51.100.1".parse().unwrap(), secure: false, proxied: false });
    }

    #[test]
    fn forwarded_for_skips_our_own_proxy_chain() {
        let h = headers(&[("x-forwarded-for", "1.2.3.4, 203.0.113.9, 10.0.0.2")]);
        assert_eq!(peer(&conn("10.0.0.1"), &h).ip, "203.0.113.9".parse::<IpAddr>().unwrap());
        let h = headers(&[("x-forwarded-for", "garbage, 192.168.1.5")]);
        assert_eq!(peer(&conn("10.0.0.1"), &h).ip, "192.168.1.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn private_ranges() {
        for ip in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.0.1", "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1"] {
            assert!(is_private(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "172.32.0.1", "2001:db8::1", "::ffff:8.8.8.8"] {
            assert!(!is_private(ip.parse().unwrap()), "{ip}");
        }
    }
}
