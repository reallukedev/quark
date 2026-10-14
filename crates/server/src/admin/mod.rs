//! The admin API (docs/admin-api.md) over a Unix socket and `quark ctl`, and over HTTP.
//!
//! One JSON request per connection, one JSON response line back. The socket lives at
//! `<data_dir>/admin.sock` with mode 0600, so only the server's own user (and root) can use it;
//! that is the whole authentication, as with Prosody's and Postfix's control sockets.

mod commands;
mod pie;
mod snapshot;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};

use crate::server::Server;

pub use snapshot::client_name;

/// The largest request accepted (account imports are the big ones).
pub const MAX_REQUEST: usize = 32 << 20;
/// How long one connection may take to send its request.
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Requests handled at once; more wait their turn.
const CONCURRENT: usize = 16;

pub const SOCKET: &str = "admin.sock";

/// Where the admin socket lives for a data folder: `<data_dir>/admin.sock`, unless that path is
/// too long for a Unix socket address (about 104 bytes), in which case a name in the temp folder
/// derived from the data folder, so the server and `quark ctl` agree without talking.
pub fn socket_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    use sha2::Digest;
    let p = data_dir.join(SOCKET);
    // Leave room for the temporary name used while binding.
    if p.as_os_str().len() <= 90 {
        return p;
    }
    let h = sha2::Sha256::digest(data_dir.as_os_str().as_encoded_bytes());
    std::env::temp_dir().join(format!("quark-{}.sock", hex::encode(&h[..6])))
}
pub const TOKEN: &str = "admin.token";

/// A refused request: a stable `code` and a sentence for people.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        ApiError { code, message: message.into() }
    }
    pub fn invalid(m: impl Into<String>) -> Self {
        Self::new("invalid", m)
    }
    pub fn not_found(m: impl Into<String>) -> Self {
        Self::new("not_found", m)
    }
    pub fn exists(m: impl Into<String>) -> Self {
        Self::new("exists", m)
    }
    pub fn internal(e: impl std::fmt::Display) -> Self {
        tracing::warn!(error = %e, "admin request failed");
        Self::new("internal", "Something went wrong on the server. Its log has the details.")
    }
}

impl From<crate::db::DbError> for ApiError {
    fn from(e: crate::db::DbError) -> Self {
        ApiError::internal(e)
    }
}

/// Answers one request (the JSON text), returning the response line without the newline.
/// `via` names the transport for the audit log.
pub async fn handle(srv: &Arc<Server>, text: &str, via: &'static str) -> String {
    let req: Value = match serde_json::from_str(text.trim()) {
        Ok(v) => v,
        Err(_) => return respond(Err(ApiError::invalid("The request isn't valid JSON."))),
    };
    let Some(cmd) = req.get("cmd").and_then(Value::as_str).map(str::to_string) else {
        return respond(Err(ApiError::invalid("The request needs a \"cmd\".")));
    };
    let args = match req.get("args") {
        None | Some(Value::Null) => json!({}),
        Some(a) => a.clone(),
    };
    let audit = commands::mutates(&cmd).then(|| commands::summary(&args));
    // Run it in its own task: a bug in one command answers `internal` instead of hanging up.
    let s = srv.clone();
    let c = cmd.clone();
    let r = match tokio::spawn(async move { commands::run(&s, &c, args).await }).await {
        Ok(r) => r,
        Err(e) => Err(ApiError::internal(e)),
    };
    if let Some(summary) = audit {
        match &r {
            Ok(_) => tracing::info!(target: "quark::audit", via, cmd = %cmd, %summary, "admin change"),
            Err(e) => tracing::info!(target: "quark::audit", via, cmd = %cmd, %summary, code = e.code, "admin change refused"),
        }
    }
    respond(r)
}

fn respond(r: Result<Value, ApiError>) -> String {
    let v = match r {
        Ok(value) => json!({ "ok": true, "value": value }),
        Err(e) => json!({ "ok": false, "code": e.code, "error": e.message }),
    };
    v.to_string()
}

/// Reads `<data_dir>/admin.token`, making a new random one (mode 0600) the first time.
pub fn load_or_create_token(data_dir: &Path) -> std::io::Result<String> {
    let path = data_dir.join(TOKEN);
    match std::fs::read_to_string(&path) {
        Ok(t) if !t.trim().is_empty() => return Ok(t.trim().to_string()),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut raw = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut raw);
    let token = hex::encode(raw);
    write_private(&path, format!("{token}\n").as_bytes())?;
    tracing::info!(path = %path.display(), "created the admin API token");
    Ok(token)
}

/// Writes a file only the owner can read, atomically (a temporary file renamed over it).
pub(crate) fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

/// Starts the admin socket listeners; returns the addresses bound (none: it's a Unix socket).
pub async fn start(srv: &Arc<Server>) -> anyhow::Result<Vec<std::net::SocketAddr>> {
    let dir = srv.config().server.data_dir.clone();
    let d = dir.clone();
    tokio::task::spawn_blocking(move || load_or_create_token(&d)).await??;
    #[cfg(unix)]
    unix::listen(srv, &socket_path(&dir))?;
    #[cfg(not(unix))]
    tracing::warn!("the admin socket needs a Unix system; use the HTTP admin API instead");
    Ok(Vec::new())
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::Arc;

    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};

    use super::{handle, MAX_REQUEST, READ_TIMEOUT};
    use crate::server::Server;

    /// Binds the socket under a temporary name, locks it down, then renames it into place, so
    /// it's never reachable with looser permissions, and a stale one from a crash is replaced.
    pub fn listen(srv: &Arc<Server>, path: &Path) -> anyhow::Result<()> {
        let tmp = path.with_extension(format!("sock.{}", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let listener = UnixListener::bind(&tmp).map_err(|e| anyhow::anyhow!("binding the admin socket {}: {e}", tmp.display()))?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&tmp, path)?;
        tracing::info!(path = %path.display(), "admin socket ready");
        let srv = srv.clone();
        let path = path.to_path_buf();
        let limit = Arc::new(tokio::sync::Semaphore::new(super::CONCURRENT));
        tokio::spawn(async move {
            let mut shutdown = srv.shutdown_signal();
            loop {
                let conn = tokio::select! {
                    r = listener.accept() => r,
                    _ = shutdown.changed() => break,
                };
                let (stream, _) = match conn {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(error = %e, "admin socket accept failed");
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        continue;
                    }
                };
                let Ok(permit) = limit.clone().acquire_owned().await else { break };
                let srv = srv.clone();
                tokio::spawn(async move {
                    serve(&srv, stream).await;
                    drop(permit);
                });
            }
            let _ = std::fs::remove_file(&path);
        });
        Ok(())
    }

    async fn serve(srv: &Arc<Server>, stream: UnixStream) {
        let (r, mut w) = stream.into_split();
        let mut buf = Vec::new();
        let mut reader = BufReader::new(r.take(MAX_REQUEST as u64 + 1));
        match tokio::time::timeout(READ_TIMEOUT, reader.read_until(b'\n', &mut buf)).await {
            Ok(Ok(_)) => {}
            _ => return,
        }
        let line = if buf.len() > MAX_REQUEST {
            super::respond(Err(super::ApiError::invalid("The request is too big.")))
        } else {
            match std::str::from_utf8(&buf) {
                Ok(t) => handle(srv, t, "socket").await,
                Err(_) => super::respond(Err(super::ApiError::invalid("The request isn't valid UTF-8."))),
            }
        };
        let _ = w.write_all(line.as_bytes()).await;
        let _ = w.write_all(b"\n").await;
        let _ = w.shutdown().await;
    }
}

/// Sends one request to the admin socket and returns the response line. Newlines outside JSON
/// strings are just whitespace (inside, they must be escaped), so pretty-printed input is folded
/// onto the one line the protocol expects.
#[cfg(unix)]
pub async fn request(socket: &Path, req: &str) -> std::io::Result<String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let stream = tokio::net::UnixStream::connect(socket).await?;
    let (r, mut w) = stream.into_split();
    let mut line: String = req.trim().chars().map(|c| if c == '\n' || c == '\r' { ' ' } else { c }).collect();
    line.push('\n');
    w.write_all(line.as_bytes()).await?;
    w.shutdown().await?;
    let mut out = String::new();
    BufReader::new(r).read_line(&mut out).await?;
    if out.trim().is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "the server closed the connection without answering"));
    }
    Ok(out.trim_end().to_string())
}

/// The data folder a config file points at (with `QUARK_DATA_DIR` applied), or the default
/// when the file can't be read: `quark ctl` must work with a broken config too.
pub fn data_dir_for(config: &Path) -> PathBuf {
    if let Some(d) = std::env::var_os("QUARK_DATA_DIR").filter(|d| !d.is_empty()) {
        return PathBuf::from(d);
    }
    match crate::config::Config::load(config) {
        Ok(c) => c.server.data_dir,
        Err(_) => crate::config::ServerSection::default().data_dir,
    }
}

/// `quark ctl`: one JSON request from stdin to the admin socket, one JSON line out.
pub async fn ctl(config: &std::path::Path) -> i32 {
    use tokio::io::AsyncReadExt;
    let mut input = Vec::new();
    if let Err(e) = tokio::io::stdin().take(MAX_REQUEST as u64).read_to_end(&mut input).await {
        eprintln!("quark ctl: couldn't read the request: {e}");
        return 2;
    }
    let text = String::from_utf8_lossy(&input);
    let socket = socket_path(&data_dir_for(config));
    #[cfg(unix)]
    {
        match request(&socket, &text).await {
            Ok(line) => {
                println!("{line}");
                0
            }
            Err(e) => {
                eprintln!("quark ctl: the server isn't reachable at {}: {e}", socket.display());
                1
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = text;
        eprintln!("quark ctl needs a Unix system ({} isn't available)", socket.display());
        1
    }
}

#[derive(Clone)]
struct HttpState {
    srv: Arc<Server>,
    token: Option<Arc<String>>,
}

/// `POST /admin/api` for the web listener, when `http.admin_api` is on.
pub fn http_router(srv: &Arc<Server>) -> axum::Router {
    let token = match load_or_create_token(&srv.config().server.data_dir) {
        Ok(t) => Some(Arc::new(t)),
        Err(e) => {
            tracing::warn!(error = %e, "no admin token, so the HTTP admin API is unavailable");
            None
        }
    };
    axum::Router::new()
        .route("/admin/api", axum::routing::post(http_api))
        .layer(DefaultBodyLimit::max(MAX_REQUEST))
        .with_state(HttpState { srv: srv.clone(), token })
}

async fn http_api(State(st): State<HttpState>, headers: HeaderMap, body: String) -> Response {
    use subtle::ConstantTimeEq;
    if !st.srv.config().http.admin_api {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(token) = st.token else {
        return (StatusCode::SERVICE_UNAVAILABLE, "The admin token couldn't be read.").into_response();
    };
    let given = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or("");
    if !bool::from(given.trim().as_bytes().ct_eq(token.as_bytes())) {
        let body = respond(Err(ApiError::new("invalid", "The admin token is missing or wrong.")));
        return (StatusCode::UNAUTHORIZED, [(header::CONTENT_TYPE, "application/json"), (header::WWW_AUTHENTICATE, "Bearer")], body)
            .into_response();
    }
    let out = handle(&st.srv, &body, "http").await;
    ([(header::CONTENT_TYPE, "application/json"), (header::CACHE_CONTROL, "no-store")], out).into_response()
}
