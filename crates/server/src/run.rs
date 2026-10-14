//! Starting and stopping the whole server.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;

use crate::config::Config;
use crate::db::Db;
use crate::server::Server;

/// Reads the config (making a starter one from the environment on first run), applies the
/// environment, and prepares folders.
pub fn load_config(path: &Path) -> anyhow::Result<Config> {
    if !path.exists() {
        let domains: Vec<String> = std::env::var("QUARK_DOMAIN")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        let admins: Vec<String> = std::env::var("QUARK_ADMINS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        std::fs::write(path, Config::starter(&domains, &admins)).with_context(|| format!("writing {}", path.display()))?;
        eprintln!("quark: wrote a starter config to {}", path.display());
    }
    let mut cfg = Config::load(path)?;
    cfg.apply_env(|k| std::env::var(k).ok())?;
    if cfg.hosts.is_empty() {
        anyhow::bail!("No domains to serve. Add a [[host]] to {} or set QUARK_DOMAIN.", path.display());
    }
    std::fs::create_dir_all(&cfg.server.data_dir).with_context(|| format!("creating {}", cfg.server.data_dir.display()))?;
    std::fs::create_dir_all(&cfg.tls.cert_dir).with_context(|| format!("creating {}", cfg.tls.cert_dir.display()))?;
    Ok(cfg)
}

/// Opens storage and builds the server, without listening yet.
pub fn build(cfg: Config) -> anyhow::Result<Arc<Server>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let db = Db::open(&cfg.server.data_dir.join("quark.db")).context("opening the database")?;
    Ok(Server::new(cfg, db)?)
}

/// A server for `a.test` with its files in `dir`, not listening, for unit tests. `extra` is
/// TOML appended to the config.
#[cfg(test)]
pub(crate) fn test_server(dir: &Path, extra: &str) -> Arc<Server> {
    let path = dir.join("quark.toml");
    let text = format!(
        "{extra}\n[server]\ndata_dir = {:?}\n[tls]\ncert_dir = {:?}\n[[host]]\ndomain = \"a.test\"\n",
        dir.join("data"),
        dir.join("certs")
    );
    std::fs::write(&path, text).expect("writing a test config");
    build(load_config(&path).expect("a valid test config")).expect("a test server")
}

/// The addresses the server listens on (useful with port 0 in tests).
#[derive(Debug, Clone, Default)]
pub struct Listening {
    pub c2s: Vec<SocketAddr>,
    pub c2s_tls: Vec<SocketAddr>,
    pub s2s: Vec<SocketAddr>,
    pub http: Vec<SocketAddr>,
    pub turn: Vec<SocketAddr>,
}

/// Starts every listener and background task. Ports are bound before this returns, so a port
/// that's taken fails the start rather than some later moment.
pub async fn start(srv: &Arc<Server>) -> anyhow::Result<Listening> {
    srv.start();
    let cfg = srv.config();
    let mut out = Listening::default();
    for (addrs, tls) in [(&cfg.listen.c2s, false), (&cfg.listen.c2s_tls, true)] {
        for addr in addrs.iter().copied() {
            let listener = tokio::net::TcpListener::bind(addr).await.with_context(|| format!("listening on {addr}"))?;
            let bound = listener.local_addr()?;
            if tls {
                out.c2s_tls.push(bound)
            } else {
                out.c2s.push(bound)
            }
            let s = srv.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::c2s::accept_loop(s, listener, tls).await {
                    tracing::error!(addr = %bound, error = %e, "client listener stopped");
                }
            });
        }
    }
    out.s2s = crate::s2s::start(srv).await?;
    out.http = crate::http::start(srv).await?;
    crate::admin::start(srv).await?;
    out.turn = crate::turn::start(srv).await?;
    Ok(out)
}

/// Runs until SIGINT/SIGTERM, then closes every session cleanly.
pub async fn run(config: PathBuf) -> anyhow::Result<()> {
    let cfg = load_config(&config)?;
    init_logging(&cfg.server.log);
    let domains: Vec<String> = cfg.hosts.iter().map(|h| h.domain.clone()).collect();
    let srv = build(cfg)?;
    start(&srv).await?;
    tracing::info!(version = env!("CARGO_PKG_VERSION"), domains = ?domains, "Quark is running");
    wait_for_signal().await;
    tracing::info!("shutting down");
    srv.shut_down();
    for h in srv.hosts() {
        for s in srv.sessions.on_host(&h.domain) {
            s.close("system-shutdown", None);
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    Ok(())
}

pub fn init_logging(filter: &str) {
    let env = tracing_subscriber::EnvFilter::try_from_env("QUARK_LOG").unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter));
    // Colours only on a terminal: log files and `docker logs` get plain text.
    let ansi = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let _ = tracing_subscriber::fmt().with_env_filter(env).with_target(false).with_ansi(ansi).with_writer(std::io::stderr).try_init();
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(t) => t,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
