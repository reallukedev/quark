//! The config file (`quark.toml`): where to listen, which domains to serve, and limits.
//!
//! Chat settings people change day to day (sign-up, history, group chats…) live in the database
//! and are changed through the admin API; the config file only seeds them for a new domain.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::settings::PartialSettings;

pub const DEFAULT_CONFIG: &str = "/etc/quark/quark.toml";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerSection,
    #[serde(default, rename = "host")]
    pub hosts: Vec<HostConfig>,
    #[serde(default)]
    pub listen: Listen,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub tls: TlsSection,
    #[serde(default)]
    pub http: HttpSection,
    #[serde(default)]
    pub s2s: S2sSection,
    #[serde(default)]
    pub turn: TurnSection,
    /// Where this config was read from (not part of the file).
    #[serde(skip)]
    pub path: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// `tracing` filter, e.g. `info` or `quark=debug`.
    #[serde(default = "default_log")]
    pub log: String,
}

impl Default for ServerSection {
    fn default() -> Self {
        ServerSection { data_dir: default_data_dir(), log: default_log() }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    pub domain: String,
    /// JIDs with full admin rights on this domain. They outrank roles set through the admin API.
    #[serde(default)]
    pub admins: Vec<String>,
    /// Starting chat settings for a domain the database hasn't seen yet.
    #[serde(default)]
    pub settings: Option<PartialSettings>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    /// Client connections with STARTTLS (RFC 6120).
    #[serde(default = "default_c2s")]
    pub c2s: Vec<SocketAddr>,
    /// Client connections with TLS from the first byte (XEP-0368).
    #[serde(default = "default_c2s_tls")]
    pub c2s_tls: Vec<SocketAddr>,
    #[serde(default = "default_s2s")]
    pub s2s: Vec<SocketAddr>,
    #[serde(default = "default_s2s_tls")]
    pub s2s_tls: Vec<SocketAddr>,
    /// WebSocket, BOSH, uploads, invite pages and the admin API. Plain HTTP: put a TLS proxy
    /// (Caddy) in front, or set `http.tls = true`.
    #[serde(default = "default_http")]
    pub http: Vec<SocketAddr>,
}

impl Default for Listen {
    fn default() -> Self {
        Listen { c2s: default_c2s(), c2s_tls: default_c2s_tls(), s2s: default_s2s(), s2s_tls: default_s2s_tls(), http: default_http() }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "default_c2s_stanza")]
    pub c2s_stanza_bytes: u64,
    #[serde(default = "default_s2s_stanza")]
    pub s2s_stanza_bytes: u64,
    /// Sustained bytes per second a client may send before reads slow down.
    #[serde(default = "default_c2s_rate")]
    pub c2s_bytes_per_sec: u64,
    /// Seconds a connection has to finish signing in.
    #[serde(default = "default_auth_timeout")]
    pub auth_timeout_secs: u64,
    /// Seconds a dropped mobile session waits to be resumed (XEP-0198).
    #[serde(default = "default_resume")]
    pub resume_secs: u64,
    /// Stanzas queued for a slow client before it is disconnected.
    #[serde(default = "default_queue")]
    pub max_queue: usize,
    /// Devices one account can have online at once.
    #[serde(default = "default_sessions")]
    pub max_sessions_per_account: usize,
    /// Failed sign-ins from one address per minute before it has to wait.
    #[serde(default = "default_auth_failures")]
    pub auth_failures_per_minute: u32,
    /// Accounts one address can register per hour (in-band registration).
    #[serde(default = "default_registrations")]
    pub registrations_per_hour: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            c2s_stanza_bytes: default_c2s_stanza(),
            s2s_stanza_bytes: default_s2s_stanza(),
            c2s_bytes_per_sec: default_c2s_rate(),
            auth_timeout_secs: default_auth_timeout(),
            resume_secs: default_resume(),
            max_queue: default_queue(),
            max_sessions_per_account: default_sessions(),
            auth_failures_per_minute: default_auth_failures(),
            registrations_per_hour: default_registrations(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSection {
    /// `<domain>.crt` + `<domain>.key` (or `<domain>/fullchain.pem` + `privkey.pem`), watched and
    /// reloaded when they change.
    #[serde(default = "default_cert_dir")]
    pub cert_dir: PathBuf,
    /// Clients must use TLS before signing in.
    #[serde(default = "yes")]
    pub require_c2s: bool,
    /// Make a self-signed certificate for a domain without one, so TLS always works.
    #[serde(default = "yes")]
    pub self_signed_fallback: bool,
}

impl Default for TlsSection {
    fn default() -> Self {
        TlsSection { cert_dir: default_cert_dir(), require_c2s: true, self_signed_fallback: true }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpSection {
    /// The public base URL clients reach the web listener at, e.g. `https://chat.example.com`.
    /// Defaults to `https://<domain>`.
    #[serde(default)]
    pub public_url: Option<String>,
    /// Serve the admin API over HTTP (bearer token in `<data_dir>/admin.token`).
    #[serde(default)]
    pub admin_api: bool,
    /// Prometheus metrics at `/metrics` (only from loopback and private addresses).
    #[serde(default = "yes")]
    pub metrics: bool,
    /// Serve the web listener over TLS itself (certificates from `tls.cert_dir`) instead of
    /// behind a TLS proxy.
    #[serde(default)]
    pub tls: bool,
}

impl Default for HttpSection {
    fn default() -> Self {
        HttpSection { public_url: None, admin_api: false, metrics: true, tls: false }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct S2sSection {
    /// Remote servers must present a valid certificate or prove themselves with dialback over TLS.
    #[serde(default = "yes")]
    pub require_tls: bool,
    /// Seconds an idle server-to-server link stays open.
    #[serde(default = "default_s2s_idle")]
    pub idle_secs: u64,
    /// Domains never talked to (their subdomains included).
    #[serde(default)]
    pub blocked: Vec<String>,
    /// Fixed addresses for remote domains instead of DNS, for private deployments and tests:
    /// `"chat.example" = "10.0.0.5:5269"` (STARTTLS) or `"tls://10.0.0.5:5270"` (direct TLS).
    #[serde(default)]
    pub routes: BTreeMap<String, String>,
    /// PEM files with certificates to trust for federation besides the public CAs: a private
    /// CA, or another server's self-signed certificate.
    #[serde(default)]
    pub trusted_certs: Vec<PathBuf>,
    /// Let servers without a certificate we trust prove who they are with dialback (XEP-0220).
    #[serde(default = "yes")]
    pub dialback: bool,
    /// The secret dialback keys are made from. Made and stored on first start when unset; set
    /// the same one on every node of a cluster.
    #[serde(default)]
    pub dialback_secret: Option<String>,
    /// Seconds a server that couldn't be reached is remembered, so messages to it fail fast.
    #[serde(default = "default_s2s_retry")]
    pub retry_secs: u64,
    /// Incoming server connections at once.
    #[serde(default = "default_s2s_incoming")]
    pub max_incoming: usize,
    /// Seconds to reach another server and sign in before giving up on it.
    #[serde(default = "default_s2s_timeout")]
    pub timeout_secs: u64,
}

impl Default for S2sSection {
    fn default() -> Self {
        S2sSection {
            require_tls: true,
            idle_secs: default_s2s_idle(),
            blocked: Vec::new(),
            routes: BTreeMap::new(),
            trusted_certs: Vec::new(),
            dialback: true,
            dialback_secret: None,
            retry_secs: default_s2s_retry(),
            max_incoming: default_s2s_incoming(),
            timeout_secs: default_s2s_timeout(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TurnSection {
    /// Run the built-in STUN/TURN relay for calls (XEP-0215). Used when calls are on and no
    /// external relay secret is set.
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "default_turn_listen")]
    pub listen: SocketAddr,
    /// The address phones are told to reach the relay at, when it differs from the domain.
    #[serde(default)]
    pub public_host: Option<String>,
    /// The public IPv4 the relay advertises for relayed addresses, when behind NAT.
    #[serde(default)]
    pub external_ip: Option<std::net::IpAddr>,
    #[serde(default = "default_relay_min")]
    pub relay_min: u16,
    #[serde(default = "default_relay_max")]
    pub relay_max: u16,
    /// Hours the relay credentials handed to clients (XEP-0215) stay valid.
    #[serde(default = "default_credential_hours")]
    pub credential_hours: u32,
    #[serde(default)]
    pub quota: TurnQuota,
    /// Which peers the relay may send to (it must never become a way into the server's network).
    #[serde(default)]
    pub peers: TurnPeers,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TurnQuota {
    /// Relayed addresses open at once, in total.
    #[serde(default = "default_turn_allocations")]
    pub allocations: usize,
    /// Relayed addresses open at once per account. Never more than an eighth of the relay port
    /// range (and at least two), so a few accounts can't take every port.
    #[serde(default = "default_turn_per_user")]
    pub allocations_per_user: usize,
    /// Kilobits per second one relayed address may carry (both directions); 0 for no limit.
    #[serde(default = "default_turn_kbps")]
    pub kbps: u32,
    /// The longest a client may ask a relayed address to live without refreshing it.
    #[serde(default = "default_turn_lifetime")]
    pub max_lifetime_secs: u32,
}

impl Default for TurnQuota {
    fn default() -> Self {
        TurnQuota {
            allocations: default_turn_allocations(),
            allocations_per_user: default_turn_per_user(),
            kbps: default_turn_kbps(),
            max_lifetime_secs: default_turn_lifetime(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TurnPeers {
    /// Relay to private (LAN) addresses. Off by default: it would let any account reach every
    /// device on the server's networks (routers, NAS boxes, docker services). Phones on the same
    /// Wi-Fi still reach each other without it, through each other's relayed addresses, which
    /// the relay connects internally.
    #[serde(default)]
    pub allow_private: bool,
    /// Relay to loopback addresses. Only for tests: it exposes services on the server itself.
    #[serde(default)]
    pub allow_loopback: bool,
    /// Networks always allowed (`"10.1.0.0/16"`), checked before everything else.
    #[serde(default)]
    pub allow: Vec<crate::turn::Cidr>,
    /// Networks never relayed to.
    #[serde(default)]
    pub deny: Vec<crate::turn::Cidr>,
}

impl Default for TurnSection {
    fn default() -> Self {
        TurnSection {
            enabled: true,
            listen: default_turn_listen(),
            public_host: None,
            external_ip: None,
            relay_min: default_relay_min(),
            relay_max: default_relay_max(),
            credential_hours: default_credential_hours(),
            quota: TurnQuota::default(),
            peers: TurnPeers::default(),
        }
    }
}

fn yes() -> bool {
    true
}
fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/quark")
}
fn default_cert_dir() -> PathBuf {
    PathBuf::from("/etc/quark/certs")
}
fn default_log() -> String {
    "info".into()
}
fn addrs(port: u16) -> Vec<SocketAddr> {
    vec![SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port))]
}
fn default_c2s() -> Vec<SocketAddr> {
    addrs(5222)
}
fn default_c2s_tls() -> Vec<SocketAddr> {
    addrs(5223)
}
fn default_s2s() -> Vec<SocketAddr> {
    addrs(5269)
}
fn default_s2s_tls() -> Vec<SocketAddr> {
    addrs(5270)
}
fn default_http() -> Vec<SocketAddr> {
    addrs(5280)
}
fn default_c2s_stanza() -> u64 {
    256 * 1024
}
fn default_s2s_stanza() -> u64 {
    512 * 1024
}
fn default_c2s_rate() -> u64 {
    64 * 1024
}
fn default_auth_timeout() -> u64 {
    60
}
fn default_resume() -> u64 {
    600
}
fn default_queue() -> usize {
    10_000
}
fn default_sessions() -> usize {
    64
}
fn default_auth_failures() -> u32 {
    10
}
fn default_registrations() -> u32 {
    5
}
fn default_s2s_idle() -> u64 {
    900
}
fn default_s2s_retry() -> u64 {
    60
}
fn default_s2s_incoming() -> usize {
    2000
}
fn default_s2s_timeout() -> u64 {
    30
}
fn default_turn_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 3478))
}
fn default_relay_min() -> u16 {
    49160
}
fn default_relay_max() -> u16 {
    49200
}
fn default_credential_hours() -> u32 {
    24
}
fn default_turn_allocations() -> usize {
    1000
}
fn default_turn_per_user() -> usize {
    16
}
fn default_turn_kbps() -> u32 {
    10_000
}
fn default_turn_lifetime() -> u32 {
    3600
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("couldn't read {path}: {source}")]
    Read { path: PathBuf, source: std::io::Error },
    #[error("{message}")]
    Parse { message: String, line: Option<usize> },
    #[error("{0}")]
    Invalid(String),
}

impl ConfigError {
    /// The 1-based line the problem is on, when known.
    pub fn line(&self) -> Option<usize> {
        match self {
            ConfigError::Parse { line, .. } => *line,
            _ => None,
        }
    }
}

impl Config {
    /// Parses and checks config text. `path` is only recorded.
    pub fn parse(text: &str, path: &Path) -> Result<Config, ConfigError> {
        let mut cfg: Config = toml::from_str(text).map_err(|e| {
            let line = e.span().map(|s| text[..s.start.min(text.len())].matches('\n').count() + 1);
            ConfigError::Parse { message: e.message().to_string(), line }
        })?;
        cfg.path = path.to_path_buf();
        cfg.normalize()?;
        Ok(cfg)
    }

    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read { path: path.to_path_buf(), source })?;
        Config::parse(&text, path)
    }

    /// Lowercases domains and admin JIDs and checks they're valid and unique.
    fn normalize(&mut self) -> Result<(), ConfigError> {
        let mut seen = std::collections::HashSet::new();
        for h in &mut self.hosts {
            let d = quark_core::Jid::domain_jid(&h.domain)
                .map_err(|e| ConfigError::Invalid(format!("\"{}\" isn't a valid domain ({e}).", h.domain)))?;
            h.domain = d.domain().to_string();
            if !seen.insert(h.domain.clone()) {
                return Err(ConfigError::Invalid(format!("{} is listed twice.", h.domain)));
            }
            for a in &mut h.admins {
                let j = quark_core::Jid::parse(a).map_err(|_| ConfigError::Invalid(format!("Admin \"{a}\" isn't a valid address.")))?;
                if j.node().is_none() {
                    return Err(ConfigError::Invalid(format!("Admin \"{a}\" needs a name before the @.")));
                }
                *a = j.to_bare().to_string();
            }
        }
        let routes = std::mem::take(&mut self.s2s.routes);
        for (d, target) in routes {
            let domain = quark_core::Jid::domain_jid(&d)
                .map_err(|e| ConfigError::Invalid(format!("s2s.routes: \"{d}\" isn't a valid domain ({e}).")))?;
            crate::s2s::Target::parse_route(&target).map_err(|e| ConfigError::Invalid(format!("s2s.routes.\"{d}\": {e}")))?;
            self.s2s.routes.insert(domain.domain().to_string(), target);
        }
        for b in &mut self.s2s.blocked {
            *b = b.trim().trim_end_matches('.').to_ascii_lowercase();
        }
        if self.turn.relay_min > self.turn.relay_max {
            return Err(ConfigError::Invalid("turn.relay_min is above turn.relay_max.".into()));
        }
        if self.turn.credential_hours == 0 || self.turn.credential_hours > 24 * 30 {
            return Err(ConfigError::Invalid("turn.credential_hours must be between 1 and 720.".into()));
        }
        if self.turn.quota.max_lifetime_secs < 600 {
            return Err(ConfigError::Invalid("turn.quota.max_lifetime_secs must be at least 600.".into()));
        }
        Ok(())
    }

    /// Applies environment overrides, for containers: `QUARK_DOMAIN` (comma separated) adds
    /// domains, `QUARK_ADMINS` adds admins to them, `QUARK_DATA_DIR` moves the data.
    pub fn apply_env(&mut self, env: impl Fn(&str) -> Option<String>) -> Result<(), ConfigError> {
        if let Some(dir) = env("QUARK_DATA_DIR").filter(|s| !s.is_empty()) {
            self.server.data_dir = PathBuf::from(dir);
        }
        if let Some(domains) = env("QUARK_DOMAIN") {
            for d in domains.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let d = d.to_ascii_lowercase();
                if !self.hosts.iter().any(|h| h.domain == d) {
                    self.hosts.push(HostConfig { domain: d, admins: Vec::new(), settings: None });
                }
            }
        }
        if let Some(admins) = env("QUARK_ADMINS") {
            for a in admins.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let Ok(j) = quark_core::Jid::parse(a) else { continue };
                if let Some(h) = self.hosts.iter_mut().find(|h| h.domain == j.domain()) {
                    let bare = j.to_bare().to_string();
                    if !h.admins.contains(&bare) {
                        h.admins.push(bare);
                    }
                }
            }
        }
        self.normalize()
    }

    pub fn host(&self, domain: &str) -> Option<&HostConfig> {
        self.hosts.iter().find(|h| h.domain == domain)
    }

    pub fn is_admin(&self, bare: &str) -> bool {
        self.hosts.iter().any(|h| h.admins.iter().any(|a| a == bare))
    }

    /// The config file a fresh install starts with.
    pub fn starter(domains: &[String], admins: &[String]) -> String {
        let mut s = String::from(
            "# Quark, the XMPP server. Chat settings (sign-up, history, group chats, files, calls)\n\
             # are changed live with `quark ctl` or Gluon; this file is for the server itself.\n\
             # Every key is optional. See docs/config.md for the full list.\n\n\
             [server]\ndata_dir = \"/var/lib/quark\"\nlog = \"info\"\n\n\
             [tls]\ncert_dir = \"/etc/quark/certs\"\n\n",
        );
        for d in domains {
            let mine: Vec<String> = admins.iter().filter(|a| a.ends_with(&format!("@{d}"))).map(|a| format!("\"{a}\"")).collect();
            s.push_str(&format!("[[host]]\ndomain = \"{d}\"\nadmins = [{}]\n\n", mine.join(", ")));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_uses_defaults() {
        let c = Config::parse("", Path::new("x")).unwrap();
        assert_eq!(c.listen.c2s[0].port(), 5222);
        assert!(c.tls.require_c2s);
    }

    #[test]
    fn hosts_are_normalized() {
        let c =
            Config::parse("[[host]]\ndomain = \"Chat.Example.COM\"\nadmins = [\"Admin@Chat.Example.com/x\"]\n", Path::new("x")).unwrap();
        assert_eq!(c.hosts[0].domain, "chat.example.com");
        assert_eq!(c.hosts[0].admins[0], "admin@chat.example.com");
    }

    #[test]
    fn errors_have_lines() {
        let e = Config::parse("[server]\nlog = \"info\"\nbogus = 1\n", Path::new("x")).unwrap_err();
        assert_eq!(e.line(), Some(3));
    }

    #[test]
    fn env_adds_domains_and_admins() {
        let mut c = Config::parse("", Path::new("x")).unwrap();
        c.apply_env(|k| match k {
            "QUARK_DOMAIN" => Some("a.test, b.test".into()),
            "QUARK_ADMINS" => Some("root@a.test".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(c.hosts.len(), 2);
        assert_eq!(c.hosts[0].admins, vec!["root@a.test".to_string()]);
    }

    #[test]
    fn s2s_routes_are_checked() {
        let c = Config::parse("[s2s.routes]\n\"B.Test\" = \"127.0.0.1:5269\"\n", Path::new("x")).unwrap();
        assert_eq!(c.s2s.routes.get("b.test").map(String::as_str), Some("127.0.0.1:5269"));
        assert!(Config::parse("[s2s.routes]\n\"b.test\" = \"nowhere\"\n", Path::new("x")).is_err());
    }

    #[test]
    fn starter_parses() {
        let s = Config::starter(&["a.test".into()], &["me@a.test".into()]);
        let c = Config::parse(&s, Path::new("x")).unwrap();
        assert_eq!(c.hosts[0].admins, vec!["me@a.test".to_string()]);
    }
}
