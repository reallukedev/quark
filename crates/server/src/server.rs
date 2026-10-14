//! The server: domains, their live settings, components, modules and shared services.

use std::any::{Any, TypeId};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use parking_lot::RwLock;
use quark_core::stanza::IqType;
use quark_core::{Element, Jid, StanzaError};
use tokio::sync::{oneshot, watch};

use crate::accounts::{Accounts, Role};
use crate::config::Config;
use crate::db::{params, Db, DbError, Migration, OptionalExtension};
use crate::modules::{Component, Event, IqTarget, Module};
use crate::sessions::Sessions;
use crate::settings::Settings;
use crate::tls::CertStore;

pub static MIGRATION: Migration = Migration {
    module: "server",
    steps: &["CREATE TABLE host_settings (domain TEXT PRIMARY KEY, json TEXT NOT NULL, updated INTEGER NOT NULL) WITHOUT ROWID;
              CREATE TABLE kv (scope TEXT NOT NULL, key TEXT NOT NULL, value BLOB NOT NULL, PRIMARY KEY (scope, key)) WITHOUT ROWID;"],
};

/// One domain we serve.
pub struct Host {
    pub domain: String,
    /// The domain as a JID, ready to use as a `from`.
    pub jid: Jid,
    settings: RwLock<Arc<Settings>>,
    /// Admins from the config file.
    config_admins: RwLock<Vec<String>>,
    /// Accounts with the admin role (set through the admin API), cached for quick checks.
    role_admins: RwLock<HashSet<String>>,
}

impl std::fmt::Debug for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Host").field("domain", &self.domain).finish_non_exhaustive()
    }
}

impl Host {
    /// The current settings. Cheap: an `Arc` clone.
    pub fn settings(&self) -> Arc<Settings> {
        self.settings.read().clone()
    }

    pub fn config_admins(&self) -> Vec<String> {
        self.config_admins.read().clone()
    }

    /// Admin in the config file or by role.
    pub fn is_admin_jid(&self, j: &Jid) -> bool {
        if j.domain() != self.domain {
            return false;
        }
        let bare = j.to_bare().to_string();
        self.config_admins.read().contains(&bare) || j.node().is_some_and(|n| self.role_admins.read().contains(n))
    }

    pub fn set_role_cache(&self, user: &str, role: Role) {
        let mut r = self.role_admins.write();
        match role {
            Role::Admin => r.insert(user.to_string()),
            Role::Member => r.remove(user),
        };
    }
}

/// Where a domain leads.
pub enum Dest {
    Local(Arc<Host>),
    Component(Arc<dyn Component>),
    Remote,
}

/// Sends stanzas to other servers. Provided by the s2s module.
pub trait Remote: Send + Sync {
    /// Queues `stanza` for `to_domain`, sent from `from_domain`. Errors come back as stanzas.
    fn send(&self, from_domain: &str, to_domain: &str, stanza: Element);
    /// (incoming, outgoing) links.
    fn counts(&self) -> (usize, usize);
    /// The links that are up, for status pages.
    fn links(&self) -> Vec<crate::s2s::LinkInfo> {
        Vec::new()
    }
}

#[derive(Default)]
pub struct Stats {
    pub stanzas_in: AtomicU64,
    pub stanzas_out: AtomicU64,
    pub c2s_connections: AtomicU64,
    pub auth_failures: AtomicU64,
}

/// IQs the server sent and is waiting on, by id, with the JID that has to answer.
#[derive(Default)]
struct Pending {
    map: parking_lot::Mutex<HashMap<String, (Jid, oneshot::Sender<Element>)>>,
}

/// Whether an answer from `from` can be the reply to a request sent to `asked` (RFC 6120
/// §8.2.3: the reply comes from the entity asked). Asking an account's bare JID, any of its
/// devices may answer for it.
fn answers_for(asked: &Jid, from: &Jid) -> bool {
    from == asked || (asked.is_bare() && asked.node().is_some() && from.to_bare() == *asked)
}

pub struct Server {
    config: RwLock<Arc<Config>>,
    hosts: RwLock<HashMap<String, Arc<Host>>>,
    components: RwLock<HashMap<String, Arc<dyn Component>>>,
    pub db: Db,
    pub accounts: Accounts,
    pub sessions: Sessions,
    pub certs: Arc<CertStore>,
    pub fast_tokens: crate::c2s::FastTokens,
    pub auth_limiter: crate::c2s::AuthLimiter,
    /// Client connections still signing in, over every transport.
    pub preauth: Arc<crate::c2s::PreAuth>,
    pub modules: Vec<Arc<dyn Module>>,
    iq_table: HashMap<IqTarget, HashMap<&'static str, Arc<dyn Module>>>,
    remote: OnceLock<Arc<dyn Remote>>,
    pending: Pending,
    pub stats: Stats,
    /// The built-in call relay, once started.
    pub turn: crate::turn::TurnState,
    pub started_at: i64,
    shutdown: watch::Sender<bool>,
    /// Per-server module state (caches, timers), by type; see [`Server::ext`].
    extensions: parking_lot::Mutex<HashMap<TypeId, Arc<dyn Any + Send + Sync>>>,
}

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error(transparent)]
    Db(#[from] DbError),
    #[error(transparent)]
    Tls(#[from] crate::tls::TlsError),
    #[error("{0}")]
    Other(String),
}

impl Server {
    /// Opens storage, loads every domain and module. Listeners are started separately.
    pub fn new(config: Config, db: Db) -> Result<Arc<Server>, StartError> {
        let modules = crate::modules::all();
        let mut migrations: Vec<&Migration> = vec![&MIGRATION, &crate::accounts::MIGRATION, &crate::c2s::fast::MIGRATION];
        for m in &modules {
            migrations.extend(m.migrations());
        }
        db.migrate(&migrations)?;

        let mut iq_table: HashMap<IqTarget, HashMap<&'static str, Arc<dyn Module>>> = HashMap::new();
        for m in &modules {
            for (ns, target) in m.iq_namespaces() {
                if let Some(prev) = iq_table.entry(*target).or_default().insert(*ns, m.clone()) {
                    return Err(StartError::Other(format!("{} and {} both answer {ns}", prev.name(), m.name())));
                }
            }
        }

        let certs = CertStore::new(&config.tls.cert_dir, &config.server.data_dir, config.tls.self_signed_fallback);
        let (shutdown, _) = watch::channel(false);
        let srv = Arc::new(Server {
            accounts: Accounts::new(db.clone()),
            fast_tokens: crate::c2s::FastTokens::new(db.clone()),
            auth_limiter: crate::c2s::AuthLimiter::default(),
            preauth: Arc::default(),
            sessions: Sessions::default(),
            config: RwLock::new(Arc::new(config)),
            hosts: RwLock::new(HashMap::new()),
            components: RwLock::new(HashMap::new()),
            db,
            certs,
            modules,
            iq_table,
            remote: OnceLock::new(),
            pending: Pending::default(),
            stats: Stats::default(),
            turn: crate::turn::TurnState::default(),
            started_at: quark_core::time::now_ms(),
            shutdown,
            extensions: parking_lot::Mutex::new(HashMap::new()),
        });
        srv.load_hosts()?;
        Ok(srv)
    }

    /// Starts module background work and the certificate watcher.
    pub fn start(self: &Arc<Self>) {
        self.certs.watch();
        for m in &self.modules {
            m.start(self);
        }
    }

    pub fn config(&self) -> Arc<Config> {
        self.config.read().clone()
    }

    /// Swaps in a new config (from `reload` or `config.set`): domains, admins, certificates.
    pub fn set_config(self: &Arc<Self>, config: Config) -> Result<(), StartError> {
        *self.config.write() = Arc::new(config);
        self.load_hosts()
    }

    fn load_hosts(self: &Arc<Self>) -> Result<(), StartError> {
        let cfg = self.config();
        let mut next = HashMap::new();
        for hc in &cfg.hosts {
            let stored: Option<String> = self.db.write_blocking(|t| {
                t.query_row("SELECT json FROM host_settings WHERE domain = ?1", [&hc.domain], |r| r.get(0)).optional()
            })?;
            let settings = match stored.and_then(|j| serde_json::from_str::<Settings>(&j).ok()) {
                // Saved before hosts were stored normalized: route by the normalized form.
                Some(mut s) => {
                    let _ = s.normalize_hosts();
                    s
                }
                None => {
                    let mut s = Settings::defaults(&hc.domain);
                    if let Some(p) = &hc.settings {
                        s = s.merged(p);
                    }
                    s.validate(&hc.domain).map_err(StartError::Other)?;
                    let json = serde_json::to_string(&s).map_err(|e| StartError::Other(e.to_string()))?;
                    let now = quark_core::time::now_ms();
                    self.db.write_blocking(|t| {
                        t.execute("INSERT INTO host_settings (domain, json, updated) VALUES (?1, ?2, ?3)", params![hc.domain, json, now])
                    })?;
                    s
                }
            };
            let admins: HashSet<String> = self.db.write_blocking(|t| {
                let mut st = t.prepare("SELECT user FROM accounts WHERE host = ?1 AND role = 'admin'")?;
                let rows = st.query_map([&hc.domain], |r| r.get(0))?;
                rows.collect()
            })?;
            let host = match self.hosts.read().get(&hc.domain) {
                // Keep the same Host so sessions holding it see the changes.
                Some(h) => {
                    *h.config_admins.write() = hc.admins.clone();
                    *h.role_admins.write() = admins;
                    h.clone()
                }
                None => Arc::new(Host {
                    jid: Jid::domain_jid(&hc.domain).map_err(|e| StartError::Other(e.to_string()))?,
                    domain: hc.domain.clone(),
                    settings: RwLock::new(Arc::new(settings)),
                    config_admins: RwLock::new(hc.admins.clone()),
                    role_admins: RwLock::new(admins),
                }),
            };
            next.insert(hc.domain.clone(), host);
        }
        *self.hosts.write() = next;
        self.rebuild_components();
        let mut names: Vec<String> = Vec::new();
        for h in self.hosts() {
            names.push(h.domain.clone());
        }
        names.extend(self.components.read().keys().cloned());
        self.certs.set_domains(names)?;
        Ok(())
    }

    fn rebuild_components(self: &Arc<Self>) {
        let mut map: HashMap<String, Arc<dyn Component>> = HashMap::new();
        for h in self.hosts() {
            for m in &self.modules {
                for c in m.components(self, &h) {
                    map.insert(c.domain().to_string(), c);
                }
            }
        }
        *self.components.write() = map;
    }

    pub fn hosts(&self) -> Vec<Arc<Host>> {
        let mut v: Vec<Arc<Host>> = self.hosts.read().values().cloned().collect();
        v.sort_by(|a, b| a.domain.cmp(&b.domain));
        v
    }

    pub fn host(&self, domain: &str) -> Option<Arc<Host>> {
        self.hosts.read().get(domain).cloned()
    }

    pub fn component(&self, domain: &str) -> Option<Arc<dyn Component>> {
        self.components.read().get(domain).cloned()
    }

    /// The local domain a component belongs to (`rooms.example.com` → `example.com`'s Host).
    pub fn component_host(&self, domain: &str) -> Option<Arc<Host>> {
        let hosts = self.hosts.read();
        hosts
            .values()
            .find(|h| {
                let s = h.settings();
                (s.groups.on && s.groups.host == domain) || (s.files.on && s.files.host == domain)
            })
            .cloned()
    }

    pub fn resolve(&self, domain: &str) -> Dest {
        if let Some(h) = self.host(domain) {
            return Dest::Local(h);
        }
        if let Some(c) = self.component(domain) {
            return Dest::Component(c);
        }
        Dest::Remote
    }

    /// Is this one of our domains or components?
    pub fn is_local(&self, domain: &str) -> bool {
        !matches!(self.resolve(domain), Dest::Remote)
    }

    /// Changes a domain's settings live: saved, then every part of the server sees them.
    pub async fn set_settings(self: &Arc<Self>, domain: &str, mut s: Settings) -> Result<(), String> {
        let host = self.host(domain).ok_or_else(|| format!("{domain} isn't a domain on this server."))?;
        s.validate(domain)?;
        for other in self.hosts() {
            if other.domain == domain {
                continue;
            }
            let o = other.settings();
            for (on, h) in [(s.groups.on, &s.groups.host), (s.files.on, &s.files.host)] {
                if on && (self.host(h).is_some() || (o.groups.on && &o.groups.host == h) || (o.files.on && &o.files.host == h)) {
                    return Err(format!("{h} is already used by {}.", other.domain));
                }
            }
        }
        let json = serde_json::to_string(&s).map_err(|e| e.to_string())?;
        let d = domain.to_string();
        let now = quark_core::time::now_ms();
        self.db
            .write(move |t| t.execute("INSERT INTO host_settings (domain, json, updated) VALUES (?1, ?2, ?3) ON CONFLICT(domain) DO UPDATE SET json = excluded.json, updated = excluded.updated", params![d, json, now]))
            .await
            .map_err(|e| e.to_string())?;
        *host.settings.write() = Arc::new(s);
        self.rebuild_components();
        let mut names: Vec<String> = self.hosts().iter().map(|h| h.domain.clone()).collect();
        names.extend(self.components.read().keys().cloned());
        let certs = self.certs.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || certs.set_domains(names)).await.map_err(|e| e.to_string())? {
            tracing::warn!(error = %e, "couldn't prepare certificates for the new settings");
        }
        self.emit(&Event::SettingsChanged { domain: domain.to_string() }).await;
        Ok(())
    }

    pub async fn emit(self: &Arc<Self>, ev: &Event) {
        for m in &self.modules {
            m.on_event(self, ev).await;
        }
    }

    pub fn iq_module(&self, ns: &str, target: IqTarget) -> Option<&Arc<dyn Module>> {
        self.iq_table.get(&target)?.get(ns)
    }

    pub fn set_remote(&self, r: Arc<dyn Remote>) {
        let _ = self.remote.set(r);
    }

    pub fn remote(&self) -> Option<&Arc<dyn Remote>> {
        self.remote.get()
    }

    /// Sends an IQ from the server and waits for the answer (result or error).
    pub async fn request(self: &Arc<Self>, mut iq: Element, timeout: Duration) -> Result<Element, StanzaError> {
        // Without a `to` the router sends it to the sender's domain (see `router::route`).
        let asked = match quark_core::stanza::jid_attr(&iq, "to") {
            Ok(Some(to)) => to,
            _ => match quark_core::stanza::jid_attr(&iq, "from").ok().flatten().and_then(|f| Jid::domain_jid(f.domain()).ok()) {
                Some(d) => d,
                None => return Err(StanzaError::internal()),
            },
        };
        let id = quark_core::new_id();
        iq.set_attr("id", id.clone());
        let (tx, rx) = oneshot::channel();
        self.pending.map.lock().insert(id.clone(), (asked, tx));
        self.route(iq).await;
        let r = tokio::time::timeout(timeout, rx).await;
        self.pending.map.lock().remove(&id);
        match r {
            Ok(Ok(el)) if quark_core::stanza::iq_type(&el) == Some(IqType::Result) => Ok(el),
            Ok(Ok(el)) => Err(StanzaError::from_stanza(&el).unwrap_or_else(StanzaError::internal)),
            _ => Err(StanzaError::new(quark_core::Condition::RemoteServerTimeout)),
        }
    }

    /// Hands an IQ result or error from `from` to whoever is waiting on it. False when nobody
    /// was, or when `from` isn't who was asked: knowing (or guessing) an id isn't enough to
    /// answer for someone else.
    pub(crate) fn answer_pending(&self, from: &Jid, iq: &Element) -> bool {
        let Some(id) = iq.attr("id") else { return false };
        let tx = {
            let mut map = self.pending.map.lock();
            match map.get(id) {
                Some((asked, _)) if answers_for(asked, from) => map.remove(id).map(|(_, tx)| tx),
                _ => None,
            }
        };
        match tx {
            Some(tx) => tx.send(iq.clone()).is_ok(),
            None => {
                tracing::debug!(%from, id, "ignoring an IQ answer nobody here waits for");
                false
            }
        }
    }

    /// The state of type `T` for this server, made on first use. Modules are unit structs shared
    /// by every server in the process (tests run several), so state that belongs to one server
    /// lives here.
    pub fn ext<T: Default + Send + Sync + 'static>(&self) -> Arc<T> {
        let any = self.extensions.lock().entry(TypeId::of::<T>()).or_insert_with(|| Arc::new(T::default())).clone();
        any.downcast::<T>().expect("each slot holds the type it is keyed by")
    }

    pub fn shutdown_signal(&self) -> watch::Receiver<bool> {
        self.shutdown.subscribe()
    }

    pub fn shut_down(&self) {
        let _ = self.shutdown.send(true);
    }

    pub fn count_in(&self) {
        self.stats.stanzas_in.fetch_add(1, Ordering::Relaxed);
    }

    pub fn count_out(&self) {
        self.stats.stanzas_out.fetch_add(1, Ordering::Relaxed);
    }

    // ---------------------------------------------------------------- small key-value store

    /// A value in the server's key-value store (for modules with tiny state).
    pub async fn kv_get(&self, scope: &str, key: &str) -> Result<Option<Vec<u8>>, DbError> {
        let (s, k) = (scope.to_string(), key.to_string());
        self.db
            .read(move |c| c.query_row("SELECT value FROM kv WHERE scope = ?1 AND key = ?2", params![s, k], |r| r.get(0)).optional())
            .await
    }

    pub async fn kv_set(&self, scope: &str, key: &str, value: Option<Vec<u8>>) -> Result<(), DbError> {
        let (s, k) = (scope.to_string(), key.to_string());
        self.db
            .write(move |t| match value {
                Some(v) => t.execute(
                    "INSERT INTO kv (scope, key, value) VALUES (?1, ?2, ?3) ON CONFLICT(scope, key) DO UPDATE SET value = excluded.value",
                    params![s, k, v],
                ),
                None => t.execute("DELETE FROM kv WHERE scope = ?1 AND key = ?2", params![s, k]),
            })
            .await
            .map(|_| ())
    }
}
