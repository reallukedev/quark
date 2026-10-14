//! Server-to-server links (RFC 6120, XEP-0220 dialback, XEP-0368 direct TLS).
//!
//! Outgoing: one link per (local domain, remote domain), set up on the first stanza while later
//! ones queue (bounded); DNS SRV or a configured route; TLS with certificate checks, then SASL
//! EXTERNAL (XEP-0178) when our certificate is trusted and the peer offers it, else dialback
//! over TLS. Stream management (XEP-0198) when offered, so stanzas a dropped link never
//! confirmed go out again on the next one. Failures bounce queued stanzas and are remembered
//! briefly so the next ones fail fast. Idle links close.
//!
//! Incoming: STARTTLS (required with `s2s.require_tls`) or direct TLS, SASL EXTERNAL against the
//! peer's client certificate, dialback (verified by calling the sender's authoritative server
//! back, or at once when its certificate is valid), and checks on every stanza: the sender's
//! domain is one this stream proved, the recipient is ours.

pub mod dialback;
pub mod dns;
mod incoming;
mod outgoing;
pub mod pki;
mod stream;

pub use dns::Target;

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use hickory_resolver::TokioResolver;
use parking_lot::{Mutex, RwLock};
use quark_core::{Condition, Element, StanzaError};
use rustls::sign::CertifiedKey;
use serde::Serialize;
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::sync::{Notify, Semaphore};

use crate::config::Config;
use crate::server::{Remote, Server};
use crate::tls::CertStore;
use pki::Pki;

/// ALPN protocol for direct TLS between servers (XEP-0368).
const ALPN: &[u8] = b"xmpp-server";
/// Unreachable domains remembered at most (the rest are forgotten early).
const MAX_UNREACHABLE: usize = 10_000;
/// Times stanzas from a dropped link are sent again before they bounce.
const MAX_ATTEMPTS: u8 = 2;
/// Incoming links one remote domain may have to one of our domains. A server needs one (a few
/// in a cluster); past this the oldest is closed, so one domain can't fill `max_incoming`
/// and a server that reconnects after losing its old connection isn't locked out by it.
const MAX_LINKS_PER_PAIR: usize = 8;
/// How often trusted certificate files are read again to notice them being replaced.
const TRUST_RECHECK: Duration = Duration::from_secs(5);
/// Client TLS configs kept (one per local domain and kind of TLS).
const MAX_CLIENT_CONFIGS: usize = 1024;

/// A link, for status pages and tests.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkInfo {
    /// "in" or "out".
    pub direction: &'static str,
    pub local: String,
    pub remote: String,
    /// How the remote proved who it is: "certificate" (SASL EXTERNAL or a valid certificate
    /// with dialback) or "dialback".
    pub auth: &'static str,
    pub secure: bool,
    /// Stream management (XEP-0198) is on.
    pub sm: bool,
    pub since: i64,
}

/// TLS material for links: the trust store and the configs made from it.
struct Tls {
    pki: Arc<Pki>,
    starttls: Arc<rustls::ServerConfig>,
    direct: Arc<rustls::ServerConfig>,
    /// Client configs by (local domain, direct TLS). Built once rather than per connection:
    /// checking our own certificate isn't free, and rustls keeps its session cache in the
    /// config, so only a shared one lets the next connection resume the TLS session. A new
    /// trust store makes a new `Tls`, which starts this afresh.
    clients: Mutex<HashMap<(String, bool), ClientTls>>,
}

/// A cached client config and the certificate it was made for.
struct ClientTls {
    /// The certificate the store had for the domain then; a reloaded one is a new `Arc`.
    from_store: Option<Arc<CertifiedKey>>,
    /// That certificate, when it's one others can verify (the one we present).
    own: Option<Arc<CertifiedKey>>,
    config: Arc<rustls::ClientConfig>,
}

impl Tls {
    fn new(pki: Pki, certs: &Arc<CertStore>) -> anyhow::Result<Tls> {
        let starttls = pki.server_config(certs, &[])?;
        let direct = pki.server_config(certs, &[ALPN])?;
        Ok(Tls { pki: Arc::new(pki), starttls, direct, clients: Mutex::new(HashMap::new()) })
    }

    /// The client config for links from `local`, and our certificate when others can verify it.
    fn client(
        &self,
        certs: &CertStore,
        local: &str,
        direct_tls: bool,
    ) -> Result<(Arc<rustls::ClientConfig>, Option<Arc<CertifiedKey>>), rustls::Error> {
        let current = certs.certified_key(local);
        let key = (local.to_string(), direct_tls);
        let same = |c: &ClientTls| match (&c.from_store, &current) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        };
        if let Some(c) = self.clients.lock().get(&key).filter(|c| same(c)) {
            return Ok((c.config.clone(), c.own.clone()));
        }
        let own = current.clone().filter(|ck| self.pki.valid_for(&ck.cert, local));
        let alpn: &[&[u8]] = if direct_tls { &[ALPN] } else { &[] };
        let config = self.pki.client_config(own.clone(), alpn)?;
        let mut clients = self.clients.lock();
        if clients.len() >= MAX_CLIENT_CONFIGS {
            clients.clear();
        }
        clients.insert(key, ClientTls { from_store: current, own: own.clone(), config: config.clone() });
        Ok((config, own))
    }
}

/// Trusted certificate files and a digest of their contents (None when unreadable).
type TrustState = (Vec<PathBuf>, Option<[u8; 32]>);

/// What one of our domains takes from other servers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Inbound {
    All,
    /// Federation is off but push notifications still go out (XEP-0357): only the app
    /// servers' answers to them come in.
    Answers,
    /// Federation is off: nothing.
    Nothing,
}

/// The domain's federation settings (a group chat or upload domain follows its host's).
fn inbound(srv: &Server, domain: &str) -> Inbound {
    match srv.host(domain).or_else(|| srv.component_host(domain)) {
        Some(h) => {
            let s = h.settings();
            if s.federation {
                Inbound::All
            } else if s.push {
                Inbound::Answers
            } else {
                Inbound::Nothing
            }
        }
        // Components configured on their own.
        None => Inbound::All,
    }
}

struct OutLink {
    id: u64,
    tx: mpsc::Sender<Element>,
}

/// Federation state shared by every link.
pub struct S2s {
    me: Weak<S2s>,
    srv: Weak<Server>,
    /// Dialback key secret (XEP-0185).
    secret: Vec<u8>,
    resolver: TokioResolver,
    tls: RwLock<Arc<Tls>>,
    out: Mutex<HashMap<(String, String), OutLink>>,
    /// (local, remote) pairs that failed recently: until when, and the error to bounce with.
    unreachable: Mutex<HashMap<(String, String), (Instant, StanzaError)>>,
    links: Mutex<HashMap<(u64, String), LinkInfo>>,
    /// Wakes an incoming link to close it, when a newer one from the same domain replaces it.
    evict: Mutex<HashMap<u64, Arc<Notify>>>,
    incoming: AtomicUsize,
    outgoing: AtomicUsize,
    in_slots: Arc<Semaphore>,
    /// Incoming connections per address (IPv6: per /64), so one peer can't take every slot.
    per_ip: Mutex<HashMap<IpAddr, usize>>,
    /// When the trusted certificate files were last read to look for changes.
    trust_checked: Mutex<Instant>,
    /// The trust store files and contents that last failed to load, so the same broken state
    /// isn't retried (and warned about) on every connection.
    trust_failed: Mutex<Option<TrustState>>,
    ids: AtomicU64,
}

impl std::fmt::Debug for S2s {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S2s").finish_non_exhaustive()
    }
}

/// Starts the server-to-server listeners; returns the addresses bound: the STARTTLS ones
/// (`listen.s2s`) first, then the direct TLS ones (`listen.s2s_tls`).
pub async fn start(srv: &Arc<Server>) -> anyhow::Result<Vec<std::net::SocketAddr>> {
    let cfg = srv.config();
    let secret = secret(srv, &cfg).await?;
    let paths = cfg.s2s.trusted_certs.clone();
    let pki = tokio::task::spawn_blocking(move || Pki::load(&paths)).await?.map_err(anyhow::Error::msg).context("s2s.trusted_certs")?;
    let tls = Tls::new(pki, &srv.certs)?;
    let resolver = resolver().context("DNS resolver")?;
    let s2s = Arc::new_cyclic(|me| S2s {
        me: me.clone(),
        srv: Arc::downgrade(srv),
        secret,
        resolver,
        tls: RwLock::new(Arc::new(tls)),
        out: Mutex::new(HashMap::new()),
        unreachable: Mutex::new(HashMap::new()),
        links: Mutex::new(HashMap::new()),
        evict: Mutex::new(HashMap::new()),
        incoming: AtomicUsize::new(0),
        outgoing: AtomicUsize::new(0),
        in_slots: Arc::new(Semaphore::new(cfg.s2s.max_incoming.max(1))),
        per_ip: Mutex::new(HashMap::new()),
        trust_checked: Mutex::new(Instant::now()),
        trust_failed: Mutex::new(None),
        ids: AtomicU64::new(1),
    });
    let mut bound = Vec::new();
    for (addrs, direct) in [(&cfg.listen.s2s, false), (&cfg.listen.s2s_tls, true)] {
        for addr in addrs.iter().copied() {
            let listener = tokio::net::TcpListener::bind(addr).await.with_context(|| format!("listening on {addr}"))?;
            let local = listener.local_addr()?;
            bound.push(local);
            tokio::spawn(incoming::accept_loop(s2s.clone(), srv.clone(), listener, direct));
        }
    }
    srv.set_remote(s2s);
    Ok(bound)
}

/// The dialback secret: from the config, else made once and kept in the database.
async fn secret(srv: &Arc<Server>, cfg: &Config) -> anyhow::Result<Vec<u8>> {
    if let Some(s) = cfg.s2s.dialback_secret.as_ref().filter(|s| !s.is_empty()) {
        return Ok(s.as_bytes().to_vec());
    }
    if let Some(v) = srv.kv_get("s2s", "dialback-secret").await? {
        if v.len() >= 16 {
            return Ok(v);
        }
    }
    let v: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    srv.kv_set("s2s", "dialback-secret", Some(v.clone())).await?;
    Ok(v)
}

/// The system's DNS servers, with short timeouts: a message shouldn't wait long on a dead
/// resolver. Falls back to public resolvers when the system config can't be read.
fn resolver() -> anyhow::Result<TokioResolver> {
    use hickory_resolver::config::{ResolverConfig, GOOGLE};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    let (config, mut opts) = match hickory_resolver::system_conf::read_system_conf() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "couldn't read the system DNS config; using public resolvers");
            (ResolverConfig::udp_and_tcp(&GOOGLE), Default::default())
        }
    };
    opts.timeout = Duration::from_secs(4);
    opts.attempts = 2;
    Ok(TokioResolver::builder_with_config(config, TokioRuntimeProvider::default()).with_options(opts).build()?)
}

/// Is `domain`, or a domain it's under, in `s2s.blocked`?
pub fn is_blocked(cfg: &Config, domain: &str) -> bool {
    cfg.s2s.blocked.iter().any(|b| !b.is_empty() && (domain == b || domain.strip_suffix(b.as_str()).is_some_and(|p| p.ends_with('.'))))
}

impl S2s {
    fn me(&self) -> Option<Arc<S2s>> {
        self.me.upgrade()
    }

    fn next_id(&self) -> u64 {
        self.ids.fetch_add(1, Ordering::Relaxed)
    }

    /// The current TLS material, rebuilt when `s2s.trusted_certs` changed in the config or one
    /// of its files was rewritten (looked at every [`TRUST_RECHECK`] at most).
    async fn tls(&self, srv: &Arc<Server>) -> Arc<Tls> {
        let cur = self.tls.read().clone();
        let paths = srv.config().s2s.trusted_certs.clone();
        let same_paths = cur.pki.sources == paths;
        let failed_paths = self.trust_failed.lock().as_ref().is_some_and(|(p, _)| *p == paths);
        if same_paths || failed_paths {
            if paths.is_empty() {
                return cur;
            }
            let mut checked = self.trust_checked.lock();
            if checked.elapsed() < TRUST_RECHECK {
                return cur;
            }
            *checked = Instant::now();
        }
        let p = paths.clone();
        // Unreadable files: the load below says why.
        let digest = tokio::task::spawn_blocking(move || Pki::fingerprint(&p)).await.ok().and_then(Result::ok);
        if same_paths && digest == Some(cur.pki.digest) {
            return cur;
        }
        let state = (paths.clone(), digest);
        if self.trust_failed.lock().as_ref() == Some(&state) {
            return cur;
        }
        let built = tokio::task::spawn_blocking(move || Pki::load(&paths)).await;
        let err = match built {
            Ok(Ok(pki)) => match Tls::new(pki, &srv.certs) {
                Ok(t) => {
                    let t = Arc::new(t);
                    *self.tls.write() = t.clone();
                    *self.trust_failed.lock() = None;
                    tracing::info!("federation trust store reloaded");
                    return t;
                }
                Err(e) => format!("couldn't rebuild the federation TLS config: {e}"),
            },
            Ok(Err(e)) => format!("couldn't reload s2s.trusted_certs; keeping the old ones: {e}"),
            Err(e) => format!("reloading s2s.trusted_certs failed: {e}"),
        };
        tracing::warn!(error = %err, "federation trust store not reloaded");
        *self.trust_failed.lock() = Some(state);
        cur
    }

    /// Takes one of the incoming connections `ip` may have, if it has one left.
    fn ip_slot(self: &Arc<Self>, ip: IpAddr, cap: usize) -> Option<IpSlot> {
        let key = ip_key(ip);
        let mut per_ip = self.per_ip.lock();
        let n = per_ip.entry(key).or_insert(0);
        if *n >= cap {
            return None;
        }
        *n += 1;
        Some(IpSlot { s2s: self.clone(), key })
    }

    /// Queues `el` on the link from `local` to `remote`, starting one if needed.
    fn enqueue(&self, srv: &Arc<Server>, local: &str, remote: &str, el: Element) {
        let cfg = srv.config();
        if is_blocked(&cfg, remote) {
            return bounce(srv, el, StanzaError::new(Condition::RemoteServerNotFound).with_text("That server is blocked here."));
        }
        let pair = (local.to_string(), remote.to_string());
        if let Some(err) = self.unreachable_error(&pair) {
            return bounce(srv, el, err);
        }
        let mut out = self.out.lock();
        let el = match out.get(&pair) {
            Some(l) => match l.tx.try_send(el) {
                Ok(()) => return,
                Err(TrySendError::Full(el)) => {
                    drop(out);
                    let text = format!("Too many messages are waiting to go to {remote}.");
                    return bounce(srv, el, StanzaError::new(Condition::ResourceConstraint).with_text(text));
                }
                Err(TrySendError::Closed(el)) => el,
            },
            None => el,
        };
        let Some(me) = self.me() else { return };
        let (tx, rx) = mpsc::channel(cfg.limits.max_queue.max(16));
        // A fresh channel has room.
        let _ = tx.try_send(el);
        let id = self.next_id();
        out.insert(pair, OutLink { id, tx });
        drop(out);
        tokio::spawn(outgoing::run(outgoing::Job {
            s2s: me,
            srv: srv.clone(),
            local: local.to_string(),
            remote: remote.to_string(),
            id,
            rx,
            carry: VecDeque::new(),
            attempt: 0,
        }));
    }

    /// Sends stanzas a link couldn't deliver again on a new link, or bounces them once they've
    /// been tried too often.
    fn requeue(&self, srv: &Arc<Server>, local: &str, remote: &str, mut items: VecDeque<Element>, attempt: u8) {
        if items.is_empty() {
            return;
        }
        if attempt > MAX_ATTEMPTS {
            let err = StanzaError::new(Condition::RemoteServerTimeout).with_text(format!("The connection to {remote} kept failing."));
            for el in items {
                bounce(srv, el, err.clone());
            }
            return;
        }
        let pair = (local.to_string(), remote.to_string());
        let mut out = self.out.lock();
        if let Some(l) = out.get(&pair).filter(|l| !l.tx.is_closed()) {
            // Someone already started a new link: join its queue.
            for el in items {
                if let Err(TrySendError::Full(el) | TrySendError::Closed(el)) = l.tx.try_send(el) {
                    bounce(srv, el, StanzaError::new(Condition::ResourceConstraint));
                }
            }
            return;
        }
        let Some(me) = self.me() else { return };
        let cap = srv.config().limits.max_queue.max(16);
        while items.len() > cap {
            if let Some(el) = items.pop_back() {
                bounce(srv, el, StanzaError::new(Condition::ResourceConstraint));
            }
        }
        let (tx, rx) = mpsc::channel(cap);
        let id = self.next_id();
        out.insert(pair, OutLink { id, tx });
        drop(out);
        tokio::spawn(outgoing::run(outgoing::Job {
            s2s: me,
            srv: srv.clone(),
            local: local.to_string(),
            remote: remote.to_string(),
            id,
            rx,
            carry: items,
            attempt,
        }));
    }

    /// Forgets link `id` so new stanzas start a new one.
    fn remove_out(&self, pair: &(String, String), id: u64) {
        let mut out = self.out.lock();
        if out.get(pair).is_some_and(|l| l.id == id) {
            out.remove(pair);
        }
    }

    fn unreachable_error(&self, pair: &(String, String)) -> Option<StanzaError> {
        let mut u = self.unreachable.lock();
        match u.get(pair) {
            Some((until, err)) if *until > Instant::now() => Some(err.clone()),
            Some(_) => {
                u.remove(pair);
                None
            }
            None => None,
        }
    }

    fn mark_unreachable(&self, pair: (String, String), err: StanzaError, secs: u64) {
        if secs == 0 {
            return;
        }
        let mut u = self.unreachable.lock();
        if u.len() >= MAX_UNREACHABLE {
            let now = Instant::now();
            u.retain(|_, (t, _)| *t > now);
            if u.len() >= MAX_UNREACHABLE {
                u.clear();
            }
        }
        u.insert(pair, (Instant::now() + Duration::from_secs(secs), err));
    }

    fn link_up(&self, id: u64, info: LinkInfo) {
        let counter = if info.direction == "in" { &self.incoming } else { &self.outgoing };
        let mut links = self.links.lock();
        if !links.keys().any(|(i, _)| *i == id) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        // Past the cap for this pair, the oldest incoming link (lowest id) makes way.
        let oldest = (info.direction == "in")
            .then(|| {
                let others: Vec<u64> = links
                    .iter()
                    .filter(|((i, _), l)| *i != id && l.direction == "in" && l.remote == info.remote && l.local == info.local)
                    .map(|((i, _), _)| *i)
                    .collect();
                (others.len() >= MAX_LINKS_PER_PAIR).then(|| others.into_iter().min()).flatten()
            })
            .flatten();
        links.insert((id, info.remote.clone()), info);
        drop(links);
        if let Some(n) = oldest.and_then(|old| self.evict.lock().get(&old).cloned()) {
            n.notify_one();
        }
    }

    /// Registers an incoming link so a newer one can close it; returns what it waits on.
    fn evictable(&self, id: u64) -> Arc<Notify> {
        let n = Arc::new(Notify::new());
        self.evict.lock().insert(id, n.clone());
        n
    }

    /// Stream management came on for link `id` after it was registered.
    fn link_sm(&self, id: u64) {
        for ((i, _), l) in self.links.lock().iter_mut() {
            if *i == id {
                l.sm = true;
            }
        }
    }

    fn link_down(&self, id: u64) {
        self.evict.lock().remove(&id);
        let mut links = self.links.lock();
        let before = links.len();
        let mut dir = None;
        links.retain(|(i, _), l| {
            if *i == id {
                dir = Some(l.direction);
            }
            *i != id
        });
        if links.len() != before {
            let counter = if dir == Some("in") { &self.incoming } else { &self.outgoing };
            counter.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl Remote for S2s {
    fn send(&self, from_domain: &str, to_domain: &str, stanza: Element) {
        if let Some(srv) = self.srv.upgrade() {
            self.enqueue(&srv, from_domain, to_domain, stanza);
        }
    }

    fn counts(&self) -> (usize, usize) {
        (self.incoming.load(Ordering::Relaxed), self.outgoing.load(Ordering::Relaxed))
    }

    fn links(&self) -> Vec<LinkInfo> {
        let mut v: Vec<LinkInfo> = self.links.lock().values().cloned().collect();
        v.sort_by(|a, b| (a.direction, &a.remote, &a.local).cmp(&(b.direction, &b.remote, &b.local)));
        v
    }
}

/// Sends the error for `el` back to its local sender, off the caller's task.
fn bounce(srv: &Arc<Server>, el: Element, err: StanzaError) {
    let srv = srv.clone();
    tokio::spawn(async move { crate::router::bounce(&srv, &el, err).await });
}

/// Holds one of an address's incoming connections until dropped.
pub(super) struct IpSlot {
    s2s: Arc<S2s>,
    key: IpAddr,
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        let mut per_ip = self.s2s.per_ip.lock();
        if let Some(n) = per_ip.get_mut(&self.key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                per_ip.remove(&self.key);
            }
        }
    }
}

/// Incoming connections one address may have open: an eighth of `max_incoming`, so filling
/// them all takes many addresses.
fn per_ip_cap(max_incoming: usize) -> usize {
    (max_incoming / 8).max(1)
}

/// What connections are counted under: the address, or its /64 for IPv6, since one host
/// usually has a whole /64 to pick from.
pub(crate) fn ip_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        v4 => v4,
    }
}

/// How often a link checks its timers, from the idle limit (so short limits in tests work).
fn tick_period(idle_secs: u64) -> Duration {
    Duration::from_millis((idle_secs * 250).clamp(250, 30_000))
}

/// `host:port` of where a stream came from, for logs.
fn peer_str(p: Option<SocketAddr>) -> String {
    p.map(|a| a.to_string()).unwrap_or_else(|| "?".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocking_covers_subdomains() {
        let mut cfg = Config::parse("", std::path::Path::new("x")).unwrap();
        cfg.s2s.blocked = vec!["spam.example".into()];
        assert!(is_blocked(&cfg, "spam.example"));
        assert!(is_blocked(&cfg, "muc.spam.example"));
        assert!(!is_blocked(&cfg, "notspam.example"));
        assert!(!is_blocked(&cfg, "example"));
    }

    #[test]
    fn addresses_are_counted_per_host() {
        assert_eq!(ip_key("10.0.0.1".parse().unwrap()), "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(ip_key("::ffff:10.0.0.1".parse().unwrap()), "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(ip_key("2001:db8:1:2:aaaa::1".parse().unwrap()), ip_key("2001:db8:1:2:bbbb::9".parse().unwrap()));
        assert_ne!(ip_key("2001:db8:1:2::1".parse().unwrap()), ip_key("2001:db8:1:3::1".parse().unwrap()));
        assert_eq!(per_ip_cap(2000), 250);
        assert_eq!(per_ip_cap(3), 1);
    }

    #[test]
    fn client_configs_are_reused_until_our_certificate_changes() {
        let dir = tempfile::tempdir().unwrap();
        let certs = CertStore::new(&dir.path().join("certs"), dir.path(), true);
        certs.set_domains(vec!["a.test".into()]).unwrap();
        let tls = Tls::new(Pki::load(&[]).unwrap(), &certs).unwrap();
        let (first, own) = tls.client(&certs, "a.test", false).unwrap();
        assert!(own.is_none(), "a self-signed certificate isn't presented");
        let (again, _) = tls.client(&certs, "a.test", false).unwrap();
        assert!(Arc::ptr_eq(&first, &again), "the same config, so TLS sessions resume");
        let (direct, _) = tls.client(&certs, "a.test", true).unwrap();
        assert!(!Arc::ptr_eq(&first, &direct));
        assert_eq!(direct.alpn_protocols, [ALPN.to_vec()]);
        // A reloaded certificate gets a new config.
        certs.reload().unwrap();
        let (after, _) = tls.client(&certs, "a.test", false).unwrap();
        assert!(!Arc::ptr_eq(&first, &after));
    }

    #[test]
    fn tick_follows_idle_limit() {
        assert_eq!(tick_period(1), Duration::from_millis(250));
        assert_eq!(tick_period(4), Duration::from_secs(1));
        assert_eq!(tick_period(900), Duration::from_secs(30));
    }
}
