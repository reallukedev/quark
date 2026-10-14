//! Links we open: finding the server, TLS, proving who we are (SASL EXTERNAL or dialback),
//! then a writer actor that batches bursts, keeps the link alive, and closes it when idle.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use quark_core::stanza::iq_type;
use quark_core::{ns, Condition, Element, StanzaError};
use rustls::pki_types::ServerName;
use rustls::sign::CertifiedKey;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use super::dialback;
use super::dns::{self, LookupError, Target};
use super::stream::{self, In, Io, Stream, StreamFailure, Writer};
use super::{LinkInfo, S2s, Tls};
use crate::config::Config;
use crate::server::Server;
use crate::transport::StreamError;

/// How long a peer may take to answer `<enable/>` (XEP-0198).
const SM_ANSWER: Duration = Duration::from_secs(10);
/// Writes between flushes while draining a burst.
const DRAIN_BATCH: usize = 64;
/// Whitespace after this long without writing, so NATs and firewalls keep the flow.
const KEEPALIVE: Duration = Duration::from_secs(60);
/// Check that a quiet peer still answers after this long.
const PROBE_AFTER: Duration = Duration::from_secs(300);
/// How long it has to answer.
const PROBE_TIMEOUT: Duration = Duration::from_secs(60);
/// Stanzas a peer may leave unacknowledged (XEP-0198) before the link is given up.
const MAX_UNACKED: usize = 10_000;

pub(super) struct Job {
    pub s2s: Arc<S2s>,
    pub srv: Arc<Server>,
    pub local: String,
    pub remote: String,
    pub id: u64,
    pub rx: mpsc::Receiver<Element>,
    /// Stanzas from an earlier link that never got through, sent first.
    pub carry: VecDeque<Element>,
    pub attempt: u8,
}

/// Why a link couldn't be set up: the error queued stanzas bounce with.
#[derive(Debug)]
pub(super) struct Fail {
    pub err: StanzaError,
    /// Another host of the same domain might work.
    pub next: bool,
}

impl Fail {
    fn not_found(text: String) -> Fail {
        Fail { err: StanzaError::new(Condition::RemoteServerNotFound).with_text(text), next: true }
    }
    fn refused(text: String) -> Fail {
        Fail { err: StanzaError::new(Condition::RemoteServerNotFound).with_text(text), next: false }
    }
    fn timeout(remote: &str) -> Fail {
        Fail { err: StanzaError::new(Condition::RemoteServerTimeout).with_text(format!("{remote} didn't answer in time.")), next: true }
    }
    fn stream(remote: &str, f: StreamFailure) -> Fail {
        match f {
            StreamFailure::Remote(c) => Fail::not_found(format!("{remote} closed the connection ({c}).")),
            StreamFailure::Local(e) => Fail::not_found(format!("{remote} sent something this server can't read ({}).", e.condition)),
            StreamFailure::Closed | StreamFailure::Io(_) => Fail::not_found(format!("Lost the connection to {remote}.")),
        }
    }
}

/// How we proved who we are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Auth {
    External,
    Dialback,
}

/// A stream to a remote server, TLS done (when available), before authentication.
pub(super) struct Opened {
    pub st: Stream,
    /// The stream id the peer gave, for dialback keys.
    pub id: Option<String>,
    /// None on a pre-1.0 stream (no features).
    pub features: Option<Element>,
    /// Our certificate for the local domain, when it's one others can verify.
    pub own: Option<Arc<CertifiedKey>>,
    /// The peer's certificate is valid for the remote domain: we know who we're talking to,
    /// not just where DNS sent us.
    pub verified: bool,
}

/// Connects to `remote` for `local`: each host in turn until one completes TLS and the stream
/// header. Used for links and for dialback verification.
pub(super) async fn open(s2s: &S2s, srv: &Arc<Server>, local: &str, remote: &str) -> Result<Opened, Fail> {
    let cfg = srv.config();
    let route = cfg.s2s.routes.get(remote).map(String::as_str);
    let targets = match dns::targets(&s2s.resolver, route, remote).await {
        Ok(t) => t,
        Err(LookupError::NotFound) => return Err(Fail::refused(format!("There's no server for {remote}."))),
        Err(LookupError::Failed(e)) => {
            tracing::debug!(remote, error = %e, "DNS lookup failed");
            return Err(Fail::not_found(format!("Couldn't look up {remote}.")));
        }
    };
    let tls = s2s.tls(srv).await;
    let mut last = Fail::not_found(format!("Couldn't connect to {remote}."));
    for t in targets {
        let addrs = match dns::addrs(&s2s.resolver, &t).await {
            Ok(a) if !a.is_empty() => a,
            Ok(_) | Err(_) => continue,
        };
        let tcp = match dns::connect(&addrs).await {
            Ok(tcp) => tcp,
            Err(e) => {
                tracing::debug!(remote, host = %t.host, error = %e, "couldn't connect");
                last = Fail::not_found(format!("Couldn't connect to {remote}."));
                continue;
            }
        };
        // Each host gets the whole allowance; the link as a whole gets twice that.
        let limit = Duration::from_secs(cfg.s2s.timeout_secs.max(1));
        match tokio::time::timeout(limit, handshake(&tls, srv, &cfg, local, remote, &t, tcp)).await {
            Ok(Ok(o)) => return Ok(o),
            Ok(Err(f)) => {
                tracing::debug!(remote, host = %t.host, error = ?f.err.text, "stream setup failed");
                let next = f.next;
                last = f;
                if !next {
                    break;
                }
            }
            Err(_) => last = Fail::timeout(remote),
        }
    }
    Err(last)
}

/// TLS (direct or STARTTLS) and the stream header on one connection.
async fn handshake(
    tls: &Tls,
    srv: &Arc<Server>,
    cfg: &Config,
    local: &str,
    remote: &str,
    t: &Target,
    tcp: tokio::net::TcpStream,
) -> Result<Opened, Fail> {
    let (client, own) = tls.client(&srv.certs, local, t.direct_tls).map_err(|e| Fail::refused(format!("TLS setup failed: {e}")))?;
    // TLS names are A-labels (RFC 6125 §6.4.2), also for internationalized domains.
    let sni = dns::to_ascii(remote)
        .and_then(|a| ServerName::try_from(a).ok())
        .ok_or_else(|| Fail::refused(format!("{remote} isn't a name TLS can check.")))?;
    let max = cfg.limits.s2s_stanza_bytes;
    let write_limit = Duration::from_secs(cfg.s2s.timeout_secs.max(1));
    let tls_fail = |e: std::io::Error| {
        tracing::debug!(remote, error = %e, "TLS handshake failed");
        Fail::not_found(format!("Couldn't set up a secure connection to {remote}."))
    };
    let mut st = if t.direct_tls {
        let s = tokio_rustls::TlsConnector::from(client.clone()).connect(sni.clone(), tcp).await.map_err(tls_fail)?;
        Stream::new(Io::Client(Box::new(s)), max, write_limit)
    } else {
        Stream::new(Io::Plain(tcp), max, write_limit)
    };
    let (mut id, mut features) = start(&mut st, local, remote).await.map_err(|f| Fail::stream(remote, f))?;
    if !st.secure {
        if features.as_ref().is_some_and(|f| f.has_child("starttls", ns::TLS)) {
            st.send(&Element::new("starttls", ns::TLS)).await.map_err(|e| Fail::stream(remote, e.into()))?;
            let r = st.read_element().await.map_err(|f| Fail::stream(remote, f))?;
            if !r.is("proceed", ns::TLS) {
                return Err(Fail::not_found(format!("{remote} refused to encrypt the connection.")));
            }
            st.starttls_client(client, sni).await.map_err(tls_fail)?;
            (id, features) = start(&mut st, local, remote).await.map_err(|f| Fail::stream(remote, f))?;
        } else if cfg.s2s.require_tls {
            st.close(None).await;
            return Err(Fail::not_found(format!("{remote} doesn't support encryption, which this server requires.")));
        }
    }
    let verified = st.secure && st.peer_certs.as_deref().is_some_and(|c| tls.pki.valid_for(c, remote));
    Ok(Opened { st, id, features, own, verified })
}

/// Sends our stream header and reads the peer's header and features.
async fn start(st: &mut Stream, local: &str, remote: &str) -> Result<(Option<String>, Option<Element>), StreamFailure> {
    st.open(Some(local), Some(remote), None).await?;
    let attrs = st.read_header().await?;
    let attr = |k: &str| attrs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let id = attr("id");
    if attr("version").is_none_or(|v| !v.starts_with("1.")) {
        return Ok((id, None));
    }
    let f = st.read_element().await?;
    if !f.is("features", ns::STREAM) {
        return Err(StreamFailure::Local(StreamError::new("invalid-xml")));
    }
    Ok((id, Some(f)))
}

/// A link that's up.
struct Established {
    st: Stream,
    auth: Auth,
    sm: bool,
}

/// Connects and proves we are `local`.
async fn establish(s2s: &S2s, srv: &Arc<Server>, local: &str, remote: &str) -> Result<Established, Fail> {
    let cfg = srv.config();
    let Opened { mut st, mut id, mut features, own, verified } = open(s2s, srv, local, remote).await?;
    let err = |f: StreamFailure| Fail::stream(remote, f);
    // Proving who we are doesn't prove who they are: without a valid certificate, the server
    // we reached is whoever DNS and the network led us to. Dialback accepts that (it's how
    // self-signed servers federate, see `incoming::verify`); with dialback off, or valid
    // certificates required, such a server isn't sent anything.
    if !verified && (cfg.s2s.require_valid_certs || !cfg.s2s.dialback) {
        st.close(None).await;
        return Err(Fail::not_found(format!("{remote}'s certificate can't be verified, and this server requires a valid one.")));
    }
    let mut auth = None;
    let offers = |f: &Option<Element>, mech: &str| {
        f.as_ref()
            .and_then(|f| f.get_child("mechanisms", ns::SASL))
            .is_some_and(|m| m.children().any(|c| c.name() == "mechanism" && c.text_content().trim() == mech))
    };
    if own.is_some() && st.secure && offers(&features, "EXTERNAL") {
        // XEP-0178: the authorization identity is the domain we send from.
        let a = Element::new("auth", ns::SASL).attr_set("mechanism", "EXTERNAL").text(B64.encode(local));
        st.send(&a).await.map_err(|e| err(e.into()))?;
        let r = st.read_element().await.map_err(err)?;
        if r.is("success", ns::SASL) {
            st.restart();
            (id, features) = start(&mut st, local, remote).await.map_err(err)?;
            auth = Some(Auth::External);
        } else {
            tracing::debug!(local, remote, reply = %r, "SASL EXTERNAL refused; trying dialback");
        }
    }
    if auth.is_none() {
        if !cfg.s2s.dialback {
            st.close(None).await;
            return Err(Fail::refused(format!("{remote} doesn't accept this server's certificate, and dialback is turned off here.")));
        }
        // Pre-1.0 streams have no features; dialback is all they know.
        let offered = features.as_ref().is_none_or(|f| f.has_child("dialback", ns::DIALBACK_FEATURE));
        let Some(stream_id) = id.as_deref().filter(|_| offered) else {
            st.close(None).await;
            return Err(Fail::refused(format!("{remote} wants a certificate this server doesn't have.")));
        };
        let key = dialback::key(&s2s.secret, remote, local, stream_id);
        st.send(&dialback::element("result", local, remote).text(key)).await.map_err(|e| err(e.into()))?;
        loop {
            let r = st.read_element().await.map_err(err)?;
            if !r.is("result", ns::DIALBACK) || r.attr("from") != Some(remote) || r.attr("to") != Some(local) {
                continue;
            }
            match r.attr("type") {
                Some("valid") => break,
                _ => {
                    st.close(None).await;
                    let why = StanzaError::from_stanza(&r).and_then(|e| e.text);
                    tracing::info!(local, remote, reason = ?why, "the other server refused our dialback");
                    return Err(Fail::refused(format!("{remote} didn't accept this server.")));
                }
            }
        }
        auth = Some(Auth::Dialback);
    }
    let auth = auth.unwrap_or(Auth::Dialback);
    let mut sm = false;
    if features.as_ref().is_some_and(|f| f.has_child("sm", ns::SM)) {
        st.send(&Element::new("enable", ns::SM)).await.map_err(|e| err(e.into()))?;
        // The reader isn't cancel safe, so a peer that doesn't answer in time costs this
        // attempt rather than leaving a half-read stream behind.
        match tokio::time::timeout(SM_ANSWER, st.read_element()).await {
            Ok(r) => sm = r.map_err(err)?.is("enabled", ns::SM),
            Err(_) => return Err(Fail::timeout(remote)),
        }
    }
    Ok(Established { st, auth, sm })
}

/// Runs one outgoing link from connecting to closing.
pub(super) async fn run(job: Job) {
    let Job { s2s, srv, local, remote, id, mut rx, carry, attempt } = job;
    let pair = (local.clone(), remote.clone());
    let limit = Duration::from_secs(srv.config().s2s.timeout_secs.max(1) * 2);
    let est = match tokio::time::timeout(limit, establish(&s2s, &srv, &local, &remote)).await {
        Ok(Ok(e)) => e,
        Ok(Err(f)) => return give_up(&s2s, &srv, &pair, id, rx, carry, f.err),
        Err(_) => return give_up(&s2s, &srv, &pair, id, rx, carry, Fail::timeout(&remote).err),
    };
    tracing::debug!(local, remote, auth = ?est.auth, sm = est.sm, "link up");
    let info = LinkInfo {
        direction: "out",
        local: local.clone(),
        remote: remote.clone(),
        auth: if est.auth == Auth::External { "certificate" } else { "dialback" },
        secure: est.st.secure,
        sm: est.sm,
        since: quark_core::time::now_ms(),
    };
    let (reader, writer) = match est.st.split() {
        Ok(x) => x,
        Err(_) => return give_up(&s2s, &srv, &pair, id, rx, carry, Fail::stream(&remote, StreamFailure::Closed).err),
    };
    s2s.link_up(id, info);
    let (in_tx, in_rx) = mpsc::channel(8);
    let reader_task = tokio::spawn(stream::read_loop(reader, in_tx));
    let now = Instant::now();
    let mut link = Link {
        srv: srv.clone(),
        local: local.clone(),
        remote: remote.clone(),
        writer,
        inbound: in_rx,
        sm: est.sm.then(Sm::default),
        last_sent: now,
        last_write: now,
        last_heard: now,
        probe: None,
        probe_task: None,
        dirty: false,
        carried: 0,
    };
    let end = link.run(&mut rx, carry).await;
    reader_task.abort();
    if let Some(p) = link.probe_task.take() {
        p.abort();
    }
    s2s.link_down(id);
    s2s.remove_out(&pair, id);
    rx.close();
    let mut left: VecDeque<Element> = link.sm.take().map(|s| s.unacked).unwrap_or_default();
    // Stanzas sent but never confirmed count as a try; ones still queued don't.
    let tried = !left.is_empty();
    // Once what this link carried over got through, earlier failures no longer matter.
    let attempt = if link.carried == 0 { 0 } else { attempt };
    while let Ok(el) = rx.try_recv() {
        left.push_back(el);
    }
    tracing::debug!(local, remote, ?end, unsent = left.len(), "link closed");
    match end {
        End::Shutdown => {}
        End::Lost if tried => s2s.requeue(&srv, &local, &remote, left, attempt + 1),
        // Closed while idle, or lost with nothing in flight: anything left starts a new link.
        End::Idle | End::Lost => s2s.requeue(&srv, &local, &remote, left, attempt),
    }
}

/// The link never came up: remember that for a while and bounce everything queued.
fn give_up(
    s2s: &S2s,
    srv: &Arc<Server>,
    pair: &(String, String),
    id: u64,
    mut rx: mpsc::Receiver<Element>,
    carry: VecDeque<Element>,
    err: StanzaError,
) {
    tracing::info!(local = %pair.0, remote = %pair.1, error = err.text.as_deref().unwrap_or(""), "couldn't reach the other server");
    s2s.mark_unreachable(pair.clone(), err.clone(), srv.config().s2s.retry_secs);
    s2s.remove_out(pair, id);
    rx.close();
    for el in carry {
        super::bounce(srv, el, err.clone());
    }
    while let Ok(el) = rx.try_recv() {
        super::bounce(srv, el, err.clone());
    }
}

/// Outgoing stream management state.
#[derive(Default)]
struct Sm {
    /// Sent and not yet acknowledged, oldest first.
    unacked: VecDeque<Element>,
    /// Stanzas the peer has acknowledged so far (mod 2³²).
    acked: u32,
    /// When we asked for an ack that hasn't come yet.
    asked: Option<Instant>,
}

#[derive(Debug, Clone, Copy)]
enum End {
    Idle,
    Lost,
    Shutdown,
}

struct Link {
    srv: Arc<Server>,
    local: String,
    remote: String,
    writer: Writer,
    inbound: mpsc::Receiver<In>,
    sm: Option<Sm>,
    /// Last real stanza sent (whitespace and server pings don't count).
    last_sent: Instant,
    last_write: Instant,
    last_heard: Instant,
    /// When an XMPP ping went out that hasn't been answered.
    probe: Option<Instant>,
    probe_task: Option<tokio::task::JoinHandle<()>>,
    /// Written since the last flush.
    dirty: bool,
    /// Stanzas carried over from an earlier link that aren't confirmed yet.
    carried: usize,
}

enum Next {
    Out(Option<Element>),
    In(Option<In>),
    Tick,
    Probe(bool),
    Shutdown,
}

impl Link {
    async fn run(&mut self, rx: &mut mpsc::Receiver<Element>, carry: VecDeque<Element>) -> End {
        // Without stream management, writing them is as confirmed as it gets.
        self.carried = if self.sm.is_some() { carry.len() } else { 0 };
        for el in carry {
            if self.write(el).await.is_err() {
                return End::Lost;
            }
        }
        if self.ask_ack().await.is_err() || self.flush().await.is_err() {
            return End::Lost;
        }
        let mut shutdown = self.srv.shutdown_signal();
        let idle = Duration::from_secs(self.srv.config().s2s.idle_secs);
        let mut tick = tokio::time::interval(super::tick_period(idle.as_secs()));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let (probe_tx, mut probe_rx) = mpsc::channel::<bool>(1);
        loop {
            let next = tokio::select! {
                biased;
                r = shutdown.changed() => match r {
                    Ok(()) if !*shutdown.borrow() => continue,
                    _ => Next::Shutdown,
                },
                i = self.inbound.recv() => Next::In(i),
                p = probe_rx.recv() => Next::Probe(p.unwrap_or(true)),
                m = rx.recv() => Next::Out(m),
                _ = tick.tick() => Next::Tick,
            };
            let res = match next {
                Next::Shutdown => {
                    stream::close(&mut self.writer, Some(&StreamError::new("system-shutdown"))).await;
                    return End::Shutdown;
                }
                Next::In(None) => return End::Lost,
                Next::In(Some(In::Gone(err, why))) => {
                    tracing::debug!(local = %self.local, remote = %self.remote, why, "link ended by the peer");
                    stream::close(&mut self.writer, err.as_ref()).await;
                    return End::Lost;
                }
                Next::In(Some(In::Stanza(el))) => self.on_inbound(el).await,
                Next::Out(None) => {
                    stream::close(&mut self.writer, None).await;
                    return End::Shutdown;
                }
                Next::Out(Some(el)) => self.burst(el, rx).await,
                Next::Probe(alive) => {
                    self.probe = None;
                    if alive {
                        self.last_heard = Instant::now();
                        Ok(())
                    } else {
                        tracing::info!(local = %self.local, remote = %self.remote, "the other server stopped answering");
                        stream::close(&mut self.writer, Some(&StreamError::new("connection-timeout"))).await;
                        return End::Lost;
                    }
                }
                Next::Tick => match self.on_tick(idle, &probe_tx).await {
                    Ok(Some(end)) => return end,
                    Ok(None) => Ok(()),
                    Err(e) => Err(e),
                },
            };
            if res.is_err() || self.flush().await.is_err() {
                return End::Lost;
            }
        }
    }

    /// Writes `first` and whatever else is queued (up to a batch), so a burst is one write.
    async fn burst(&mut self, first: Element, rx: &mut mpsc::Receiver<Element>) -> std::io::Result<()> {
        self.write(first).await?;
        for _ in 1..DRAIN_BATCH {
            let Ok(el) = rx.try_recv() else { break };
            self.write(el).await?;
        }
        self.ask_ack().await
    }

    /// Asks for an ack (XEP-0198) when stanzas are waiting for one and no request is out.
    async fn ask_ack(&mut self) -> std::io::Result<()> {
        if let Some(sm) = self.sm.as_mut() {
            if !sm.unacked.is_empty() && sm.asked.is_none() {
                sm.asked = Some(Instant::now());
                stream::write_el(&mut self.writer, &Element::new("r", ns::SM)).await?;
                self.dirty = true;
            }
            if sm.unacked.len() > MAX_UNACKED {
                return Err(std::io::Error::other("the other server doesn't acknowledge stanzas"));
            }
        }
        Ok(())
    }

    async fn write(&mut self, el: Element) -> std::io::Result<()> {
        stream::write_el(&mut self.writer, &el).await?;
        self.dirty = true;
        self.srv.count_out();
        if !is_keepalive(&el, &self.local, &self.remote) {
            self.last_sent = Instant::now();
        }
        if let Some(sm) = self.sm.as_mut() {
            sm.unacked.push_back(el);
        }
        Ok(())
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        if self.dirty {
            self.dirty = false;
            self.last_write = Instant::now();
            self.writer.flush().await?;
        }
        Ok(())
    }

    /// The receiving side only sends stream management on this stream (no bidi, XEP-0288).
    async fn on_inbound(&mut self, el: Element) -> std::io::Result<()> {
        self.last_heard = Instant::now();
        if el.is("a", ns::SM) {
            if let (Some(sm), Some(h)) = (self.sm.as_mut(), el.attr("h").and_then(|h| h.parse::<u32>().ok())) {
                let n = h.wrapping_sub(sm.acked) as usize;
                if n <= sm.unacked.len() {
                    sm.unacked.drain(..n);
                    sm.acked = h;
                    self.carried = self.carried.saturating_sub(n);
                }
                sm.asked = None;
            }
        } else if el.is("r", ns::SM) {
            // We never receive stanzas on our own stream, so nothing was handled.
            stream::write_el(&mut self.writer, &Element::new("a", ns::SM).attr_set("h", "0")).await?;
            self.dirty = true;
        } else {
            tracing::debug!(remote = %self.remote, element = el.name(), "ignoring an element on an outgoing stream");
        }
        Ok(())
    }

    async fn on_tick(&mut self, idle: Duration, probe_tx: &mpsc::Sender<bool>) -> std::io::Result<Option<End>> {
        let unacked = self.sm.as_ref().is_some_and(|s| !s.unacked.is_empty());
        if self.last_sent.elapsed() >= idle {
            if !unacked {
                stream::close(&mut self.writer, None).await;
                return Ok(Some(End::Idle));
            }
            if let Some(sm) = self.sm.as_mut().filter(|s| s.asked.is_none()) {
                sm.asked = Some(Instant::now());
                stream::write_el(&mut self.writer, &Element::new("r", ns::SM)).await?;
                self.dirty = true;
            }
        }
        let probe_after = PROBE_AFTER.min(idle / 2).max(Duration::from_secs(1));
        if let Some(sm) = self.sm.as_mut() {
            match sm.asked {
                Some(t) if t.elapsed() > PROBE_TIMEOUT => {
                    tracing::info!(local = %self.local, remote = %self.remote, "the other server stopped acknowledging");
                    stream::close(&mut self.writer, Some(&StreamError::new("connection-timeout"))).await;
                    return Ok(Some(End::Lost));
                }
                None if self.last_heard.elapsed() > probe_after => {
                    sm.asked = Some(Instant::now());
                    stream::write_el(&mut self.writer, &Element::new("r", ns::SM)).await?;
                    self.dirty = true;
                }
                _ => {}
            }
        } else if self.probe.is_none() && self.last_sent > self.last_heard && self.last_heard.elapsed() > probe_after {
            // Without stream management, an XMPP ping (XEP-0199) shows the peer still listens
            // to what we've been sending; its answer comes back on the peer's own link to us.
            self.probe = Some(Instant::now());
            let (srv, tx) = (self.srv.clone(), probe_tx.clone());
            let ping = quark_core::stanza::iq("get", "", Some(&self.local), Some(&self.remote), Element::new("ping", ns::PING));
            self.probe_task = Some(tokio::spawn(async move {
                let alive = match srv.request(ping, PROBE_TIMEOUT).await {
                    Ok(_) => true,
                    Err(e) => e.condition != Condition::RemoteServerTimeout,
                };
                let _ = tx.send(alive).await;
            }));
        }
        if self.last_write.elapsed() >= KEEPALIVE {
            self.writer.write_all(b" ").await?;
            self.dirty = true;
        }
        Ok(None)
    }
}

/// A server-to-server ping or its answer. These don't keep a link from going idle, or two
/// servers checking on each other would keep both links open forever.
fn is_keepalive(el: &Element, local: &str, remote: &str) -> bool {
    use quark_core::stanza::IqType;
    el.name() == "iq"
        && el.attr("from") == Some(local)
        && el.attr("to") == Some(remote)
        && match iq_type(el) {
            Some(IqType::Get) => el.has_child("ping", ns::PING),
            Some(IqType::Result) => el.first_child().is_none(),
            _ => false,
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pings_between_servers_are_keepalives() {
        let ping = quark_core::stanza::iq("get", "1", Some("a.test"), Some("b.test"), Element::new("ping", ns::PING));
        assert!(is_keepalive(&ping, "a.test", "b.test"));
        let pong = quark_core::stanza::iq_result(&Element::new("iq", ns::CLIENT).attr_set("from", "b.test").attr_set("to", "a.test"));
        assert!(is_keepalive(&pong, "a.test", "b.test"));
        let user_ping = quark_core::stanza::iq("get", "1", Some("alice@a.test/x"), Some("b.test"), Element::new("ping", ns::PING));
        assert!(!is_keepalive(&user_ping, "a.test", "b.test"));
        let disco = quark_core::stanza::iq("get", "1", Some("a.test"), Some("b.test"), Element::new("query", ns::DISCO_INFO));
        assert!(!is_keepalive(&disco, "a.test", "b.test"));
    }
}
