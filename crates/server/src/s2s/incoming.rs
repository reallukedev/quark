//! Links other servers open to us: stream negotiation (STARTTLS, SASL EXTERNAL), dialback
//! (XEP-0220) as receiving and as authoritative server, and the checks every stanza passes
//! before it's routed.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use quark_core::stanza::jid_attr;
use quark_core::{ns, Condition, Element, Jid, StanzaError};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, OwnedSemaphorePermit};

use super::dialback::{self, Outcome};
use super::stream::{self, In, Io, Stream, StreamFailure, Writer};
use super::{is_blocked, LinkInfo, S2s};
use crate::server::Server;
use crate::transport::StreamError;

/// Domains one stream may prove (dialback lets a server add several).
const MAX_DOMAINS: usize = 64;
/// Dialback checks one stream may have running at once.
const MAX_VERIFYING: usize = 8;
/// Whitespace after this long without writing.
const KEEPALIVE: Duration = Duration::from_secs(60);

/// Accepts server connections. `direct_tls`: TLS from the first byte (XEP-0368).
pub(super) async fn accept_loop(s2s: Arc<S2s>, srv: Arc<Server>, listener: TcpListener, direct_tls: bool) {
    if let Ok(addr) = listener.local_addr() {
        tracing::info!(%addr, direct_tls, "listening for servers");
    }
    let mut shutdown = srv.shutdown_signal();
    loop {
        let tcp = tokio::select! {
            r = listener.accept() => match r {
                Ok((tcp, _)) => tcp,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            },
            r = shutdown.changed() => match r {
                Ok(()) if !*shutdown.borrow() => continue,
                _ => return,
            },
        };
        let Ok(permit) = s2s.in_slots.clone().try_acquire_owned() else {
            tracing::warn!("too many server connections; refusing one");
            continue;
        };
        tokio::spawn(serve(s2s.clone(), srv.clone(), tcp, direct_tls, permit));
    }
}

async fn serve(s2s: Arc<S2s>, srv: Arc<Server>, tcp: TcpStream, direct_tls: bool, _permit: OwnedSemaphorePermit) {
    let cfg = srv.config();
    let tls = s2s.tls(&srv).await;
    let max = cfg.limits.s2s_stanza_bytes;
    let mut st = if direct_tls {
        let accept = tokio_rustls::TlsAcceptor::from(tls.direct.clone()).accept(tcp);
        match tokio::time::timeout(Duration::from_secs(15), accept).await {
            Ok(Ok(s)) => Stream::new(Io::Server(Box::new(s)), max),
            _ => return,
        }
    } else {
        Stream::new(Io::Plain(tcp), max)
    };
    let limit = Duration::from_secs(cfg.limits.auth_timeout_secs);
    let neg = match tokio::time::timeout(limit, negotiate(&srv, &tls, &mut st)).await {
        Ok(Ok(n)) => n,
        Ok(Err(f)) => {
            match f {
                StreamFailure::Local(e) => {
                    tracing::debug!(peer = %super::peer_str(st.peer), error = e.condition, "refused a server stream");
                    st.close(Some(&e)).await;
                }
                other => {
                    tracing::debug!(peer = %super::peer_str(st.peer), error = %other, "server stream ended during setup");
                    st.close(None).await;
                }
            }
            return;
        }
        Err(_) => {
            st.close(Some(&StreamError::new("connection-timeout"))).await;
            return;
        }
    };
    let peer = st.peer;
    let secure = st.secure;
    let peer_certs = st.peer_certs.clone();
    let Ok((reader, writer)) = st.split() else { return };
    let (in_tx, in_rx) = mpsc::channel(8);
    let reader_task = tokio::spawn(stream::read_loop(reader, in_tx));
    let (ev_tx, ev_rx) = mpsc::channel(MAX_VERIFYING);
    let mut link = Link {
        s2s: s2s.clone(),
        srv,
        tls,
        id: s2s.next_id(),
        local: neg.local,
        stream_id: neg.stream_id,
        secure,
        peer,
        peer_certs,
        authed: HashSet::new(),
        auth: if neg.authed.is_some() { "certificate" } else { "dialback" },
        writer,
        dirty: false,
        verifying: 0,
        ev_tx,
        sm: None,
        since: Instant::now(),
        last_heard: Instant::now(),
        last_write: Instant::now(),
    };
    if let Some(d) = neg.authed {
        link.add_domain(d);
    }
    link.run(in_rx, ev_rx, neg.first).await;
    reader_task.abort();
    s2s.link_down(link.id);
}

/// What negotiation settled.
struct Negotiated {
    /// Our domain the stream is for.
    local: String,
    /// Our id for the current stream (dialback keys are made with it).
    stream_id: String,
    /// The domain SASL EXTERNAL proved.
    authed: Option<String>,
    /// The first element after negotiation, for the link to handle.
    first: Option<Element>,
}

/// Headers, features, STARTTLS and SASL EXTERNAL; stops at the first element of anything else.
async fn negotiate(srv: &Arc<Server>, tls: &super::Tls, st: &mut Stream) -> Result<Negotiated, StreamFailure> {
    let cfg = srv.config();
    let mut authed: Option<String> = None;
    loop {
        let attrs = st.read_header().await?;
        let attr = |k: &str| attrs.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        let local = match attr("to").map(Jid::domain_jid) {
            Some(Ok(j)) if srv.is_local(j.domain()) => j.domain().to_string(),
            _ => {
                // The header still has to go out before the error (RFC 6120 §4.9.1.2).
                st.open(srv.hosts().first().map(|h| h.domain.as_str()), None, Some(&quark_core::new_id())).await?;
                return Err(StreamFailure::Local(StreamError::new("host-unknown")));
            }
        };
        let from = match attr("from").map(Jid::domain_jid) {
            Some(Ok(j)) => Some(j.domain().to_string()),
            Some(Err(_)) => {
                st.open(Some(&local), None, Some(&quark_core::new_id())).await?;
                return Err(StreamFailure::Local(StreamError::new("invalid-from")));
            }
            None => None,
        };
        let id = quark_core::new_id();
        st.open(Some(&local), from.as_deref(), Some(&id)).await?;
        if let Some(f) = from.as_deref().filter(|f| is_blocked(&cfg, f) || srv.is_local(f)) {
            let text = if srv.is_local(f) { "That's this server's own name." } else { "This server doesn't talk to yours." };
            return Err(StreamFailure::Local(StreamError::with_text("policy-violation", text)));
        }
        if attr("version").is_none_or(|v| !v.starts_with("1.")) {
            // A pre-1.0 peer: no features, no TLS, dialback only.
            if cfg.s2s.require_tls {
                return Err(StreamFailure::Local(StreamError::with_text("unsupported-version", "This server requires encryption.")));
            }
            return Ok(Negotiated { local, stream_id: id, authed, first: None });
        }
        let cert_ok = |st: &Stream, d: &str| st.secure && st.peer_certs.as_deref().is_some_and(|c| tls.pki.valid_for(c, d));
        let external = authed.is_none() && from.as_deref().is_some_and(|f| cert_ok(st, f));
        let mut features = Element::new("features", ns::STREAM);
        if !st.secure {
            let mut t = Element::new("starttls", ns::TLS);
            if cfg.s2s.require_tls {
                t.append(Element::new("required", ns::TLS));
            }
            features.append(t);
        }
        if external {
            features.append(Element::new("mechanisms", ns::SASL).child(Element::new("mechanism", ns::SASL).text("EXTERNAL")));
        }
        if authed.is_none() && cfg.s2s.dialback && (st.secure || !cfg.s2s.require_tls) {
            features.append(Element::new("dialback", ns::DIALBACK_FEATURE).child(Element::new("errors", ns::DIALBACK_FEATURE)));
        }
        if st.secure || !cfg.s2s.require_tls {
            features.append(Element::new("sm", ns::SM));
        }
        st.send(&features).await?;
        loop {
            let el = st.read_element().await?;
            if el.is("starttls", ns::TLS) && !st.secure {
                st.send(&Element::new("proceed", ns::TLS)).await?;
                st.starttls_server(tls.starttls.clone()).await?;
                break;
            }
            if el.is("auth", ns::SASL) && external {
                match external_identity(&el, from.as_deref()) {
                    Some(d) if cert_ok(st, &d) && !is_blocked(&cfg, &d) => {
                        st.send(&Element::new("success", ns::SASL)).await?;
                        st.restart();
                        tracing::debug!(remote = d, local, "server signed in with its certificate");
                        authed = Some(d);
                        break;
                    }
                    _ => {
                        let f = Element::new("failure", ns::SASL).child(Element::new("not-authorized", ns::SASL));
                        st.send(&f).await?;
                        continue;
                    }
                }
            }
            if el.is("auth", ns::SASL) {
                // Only EXTERNAL exists between servers, and only with a certificate we trust.
                let f = Element::new("failure", ns::SASL).child(Element::new("invalid-mechanism", ns::SASL));
                st.send(&f).await?;
                continue;
            }
            if !st.secure && cfg.s2s.require_tls {
                return Err(StreamFailure::Local(StreamError::with_text("policy-violation", "This server requires encryption.")));
            }
            return Ok(Negotiated { local, stream_id: id, authed, first: Some(el) });
        }
    }
}

/// The domain a SASL EXTERNAL `<auth/>` asks to be: its authorization identity, or the stream
/// header's `from` when it's empty (XEP-0178 §3).
fn external_identity(auth: &Element, from: Option<&str>) -> Option<String> {
    if auth.attr("mechanism") != Some("EXTERNAL") {
        return None;
    }
    let text = auth.text_content();
    let text = text.trim();
    let authzid = if text.is_empty() || text == "=" { None } else { Some(String::from_utf8(B64.decode(text).ok()?).ok()?) };
    let d = match (authzid, from) {
        (Some(a), Some(f)) => {
            let a = Jid::domain_jid(&a).ok()?.domain().to_string();
            (a == f).then_some(a)?
        }
        (Some(a), None) => Jid::domain_jid(&a).ok()?.domain().to_string(),
        (None, Some(f)) => f.to_string(),
        (None, None) => return None,
    };
    Some(d)
}

/// A finished dialback check.
struct Verified {
    from: String,
    to: String,
    outcome: Outcome,
}

struct Link {
    s2s: Arc<S2s>,
    srv: Arc<Server>,
    tls: Arc<super::Tls>,
    id: u64,
    local: String,
    stream_id: String,
    secure: bool,
    peer: Option<std::net::SocketAddr>,
    peer_certs: Option<Vec<rustls::pki_types::CertificateDer<'static>>>,
    /// Domains this stream proved; stanzas must come from one of them.
    authed: HashSet<String>,
    auth: &'static str,
    writer: Writer,
    dirty: bool,
    verifying: usize,
    ev_tx: mpsc::Sender<Verified>,
    /// Stanzas handled, once stream management is on (XEP-0198).
    sm: Option<u32>,
    since: Instant,
    last_heard: Instant,
    last_write: Instant,
}

enum Next {
    In(Option<In>),
    Verified(Verified),
    Tick,
    Shutdown,
}

/// How a link ends: the stream error to send, if any.
type End = Option<StreamError>;

impl Link {
    async fn run(&mut self, mut inbound: mpsc::Receiver<In>, mut events: mpsc::Receiver<Verified>, first: Option<Element>) {
        let mut shutdown = self.srv.shutdown_signal();
        let idle = Duration::from_secs(self.srv.config().s2s.idle_secs);
        let auth_limit = Duration::from_secs(self.srv.config().limits.auth_timeout_secs);
        let mut tick = tokio::time::interval(super::tick_period(idle.as_secs()));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut pending = first;
        loop {
            let next = match pending.take() {
                Some(el) => Next::In(Some(In::Stanza(el))),
                None => tokio::select! {
                    biased;
                    r = shutdown.changed() => match r {
                        Ok(()) if !*shutdown.borrow() => continue,
                        _ => Next::Shutdown,
                    },
                    v = events.recv() => match v {
                        Some(v) => Next::Verified(v),
                        None => continue,
                    },
                    i = inbound.recv() => Next::In(i),
                    _ = tick.tick() => Next::Tick,
                },
            };
            let end: Option<End> = match next {
                Next::Shutdown => Some(Some(StreamError::new("system-shutdown"))),
                Next::In(None) => Some(None),
                Next::In(Some(In::Gone(err, why))) => {
                    tracing::debug!(peer = %super::peer_str(self.peer), domains = ?self.authed, why, "server stream ended");
                    Some(err)
                }
                Next::In(Some(In::Stanza(el))) => {
                    self.last_heard = Instant::now();
                    self.on_element(el).await
                }
                Next::Verified(v) => self.on_verified(v).await,
                Next::Tick => self.on_tick(idle, auth_limit).await,
            };
            if let Some(err) = end {
                stream::close(&mut self.writer, err.as_ref()).await;
                return;
            }
            if self.dirty {
                self.dirty = false;
                self.last_write = Instant::now();
                if self.writer.flush().await.is_err() {
                    return;
                }
            }
        }
    }

    async fn write(&mut self, el: &Element) -> Option<End> {
        self.dirty = true;
        match stream::write_el(&mut self.writer, el).await {
            Ok(()) => None,
            Err(_) => Some(None),
        }
    }

    fn add_domain(&mut self, d: String) {
        let info = LinkInfo {
            direction: "in",
            local: self.local.clone(),
            remote: d.clone(),
            auth: self.auth,
            secure: self.secure,
            sm: self.sm.is_some(),
            since: quark_core::time::now_ms(),
        };
        self.s2s.link_up(self.id, info);
        self.authed.insert(d);
    }

    async fn on_tick(&mut self, idle: Duration, auth_limit: Duration) -> Option<End> {
        if self.authed.is_empty() && self.verifying == 0 && self.since.elapsed() > auth_limit {
            return Some(Some(StreamError::new("connection-timeout")));
        }
        if self.last_heard.elapsed() > idle {
            return Some(None);
        }
        if self.last_write.elapsed() >= KEEPALIVE {
            self.dirty = true;
            if self.writer.write_all(b" ").await.is_err() {
                return Some(None);
            }
        }
        None
    }

    async fn on_element(&mut self, el: Element) -> Option<End> {
        match el.ns() {
            ns::DIALBACK => match el.name() {
                "result" if el.attr("type").is_none() => self.on_result(el).await,
                "verify" if el.attr("type").is_none() => self.on_verify(&el).await,
                // Answers only come on streams we opened.
                _ => None,
            },
            ns::SM => match el.name() {
                "enable" if self.sm.is_none() && !self.authed.is_empty() => {
                    self.sm = Some(0);
                    self.s2s.link_sm(self.id);
                    self.write(&Element::new("enabled", ns::SM)).await
                }
                "enable" => {
                    let f = Element::new("failed", ns::SM).child(Element::new("unexpected-request", ns::STANZAS));
                    self.write(&f).await
                }
                "r" => match self.sm {
                    Some(h) => self.write(&Element::new("a", ns::SM).attr_set("h", h.to_string())).await,
                    None => None,
                },
                _ => None,
            },
            ns::CLIENT if matches!(el.name(), "message" | "presence" | "iq") => self.on_stanza(el).await,
            _ => Some(Some(StreamError::new("unsupported-stanza-type"))),
        }
    }

    /// A stanza from the other server: it must come from a domain this stream proved and be
    /// for one of ours (RFC 6120 §4.9.3.10, §4.9.3.6).
    async fn on_stanza(&mut self, el: Element) -> Option<End> {
        if self.authed.is_empty() {
            return Some(Some(StreamError::new("not-authorized")));
        }
        match jid_attr(&el, "from") {
            Ok(Some(f)) if self.authed.contains(f.domain()) => {}
            Ok(Some(f)) => {
                let text = format!("This stream isn't authenticated for {}.", f.domain());
                return Some(Some(StreamError::with_text("invalid-from", text)));
            }
            _ => return Some(Some(StreamError::new("invalid-from"))),
        }
        let to = match jid_attr(&el, "to") {
            Ok(Some(t)) => t,
            Ok(None) => return Some(Some(StreamError::new("improper-addressing"))),
            Err(_) => {
                // A malformed recipient: an error back, not a dead stream.
                let err = StanzaError::new(Condition::JidMalformed);
                let srv = self.srv.clone();
                tokio::spawn(async move { crate::router::bounce(&srv, &el, err).await });
                return None;
            }
        };
        if !self.srv.is_local(to.domain()) {
            return Some(Some(StreamError::with_text("host-unknown", format!("{} isn't served here.", to.domain()))));
        }
        self.srv.count_in();
        crate::router::route(&self.srv, el).await;
        if let Some(h) = self.sm.as_mut() {
            *h = h.wrapping_add(1);
        }
        None
    }

    /// `<db:result/>`: the other server asks to send as `from` to our `to` (XEP-0220 §2.1).
    async fn on_result(&mut self, el: Element) -> Option<End> {
        let cfg = self.srv.config();
        let (Some(from), Some(to)) = (el.attr("from"), el.attr("to")) else {
            return Some(Some(StreamError::new("improper-addressing")));
        };
        let Ok(from) = Jid::domain_jid(from).map(|j| j.domain().to_string()) else {
            return Some(Some(StreamError::new("invalid-from")));
        };
        let to = to.to_ascii_lowercase();
        let deny = |e: StanzaError| Some(dialback::answer("result", &to, &from, None, Outcome::Error(e)));
        let answer = if !cfg.s2s.dialback {
            deny(StanzaError::new(Condition::PolicyViolation).with_text("Dialback isn't accepted here."))
        } else if !self.secure && cfg.s2s.require_tls {
            deny(StanzaError::new(Condition::PolicyViolation).with_text("This server requires encryption."))
        } else if !self.srv.is_local(&to) {
            deny(StanzaError::new(Condition::ItemNotFound).with_text(format!("{to} isn't served here.")))
        } else if is_blocked(&cfg, &from) || self.srv.is_local(&from) {
            deny(StanzaError::new(Condition::Forbidden).with_text("This server doesn't talk to yours."))
        } else if self.authed.contains(&from) {
            Some(dialback::answer("result", &to, &from, None, Outcome::Valid))
        } else if self.authed.len() >= MAX_DOMAINS || self.verifying >= MAX_VERIFYING {
            deny(StanzaError::new(Condition::ResourceConstraint))
        } else if self.secure && self.peer_certs.as_deref().is_some_and(|c| self.tls.pki.valid_for(c, &from)) {
            // A certificate we trust already proves the domain; no need to call back (XEP-0344).
            self.auth = "certificate";
            self.add_domain(from.clone());
            Some(dialback::answer("result", &to, &from, None, Outcome::Valid))
        } else {
            self.verifying += 1;
            let (s2s, srv, tx) = (self.s2s.clone(), self.srv.clone(), self.ev_tx.clone());
            let (key, id) = (el.text_content(), self.stream_id.clone());
            tokio::spawn(async move {
                let limit = Duration::from_secs(srv.config().s2s.timeout_secs.max(1));
                let outcome = match tokio::time::timeout(limit, verify(&s2s, &srv, &to, &from, &id, key.trim())).await {
                    Ok(o) => o,
                    Err(_) => Outcome::Error(StanzaError::new(Condition::RemoteServerTimeout)),
                };
                let _ = tx.send(Verified { from, to, outcome }).await;
            });
            None
        };
        match answer {
            Some(a) => self.write(&a).await,
            None => None,
        }
    }

    async fn on_verified(&mut self, v: Verified) -> Option<End> {
        self.verifying = self.verifying.saturating_sub(1);
        let valid = matches!(v.outcome, Outcome::Valid);
        if valid {
            tracing::debug!(remote = v.from, local = v.to, "server proved itself with dialback");
            self.add_domain(v.from.clone());
        } else {
            tracing::info!(remote = v.from, peer = %super::peer_str(self.peer), outcome = ?v.outcome, "dialback failed");
        }
        self.write(&dialback::answer("result", &v.to, &v.from, None, v.outcome)).await
    }

    /// `<db:verify/>`: the other server checks a key we gave it (we're the authoritative
    /// server, XEP-0220 §2.3). Allowed before authentication.
    async fn on_verify(&mut self, el: &Element) -> Option<End> {
        let (Some(from), Some(to), Some(id)) = (el.attr("from"), el.attr("to"), el.attr("id")) else {
            return Some(Some(StreamError::new("improper-addressing")));
        };
        let valid = self.srv.is_local(to) && dialback::check(&self.s2s.secret, from, to, id, &el.text_content());
        let outcome = if valid { Outcome::Valid } else { Outcome::Invalid };
        self.write(&dialback::answer("verify", to, from, Some(id), outcome)).await
    }
}

/// Asks `originating`'s authoritative server whether `key` is its key for a stream to
/// `receiving` (ours) with id `stream_id`, over a fresh connection to it (XEP-0220 §2.3).
async fn verify(s2s: &S2s, srv: &Arc<Server>, receiving: &str, originating: &str, stream_id: &str, key: &str) -> Outcome {
    let mut o = match super::outgoing::open(s2s, srv, receiving, originating).await {
        Ok(o) => o,
        Err(f) => return Outcome::Error(f.err),
    };
    let q = dialback::element("verify", receiving, originating).attr_set("id", stream_id).text(key);
    if o.st.send(&q).await.is_err() {
        return Outcome::Error(StanzaError::new(Condition::RemoteServerNotFound));
    }
    let outcome = loop {
        match o.st.read_element().await {
            Ok(r) if r.is("verify", ns::DIALBACK) && r.attr("id") == Some(stream_id) && r.attr("from") == Some(originating) => {
                break match r.attr("type") {
                    Some("valid") => Outcome::Valid,
                    Some("invalid") => Outcome::Invalid,
                    _ => Outcome::Error(StanzaError::from_stanza(&r).unwrap_or_else(|| StanzaError::new(Condition::RemoteServerNotFound))),
                };
            }
            Ok(_) => continue,
            Err(_) => break Outcome::Error(StanzaError::new(Condition::RemoteServerNotFound)),
        }
    };
    o.st.close(None).await;
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(text: &str) -> Element {
        Element::new("auth", ns::SASL).attr_set("mechanism", "EXTERNAL").text(text)
    }

    #[test]
    fn external_identity_comes_from_authzid_or_header() {
        assert_eq!(external_identity(&auth("="), Some("a.test")).as_deref(), Some("a.test"));
        assert_eq!(external_identity(&auth(&B64.encode("A.Test")), Some("a.test")).as_deref(), Some("a.test"));
        assert_eq!(external_identity(&auth(&B64.encode("a.test")), None).as_deref(), Some("a.test"));
        assert_eq!(external_identity(&auth(&B64.encode("evil.test")), Some("a.test")), None);
        assert_eq!(external_identity(&auth("="), None), None);
        assert_eq!(external_identity(&auth("!!!"), Some("a.test")), None);
        let plain = Element::new("auth", ns::SASL).attr_set("mechanism", "PLAIN");
        assert_eq!(external_identity(&plain, Some("a.test")), None);
    }
}
