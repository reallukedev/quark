//! Client connections: listeners and stream negotiation (RFC 6120): STARTTLS, SASL or SASL2
//! (XEP-0388) with Bind2 (XEP-0386) and FAST (XEP-0484), resource binding, and resuming a
//! session (XEP-0198). Once bound, the session actor in [`session`] takes over.

pub mod fast;
pub mod session;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use parking_lot::Mutex;
use quark_core::xml::StreamEvent;
use quark_core::{ns, Element, Jid};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

use crate::sasl::{self, Failure, Sasl, Step};
use crate::server::{Host, Server};
use crate::sessions::SessionInfo;
use crate::transport::{StreamError, TcpTransport, Transport};

pub use fast::FastTokens;

/// Failed sign-ins per address, so password guessing gets slow.
#[derive(Default)]
pub struct AuthLimiter {
    map: Mutex<HashMap<IpAddr, (u32, std::time::Instant)>>,
}

impl AuthLimiter {
    const WINDOW: Duration = Duration::from_secs(60);

    pub fn blocked(&self, ip: Option<IpAddr>, limit: u32) -> bool {
        let Some(ip) = ip else { return false };
        let m = self.map.lock();
        m.get(&ip).is_some_and(|(n, t)| *n >= limit && t.elapsed() < Self::WINDOW)
    }

    pub fn failed(&self, ip: Option<IpAddr>) {
        let Some(ip) = ip else { return };
        let mut m = self.map.lock();
        if m.len() > 100_000 {
            m.retain(|_, (_, t)| t.elapsed() < Self::WINDOW);
        }
        let e = m.entry(ip).or_insert((0, std::time::Instant::now()));
        if e.1.elapsed() >= Self::WINDOW {
            *e = (0, std::time::Instant::now());
        }
        e.0 += 1;
    }
}

/// Accepts client connections. `direct_tls`: TLS from the first byte (XEP-0368).
pub async fn accept_loop(srv: Arc<Server>, listener: TcpListener, direct_tls: bool) -> std::io::Result<()> {
    if let Ok(addr) = listener.local_addr() {
        tracing::info!(%addr, direct_tls, "listening for clients");
    }
    let starttls = srv.certs.server_config(&[]);
    let direct = srv.certs.server_config(&[b"xmpp-client"]);
    let mut shutdown = srv.shutdown_signal();
    loop {
        let (tcp, _) = tokio::select! {
            r = listener.accept() => match r {
                Ok(x) => x,
                Err(e) => {
                    // Out of file descriptors and the like: back off instead of spinning.
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            },
            _ = shutdown.changed() => return Ok(()),
        };
        let srv = srv.clone();
        let (starttls, direct) = (starttls.clone(), direct.clone());
        tokio::spawn(async move {
            let cfg = srv.config();
            let t: Box<dyn Transport> = if direct_tls {
                let accept = tokio_rustls::TlsAcceptor::from(direct).accept(tcp);
                match tokio::time::timeout(Duration::from_secs(15), accept).await {
                    Ok(Ok(tls)) => Box::new(TcpTransport::tls(tls, ns::CLIENT, cfg.limits.c2s_stanza_bytes, srv.certs.clone())),
                    _ => return,
                }
            } else {
                Box::new(TcpTransport::plain(tcp, ns::CLIENT, cfg.limits.c2s_stanza_bytes, srv.certs.clone(), starttls))
            };
            serve(srv, t).await;
        });
    }
}

/// Runs a client connection from the first byte to the end of its session.
pub async fn serve(srv: Arc<Server>, mut t: Box<dyn Transport>) {
    srv.stats.c2s_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let limit = Duration::from_secs(srv.config().limits.auth_timeout_secs);
    let mut n = Negotiation::new(srv.clone());
    let outcome = match tokio::time::timeout(limit, n.run(t.as_mut())).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            t.close(e.as_ref()).await;
            return;
        }
        Err(_) => {
            t.close(Some(&StreamError::new("connection-timeout"))).await;
            return;
        }
    };
    match outcome {
        Outcome::Bound(b) => {
            let info =
                SessionInfo { ip: t.peer(), secure: t.secure(), since: quark_core::time::now_ms(), transport: t.kind(), client: b.client };
            let (reader, writer) = t.split();
            let handle = session::spawn(session::Start {
                srv: srv.clone(),
                host: b.host,
                jid: b.jid,
                info,
                writer,
                reader,
                prelude: b.prelude,
                carbons: b.carbons,
                inactive: b.inactive,
                sm: b.sm,
            });
            // An admin may have turned the account off or deleted it while this connection
            // was signing in; that sign-out only reached sessions already registered.
            let (user, domain) = (handle.jid.node().unwrap_or_default(), handle.jid.domain());
            match srv.accounts.info(domain, user).await {
                Ok(Some(i)) if i.enabled => {}
                Ok(_) => handle.close("not-authorized", Some("This account was turned off.".into())),
                Err(e) => tracing::warn!(error = %e, "couldn't recheck an account after sign-in"),
            }
        }
        Outcome::Resume { handle, h, wrap } => {
            let (reader, writer) = t.split();
            let (in_tx, in_rx) = mpsc::channel(32);
            let (reply, done) = oneshot::channel();
            let req = session::ResumeRequest { writer, inbound: in_rx, h, reply, wrap };
            if handle.post(session::SessionMsg::Resume(Box::new(req))) && done.await.unwrap_or(false) {
                let rate = srv.config().limits.c2s_bytes_per_sec;
                tokio::spawn(session::read_loop(reader, in_tx, rate));
            }
        }
    }
}

struct Bound {
    host: Arc<Host>,
    jid: Jid,
    client: Option<String>,
    prelude: Vec<Element>,
    carbons: bool,
    inactive: bool,
    sm: Option<bool>,
}

enum Outcome {
    Bound(Bound),
    Resume { handle: Arc<crate::sessions::SessionHandle>, h: u32, wrap: Option<Element> },
}

/// Options a SASL2 client asked for inline.
#[derive(Default)]
struct Inline {
    agent_id: Option<String>,
    software: Option<String>,
    bind: Option<Element>,
    resume: Option<Element>,
    request_token: Option<String>,
    fast_invalidate: bool,
}

struct Negotiation {
    srv: Arc<Server>,
    host: Option<Arc<Host>>,
    user: Option<String>,
    sasl: Option<Sasl>,
    /// Whether the current exchange is SASL2, and what it asked for inline.
    sasl2: Option<Inline>,
    mechanism: Option<String>,
    plus_offered: bool,
    /// Software name from SASL2's user-agent, kept for the session.
    client: Option<String>,
    /// Whether we've sent a stream header on this connection.
    header_sent: bool,
    /// Failed sign-in attempts on this stream.
    failures: u32,
    /// In-band registration state (an invite token sent with `<preauth/>`).
    register: crate::modules::register::PreauthState,
}

type NegResult<T> = Result<T, Option<StreamError>>;

/// Failed SASL attempts allowed on one stream.
const MAX_AUTH_TRIES: u32 = 5;

fn sasl_el(name: &str, b: Option<&[u8]>) -> Element {
    let e = Element::new(name, ns::SASL);
    match b {
        Some([]) => e.text("="),
        Some(d) => e.text(B64.encode(d)),
        None => e,
    }
}

fn failure_el(ns_: &str, f: Failure, text: Option<&str>) -> Element {
    let mut e = Element::new("failure", ns_).child(Element::new(f.as_str(), ns::SASL));
    if let Some(t) = text {
        e.append(Element::new("text", ns_).text(t));
    }
    e
}

fn decode_b64(text: &str) -> Option<Vec<u8>> {
    let t = text.trim();
    if t.is_empty() || t == "=" {
        return Some(Vec::new());
    }
    B64.decode(t).ok()
}

impl Negotiation {
    fn new(srv: Arc<Server>) -> Self {
        Negotiation {
            srv,
            host: None,
            user: None,
            sasl: None,
            sasl2: None,
            mechanism: None,
            plus_offered: false,
            client: None,
            header_sent: false,
            failures: 0,
            register: Default::default(),
        }
    }

    async fn run(&mut self, t: &mut dyn Transport) -> NegResult<Outcome> {
        use quark_core::xml::XmlError;
        loop {
            let err = match t.read().await {
                Ok(Some(ev)) => match self.event(t, ev).await {
                    Ok(Some(o)) => return Ok(o),
                    Ok(None) => continue,
                    Err(e) => e,
                },
                Ok(None) | Err(XmlError::Io(_)) => None,
                Err(XmlError::TooBig | XmlError::TooDeep) => Some(StreamError::new("policy-violation")),
                Err(XmlError::Restricted) => Some(StreamError::new("restricted-xml")),
                Err(XmlError::InvalidNamespace) => Some(StreamError::new("invalid-namespace")),
                Err(XmlError::Malformed(_)) => Some(StreamError::new("not-well-formed")),
            };
            // A stream error goes inside a stream: send our header first if we haven't yet
            // (RFC 6120 §4.9.1.2).
            if err.is_some() && !self.header_sent {
                let from = self.srv.hosts().first().map(|h| h.domain.clone()).unwrap_or_default();
                let _ = t.open(&from, &quark_core::new_id(), None).await;
            }
            return Err(err);
        }
    }

    async fn event(&mut self, t: &mut dyn Transport, ev: StreamEvent) -> NegResult<Option<Outcome>> {
        let el = match ev {
            StreamEvent::Open { attrs, default_ns } => {
                self.open(t, &attrs, &default_ns).await?;
                return Ok(None);
            }
            StreamEvent::Close => return Err(None),
            StreamEvent::Stanza(el) => el,
        };
        if self.host.is_none() {
            return Err(Some(StreamError::new("invalid-xml")));
        }
        self.element(t, el).await
    }

    fn host(&self) -> NegResult<Arc<Host>> {
        self.host.clone().ok_or(Some(StreamError::new("invalid-xml")))
    }

    async fn open(&mut self, t: &mut dyn Transport, attrs: &[(String, String)], default_ns: &str) -> NegResult<()> {
        let id = quark_core::new_id();
        let to = StreamEvent::open_attr(attrs, "to").map(str::to_ascii_lowercase);
        let fallback = self.srv.hosts().first().map(|h| h.domain.clone()).unwrap_or_default();
        let from = to.clone().unwrap_or_else(|| fallback.clone());
        // Answer with our header before any error, as RFC 6120 §4.9.1.2 requires.
        let _ = t.open(&from, &id, None).await;
        self.header_sent = true;
        if default_ns != ns::CLIENT && t.kind() == "tcp" {
            return Err(Some(StreamError::new("invalid-namespace")));
        }
        let Some(to) = to else { return Err(Some(StreamError::new("host-unknown"))) };
        let Some(host) = self.srv.host(&to) else {
            return Err(Some(StreamError::with_text("host-unknown", format!("This server doesn't serve {to}."))));
        };
        if StreamEvent::open_attr(attrs, "version").is_none_or(|v| !v.starts_with("1.")) {
            return Err(Some(StreamError::new("unsupported-version")));
        }
        if self.host.as_ref().is_some_and(|h| h.domain != host.domain) {
            return Err(Some(StreamError::new("host-unknown")));
        }
        self.host = Some(host.clone());
        let features = self.features(t, &host);
        t.send(&features).await.map_err(|_| None)
    }

    fn features(&mut self, t: &dyn Transport, host: &Arc<Host>) -> Element {
        let cfg = self.srv.config();
        let mut f = Element::new("features", ns::STREAM);
        if t.can_starttls() {
            let mut s = Element::new("starttls", ns::TLS);
            if cfg.tls.require_c2s {
                s.append(Element::new("required", ns::TLS));
                f.append(s);
                return f;
            }
            f.append(s);
        }
        if self.user.is_none() {
            let mechs = sasl::mechanisms(t.bindings(), t.secure());
            self.plus_offered = mechs.iter().any(|m| m.ends_with("-PLUS"));
            f.append(
                Element::new("mechanisms", ns::SASL).children_from(mechs.iter().map(|m| Element::new("mechanism", ns::SASL).text(*m))),
            );
            let kinds = t.bindings().kinds();
            if !kinds.is_empty() {
                f.append(
                    Element::new("sasl-channel-binding", ns::CHANNEL_BINDING)
                        .children_from(kinds.iter().map(|k| Element::new("channel-binding", ns::CHANNEL_BINDING).attr_set("type", *k))),
                );
            }
            let mut fast = Element::new("fast", ns::FAST);
            for m in sasl::FAST_MECHANISMS {
                if m != "HT-SHA-256-ENDP" || t.bindings().server_end_point.is_some() {
                    fast.append(Element::new("mechanism", ns::FAST).text(m));
                }
            }
            let bind_inline = Element::new("inline", ns::BIND2)
                .children_from([ns::CARBONS, ns::CSI, ns::SM].map(|v| Element::new("feature", ns::BIND2).attr_set("var", v)));
            f.append(
                Element::new("authentication", ns::SASL2)
                    .children_from(mechs.iter().map(|m| Element::new("mechanism", ns::SASL2).text(*m)))
                    .child(
                        Element::new("inline", ns::SASL2)
                            .child(Element::new("bind", ns::BIND2).child(bind_inline))
                            .child(Element::new("sm", ns::SM))
                            .child(fast),
                    ),
            );
            for e in crate::modules::register::preauth_features(&self.srv, host, t.secure()) {
                f.append(e);
            }
        } else {
            f.append(Element::new("bind", ns::BIND));
            f.append(Element::new("session", ns::SESSION).child(Element::new("optional", ns::SESSION)));
            f.append(Element::new("sm", ns::SM));
            for m in &self.srv.modules {
                for e in m.stream_features(host) {
                    f.append(e);
                }
            }
        }
        f
    }

    /// One top-level element during negotiation. Some(outcome) when the session can start.
    async fn element(&mut self, t: &mut dyn Transport, el: Element) -> NegResult<Option<Outcome>> {
        let host = self.host()?;
        let cfg = self.srv.config();
        match (el.ns(), el.name()) {
            (ns::TLS, "starttls") => {
                if !t.can_starttls() {
                    return Err(Some(StreamError::new("policy-violation")));
                }
                t.send(&Element::new("proceed", ns::TLS)).await.map_err(|_| None)?;
                if t.starttls().await.is_err() {
                    return Err(None);
                }
                Ok(None)
            }
            _ if !t.secure() && cfg.tls.require_c2s && el.ns() != ns::TLS => Err(Some(StreamError::with_text(
                "policy-violation",
                if t.can_starttls() { "Use TLS first (STARTTLS)." } else { "This server only accepts encrypted connections." },
            ))),
            (ns::SASL, "auth") if self.user.is_none() => {
                self.sasl2 = None;
                let mech = el.attr("mechanism").unwrap_or_default().to_string();
                // No text at all means no initial response; "=" means an empty one.
                let text = el.text_content();
                let initial = if text.trim().is_empty() {
                    None
                } else {
                    let Some(d) = decode_b64(&text) else {
                        t.send(&failure_el(ns::SASL, Failure::IncorrectEncoding, None)).await.map_err(|_| None)?;
                        return Ok(None);
                    };
                    Some(d)
                };
                self.start_sasl(t, &host, &mech, initial.as_deref()).await
            }
            (ns::SASL2, "authenticate") if self.user.is_none() => {
                let mech = el.attr("mechanism").unwrap_or_default().to_string();
                let initial = match el.get_child("initial-response", ns::SASL2) {
                    Some(r) => match decode_b64(&r.text_content()) {
                        Some(d) => Some(d),
                        None => {
                            t.send(&failure_el(ns::SASL2, Failure::IncorrectEncoding, None)).await.map_err(|_| None)?;
                            return Ok(None);
                        }
                    },
                    None => None,
                };
                let ua = el.get_child("user-agent", ns::SASL2);
                self.sasl2 = Some(Inline {
                    agent_id: ua.and_then(|u| u.attr("id")).map(str::to_string),
                    software: ua.and_then(|u| u.child_text("software", ns::SASL2)),
                    bind: el.get_child("bind", ns::BIND2).cloned(),
                    resume: el.get_child("resume", ns::SM).cloned(),
                    request_token: el.get_child("request-token", ns::FAST).and_then(|r| r.attr("mechanism")).map(str::to_string),
                    fast_invalidate: el.get_child("fast", ns::FAST).is_some_and(|f| matches!(f.attr("invalidate"), Some("true" | "1"))),
                });
                self.client = self.sasl2.as_ref().and_then(|i| i.software.clone());
                self.start_sasl(t, &host, &mech, initial.as_deref()).await
            }
            (ns::SASL, "response") | (ns::SASL2, "response") if self.sasl.is_some() => {
                let ns_ = el.ns().to_string();
                let Some(data) = decode_b64(&el.text_content()) else {
                    self.sasl = None;
                    t.send(&failure_el(&ns_, Failure::IncorrectEncoding, None)).await.map_err(|_| None)?;
                    return Ok(None);
                };
                let mut s = self.sasl.take().ok_or(None)?;
                let tokens = self.srv.fast_tokens.clone();
                let ctx = sasl::Context {
                    host: &host.domain,
                    accounts: &self.srv.accounts,
                    cb: t.bindings(),
                    secure: t.secure(),
                    plus_offered: self.plus_offered,
                    tokens: Some(&tokens),
                };
                let step = s.step(&ctx, &data).await;
                self.sasl = Some(s);
                self.after_step(t, &host, step).await
            }
            (ns::SASL, "abort") | (ns::SASL2, "abort") => {
                self.sasl = None;
                let n = el.ns().to_string();
                t.send(&failure_el(&n, Failure::Aborted, None)).await.map_err(|_| None)?;
                Ok(None)
            }
            (ns::CLIENT, "iq") if self.user.is_none() => {
                // Only in-band registration is allowed before signing in (XEP-0077).
                let reply = match el.first_child() {
                    Some(q) if q.is("query", ns::REGISTER) || q.is("preauth", ns::PARS) => {
                        crate::modules::register::preauth_with(&self.srv, &host, &el, t.secure(), t.peer(), &mut self.register).await
                    }
                    // Anything else before signing in ends the stream (RFC 6120 §4.3.5).
                    _ => return Err(Some(StreamError::new("not-authorized"))),
                };
                if let Some(r) = reply {
                    t.send(&r).await.map_err(|_| None)?;
                }
                Ok(None)
            }
            (ns::CLIENT, "iq") => self.bind_iq(t, &host, el).await,
            (ns::SM, "resume") if self.user.is_some() => {
                let user = self.user.clone().ok_or(None)?;
                match self.resume_target(&host, &user, &el) {
                    Ok((handle, h)) => Ok(Some(Outcome::Resume { handle, h, wrap: None })),
                    Err(f) => {
                        t.send(&f).await.map_err(|_| None)?;
                        Ok(None)
                    }
                }
            }
            (ns::SM, "enable") => {
                let f = Element::new("failed", ns::SM).child(Element::new("unexpected-request", ns::STANZAS));
                t.send(&f).await.map_err(|_| None)?;
                Ok(None)
            }
            (ns::CLIENT, _) => Err(Some(StreamError::new("not-authorized"))),
            _ => Err(Some(StreamError::new("unsupported-stanza-type"))),
        }
    }

    async fn start_sasl(
        &mut self,
        t: &mut dyn Transport,
        host: &Arc<Host>,
        mech: &str,
        initial: Option<&[u8]>,
    ) -> NegResult<Option<Outcome>> {
        let cfg = self.srv.config();
        if self.srv.auth_limiter.blocked(t.peer(), cfg.limits.auth_failures_per_minute) {
            let ns_ = if self.sasl2.is_some() { ns::SASL2 } else { ns::SASL };
            t.send(&failure_el(ns_, Failure::TemporaryAuthFailure, Some("Too many failed sign-ins. Wait a minute and try again.")))
                .await
                .map_err(|_| None)?;
            return Ok(None);
        }
        let offered = sasl::mechanisms(t.bindings(), t.secure());
        if !offered.contains(&mech) && !(self.sasl2.is_some() && mech.starts_with("HT-SHA-256-")) {
            let ns_ = if self.sasl2.is_some() { ns::SASL2 } else { ns::SASL };
            t.send(&failure_el(ns_, Failure::InvalidMechanism, None)).await.map_err(|_| None)?;
            return Ok(None);
        }
        self.mechanism = Some(mech.to_string());
        let tokens = self.srv.fast_tokens.clone();
        let ctx = sasl::Context {
            host: &host.domain,
            accounts: &self.srv.accounts,
            cb: t.bindings(),
            secure: t.secure(),
            plus_offered: self.plus_offered,
            tokens: Some(&tokens),
        };
        let (s, step) = Sasl::start(&ctx, mech, initial).await;
        self.sasl = s;
        self.after_step(t, host, step).await
    }

    async fn after_step(&mut self, t: &mut dyn Transport, host: &Arc<Host>, step: Step) -> NegResult<Option<Outcome>> {
        let v2 = self.sasl2.is_some();
        let ns_ = if v2 { ns::SASL2 } else { ns::SASL };
        match step {
            Step::Challenge(c) => {
                let e = if v2 { Element::new("challenge", ns::SASL2).text(B64.encode(&c)) } else { sasl_el("challenge", Some(&c)) };
                t.send(&e).await.map_err(|_| None)?;
                Ok(None)
            }
            Step::Failure(f, text) => {
                self.sasl = None;
                self.srv.auth_limiter.failed(t.peer());
                self.srv.stats.auth_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                t.send(&failure_el(ns_, f, text)).await.map_err(|_| None)?;
                // RFC 6120 §6.4.5: a few retries, then the stream ends.
                self.failures += 1;
                if self.failures >= MAX_AUTH_TRIES && f != Failure::Aborted {
                    return Err(Some(StreamError::with_text("policy-violation", "Too many failed sign-in attempts.")));
                }
                Ok(None)
            }
            Step::Success { user, data } => {
                self.sasl = None;
                self.user = Some(user.clone());
                if !v2 {
                    // No additional data: an empty <success/> (RFC 6120 §6.4.6).
                    t.send(&sasl_el("success", data.as_deref().filter(|d| !d.is_empty()))).await.map_err(|_| None)?;
                    t.restart();
                    return Ok(None);
                }
                self.sasl2_success(t, host, &user, data).await
            }
        }
    }

    /// SASL2 succeeded: apply what the client asked for inline and say so in `<success/>`.
    async fn sasl2_success(
        &mut self,
        t: &mut dyn Transport,
        host: &Arc<Host>,
        user: &str,
        data: Option<Vec<u8>>,
    ) -> NegResult<Option<Outcome>> {
        let inline = self.sasl2.take().unwrap_or_default();
        let bare = Jid::bare_unchecked(user, &host.domain);
        let mut success = Element::new("success", ns::SASL2);
        if let Some(d) = data {
            success.append(Element::new("additional-data", ns::SASL2).text(B64.encode(d)));
        }
        if let Some(agent) = &inline.agent_id {
            if inline.fast_invalidate {
                let _ = self.srv.fast_tokens.revoke(&host.domain, user, agent).await;
            }
            if let Some(mech) = inline.request_token.as_deref().filter(|m| sasl::FAST_MECHANISMS.contains(m)) {
                if let Ok((token, expiry)) = self.srv.fast_tokens.issue(&host.domain, user, agent, mech).await {
                    success.append(
                        Element::new("token", ns::FAST).attr_set("token", token).attr_set("expiry", quark_core::time::xep82(expiry)),
                    );
                }
            }
        }

        if let Some(r) = &inline.resume {
            match self.resume_target(host, user, r) {
                Ok((handle, h)) => {
                    success.prepend(Element::new("authorization-identifier", ns::SASL2).text(handle.jid.to_string()));
                    return Ok(Some(Outcome::Resume { handle, h, wrap: Some(success) }));
                }
                Err(failed) => success.append(failed),
            }
        }

        let Some(bind) = inline.bind else {
            success.prepend(Element::new("authorization-identifier", ns::SASL2).text(bare.to_string()));
            t.send(&success).await.map_err(|_| None)?;
            // No restart with SASL2; the client binds next and needs the post-auth features.
            let f = self.features(t, host);
            t.send(&f).await.map_err(|_| None)?;
            return Ok(None);
        };
        // Bind2 resources are the client's tag plus something unique (XEP-0386 §2.3).
        let tag: String =
            bind.child_text("tag", ns::BIND2).unwrap_or_default().chars().filter(|c| !c.is_control() && *c != '/').take(32).collect();
        let resource = match self.new_resource(&bare, None) {
            Ok(r) if !tag.trim().is_empty() => format!("{}.{r}", tag.trim()),
            Ok(r) => r,
            Err(e) => {
                let f = failure_el(ns::SASL2, Failure::TemporaryAuthFailure, Some(&e));
                t.send(&f).await.map_err(|_| None)?;
                return Err(None);
            }
        };
        let full = bare.with_resource(&resource).map_err(|_| None)?;
        success.prepend(Element::new("authorization-identifier", ns::SASL2).text(full.to_string()));
        let carbons = bind.has_child("enable", ns::CARBONS);
        let inactive = bind.has_child("inactive", ns::CSI);
        let sm = bind.get_child("enable", ns::SM).map(|e| matches!(e.attr("resume"), Some("true" | "1")));
        // The session puts <enabled/> inside <bound/> itself; carbons and CSI need no answer.
        let bound = Element::new("bound", ns::BIND2);
        Ok(Some(Outcome::Bound(Bound {
            host: host.clone(),
            jid: full,
            client: self.client.clone(),
            prelude: vec![success.child(bound)],
            carbons,
            inactive,
            sm,
        })))
    }

    /// Finds the session a `<resume/>` names, or the `<failed/>` to send.
    fn resume_target(&self, host: &Arc<Host>, user: &str, r: &Element) -> Result<(Arc<crate::sessions::SessionHandle>, u32), Element> {
        let failed = |cond: &str| Element::new("failed", ns::SM).child(Element::new(cond, ns::STANZAS));
        let (Some(previd), Some(h)) = (r.attr("previd"), r.attr("h").and_then(|h| h.parse::<u32>().ok())) else {
            return Err(failed("bad-request"));
        };
        match self.srv.sessions.by_smid(previd) {
            Some(s) if s.jid.domain() == host.domain && s.jid.node() == Some(user) => Ok((s, h)),
            _ => Err(failed("item-not-found")),
        }
    }

    /// A resource for a new session: the client's choice when free (an old session with it is
    /// replaced), else a fresh one. Refuses when the account has too many sessions.
    fn new_resource(&self, bare: &Jid, wanted: Option<&str>) -> Result<String, String> {
        let max = self.srv.config().limits.max_sessions_per_account;
        let existing = self.srv.sessions.of(bare);
        let replacing = wanted.is_some_and(|w| existing.iter().any(|s| s.jid.resource() == Some(w)));
        if existing.len() >= max && !replacing {
            return Err(format!("This account already has {max} devices online."));
        }
        Ok(match wanted {
            Some(w) if bare.with_resource(w).is_ok() => w.to_string(),
            _ => quark_core::new_id()[..12].to_string(),
        })
    }

    /// Resource binding (RFC 6120 §7) and the legacy session IQ.
    async fn bind_iq(&mut self, t: &mut dyn Transport, host: &Arc<Host>, el: Element) -> NegResult<Option<Outcome>> {
        use quark_core::stanza::{error_reply, iq_result};
        use quark_core::{Condition, StanzaError};
        let Some(user) = self.user.clone() else { return Err(Some(StreamError::new("not-authorized"))) };
        let bare = Jid::bare_unchecked(&user, &host.domain);
        let Some(bind) = el.get_child("bind", ns::BIND).filter(|_| el.attr("type") == Some("set")) else {
            let reply = if el.has_child("session", ns::SESSION) {
                Some(iq_result(&el))
            } else {
                error_reply(&el, &StanzaError::new(Condition::NotAllowed).with_text("Bind a resource first."))
            };
            if let Some(r) = reply {
                t.send(&r).await.map_err(|_| None)?;
            }
            return Ok(None);
        };
        let wanted = bind.child_text("resource", ns::BIND).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        if let Some(w) = &wanted {
            if bare.with_resource(w).is_err() {
                if let Some(r) = error_reply(&el, &StanzaError::bad_request().with_text("That resource isn't valid.")) {
                    t.send(&r).await.map_err(|_| None)?;
                }
                return Ok(None);
            }
        }
        let resource = match self.new_resource(&bare, wanted.as_deref()) {
            Ok(r) => r,
            Err(text) => {
                if let Some(r) = error_reply(&el, &StanzaError::new(Condition::ResourceConstraint).with_text(text)) {
                    t.send(&r).await.map_err(|_| None)?;
                }
                return Ok(None);
            }
        };
        let full = bare.with_resource(&resource).map_err(|_| None)?;
        let mut result = iq_result(&el);
        result.remove_attr("from");
        result.remove_attr("to");
        result.append(Element::new("bind", ns::BIND).text_child("jid", ns::BIND, full.to_string()));
        Ok(Some(Outcome::Bound(Bound {
            host: host.clone(),
            jid: full,
            client: self.client.clone(),
            prelude: vec![result],
            carbons: false,
            inactive: false,
            sm: None,
        })))
    }
}
