//! BOSH (XEP-0124 with XEP-0206): XMPP over long-polled HTTP requests, for older web clients.
//!
//! Each session is a [`Transport`] fed by HTTP requests: payloads go to the negotiation or session
//! in `rid` order (requests may arrive out of order within the window and are put back in
//! order), and outgoing stanzas wait for a held request. A session ends when the client
//! terminates it, the server closes the stream, or no request arrives for `inactivity` seconds
//! (then a resumable session hibernates, as with a dropped TCP connection).
//!
//! Not supported, as the XEPs allow: `pause`, `ack`-based reporting, key sequencing and
//! multiple streams per session.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use parking_lot::Mutex;
use quark_core::xml::{escape, StreamEvent, XmlError};
use quark_core::{ns, Element};
use rand::RngCore;
use tokio::sync::{mpsc, Notify};
use tokio::time::Instant;

use super::{AppState, Conn, WebState};
use crate::sasl::ChannelBindings;
use crate::transport::{StanzaReader, StanzaWriter, StreamError, Transport};

const MAX_SESSIONS: usize = 10_000;
/// Longest a request is held, in seconds (the client's `wait`, capped).
const MAX_WAIT: u64 = 60;
const INACTIVITY: u64 = 60;
/// Shortest time between polls we ask of `hold=0` clients.
const POLLING: u64 = 2;
/// Requests ahead of the next expected `rid` that are queued rather than refused.
const WINDOW: u64 = 2;
/// Responses kept for clients that resend a request (lost connection).
const CACHED_RESPONSES: usize = 4;
/// Output waiting for the client before the session's writes wait (like a full socket).
const OUT_LIMIT: usize = 1 << 20;
const BODY_TIMEOUT: Duration = Duration::from_secs(30);
/// How long creation and restart requests wait for the stream features.
const FEATURES_WAIT: Duration = Duration::from_secs(10);
const INBOUND_QUEUE: usize = 32;
const REAP_EVERY: Duration = Duration::from_secs(5);

#[derive(Default)]
pub(crate) struct Registry {
    map: Mutex<HashMap<String, Arc<Session>>>,
}

impl Registry {
    pub fn len(&self) -> usize {
        self.map.lock().len()
    }
    fn get(&self, sid: &str) -> Option<Arc<Session>> {
        self.map.lock().get(sid).cloned()
    }
    fn remove(&self, sid: &str) {
        self.map.lock().remove(sid);
    }
}

/// Why a session is over.
#[derive(Debug, Clone)]
enum End {
    /// The client sent `type='terminate'`.
    Client,
    /// The server closed the stream, perhaps with an error.
    Server(Option<StreamError>),
    /// Nothing heard for too long, or the client broke the protocol (`condition`).
    Dropped(&'static str),
}

struct Inner {
    /// The `rid` whose payload is processed next.
    next_rid: u64,
    /// A request's payload is being handed over right now.
    busy: bool,
    /// Serialized elements waiting for a response.
    out: Vec<String>,
    out_bytes: usize,
    held: usize,
    /// Held requests with a `rid` below this return now (a newer one took over).
    release_below: u64,
    last_seen: Instant,
    cache: VecDeque<(u64, String)>,
    ended: Option<(End, Instant)>,
    /// The stream id and domain from the negotiation's `open`.
    authid: Option<String>,
    from: String,
}

pub(crate) struct Session {
    sid: String,
    wait: Duration,
    hold: u64,
    inbound: Mutex<Option<mpsc::Sender<StreamEvent>>>,
    st: Mutex<Inner>,
    changed: Notify,
    bytes_in: AtomicU64,
}

fn xml_response(body: String) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/xml; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
        ],
        body,
    )
        .into_response()
}

fn terminate(condition: &str) -> Response {
    xml_response(format!("<body xmlns='{}' type='terminate' condition='{}'/>", ns::BOSH, escape(condition)))
}

pub(super) async fn preflight() -> Response {
    (
        StatusCode::NO_CONTENT,
        [
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            (header::ACCESS_CONTROL_ALLOW_METHODS, "POST, GET, OPTIONS"),
            (header::ACCESS_CONTROL_ALLOW_HEADERS, "Content-Type"),
            (header::ACCESS_CONTROL_MAX_AGE, "86400"),
        ],
    )
        .into_response()
}

pub(super) async fn info() -> Response {
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], "This is a BOSH endpoint (XEP-0206). Chat apps POST here.\n").into_response()
}

/// A BOSH attribute in the `urn:xmpp:xbosh` namespace, whatever prefix the client bound.
fn xbosh_attr<'a>(el: &'a Element, local: &str) -> Option<&'a str> {
    el.attr_ns(ns::XBOSH, local)
}

pub(super) async fn handler(State(st): AppState, Extension(conn): Extension<Conn>, headers: HeaderMap, body: Body) -> Response {
    let limit = usize::try_from(st.srv.config().limits.c2s_stanza_bytes).unwrap_or(usize::MAX).saturating_add(64 * 1024);
    let announced = headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<usize>().ok());
    if announced.is_some_and(|n| n > limit) {
        return terminate("policy-violation");
    }
    let bytes = match tokio::time::timeout(BODY_TIMEOUT, axum::body::to_bytes(body, limit)).await {
        Ok(Ok(b)) => b,
        Ok(Err(_)) => return terminate("policy-violation"),
        Err(_) => return (StatusCode::REQUEST_TIMEOUT, "The request body took too long.\n").into_response(),
    };
    let Some(el) = std::str::from_utf8(&bytes).ok().and_then(|t| Element::parse(t).ok()).filter(|e| e.is("body", ns::BOSH)) else {
        return terminate("bad-request");
    };
    let Some(rid) = el.attr("rid").and_then(|r| r.trim().parse::<u64>().ok()) else { return terminate("bad-request") };
    match el.attr("sid") {
        None => create(&st, &conn, &headers, el, rid).await,
        Some(sid) => match st.bosh.get(sid) {
            Some(s) => {
                s.bytes_in.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                s.request(&st, rid, el).await
            }
            None => terminate("item-not-found"),
        },
    }
}

/// A session creation request (XEP-0124 §7).
async fn create(st: &Arc<WebState>, conn: &Conn, headers: &HeaderMap, el: Element, rid: u64) -> Response {
    let srv = &st.srv;
    let Some(to) = el.attr("to").map(str::to_ascii_lowercase) else { return terminate("improper-addressing") };
    let Some(host) = srv.host(&to) else { return terminate("host-unknown") };
    if !host.settings().web {
        return terminate("policy-violation");
    }
    if st.bosh.len() >= MAX_SESSIONS {
        tracing::warn!("too many BOSH sessions; refusing a new one");
        return terminate("remote-connection-failed");
    }
    let wait = el.attr("wait").and_then(|w| w.parse::<u64>().ok()).unwrap_or(MAX_WAIT).min(MAX_WAIT);
    let hold = el.attr("hold").and_then(|h| h.parse::<u64>().ok()).unwrap_or(1).min(1);
    let mut raw = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut raw);
    let sid = hex::encode(raw);
    let (tx, rx) = mpsc::channel(INBOUND_QUEUE);
    let session = Arc::new(Session {
        sid: sid.clone(),
        wait: Duration::from_secs(wait),
        hold,
        inbound: Mutex::new(Some(tx.clone())),
        st: Mutex::new(Inner {
            next_rid: rid.wrapping_add(1),
            busy: false,
            out: Vec::new(),
            out_bytes: 0,
            held: 0,
            release_below: 0,
            last_seen: Instant::now(),
            cache: VecDeque::new(),
            ended: None,
            authid: None,
            from: host.domain.clone(),
        }),
        changed: Notify::new(),
        bytes_in: AtomicU64::new(0),
    });
    st.bosh.map.lock().insert(sid, session.clone());
    st.stats.bosh_sessions.fetch_add(1, Ordering::Relaxed);
    let peer = super::peer(conn, headers);
    let t = BoshTransport { session: session.clone(), rx, ip: peer.ip, secure: peer.secure, cb: ChannelBindings::default() };
    tokio::spawn(crate::c2s::serve(srv.clone(), Box::new(t)));
    let version = xbosh_attr(&el, "version").unwrap_or("1.0").to_string();
    let open = StreamEvent::Open { attrs: vec![("to".into(), to), ("version".into(), version)], default_ns: ns::CLIENT.into() };
    if tx.send(open).await.is_err() {
        return terminate("internal-server-error");
    }
    drop(tx);
    session.respond(st, rid, true, true, Instant::now() + FEATURES_WAIT.max(session.wait)).await
}

impl Session {
    /// A request on an existing session.
    async fn request(self: &Arc<Self>, st: &Arc<WebState>, rid: u64, el: Element) -> Response {
        // Wait for this request's turn: earlier rids are handed over first.
        let deadline = Instant::now() + self.wait.max(Duration::from_secs(5));
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut s = self.st.lock();
                if s.ended.is_some() {
                    // Whatever the stream said last goes out with the terminate.
                    let body = self.body(&mut s, false);
                    drop(s);
                    st.bosh.remove(&self.sid);
                    return xml_response(body);
                }
                if rid < s.next_rid || (rid == s.next_rid && s.busy) {
                    // A resent request: the answer it missed, if we still have it.
                    let cached = s.cache.iter().find(|(r, _)| *r == rid).map(|(_, b)| b.clone());
                    return xml_response(cached.unwrap_or_else(|| format!("<body xmlns='{}'/>", ns::BOSH)));
                }
                if rid > s.next_rid + WINDOW {
                    drop(s);
                    self.end(End::Dropped("item-not-found"));
                    st.bosh.remove(&self.sid);
                    return terminate("item-not-found");
                }
                if rid == s.next_rid {
                    s.busy = true;
                    s.last_seen = Instant::now();
                    break;
                }
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                // The requests before this one never came.
                self.end(End::Dropped("item-not-found"));
                st.bosh.remove(&self.sid);
                return terminate("item-not-found");
            }
        }

        let terminating = el.attr("type") == Some("terminate");
        let restart = xbosh_attr(&el, "restart") == Some("true");
        let mut events: Vec<StreamEvent> = Vec::new();
        if restart {
            let from = self.st.lock().from.clone();
            events.push(StreamEvent::Open {
                attrs: vec![("to".into(), from), ("version".into(), "1.0".into())],
                default_ns: ns::CLIENT.into(),
            });
        } else {
            for c in el.children() {
                let mut c = c.clone();
                c.rewrite_ns(ns::BOSH, ns::CLIENT);
                events.push(StreamEvent::Stanza(c));
            }
        }
        if terminating {
            events.push(StreamEvent::Close);
        }
        let fed = self.feed(events).await;
        {
            let mut s = self.st.lock();
            s.busy = false;
            s.next_rid = rid.wrapping_add(1);
            s.release_below = rid;
        }
        self.changed.notify_waiters();
        if !fed {
            self.end(End::Dropped("policy-violation"));
            st.bosh.remove(&self.sid);
            return terminate("policy-violation");
        }
        if terminating {
            self.end(End::Client);
            st.bosh.remove(&self.sid);
            return xml_response(format!("<body xmlns='{}' type='terminate'/>", ns::BOSH));
        }
        if restart {
            return self.respond(st, rid, false, true, Instant::now() + FEATURES_WAIT.max(self.wait)).await;
        }
        self.respond(st, rid, false, false, Instant::now() + self.wait).await
    }

    /// Hands events to the stream, in order. False when the stream is gone or stopped reading.
    async fn feed(&self, events: Vec<StreamEvent>) -> bool {
        let Some(tx) = self.inbound.lock().clone() else { return events.is_empty() };
        for ev in events {
            match tokio::time::timeout(BODY_TIMEOUT, tx.send(ev)).await {
                Ok(Ok(())) => {}
                _ => return false,
            }
        }
        true
    }

    /// Holds the request until there's output, a newer request takes over, or `deadline`.
    /// `creation`: the first response, with the session's attributes. `features`: wait for the
    /// stream features even when the client polls.
    async fn respond(self: &Arc<Self>, st: &Arc<WebState>, rid: u64, creation: bool, features: bool, deadline: Instant) -> Response {
        self.st.lock().held += 1;
        // Polling clients get an answer right away, except while their features are coming.
        let deadline = if self.hold == 0 && !features { Instant::now() } else { deadline };
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let ready = {
                let s = self.st.lock();
                !s.out.is_empty() || s.ended.is_some() || s.release_below > rid
            };
            if ready || tokio::time::timeout_at(deadline, notified).await.is_err() {
                break;
            }
        }
        let (body, ended) = {
            let mut s = self.st.lock();
            s.held -= 1;
            s.last_seen = Instant::now();
            let body = self.body(&mut s, creation);
            s.cache.push_back((rid, body.clone()));
            if s.cache.len() > CACHED_RESPONSES {
                s.cache.pop_front();
            }
            (body, s.ended.is_some())
        };
        // Writers waiting for room can go on.
        self.changed.notify_waiters();
        if ended {
            st.bosh.remove(&self.sid);
        }
        xml_response(body)
    }

    fn body(&self, s: &mut Inner, first: bool) -> String {
        let mut b = format!("<body xmlns='{}'", ns::BOSH);
        if first {
            let (authid, from) = (s.authid.as_deref().unwrap_or_default(), &s.from);
            b.push_str(&format!(
                " xmlns:xmpp='{}' xmlns:stream='{}' sid='{}' wait='{}' requests='{}' hold='{}' inactivity='{INACTIVITY}' polling='{POLLING}' \
                 ver='1.11' from='{}' authid='{}' xmpp:version='1.0' xmpp:restartlogic='true'",
                ns::XBOSH,
                ns::STREAM,
                self.sid,
                self.wait.as_secs(),
                self.hold + 1,
                self.hold,
                escape(from),
                escape(authid)
            ));
        }
        let mut error = None;
        if let Some((end, _)) = &s.ended {
            b.push_str(" type='terminate'");
            if let Some(c) = end_condition(end) {
                b.push_str(&format!(" condition='{c}'"));
            }
            if let End::Server(Some(e)) = end {
                error = Some(e.to_element().to_xml());
            }
        }
        let out = std::mem::take(&mut s.out);
        s.out_bytes = 0;
        if out.is_empty() && error.is_none() {
            b.push_str("/>");
            return b;
        }
        b.push('>');
        for x in out {
            b.push_str(&x);
        }
        if let Some(e) = error {
            b.push_str(&e);
        }
        b.push_str("</body>");
        b
    }

    /// Queues output, waiting while too much is already waiting for the client.
    async fn push(&self, el: &Element) -> io::Result<()> {
        let xml = el.to_xml();
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut s = self.st.lock();
                if s.ended.is_some() {
                    return Err(io::Error::new(io::ErrorKind::NotConnected, "BOSH session ended"));
                }
                if s.out_bytes < OUT_LIMIT {
                    s.out_bytes += xml.len();
                    s.out.push(xml);
                    return Ok(());
                }
            }
            notified.await;
        }
    }

    fn end(&self, why: End) {
        {
            let mut s = self.st.lock();
            if s.ended.is_none() {
                s.ended = Some((why, Instant::now()));
            }
        }
        // The stream sees the end of input once the queued events are read.
        self.inbound.lock().take();
        self.changed.notify_waiters();
    }
}

/// The `condition` a terminate carries; none for an orderly end.
fn end_condition(e: &End) -> Option<&'static str> {
    match e {
        End::Client | End::Server(None) => None,
        End::Server(Some(_)) => Some("remote-stream-error"),
        End::Dropped(c) => Some(c),
    }
}

/// Ends sessions nobody polls, and forgets finished ones.
pub(super) fn spawn_reaper(st: Arc<WebState>) {
    let mut shutdown = st.srv.shutdown_signal();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(REAP_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = shutdown.changed() => return,
            }
            let sessions: Vec<Arc<Session>> = st.bosh.map.lock().values().cloned().collect();
            for s in sessions {
                let (idle, gone) = {
                    let i = s.st.lock();
                    let idle = i.ended.is_none() && i.held == 0 && !i.busy && i.last_seen.elapsed() > Duration::from_secs(INACTIVITY);
                    let gone = i.ended.as_ref().is_some_and(|(_, at)| i.held == 0 && at.elapsed() > REAP_EVERY);
                    (idle, gone)
                };
                if idle {
                    tracing::debug!(sid = %s.sid, "BOSH session inactive");
                    s.end(End::Dropped("item-not-found"));
                    st.bosh.remove(&s.sid);
                } else if gone {
                    st.bosh.remove(&s.sid);
                }
            }
        }
    });
}

struct BoshTransport {
    session: Arc<Session>,
    rx: mpsc::Receiver<StreamEvent>,
    ip: IpAddr,
    secure: bool,
    cb: ChannelBindings,
}

#[async_trait]
impl Transport for BoshTransport {
    async fn read(&mut self) -> Result<Option<StreamEvent>, XmlError> {
        Ok(self.rx.recv().await)
    }

    async fn send(&mut self, el: &Element) -> io::Result<()> {
        self.session.push(el).await?;
        self.session.changed.notify_waiters();
        Ok(())
    }

    async fn open(&mut self, from: &str, id: &str, _to: Option<&str>) -> io::Result<()> {
        let mut s = self.session.st.lock();
        s.authid = Some(id.to_string());
        s.from = from.to_string();
        Ok(())
    }

    async fn close(&mut self, err: Option<&StreamError>) {
        self.session.end(End::Server(err.cloned()));
    }

    fn restart(&mut self) {}

    fn secure(&self) -> bool {
        self.secure
    }

    fn can_starttls(&self) -> bool {
        false
    }

    async fn starttls(&mut self) -> io::Result<()> {
        Err(io::Error::other("STARTTLS isn't available over BOSH"))
    }

    fn bindings(&self) -> &ChannelBindings {
        &self.cb
    }

    fn sni(&self) -> Option<&str> {
        None
    }

    fn peer(&self) -> Option<IpAddr> {
        Some(self.ip)
    }

    fn kind(&self) -> &'static str {
        "bosh"
    }

    fn split(self: Box<Self>) -> (Box<dyn StanzaReader>, Box<dyn StanzaWriter>) {
        let me = *self;
        (Box::new(BoshReader { rx: me.rx, session: me.session.clone() }), Box::new(BoshWriter { session: me.session }))
    }
}

struct BoshReader {
    rx: mpsc::Receiver<StreamEvent>,
    session: Arc<Session>,
}

#[async_trait]
impl StanzaReader for BoshReader {
    async fn read(&mut self) -> Result<Option<StreamEvent>, XmlError> {
        Ok(self.rx.recv().await)
    }
    fn bytes_read(&self) -> u64 {
        self.session.bytes_in.load(Ordering::Relaxed)
    }
}

struct BoshWriter {
    session: Arc<Session>,
}

#[async_trait]
impl StanzaWriter for BoshWriter {
    async fn write(&mut self, el: &Element) -> io::Result<()> {
        self.session.push(el).await
    }
    async fn flush(&mut self) -> io::Result<()> {
        self.session.changed.notify_waiters();
        Ok(())
    }
    /// Empty responses to held requests already keep the connection alive.
    async fn keepalive(&mut self) -> io::Result<()> {
        Ok(())
    }
    async fn close(&mut self, err: Option<&StreamError>) {
        self.session.end(End::Server(err.cloned()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xbosh_attributes_by_any_prefix() {
        let el =
            Element::parse("<body xmlns='http://jabber.org/protocol/httpbind' xmlns:x='urn:xmpp:xbosh' x:restart='true' xml:lang='en'/>")
                .unwrap();
        assert_eq!(xbosh_attr(&el, "restart"), Some("true"));
        assert_eq!(xbosh_attr(&el, "lang"), None);
    }

    #[test]
    fn end_conditions() {
        assert_eq!(end_condition(&End::Server(Some(StreamError::new("conflict")))), Some("remote-stream-error"));
        assert_eq!(end_condition(&End::Dropped("item-not-found")), Some("item-not-found"));
        assert_eq!(end_condition(&End::Client), None);
    }
}
