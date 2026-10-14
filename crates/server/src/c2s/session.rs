//! A signed-in client: one actor task per session owns the writer, the stream management queue
//! and the CSI buffer. A separate reader task parses the client's stanzas and hands them over a
//! small bounded channel, so a client sending faster than we process is slowed at the socket.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use quark_core::xml::{StreamEvent, XmlError};
use quark_core::{ns, Element, Jid};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::server::{Host, Server};
use crate::sessions::{SessionHandle, SessionInfo};
use crate::transport::{StanzaReader, StanzaWriter, StreamError};

/// Messages to a session actor.
pub enum SessionMsg {
    Deliver(Element),
    Close { condition: &'static str, text: Option<String> },
    Resume(Box<ResumeRequest>),
}

/// A new connection taking over a hibernating session (XEP-0198 §5).
pub struct ResumeRequest {
    pub writer: Box<dyn StanzaWriter>,
    pub inbound: mpsc::Receiver<ReaderEvent>,
    /// The client's count of stanzas it received.
    pub h: u32,
    /// Ok when resumed: the actor already sent `<resumed/>`.
    pub reply: oneshot::Sender<bool>,
    /// SASL2: the `<success/>` to carry `<resumed/>` inside, instead of sending it alone.
    pub wrap: Option<Element>,
}

pub enum ReaderEvent {
    Stanza(Element),
    /// The connection ended: cleanly (`</stream:stream>`), by dropping, or with a stream error.
    Gone(Gone),
}

pub enum Gone {
    /// The client closed the stream: it's signing out.
    Closed,
    /// The connection dropped.
    Dropped,
    /// The client broke the protocol.
    Error(StreamError),
}

/// What the session starts with, from negotiation.
pub struct Start {
    pub srv: Arc<Server>,
    pub host: Arc<Host>,
    pub jid: Jid,
    pub info: SessionInfo,
    pub writer: Box<dyn StanzaWriter>,
    pub reader: Box<dyn StanzaReader>,
    /// Sent before anything else (the bind result, a SASL2 success).
    pub prelude: Vec<Element>,
    /// Bind2 inline enables (XEP-0386).
    pub carbons: bool,
    pub inactive: bool,
    /// Bind2 asked for stream management: (resume).
    pub sm: Option<bool>,
}

/// Stream management state (XEP-0198).
struct Sm {
    id: Option<String>,
    /// Stanzas received from the client.
    in_h: u32,
    /// Stanzas sent to the client.
    out_h: u32,
    /// Sent but not yet acknowledged, oldest first. The last one is number `out_h`.
    unacked: VecDeque<Element>,
    /// Sent stanzas since we last asked for an ack.
    since_request: u32,
}

impl Sm {
    fn new(id: Option<String>) -> Self {
        Sm { id, in_h: 0, out_h: 0, unacked: VecDeque::new(), since_request: 0 }
    }

    /// Drops what the client confirmed. False when `h` is impossible (acks more than we sent).
    fn ack(&mut self, h: u32) -> bool {
        let pending = self.unacked.len() as u32;
        let acked_before = self.out_h.wrapping_sub(pending);
        let newly = h.wrapping_sub(acked_before);
        if newly > pending {
            return false;
        }
        self.unacked.drain(..newly as usize);
        true
    }
}

const INBOUND_QUEUE: usize = 32;
const CSI_BUFFER: usize = 256;
/// How long without hearing from the client before we check on it, then give up.
const IDLE_CHECK: Duration = Duration::from_secs(300);
const IDLE_GIVE_UP: Duration = Duration::from_secs(120);
/// Ask for an ack after this many unacknowledged stanzas.
const ACK_EVERY: u32 = 5;
/// Stanzas a hibernating session holds before it gives up waiting to be resumed.
const HIBERNATION_QUEUE: usize = 5_000;
/// Writes between flushes while draining a burst.
const DRAIN_BATCH: usize = 64;
/// Longest a single write or flush may take. A client that stops reading (but keeps the TCP
/// connection open) fills its socket buffer and would otherwise park the actor in a write
/// forever, where neither new stanzas nor an admin's sign-out can reach it.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// A writer whose writes and flushes fail with `TimedOut` after `limit`, so the session treats
/// a stuck connection like a dropped one.
pub struct TimedWriter {
    inner: Box<dyn StanzaWriter>,
    limit: Duration,
}

impl TimedWriter {
    pub fn boxed(inner: Box<dyn StanzaWriter>, limit: Duration) -> Box<dyn StanzaWriter> {
        Box::new(TimedWriter { inner, limit })
    }
}

async fn timed(limit: Duration, f: impl std::future::Future<Output = std::io::Result<()>>) -> std::io::Result<()> {
    tokio::time::timeout(limit, f)
        .await
        .unwrap_or_else(|_| Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "the client stopped reading")))
}

#[async_trait::async_trait]
impl StanzaWriter for TimedWriter {
    async fn write(&mut self, el: &Element) -> std::io::Result<()> {
        timed(self.limit, self.inner.write(el)).await
    }
    async fn flush(&mut self) -> std::io::Result<()> {
        timed(self.limit, self.inner.flush()).await
    }
    async fn keepalive(&mut self) -> std::io::Result<()> {
        timed(self.limit, self.inner.keepalive()).await
    }
    async fn close(&mut self, err: Option<&StreamError>) {
        // Transports bound their own close; this bounds it again for any that don't.
        let _ = tokio::time::timeout(self.limit, self.inner.close(err)).await;
    }
}

/// Registers and runs a new session. Returns its handle once it's in the registry.
pub fn spawn(s: Start) -> Arc<SessionHandle> {
    let (tx, rx) = mpsc::unbounded_channel();
    let queued = Arc::new(AtomicUsize::new(0));
    let cfg = s.srv.config();
    let handle = Arc::new(SessionHandle::new(s.jid.clone(), s.info, tx, queued.clone(), cfg.limits.max_queue));
    {
        let mut f = handle.flags.lock();
        f.carbons = s.carbons;
        f.inactive = s.inactive;
    }
    if let Some(old) = s.srv.sessions.add(handle.clone()) {
        old.close("conflict", Some("Signed in again from another place with the same resource.".into()));
    }
    let (in_tx, in_rx) = mpsc::channel(INBOUND_QUEUE);
    tokio::spawn(read_loop(s.reader, in_tx, cfg.limits.c2s_bytes_per_sec));
    let mut sm = None;
    if let Some(resume) = s.sm {
        sm = Some(enable_sm(&s.srv, &handle, resume));
    }
    let actor = Actor {
        srv: s.srv,
        host: s.host,
        handle: handle.clone(),
        rx,
        queued,
        inbound: Some(in_rx),
        writer: Some(TimedWriter::boxed(s.writer, WRITE_TIMEOUT)),
        write_failed: false,
        sm,
        csi: Vec::new(),
        hibernate_until: None,
        last_heard: Instant::now(),
        checking_since: None,
        resume_secs: cfg.limits.resume_secs,
    };
    tokio::spawn(actor.run(s.prelude));
    handle
}

/// Enables stream management; returns the state (the `<enabled/>` is written by the caller).
fn enable_sm(srv: &Arc<Server>, handle: &Arc<SessionHandle>, resume: bool) -> Sm {
    let id = resume.then(quark_core::new_id);
    if let Some(id) = &id {
        let mut f = handle.flags.lock();
        f.resumable = true;
        f.smid = Some(id.clone());
        drop(f);
        srv.sessions.register_smid(id, handle.clone());
    }
    Sm::new(id)
}

/// Reads stanzas and passes them on, holding a client to `rate` bytes per second on average
/// (with a burst allowance) by simply not reading faster.
pub(super) async fn read_loop(mut r: Box<dyn StanzaReader>, tx: mpsc::Sender<ReaderEvent>, rate: u64) {
    let burst = (rate * 4) as f64;
    let mut tokens = burst;
    let mut last = Instant::now();
    let mut seen = r.bytes_read();
    loop {
        let ev = match r.read().await {
            Ok(Some(StreamEvent::Stanza(el))) => ReaderEvent::Stanza(el),
            Ok(Some(StreamEvent::Close)) => ReaderEvent::Gone(Gone::Closed),
            Ok(Some(StreamEvent::Open { .. })) => ReaderEvent::Gone(Gone::Error(StreamError::new("invalid-xml"))),
            Ok(None) => ReaderEvent::Gone(Gone::Dropped),
            Err(XmlError::Io(_)) => ReaderEvent::Gone(Gone::Dropped),
            Err(XmlError::TooBig | XmlError::TooDeep) => {
                ReaderEvent::Gone(Gone::Error(StreamError::with_text("policy-violation", "Stanza too big.")))
            }
            Err(XmlError::Restricted) => ReaderEvent::Gone(Gone::Error(StreamError::new("restricted-xml"))),
            Err(XmlError::Malformed(_) | XmlError::InvalidNamespace) => ReaderEvent::Gone(Gone::Error(StreamError::new("not-well-formed"))),
        };
        let done = matches!(ev, ReaderEvent::Gone(_));
        if tx.send(ev).await.is_err() || done {
            return;
        }
        if rate > 0 {
            let now = Instant::now();
            tokens = (tokens + now.duration_since(last).as_secs_f64() * rate as f64).min(burst);
            last = now;
            let total = r.bytes_read();
            tokens -= total.saturating_sub(seen) as f64;
            seen = total;
            if tokens < 0.0 {
                tokio::time::sleep(Duration::from_secs_f64(-tokens / rate as f64)).await;
            }
        }
    }
}

struct Actor {
    srv: Arc<Server>,
    host: Arc<Host>,
    handle: Arc<SessionHandle>,
    rx: mpsc::UnboundedReceiver<SessionMsg>,
    queued: Arc<AtomicUsize>,
    inbound: Option<mpsc::Receiver<ReaderEvent>>,
    writer: Option<Box<dyn StanzaWriter>>,
    /// A write or flush failed (or timed out): the connection is as good as gone even though
    /// the reader may never notice (a client that stopped reading but still sends nothing).
    write_failed: bool,
    sm: Option<Sm>,
    /// Stanzas held back while the app is in the background (CSI, XEP-0352).
    csi: Vec<Element>,
    hibernate_until: Option<Instant>,
    last_heard: Instant,
    /// When we last asked a quiet client whether it's still there.
    checking_since: Option<Instant>,
    resume_secs: u64,
}

enum Next {
    Msg(Option<SessionMsg>),
    Inbound(Option<ReaderEvent>),
    Expired,
    Tick,
}

/// Why the session ends.
enum End {
    /// Signed out or closed by the server: no hibernation.
    Final,
    /// The connection is gone; hibernate if resumable.
    Lost,
}

impl Actor {
    async fn run(mut self, mut prelude: Vec<Element>) {
        if let Some(sm) = &self.sm {
            let enabled = sm_enabled(sm, self.resume_secs);
            // Bind2 reports it inside <bound/>; otherwise it follows the prelude.
            match prelude.last_mut().and_then(|s| s.get_child_mut("bound", ns::BIND2)) {
                Some(bound) => bound.append(enabled),
                None => prelude.push(enabled),
            }
        }
        for el in prelude {
            self.write_raw(&el).await;
        }
        self.flush().await;
        self.srv.emit(&crate::modules::Event::SessionStarted { jid: self.handle.jid.clone() }).await;

        let mut tick = tokio::time::interval(Duration::from_secs(30));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let next = tokio::select! {
                biased;
                m = self.rx.recv() => Next::Msg(m),
                i = recv_opt(&mut self.inbound) => Next::Inbound(i),
                _ = sleep_opt(self.hibernate_until) => Next::Expired,
                _ = tick.tick() => Next::Tick,
            };
            let end = match next {
                Next::Msg(None) => Some(End::Final),
                Next::Msg(Some(m)) => self.on_msg(m).await,
                Next::Inbound(None) => self.lost(),
                Next::Inbound(Some(ev)) => self.on_inbound(ev).await,
                Next::Expired => Some(End::Final),
                Next::Tick => self.on_tick().await,
            };
            let end = end.or_else(|| self.write_failure());
            if let Some(end) = end {
                match end {
                    End::Lost if self.resumable() => self.hibernate(),
                    _ => break,
                }
            } else {
                // Drain what's ready without waiting, then flush once: one write for a burst.
                let mut n = 0;
                while n < DRAIN_BATCH {
                    let Ok(m) = self.rx.try_recv() else { break };
                    n += 1;
                    let end = self.on_msg(m).await;
                    if let Some(end) = end.or_else(|| self.write_failure()) {
                        if matches!(end, End::Final) || !self.resumable() {
                            self.finish().await;
                            return;
                        }
                        self.hibernate();
                        break;
                    }
                }
            }
            self.flush().await;
            if self.write_failure().is_some() {
                if !self.resumable() {
                    break;
                }
                self.hibernate();
            }
        }
        self.finish().await;
    }

    /// `End::Lost` once after a write failed; the reader is dropped with the writer, which
    /// closes the connection.
    fn write_failure(&mut self) -> Option<End> {
        if !std::mem::take(&mut self.write_failed) {
            return None;
        }
        tracing::debug!(jid = %self.handle.jid, "couldn't write to the client; treating the connection as lost");
        self.lost()
    }

    fn resumable(&self) -> bool {
        self.sm.as_ref().is_some_and(|s| s.id.is_some())
    }

    fn lost(&mut self) -> Option<End> {
        self.inbound = None;
        Some(End::Lost)
    }

    fn hibernate(&mut self) {
        tracing::debug!(jid = %self.handle.jid, "session hibernating");
        self.writer = None;
        self.inbound = None;
        self.handle.flags.lock().hibernating = true;
        self.hibernate_until = Some(Instant::now() + Duration::from_secs(self.resume_secs));
    }

    async fn on_msg(&mut self, m: SessionMsg) -> Option<End> {
        match m {
            SessionMsg::Deliver(el) => {
                self.queued.fetch_sub(1, Ordering::Relaxed);
                self.deliver(el).await
            }
            SessionMsg::Close { condition, text } => {
                if let Some(w) = self.writer.as_mut() {
                    let _ = w.flush().await;
                    w.close(Some(&StreamError { condition, text, app: None })).await;
                }
                self.writer = None;
                Some(End::Final)
            }
            SessionMsg::Resume(req) => self.resume(*req).await,
        }
    }

    async fn on_inbound(&mut self, ev: ReaderEvent) -> Option<End> {
        self.last_heard = Instant::now();
        self.checking_since = None;
        let el = match ev {
            ReaderEvent::Stanza(el) => el,
            ReaderEvent::Gone(Gone::Closed) => {
                if let Some(w) = self.writer.as_mut() {
                    let _ = w.flush().await;
                    w.close(None).await;
                }
                self.writer = None;
                return Some(End::Final);
            }
            ReaderEvent::Gone(Gone::Dropped) => return self.lost(),
            ReaderEvent::Gone(Gone::Error(e)) => {
                if let Some(w) = self.writer.as_mut() {
                    let _ = w.flush().await;
                    w.close(Some(&e)).await;
                }
                self.writer = None;
                return Some(End::Final);
            }
        };
        match (el.ns(), el.name()) {
            (ns::SM, "r") => {
                if let Some(sm) = &self.sm {
                    let a = Element::new("a", ns::SM).attr_set("h", sm.in_h.to_string());
                    self.write_raw(&a).await;
                }
                None
            }
            (ns::SM, "a") => {
                let h = el.attr("h").and_then(|h| h.parse::<u32>().ok());
                let sm = self.sm.as_mut()?;
                if h.is_some_and(|h| sm.ack(h)) {
                    return None;
                }
                // XEP-0198 §5: say what was claimed and what was really sent.
                let sent = sm.out_h;
                let too_high = Element::new("handled-count-too-high", ns::SM)
                    .attr_set("h", h.unwrap_or(0).to_string())
                    .attr_set("send-count", sent.to_string());
                self.close_with(StreamError { condition: "undefined-condition", text: None, app: Some(Box::new(too_high)) }).await
            }
            (ns::SM, "enable") => {
                if self.sm.is_some() {
                    let f = Element::new("failed", ns::SM).child(Element::new("unexpected-request", ns::STANZAS));
                    self.write_raw(&f).await;
                    return None;
                }
                let resume = matches!(el.attr("resume"), Some("true" | "1"));
                let sm = enable_sm(&self.srv, &self.handle, resume);
                let enabled = sm_enabled(&sm, self.resume_secs);
                self.sm = Some(sm);
                self.write_raw(&enabled).await;
                None
            }
            (ns::CSI, "active") => {
                self.handle.flags.lock().inactive = false;
                self.flush_csi().await;
                None
            }
            (ns::CSI, "inactive") => {
                self.handle.flags.lock().inactive = true;
                None
            }
            (ns::CLIENT, "iq" | "message" | "presence") => {
                if let Some(sm) = self.sm.as_mut() {
                    sm.in_h = sm.in_h.wrapping_add(1);
                }
                self.srv.count_in();
                crate::router::from_client(&self.srv, &self.host, &self.handle, el).await;
                None
            }
            _ => self.fail("unsupported-stanza-type", "").await,
        }
    }

    async fn fail(&mut self, condition: &'static str, text: &str) -> Option<End> {
        self.close_with(StreamError { condition, text: (!text.is_empty()).then(|| text.to_string()), app: None }).await
    }

    async fn close_with(&mut self, e: StreamError) -> Option<End> {
        if let Some(w) = self.writer.as_mut() {
            let _ = w.flush().await;
            w.close(Some(&e)).await;
        }
        self.writer = None;
        Some(End::Final)
    }

    async fn on_tick(&mut self) -> Option<End> {
        // Hibernating: nobody to check on.
        self.writer.as_ref()?;
        let quiet = self.last_heard.elapsed();
        if let Some(since) = self.checking_since {
            if since.elapsed() > IDLE_GIVE_UP {
                tracing::debug!(jid = %self.handle.jid, "client stopped answering");
                return self.lost();
            }
        } else if quiet > IDLE_CHECK {
            self.checking_since = Some(Instant::now());
            // A client answers either, so a dead connection is noticed even through NAT boxes
            // that keep the TCP connection looking alive.
            let probe = if self.sm.is_some() {
                Element::new("r", ns::SM)
            } else {
                quark_core::stanza::iq(
                    "get",
                    &quark_core::new_id(),
                    Some(&self.host.domain),
                    Some(&self.handle.jid.to_string()),
                    Element::new("ping", ns::PING),
                )
            };
            self.write_raw(&probe).await;
        }
        None
    }

    /// A stanza for the client: held back while the app is in the background if it can wait.
    async fn deliver(&mut self, el: Element) -> Option<End> {
        if self.handle.flags.lock().inactive && !urgent(&el) {
            if el.name() == "presence" {
                // Only the latest presence from each contact matters.
                let from = el.attr("from").map(str::to_string);
                self.csi.retain(|x| x.name() != "presence" || x.attr("from").map(str::to_string) != from);
            }
            self.csi.push(el);
            if self.csi.len() >= CSI_BUFFER {
                self.flush_csi().await;
            }
            return None;
        }
        self.flush_csi().await;
        self.send(el).await;
        // A session nobody resumes can't hoard messages forever.
        if self.writer.is_none() && self.sm.as_ref().is_some_and(|s| s.unacked.len() > HIBERNATION_QUEUE) {
            return Some(End::Final);
        }
        None
    }

    async fn flush_csi(&mut self) {
        for el in std::mem::take(&mut self.csi) {
            self.send(el).await;
        }
    }

    /// Sends a counted stanza (kept for resending until acked when SM is on).
    async fn send(&mut self, el: Element) {
        self.srv.count_out();
        let mut ask = false;
        if let Some(sm) = self.sm.as_mut() {
            sm.out_h = sm.out_h.wrapping_add(1);
            sm.since_request += 1;
            if sm.since_request >= ACK_EVERY {
                sm.since_request = 0;
                ask = true;
            }
            self.write_raw(&el).await;
            if let Some(sm) = self.sm.as_mut() {
                sm.unacked.push_back(el);
            }
        } else {
            self.write_raw(&el).await;
        }
        if ask {
            self.write_raw(&Element::new("r", ns::SM)).await;
        }
    }

    async fn write_raw(&mut self, el: &Element) {
        if let Some(w) = self.writer.as_mut() {
            if w.write(el).await.is_err() {
                self.writer = None;
                self.write_failed = true;
            }
        }
    }

    async fn flush(&mut self) {
        if let Some(w) = self.writer.as_mut() {
            if w.flush().await.is_err() {
                self.writer = None;
                self.write_failed = true;
            }
        }
    }

    async fn resume(&mut self, mut req: ResumeRequest) -> Option<End> {
        let Some(sm) = self.sm.as_mut() else {
            let _ = req.reply.send(false);
            return None;
        };
        if !sm.ack(req.h) {
            let f = Element::new("failed", ns::SM).child(Element::new("unexpected-request", ns::STANZAS));
            let _ = req.writer.write(&f).await;
            req.writer.close(None).await;
            let _ = req.reply.send(false);
            return None;
        }
        // The old connection, if it's still half there, is dropped for the new one.
        if let Some(mut old) = self.writer.take() {
            old.close(Some(&StreamError::with_text("conflict", "Resumed from another connection."))).await;
        }
        let resumed = Element::new("resumed", ns::SM).attr_set("h", sm.in_h.to_string()).attr_opt("previd", sm.id.clone());
        let replay: Vec<Element> = sm.unacked.iter().cloned().collect();
        let mut w = TimedWriter::boxed(req.writer, WRITE_TIMEOUT);
        let first = match req.wrap {
            Some(success) => success.child(resumed),
            None => resumed,
        };
        let ok = w.write(&first).await.is_ok();
        for el in &replay {
            if !ok || w.write(el).await.is_err() {
                break;
            }
        }
        self.writer = Some(w);
        self.inbound = Some(req.inbound);
        self.hibernate_until = None;
        self.last_heard = Instant::now();
        self.checking_since = None;
        self.handle.flags.lock().hibernating = false;
        let _ = req.reply.send(ok);
        tracing::debug!(jid = %self.handle.jid, resent = replay.len(), "session resumed");
        self.flush_csi().await;
        None
    }

    /// The session is over for good: tell contacts, hand back undelivered messages.
    async fn finish(mut self) {
        self.flush().await;
        if let Some(mut w) = self.writer.take() {
            w.close(None).await;
        }
        // Replaced by a new sign-in on the same resource: that JID is online and belongs to the
        // new session now, so contacts must not see it leave and modules must not drop its state.
        let replaced = self.srv.sessions.replaced(&self.handle);
        self.srv.sessions.remove(&self.handle);
        if replaced {
            self.handle.presence.lock().available = false;
        } else {
            crate::modules::presence::session_ended(&self.srv, &self.host, &self.handle).await;
        }
        // Messages the client never confirmed go to the account's other devices or offline storage.
        let unacked = self.sm.take().map(|s| s.unacked).unwrap_or_default();
        let held = std::mem::take(&mut self.csi);
        for el in unacked.into_iter().chain(held) {
            if el.name() == "message" && el.has_child("body", ns::CLIENT) && matches!(el.attr("type"), None | Some("chat" | "normal")) {
                crate::router::redeliver(&self.srv, &self.host, &self.handle.jid, el).await;
            }
        }
        if let Some(n) = self.handle.jid.node() {
            let _ = self.srv.accounts.touch(&self.host.domain, n, quark_core::time::now_ms()).await;
        }
        if !replaced {
            self.srv.emit(&crate::modules::Event::SessionEnded { jid: self.handle.jid.clone() }).await;
        }
    }
}

fn sm_enabled(sm: &Sm, resume_secs: u64) -> Element {
    let mut e = Element::new("enabled", ns::SM);
    if let Some(id) = &sm.id {
        e.set_attr("id", id.clone());
        e.set_attr("resume", "true");
        e.set_attr("max", resume_secs.to_string());
    }
    e
}

/// Stanzas a backgrounded app should get right away: anything with content a person reads, or
/// that something waits on. Presence, chat states, receipts and markers can wait.
fn urgent(el: &Element) -> bool {
    match el.name() {
        "presence" => {
            // Subscription requests and errors are for a person; status updates aren't.
            matches!(el.attr("type"), Some("subscribe" | "error"))
                // MUC self-presence (status 110) answers a join the app is waiting on.
                || el.get_child("x", ns::MUC_USER).is_some_and(|x| x.children().any(|c| c.name() == "status" && c.attr("code") == Some("110")))
        }
        "message" => {
            el.has_child("body", ns::CLIENT)
                || el.has_child("encrypted", ns::OMEMO)
                || el.has_child("encrypted", "urn:xmpp:omemo:2")
                || el.has_child("propose", "urn:xmpp:jingle-message:0")
                || el.has_child("subject", ns::CLIENT)
                || el.get_child("x", ns::MUC_USER).is_some_and(|x| x.has_child("invite", ns::MUC_USER))
                || el.has_child("x", "jabber:x:conference")
                || el.attr("type") == Some("error")
                // Carbons and MAM results wrap a message; look inside.
                || ["received", "sent"].iter().any(|n| {
                    el.get_child(n, ns::CARBONS).and_then(|c| c.get_child("forwarded", ns::FORWARD)).and_then(|f| f.get_child("message", ns::CLIENT)).is_some_and(urgent)
                })
                || el.get_child("event", ns::PUBSUB_EVENT).is_some_and(|e| e.children().any(|i| i.attr("node").is_some_and(|n| n == ns::BOOKMARKS2 || n.starts_with("eu.siacs.conversations.axolotl.devicelist") || n == "urn:xmpp:omemo:2:devices")))
        }
        _ => true,
    }
}

async fn recv_opt(rx: &mut Option<mpsc::Receiver<ReaderEvent>>) -> Option<ReaderEvent> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

async fn sleep_opt(until: Option<Instant>) {
    match until {
        Some(t) => tokio::time::sleep_until(t).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg() -> Element {
        Element::new("message", ns::CLIENT)
    }

    #[test]
    fn ack_drops_confirmed_stanzas() {
        let mut sm = Sm::new(None);
        for _ in 0..5 {
            sm.out_h += 1;
            sm.unacked.push_back(msg());
        }
        assert!(sm.ack(3));
        assert_eq!(sm.unacked.len(), 2);
        assert!(sm.ack(3));
        assert_eq!(sm.unacked.len(), 2);
        assert!(!sm.ack(9));
        assert!(sm.ack(5));
        assert!(sm.unacked.is_empty());
    }

    #[test]
    fn ack_handles_wraparound() {
        let mut sm = Sm::new(None);
        sm.out_h = u32::MAX - 1;
        for _ in 0..3 {
            sm.out_h = sm.out_h.wrapping_add(1);
            sm.unacked.push_back(msg());
        }
        assert!(sm.ack(0));
        assert_eq!(sm.unacked.len(), 1);
    }

    /// A connection whose writes never finish (a client that stopped reading) and that never
    /// sends anything.
    struct Stuck;

    #[async_trait::async_trait]
    impl StanzaWriter for Stuck {
        async fn write(&mut self, _el: &Element) -> std::io::Result<()> {
            std::future::pending().await
        }
        async fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
        async fn keepalive(&mut self) -> std::io::Result<()> {
            std::future::pending().await
        }
        async fn close(&mut self, _err: Option<&StreamError>) {}
    }

    #[async_trait::async_trait]
    impl StanzaReader for Stuck {
        async fn read(&mut self) -> Result<Option<StreamEvent>, XmlError> {
            std::future::pending().await
        }
        fn bytes_read(&self) -> u64 {
            0
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_stops_reading_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("quark.toml");
        let text = format!(
            "[server]\ndata_dir = {:?}\n[tls]\ncert_dir = {:?}\n[[host]]\ndomain = \"a.test\"\n",
            dir.path().join("data"),
            dir.path().join("certs")
        );
        std::fs::write(&path, text).unwrap();
        let srv = crate::run::build(crate::run::load_config(&path).unwrap()).unwrap();
        let host = srv.host("a.test").unwrap();
        let jid = Jid::parse("sam@a.test/phone").unwrap();
        let info = SessionInfo { ip: None, secure: true, since: 0, transport: "tcp", client: None };
        let start = Start {
            srv: srv.clone(),
            host,
            jid: jid.clone(),
            info,
            writer: Box::new(Stuck),
            reader: Box::new(Stuck),
            prelude: Vec::new(),
            carbons: false,
            inactive: false,
            sm: None,
        };
        let handle = spawn(start);
        handle.send(Element::new("message", ns::CLIENT).text_child("body", ns::CLIENT, "hi"));
        tokio::time::sleep(WRITE_TIMEOUT - Duration::from_secs(1)).await;
        assert!(srv.sessions.get(&jid).is_some(), "still trying to write");
        tokio::time::sleep(Duration::from_secs(5)).await;
        for _ in 0..100 {
            if srv.sessions.get(&jid).is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(srv.sessions.get(&jid).is_none(), "the stuck session was removed");
    }

    #[test]
    fn chat_states_can_wait_but_bodies_cannot() {
        let state = Element::new("message", ns::CLIENT).child(Element::new("composing", ns::CHAT_STATES));
        assert!(!urgent(&state));
        let body = Element::new("message", ns::CLIENT).text_child("body", ns::CLIENT, "hi");
        assert!(urgent(&body));
        assert!(!urgent(&Element::new("presence", ns::CLIENT)));
        assert!(urgent(&Element::new("presence", ns::CLIENT).attr_set("type", "subscribe")));
        assert!(urgent(&Element::new("iq", ns::CLIENT)));
    }
}
