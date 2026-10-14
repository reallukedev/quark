//! XMPP over WebSocket (RFC 7395): one top-level element per text frame, `<open/>` and
//! `<close/>` instead of stream tags. The negotiation and the session are the same as on TCP;
//! only the [`Transport`] differs.

use std::io;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use quark_core::xml::{StreamEvent, XmlError};
use quark_core::{ns, Element};

use super::{AppState, Conn};
use crate::sasl::ChannelBindings;
use crate::server::Server;
use crate::transport::{StanzaReader, StanzaWriter, StreamError, Transport};

/// Room for the frame around a maximum-size stanza.
const FRAME_SLACK: u64 = 4096;
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
const PING_EVERY: Duration = Duration::from_secs(30);

pub(super) async fn handler(
    State(st): AppState,
    Extension(conn): Extension<Conn>,
    headers: HeaderMap,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    if !st.srv.hosts().iter().any(|h| h.settings().web) {
        return (StatusCode::NOT_FOUND, "Web clients are turned off on this server.\n").into_response();
    }
    let ws = match ws {
        Ok(ws) => ws,
        Err(e) => return (e.status(), "This is the XMPP WebSocket endpoint (RFC 7395). Chat apps connect here.\n").into_response(),
    };
    let peer = super::peer(&conn, &headers);
    let max_stanza = st.srv.config().limits.c2s_stanza_bytes;
    let frame = usize::try_from(max_stanza + FRAME_SLACK).unwrap_or(usize::MAX);
    // Channel binding only holds when our own TLS reaches the client.
    let (cb, sni) = match (&conn.tls, peer.proxied) {
        (Some(t), false) => (t.cb.clone(), t.sni.clone()),
        _ => (ChannelBindings::default(), None),
    };
    st.stats.websockets.fetch_add(1, Ordering::Relaxed);
    ws.protocols(["xmpp"]).max_message_size(frame).max_frame_size(frame).on_upgrade(move |socket| async move {
        let (tx, rx) = socket.split();
        let t = WsTransport {
            srv: st.srv.clone(),
            reader: WsReader { rx, max_stanza, bytes: 0 },
            writer: WsWriter::new(tx),
            ip: peer.ip,
            secure: peer.secure,
            cb,
            sni,
        };
        crate::c2s::serve(st.srv.clone(), Box::new(t)).await;
    })
}

/// Parses one frame: `<open/>`, `<close/>` or a stanza-level element.
pub(crate) fn parse_frame(text: &str) -> Result<StreamEvent, XmlError> {
    let mut el = Element::parse(text)?;
    if el.ns().is_empty() {
        // RFC 7395 wants an explicit jabber:client, but some libraries leave it out.
        el.rewrite_ns("", ns::CLIENT);
    }
    if el.ns() != ns::FRAMING {
        return Ok(StreamEvent::Stanza(el));
    }
    match el.name() {
        "open" => Ok(StreamEvent::Open {
            attrs: el.attrs().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            default_ns: ns::FRAMING.into(),
        }),
        "close" => Ok(StreamEvent::Close),
        _ => Err(XmlError::Malformed("unknown framing element".into())),
    }
}

/// `<open/>` from the server.
fn open_frame(from: &str, id: &str, to: Option<&str>) -> Element {
    Element::new("open", ns::FRAMING)
        .attr_set("from", from)
        .attr_set("id", id)
        .attr_opt("to", to)
        .attr_set("version", "1.0")
        .attr_set("xml:lang", "en")
}

struct WsReader {
    rx: SplitStream<WebSocket>,
    max_stanza: u64,
    bytes: u64,
}

impl WsReader {
    async fn next(&mut self) -> Result<Option<StreamEvent>, XmlError> {
        loop {
            let msg = match self.rx.next().await {
                None => return Ok(None),
                Some(Err(e)) => return Err(XmlError::Io(io::Error::other(e))),
                Some(Ok(m)) => m,
            };
            match msg {
                Message::Text(t) => {
                    self.bytes += t.len() as u64;
                    if t.len() as u64 > self.max_stanza {
                        return Err(XmlError::TooBig);
                    }
                    return parse_frame(t.as_str()).map(Some);
                }
                Message::Binary(_) => return Err(XmlError::Malformed("binary frames aren't XMPP".into())),
                // Pongs are answered by the WebSocket layer itself.
                Message::Ping(_) | Message::Pong(_) => {}
                // Closing the socket without `<close/>` is a dropped connection, so a resumable
                // session waits for the client to come back.
                Message::Close(_) => return Ok(None),
            }
        }
    }
}

type Sink = SplitSink<WebSocket, Message>;

/// The sending half, shared with the task that pings the client.
struct WsWriter {
    tx: Arc<tokio::sync::Mutex<Sink>>,
    closed: bool,
}

impl WsWriter {
    /// Starts pinging: proxies drop WebSockets that look idle (nginx after 60 seconds), and a
    /// failed ping finds a dead connection long before the session's own check would.
    fn new(sink: Sink) -> Self {
        let tx = Arc::new(tokio::sync::Mutex::new(sink));
        let weak = Arc::downgrade(&tx);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(PING_EVERY);
            tick.tick().await;
            loop {
                tick.tick().await;
                let Some(tx) = weak.upgrade() else { return };
                let mut sink = tx.lock().await;
                let sent = tokio::time::timeout(CLOSE_TIMEOUT, sink.send(Message::Ping(Default::default()))).await;
                if !matches!(sent, Ok(Ok(()))) {
                    return;
                }
            }
        });
        WsWriter { tx, closed: false }
    }

    fn check(&self) -> io::Result<()> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "stream closed"));
        }
        Ok(())
    }

    async fn feed(&mut self, el: &Element) -> io::Result<()> {
        self.check()?;
        let xml = el.to_xml();
        self.tx.lock().await.feed(Message::Text(xml.into())).await.map_err(io::Error::other)
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        self.tx.lock().await.flush().await.map_err(io::Error::other)
    }

    async fn ping(&mut self) -> io::Result<()> {
        self.check()?;
        self.tx.lock().await.send(Message::Ping(Default::default())).await.map_err(io::Error::other)
    }

    async fn close(&mut self, err: Option<&StreamError>) {
        if self.closed {
            return;
        }
        self.closed = true;
        let mut tx = self.tx.lock().await;
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, async move {
            if let Some(e) = err {
                tx.feed(Message::Text(e.to_element().to_xml().into())).await?;
            }
            tx.feed(Message::Text(Element::new("close", ns::FRAMING).to_xml().into())).await?;
            tx.feed(Message::Close(None)).await?;
            tx.close().await
        })
        .await;
    }
}

pub struct WsTransport {
    srv: Arc<Server>,
    reader: WsReader,
    writer: WsWriter,
    ip: IpAddr,
    secure: bool,
    cb: ChannelBindings,
    sni: Option<String>,
}

#[async_trait]
impl Transport for WsTransport {
    async fn read(&mut self) -> Result<Option<StreamEvent>, XmlError> {
        let ev = self.reader.next().await?;
        if let Some(StreamEvent::Open { attrs, .. }) = &ev {
            let to = StreamEvent::open_attr(attrs, "to").map(str::to_ascii_lowercase);
            if let Some(host) = to.as_deref().and_then(|d| self.srv.host(d)) {
                if !host.settings().web {
                    let _ = self.open(&host.domain, &quark_core::new_id(), None).await;
                    let e = StreamError::with_text("policy-violation", format!("Web clients are turned off on {}.", host.domain));
                    self.writer.close(Some(&e)).await;
                    return Ok(None);
                }
            }
        }
        Ok(ev)
    }

    async fn send(&mut self, el: &Element) -> io::Result<()> {
        self.writer.feed(el).await?;
        self.writer.flush().await
    }

    async fn open(&mut self, from: &str, id: &str, to: Option<&str>) -> io::Result<()> {
        self.send(&open_frame(from, id, to)).await
    }

    async fn close(&mut self, err: Option<&StreamError>) {
        self.writer.close(err).await;
    }

    fn restart(&mut self) {}

    fn secure(&self) -> bool {
        self.secure
    }

    fn can_starttls(&self) -> bool {
        false
    }

    async fn starttls(&mut self) -> io::Result<()> {
        Err(io::Error::other("STARTTLS isn't available over WebSocket"))
    }

    fn bindings(&self) -> &ChannelBindings {
        &self.cb
    }

    fn sni(&self) -> Option<&str> {
        self.sni.as_deref()
    }

    fn peer(&self) -> Option<IpAddr> {
        Some(self.ip)
    }

    fn kind(&self) -> &'static str {
        "websocket"
    }

    fn split(self: Box<Self>) -> (Box<dyn StanzaReader>, Box<dyn StanzaWriter>) {
        let me = *self;
        (Box::new(me.reader), Box::new(me.writer))
    }
}

#[async_trait]
impl StanzaReader for WsReader {
    async fn read(&mut self) -> Result<Option<StreamEvent>, XmlError> {
        self.next().await
    }
    fn bytes_read(&self) -> u64 {
        self.bytes
    }
}

#[async_trait]
impl StanzaWriter for WsWriter {
    async fn write(&mut self, el: &Element) -> io::Result<()> {
        self.feed(el).await
    }
    async fn flush(&mut self) -> io::Result<()> {
        WsWriter::flush(self).await
    }
    async fn keepalive(&mut self) -> io::Result<()> {
        self.ping().await
    }
    async fn close(&mut self, err: Option<&StreamError>) {
        WsWriter::close(self, err).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_parse() {
        let open = parse_frame("<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' to='a.test' version='1.0'/>").unwrap();
        match open {
            StreamEvent::Open { attrs, default_ns } => {
                assert_eq!(default_ns, ns::FRAMING);
                assert_eq!(StreamEvent::open_attr(&attrs, "to"), Some("a.test"));
            }
            e => panic!("{e:?}"),
        }
        assert!(matches!(parse_frame("<close xmlns='urn:ietf:params:xml:ns:xmpp-framing'/>").unwrap(), StreamEvent::Close));
        assert!(parse_frame("<bogus xmlns='urn:ietf:params:xml:ns:xmpp-framing'/>").is_err());
        assert!(parse_frame("<message xmlns='jabber:client'/><message xmlns='jabber:client'/>").is_err());
        assert!(parse_frame("not xml").is_err());
    }

    #[test]
    fn unqualified_stanzas_become_jabber_client() {
        match parse_frame("<message to='b@a.test'><body>hi</body></message>").unwrap() {
            StreamEvent::Stanza(el) => {
                assert!(el.is("message", ns::CLIENT));
                assert_eq!(el.child_text("body", ns::CLIENT).as_deref(), Some("hi"));
            }
            e => panic!("{e:?}"),
        }
    }

    #[test]
    fn open_frame_is_framing() {
        let x = open_frame("a.test", "id1", None).to_xml();
        assert!(x.starts_with("<open xmlns='urn:ietf:params:xml:ns:xmpp-framing'"));
        assert!(x.contains("version='1.0'"));
    }
}
