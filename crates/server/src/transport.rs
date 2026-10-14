//! How stanzas travel: XML streams over TCP (with STARTTLS or direct TLS) here, WebSocket in
//! `http::websocket`. Stream negotiation and sessions only see these traits.

use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use quark_core::xml::{stream_header, StreamEvent, StreamReader, XmlError};
use quark_core::{ns, Element};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufWriter, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::TcpStream;

use crate::sasl::ChannelBindings;
use crate::tls::CertStore;

/// A `<stream:error/>` (RFC 6120 §4.9.3).
#[derive(Debug, Clone)]
pub struct StreamError {
    pub condition: &'static str,
    pub text: Option<String>,
    /// An application-specific condition element.
    pub app: Option<Box<Element>>,
}

impl StreamError {
    pub fn new(condition: &'static str) -> Self {
        StreamError { condition, text: None, app: None }
    }
    pub fn with_text(condition: &'static str, text: impl Into<String>) -> Self {
        StreamError { condition, text: Some(text.into()), app: None }
    }
    pub fn to_element(&self) -> Element {
        let mut e = Element::new("error", ns::STREAM).child(Element::new(self.condition, ns::STREAMS));
        if let Some(t) = &self.text {
            e.append(Element::new("text", ns::STREAMS).attr_set("xml:lang", "en").text(t.clone()));
        }
        if let Some(a) = &self.app {
            e.append((**a).clone());
        }
        e
    }
}

/// The receiving half of an established stream.
#[async_trait]
pub trait StanzaReader: Send {
    async fn read(&mut self) -> Result<Option<StreamEvent>, XmlError>;
    fn bytes_read(&self) -> u64;
}

/// The sending half. `write` may buffer; `flush` sends.
#[async_trait]
pub trait StanzaWriter: Send {
    async fn write(&mut self, el: &Element) -> io::Result<()>;
    async fn flush(&mut self) -> io::Result<()>;
    /// Sends a keepalive the client ignores (whitespace on TCP).
    async fn keepalive(&mut self) -> io::Result<()>;
    /// Ends the stream, with an error first when given.
    async fn close(&mut self, err: Option<&StreamError>);
}

/// A stream during negotiation, before it splits into a reader and a writer.
#[async_trait]
pub trait Transport: Send {
    async fn read(&mut self) -> Result<Option<StreamEvent>, XmlError>;
    /// Sends and flushes.
    async fn send(&mut self, el: &Element) -> io::Result<()>;
    /// Sends our stream header (or WebSocket `<open/>`).
    async fn open(&mut self, from: &str, id: &str, to: Option<&str>) -> io::Result<()>;
    async fn close(&mut self, err: Option<&StreamError>);
    /// The client will open a new stream on the same connection (after SASL).
    fn restart(&mut self);
    fn secure(&self) -> bool;
    fn can_starttls(&self) -> bool;
    async fn starttls(&mut self) -> io::Result<()>;
    fn bindings(&self) -> &ChannelBindings;
    fn sni(&self) -> Option<&str>;
    fn peer(&self) -> Option<IpAddr>;
    fn kind(&self) -> &'static str;
    fn split(self: Box<Self>) -> (Box<dyn StanzaReader>, Box<dyn StanzaWriter>);
}

/// TCP, optionally upgraded to TLS.
pub enum Io {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::server::TlsStream<TcpStream>>),
}

impl AsyncRead for Io {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Io::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Io::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Io {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Io::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Io::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Io::Plain(s) => Pin::new(s).poll_flush(cx),
            Io::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Io::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Io::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Io::Plain(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Io::Tls(s) => Pin::new(s.as_mut()).poll_write_vectored(cx, bufs),
        }
    }
    fn is_write_vectored(&self) -> bool {
        match self {
            Io::Plain(s) => s.is_write_vectored(),
            Io::Tls(s) => s.is_write_vectored(),
        }
    }
}

/// An XML stream over TCP: client-to-server or server-to-server.
pub struct TcpTransport {
    reader: Option<StreamReader<ReadHalf<Io>>>,
    writer: Option<BufWriter<WriteHalf<Io>>>,
    peer: Option<IpAddr>,
    secure: bool,
    cb: ChannelBindings,
    sni: Option<String>,
    /// jabber:client or jabber:server.
    stream_ns: &'static str,
    max_stanza: u64,
    certs: Arc<CertStore>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
}

impl TcpTransport {
    /// A plain connection that can upgrade with STARTTLS using `tls_config`.
    pub fn plain(
        tcp: TcpStream,
        stream_ns: &'static str,
        max_stanza: u64,
        certs: Arc<CertStore>,
        tls_config: Arc<rustls::ServerConfig>,
    ) -> Self {
        let peer = tcp.peer_addr().ok().map(|a| a.ip().to_canonical());
        tune_socket(&tcp);
        let (r, w) = tokio::io::split(Io::Plain(tcp));
        let mut reader = StreamReader::new(r, max_stanza);
        reader.server_ns = stream_ns == ns::SERVER;
        TcpTransport {
            reader: Some(reader),
            writer: Some(BufWriter::with_capacity(8 * 1024, w)),
            peer,
            secure: false,
            cb: ChannelBindings::default(),
            sni: None,
            stream_ns,
            max_stanza,
            certs,
            tls_config: Some(tls_config),
        }
    }

    /// A connection that already did its TLS handshake (direct TLS, XEP-0368).
    pub fn tls(tls: tokio_rustls::server::TlsStream<TcpStream>, stream_ns: &'static str, max_stanza: u64, certs: Arc<CertStore>) -> Self {
        let peer = tls.get_ref().0.peer_addr().ok().map(|a| a.ip().to_canonical());
        tune_socket(tls.get_ref().0);
        let (sni, _, cb) = crate::tls::session_facts(&tls, &certs);
        let (r, w) = tokio::io::split(Io::Tls(Box::new(tls)));
        let mut reader = StreamReader::new(r, max_stanza);
        reader.server_ns = stream_ns == ns::SERVER;
        TcpTransport {
            reader: Some(reader),
            writer: Some(BufWriter::with_capacity(8 * 1024, w)),
            peer,
            secure: true,
            cb,
            sni,
            stream_ns,
            max_stanza,
            certs,
            tls_config: None,
        }
    }

    fn writer(&mut self) -> io::Result<&mut BufWriter<WriteHalf<Io>>> {
        self.writer.as_mut().ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stream closed"))
    }
}

/// TCP keepalive finds dead peers (phones that vanished) even when nothing is being sent, and
/// Nagle is off: stanzas are small and latency matters more than packet count.
fn tune_socket(tcp: &TcpStream) {
    let _ = tcp.set_nodelay(true);
    let sock = socket2::SockRef::from(tcp);
    let ka = socket2::TcpKeepalive::new().with_time(std::time::Duration::from_secs(120)).with_interval(std::time::Duration::from_secs(30));
    let _ = sock.set_tcp_keepalive(&ka);
}

#[async_trait]
impl Transport for TcpTransport {
    async fn read(&mut self) -> Result<Option<StreamEvent>, XmlError> {
        match self.reader.as_mut() {
            Some(r) => r.next().await,
            None => Ok(None),
        }
    }

    async fn send(&mut self, el: &Element) -> io::Result<()> {
        let xml = el.to_stream_xml(self.stream_ns);
        let w = self.writer()?;
        w.write_all(xml.as_bytes()).await?;
        w.flush().await
    }

    async fn open(&mut self, from: &str, id: &str, to: Option<&str>) -> io::Result<()> {
        let extra: &[(&str, &str)] = if self.stream_ns == ns::SERVER { &[("xmlns:db", ns::DIALBACK)] } else { &[] };
        let h = stream_header(self.stream_ns, Some(from), to, Some(id), extra);
        let w = self.writer()?;
        w.write_all(h.as_bytes()).await?;
        w.flush().await
    }

    async fn close(&mut self, err: Option<&StreamError>) {
        let ns = self.stream_ns;
        if let Ok(w) = self.writer() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), close_stream(w, err, ns)).await;
        }
    }

    fn restart(&mut self) {
        self.reader = self.reader.take().map(StreamReader::restart);
    }

    fn secure(&self) -> bool {
        self.secure
    }

    fn can_starttls(&self) -> bool {
        !self.secure && self.tls_config.is_some()
    }

    async fn starttls(&mut self) -> io::Result<()> {
        let cfg = self.tls_config.take().ok_or_else(|| io::Error::other("TLS isn't available"))?;
        let (Some(reader), Some(writer)) = (self.reader.take(), self.writer.take()) else {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "stream closed"));
        };
        if reader.has_buffered() {
            // Anything sent before the handshake would be injected into the encrypted stream.
            return Err(io::Error::new(io::ErrorKind::InvalidData, "data after <starttls/>"));
        }
        let tcp = match reader.into_inner().unsplit(writer.into_inner()) {
            Io::Plain(tcp) => tcp,
            Io::Tls(_) => return Err(io::Error::other("already encrypted")),
        };
        let tls = tokio_rustls::TlsAcceptor::from(cfg).accept(tcp).await?;
        let (sni, _, cb) = crate::tls::session_facts(&tls, &self.certs);
        self.sni = sni;
        self.cb = cb;
        self.secure = true;
        let (r, w) = tokio::io::split(Io::Tls(Box::new(tls)));
        let mut reader = StreamReader::new(r, self.max_stanza);
        reader.server_ns = self.stream_ns == ns::SERVER;
        self.reader = Some(reader);
        self.writer = Some(BufWriter::with_capacity(8 * 1024, w));
        Ok(())
    }

    fn bindings(&self) -> &ChannelBindings {
        &self.cb
    }

    fn sni(&self) -> Option<&str> {
        self.sni.as_deref()
    }

    fn peer(&self) -> Option<IpAddr> {
        self.peer
    }

    fn kind(&self) -> &'static str {
        "tcp"
    }

    fn split(self: Box<Self>) -> (Box<dyn StanzaReader>, Box<dyn StanzaWriter>) {
        let me = *self;
        let reader = me.reader.map(|r| Box::new(TcpReader(r)) as Box<dyn StanzaReader>).unwrap_or_else(|| Box::new(Closed));
        let writer = me
            .writer
            .map(|w| Box::new(TcpWriter { w, stream_ns: me.stream_ns }) as Box<dyn StanzaWriter>)
            .unwrap_or_else(|| Box::new(Closed));
        (reader, writer)
    }
}

async fn close_stream<W: AsyncWrite + Unpin>(w: &mut W, err: Option<&StreamError>, stream_ns: &str) -> io::Result<()> {
    let mut s = String::new();
    if let Some(e) = err {
        e.to_element().write_into_stream(&mut s, stream_ns);
    }
    s.push_str("</stream:stream>");
    w.write_all(s.as_bytes()).await?;
    w.flush().await?;
    w.shutdown().await
}

struct TcpReader(StreamReader<ReadHalf<Io>>);

#[async_trait]
impl StanzaReader for TcpReader {
    async fn read(&mut self) -> Result<Option<StreamEvent>, XmlError> {
        self.0.next().await
    }
    fn bytes_read(&self) -> u64 {
        self.0.bytes_read()
    }
}

pub struct TcpWriter {
    w: BufWriter<WriteHalf<Io>>,
    stream_ns: &'static str,
}

#[async_trait]
impl StanzaWriter for TcpWriter {
    async fn write(&mut self, el: &Element) -> io::Result<()> {
        let xml = el.to_stream_xml(self.stream_ns);
        self.w.write_all(xml.as_bytes()).await
    }
    async fn flush(&mut self) -> io::Result<()> {
        self.w.flush().await
    }
    async fn keepalive(&mut self) -> io::Result<()> {
        self.w.write_all(b" ").await?;
        self.w.flush().await
    }
    async fn close(&mut self, err: Option<&StreamError>) {
        let ns = self.stream_ns;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), close_stream(&mut self.w, err, ns)).await;
    }
}

/// A stream that's already gone.
struct Closed;

#[async_trait]
impl StanzaReader for Closed {
    async fn read(&mut self) -> Result<Option<StreamEvent>, XmlError> {
        Ok(None)
    }
    fn bytes_read(&self) -> u64 {
        0
    }
}

#[async_trait]
impl StanzaWriter for Closed {
    async fn write(&mut self, _el: &Element) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::NotConnected, "stream closed"))
    }
    async fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
    async fn keepalive(&mut self) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::NotConnected, "stream closed"))
    }
    async fn close(&mut self, _err: Option<&StreamError>) {}
}
