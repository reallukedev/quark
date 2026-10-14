//! One server-to-server XML stream over TCP: plain, after STARTTLS, or TLS from the first byte,
//! in either direction. Elements read in jabber:server come out in jabber:client like everything
//! else in the server, and go back out in jabber:server.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use quark_core::xml::{stream_header, StreamEvent, StreamReader, XmlError};
use quark_core::{ns, Element};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufWriter, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::TcpStream;

use crate::transport::StreamError;

/// TCP, maybe with TLS, as the connecting or the accepting side.
pub enum Io {
    Plain(TcpStream),
    Client(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    Server(Box<tokio_rustls::server::TlsStream<TcpStream>>),
}

macro_rules! each {
    ($self:expr, $m:ident($($a:expr),*)) => {
        match $self.get_mut() {
            Io::Plain(s) => Pin::new(s).$m($($a),*),
            Io::Client(s) => Pin::new(s.as_mut()).$m($($a),*),
            Io::Server(s) => Pin::new(s.as_mut()).$m($($a),*),
        }
    };
}

impl AsyncRead for Io {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        each!(self, poll_read(cx, buf))
    }
}

impl AsyncWrite for Io {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        each!(self, poll_write(cx, buf))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        each!(self, poll_flush(cx))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        each!(self, poll_shutdown(cx))
    }
}

impl Io {
    /// The peer's certificate chain, leaf first, when it sent one.
    fn peer_certs(&self) -> Option<Vec<CertificateDer<'static>>> {
        let certs = match self {
            Io::Plain(_) => None,
            Io::Client(t) => t.get_ref().1.peer_certificates(),
            Io::Server(t) => t.get_ref().1.peer_certificates(),
        };
        certs.filter(|c| !c.is_empty()).map(<[CertificateDer<'static>]>::to_vec)
    }
}

pub type Reader = StreamReader<ReadHalf<Io>>;
pub type Writer = BufWriter<Stalls<WriteHalf<Io>>>;

/// A writer whose writes fail once they've made no progress for `limit`. A peer that stops
/// reading fills its socket buffers and then every write waits forever; with this the link's
/// task gets an error instead, closes the link, and its timers and queues aren't held up.
pub struct Stalls<W> {
    inner: W,
    limit: Duration,
    /// Armed while a write is pending, cleared whenever one goes through.
    stalled: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<W> Stalls<W> {
    pub fn new(inner: W, limit: Duration) -> Stalls<W> {
        Stalls { inner, limit, stalled: None }
    }

    pub fn into_inner(self) -> W {
        self.inner
    }

    fn check<T>(&mut self, cx: &mut Context<'_>, r: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        if r.is_ready() {
            self.stalled = None;
            return r;
        }
        let limit = self.limit;
        let sleep = self.stalled.get_or_insert_with(|| Box::pin(tokio::time::sleep(limit)));
        match sleep.as_mut().poll(cx) {
            Poll::Ready(()) => {
                self.stalled = None;
                Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "the other server stopped reading")))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Stalls<W> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let r = Pin::new(&mut me.inner).poll_write(cx, buf);
        me.check(cx, r)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let r = Pin::new(&mut me.inner).poll_flush(cx);
        me.check(cx, r)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let r = Pin::new(&mut me.inner).poll_shutdown(cx);
        me.check(cx, r)
    }
}

/// A stream during negotiation; split into a reader and a writer once it's set up.
pub struct Stream {
    reader: Option<Reader>,
    writer: Option<Writer>,
    max_stanza: u64,
    /// How long a write may make no progress before it fails.
    write_limit: Duration,
    pub secure: bool,
    pub peer: Option<SocketAddr>,
    /// The peer's certificate chain after TLS, if it presented one.
    pub peer_certs: Option<Vec<CertificateDer<'static>>>,
}

/// Sockets get the same treatment as client ones: no Nagle, TCP keepalive.
fn tune(tcp: &TcpStream) {
    let _ = tcp.set_nodelay(true);
    let ka = socket2::TcpKeepalive::new().with_time(std::time::Duration::from_secs(120)).with_interval(std::time::Duration::from_secs(30));
    let _ = socket2::SockRef::from(tcp).set_tcp_keepalive(&ka);
}

impl Stream {
    pub fn new(io: Io, max_stanza: u64, write_limit: Duration) -> Stream {
        let (peer, secure) = match &io {
            Io::Plain(t) => (t.peer_addr().ok(), false),
            Io::Client(t) => (t.get_ref().0.peer_addr().ok(), true),
            Io::Server(t) => (t.get_ref().0.peer_addr().ok(), true),
        };
        match &io {
            Io::Plain(t) => tune(t),
            Io::Client(t) => tune(t.get_ref().0),
            Io::Server(t) => tune(t.get_ref().0),
        }
        let peer_certs = io.peer_certs();
        let (r, w) = tokio::io::split(io);
        let mut reader = StreamReader::new(r, max_stanza);
        reader.server_ns = true;
        let writer = BufWriter::with_capacity(8 * 1024, Stalls::new(w, write_limit));
        Stream { reader: Some(reader), writer: Some(writer), max_stanza, write_limit, secure, peer, peer_certs }
    }

    fn writer(&mut self) -> io::Result<&mut Writer> {
        self.writer.as_mut().ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stream closed"))
    }

    pub async fn read(&mut self) -> Result<Option<StreamEvent>, XmlError> {
        match self.reader.as_mut() {
            Some(r) => r.next().await,
            None => Ok(None),
        }
    }

    /// Reads the next element, failing on a closed stream or a stream header.
    pub async fn read_element(&mut self) -> Result<Element, StreamFailure> {
        match self.read().await {
            Ok(Some(StreamEvent::Stanza(el))) => match stream_error(&el) {
                Some(e) => Err(StreamFailure::Remote(e)),
                None => Ok(el),
            },
            Ok(Some(StreamEvent::Open { .. })) => Err(StreamFailure::Local(StreamError::new("invalid-xml"))),
            Ok(Some(StreamEvent::Close)) | Ok(None) => Err(StreamFailure::Closed),
            Err(e) => Err(StreamFailure::from(e)),
        }
    }

    /// Reads the peer's stream header: its attributes, checked to be in jabber:server.
    pub async fn read_header(&mut self) -> Result<Vec<(String, String)>, StreamFailure> {
        match self.read().await {
            Ok(Some(StreamEvent::Open { attrs, default_ns })) => {
                if default_ns != ns::SERVER {
                    return Err(StreamFailure::Local(StreamError::new("invalid-namespace")));
                }
                Ok(attrs)
            }
            Ok(Some(StreamEvent::Stanza(el))) => Err(match stream_error(&el) {
                Some(e) => StreamFailure::Remote(e),
                None => StreamFailure::Local(StreamError::new("invalid-xml")),
            }),
            Ok(Some(StreamEvent::Close)) | Ok(None) => Err(StreamFailure::Closed),
            Err(e) => Err(StreamFailure::from(e)),
        }
    }

    /// Writes and flushes one element.
    pub async fn send(&mut self, el: &Element) -> io::Result<()> {
        let w = self.writer()?;
        write_el(w, el).await?;
        w.flush().await
    }

    /// Sends our stream header (with the dialback prefix declared).
    pub async fn open(&mut self, from: Option<&str>, to: Option<&str>, id: Option<&str>) -> io::Result<()> {
        let h = stream_header(ns::SERVER, from, to, id, &[("xmlns:db", ns::DIALBACK)]);
        let w = self.writer()?;
        w.write_all(h.as_bytes()).await?;
        w.flush().await
    }

    /// The peer opens a new stream on the same connection (after SASL).
    pub fn restart(&mut self) {
        self.reader = self.reader.take().map(StreamReader::restart);
    }

    fn take_tcp(&mut self) -> io::Result<TcpStream> {
        let (Some(reader), Some(writer)) = (self.reader.take(), self.writer.take()) else {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "stream closed"));
        };
        if reader.has_buffered() {
            // Bytes sent before the handshake would be read as if they came encrypted.
            return Err(io::Error::new(io::ErrorKind::InvalidData, "data after <starttls/>"));
        }
        match reader.into_inner().unsplit(writer.into_inner().into_inner()) {
            Io::Plain(tcp) => Ok(tcp),
            _ => Err(io::Error::other("already encrypted")),
        }
    }

    fn reset(&mut self, io: Io) {
        *self = Stream::new(io, self.max_stanza, self.write_limit);
    }

    /// STARTTLS as the connecting side, with SNI `name`.
    pub async fn starttls_client(&mut self, cfg: Arc<rustls::ClientConfig>, name: ServerName<'static>) -> io::Result<()> {
        let tcp = self.take_tcp()?;
        let tls = tokio_rustls::TlsConnector::from(cfg).connect(name, tcp).await?;
        self.reset(Io::Client(Box::new(tls)));
        Ok(())
    }

    /// STARTTLS as the accepting side.
    pub async fn starttls_server(&mut self, cfg: Arc<rustls::ServerConfig>) -> io::Result<()> {
        let tcp = self.take_tcp()?;
        let tls = tokio_rustls::TlsAcceptor::from(cfg).accept(tcp).await?;
        self.reset(Io::Server(Box::new(tls)));
        Ok(())
    }

    /// Ends the stream, with a stream error first when given.
    pub async fn close(&mut self, err: Option<&StreamError>) {
        if let Ok(w) = self.writer() {
            close(w, err).await;
        }
    }

    pub fn split(mut self) -> io::Result<(Reader, Writer)> {
        match (self.reader.take(), self.writer.take()) {
            (Some(r), Some(w)) => Ok((r, w)),
            _ => Err(io::Error::new(io::ErrorKind::NotConnected, "stream closed")),
        }
    }
}

/// Writes one element in the jabber:server stream namespace (buffered).
pub async fn write_el(w: &mut Writer, el: &Element) -> io::Result<()> {
    let xml = if el.ns() == ns::DIALBACK { super::dialback::to_stream_xml(el) } else { el.to_stream_xml(ns::SERVER) };
    w.write_all(xml.as_bytes()).await
}

/// Writes a stream error if any and `</stream:stream>`, then shuts the connection down.
pub async fn close(w: &mut Writer, err: Option<&StreamError>) {
    let mut s = String::new();
    if let Some(e) = err {
        e.to_element().write_into_stream(&mut s, ns::SERVER);
    }
    s.push_str("</stream:stream>");
    let done = async {
        w.write_all(s.as_bytes()).await?;
        w.flush().await?;
        w.shutdown().await
    };
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), done).await;
}

/// The condition of a `<stream:error/>`, if `el` is one.
pub fn stream_error(el: &Element) -> Option<String> {
    if !el.is("error", ns::STREAM) {
        return None;
    }
    let cond = el.children().find(|c| c.ns() == ns::STREAMS && c.name() != "text").map(|c| c.name().to_string());
    let text = el.child_text("text", ns::STREAMS);
    Some(match (cond, text) {
        (Some(c), Some(t)) => format!("{c} ({t})"),
        (Some(c), None) => c,
        (None, _) => "undefined-condition".into(),
    })
}

/// Why a stream ended during negotiation.
#[derive(Debug)]
pub enum StreamFailure {
    /// The peer sent a stream error.
    Remote(String),
    /// We end it with this stream error.
    Local(StreamError),
    Closed,
    Io(io::Error),
}

impl From<XmlError> for StreamFailure {
    fn from(e: XmlError) -> Self {
        match e {
            XmlError::Io(e) => StreamFailure::Io(e),
            XmlError::TooBig | XmlError::TooDeep => StreamFailure::Local(StreamError::with_text("policy-violation", "Stanza too big.")),
            XmlError::Restricted => StreamFailure::Local(StreamError::new("restricted-xml")),
            XmlError::Malformed(_) => StreamFailure::Local(StreamError::new("not-well-formed")),
            XmlError::InvalidNamespace => StreamFailure::Local(StreamError::new("invalid-namespace")),
        }
    }
}

impl From<io::Error> for StreamFailure {
    fn from(e: io::Error) -> Self {
        StreamFailure::Io(e)
    }
}

impl std::fmt::Display for StreamFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamFailure::Remote(c) => write!(f, "the other server ended the stream: {c}"),
            StreamFailure::Local(e) => write!(f, "stream error {}", e.condition),
            StreamFailure::Closed => f.write_str("the connection closed"),
            StreamFailure::Io(e) => write!(f, "{e}"),
        }
    }
}

/// What the reader task reports on an established link.
#[derive(Debug)]
pub enum In {
    Stanza(Element),
    /// The stream is over: with the stream error to send, if it's the peer's fault, and why.
    Gone(Option<StreamError>, String),
}

/// Reads elements and passes them on; the reader isn't cancel safe, so it gets its own task.
/// The channel is small, so a peer can't send faster than its stanzas are handled.
pub async fn read_loop(mut r: Reader, tx: tokio::sync::mpsc::Sender<In>) {
    loop {
        let ev = match r.next().await {
            Ok(Some(StreamEvent::Stanza(el))) => match stream_error(&el) {
                Some(c) => In::Gone(None, format!("stream error from the peer: {c}")),
                None => In::Stanza(el),
            },
            Ok(Some(StreamEvent::Close)) => In::Gone(None, "closed by the peer".into()),
            Ok(Some(StreamEvent::Open { .. })) => In::Gone(Some(StreamError::new("invalid-xml")), "a second stream header".into()),
            Ok(None) => In::Gone(None, "connection closed".into()),
            Err(e) => match StreamFailure::from(e) {
                StreamFailure::Local(se) => {
                    let why = format!("sent bad XML ({})", se.condition);
                    In::Gone(Some(se), why)
                }
                other => In::Gone(None, other.to_string()),
            },
        };
        let done = matches!(ev, In::Gone(..));
        if tx.send(ev).await.is_err() || done {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn writes_to_a_peer_that_stopped_reading_fail() {
        // Nobody reads the other end, so the 1 KiB pipe fills and the write can't finish.
        let (near, _far) = tokio::io::duplex(1024);
        let mut w = Stalls::new(near, Duration::from_millis(100));
        let started = std::time::Instant::now();
        let err = w.write_all(&[b'x'; 64 * 1024]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn writes_that_keep_moving_never_time_out() {
        let (near, mut far) = tokio::io::duplex(1024);
        let reader = tokio::spawn(async move {
            let mut buf = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut far, &mut buf).await.map(|_| buf.len())
        });
        // Each chunk only waits for the reader, never for the whole limit.
        let mut w = Stalls::new(near, Duration::from_millis(200));
        for _ in 0..8 {
            w.write_all(&[b'x'; 16 * 1024]).await.unwrap();
        }
        w.shutdown().await.unwrap();
        drop(w);
        assert_eq!(reader.await.unwrap().unwrap(), 8 * 16 * 1024);
    }
}
