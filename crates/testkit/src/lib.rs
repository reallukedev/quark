//! Test kit: a real Quark server on random local ports, and a raw XMPP client to drive it.
//!
//! ```no_run
//! # async fn t() -> anyhow::Result<()> {
//! use quark_testkit::{TestServer, Client};
//! let server = TestServer::start().await?;
//! server.add_user("alice", "password1").await?;
//! let mut alice = server.login("alice", "password1").await?;
//! let pong = alice.iq_get(Some(server.domain()), quark_core::Element::new("ping", quark_core::ns::PING)).await?;
//! assert_eq!(pong.attr("type"), Some("result"));
//! # Ok(()) }
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use quark::accounts::Role;
use quark::server::Server;
use quark_core::xml::{stream_header, StreamEvent, StreamReader};
use quark_core::{ns, Element};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;

pub use quark_core;

/// The domain every test server serves.
pub const DOMAIN: &str = "quark.test";

/// How long `recv` waits before failing a test.
pub const TIMEOUT: Duration = Duration::from_secs(5);

/// A running server, stopped when dropped.
pub struct TestServer {
    pub srv: Arc<Server>,
    pub listening: quark::run::Listening,
    domain: String,
    _dir: tempfile::TempDir,
}

/// Knobs for [`TestServer::start_with`].
#[derive(Clone, Default)]
pub struct Options {
    /// Extra TOML appended to the generated config.
    pub extra_config: String,
    /// Allow signing in without TLS (to test plain connections).
    pub allow_plain: bool,
    /// Settings for the domain, applied before the listeners start.
    pub settings: Option<quark::settings::Settings>,
    /// The domain to serve instead of [`DOMAIN`] (to run two servers that federate).
    pub domain: Option<String>,
    /// Also listen for servers with direct TLS (XEP-0368).
    pub s2s_tls: bool,
    /// Certificates for the cert folder: (domain, certificate PEM, key PEM).
    pub certs: Vec<(String, String, String)>,
}

impl TestServer {
    pub async fn start() -> anyhow::Result<TestServer> {
        Self::start_with(Options::default()).await
    }

    pub async fn start_with(o: Options) -> anyhow::Result<TestServer> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir()?;
        let data = dir.path().join("data");
        let certs = dir.path().join("certs");
        std::fs::create_dir_all(&certs)?;
        for (name, crt, key) in &o.certs {
            std::fs::write(certs.join(format!("{name}.crt")), crt)?;
            std::fs::write(certs.join(format!("{name}.key")), key)?;
        }
        let domain = o.domain.clone().unwrap_or_else(|| DOMAIN.to_string());
        let s2s_tls = if o.s2s_tls { "[\"127.0.0.1:0\"]" } else { "[]" };
        let local = "127.0.0.1:0";
        let text = format!(
            "[server]\ndata_dir = {data:?}\nlog = \"warn\"\n\n[tls]\ncert_dir = {certs:?}\nrequire_c2s = {}\n\n\
             [listen]\nc2s = [\"{local}\"]\nc2s_tls = [\"{local}\"]\ns2s = [\"{local}\"]\ns2s_tls = {s2s_tls}\nhttp = [\"{local}\"]\n\n\
             [turn]\nlisten = \"{local}\"\n\n\
             [[host]]\ndomain = \"{domain}\"\nadmins = [\"admin@{domain}\"]\n\n{}",
            !o.allow_plain, o.extra_config
        );
        let path = dir.path().join("quark.toml");
        std::fs::write(&path, &text)?;
        let cfg = quark::run::load_config(&path)?;
        let srv = quark::run::build(cfg)?;
        if let Some(s) = o.settings {
            srv.set_settings(&domain, s).await.map_err(|e| anyhow!(e))?;
        }
        let listening = quark::run::start(&srv).await?;
        Ok(TestServer { srv, listening, domain, _dir: dir })
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The server-to-server STARTTLS port.
    pub fn s2s(&self) -> SocketAddr {
        self.listening.s2s[0]
    }

    /// The server-to-server direct TLS port, with `Options::s2s_tls`.
    pub fn s2s_tls(&self) -> Option<SocketAddr> {
        self.listening.s2s.get(1).copied()
    }

    /// Changes the config live (like `quark reload`).
    pub fn change_config(&self, f: impl FnOnce(&mut quark::config::Config)) -> anyhow::Result<()> {
        let mut c = (*self.srv.config()).clone();
        f(&mut c);
        self.srv.set_config(c)?;
        Ok(())
    }

    /// Sends federation traffic for `domain` to `target` (`host:port`, or `tls://host:port`).
    pub fn route(&self, domain: &str, target: &str) -> anyhow::Result<()> {
        self.change_config(|c| {
            c.s2s.routes.insert(domain.to_string(), target.to_string());
        })
    }

    /// The STARTTLS client port.
    pub fn c2s(&self) -> SocketAddr {
        self.listening.c2s[0]
    }

    /// The direct TLS client port (XEP-0368).
    pub fn c2s_tls(&self) -> SocketAddr {
        self.listening.c2s_tls[0]
    }

    /// The HTTP port, when the web listener is running.
    pub fn http(&self) -> Option<SocketAddr> {
        self.listening.http.first().copied()
    }

    pub async fn add_user(&self, user: &str, password: &str) -> anyhow::Result<()> {
        self.srv.accounts.create(&self.domain, user, password, Role::Member).await?;
        Ok(())
    }

    pub async fn add_admin(&self, user: &str, password: &str) -> anyhow::Result<()> {
        self.srv.accounts.create(&self.domain, user, password, Role::Admin).await?;
        if let Some(h) = self.srv.host(&self.domain) {
            h.set_role_cache(user, Role::Admin);
        }
        Ok(())
    }

    /// Enables or disables an account.
    pub async fn set_enabled(&self, user: &str, enabled: bool) -> anyhow::Result<()> {
        self.srv.accounts.set_enabled(DOMAIN, user, enabled).await.map_err(|e| anyhow!("{e:?}"))
    }

    /// Changes the domain's settings live.
    pub async fn set_settings(&self, f: impl FnOnce(&mut quark::settings::Settings)) -> anyhow::Result<()> {
        let mut s = (*self.srv.host(&self.domain).context("no host")?.settings()).clone();
        f(&mut s);
        self.srv.set_settings(&self.domain, s).await.map_err(|e| anyhow!(e))
    }

    /// Connects, does STARTTLS, signs in with SCRAM-SHA-256 and binds `resource` "test".
    pub async fn login(&self, user: &str, password: &str) -> anyhow::Result<Client> {
        self.login_as(user, password, "test").await
    }

    pub async fn login_as(&self, user: &str, password: &str, resource: &str) -> anyhow::Result<Client> {
        let mut c = Client::connect(self.c2s(), &self.domain).await?;
        c.starttls().await?;
        c.auth_scram("SCRAM-SHA-256", user, password).await?;
        c.bind(Some(resource)).await?;
        Ok(c)
    }

    /// `login` plus initial presence and a roster fetch, like a real client after connecting.
    pub async fn online(&self, user: &str, password: &str, resource: &str) -> anyhow::Result<Client> {
        let mut c = self.login_as(user, password, resource).await?;
        c.iq_get(None, Element::new("query", ns::ROSTER)).await?;
        c.send(&Element::new("presence", ns::CLIENT)).await?;
        Ok(c)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.srv.shut_down();
    }
}

/// A TCP connection, plain or after STARTTLS.
enum Io {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for Io {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Io::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Io::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Io {
    fn poll_write(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Io::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            Io::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Io::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            Io::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Io::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Io::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// A raw XMPP client: you send elements and read what comes back.
pub struct Client {
    reader: Option<StreamReader<ReadHalf<Io>>>,
    writer: Option<WriteHalf<Io>>,
    domain: String,
    /// The stream features from the latest stream header.
    pub features: Option<Element>,
    /// The full JID after binding.
    pub jid: Option<String>,
    /// Attributes of the server's latest stream header, as `(name, value)` pairs.
    pub header: Vec<(String, String)>,
    /// The ALPN protocol the server picked on a direct TLS connection.
    pub alpn: Option<Vec<u8>>,
    /// Elements read while waiting for something else, handed out by `recv` first.
    backlog: std::collections::VecDeque<Element>,
    /// tls-exporter channel binding, after STARTTLS on TLS 1.3.
    pub exporter: Option<Vec<u8>>,
}

impl Client {
    /// Opens a TCP connection and the first stream; reads the features.
    pub async fn connect(addr: SocketAddr, domain: &str) -> anyhow::Result<Client> {
        let tcp = TcpStream::connect(addr).await?;
        let (r, w) = tokio::io::split(Io::Plain(tcp));
        let mut c = Client {
            reader: Some(StreamReader::new(r, 16 << 20)),
            writer: Some(w),
            domain: domain.to_string(),
            features: None,
            jid: None,
            header: Vec::new(),
            alpn: None,
            backlog: Default::default(),
            exporter: None,
        };
        c.open().await?;
        Ok(c)
    }

    /// Opens a TCP connection and sends nothing, for tests that write their own stream header.
    pub async fn connect_raw(addr: SocketAddr, domain: &str) -> anyhow::Result<Client> {
        let tcp = TcpStream::connect(addr).await?;
        let (r, w) = tokio::io::split(Io::Plain(tcp));
        Ok(Client {
            reader: Some(StreamReader::new(r, 16 << 20)),
            writer: Some(w),
            domain: domain.to_string(),
            features: None,
            jid: None,
            header: Vec::new(),
            alpn: None,
            backlog: Default::default(),
            exporter: None,
        })
    }

    /// Sends `raw` (a stream header written by the test) and reads the server's stream header
    /// into `header`. The features (or a stream error) are left for `recv`.
    pub async fn open_with(&mut self, raw: &str) -> anyhow::Result<()> {
        self.send_raw(raw).await?;
        match self.next_event().await? {
            StreamEvent::Open { attrs, .. } => {
                self.header = attrs;
                Ok(())
            }
            e => bail!("expected a stream header, got {e:?}"),
        }
    }

    /// An attribute of the server's latest stream header (matched on the local name too).
    pub fn header_attr(&self, name: &str) -> Option<&str> {
        self.header.iter().find(|(k, _)| k == name || k.rsplit(':').next() == Some(name)).map(|(_, v)| v.as_str())
    }

    /// Connects with TLS from the first byte (XEP-0368), ALPN `xmpp-client`.
    pub async fn connect_tls(addr: SocketAddr, domain: &str) -> anyhow::Result<Client> {
        let tcp = TcpStream::connect(addr).await?;
        let tls = tls_connect(tcp, domain, &[b"xmpp-client"]).await?;
        let exporter = exporter(&tls);
        let alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        let (r, w) = tokio::io::split(Io::Tls(Box::new(tls)));
        let mut c = Client {
            reader: Some(StreamReader::new(r, 16 << 20)),
            writer: Some(w),
            domain: domain.to_string(),
            features: None,
            jid: None,
            header: Vec::new(),
            alpn,
            backlog: Default::default(),
            exporter,
        };
        c.open().await?;
        Ok(c)
    }

    /// Sends a stream header and reads the server's header and features.
    pub async fn open(&mut self) -> anyhow::Result<()> {
        let h = stream_header(ns::CLIENT, None, Some(&self.domain), None, &[]);
        self.send_raw(&h).await?;
        match self.next_event().await? {
            StreamEvent::Open { attrs, .. } => self.header = attrs,
            e => bail!("expected a stream header, got {e:?}"),
        }
        let f = self.recv().await?;
        if !f.is("features", ns::STREAM) {
            bail!("expected stream features, got {f}");
        }
        self.features = Some(f);
        Ok(())
    }

    /// STARTTLS (accepting the server's certificate, whatever it is), then a new stream.
    pub async fn starttls(&mut self) -> anyhow::Result<()> {
        self.send(&Element::new("starttls", ns::TLS)).await?;
        let r = self.recv().await?;
        if !r.is("proceed", ns::TLS) {
            bail!("STARTTLS refused: {r}");
        }
        let (Some(reader), Some(writer)) = (self.reader.take(), self.writer.take()) else { bail!("closed") };
        let tcp = match reader.into_inner().unsplit(writer) {
            Io::Plain(t) => t,
            Io::Tls(_) => bail!("already TLS"),
        };
        let tls = tls_connect(tcp, &self.domain, &[]).await?;
        self.exporter = exporter(&tls);
        let (r, w) = tokio::io::split(Io::Tls(Box::new(tls)));
        self.reader = Some(StreamReader::new(r, 16 << 20));
        self.writer = Some(w);
        self.open().await
    }

    /// The SASL mechanisms offered in the current features.
    pub fn mechanisms(&self) -> Vec<String> {
        self.features
            .as_ref()
            .and_then(|f| f.get_child("mechanisms", ns::SASL))
            .map(|m| m.children().map(|c| c.text_content()).collect())
            .unwrap_or_default()
    }

    pub async fn auth_plain(&mut self, user: &str, password: &str) -> anyhow::Result<()> {
        let blob = B64.encode(format!("\0{user}\0{password}"));
        self.send(&Element::new("auth", ns::SASL).attr_set("mechanism", "PLAIN").text(blob)).await?;
        let r = self.recv().await?;
        if !r.is("success", ns::SASL) {
            bail!("PLAIN failed: {r}");
        }
        self.restart().await
    }

    /// SCRAM with SHA-1, SHA-256 or SHA-512, with `-PLUS` using tls-exporter.
    pub async fn auth_scram(&mut self, mechanism: &str, user: &str, password: &str) -> anyhow::Result<()> {
        let mut scram = ScramClient::new(mechanism, user, password, self.exporter.clone())?;
        let first = scram.client_first();
        self.send(&Element::new("auth", ns::SASL).attr_set("mechanism", mechanism).text(B64.encode(first))).await?;
        let ch = self.recv().await?;
        if !ch.is("challenge", ns::SASL) {
            bail!("SCRAM failed at the first step: {ch}");
        }
        let server_first = String::from_utf8(B64.decode(ch.text_content().trim())?)?;
        let fin = scram.client_final(&server_first)?;
        self.send(&Element::new("response", ns::SASL).text(B64.encode(fin))).await?;
        let r = self.recv().await?;
        if !r.is("success", ns::SASL) {
            bail!("SCRAM failed: {r}");
        }
        let data = String::from_utf8(B64.decode(r.text_content().trim())?)?;
        scram.verify_server(&data)?;
        self.restart().await
    }

    /// Restarts the stream, e.g. after a SASL `<success/>` the test handled itself.
    pub async fn restart(&mut self) -> anyhow::Result<()> {
        self.reader = self.reader.take().map(StreamReader::restart);
        self.open().await
    }

    /// Binds a resource (RFC 6120 §7) and remembers the full JID.
    pub async fn bind(&mut self, resource: Option<&str>) -> anyhow::Result<String> {
        let mut b = Element::new("bind", ns::BIND);
        if let Some(r) = resource {
            b.append(Element::new("resource", ns::BIND).text(r));
        }
        let r = self.iq("set", None, b).await?;
        if r.attr("type") != Some("result") {
            bail!("bind failed: {r}");
        }
        let jid = r.get_child("bind", ns::BIND).and_then(|b| b.child_text("jid", ns::BIND)).context("no jid in bind result")?;
        self.jid = Some(jid.clone());
        Ok(jid)
    }

    pub async fn send(&mut self, el: &Element) -> anyhow::Result<()> {
        let xml = el.to_stream_xml(ns::CLIENT);
        self.send_raw(&xml).await
    }

    pub async fn send_raw(&mut self, xml: &str) -> anyhow::Result<()> {
        let w = self.writer.as_mut().context("closed")?;
        w.write_all(xml.as_bytes()).await?;
        w.flush().await?;
        Ok(())
    }

    async fn next_event(&mut self) -> anyhow::Result<StreamEvent> {
        let r = self.reader.as_mut().context("closed")?;
        match tokio::time::timeout(TIMEOUT, r.next()).await {
            Err(_) => bail!("timed out waiting for the server"),
            Ok(Err(e)) => bail!("read error: {e}"),
            Ok(Ok(None)) => bail!("the server closed the connection"),
            Ok(Ok(Some(ev))) => Ok(ev),
        }
    }

    /// The next top-level element. Fails on timeout or a closed stream.
    pub async fn recv(&mut self) -> anyhow::Result<Element> {
        if let Some(e) = self.backlog.pop_front() {
            return Ok(e);
        }
        match self.next_event().await? {
            StreamEvent::Stanza(e) => Ok(e),
            StreamEvent::Close => bail!("the server closed the stream"),
            StreamEvent::Open { .. } => bail!("unexpected stream header"),
        }
    }

    /// Like `recv` but returns None when nothing arrives within `wait`.
    pub async fn recv_within(&mut self, wait: Duration) -> anyhow::Result<Option<Element>> {
        if let Some(e) = self.backlog.pop_front() {
            return Ok(Some(e));
        }
        let r = self.reader.as_mut().context("closed")?;
        match tokio::time::timeout(wait, r.next()).await {
            Err(_) => Ok(None),
            Ok(Ok(Some(StreamEvent::Stanza(e)))) => Ok(Some(e)),
            Ok(Ok(Some(ev))) => bail!("unexpected {ev:?}"),
            Ok(Ok(None)) => bail!("the server closed the connection"),
            Ok(Err(e)) => bail!("read error: {e}"),
        }
    }

    /// Asserts nothing arrives for `wait`.
    pub async fn expect_silence(&mut self, wait: Duration) -> anyhow::Result<()> {
        match self.recv_within(wait).await? {
            None => Ok(()),
            Some(e) => bail!("expected nothing, got {e}"),
        }
    }

    /// Reads until `f` matches; the elements skipped are kept for later `recv`s.
    pub async fn expect(&mut self, mut f: impl FnMut(&Element) -> bool) -> anyhow::Result<Element> {
        let mut skipped = Vec::new();
        if let Some(i) = self.backlog.iter().position(&mut f) {
            return self.backlog.remove(i).context("backlog");
        }
        let deadline = tokio::time::Instant::now() + TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let r = self.reader.as_mut().context("closed")?;
            let ev = match tokio::time::timeout(left, r.next()).await {
                Err(_) => bail!("timed out; got instead: {}", skipped.iter().map(|e: &Element| e.to_xml()).collect::<Vec<_>>().join("\n")),
                Ok(Err(e)) => bail!("read error: {e}"),
                Ok(Ok(None)) => bail!("the server closed the connection"),
                Ok(Ok(Some(ev))) => ev,
            };
            match ev {
                StreamEvent::Stanza(e) if f(&e) => {
                    self.backlog.extend(skipped);
                    return Ok(e);
                }
                StreamEvent::Stanza(e) => skipped.push(e),
                other => bail!("unexpected {other:?}"),
            }
        }
    }

    /// Sends an IQ and waits for the reply with the same id (other stanzas are kept).
    pub async fn iq(&mut self, kind: &str, to: Option<&str>, payload: Element) -> anyhow::Result<Element> {
        let id = quark_core::new_id();
        let iq = quark_core::stanza::iq(kind, &id, None, to, payload);
        self.send(&iq).await?;
        self.expect(|e| e.name() == "iq" && e.attr("id") == Some(&id) && matches!(e.attr("type"), Some("result" | "error"))).await
    }

    pub async fn iq_get(&mut self, to: Option<&str>, payload: Element) -> anyhow::Result<Element> {
        self.iq("get", to, payload).await
    }

    pub async fn iq_set(&mut self, to: Option<&str>, payload: Element) -> anyhow::Result<Element> {
        self.iq("set", to, payload).await
    }

    /// Answers IQs from the server (pings, roster pushes) the way a client must.
    pub async fn answer(&mut self, iq: &Element) -> anyhow::Result<()> {
        let r = quark_core::stanza::iq_result(iq);
        self.send(&r).await
    }

    /// Closes the stream politely.
    pub async fn close(mut self) -> anyhow::Result<()> {
        self.send_raw("</stream:stream>").await?;
        Ok(())
    }

    /// Drops the connection without closing the stream (a phone losing signal).
    pub fn drop_connection(mut self) {
        self.reader.take();
        self.writer.take();
    }

    /// Bare JID after binding.
    pub fn bare(&self) -> Option<String> {
        self.jid.as_ref().map(|j| j.split('/').next().unwrap_or(j).to_string())
    }
}

async fn tls_connect(tcp: TcpStream, domain: &str, alpn: &[&[u8]]) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let name = rustls::pki_types::ServerName::try_from(domain.to_string())?;
    Ok(tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, tcp).await?)
}

fn exporter(tls: &tokio_rustls::client::TlsStream<TcpStream>) -> Option<Vec<u8>> {
    let (_, c) = tls.get_ref();
    if c.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
        return None;
    }
    let mut buf = [0u8; 32];
    c.export_keying_material(&mut buf, b"EXPORTER-Channel-Binding", None).ok()?;
    Some(buf.to_vec())
}

/// Tests talk to self-signed servers.
#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// The client side of SCRAM (RFC 5802), written independently of the server's.
pub struct ScramClient {
    hash: &'static str,
    password: String,
    nonce: String,
    gs2: String,
    cb: Option<Vec<u8>>,
    client_first_bare: String,
    server_signature: Option<Vec<u8>>,
}

impl ScramClient {
    pub fn new(mechanism: &str, user: &str, password: &str, exporter: Option<Vec<u8>>) -> anyhow::Result<Self> {
        let plus = mechanism.ends_with("-PLUS");
        let hash = match mechanism.trim_end_matches("-PLUS") {
            "SCRAM-SHA-1" => "sha1",
            "SCRAM-SHA-256" => "sha256",
            "SCRAM-SHA-512" => "sha512",
            m => bail!("unknown mechanism {m}"),
        };
        let nonce: String = (0..24).map(|_| rand::random::<char>()).filter(char::is_ascii_alphanumeric).take(16).collect();
        let nonce = if nonce.len() < 8 { "fallbacknonce1234".to_string() } else { nonce };
        let (gs2, cb) =
            if plus { ("p=tls-exporter,,".to_string(), Some(exporter.context("-PLUS needs TLS 1.3")?)) } else { ("n,,".to_string(), None) };
        let client_first_bare = format!("n={user},r={nonce}");
        Ok(ScramClient { hash, password: password.into(), nonce, gs2, cb, client_first_bare, server_signature: None })
    }

    pub fn client_first(&self) -> String {
        format!("{}{}", self.gs2, self.client_first_bare)
    }

    fn hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        use hmac::Mac;
        macro_rules! m {
            ($h:ty) => {{
                let mut m = <hmac::Hmac<$h>>::new_from_slice(key).expect("any key length");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }};
        }
        match self.hash {
            "sha1" => m!(sha1::Sha1),
            "sha256" => m!(sha2::Sha256),
            _ => m!(sha2::Sha512),
        }
    }

    fn h(&self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        match self.hash {
            "sha1" => sha1::Sha1::digest(data).to_vec(),
            "sha256" => sha2::Sha256::digest(data).to_vec(),
            _ => sha2::Sha512::digest(data).to_vec(),
        }
    }

    pub fn client_final(&mut self, server_first: &str) -> anyhow::Result<String> {
        let mut r = None;
        let mut s = None;
        let mut i = None;
        for p in server_first.split(',') {
            if let Some(v) = p.strip_prefix("r=") {
                r = Some(v.to_string());
            } else if let Some(v) = p.strip_prefix("s=") {
                s = Some(B64.decode(v)?);
            } else if let Some(v) = p.strip_prefix("i=") {
                i = Some(v.parse::<u32>()?);
            }
        }
        let (r, s, i) = (r.context("no nonce")?, s.context("no salt")?, i.context("no iterations")?);
        if !r.starts_with(&self.nonce) {
            bail!("server nonce doesn't extend ours");
        }
        let salted = match self.hash {
            "sha1" => pbkdf2::pbkdf2_hmac_array::<sha1::Sha1, 20>(self.password.as_bytes(), &s, i).to_vec(),
            "sha256" => pbkdf2::pbkdf2_hmac_array::<sha2::Sha256, 32>(self.password.as_bytes(), &s, i).to_vec(),
            _ => pbkdf2::pbkdf2_hmac_array::<sha2::Sha512, 64>(self.password.as_bytes(), &s, i).to_vec(),
        };
        let client_key = self.hmac(&salted, b"Client Key");
        let stored = self.h(&client_key);
        let mut cbind = self.gs2.as_bytes().to_vec();
        if let Some(cb) = &self.cb {
            cbind.extend_from_slice(cb);
        }
        let without = format!("c={},r={r}", B64.encode(cbind));
        let auth = format!("{},{server_first},{without}", self.client_first_bare);
        let sig = self.hmac(&stored, auth.as_bytes());
        let proof: Vec<u8> = client_key.iter().zip(&sig).map(|(a, b)| a ^ b).collect();
        let server_key = self.hmac(&salted, b"Server Key");
        self.server_signature = Some(self.hmac(&server_key, auth.as_bytes()));
        Ok(format!("{without},p={}", B64.encode(proof)))
    }

    pub fn verify_server(&self, server_final: &str) -> anyhow::Result<()> {
        let v = server_final.strip_prefix("v=").context("server final has no signature")?;
        if Some(B64.decode(v)?) != self.server_signature {
            bail!("the server's SCRAM signature is wrong");
        }
        Ok(())
    }
}

/// A certificate authority for tests: certificates it issues validate for their names once its
/// PEM is in `s2s.trusted_certs`.
pub struct TestCa {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
}

impl TestCa {
    pub fn new() -> anyhow::Result<TestCa> {
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new())?;
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.distinguished_name.push(rcgen::DnType::CommonName, "Quark Test CA");
        let key = rcgen::KeyPair::generate()?;
        let cert = p.self_signed(&key)?;
        Ok(TestCa { cert, key })
    }

    /// The CA certificate, PEM.
    pub fn pem(&self) -> String {
        self.cert.pem()
    }

    /// A certificate for `domain` and its subdomains, as (domain, certificate PEM, key PEM) for
    /// `Options::certs`.
    pub fn issue(&self, domain: &str) -> anyhow::Result<(String, String, String)> {
        let p = rcgen::CertificateParams::new(vec![domain.to_string(), format!("*.{domain}")])?;
        let key = rcgen::KeyPair::generate()?;
        let cert = p.signed_by(&key, &self.cert, &self.key)?;
        Ok((domain.to_string(), cert.pem(), key.serialize_pem()))
    }
}

/// Builds a `<message/>` with a body.
pub fn message(to: &str, kind: &str, body: &str) -> Element {
    Element::new("message", ns::CLIENT).attr_set("to", to).attr_set("type", kind).attr_set("id", quark_core::new_id()).text_child(
        "body",
        ns::CLIENT,
        body,
    )
}

/// Builds a `<presence/>`.
pub fn presence(to: Option<&str>, kind: Option<&str>) -> Element {
    Element::new("presence", ns::CLIENT).attr_opt("to", to).attr_opt("type", kind)
}
