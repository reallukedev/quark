//! Clients for the web listener: plain HTTP requests, XMPP over WebSocket (RFC 7395) and over
//! BOSH (XEP-0206).

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{bail, Context as _};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use quark_core::{ns, Element};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

use crate::{ScramClient, TestServer, DOMAIN, TIMEOUT};

/// A raw HTTP/1.1 response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    /// Header names lowercased, in order.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers.iter().find(|(k, _)| *k == name).map(|(_, v)| v.as_str())
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// One HTTP/1.1 request on its own connection (`Connection: close`). `Host` defaults to the test
/// domain; `Content-Length` is added for bodies and for PUT/POST unless given in `headers`.
pub async fn http_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> anyhow::Result<HttpResponse> {
    let mut tcp = TcpStream::connect(addr).await?;
    let mut head = format!("{method} {path} HTTP/1.1\r\nConnection: close\r\n");
    let has = |n: &str| headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(n));
    if !has("host") {
        head.push_str(&format!("Host: {DOMAIN}\r\n"));
    }
    if !has("content-length") && (!body.is_empty() || matches!(method, "PUT" | "POST")) {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    tcp.write_all(head.as_bytes()).await?;
    tcp.write_all(body).await?;
    tcp.flush().await?;
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(90), tcp.read_to_end(&mut raw)).await.context("timed out waiting for an HTTP response")??;
    parse_http_response(&raw, method == "HEAD")
}

fn parse_http_response(raw: &[u8], head_only: bool) -> anyhow::Result<HttpResponse> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n").context("no end of headers")?;
    let head = std::str::from_utf8(&raw[..end])?;
    let mut lines = head.split("\r\n");
    let status: u16 = lines.next().and_then(|l| l.split(' ').nth(1)).context("no status line")?.parse()?;
    let headers: Vec<(String, String)> =
        lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
    let mut rest = &raw[end + 4..];
    let chunked = headers.iter().any(|(k, v)| k == "transfer-encoding" && v.eq_ignore_ascii_case("chunked"));
    let body = if head_only {
        Vec::new()
    } else if chunked {
        let mut out = Vec::new();
        loop {
            let nl = rest.windows(2).position(|w| w == b"\r\n").context("bad chunk")?;
            let size = usize::from_str_radix(std::str::from_utf8(&rest[..nl])?.split(';').next().unwrap_or("0").trim(), 16)?;
            rest = &rest[nl + 2..];
            if size == 0 {
                break;
            }
            out.extend_from_slice(rest.get(..size).context("short chunk")?);
            rest = rest.get(size + 2..).context("short chunk")?;
        }
        out
    } else {
        rest.to_vec()
    };
    Ok(HttpResponse { status, headers, body })
}

/// The header a TLS proxy in front of the web listener adds. Tests connect over plain HTTP from
/// loopback, which is trusted as such a proxy.
pub const VIA_TLS_PROXY: (&str, &str) = ("X-Forwarded-Proto", "https");

/// An XMPP client over WebSocket (RFC 7395).
pub struct WsClient {
    ws: tokio_tungstenite::WebSocketStream<crate::Io>,
    /// tls-exporter channel binding, over `wss:` on TLS 1.3.
    pub exporter: Option<Vec<u8>>,
    domain: String,
    /// The stream features from the latest `<open/>`.
    pub features: Option<Element>,
    /// The `<open/>` the server answered with.
    pub server_open: Option<Element>,
    pub jid: Option<String>,
    /// The subprotocol the server picked.
    pub protocol: Option<String>,
    backlog: VecDeque<Element>,
}

impl WsClient {
    /// Opens a WebSocket to `/xmpp-websocket` with the `xmpp` subprotocol and the extra headers,
    /// then the first stream; reads the features.
    pub async fn connect(addr: SocketAddr, domain: &str, headers: &[(&str, &str)]) -> anyhow::Result<WsClient> {
        let mut c = Self::handshake(addr, headers).await?;
        c.domain = domain.to_string();
        c.open().await?;
        Ok(c)
    }

    /// Like `connect`, over TLS (`wss:`) to a web listener with `http.tls` on.
    pub async fn connect_tls(addr: SocketAddr, domain: &str) -> anyhow::Result<WsClient> {
        let tls = crate::tls_connect(TcpStream::connect(addr).await?, domain, &[b"http/1.1"]).await?;
        let exporter = crate::exporter(&tls);
        let mut c = Self::upgrade(crate::Io::Tls(Box::new(tls)), &format!("wss://{domain}/xmpp-websocket"), &[]).await?;
        c.exporter = exporter;
        c.domain = domain.to_string();
        c.open().await?;
        Ok(c)
    }

    /// Only the WebSocket handshake, no `<open/>` yet.
    pub async fn handshake(addr: SocketAddr, headers: &[(&str, &str)]) -> anyhow::Result<WsClient> {
        let tcp = TcpStream::connect(addr).await?;
        Self::upgrade(crate::Io::Plain(tcp), &format!("ws://{addr}/xmpp-websocket"), headers).await
    }

    async fn upgrade(io: crate::Io, url: &str, headers: &[(&str, &str)]) -> anyhow::Result<WsClient> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
        let mut req = url.into_client_request()?;
        req.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static("xmpp"));
        for (k, v) in headers {
            req.headers_mut().insert(HeaderName::try_from(*k)?, HeaderValue::try_from(*v)?);
        }
        let (ws, resp) = tokio::time::timeout(TIMEOUT, tokio_tungstenite::client_async(req, io)).await??;
        let protocol = resp.headers().get("sec-websocket-protocol").and_then(|v| v.to_str().ok()).map(str::to_string);
        Ok(WsClient {
            ws,
            exporter: None,
            domain: DOMAIN.into(),
            features: None,
            server_open: None,
            jid: None,
            protocol,
            backlog: VecDeque::new(),
        })
    }

    /// Sends `<open/>` and reads the server's `<open/>` and features.
    pub async fn open(&mut self) -> anyhow::Result<()> {
        let open = Element::new("open", ns::FRAMING).attr_set("to", self.domain.clone()).attr_set("version", "1.0");
        self.send(&open).await?;
        let o = self.recv().await?;
        if !o.is("open", ns::FRAMING) {
            bail!("expected <open/>, got {o}");
        }
        self.server_open = Some(o);
        let f = self.recv().await?;
        if !f.is("features", ns::STREAM) {
            bail!("expected stream features, got {f}");
        }
        self.features = Some(f);
        Ok(())
    }

    pub async fn send(&mut self, el: &Element) -> anyhow::Result<()> {
        self.send_raw(&el.to_xml()).await
    }

    pub async fn send_raw(&mut self, text: &str) -> anyhow::Result<()> {
        self.ws.send(Message::text(text)).await?;
        Ok(())
    }

    pub async fn send_message(&mut self, m: Message) -> anyhow::Result<()> {
        self.ws.send(m).await?;
        Ok(())
    }

    /// The next frame as an element (`<close/>` included). Fails on timeout or a closed socket.
    pub async fn recv(&mut self) -> anyhow::Result<Element> {
        match self.recv_within(TIMEOUT).await? {
            Some(e) => Ok(e),
            None => bail!("timed out waiting for the server"),
        }
    }

    /// Like `recv`, but None when nothing arrives within `wait`.
    pub async fn recv_within(&mut self, wait: Duration) -> anyhow::Result<Option<Element>> {
        if let Some(e) = self.backlog.pop_front() {
            return Ok(Some(e));
        }
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let msg = match tokio::time::timeout_at(deadline, self.ws.next()).await {
                Err(_) => return Ok(None),
                Ok(None) => bail!("the server closed the WebSocket"),
                Ok(Some(m)) => m?,
            };
            match msg {
                Message::Text(t) => return Ok(Some(Element::parse(t.as_str())?)),
                Message::Close(_) => bail!("the server closed the WebSocket"),
                Message::Binary(_) => bail!("the server sent a binary frame"),
                _ => {}
            }
        }
    }

    /// Reads until `f` matches; skipped elements stay for later `recv`s.
    pub async fn expect(&mut self, mut f: impl FnMut(&Element) -> bool) -> anyhow::Result<Element> {
        if let Some(i) = self.backlog.iter().position(&mut f) {
            return self.backlog.remove(i).context("backlog");
        }
        let mut skipped = Vec::new();
        let deadline = tokio::time::Instant::now() + TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let next = match self.ws_next_element(left).await? {
                Some(e) => e,
                None => bail!("timed out; got instead: {}", skipped.iter().map(Element::to_xml).collect::<Vec<_>>().join("\n")),
            };
            if f(&next) {
                self.backlog.extend(skipped);
                return Ok(next);
            }
            skipped.push(next);
        }
    }

    async fn ws_next_element(&mut self, wait: Duration) -> anyhow::Result<Option<Element>> {
        let saved = std::mem::take(&mut self.backlog);
        let r = self.recv_within(wait).await;
        self.backlog = saved;
        r
    }

    /// Reads frames until the WebSocket closes; returns what came before.
    pub async fn expect_closed(&mut self) -> anyhow::Result<Vec<Element>> {
        let mut got: Vec<Element> = self.backlog.drain(..).collect();
        loop {
            match tokio::time::timeout(TIMEOUT, self.ws.next()).await? {
                None | Some(Ok(Message::Close(_))) | Some(Err(_)) => return Ok(got),
                Some(Ok(Message::Text(t))) => got.push(Element::parse(t.as_str())?),
                Some(Ok(_)) => {}
            }
        }
    }

    pub fn mechanisms(&self) -> Vec<String> {
        self.features
            .as_ref()
            .and_then(|f| f.get_child("mechanisms", ns::SASL))
            .map(|m| m.children().map(|c| c.text_content()).collect())
            .unwrap_or_default()
    }

    /// SCRAM (`-PLUS` uses tls-exporter, over `wss:`), then a new stream.
    pub async fn auth_scram(&mut self, mechanism: &str, user: &str, password: &str) -> anyhow::Result<()> {
        let mut scram = ScramClient::new(mechanism, user, password, self.exporter.clone())?;
        self.send(&Element::new("auth", ns::SASL).attr_set("mechanism", mechanism).text(B64.encode(scram.client_first()))).await?;
        let ch = self.recv().await?;
        if !ch.is("challenge", ns::SASL) {
            bail!("SCRAM failed at the first step: {ch}");
        }
        let fin = scram.client_final(&String::from_utf8(B64.decode(ch.text_content().trim())?)?)?;
        self.send(&Element::new("response", ns::SASL).text(B64.encode(fin))).await?;
        let r = self.recv().await?;
        if !r.is("success", ns::SASL) {
            bail!("SCRAM failed: {r}");
        }
        scram.verify_server(&String::from_utf8(B64.decode(r.text_content().trim())?)?)?;
        self.open().await
    }

    pub async fn iq(&mut self, kind: &str, to: Option<&str>, payload: Element) -> anyhow::Result<Element> {
        let id = quark_core::new_id();
        self.send(&quark_core::stanza::iq(kind, &id, None, to, payload)).await?;
        self.expect(|e| e.name() == "iq" && e.attr("id") == Some(&id) && matches!(e.attr("type"), Some("result" | "error"))).await
    }

    pub async fn bind(&mut self, resource: Option<&str>) -> anyhow::Result<String> {
        let mut b = Element::new("bind", ns::BIND);
        if let Some(r) = resource {
            b.append(Element::new("resource", ns::BIND).text(r));
        }
        let r = self.iq("set", None, b).await?;
        let jid = r.get_child("bind", ns::BIND).and_then(|b| b.child_text("jid", ns::BIND)).with_context(|| format!("bind failed: {r}"))?;
        self.jid = Some(jid.clone());
        Ok(jid)
    }

    /// Ends the stream with `<close/>`.
    pub async fn close(&mut self) -> anyhow::Result<()> {
        self.send(&Element::new("close", ns::FRAMING)).await
    }
}

/// An XMPP client over BOSH (XEP-0206). Each request is a fresh HTTP connection.
pub struct BoshClient {
    addr: SocketAddr,
    pub sid: String,
    pub rid: u64,
    /// The session creation response.
    pub session: Element,
    pub features: Option<Element>,
    pub jid: Option<String>,
    /// Payload elements received while waiting for something else.
    backlog: VecDeque<Element>,
}

impl BoshClient {
    /// Creates a session (through the trusted-proxy header, so it counts as secure).
    pub async fn connect(addr: SocketAddr, domain: &str) -> anyhow::Result<BoshClient> {
        let rid = 1_000 + u64::from(rand::random::<u16>());
        let body = format!(
            "<body xmlns='{}' xmlns:xmpp='{}' rid='{rid}' to='{domain}' wait='5' hold='1' ver='1.11' xmpp:version='1.0' content='text/xml; charset=utf-8'/>",
            ns::BOSH,
            ns::XBOSH
        );
        let r = Self::post(addr, &body).await?;
        let sid = r.attr("sid").with_context(|| format!("no sid in {r}"))?.to_string();
        let features = r.get_child("features", ns::STREAM).cloned();
        Ok(BoshClient { addr, sid, rid: rid + 1, session: r, features, jid: None, backlog: VecDeque::new() })
    }

    pub async fn post(addr: SocketAddr, body: &str) -> anyhow::Result<Element> {
        let r = http_request(addr, "POST", "/http-bind", &[("Content-Type", "text/xml; charset=utf-8"), VIA_TLS_PROXY], body.as_bytes())
            .await?;
        if r.status != 200 {
            bail!("BOSH request failed with HTTP {}: {}", r.status, r.text());
        }
        Ok(Element::parse(&r.text())?)
    }

    /// The `<body/>` for the next rid, with extra attributes and payload.
    pub fn body(&mut self, attrs: &[(&str, &str)], payload: &[Element]) -> String {
        let mut b = Element::new("body", ns::BOSH).attr_set("rid", self.rid.to_string()).attr_set("sid", self.sid.clone());
        b.set_attr("xmlns:xmpp", ns::XBOSH);
        for (k, v) in attrs {
            b.set_attr(k, *v);
        }
        for p in payload {
            b.append(p.clone());
        }
        self.rid += 1;
        b.to_xml()
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Sends one request and returns the response `<body/>`.
    pub async fn request(&mut self, attrs: &[(&str, &str)], payload: &[Element]) -> anyhow::Result<Element> {
        let body = self.body(attrs, payload);
        Self::post(self.addr, &body).await
    }

    /// Sends `payload`, then keeps polling until `f` matches something received.
    pub async fn send_expect(&mut self, payload: &[Element], mut f: impl FnMut(&Element) -> bool) -> anyhow::Result<Element> {
        if let Some(i) = self.backlog.iter().position(&mut f) {
            return self.backlog.remove(i).context("backlog");
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let mut first = true;
        loop {
            if tokio::time::Instant::now() > deadline {
                bail!("timed out waiting over BOSH; got {:?}", self.backlog);
            }
            let r = self.request(&[], if first { payload } else { &[] }).await?;
            first = false;
            if r.attr("type") == Some("terminate") {
                bail!("the session ended: {r}");
            }
            let mut found = None;
            for c in r.children() {
                if found.is_none() && f(c) {
                    found = Some(c.clone());
                } else {
                    self.backlog.push_back(c.clone());
                }
            }
            if let Some(e) = found {
                return Ok(e);
            }
        }
    }

    /// SCRAM, then a stream restart (XEP-0206 §5).
    pub async fn auth_scram(&mut self, mechanism: &str, user: &str, password: &str) -> anyhow::Result<()> {
        let mut scram = ScramClient::new(mechanism, user, password, None)?;
        let auth = Element::new("auth", ns::SASL).attr_set("mechanism", mechanism).text(B64.encode(scram.client_first()));
        let ch = self.send_expect(&[auth], |e| e.ns() == ns::SASL).await?;
        if !ch.is("challenge", ns::SASL) {
            bail!("SCRAM failed at the first step: {ch}");
        }
        let fin = scram.client_final(&String::from_utf8(B64.decode(ch.text_content().trim())?)?)?;
        let r = self.send_expect(&[Element::new("response", ns::SASL).text(B64.encode(fin))], |e| e.ns() == ns::SASL).await?;
        if !r.is("success", ns::SASL) {
            bail!("SCRAM failed: {r}");
        }
        scram.verify_server(&String::from_utf8(B64.decode(r.text_content().trim())?)?)?;
        let restarted = self.request(&[("xmpp:restart", "true")], &[]).await?;
        self.features = restarted.get_child("features", ns::STREAM).cloned();
        if self.features.is_none() {
            bail!("no features after the restart: {restarted}");
        }
        Ok(())
    }

    pub async fn bind(&mut self, resource: &str) -> anyhow::Result<String> {
        let id = quark_core::new_id();
        let iq = quark_core::stanza::iq("set", &id, None, None, Element::new("bind", ns::BIND).text_child("resource", ns::BIND, resource));
        let r = self.send_expect(&[iq], |e| e.name() == "iq" && e.attr("id") == Some(&id)).await?;
        let jid = r.get_child("bind", ns::BIND).and_then(|b| b.child_text("jid", ns::BIND)).with_context(|| format!("bind failed: {r}"))?;
        self.jid = Some(jid.clone());
        Ok(jid)
    }
}

impl TestServer {
    /// The web listener's address.
    pub fn web(&self) -> SocketAddr {
        self.listening.http[0]
    }

    /// Signs in over WebSocket (through the trusted-proxy header) and binds `resource`.
    pub async fn ws_login(&self, user: &str, password: &str, resource: &str) -> anyhow::Result<WsClient> {
        let mut c = WsClient::connect(self.web(), DOMAIN, &[VIA_TLS_PROXY]).await?;
        c.auth_scram("SCRAM-SHA-256", user, password).await?;
        c.bind(Some(resource)).await?;
        Ok(c)
    }

    /// Signs in over BOSH and binds `resource`.
    pub async fn bosh_login(&self, user: &str, password: &str, resource: &str) -> anyhow::Result<BoshClient> {
        let mut c = BoshClient::connect(self.web(), DOMAIN).await?;
        c.auth_scram("SCRAM-SHA-256", user, password).await?;
        c.bind(resource).await?;
        Ok(c)
    }
}
