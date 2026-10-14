//! RFC 7395 XMPP over WebSocket, XEP-0124/XEP-0206 BOSH and XEP-0156 host-meta.
//! Black-box: written from the specifications only.

mod blind_feat;

use std::time::Duration;

use anyhow::{ensure, Context as _};
use blind_feat::*;
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{http_request, message, presence, BoshClient, HttpResponse, TestServer, WsClient, DOMAIN, VIA_TLS_PROXY};

async fn server(users: &[&str]) -> anyhow::Result<TestServer> {
    let s = TestServer::start().await?;
    for u in users {
        s.add_user(u, PW).await?;
    }
    Ok(s)
}

// ---------------------------------------------------------------- WebSocket (RFC 7395)

/// §3.1: the server picks the `xmpp` subprotocol. §3.4 / RFC 6120 §4.7: its `<open/>` is in
/// the framing namespace with from, id and version. §3.9: no STARTTLS feature.
#[tokio::test]
async fn ws_open_and_features() -> anyhow::Result<()> {
    let s = server(&[]).await?;
    let c = WsClient::connect(s.web(), DOMAIN, &[VIA_TLS_PROXY]).await?;
    assert_eq!(c.protocol.as_deref(), Some("xmpp"), "§3.1: Sec-WebSocket-Protocol must be xmpp");
    let open = c.server_open.as_ref().context("no open")?;
    ensure!(open.is("open", ns::FRAMING), "{open}");
    assert_eq!(open.attr("from"), Some(DOMAIN), "{open}");
    assert_eq!(open.attr("version"), Some("1.0"), "{open}");
    ensure!(open.attr("id").is_some_and(|i| !i.is_empty()), "the open needs a stream id: {open}");
    let f = c.features.as_ref().context("no features")?;
    ensure!(!f.has_child("starttls", ns::TLS), "§3.9: a server MUST NOT advertise TLS over WebSocket: {f}");
    ensure!(!c.mechanisms().is_empty(), "SASL offered: {f}");
    Ok(())
}

/// §3.7 + RFC 6120: SASL, restart with a new `<open/>`, bind, then messages both ways with a
/// TCP client; every stanza arrives as one element qualified by `jabber:client`.
#[tokio::test]
async fn ws_auth_bind_and_message_exchange() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut ws = WsClient::connect(s.web(), DOMAIN, &[VIA_TLS_PROXY]).await?;
    ws.auth_scram("SCRAM-SHA-256", "alice", PW).await?;
    let f = ws.features.as_ref().context("no features after restart")?;
    ensure!(f.has_child("bind", ns::BIND), "bind offered after SASL: {f}");
    let me = ws.bind(Some("web")).await?;
    assert_eq!(me, "alice@quark.test/web");
    ws.send(&presence(None, None)).await?;

    let mut bob = s.online("bob", PW, "tcp").await?;
    bob.send(&message("alice@quark.test/web", "chat", "hello web")).await?;
    let m = ws.expect(|e| e.name() == "message").await?;
    assert_eq!(m.ns(), ns::CLIENT, "{m}");
    assert_eq!(m.attr("from"), Some("bob@quark.test/tcp"), "{m}");
    assert_eq!(m.child_text("body", ns::CLIENT).as_deref(), Some("hello web"));

    ws.send(&message("bob@quark.test/tcp", "chat", "hello tcp")).await?;
    let m = bob.expect(|e| e.name() == "message").await?;
    assert_eq!(m.attr("from"), Some("alice@quark.test/web"), "{m}");
    assert_eq!(m.child_text("body", ns::CLIENT).as_deref(), Some("hello tcp"));
    Ok(())
}

/// §3.6: `<close/>` from the client is answered with `<close/>`; the session ends (a contact
/// sees it go unavailable).
#[tokio::test]
async fn ws_close() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    s.make_contacts("alice", "bob").await?;
    let mut bob = s.online("bob", PW, "tcp").await?;
    let mut ws = s.ws_login("alice", PW, "web").await?;
    ws.iq("get", None, Element::new("query", ns::ROSTER)).await?;
    ws.send(&presence(None, None)).await?;
    bob.expect(|e| e.name() == "presence" && e.attr("from") == Some("alice@quark.test/web") && e.attr("type").is_none()).await?;

    ws.close().await?;
    let got = ws.expect(|e| e.is("close", ns::FRAMING)).await.context("the server must answer <close/> with <close/>")?;
    ensure!(got.children().next().is_none(), "{got}");
    bob.expect(|e| e.name() == "presence" && e.attr("from") == Some("alice@quark.test/web") && e.attr("type") == Some("unavailable"))
        .await?;
    Ok(())
}

/// §3.5: a stream error during the open (unknown host) is a complete element, then the
/// connection is closed.
#[tokio::test]
async fn ws_unknown_host_is_a_stream_error() -> anyhow::Result<()> {
    let s = server(&[]).await?;
    let mut c = WsClient::handshake(s.web(), &[VIA_TLS_PROXY]).await?;
    c.send(&Element::new("open", ns::FRAMING).attr_set("to", "nowhere.example").attr_set("version", "1.0")).await?;
    let frames = c.expect_closed().await?;
    let err = frames.iter().find(|e| e.is("error", ns::STREAM)).with_context(|| format!("no stream error in {frames:?}"))?;
    ensure!(err.has_child("host-unknown", ns::STREAMS), "{err}");
    Ok(())
}

/// §3.3.2 / §3.5: a frame that isn't a complete XML element is a fatal stream error.
#[tokio::test]
async fn ws_malformed_frame_is_a_stream_error() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut ws = s.ws_login("alice", PW, "web").await?;
    ws.send_raw("<message xmlns='jabber:client' to='alice@quark.test'><body>half").await?;
    let frames = ws.expect_closed().await?;
    let err = frames.iter().find(|e| e.is("error", ns::STREAM)).with_context(|| format!("no stream error in {frames:?}"))?;
    ensure!(err.has_child("not-well-formed", ns::STREAMS) || err.has_child("bad-format", ns::STREAMS), "{err}");
    Ok(())
}

// ---------------------------------------------------------------- BOSH (XEP-0124 / XEP-0206)

async fn bosh_raw(s: &TestServer, body: &str) -> anyhow::Result<HttpResponse> {
    http_request(s.web(), "POST", "/http-bind", &[("Content-Type", "text/xml; charset=utf-8"), VIA_TLS_PROXY], body.as_bytes()).await
}

fn create_body(rid: u64) -> String {
    format!(
        "<body xmlns='{}' xmlns:xmpp='{}' rid='{rid}' to='{DOMAIN}' wait='5' hold='1' ver='1.11' xmpp:version='1.0' content='text/xml; charset=utf-8' xml:lang='en'/>",
        ns::BOSH,
        ns::XBOSH
    )
}

/// XEP-0124 §17 (terminal binding conditions): an invalid sid or an out-of-window rid ends the session with
/// `item-not-found` (binding condition for ver ≥ 1.6; legacy HTTP 404 also tolerated).
fn assert_item_not_found(r: &HttpResponse) -> anyhow::Result<()> {
    if r.status == 404 {
        return Ok(());
    }
    ensure!(r.status == 200, "HTTP {}: {}", r.status, r.text());
    let b = Element::parse(&r.text())?;
    ensure!(b.attr("type") == Some("terminate") && b.attr("condition") == Some("item-not-found"), "{b}");
    Ok(())
}

/// XEP-0124 "Session Creation Response" + XEP-0206 "Session Creation": the session creation response has sid, wait (≤ the
/// requested), from, and `xmpp:version='1.0'`; features come without STARTTLS.
#[tokio::test]
async fn bosh_session_creation() -> anyhow::Result<()> {
    let s = server(&[]).await?;
    let r = bosh_raw(&s, &create_body(5000)).await?;
    assert_eq!(r.status, 200, "{}", r.text());
    let ct = r.header("content-type").unwrap_or("");
    ensure!(ct.starts_with("text/xml"), "XEP-0124 §7.2: content type {ct}");
    let text = r.text();
    let b = Element::parse(&text)?;
    ensure!(b.is("body", ns::BOSH), "{b}");
    ensure!(b.attr("sid").is_some_and(|s| !s.is_empty()), "no sid: {b}");
    let wait: u64 = b.attr("wait").context("no wait")?.parse()?;
    ensure!(wait <= 5, "wait {wait} longer than requested");
    if let Some(from) = b.attr("from") {
        assert_eq!(from, DOMAIN);
    }
    if let Some(req) = b.attr("requests") {
        ensure!(req.parse::<u32>()? >= 2, "requests should allow hold+1: {b}");
    }
    ensure!(
        text.contains("version='1.0'") || text.contains("version=\"1.0\""),
        "XEP-0206: xmpp:version='1.0' in the creation response: {text}"
    );
    let features = match b.get_child("features", ns::STREAM) {
        Some(f) => f.clone(),
        None => {
            let sid = b.attr("sid").unwrap_or_default();
            let next = format!("<body xmlns='{}' rid='5001' sid='{sid}'/>", ns::BOSH);
            let r = bosh_raw(&s, &next).await?;
            Element::parse(&r.text())?.get_child("features", ns::STREAM).cloned().context("no features")?
        }
    };
    ensure!(!features.has_child("starttls", ns::TLS), "no STARTTLS over BOSH: {features}");
    ensure!(features.has_child("mechanisms", ns::SASL), "{features}");
    Ok(())
}

/// XEP-0206 §5–§7: auth with restart, bind, and messages both ways with a TCP client.
#[tokio::test]
async fn bosh_auth_bind_and_message_exchange() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut b = s.bosh_login("alice", PW, "bosh").await?;
    assert_eq!(b.jid.as_deref(), Some("alice@quark.test/bosh"));
    let mut bob = s.online("bob", PW, "tcp").await?;

    // The request carrying the message may be held until there is something to answer with.
    let body = b.body(&[], &[message("bob@quark.test/tcp", "chat", "from bosh")]);
    let addr = b.addr();
    let pending = tokio::spawn(async move { BoshClient::post(addr, &body).await });
    let got = bob.expect(|e| e.name() == "message").await?;
    assert_eq!(got.attr("from"), Some("alice@quark.test/bosh"), "{got}");
    assert_eq!(got.child_text("body", ns::CLIENT).as_deref(), Some("from bosh"));

    bob.send(&message("alice@quark.test/bosh", "chat", "to bosh")).await?;
    let first = pending.await??;
    let m = match first.children().find(|e| e.name() == "message") {
        Some(m) => m.clone(),
        None => b.send_expect(&[], |e| e.name() == "message").await?,
    };
    assert_eq!(m.attr("from"), Some("bob@quark.test/tcp"), "{m}");
    assert_eq!(m.child_text("body", ns::CLIENT).as_deref(), Some("to bosh"));
    Ok(())
}

/// XEP-0124 §8/§10: a held (long-poll) request is answered as soon as a stanza arrives, well
/// before `wait`.
#[tokio::test]
async fn bosh_long_poll_returns_on_data() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut b = s.bosh_login("alice", PW, "bosh").await?;
    let mut bob = s.online("bob", PW, "tcp").await?;
    // Drain anything pending (e.g. nothing) with one quick exchange carrying presence.
    let body = b.body(&[], &[presence(None, None)]);
    BoshClient::post(b.addr(), &body).await?;

    let body = b.body(&[], &[]);
    let addr = b.addr();
    let started = tokio::time::Instant::now();
    let held = tokio::spawn(async move { BoshClient::post(addr, &body).await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    bob.send(&message("alice@quark.test/bosh", "chat", "ping")).await?;
    let r = tokio::time::timeout(Duration::from_secs(4), held).await.context("the held request wasn't answered")???;
    ensure!(started.elapsed() < Duration::from_secs(4), "answered too late");
    ensure!(r.children().any(|c| c.name() == "message"), "the held request carries the message: {r}");
    Ok(())
}

/// XEP-0124 §17: a rid beyond the window, or an unknown sid, ends with
/// `item-not-found`.
#[tokio::test]
async fn bosh_bad_rid_and_sid() -> anyhow::Result<()> {
    let s = server(&[]).await?;
    let unknown = format!("<body xmlns='{}' rid='77' sid='no-such-session'/>", ns::BOSH);
    assert_item_not_found(&bosh_raw(&s, &unknown).await?)?;

    let mut b = BoshClient::connect(s.web(), DOMAIN).await?;
    let far = b.rid + 1000;
    let body = format!("<body xmlns='{}' rid='{far}' sid='{}'/>", ns::BOSH, b.sid);
    assert_item_not_found(&bosh_raw(&s, &body).await?)?;
    // That error was terminal: the session is gone.
    let next = b.body(&[], &[]);
    assert_item_not_found(&bosh_raw(&s, &next).await?)?;
    Ok(())
}

/// XEP-0124 §13 / XEP-0206: `type='terminate'` ends the session (with the unavailable
/// presence it carries); the sid is no longer valid.
#[tokio::test]
async fn bosh_terminate() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    s.make_contacts("alice", "bob").await?;
    let mut bob = s.online("bob", PW, "tcp").await?;
    let mut b = s.bosh_login("alice", PW, "bosh").await?;
    let roster_id = quark_testkit::quark_core::new_id();
    let roster = quark_testkit::quark_core::stanza::iq("get", &roster_id, None, None, Element::new("query", ns::ROSTER));
    b.send_expect(&[roster], |e| e.attr("id") == Some(roster_id.as_str())).await?;
    let body = b.body(&[], &[presence(None, None)]);
    BoshClient::post(b.addr(), &body).await?;
    bob.expect(|e| e.name() == "presence" && e.attr("from") == Some("alice@quark.test/bosh") && e.attr("type").is_none()).await?;

    let body = b.body(&[("type", "terminate")], &[presence(None, Some("unavailable"))]);
    let r = bosh_raw(&s, &body).await?;
    assert_eq!(r.status, 200, "{}", r.text());
    bob.expect(|e| e.name() == "presence" && e.attr("from") == Some("alice@quark.test/bosh") && e.attr("type") == Some("unavailable"))
        .await?;
    let after = b.body(&[], &[]);
    assert_item_not_found(&bosh_raw(&s, &after).await?)?;
    Ok(())
}

/// XEP-0124 §11: with `hold='1'`, a new request makes the server answer the one it was
/// holding.
#[tokio::test]
async fn bosh_new_request_releases_held_one() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut b = s.bosh_login("alice", PW, "bosh").await?;
    let addr = b.addr();
    let first = b.body(&[], &[]);
    let started = tokio::time::Instant::now();
    let held = tokio::spawn(async move { BoshClient::post(addr, &first).await });
    tokio::time::sleep(Duration::from_millis(400)).await;
    let second = b.body(&[], &[]);
    let next = tokio::spawn(async move { BoshClient::post(addr, &second).await });
    tokio::time::timeout(Duration::from_secs(3), held).await.context("the held request was not released")???;
    ensure!(started.elapsed() < Duration::from_secs(3));
    next.abort();
    Ok(())
}

/// XEP-0124 §7.1 / §11: an empty request with nothing to send is held for at most `wait`.
#[tokio::test]
async fn bosh_empty_poll_returns_after_wait() -> anyhow::Result<()> {
    let s = server(&[]).await?;
    let create = create_body(4242).replace("wait='5'", "wait='1'");
    let r = Element::parse(&bosh_raw(&s, &create).await?.text())?;
    let sid = r.attr("sid").context("no sid")?.to_string();
    let wait: u64 = r.attr("wait").context("no wait")?.parse()?;
    let mut rid = 4243;
    if r.get_child("features", ns::STREAM).is_none() {
        // Features come in the next response; take them first.
        bosh_raw(&s, &format!("<body xmlns='{}' rid='{rid}' sid='{sid}'/>", ns::BOSH)).await?;
        rid += 1;
    }
    let started = tokio::time::Instant::now();
    let r = bosh_raw(&s, &format!("<body xmlns='{}' rid='{rid}' sid='{sid}'/>", ns::BOSH)).await?;
    assert_eq!(r.status, 200, "{}", r.text());
    ensure!(started.elapsed() <= Duration::from_secs(wait + 2), "held {:?} with wait={wait}", started.elapsed());
    Ok(())
}

// ---------------------------------------------------------------- host-meta (XEP-0156)

fn xrd_links(xml: &str) -> anyhow::Result<Vec<(String, String)>> {
    let x = Element::parse(xml)?;
    ensure!(x.is("XRD", "http://docs.oasis-open.org/ns/xri/xrd-1.0"), "{x}");
    Ok(x.children()
        .filter(|l| l.name() == "Link")
        .filter_map(|l| Some((l.attr("rel")?.to_string(), l.attr("href")?.to_string())))
        .collect())
}

fn find<'a>(links: &'a [(String, String)], rel: &str) -> Option<&'a str> {
    links.iter().find(|(r, _)| r == rel).map(|(_, h)| h.as_str())
}

/// The path of an absolute URL.
fn path_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.find('/').map_or("/", |i| &rest[i..])
}

/// XEP-0156 §3.3: host-meta (XRD) and host-meta.json list the WebSocket (`wss:`) and BOSH
/// (`https:`) endpoints, and those endpoints answer.
#[tokio::test]
async fn host_meta_advertises_endpoints() -> anyhow::Result<()> {
    let s = server(&[]).await?;
    let r = http_request(s.web(), "GET", "/.well-known/host-meta", &[], b"").await?;
    assert_eq!(r.status, 200, "{}", r.text());
    let links = xrd_links(&r.text())?;
    let ws = find(&links, "urn:xmpp:alt-connections:websocket").with_context(|| format!("no websocket link: {links:?}"))?.to_string();
    let bosh = find(&links, "urn:xmpp:alt-connections:xbosh").with_context(|| format!("no xbosh link: {links:?}"))?.to_string();
    ensure!(ws.starts_with("wss://"), "{ws}");
    ensure!(bosh.starts_with("https://"), "{bosh}");

    let r = http_request(s.web(), "GET", "/.well-known/host-meta.json", &[], b"").await?;
    assert_eq!(r.status, 200, "{}", r.text());
    let ct = r.header("content-type").unwrap_or("");
    ensure!(ct.starts_with("application/json"), "content type {ct}");
    let j: serde_json::Value = serde_json::from_slice(&r.body)?;
    let links = j["links"].as_array().context("no links array")?;
    let jfind = |rel: &str| links.iter().find(|l| l["rel"] == rel).and_then(|l| l["href"].as_str()).map(str::to_string);
    assert_eq!(jfind("urn:xmpp:alt-connections:websocket").as_deref(), Some(ws.as_str()), "JSON and XRD agree");
    assert_eq!(jfind("urn:xmpp:alt-connections:xbosh").as_deref(), Some(bosh.as_str()), "JSON and XRD agree");

    // The BOSH endpoint answers a session creation request at the advertised path.
    let r = http_request(
        s.web(),
        "POST",
        path_of(&bosh),
        &[("Content-Type", "text/xml; charset=utf-8"), VIA_TLS_PROXY],
        create_body(9000).as_bytes(),
    )
    .await?;
    assert_eq!(r.status, 200, "{}", r.text());
    ensure!(Element::parse(&r.text())?.attr("sid").is_some(), "{}", r.text());

    // The WebSocket endpoint upgrades at the advertised path.
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut req = format!("ws://{}{}", s.web(), path_of(&ws)).into_client_request()?;
    req.headers_mut().insert("sec-websocket-protocol", "xmpp".parse()?);
    let tcp = tokio::net::TcpStream::connect(s.web()).await?;
    let (_ws, resp) = tokio_tungstenite::client_async(req, tcp).await?;
    assert_eq!(resp.status().as_u16(), 101);
    Ok(())
}
