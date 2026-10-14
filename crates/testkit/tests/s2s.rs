//! Federation: two real servers (a.test and b.test) talking over localhost.

use std::time::Duration;

use quark_testkit::quark_core::xml::{stream_header, StreamEvent, StreamReader};
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{message, presence, Client, Options, TestCa, TestServer};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

const A: &str = "a.test";
const B: &str = "b.test";
/// Dialback secret configured on a.test, so raw tests can make its keys.
const A_SECRET: &str = "a-test-dialback-secret";

fn opts(domain: &str, extra: &str) -> Options {
    Options { domain: Some(domain.into()), extra_config: extra.into(), ..Default::default() }
}

/// a.test and b.test with self-signed certificates, routed to each other (dialback over TLS).
async fn pair_with(a_extra: &str, b_extra: &str) -> anyhow::Result<(TestServer, TestServer)> {
    let a = TestServer::start_with(opts(A, &format!("[s2s]\ndialback_secret = \"{A_SECRET}\"\n{a_extra}"))).await?;
    let b = TestServer::start_with(opts(B, &format!("[s2s]\n{b_extra}"))).await?;
    federate(&a, &b)?;
    Ok((a, b))
}

async fn pair() -> anyhow::Result<(TestServer, TestServer)> {
    pair_with("", "").await
}

fn federate(a: &TestServer, b: &TestServer) -> anyhow::Result<()> {
    a.route(b.domain(), &b.s2s().to_string())?;
    b.route(a.domain(), &a.s2s().to_string())
}

/// alice@a.test and bob@b.test, online.
async fn people(a: &TestServer, b: &TestServer) -> anyhow::Result<(Client, Client)> {
    a.add_user("alice", "password-a").await?;
    b.add_user("bob", "password-b").await?;
    let mut alice = a.online("alice", "password-a", "phone").await?;
    let mut bob = b.online("bob", "password-b", "laptop").await?;
    // Ask for the roster at the account itself, so roster pushes come.
    alice.iq_get(Some("alice@a.test"), Element::new("query", ns::ROSTER)).await?;
    bob.iq_get(Some("bob@b.test"), Element::new("query", ns::ROSTER)).await?;
    Ok((alice, bob))
}

fn body(e: &Element) -> Option<String> {
    e.child_text("body", ns::CLIENT)
}

fn error_condition(e: &Element) -> Option<String> {
    let err = e.get_child("error", ns::CLIENT)?;
    err.children().find(|c| c.ns() == ns::STANZAS && c.name() != "text").map(|c| c.name().to_string())
}

fn is_message(e: &Element) -> bool {
    e.name() == "message"
}

#[tokio::test]
async fn messages_cross_between_servers_with_dialback() -> anyhow::Result<()> {
    let (a, b) = pair().await?;
    let (mut alice, mut bob) = people(&a, &b).await?;

    alice.send(&message("bob@b.test", "chat", "hello from a")).await?;
    let got = bob.expect(is_message).await?;
    assert_eq!(body(&got).as_deref(), Some("hello from a"));
    assert_eq!(got.attr("from"), Some("alice@a.test/phone"));
    assert_eq!(got.attr("to"), Some("bob@b.test/laptop"));

    bob.send(&message("alice@a.test/phone", "chat", "hello back")).await?;
    let got = alice.expect(is_message).await?;
    assert_eq!(body(&got).as_deref(), Some("hello back"));
    assert_eq!(got.attr("from"), Some("bob@b.test/laptop"));

    let out = a.srv.remote().unwrap().links();
    let link = out.iter().find(|l| l.direction == "out" && l.remote == B).expect("a.test has a link to b.test");
    assert_eq!(link.auth, "dialback", "self-signed certificates aren't trusted, so dialback proves the domain");
    assert!(link.secure);
    assert!(link.sm, "both sides speak stream management");
    assert!(b.srv.remote().unwrap().links().iter().any(|l| l.direction == "in" && l.remote == A));
    assert_eq!(a.srv.remote().unwrap().counts(), (1, 1));
    Ok(())
}

#[tokio::test]
async fn a_burst_of_messages_arrives_in_order() -> anyhow::Result<()> {
    let (a, b) = pair().await?;
    let (mut alice, mut bob) = people(&a, &b).await?;
    for i in 0..50 {
        alice.send(&message("bob@b.test", "chat", &format!("m{i}"))).await?;
    }
    for i in 0..50 {
        let got = bob.expect(is_message).await?;
        assert_eq!(body(&got), Some(format!("m{i}")));
    }
    Ok(())
}

#[tokio::test]
async fn presence_subscriptions_work_across_servers() -> anyhow::Result<()> {
    let (a, b) = pair().await?;
    let (mut alice, mut bob) = people(&a, &b).await?;

    alice.send(&presence(Some("bob@b.test"), Some("subscribe"))).await?;
    let req = bob.expect(|e| e.name() == "presence" && e.attr("type") == Some("subscribe")).await?;
    assert_eq!(req.attr("from"), Some("alice@a.test"));

    bob.send(&presence(Some("alice@a.test"), Some("subscribed"))).await?;
    let ok = alice.expect(|e| e.name() == "presence" && e.attr("type") == Some("subscribed")).await?;
    assert_eq!(ok.attr("from"), Some("bob@b.test"));
    // Approval sends bob's current presence along.
    let p = alice.expect(|e| e.name() == "presence" && e.attr("type").is_none()).await?;
    assert_eq!(p.attr("from"), Some("bob@b.test/laptop"));
    // Alice's roster now shows she sees bob.
    let item = |e: &Element| e.get_child("query", ns::ROSTER).and_then(|q| q.get_child("item", ns::ROSTER)).cloned();
    let push = alice.expect(|e| item(e).is_some_and(|i| i.attr("subscription") == Some("to"))).await?;
    assert_eq!(item(&push).and_then(|i| i.attr("jid").map(String::from)).as_deref(), Some("bob@b.test"));

    // Bob changing his presence now reaches alice.
    bob.send(&Element::new("presence", ns::CLIENT).text_child("status", ns::CLIENT, "busy")).await?;
    let p = alice.expect(|e| e.name() == "presence" && e.has_child("status", ns::CLIENT)).await?;
    assert_eq!(p.child_text("status", ns::CLIENT).as_deref(), Some("busy"));
    Ok(())
}

#[tokio::test]
async fn iqs_round_trip_between_servers() -> anyhow::Result<()> {
    let (a, b) = pair().await?;
    let (mut alice, mut bob) = people(&a, &b).await?;

    // To the other server itself.
    let pong = alice.iq_get(Some(B), Element::new("ping", ns::PING)).await?;
    assert_eq!(pong.attr("type"), Some("result"));
    assert_eq!(pong.attr("from"), Some(B));
    let info = alice.iq_get(Some(B), Element::new("query", ns::DISCO_INFO)).await?;
    assert_eq!(info.attr("type"), Some("result"));

    // To a person there, answered by their client.
    let id = "q1";
    let iq = quark_testkit::quark_core::stanza::iq("get", id, None, Some("bob@b.test/laptop"), Element::new("query", ns::VERSION));
    alice.send(&iq).await?;
    let asked = bob.expect(|e| e.name() == "iq" && e.attr("id") == Some(id)).await?;
    assert_eq!(asked.attr("from"), Some("alice@a.test/phone"));
    bob.answer(&asked).await?;
    let answer = alice.expect(|e| e.name() == "iq" && e.attr("id") == Some(id)).await?;
    assert_eq!(answer.attr("type"), Some("result"));
    assert_eq!(answer.attr("from"), Some("bob@b.test/laptop"));

    // An IQ to someone who isn't online gets an error from their server.
    let r = alice.iq_get(Some("nobody@b.test/x"), Element::new("ping", ns::PING)).await?;
    assert_eq!(r.attr("type"), Some("error"));
    Ok(())
}

#[tokio::test]
async fn unreachable_servers_bounce_and_are_remembered() -> anyhow::Result<()> {
    let a = TestServer::start_with(opts(A, "")).await?;
    // A port nothing listens on.
    let closed = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    a.route("down.test", &closed.to_string())?;
    a.add_user("alice", "password-a").await?;
    let mut alice = a.online("alice", "password-a", "phone").await?;

    alice.send(&message("bob@down.test", "chat", "anyone?")).await?;
    let err = alice.expect(|e| is_message(e) && e.attr("type") == Some("error")).await?;
    assert_eq!(error_condition(&err).as_deref(), Some("remote-server-not-found"));
    assert_eq!(err.attr("from"), Some("bob@down.test"));
    assert_eq!(body(&err).as_deref(), Some("anyone?"));

    // The second one fails at once, without trying again.
    let started = std::time::Instant::now();
    let r = alice.iq_get(Some("down.test"), Element::new("ping", ns::PING)).await?;
    assert_eq!(r.attr("type"), Some("error"));
    assert_eq!(error_condition(&r).as_deref(), Some("remote-server-not-found"));
    assert!(started.elapsed() < Duration::from_secs(1));

    // Reserved names aren't even looked up.
    alice.send(&message("x@nowhere.invalid", "chat", "hi")).await?;
    let err = alice.expect(|e| is_message(e) && e.attr("type") == Some("error")).await?;
    assert_eq!(error_condition(&err).as_deref(), Some("remote-server-not-found"));
    assert_eq!(a.srv.remote().unwrap().counts(), (0, 0));
    Ok(())
}

#[tokio::test]
async fn a_server_that_never_answers_times_out() -> anyhow::Result<()> {
    // Accepts TCP but never says a word.
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = silent.local_addr()?;
    let hold = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = silent.accept().await {
            held.push(s);
        }
    });
    let a = TestServer::start_with(opts(A, "[s2s]\ntimeout_secs = 2\n")).await?;
    a.route("slow.test", &addr.to_string())?;
    a.add_user("alice", "password-a").await?;
    let mut alice = a.online("alice", "password-a", "phone").await?;
    alice.send(&message("bob@slow.test", "chat", "hello?")).await?;
    // The stanza waits in the queue while the link tries; it bounces once the host times out.
    alice.expect_silence(Duration::from_millis(500)).await?;
    let mut err = None;
    for _ in 0..10 {
        if let Some(e) = alice.recv_within(Duration::from_secs(1)).await? {
            err = Some(e);
            break;
        }
    }
    let err = err.expect("a bounce after the timeout");
    assert_eq!(error_condition(&err).as_deref(), Some("remote-server-timeout"));
    hold.abort();
    Ok(())
}

#[tokio::test]
async fn blocked_domains_are_refused_both_ways() -> anyhow::Result<()> {
    let (a, b) = pair_with("", "blocked = [\"a.test\"]").await?;
    let (mut alice, mut bob) = people(&a, &b).await?;

    // b.test refuses a.test's stream, so alice's message bounces.
    alice.send(&message("bob@b.test", "chat", "let me in")).await?;
    let err = alice.expect(|e| is_message(e) && e.attr("type") == Some("error")).await?;
    assert_eq!(error_condition(&err).as_deref(), Some("remote-server-not-found"));

    // And b.test won't send there either.
    bob.send(&message("alice@a.test", "chat", "no")).await?;
    let err = bob.expect(|e| is_message(e) && e.attr("type") == Some("error")).await?;
    assert_eq!(error_condition(&err).as_deref(), Some("remote-server-not-found"));
    assert_eq!(b.srv.remote().unwrap().counts(), (0, 0));
    Ok(())
}

#[tokio::test]
async fn idle_links_close_and_come_back() -> anyhow::Result<()> {
    let (a, b) = pair_with("idle_secs = 1", "idle_secs = 1").await?;
    let (mut alice, mut bob) = people(&a, &b).await?;
    alice.send(&message("bob@b.test", "chat", "first")).await?;
    assert_eq!(body(&bob.expect(is_message).await?).as_deref(), Some("first"));
    assert_eq!(a.srv.remote().unwrap().counts().1, 1);

    let mut closed = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if a.srv.remote().unwrap().counts() == (0, 0) && b.srv.remote().unwrap().counts() == (0, 0) {
            closed = true;
            break;
        }
    }
    assert!(closed, "idle links close on both sides");

    alice.send(&message("bob@b.test", "chat", "second")).await?;
    assert_eq!(body(&bob.expect(is_message).await?).as_deref(), Some("second"));
    Ok(())
}

#[tokio::test]
async fn trusted_certificates_sign_in_with_sasl_external() -> anyhow::Result<()> {
    let ca = TestCa::new()?;
    let dir = tempfile::tempdir()?;
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, ca.pem())?;
    // Dialback off: only certificates can work.
    let extra = format!("[s2s]\ndialback = false\ntrusted_certs = [{ca_path:?}]\n");
    let a = TestServer::start_with(Options { certs: vec![ca.issue(A)?], ..opts(A, &extra) }).await?;
    let b = TestServer::start_with(Options { certs: vec![ca.issue(B)?], ..opts(B, &extra) }).await?;
    federate(&a, &b)?;
    let (mut alice, mut bob) = people(&a, &b).await?;

    alice.send(&message("bob@b.test", "chat", "signed")).await?;
    assert_eq!(body(&bob.expect(is_message).await?).as_deref(), Some("signed"));
    bob.send(&message("alice@a.test", "chat", "sealed")).await?;
    assert_eq!(body(&alice.expect(is_message).await?).as_deref(), Some("sealed"));

    let links = a.srv.remote().unwrap().links();
    assert!(links.iter().any(|l| l.direction == "out" && l.remote == B && l.auth == "certificate"));
    assert!(links.iter().any(|l| l.direction == "in" && l.remote == B && l.auth == "certificate"));
    Ok(())
}

#[tokio::test]
async fn untrusted_certificates_fail_when_dialback_is_off() -> anyhow::Result<()> {
    let (a, b) = pair_with("dialback = false", "").await?;
    let (mut alice, _bob) = people(&a, &b).await?;
    alice.send(&message("bob@b.test", "chat", "hi")).await?;
    let err = alice.expect(|e| is_message(e) && e.attr("type") == Some("error")).await?;
    assert_eq!(error_condition(&err).as_deref(), Some("remote-server-not-found"));
    Ok(())
}

#[tokio::test]
async fn direct_tls_links_work() -> anyhow::Result<()> {
    let a = TestServer::start_with(Options { s2s_tls: true, ..opts(A, "") }).await?;
    let b = TestServer::start_with(Options { s2s_tls: true, ..opts(B, "") }).await?;
    a.route(B, &format!("tls://{}", b.s2s_tls().unwrap()))?;
    b.route(A, &format!("tls://{}", a.s2s_tls().unwrap()))?;
    let (mut alice, mut bob) = people(&a, &b).await?;
    alice.send(&message("bob@b.test", "chat", "straight to TLS")).await?;
    assert_eq!(body(&bob.expect(is_message).await?).as_deref(), Some("straight to TLS"));
    Ok(())
}

#[tokio::test]
async fn federation_off_for_a_domain_bounces() -> anyhow::Result<()> {
    let (a, b) = pair().await?;
    a.set_settings(|s| s.federation = false).await?;
    let (mut alice, _bob) = people(&a, &b).await?;
    alice.send(&message("bob@b.test", "chat", "hi")).await?;
    let err = alice.expect(|e| is_message(e) && e.attr("type") == Some("error")).await?;
    assert_eq!(error_condition(&err).as_deref(), Some("remote-server-not-found"));
    Ok(())
}

// ------------------------------------------------------------------------- raw streams

/// A hand-driven server-to-server stream, to test what a misbehaving server gets.
struct Raw {
    reader: StreamReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl Raw {
    async fn connect(addr: std::net::SocketAddr) -> anyhow::Result<Raw> {
        let tcp = TcpStream::connect(addr).await?;
        let (r, w) = tcp.into_split();
        let mut reader = StreamReader::new(r, 1 << 20);
        reader.server_ns = true;
        Ok(Raw { reader, writer: w })
    }

    /// Opens a stream from `from` to `to`; returns the stream id and features.
    async fn open(&mut self, from: &str, to: &str) -> anyhow::Result<(String, Option<Element>)> {
        self.send_raw(&stream_header(ns::SERVER, Some(from), Some(to), None, &[("xmlns:db", ns::DIALBACK)])).await?;
        let id = match self.next().await? {
            StreamEvent::Open { attrs, .. } => StreamEvent::open_attr(&attrs, "id").unwrap_or_default().to_string(),
            e => anyhow::bail!("expected a header, got {e:?}"),
        };
        let f = match self.next().await? {
            StreamEvent::Stanza(f) if f.is("features", ns::STREAM) => Some(f),
            StreamEvent::Stanza(e) => return Ok((id, Some(e))),
            e => anyhow::bail!("expected features, got {e:?}"),
        };
        Ok((id, f))
    }

    async fn send_raw(&mut self, s: &str) -> anyhow::Result<()> {
        self.writer.write_all(s.as_bytes()).await?;
        Ok(())
    }

    async fn send(&mut self, el: &Element) -> anyhow::Result<()> {
        self.send_raw(&el.to_stream_xml(ns::SERVER)).await
    }

    async fn next(&mut self) -> anyhow::Result<StreamEvent> {
        match tokio::time::timeout(Duration::from_secs(5), self.reader.next()).await {
            Err(_) => anyhow::bail!("timed out"),
            Ok(Err(e)) => anyhow::bail!("read error: {e}"),
            Ok(Ok(None)) => anyhow::bail!("connection closed"),
            Ok(Ok(Some(ev))) => Ok(ev),
        }
    }

    async fn recv(&mut self) -> anyhow::Result<Element> {
        match self.next().await? {
            StreamEvent::Stanza(e) => Ok(e),
            e => anyhow::bail!("expected an element, got {e:?}"),
        }
    }

    /// The condition of the stream error the server ends the stream with.
    async fn stream_error(&mut self) -> anyhow::Result<String> {
        loop {
            let e = self.recv().await?;
            if e.is("error", ns::STREAM) {
                let c = e.children().find(|c| c.ns() == ns::STREAMS && c.name() != "text").map(|c| c.name().to_string());
                return Ok(c.unwrap_or_default());
            }
        }
    }

    /// Proves a.test to b.test with dialback (a.test's key, checked by calling a.test back).
    async fn dialback_as_a(&mut self, b: &TestServer) -> anyhow::Result<()> {
        let (id, _) = self.open(A, b.domain()).await?;
        let key = quark::s2s::dialback::key(A_SECRET.as_bytes(), b.domain(), A, &id);
        self.send(&quark::s2s::dialback::element("result", A, b.domain()).text(key)).await?;
        let r = self.recv().await?;
        anyhow::ensure!(r.is("result", ns::DIALBACK) && r.attr("type") == Some("valid"), "dialback failed: {r}");
        Ok(())
    }
}

/// a.test (which raw streams pretend to be) and b.test without TLS, so raw streams stay plain.
async fn plain_pair(b_extra: &str) -> anyhow::Result<(TestServer, TestServer)> {
    pair_with("require_tls = false", &format!("require_tls = false\n{b_extra}")).await
}

#[tokio::test]
async fn encryption_is_required_before_dialback() -> anyhow::Result<()> {
    let (_a, b) = pair().await?;
    let mut raw = Raw::connect(b.s2s()).await?;
    let (_, features) = raw.open(A, B).await?;
    let f = features.expect("features");
    assert!(f.get_child("starttls", ns::TLS).is_some_and(|t| t.has_child("required", ns::TLS)));
    assert!(!f.has_child("dialback", ns::DIALBACK_FEATURE), "dialback is only offered after TLS");
    raw.send(&quark::s2s::dialback::element("result", A, B).text("abc")).await?;
    assert_eq!(raw.stream_error().await?, "policy-violation");
    Ok(())
}

#[tokio::test]
async fn unknown_hosts_and_blocked_senders_are_refused_at_the_header() -> anyhow::Result<()> {
    let (_a, b) = plain_pair("blocked = [\"spam.test\"]").await?;
    let mut raw = Raw::connect(b.s2s()).await?;
    raw.send_raw(&stream_header(ns::SERVER, Some(A), Some("elsewhere.test"), None, &[])).await?;
    assert!(matches!(raw.next().await?, StreamEvent::Open { .. }));
    assert_eq!(raw.stream_error().await?, "host-unknown");

    let mut raw = Raw::connect(b.s2s()).await?;
    let (_, first) = raw.open("muc.spam.test", B).await?;
    let e = first.expect("an error");
    assert!(e.is("error", ns::STREAM) && e.has_child("policy-violation", ns::STREAMS), "{e}");
    Ok(())
}

#[tokio::test]
async fn stanzas_must_come_from_the_proven_domain_and_go_to_ours() -> anyhow::Result<()> {
    let (_a, b) = plain_pair("").await?;
    b.add_user("bob", "password-b").await?;
    let mut bob = b.online("bob", "password-b", "laptop").await?;

    // Unauthenticated: not allowed to send anything.
    let mut raw = Raw::connect(b.s2s()).await?;
    raw.open(A, B).await?;
    raw.send(&message("bob@b.test", "chat", "sneaky").attr_set("from", "x@a.test")).await?;
    assert_eq!(raw.stream_error().await?, "not-authorized");

    // Authenticated as a.test: a.test senders are fine…
    let mut raw = Raw::connect(b.s2s()).await?;
    raw.dialback_as_a(&b).await?;
    raw.send(&message("bob@b.test", "chat", "legit").attr_set("from", "x@a.test/r")).await?;
    let got = bob.expect(is_message).await?;
    assert_eq!(got.attr("from"), Some("x@a.test/r"));
    // …but another domain isn't.
    raw.send(&message("bob@b.test", "chat", "spoofed").attr_set("from", "x@c.test")).await?;
    assert_eq!(raw.stream_error().await?, "invalid-from");
    bob.expect_silence(Duration::from_millis(200)).await?;

    // Stanzas for domains b.test doesn't serve end the stream.
    let mut raw = Raw::connect(b.s2s()).await?;
    raw.dialback_as_a(&b).await?;
    raw.send(&message("someone@c.test", "chat", "relay this").attr_set("from", "x@a.test")).await?;
    assert_eq!(raw.stream_error().await?, "host-unknown");
    Ok(())
}

#[tokio::test]
async fn wrong_dialback_keys_are_refused() -> anyhow::Result<()> {
    let (_a, b) = plain_pair("").await?;
    let mut raw = Raw::connect(b.s2s()).await?;
    raw.open(A, B).await?;
    raw.send(&quark::s2s::dialback::element("result", A, B).text("0123456789abcdef")).await?;
    let r = raw.recv().await?;
    assert!(r.is("result", ns::DIALBACK));
    assert_eq!(r.attr("type"), Some("invalid"));
    // Still not allowed to send.
    raw.send(&message("bob@b.test", "chat", "hi").attr_set("from", "x@a.test")).await?;
    assert_eq!(raw.stream_error().await?, "not-authorized");
    Ok(())
}

#[tokio::test]
async fn the_authoritative_server_answers_db_verify() -> anyhow::Result<()> {
    let (a, _b) = plain_pair("").await?;
    let mut raw = Raw::connect(a.s2s()).await?;
    raw.open(B, A).await?;
    let key = quark::s2s::dialback::key(A_SECRET.as_bytes(), B, A, "stream-1");
    let q = |key: &str, id: &str| quark::s2s::dialback::element("verify", B, A).attr_set("id", id).text(key);
    raw.send(&q(&key, "stream-1")).await?;
    let r = raw.recv().await?;
    assert_eq!((r.attr("type"), r.attr("id"), r.attr("from")), (Some("valid"), Some("stream-1"), Some(A)));
    raw.send(&q(&key, "stream-2")).await?;
    assert_eq!(raw.recv().await?.attr("type"), Some("invalid"));
    Ok(())
}

#[tokio::test]
async fn oversized_stanzas_end_the_stream() -> anyhow::Result<()> {
    let (_a, b) = pair_with("require_tls = false", "require_tls = false\n\n[limits]\ns2s_stanza_bytes = 4096").await?;
    let mut raw = Raw::connect(b.s2s()).await?;
    raw.dialback_as_a(&b).await?;
    raw.send(&message("bob@b.test", "chat", &"x".repeat(64 * 1024)).attr_set("from", "x@a.test")).await?;
    assert_eq!(raw.stream_error().await?, "policy-violation");
    Ok(())
}

#[tokio::test]
async fn stream_management_acks_stanzas() -> anyhow::Result<()> {
    let (_a, b) = plain_pair("").await?;
    b.add_user("bob", "password-b").await?;
    let mut raw = Raw::connect(b.s2s()).await?;
    raw.dialback_as_a(&b).await?;
    raw.send(&Element::new("enable", ns::SM)).await?;
    assert!(raw.recv().await?.is("enabled", ns::SM));
    for i in 0..3 {
        raw.send(&message("bob@b.test", "chat", &format!("{i}")).attr_set("from", "x@a.test")).await?;
    }
    raw.send(&Element::new("r", ns::SM)).await?;
    let a = raw.recv().await?;
    assert!(a.is("a", ns::SM));
    assert_eq!(a.attr("h"), Some("3"));
    Ok(())
}

/// Plays a receiving server for b.test that believes any dialback key and turns stream
/// management on; returns the messages the link sent before asking for an ack.
async fn fake_b_session(listener: &tokio::net::TcpListener, ack: bool) -> anyhow::Result<Vec<Element>> {
    let (tcp, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await??;
    let (r, w) = tcp.into_split();
    let mut raw = Raw { reader: StreamReader::new(r, 1 << 20), writer: w };
    raw.reader.server_ns = true;
    assert!(matches!(raw.next().await?, StreamEvent::Open { .. }));
    raw.send_raw(&stream_header(ns::SERVER, Some(B), Some(A), Some("fake-1"), &[("xmlns:db", ns::DIALBACK)])).await?;
    let features =
        Element::new("features", ns::STREAM).child(Element::new("dialback", ns::DIALBACK_FEATURE)).child(Element::new("sm", ns::SM));
    raw.send(&features).await?;
    let mut got = Vec::new();
    loop {
        let e = raw.recv().await?;
        if e.is("result", ns::DIALBACK) {
            raw.send_raw("<db:result from='b.test' to='a.test' type='valid'/>").await?;
        } else if e.is("enable", ns::SM) {
            raw.send(&Element::new("enabled", ns::SM)).await?;
        } else if e.is("r", ns::SM) {
            if ack {
                raw.send(&Element::new("a", ns::SM).attr_set("h", got.len().to_string())).await?;
            }
            return Ok(got);
        } else if e.name() == "message" {
            got.push(e);
        }
    }
}

#[tokio::test]
async fn unacknowledged_stanzas_go_out_again_on_a_new_link() -> anyhow::Result<()> {
    let fake = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let a = TestServer::start_with(opts(A, "[s2s]\nrequire_tls = false\n")).await?;
    a.route(B, &fake.local_addr()?.to_string())?;
    a.add_user("alice", "password-a").await?;
    let mut alice = a.online("alice", "password-a", "phone").await?;

    alice.send(&message("bob@b.test", "chat", "don't lose me")).await?;
    // The first link takes the message and drops without confirming it…
    let first = fake_b_session(&fake, false).await?;
    assert_eq!(first.len(), 1);
    // …so a new link sends it again, and this time it's confirmed.
    let second = fake_b_session(&fake, true).await?;
    assert_eq!(second.len(), 1);
    assert_eq!(body(&second[0]).as_deref(), Some("don't lose me"));
    alice.expect_silence(Duration::from_millis(300)).await?;
    Ok(())
}
