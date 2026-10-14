//! BOSH (XEP-0124 / XEP-0206): sessions, rid ordering, holding requests, restart, terminate.

use std::time::{Duration, Instant};

use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{http_request, message, BoshClient, TestServer, VIA_TLS_PROXY};

fn body_of(r: &quark_testkit::HttpResponse) -> anyhow::Result<Element> {
    Ok(Element::parse(&r.text())?)
}

#[tokio::test]
async fn session_creation_reports_its_parameters_and_features() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let c = BoshClient::connect(s.web(), s.domain()).await?;
    let b = &c.session;
    assert!(b.is("body", ns::BOSH));
    assert_eq!(b.attr("wait"), Some("5"));
    assert_eq!(b.attr("hold"), Some("1"));
    assert_eq!(b.attr("requests"), Some("2"));
    assert_eq!(b.attr("from"), Some(s.domain()));
    assert_eq!(b.attr_ns(ns::XBOSH, "version"), Some("1.0"));
    assert_eq!(b.attr_ns(ns::XBOSH, "restartlogic"), Some("true"));
    assert!(b.attr("authid").is_some_and(|a| !a.is_empty()));
    assert!(b.attr("inactivity").is_some());
    let f = c.features.clone().expect("features in the creation response");
    assert!(f.has_child("mechanisms", ns::SASL));
    assert!(!f.has_child("starttls", ns::TLS));
    Ok(())
}

#[tokio::test]
async fn bosh_client_signs_in_and_talks_to_a_tcp_client() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    s.add_user("bob", "password-b").await?;
    let mut bob = s.online("bob", "password-b", "laptop").await?;
    let mut alice = s.bosh_login("alice", "password-a", "old-web").await?;
    assert_eq!(alice.jid.as_deref(), Some("alice@quark.test/old-web"));
    let session = s.srv.sessions.of(&"alice@quark.test".parse()?).into_iter().next().unwrap();
    assert_eq!(session.info.transport, "bosh");

    alice.request(&[], &[message("bob@quark.test", "chat", "hi over bosh")]).await?;
    let got = bob.expect(|e| e.name() == "message").await?;
    assert_eq!(got.child_text("body", ns::CLIENT).as_deref(), Some("hi over bosh"));
    assert_eq!(got.attr("from"), Some("alice@quark.test/old-web"));

    // A held request returns as soon as something arrives, well before `wait`.
    let addr = alice.addr();
    let body = alice.body(&[], &[]);
    let started = Instant::now();
    let poll = tokio::spawn(async move { BoshClient::post(addr, &body).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    bob.send(&message("alice@quark.test/old-web", "chat", "hello back")).await?;
    let r = poll.await??;
    assert!(started.elapsed() < Duration::from_secs(4), "the held request answered late");
    let m = r.get_child("message", ns::CLIENT).expect("the message in the held response");
    assert_eq!(m.child_text("body", ns::CLIENT).as_deref(), Some("hello back"));

    let bye = alice.request(&[("type", "terminate")], &[Element::new("presence", ns::CLIENT).attr_set("type", "unavailable")]).await?;
    assert_eq!(bye.attr("type"), Some("terminate"));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!s.srv.sessions.is_online(&"alice@quark.test".parse()?));
    let after = alice.request(&[], &[]).await?;
    assert_eq!(after.attr("type"), Some("terminate"));
    assert_eq!(after.attr("condition"), Some("item-not-found"));
    Ok(())
}

#[tokio::test]
async fn requests_are_processed_in_rid_order() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    s.add_user("bob", "password-b").await?;
    let mut bob = s.online("bob", "password-b", "laptop").await?;
    let mut alice = s.bosh_login("alice", "password-a", "web").await?;
    let first = alice.body(&[], &[message("bob@quark.test", "chat", "one")]);
    let second = alice.body(&[], &[message("bob@quark.test", "chat", "two")]);
    let addr = alice.addr();
    // The later rid arrives first and waits for the earlier one.
    let late = tokio::spawn(async move { BoshClient::post(addr, &second).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    BoshClient::post(addr, &first).await?;
    late.await??;
    let a = bob.expect(|e| e.name() == "message").await?;
    let b = bob.expect(|e| e.name() == "message").await?;
    assert_eq!(a.child_text("body", ns::CLIENT).as_deref(), Some("one"));
    assert_eq!(b.child_text("body", ns::CLIENT).as_deref(), Some("two"));
    Ok(())
}

#[tokio::test]
async fn a_new_request_releases_the_held_one() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    let mut alice = s.bosh_login("alice", "password-a", "web").await?;
    let addr = alice.addr();
    let held = alice.body(&[], &[]);
    let started = Instant::now();
    let h = tokio::spawn(async move { BoshClient::post(addr, &held).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let next = alice.body(&[], &[]);
    let n = tokio::spawn(async move { BoshClient::post(addr, &next).await });
    let r = h.await??;
    assert!(started.elapsed() < Duration::from_secs(3), "hold=1 lets only one request wait");
    assert!(r.attr("type").is_none());
    n.abort();
    Ok(())
}

#[tokio::test]
async fn a_resent_request_gets_the_same_answer() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    let mut alice = s.bosh_login("alice", "password-a", "web").await?;
    let id = "ping-1";
    let ping = quark_testkit::quark_core::stanza::iq("get", id, None, Some(s.domain()), Element::new("ping", ns::PING));
    let body = alice.body(&[], &[ping]);
    let first = BoshClient::post(alice.addr(), &body).await?;
    assert!(first.children().any(|c| c.attr("id") == Some(id)), "{first}");
    let again = BoshClient::post(alice.addr(), &body).await?;
    assert_eq!(again, first);
    Ok(())
}

#[tokio::test]
async fn bad_requests_get_terminate_conditions() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let post = |body: &'static str| http_request(s.web(), "POST", "/http-bind", &[VIA_TLS_PROXY], body.as_bytes());
    let r = body_of(&post("<body xmlns='http://jabber.org/protocol/httpbind' rid='1' sid='nope'/>").await?)?;
    assert_eq!((r.attr("type"), r.attr("condition")), (Some("terminate"), Some("item-not-found")));
    let r = body_of(&post("not xml at all").await?)?;
    assert_eq!(r.attr("condition"), Some("bad-request"));
    let r = body_of(&post("<body xmlns='http://jabber.org/protocol/httpbind' to='quark.test'/>").await?)?;
    assert_eq!(r.attr("condition"), Some("bad-request"));
    let r = body_of(&post("<body xmlns='http://jabber.org/protocol/httpbind' rid='5' to='elsewhere.test' xmlns:xmpp='urn:xmpp:xbosh' xmpp:version='1.0'/>").await?)?;
    assert_eq!(r.attr("condition"), Some("host-unknown"));

    let mut c = BoshClient::connect(s.web(), s.domain()).await?;
    c.rid += 10;
    let r = c.request(&[], &[]).await?;
    assert_eq!(r.attr("condition"), Some("item-not-found"), "a rid far ahead of the window ends the session");
    Ok(())
}

#[tokio::test]
async fn oversized_bodies_are_refused() -> anyhow::Result<()> {
    let s =
        TestServer::start_with(quark_testkit::Options { extra_config: "[limits]\nc2s_stanza_bytes = 4096\n".into(), ..Default::default() })
            .await?;
    // Refused from the announced length alone, before reading any of it.
    let r = http_request(s.web(), "POST", "/http-bind", &[VIA_TLS_PROXY, ("Content-Length", "200000")], b"").await?;
    assert_eq!(body_of(&r)?.attr("condition"), Some("policy-violation"));
    Ok(())
}

#[tokio::test]
async fn bosh_preflight_allows_cross_origin_clients() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let r = http_request(
        s.web(),
        "OPTIONS",
        "/http-bind",
        &[("Origin", "https://app.example"), ("Access-Control-Request-Method", "POST")],
        b"",
    )
    .await?;
    assert_eq!(r.status, 204);
    assert_eq!(r.header("access-control-allow-origin"), Some("*"));
    assert!(r.header("access-control-allow-methods").is_some_and(|m| m.contains("POST")));
    Ok(())
}

#[tokio::test]
async fn a_resent_request_takes_over_from_the_one_still_held() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    s.add_user("bob", "password-b").await?;
    let mut bob = s.online("bob", "password-b", "laptop").await?;
    let mut alice = s.bosh_login("alice", "password-a", "web").await?;
    let addr = alice.addr();
    let body = alice.body(&[], &[]);
    let original = {
        let body = body.clone();
        tokio::spawn(async move { BoshClient::post(addr, &body).await })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The client thinks the original's connection died and sends the same rid again.
    let started = Instant::now();
    let resent = tokio::spawn(async move { BoshClient::post(addr, &body).await });
    let o = original.await??;
    assert!(started.elapsed() < Duration::from_secs(3), "the original is answered (empty) right away");
    assert_eq!(o.children().count(), 0, "{o}");
    bob.send(&message("alice@quark.test/web", "chat", "after the resend")).await?;
    let r = resent.await??;
    let m = r.get_child("message", ns::CLIENT).expect("the resend waits for the output");
    assert_eq!(m.child_text("body", ns::CLIENT).as_deref(), Some("after the resend"));
    Ok(())
}

/// The `quark_bosh_sessions` gauge.
async fn open_sessions(s: &TestServer) -> anyhow::Result<u64> {
    let t = http_request(s.web(), "GET", "/metrics", &[], b"").await?.text();
    let line = t.lines().find(|l| l.starts_with("quark_bosh_sessions ")).expect("the gauge");
    Ok(line.rsplit(' ').next().unwrap_or_default().parse()?)
}

#[tokio::test]
async fn a_session_whose_held_request_was_dropped_is_still_reaped() -> anyhow::Result<()> {
    // Sign-ins time out after a second, which ends the session.
    let s =
        TestServer::start_with(quark_testkit::Options { extra_config: "[limits]\nauth_timeout_secs = 1\n".into(), ..Default::default() })
            .await?;
    let mut c = BoshClient::connect(s.web(), s.domain()).await?;
    // A held request whose client goes away before the answer.
    let body = c.body(&[], &[]);
    let mut tcp = tokio::net::TcpStream::connect(s.web()).await?;
    let req = format!(
        "POST /http-bind HTTP/1.1\r\nHost: quark.test\r\nX-Forwarded-Proto: https\r\nContent-Type: text/xml\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    tokio::io::AsyncWriteExt::write_all(&mut tcp, req.as_bytes()).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(tcp);
    assert_eq!(open_sessions(&s).await?, 1);
    let deadline = Instant::now() + Duration::from_secs(20);
    while open_sessions(&s).await? > 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(open_sessions(&s).await?, 0, "the ended session was forgotten");
    Ok(())
}

#[tokio::test]
async fn web_clients_off_refuses_bosh_sessions() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.set_settings(|st| st.web = false).await?;
    assert!(BoshClient::connect(s.web(), s.domain()).await.is_err());
    Ok(())
}
