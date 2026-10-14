//! XMPP over WebSocket (RFC 7395): framing, sign-in, talking to TCP clients, limits.

use std::time::Duration;

use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{http_request, message, Options, TestServer, WsClient, VIA_TLS_PROXY};

#[tokio::test]
async fn websocket_client_signs_in_and_talks_to_a_tcp_client() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    s.add_user("bob", "password-b").await?;
    let mut bob = s.online("bob", "password-b", "laptop").await?;

    let mut alice = WsClient::connect(s.web(), s.domain(), &[VIA_TLS_PROXY]).await?;
    assert_eq!(alice.protocol.as_deref(), Some("xmpp"));
    let open = alice.server_open.clone().unwrap();
    assert_eq!(open.attr("from"), Some(s.domain()));
    assert_eq!(open.attr("version"), Some("1.0"));
    assert!(open.attr("id").is_some());
    let features = alice.features.clone().unwrap();
    assert!(!features.has_child("starttls", ns::TLS), "WebSocket never offers STARTTLS");
    assert!(alice.mechanisms().iter().any(|m| m == "SCRAM-SHA-256"));

    alice.auth_scram("SCRAM-SHA-256", "alice", "password-a").await?;
    assert!(alice.features.as_ref().unwrap().has_child("bind", ns::BIND));
    let jid = alice.bind(Some("web")).await?;
    assert_eq!(jid, "alice@quark.test/web");
    let session = s.srv.sessions.of(&"alice@quark.test".parse()?).into_iter().next().unwrap();
    assert_eq!(session.info.transport, "websocket");
    assert!(session.info.secure);

    alice.send(&message("bob@quark.test", "chat", "hi from the browser")).await?;
    let got = bob.expect(|e| e.name() == "message").await?;
    assert_eq!(got.child_text("body", ns::CLIENT).as_deref(), Some("hi from the browser"));
    assert_eq!(got.attr("from"), Some("alice@quark.test/web"));

    bob.send(&message("alice@quark.test/web", "chat", "hello back")).await?;
    let got = alice.expect(|e| e.name() == "message").await?;
    assert_eq!(got.ns(), ns::CLIENT);
    assert_eq!(got.child_text("body", ns::CLIENT).as_deref(), Some("hello back"));

    let pong = alice.iq("get", Some(s.domain()), Element::new("ping", ns::PING)).await?;
    assert_eq!(pong.attr("type"), Some("result"));
    Ok(())
}

#[tokio::test]
async fn close_is_answered_with_close() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    let mut alice = s.ws_login("alice", "password-a", "web").await?;
    alice.close().await?;
    let rest = alice.expect_closed().await?;
    assert!(rest.iter().any(|e| e.is("close", ns::FRAMING)), "got {rest:?}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!s.srv.sessions.is_online(&"alice@quark.test".parse()?));
    Ok(())
}

#[tokio::test]
async fn plain_http_without_a_tls_proxy_cannot_sign_in() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    let mut c = WsClient::connect(s.web(), s.domain(), &[]).await?;
    c.send(&Element::new("auth", ns::SASL).attr_set("mechanism", "PLAIN").text("AGFsaWNlAHBhc3N3b3JkLWE=")).await?;
    let rest = c.expect_closed().await?;
    let err = rest.iter().find(|e| e.is("error", ns::STREAM)).expect("a stream error");
    assert!(err.has_child("policy-violation", ns::STREAMS));
    Ok(())
}

#[tokio::test]
async fn sign_in_over_plain_websocket_works_when_tls_is_not_required() -> anyhow::Result<()> {
    let s = TestServer::start_with(Options { allow_plain: true, ..Default::default() }).await?;
    s.add_user("alice", "password-a").await?;
    let mut c = WsClient::connect(s.web(), s.domain(), &[]).await?;
    c.auth_scram("SCRAM-SHA-256", "alice", "password-a").await?;
    c.bind(None).await?;
    let session = s.srv.sessions.of(&"alice@quark.test".parse()?).into_iter().next().unwrap();
    assert!(!session.info.secure);
    Ok(())
}

#[tokio::test]
async fn malformed_frames_end_the_stream() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut c = WsClient::connect(s.web(), s.domain(), &[VIA_TLS_PROXY]).await?;
    c.send_raw("<message xmlns='jabber:client'><body>unclosed").await?;
    let rest = c.expect_closed().await?;
    let err = rest.iter().find(|e| e.is("error", ns::STREAM)).expect("a stream error");
    assert!(err.has_child("not-well-formed", ns::STREAMS), "{err}");

    let mut c = WsClient::connect(s.web(), s.domain(), &[VIA_TLS_PROXY]).await?;
    c.send_message(tokio_tungstenite::tungstenite::Message::binary(vec![1, 2, 3])).await?;
    let rest = c.expect_closed().await?;
    assert!(rest.iter().any(|e| e.is("error", ns::STREAM)));
    Ok(())
}

#[tokio::test]
async fn oversized_stanzas_are_a_policy_violation() -> anyhow::Result<()> {
    let s = TestServer::start_with(Options { extra_config: "[limits]\nc2s_stanza_bytes = 4096\n".into(), ..Default::default() }).await?;
    s.add_user("alice", "password-a").await?;
    let mut alice = s.ws_login("alice", "password-a", "web").await?;
    alice.send(&message("bob@quark.test", "chat", &"x".repeat(6000))).await?;
    let rest = alice.expect_closed().await?;
    let err = rest.iter().find(|e| e.is("error", ns::STREAM)).expect("a stream error");
    assert!(err.has_child("policy-violation", ns::STREAMS));
    Ok(())
}

#[tokio::test]
async fn unknown_domain_is_host_unknown() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut c = WsClient::handshake(s.web(), &[VIA_TLS_PROXY]).await?;
    c.send(&Element::new("open", ns::FRAMING).attr_set("to", "elsewhere.test").attr_set("version", "1.0")).await?;
    let rest = c.expect_closed().await?;
    assert!(rest.first().is_some_and(|e| e.is("open", ns::FRAMING)), "the server answers with <open/> first");
    let err = rest.iter().find(|e| e.is("error", ns::STREAM)).expect("a stream error");
    assert!(err.has_child("host-unknown", ns::STREAMS));
    Ok(())
}

#[tokio::test]
async fn web_clients_off_refuses_websockets() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.set_settings(|st| st.web = false).await?;
    assert!(WsClient::handshake(s.web(), &[VIA_TLS_PROXY]).await.is_err());
    let r = http_request(s.web(), "GET", "/xmpp-websocket", &[], b"").await?;
    assert_eq!(r.status, 404);
    Ok(())
}

#[tokio::test]
async fn a_dropped_websocket_session_can_be_resumed() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    s.add_user("bob", "password-b").await?;
    let mut bob = s.online("bob", "password-b", "laptop").await?;

    let mut alice = s.ws_login("alice", "password-a", "web").await?;
    alice.send(&Element::new("enable", ns::SM).attr_set("resume", "true")).await?;
    let enabled = alice.expect(|e| e.is("enabled", ns::SM)).await?;
    let id = enabled.attr("id").unwrap().to_string();
    drop(alice);
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Sent while alice is away: held for her.
    bob.send(&message("alice@quark.test/web", "chat", "while you were gone")).await?;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut again = WsClient::connect(s.web(), s.domain(), &[VIA_TLS_PROXY]).await?;
    again.auth_scram("SCRAM-SHA-256", "alice", "password-a").await?;
    again.send(&Element::new("resume", ns::SM).attr_set("previd", id).attr_set("h", "0")).await?;
    again.expect(|e| e.is("resumed", ns::SM)).await?;
    let got = again.expect(|e| e.name() == "message").await?;
    assert_eq!(got.child_text("body", ns::CLIENT).as_deref(), Some("while you were gone"));
    Ok(())
}
