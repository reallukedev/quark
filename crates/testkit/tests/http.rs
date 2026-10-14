//! The web listener's own pages: host-meta (XEP-0156), health, metrics, the front page.

use std::time::Duration;

use quark_testkit::{http_request, Options, TestServer};

#[tokio::test]
async fn host_meta_advertises_websocket_and_bosh() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let r = http_request(s.web(), "GET", "/.well-known/host-meta", &[], b"").await?;
    assert_eq!(r.status, 200);
    assert!(r.header("content-type").is_some_and(|t| t.starts_with("application/xrd+xml")));
    assert_eq!(r.header("access-control-allow-origin"), Some("*"));
    let x = r.text();
    assert!(x.contains("rel='urn:xmpp:alt-connections:websocket' href='wss://quark.test/xmpp-websocket'"), "{x}");
    assert!(x.contains("rel='urn:xmpp:alt-connections:xbosh' href='https://quark.test/http-bind'"), "{x}");

    let r = http_request(s.web(), "GET", "/.well-known/host-meta.json", &[], b"").await?;
    let j: serde_json::Value = serde_json::from_slice(&r.body)?;
    let links = j["links"].as_array().unwrap();
    assert!(links.iter().any(|l| l["rel"] == "urn:xmpp:alt-connections:websocket" && l["href"] == "wss://quark.test/xmpp-websocket"));
    assert!(links.iter().any(|l| l["rel"] == "urn:xmpp:alt-connections:xbosh"));
    Ok(())
}

#[tokio::test]
async fn host_meta_uses_the_public_url_and_respects_the_web_setting() -> anyhow::Result<()> {
    let s = TestServer::start_with(Options {
        extra_config: "[http]\npublic_url = \"http://chat.example.test:8080/\"\n".into(),
        ..Default::default()
    })
    .await?;
    let x = http_request(s.web(), "GET", "/.well-known/host-meta", &[], b"").await?.text();
    assert!(x.contains("href='ws://chat.example.test:8080/xmpp-websocket'"), "{x}");
    assert!(x.contains("href='http://chat.example.test:8080/http-bind'"), "{x}");
    s.set_settings(|st| st.web = false).await?;
    let x = http_request(s.web(), "GET", "/.well-known/host-meta", &[], b"").await?.text();
    assert!(!x.contains("<Link"), "{x}");
    Ok(())
}

#[tokio::test]
async fn health_and_front_page() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let r = http_request(s.web(), "GET", "/health", &[], b"").await?;
    assert_eq!((r.status, r.text().as_str()), (200, "ok\n"));
    let r = http_request(s.web(), "GET", "/", &[], b"").await?;
    assert_eq!(r.status, 200);
    assert!(r.header("content-type").is_some_and(|t| t.starts_with("text/html")));
    assert!(r.text().contains("<h1>quark.test</h1>"));
    let r = http_request(s.web(), "GET", "/", &[("Host", "<script>.test")], b"").await?;
    assert!(!r.text().contains("<script>"), "the Host header is never echoed");
    assert_eq!(http_request(s.web(), "GET", "/no/such/page", &[], b"").await?.status, 404);
    Ok(())
}

#[tokio::test]
async fn metrics_are_for_local_scrapers_only() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    let _alice = s.online("alice", "password-a", "phone").await?;
    let r = http_request(s.web(), "GET", "/metrics", &[], b"").await?;
    assert_eq!(r.status, 200);
    let t = r.text();
    assert!(t.contains("quark_sessions{transport=\"tcp\"} 1"), "{t}");
    for name in [
        "quark_stanzas_in_total",
        "quark_stanzas_out_total",
        "quark_auth_failures_total",
        "quark_s2s_links",
        "quark_uploads_total",
        "quark_bosh_sessions",
    ] {
        assert!(t.contains(&format!("# TYPE {name} ")), "{name} missing");
    }
    // Through a proxy for someone on the internet: not shown.
    let r = http_request(s.web(), "GET", "/metrics", &[("X-Forwarded-For", "203.0.113.5")], b"").await?;
    assert_eq!(r.status, 404);
    Ok(())
}

#[tokio::test]
async fn metrics_can_be_turned_off() -> anyhow::Result<()> {
    let s = TestServer::start_with(Options { extra_config: "[http]\nmetrics = false\n".into(), ..Default::default() }).await?;
    assert_eq!(http_request(s.web(), "GET", "/metrics", &[], b"").await?.status, 404);
    Ok(())
}

#[tokio::test]
async fn large_bodies_are_refused() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let r = http_request(s.web(), "POST", "/http-bind", &[("Content-Length", "50000000")], b"").await?;
    assert!(r.text().contains("policy-violation"));
    Ok(())
}

#[tokio::test]
async fn the_listener_stops_on_shutdown() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let addr = s.web();
    assert_eq!(http_request(addr, "GET", "/health", &[], b"").await?.status, 200);
    s.srv.shut_down();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(http_request(addr, "GET", "/health", &[], b"").await.is_err());
    Ok(())
}

#[tokio::test]
async fn web_listener_can_do_its_own_tls_with_channel_binding() -> anyhow::Result<()> {
    let s = TestServer::start_with(Options { extra_config: "[http]\ntls = true\n".into(), ..Default::default() }).await?;
    s.add_user("alice", "password-a").await?;
    // A plain request to a TLS port gets no HTTP answer.
    assert!(http_request(s.web(), "GET", "/health", &[], b"").await.is_err());
    let mut c = quark_testkit::WsClient::connect_tls(s.web(), s.domain()).await?;
    assert!(c.mechanisms().iter().any(|m| m == "SCRAM-SHA-256-PLUS"), "{:?}", c.mechanisms());
    c.auth_scram("SCRAM-SHA-256-PLUS", "alice", "password-a").await?;
    c.bind(Some("wss")).await?;
    let session = s.srv.sessions.of(&"alice@quark.test".parse()?).into_iter().next().unwrap();
    assert!(session.info.secure);
    Ok(())
}
