//! External service discovery (XEP-0215): STUN/TURN services and credentials for calls.

use quark_testkit::quark_core::{ns, Element};
use quark_testkit::turn::TurnClient;
use quark_testkit::{Client, TestServer};
use serde_json::{json, Value};

async fn alice(s: &TestServer) -> anyhow::Result<Client> {
    s.add_user("alice", "password-a").await?;
    s.login("alice", "password-a").await
}

async fn services(c: &mut Client, kind: Option<&str>) -> anyhow::Result<Element> {
    c.iq_get(Some("quark.test"), Element::new("services", ns::EXTDISCO).attr_opt("type", kind)).await
}

fn entries(r: &Element) -> Vec<&Element> {
    r.get_child("services", ns::EXTDISCO).map(|s| s.children().collect()).unwrap_or_default()
}

fn find<'a>(list: &[&'a Element], kind: &str, transport: &str) -> Option<&'a Element> {
    list.iter().copied().find(|e| e.attr("type") == Some(kind) && e.attr("transport") == Some(transport))
}

#[tokio::test]
async fn services_carry_credentials_the_built_in_relay_accepts() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut c = alice(&s).await?;
    let r = services(&mut c, None).await?;
    assert_eq!(r.attr("type"), Some("result"));
    let list = entries(&r);
    assert_eq!(list.len(), 3);
    let port = s.listening.turn[0].port().to_string();
    let stun = find(&list, "stun", "udp").expect("a STUN service");
    assert_eq!((stun.attr("host"), stun.attr("port")), (Some("quark.test"), Some(port.as_str())));
    assert!(stun.attr("username").is_none());
    assert!(find(&list, "turn", "tcp").is_some());

    let turn = find(&list, "turn", "udp").expect("a TURN service");
    assert_eq!(turn.attr("restricted"), Some("1"));
    let (user, pass) = (turn.attr("username").expect("username"), turn.attr("password").expect("password"));
    assert!(user.ends_with(":alice@quark.test"));
    let expires = quark_testkit::quark_core::time::parse_xep82(turn.attr("expires").expect("expires")).expect("a valid time");
    let left = expires - quark_testkit::quark_core::time::now_ms();
    assert!(left > 23 * 3_600_000 && left <= 24 * 3_600_000 + 1000, "{left}");

    let mut t = TurnClient::udp(s.listening.turn[0]).await?.with_credentials(user, pass);
    t.allocate().await?;
    let mut t = TurnClient::tcp(s.listening.turn[1]).await?.with_credentials(user, pass);
    t.allocate().await?;
    Ok(())
}

#[tokio::test]
async fn services_can_be_filtered_by_type() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut c = alice(&s).await?;
    let r = services(&mut c, Some("stun")).await?;
    let list = entries(&r);
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].attr("type"), Some("stun"));
    assert_eq!(r.get_child("services", ns::EXTDISCO).and_then(|s| s.attr("type")), Some("stun"));
    Ok(())
}

#[tokio::test]
async fn credentials_requests_get_fresh_credentials_for_the_named_service() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut c = alice(&s).await?;
    let ask = Element::new("credentials", ns::EXTDISCO)
        .child(Element::new("service", ns::EXTDISCO).attr_set("host", "quark.test").attr_set("type", "turn"));
    let r = c.iq_get(Some("quark.test"), ask).await?;
    let got: Vec<&Element> = r.get_child("credentials", ns::EXTDISCO).map(|e| e.children().collect()).unwrap_or_default();
    assert_eq!(got.len(), 2);
    assert!(got.iter().all(|e| e.attr("type") == Some("turn") && e.attr("password").is_some()));

    let unknown = Element::new("credentials", ns::EXTDISCO)
        .child(Element::new("service", ns::EXTDISCO).attr_set("host", "elsewhere.test").attr_set("type", "turn"));
    let r = c.iq_get(Some("quark.test"), unknown).await?;
    assert_eq!(r.attr("type"), Some("error"));
    assert!(r.get_child("error", ns::CLIENT).is_some_and(|e| e.has_child("item-not-found", ns::STANZAS)));
    Ok(())
}

#[tokio::test]
async fn an_external_relay_secret_switches_the_credentials_to_it() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    quark::turn::set_external(&s.srv, Some("their-secret"), Some("turn.example.net"), Some(3479)).await?;
    let mut c = alice(&s).await?;
    let r = services(&mut c, Some("turn")).await?;
    let list = entries(&r);
    let turn = find(&list, "turn", "udp").expect("a TURN service");
    assert_eq!((turn.attr("host"), turn.attr("port")), (Some("turn.example.net"), Some("3479")));
    let user = turn.attr("username").expect("username");
    assert_eq!(turn.attr("password"), Some(quark::turn::rest_password("their-secret", user).as_str()));
    // Those are for the other relay; ours doesn't take them.
    let mut t = TurnClient::udp(s.listening.turn[0]).await?.with_credentials(user, turn.attr("password").unwrap_or_default());
    assert!(t.allocate().await.is_err());

    // Clearing the secret goes back to the built-in relay.
    quark::turn::set_external(&s.srv, None, None, None).await?;
    let r = services(&mut c, Some("turn")).await?;
    assert_eq!(find(&entries(&r), "turn", "udp").and_then(|e| e.attr("host")), Some("quark.test"));
    Ok(())
}

/// One request over the admin socket, as `quark` and the MCP tools send it.
async fn admin(s: &TestServer, req: Value) -> anyhow::Result<Value> {
    let sock = s.srv.config().server.data_dir.join(quark::admin::SOCKET);
    Ok(serde_json::from_str(&quark::admin::request(&sock, &req.to_string()).await?)?)
}

#[tokio::test]
async fn turn_set_over_the_admin_socket_switches_discovery_to_the_external_relay() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut c = alice(&s).await?;
    let set = json!({ "cmd": "turn.set", "args": { "secret": " their-secret ", "host": "TURN.example.net", "port": 3479 } });
    assert_eq!(admin(&s, set).await?["ok"], json!(true));
    let r = services(&mut c, Some("turn")).await?;
    let turn = find(&entries(&r), "turn", "udp").cloned().expect("a TURN service");
    assert_eq!((turn.attr("host"), turn.attr("port")), (Some("turn.example.net"), Some("3479")));
    let user = turn.attr("username").expect("username");
    assert_eq!(turn.attr("password"), Some(quark::turn::rest_password("their-secret", user).as_str()));

    // A null secret goes back to the built-in relay.
    assert_eq!(admin(&s, json!({ "cmd": "turn.set", "args": { "secret": null } })).await?["ok"], json!(true));
    let r = services(&mut c, Some("turn")).await?;
    let port = s.listening.turn[0].port().to_string();
    let turn = find(&entries(&r), "turn", "udp").cloned().expect("a TURN service");
    assert_eq!((turn.attr("host"), turn.attr("port")), (Some("quark.test"), Some(port.as_str())));
    let bad = admin(&s, json!({ "cmd": "turn.set", "args": { "secret": "x", "port": 70000 } })).await?;
    assert_eq!(bad["ok"], json!(false));
    Ok(())
}

#[tokio::test]
async fn an_external_relay_without_host_or_port_uses_the_calls_host_and_3478() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    // The admin API's storage shape: UTF-8 values under scope "turn".
    s.srv.kv_set("turn", "secret", Some(b"abc".to_vec())).await?;
    s.set_settings(|st| st.calls.host = "calls.quark.test".into()).await?;
    let mut c = alice(&s).await?;
    let r = services(&mut c, Some("stun")).await?;
    let stun = entries(&r)[0].clone();
    assert_eq!((stun.attr("host"), stun.attr("port")), (Some("calls.quark.test"), Some("3478")));
    Ok(())
}

#[tokio::test]
async fn calls_off_means_no_services_and_no_feature() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut c = alice(&s).await?;
    let has_feature = |info: &Element| {
        info.get_child("query", ns::DISCO_INFO)
            .is_some_and(|q| q.children().any(|f| f.name() == "feature" && f.attr("var") == Some(ns::EXTDISCO)))
    };
    let info = c.iq_get(Some("quark.test"), Element::new("query", ns::DISCO_INFO)).await?;
    assert!(has_feature(&info));

    s.set_settings(|st| st.calls.on = false).await?;
    let info = c.iq_get(Some("quark.test"), Element::new("query", ns::DISCO_INFO)).await?;
    assert!(!has_feature(&info));
    let r = services(&mut c, None).await?;
    assert_eq!(r.attr("type"), Some("error"));
    assert!(r.get_child("error", ns::CLIENT).is_some_and(|e| e.has_child("service-unavailable", ns::STANZAS)));
    Ok(())
}

#[tokio::test]
async fn setting_services_is_a_bad_request() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut c = alice(&s).await?;
    let r = c.iq_set(Some("quark.test"), Element::new("services", ns::EXTDISCO)).await?;
    assert_eq!(r.attr("type"), Some("error"));
    assert!(r.get_child("error", ns::CLIENT).is_some_and(|e| e.has_child("bad-request", ns::STANZAS)));
    Ok(())
}
