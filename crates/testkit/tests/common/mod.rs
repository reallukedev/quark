//! Helpers the account tests share: the admin API, registration and stream errors.
#![allow(dead_code)]

use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{Client, TestServer};
use serde_json::Value;

/// Runs one admin request in-process and returns the whole response.
pub async fn admin(s: &TestServer, req: Value) -> Value {
    let line = quark::admin::handle(&s.srv, &req.to_string(), "test").await;
    serde_json::from_str(&line).expect("the admin API answers JSON")
}

/// Runs one admin request that must succeed and returns its `value`.
pub async fn admin_ok(s: &TestServer, req: Value) -> Value {
    let r = admin(s, req.clone()).await;
    assert_eq!(r["ok"], true, "{req} was refused: {r}");
    r["value"].clone()
}

/// The stable code of a refused admin request.
pub async fn admin_code(s: &TestServer, req: Value) -> String {
    let r = admin(s, req.clone()).await;
    assert_eq!(r["ok"], false, "{req} should be refused: {r}");
    r["code"].as_str().unwrap_or_default().to_string()
}

/// Waits for the server to close the stream with an error; returns its condition.
pub async fn stream_error(c: &mut Client) -> String {
    let e = c.expect(|e| e.is("error", ns::STREAM)).await.expect("a stream error");
    let name = e.children().find(|c| c.ns() == ns::STREAMS && c.name() != "text").map(|c| c.name().to_string());
    name.unwrap_or_default()
}

/// A connection after STARTTLS, not signed in: where in-band registration happens.
pub async fn unauthenticated(s: &TestServer) -> anyhow::Result<Client> {
    let mut c = Client::connect(s.c2s(), s.domain()).await?;
    c.starttls().await?;
    Ok(c)
}

/// A registration set with the legacy fields.
pub fn register_query(user: &str, password: &str) -> Element {
    Element::new("query", ns::REGISTER).text_child("username", ns::REGISTER, user).text_child("password", ns::REGISTER, password)
}

/// The defined condition of an IQ error, or "" for a result.
pub fn condition(iq: &Element) -> String {
    iq.get_child("error", ns::CLIENT)
        .and_then(|e| e.children().find(|c| c.ns() == "urn:ietf:params:xml:ns:xmpp-stanzas" && c.name() != "text"))
        .map(|c| c.name().to_string())
        .unwrap_or_default()
}

/// The token in an invite URI (`…;preauth=TOKEN;…`).
pub fn token_of(uri: &str) -> String {
    uri.split("preauth=").nth(1).unwrap_or_default().split(';').next().unwrap_or_default().to_string()
}

/// Whether a sign-in with SCRAM-SHA-256 works (on a resource of its own, so it doesn't take
/// over a test's session).
pub async fn can_sign_in(s: &TestServer, user: &str, password: &str) -> bool {
    match s.login_as(user, password, "sign-in-check").await {
        Ok(c) => c.close().await.is_ok(),
        Err(_) => false,
    }
}
