//! Black-box conformance: SASL2 (XEP-0388), Bind2 (XEP-0386), FAST (XEP-0484) and the SASL2
//! parts of XEP-0198 / XEP-0280 / XEP-0352. Written from the specifications only.

use crate::blind_common;

use blind_common::*;
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{message, Client, TestServer, DOMAIN};

async fn server() -> anyhow::Result<TestServer> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password1").await?;
    s.add_user("bob", "password1").await?;
    Ok(s)
}

fn sasl2_feature(c: &Client) -> Option<&Element> {
    feature(c, "authentication", SASL2)
}

fn inline(c: &Client) -> Option<&Element> {
    sasl2_feature(c)?.get_child("inline", SASL2)
}

fn expect_success(end: SaslEnd) -> Element {
    match end {
        SaslEnd::Success(s) => s,
        other => panic!("SASL2 did not succeed: {other:?}"),
    }
}

/// SASL2 + Bind2 with `inline` requests; returns the client and `<success/>`.
async fn sasl2_bind(
    s: &TestServer,
    user: &str,
    ua: &str,
    inline_reqs: Vec<Element>,
    extra: Vec<Element>,
) -> anyhow::Result<(Client, Element)> {
    let mut c = tls_client(s).await?;
    let mut children = vec![user_agent(ua), bind2("blind", inline_reqs)];
    children.extend(extra);
    let ok = expect_success(sasl2_scram(&mut c, user, "password1", children).await?);
    if let Some(j) = authz_id(&ok) {
        c.jid = Some(j);
    }
    Ok((c, ok))
}

#[tokio::test]
async fn sasl2_is_advertised_with_mechanisms_and_bind2_inline() -> anyhow::Result<()> {
    // XEP-0388 §2.1, XEP-0386 §3.
    let s = server().await?;
    let c = tls_client(&s).await?;
    let auth = sasl2_feature(&c).expect("no <authentication xmlns='urn:xmpp:sasl:2'/>");
    let mechs: Vec<String> = auth.children().filter(|m| m.name() == "mechanism").map(|m| m.text_content()).collect();
    assert!(mechs.iter().any(|m| m == "SCRAM-SHA-256"), "{auth}");
    let inl = inline(&c).expect("no <inline/> in SASL2 feature");
    assert!(inl.has_child("bind", BIND2), "Bind2 not offered inline: {inl}");
    assert!(inl.has_child("sm", SM), "SM not offered inline: {inl}");
    let fast = inl.get_child("fast", FAST).expect("FAST not offered inline");
    assert!(fast.children().any(|m| m.name() == "mechanism" && m.text_content() == "HT-SHA-256-NONE"), "{fast}");
    // Bind2 lists the features it can enable inline.
    let b = inl.get_child("bind", BIND2).expect("bind");
    let vars: Vec<&str> = b.get_child("inline", BIND2).map(|i| i.children().filter_map(|f| f.attr("var")).collect()).unwrap_or_default();
    for v in [ns::CARBONS, CSI, SM] {
        assert!(vars.contains(&v), "Bind2 inline feature {v} missing: {b}");
    }
    Ok(())
}

#[tokio::test]
async fn sasl2_bind2_returns_full_jid_and_bound() -> anyhow::Result<()> {
    // XEP-0388 §2.6 <authorization-identifier/>; XEP-0386 §4 <bound/>; no stream restart.
    let s = server().await?;
    let (mut c, ok) = sasl2_bind(&s, "alice", &agent_id(), vec![], vec![]).await?;
    let jid = authz_id(&ok).expect("no <authorization-identifier/>");
    let (bare, res) = jid.split_once('/').unwrap_or_else(|| panic!("authorization-identifier is not a full JID: {jid}"));
    assert_eq!(bare, "alice@quark.test");
    assert!(!res.is_empty());
    assert!(ok.has_child("bound", BIND2), "no <bound/>: {ok}");
    // The session is live straight away (no restart, no <bind/> IQ).
    let pong = c.iq_get(Some(DOMAIN), Element::new("ping", ns::PING)).await?;
    assert_eq!(pong.attr("type"), Some("result"));
    let mut bob = s.login("bob", "password1").await?;
    bob.send(&message(&jid, "chat", "to bind2")).await?;
    let m = c.expect(|e| e.name() == "message").await?;
    assert_eq!(m.child_text("body", ns::CLIENT).as_deref(), Some("to bind2"));
    Ok(())
}

#[tokio::test]
async fn sasl2_same_user_agent_twice_does_not_reuse_a_live_resource_silently() -> anyhow::Result<()> {
    // Two sessions bound with Bind2 at once must have distinct full JIDs (or the old one is
    // replaced with <conflict/>, RFC 6120 §7.7.2.2).
    let s = server().await?;
    let ua = agent_id();
    let (mut c1, ok1) = sasl2_bind(&s, "alice", &ua, vec![], vec![]).await?;
    let (_c2, ok2) = sasl2_bind(&s, "alice", &ua, vec![], vec![]).await?;
    let (j1, j2) = (authz_id(&ok1).unwrap_or_default(), authz_id(&ok2).unwrap_or_default());
    if j1 == j2 {
        expect_stream_error(&mut c1, &["conflict"]).await?;
    } else {
        let pong = c1.iq_get(Some(DOMAIN), Element::new("ping", ns::PING)).await?;
        assert_eq!(pong.attr("type"), Some("result"));
    }
    Ok(())
}

#[tokio::test]
async fn sasl2_without_bind2_then_classic_bind() -> anyhow::Result<()> {
    // XEP-0388: without inline Bind2 the client binds with RFC 6120 afterwards.
    let s = server().await?;
    let mut c = tls_client(&s).await?;
    let ok = expect_success(sasl2_scram(&mut c, "alice", "password1", vec![user_agent(&agent_id())]).await?);
    let id = authz_id(&ok).expect("no <authorization-identifier/>");
    assert!(id.starts_with("alice@quark.test"), "{ok}");
    // The server may send fresh stream features (it must offer bind if it does).
    if let Some(f) = c.recv_within(QUIET).await? {
        assert!(f.is("features", ns::STREAM), "unexpected {f}");
        assert!(f.has_child("bind", ns::BIND), "features after SASL2 lack bind: {f}");
    }
    let jid = c.bind(Some("classic")).await?;
    assert_eq!(jid, "alice@quark.test/classic");
    Ok(())
}

#[tokio::test]
async fn sasl2_wrong_password_fails_with_not_authorized() -> anyhow::Result<()> {
    // XEP-0388 §2.7: <failure xmlns='urn:xmpp:sasl:2'><not-authorized xmlns='…xmpp-sasl'/>.
    let s = server().await?;
    let mut c = tls_client(&s).await?;
    let end = sasl2_scram(&mut c, "alice", "wrong-password", vec![user_agent(&agent_id())]).await?;
    match &end {
        SaslEnd::Failure(f) => {
            assert_eq!(f.ns(), SASL2, "{f}");
            assert_eq!(sasl_failure_condition(f).as_deref(), Some("not-authorized"), "{f}");
        }
        other => panic!("expected failure: {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn sasl2_inline_carbons_are_enabled() -> anyhow::Result<()> {
    // XEP-0386 §4 + XEP-0280: <enable xmlns='urn:xmpp:carbons:2'/> inside <bind/>.
    let s = server().await?;
    let mut phone = s.online("alice", "password1", "phone").await?;
    let (mut c, _) = sasl2_bind(&s, "alice", &agent_id(), vec![Element::new("enable", ns::CARBONS)], vec![]).await?;
    c.send(&Element::new("presence", ns::CLIENT)).await?;
    drain(&mut c).await?;
    drain(&mut phone).await?;
    let mut bob = s.login("bob", "password1").await?;
    bob.send(&message("alice@quark.test/phone", "chat", "carbon me")).await?;
    phone.expect(|e| e.name() == "message").await?;
    let carbon = c.expect(|e| e.name() == "message" && e.has_child("received", ns::CARBONS)).await?;
    let inner = carbon.get_child("received", ns::CARBONS).and_then(|r| r.get_child("forwarded", ns::FORWARD)).expect("forwarded");
    let m = inner.get_child("message", ns::CLIENT).expect("forwarded message");
    assert_eq!(m.child_text("body", ns::CLIENT).as_deref(), Some("carbon me"));
    // XEP-0280 §11: carbons come from the user's own bare JID.
    assert_eq!(carbon.attr("from"), Some("alice@quark.test"), "{carbon}");
    Ok(())
}

#[tokio::test]
async fn sasl2_without_inline_carbons_gets_no_carbons() -> anyhow::Result<()> {
    // XEP-0280 §6: carbons go only to resources that enabled them.
    let s = server().await?;
    let mut phone = s.online("alice", "password1", "phone").await?;
    let (mut c, _) = sasl2_bind(&s, "alice", &agent_id(), vec![], vec![]).await?;
    c.send(&Element::new("presence", ns::CLIENT)).await?;
    drain(&mut c).await?;
    drain(&mut phone).await?;
    let mut bob = s.login("bob", "password1").await?;
    bob.send(&message("alice@quark.test/phone", "chat", "not for you")).await?;
    phone.expect(|e| e.name() == "message").await?;
    if let Some(e) = c.recv_within(QUIET).await? {
        assert!(!e.has_child("received", ns::CARBONS), "carbon delivered without enabling carbons: {e}");
    }
    Ok(())
}

#[tokio::test]
async fn sasl2_inline_sm_enable_returns_enabled_in_bound() -> anyhow::Result<()> {
    // XEP-0198 §3 + XEP-0386: <enable/> inside <bind/> → <enabled/> inside <bound/>.
    let s = server().await?;
    let (mut c, ok) = sasl2_bind(&s, "alice", &agent_id(), vec![Element::new("enable", SM).attr_set("resume", "true")], vec![]).await?;
    let en = find_deep(&ok, "enabled", SM).unwrap_or_else(|| panic!("no <enabled/> in success: {ok}"));
    let bound = ok.get_child("bound", BIND2).expect("bound");
    assert!(bound.has_child("enabled", SM), "<enabled/> should be inside <bound/>: {ok}");
    assert!(en.attr("id").is_some(), "{en}");
    assert!(is_true(en.attr("resume")), "{en}");
    assert_eq!(sm_request_ack(&mut c).await?, 0);
    Ok(())
}

#[tokio::test]
async fn sasl2_inline_resume_redelivers() -> anyhow::Result<()> {
    // XEP-0198 §5 + XEP-0388: <resume/> inside <authenticate/> → <resumed/> in <success/>.
    let s = server().await?;
    let ua = agent_id();
    let (mut c, ok) = sasl2_bind(&s, "alice", &ua, vec![Element::new("enable", SM).attr_set("resume", "true")], vec![]).await?;
    let jid = authz_id(&ok).expect("jid");
    let id = find_deep(&ok, "enabled", SM).and_then(|e| e.attr("id")).expect("sm id").to_string();
    c.send(&Element::new("presence", ns::CLIENT)).await?;
    // Count the stanzas alice got since enabling (e.g. her own presence) to resume with that h.
    let received = drain(&mut c).await?.iter().filter(|e| matches!(e.name(), "message" | "presence" | "iq")).count();
    c.drop_connection();
    let mut bob = s.login("bob", "password1").await?;
    bob.send(&message(&jid, "chat", "while away")).await?;
    bob.iq_get(Some(DOMAIN), Element::new("ping", ns::PING)).await?;

    let mut c2 = tls_client(&s).await?;
    let resume = Element::new("resume", SM).attr_set("previd", &id).attr_set("h", received.to_string());
    let ok2 = expect_success(sasl2_scram(&mut c2, "alice", "password1", vec![user_agent(&ua), resume]).await?);
    let resumed = ok2.get_child("resumed", SM).unwrap_or_else(|| panic!("no <resumed/> in success: {ok2}"));
    assert_eq!(resumed.attr("previd"), Some(id.as_str()), "{resumed}");
    assert!(resumed.attr("h").is_some(), "{resumed}");
    assert_eq!(authz_id(&ok2).as_deref(), Some(jid.as_str()), "resumed session has another JID: {ok2}");
    let m = c2.expect(|e| e.name() == "message").await?;
    assert_eq!(m.child_text("body", ns::CLIENT).as_deref(), Some("while away"));
    Ok(())
}

#[tokio::test]
async fn sasl2_inline_resume_with_unknown_id_fails_and_falls_back_to_bind2() -> anyhow::Result<()> {
    // XEP-0198 §5 (SASL2): a failed inline resume is reported with <failed/> and, when the client
    // also sent Bind2, a new session is bound instead.
    let s = server().await?;
    let mut c = tls_client(&s).await?;
    let resume = Element::new("resume", SM).attr_set("previd", "nope").attr_set("h", "0");
    let end = sasl2_scram(&mut c, "alice", "password1", vec![user_agent(&agent_id()), resume, bind2("blind", vec![])]).await?;
    match end {
        SaslEnd::Success(ok) => {
            assert!(find_deep(&ok, "failed", SM).is_some(), "no <failed/> for the bad resume: {ok}");
            assert!(ok.has_child("bound", BIND2), "Bind2 fallback didn't bind: {ok}");
        }
        SaslEnd::Failure(f) => panic!("authentication itself should not fail for a stale resume: {f}"),
        SaslEnd::StreamError(e) => panic!("{e}"),
    }
    Ok(())
}

#[tokio::test]
async fn sasl2_inline_csi_inactive_holds_chat_states_but_not_messages() -> anyhow::Result<()> {
    // XEP-0352 inline in Bind2 (XEP-0386).
    let s = server().await?;
    let (mut c, _) = sasl2_bind(&s, "alice", &agent_id(), vec![Element::new("inactive", CSI)], vec![]).await?;
    let jid = c.jid.clone().expect("jid");
    c.send(&Element::new("presence", ns::CLIENT)).await?;
    drain(&mut c).await?;
    let mut bob = s.login("bob", "password1").await?;
    bob.send(
        &Element::new("message", ns::CLIENT).attr_set("to", &jid).attr_set("type", "chat").child(Element::new("composing", CHAT_STATES)),
    )
    .await?;
    c.expect_silence(QUIET).await.map_err(|e| anyhow::anyhow!("chat state not held while inactive: {e}"))?;
    bob.send(&message(&jid, "chat", "urgent")).await?;
    let m = c.expect(|e| e.name() == "message" && e.has_child("body", ns::CLIENT)).await?;
    assert_eq!(m.child_text("body", ns::CLIENT).as_deref(), Some("urgent"));
    Ok(())
}

// --- FAST (XEP-0484) ---

fn ht_initial_response(user: &str, token: &str) -> String {
    let mut ir = user.as_bytes().to_vec();
    ir.push(0);
    ir.extend(hmac_sha256(token.as_bytes(), b"Initiator"));
    b64(ir)
}

async fn fast_authenticate(s: &TestServer, user: &str, ua: &str, token: &str) -> anyhow::Result<(Client, SaslEnd)> {
    let mut c = tls_client(s).await?;
    let auth = Element::new("authenticate", SASL2)
        .attr_set("mechanism", "HT-SHA-256-NONE")
        .text_child("initial-response", SASL2, ht_initial_response(user, token))
        .child(user_agent(ua))
        .child(Element::new("fast", FAST))
        .child(bind2("blind", vec![]));
    c.send(&auth).await?;
    let r = c.recv().await?;
    let end = if r.is("success", SASL2) {
        SaslEnd::Success(r)
    } else if r.is("failure", SASL2) {
        SaslEnd::Failure(r)
    } else {
        SaslEnd::StreamError(r)
    };
    Ok((c, end))
}

async fn get_fast_token(s: &TestServer, ua: &str) -> anyhow::Result<String> {
    let mut c = tls_client(s).await?;
    let req = Element::new("request-token", FAST).attr_set("mechanism", "HT-SHA-256-NONE");
    let ok = expect_success(sasl2_scram(&mut c, "alice", "password1", vec![user_agent(ua), bind2("blind", vec![]), req]).await?);
    let tok = ok.get_child("token", FAST).unwrap_or_else(|| panic!("no <token/> in success: {ok}"));
    assert!(tok.attr("expiry").is_some(), "token without expiry: {tok}");
    let expiry = tok.attr("expiry").unwrap_or_default();
    assert!(parse_xep82(expiry)? > now_unix(), "token already expired: {tok}");
    Ok(tok.attr("token").expect("token attribute").to_string())
}

#[tokio::test]
async fn fast_token_signs_in_with_ht_sha_256_none() -> anyhow::Result<()> {
    let s = server().await?;
    let ua = agent_id();
    let token = get_fast_token(&s, &ua).await?;
    let (mut c, end) = fast_authenticate(&s, "alice", &ua, &token).await?;
    let ok = expect_success(end);
    // Mutual authentication: the server proves it knows the token too.
    let data = ok.child_text("additional-data", SASL2).unwrap_or_else(|| panic!("no <additional-data/>: {ok}"));
    assert_eq!(unb64(&data)?, hmac_sha256(token.as_bytes(), b"Responder"), "server's HT proof is wrong");
    let jid = authz_id(&ok).expect("jid");
    assert!(jid.starts_with("alice@quark.test/"), "{jid}");
    let pong = c.iq_get(Some(DOMAIN), Element::new("ping", ns::PING)).await?;
    assert_eq!(pong.attr("type"), Some("result"));
    Ok(())
}

#[tokio::test]
async fn fast_wrong_token_fails() -> anyhow::Result<()> {
    let s = server().await?;
    let ua = agent_id();
    let token = get_fast_token(&s, &ua).await?;
    let (_c, end) = fast_authenticate(&s, "alice", &ua, &format!("{token}x")).await?;
    match end {
        SaslEnd::Failure(f) => assert_eq!(sasl_failure_condition(&f).as_deref(), Some("not-authorized"), "{f}"),
        other => panic!("wrong FAST token accepted or odd reply: {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn fast_token_without_any_issued_fails() -> anyhow::Result<()> {
    let s = server().await?;
    let (_c, end) = fast_authenticate(&s, "alice", &agent_id(), "made-up-token").await?;
    assert!(matches!(end, SaslEnd::Failure(_)), "{end:?}");
    Ok(())
}

#[tokio::test]
async fn fast_token_is_bound_to_its_user() -> anyhow::Result<()> {
    // A token issued to alice must not sign in bob.
    let s = server().await?;
    let ua = agent_id();
    let token = get_fast_token(&s, &ua).await?;
    let (_c, end) = fast_authenticate(&s, "bob", &ua, &token).await?;
    assert!(matches!(end, SaslEnd::Failure(_)), "alice's token signed in bob: {end:?}");
    Ok(())
}
