//! Invites (XEP-0401 / XEP-0379): friends inviting friends, pre-approved contacts, and the
//! landing page.

mod common;

use common::*;
use quark::settings::SignUp;
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{presence, Client, TestServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Runs the "Invite someone" command and returns the invite URI.
async fn friend_invite(c: &mut Client, domain: &str) -> anyhow::Result<String> {
    let cmd = Element::new("command", ns::COMMANDS).attr_set("node", "urn:xmpp:invite#invite").attr_set("action", "execute");
    let r = c.iq_set(Some(domain), cmd).await?;
    let x = r.get_child("command", ns::COMMANDS).and_then(|c| c.get_child("x", ns::DATA_FORMS)).cloned();
    let uri = x
        .and_then(|x| x.children().find(|f| f.attr("var") == Some("uri")).and_then(|f| f.child_text("value", ns::DATA_FORMS)))
        .unwrap_or_default();
    anyhow::ensure!(!uri.is_empty(), "no invite in {r}");
    Ok(uri)
}

/// The note of a refused "Invite someone".
async fn friend_invite_refusal(c: &mut Client, domain: &str) -> anyhow::Result<String> {
    let cmd = Element::new("command", ns::COMMANDS).attr_set("node", "urn:xmpp:invite#invite").attr_set("action", "execute");
    let r = c.iq_set(Some(domain), cmd).await?;
    let note = r.get_child("command", ns::COMMANDS).and_then(|c| c.get_child("note", ns::COMMANDS)).cloned();
    anyhow::ensure!(note.as_ref().and_then(|n| n.attr("type")) == Some("error"), "not refused: {r}");
    Ok(note.map(|n| n.text_content()).unwrap_or_default())
}

/// Signs up `user` with the invite behind `uri`; returns the IQ answer.
async fn sign_up_with(s: &TestServer, uri: &str, user: &str) -> anyhow::Result<Element> {
    let mut c = unauthenticated(s).await?;
    let q = register_query(user, "password-9").child(Element::new("preauth", ns::PARS).attr_set("token", token_of(uri)));
    c.iq_set(None, q).await
}

async fn roster_of(c: &mut Client) -> anyhow::Result<Vec<(String, String)>> {
    let me = c.bare().unwrap_or_default();
    let r = c.iq_get(Some(&me), Element::new("query", ns::ROSTER)).await?;
    Ok(r.get_child("query", ns::ROSTER)
        .map(|q| {
            q.children()
                .map(|i| (i.attr("jid").unwrap_or_default().to_string(), i.attr("subscription").unwrap_or_default().to_string()))
                .collect()
        })
        .unwrap_or_default())
}

#[tokio::test]
async fn a_friend_invite_makes_an_account_and_a_contact() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("sam", "password-1").await?;
    let mut sam = s.online("sam", "password-1", "phone").await?;
    let uri = friend_invite(&mut sam, s.domain()).await?;
    assert!(uri.starts_with(&format!("xmpp:sam@{}?roster;preauth=", s.domain())) && uri.ends_with(";ibr=y"), "{uri}");

    let mut c = unauthenticated(&s).await?;
    assert_eq!(c.iq_set(None, Element::new("preauth", ns::PARS).attr_set("token", token_of(&uri))).await?.attr("type"), Some("result"));
    assert_eq!(c.iq_set(None, register_query("kim", "password-2")).await?.attr("type"), Some("result"));

    let mut kim = s.online("kim", "password-2", "phone").await?;
    assert_eq!(roster_of(&mut kim).await?, [(format!("sam@{}", s.domain()), "both".to_string())]);
    assert_eq!(roster_of(&mut sam).await?, [(format!("kim@{}", s.domain()), "both".to_string())]);

    // Friend invites stop making accounts when sign-up closes.
    let uri = friend_invite(&mut sam, s.domain()).await?;
    s.set_settings(|st| st.sign_up = SignUp::Closed).await?;
    let mut c = unauthenticated(&s).await?;
    assert_eq!(condition(&c.iq_set(None, Element::new("preauth", ns::PARS).attr_set("token", token_of(&uri))).await?), "item-not-found");
    Ok(())
}

#[tokio::test]
async fn an_invite_token_preapproves_a_subscription() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("sam", "password-1").await?;
    s.add_user("kim", "password-2").await?;
    let mut sam = s.online("sam", "password-1", "phone").await?;
    let uri = friend_invite(&mut sam, s.domain()).await?;
    let mut kim = s.online("kim", "password-2", "phone").await?;

    let sam_jid = format!("sam@{}", s.domain());
    let sub = presence(Some(&sam_jid), Some("subscribe")).child(Element::new("preauth", ns::PARS).attr_set("token", token_of(&uri)));
    kim.send(&sub).await?;
    // Approved without asking sam, and sam subscribes back.
    let ok = kim.expect(|e| e.name() == "presence" && e.attr("type") == Some("subscribed")).await?;
    assert_eq!(ok.attr("from"), Some(sam_jid.as_str()));
    let back = kim.expect(|e| e.name() == "presence" && e.attr("type") == Some("subscribe")).await?;
    assert_eq!(back.attr("from"), Some(sam_jid.as_str()));
    let mut kim_in_sam: Vec<_> = roster_of(&mut sam).await?;
    kim_in_sam.retain(|(j, _)| j.starts_with("kim@"));
    assert_eq!(kim_in_sam.len(), 1);
    assert!(matches!(kim_in_sam[0].1.as_str(), "from" | "both"), "{kim_in_sam:?}");

    // The token is used up: someone else gets the ordinary question.
    s.add_user("lee", "password-3").await?;
    let mut lee = s.online("lee", "password-3", "phone").await?;
    lee.send(&presence(Some(&sam_jid), Some("subscribe")).child(Element::new("preauth", ns::PARS).attr_set("token", token_of(&uri))))
        .await?;
    let asked = sam.expect(|e| e.name() == "presence" && e.attr("type") == Some("subscribe")).await?;
    assert_eq!(asked.attr("from"), Some(format!("lee@{}", s.domain()).as_str()));
    Ok(())
}

#[tokio::test]
async fn a_token_taken_before_sign_up_closed_stops_working() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("sam", "password-1").await?;
    let mut sam = s.online("sam", "password-1", "phone").await?;
    let uri = friend_invite(&mut sam, s.domain()).await?;
    let mut c = unauthenticated(&s).await?;
    assert_eq!(c.iq_set(None, Element::new("preauth", ns::PARS).attr_set("token", token_of(&uri))).await?.attr("type"), Some("result"));
    s.set_settings(|st| st.sign_up = SignUp::Closed).await?;
    assert_eq!(condition(&c.iq_set(None, register_query("kim", "password-2")).await?), "item-not-found");
    assert!(!s.srv.accounts.exists(s.domain(), "kim").await?);
    Ok(())
}

#[tokio::test]
async fn member_invites_are_limited_and_new_members_wait() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("sam", "password-1").await?;
    let mut sam = s.online("sam", "password-1", "phone").await?;
    let mut uris = Vec::new();
    for _ in 0..10 {
        uris.push(friend_invite(&mut sam, s.domain()).await?);
    }
    // Ten open at once.
    assert!(friend_invite_refusal(&mut sam, s.domain()).await?.contains("open invites"));

    // Five people a day join with one member's invites.
    for (i, uri) in uris.iter().take(5).enumerate() {
        let r = sign_up_with(&s, uri, &format!("f{i}")).await?;
        assert_eq!(r.attr("type"), Some("result"), "{r}");
    }
    let r = sign_up_with(&s, &uris[5], "f5").await?;
    assert_eq!(condition(&r), "policy-violation");
    assert!(!s.srv.accounts.exists(s.domain(), "f5").await?);
    // The refused sign-up didn't use the invite up.
    assert_eq!(s.srv.db.read(|c| c.query_row("SELECT COUNT(*) FROM invite_signups", [], |r| r.get::<_, i64>(0))).await?, 5);

    // Someone who joined with a member's invite can't invite others yet.
    let mut f0 = s.online("f0", "password-9", "phone").await?;
    assert!(friend_invite_refusal(&mut f0, s.domain()).await?.contains("after a week"));
    Ok(())
}

#[tokio::test]
async fn admins_invite_without_member_limits() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_admin("kim", "password-1").await?;
    let mut kim = s.online("kim", "password-1", "phone").await?;
    let mut uris = Vec::new();
    for _ in 0..12 {
        uris.push(friend_invite(&mut kim, s.domain()).await?);
    }
    for (i, uri) in uris.iter().take(6).enumerate() {
        assert_eq!(sign_up_with(&s, uri, &format!("a{i}")).await?.attr("type"), Some("result"));
    }
    Ok(())
}

#[tokio::test]
async fn member_invite_sign_ups_are_limited_per_address() -> anyhow::Result<()> {
    // One open sign-up an hour from an address, so four with members' invites.
    let s = quark_testkit::TestServer::start_with(quark_testkit::Options {
        extra_config: "[limits]\nregistrations_per_hour = 1\n".into(),
        ..Default::default()
    })
    .await?;
    let mut uris = Vec::new();
    for who in ["sam", "lee"] {
        s.add_user(who, "password-1").await?;
        let mut c = s.online(who, "password-1", "phone").await?;
        for _ in 0..3 {
            uris.push(friend_invite(&mut c, s.domain()).await?);
        }
    }
    for (i, uri) in uris.iter().take(4).enumerate() {
        assert_eq!(sign_up_with(&s, uri, &format!("n{i}")).await?.attr("type"), Some("result"));
    }
    let r = sign_up_with(&s, &uris[4], "n4").await?;
    assert_eq!(condition(&r), "policy-violation");
    assert!(r.to_xml().contains("your address"), "{r}");
    Ok(())
}

async fn get(router: axum::Router, path: &str) -> anyhow::Result<(u16, String)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move { axum::serve(listener, router).await });
    let mut c = tokio::net::TcpStream::connect(addr).await?;
    c.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: x\r\nUser-Agent: Mozilla/5.0 (Linux; Android 14)\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await?;
    let mut out = String::new();
    c.read_to_string(&mut out).await?;
    Ok((out.split(' ').nth(1).unwrap_or_default().parse()?, out))
}

#[tokio::test]
async fn the_landing_page_shows_live_invites_only() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let v = admin_ok(
        &s,
        serde_json::json!({ "cmd": "invite.create", "args": { "host": s.domain(), "username": null, "role": "member", "days": 1, "reusable": false } }),
    )
    .await;
    let token = v["token"].as_str().unwrap_or_default().to_string();
    let (code, page) = get(quark::modules::invites::router(&s.srv), &format!("/invite/{token}")).await?;
    assert_eq!(code, 200);
    assert!(page.contains(&format!("preauth={token}")) && page.contains("<svg"), "{page}");
    assert!(page.to_lowercase().contains("referrer-policy: no-referrer"));
    assert_eq!(get(quark::modules::invites::router(&s.srv), "/invite/AAAAAAAAAAAAAAAAAAAAAAAA").await?.0, 404);

    s.set_settings(|st| st.web = false).await?;
    assert_eq!(get(quark::modules::invites::router(&s.srv), &format!("/invite/{token}")).await?.0, 404);
    Ok(())
}
