//! In-band registration (XEP-0077): sign-up modes, invites with `<preauth/>` (XEP-0401),
//! limits, and changing or deleting an account once signed in.

use crate::common;

use common::*;
use quark::settings::SignUp;
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{Options, TestServer};
use serde_json::json;

async fn invite(s: &TestServer, username: Option<&str>, role: &str, reusable: bool) -> String {
    let v = admin_ok(s, json!({ "cmd": "invite.create", "args": { "host": s.domain(), "username": username, "role": role, "days": 1, "reusable": reusable } })).await;
    v["token"].as_str().unwrap_or_default().to_string()
}

fn preauth(token: &str) -> Element {
    Element::new("preauth", ns::PARS).attr_set("token", token)
}

#[tokio::test]
async fn registration_is_offered_with_invites() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let c = unauthenticated(&s).await?;
    let f = c.features.clone().unwrap_or_else(|| Element::new("none", ""));
    for n in [ns::REGISTER_FEATURE, ns::INVITE, ns::IBR_TOKEN] {
        assert!(f.has_child("register", n), "no <register xmlns='{n}'/> in {f}");
    }
    Ok(())
}

#[tokio::test]
async fn sign_up_follows_the_setting() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    // Invite only (the default): the form says so and a plain sign-up is refused.
    let mut c = unauthenticated(&s).await?;
    let form = c.iq_get(None, Element::new("query", ns::REGISTER)).await?;
    assert!(form.to_xml().contains("need an invite"), "{form}");
    let r = c.iq_set(None, register_query("sam", "password-1")).await?;
    assert_eq!(condition(&r), "not-allowed");

    s.set_settings(|st| st.sign_up = SignUp::Open).await?;
    let r = c.iq_set(None, register_query("Sam", "password-1")).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    assert!(can_sign_in(&s, "sam", "password-1").await);
    let r = c.iq_set(None, register_query("sam", "password-2")).await?;
    assert_eq!(condition(&r), "conflict");
    for (user, pw) in [("admin", "password-1"), ("bad name", "password-1"), ("kim", "short"), ("", "password-1")] {
        let r = c.iq_set(None, register_query(user, pw)).await?;
        assert_eq!(condition(&r), "not-acceptable", "{user}/{pw}: {r}");
    }

    s.set_settings(|st| st.sign_up = SignUp::Closed).await?;
    let r = c.iq_set(None, register_query("kim", "password-1")).await?;
    assert_eq!(condition(&r), "not-allowed");
    Ok(())
}

#[tokio::test]
async fn sign_ups_per_address_are_limited() -> anyhow::Result<()> {
    let s = TestServer::start_with(Options { extra_config: "[limits]\nregistrations_per_hour = 2\n".into(), ..Default::default() }).await?;
    s.set_settings(|st| st.sign_up = SignUp::Open).await?;
    let mut c = unauthenticated(&s).await?;
    for u in ["a1", "a2"] {
        assert_eq!(c.iq_set(None, register_query(u, "password-1")).await?.attr("type"), Some("result"));
    }
    let r = c.iq_set(None, register_query("a3", "password-1")).await?;
    assert_eq!(condition(&r), "policy-violation");
    // An invite isn't counted against the address.
    let t = invite(&s, None, "member", false).await;
    assert_eq!(c.iq_set(None, preauth(&t)).await?.attr("type"), Some("result"));
    assert_eq!(c.iq_set(None, register_query("a3", "password-1")).await?.attr("type"), Some("result"));
    Ok(())
}

#[tokio::test]
async fn invites_let_people_in_once() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.set_settings(|st| st.sign_up = SignUp::Closed).await?;
    let t = invite(&s, None, "admin", false).await;

    let mut c = unauthenticated(&s).await?;
    assert_eq!(condition(&c.iq_set(None, preauth("not-a-real-token-at-all")).await?), "item-not-found");
    assert_eq!(c.iq_set(None, preauth(&t)).await?.attr("type"), Some("result"));
    let form = c.iq_get(None, Element::new("query", ns::REGISTER)).await?;
    assert!(form.to_xml().contains("Choose a username"), "{form}");
    assert_eq!(c.iq_set(None, register_query("kim", "password-1")).await?.attr("type"), Some("result"));
    assert_eq!(s.srv.accounts.info(s.domain(), "kim").await?.map(|i| i.role), Some(quark::accounts::Role::Admin));

    // Used up, also when sent inside the registration itself.
    let mut c = unauthenticated(&s).await?;
    let r = c.iq_set(None, register_query("lee", "password-1").child(preauth(&t))).await?;
    assert_eq!(condition(&r), "item-not-found");

    // A reusable one, inside the query, works twice; a reserved name is still refused.
    let t = invite(&s, None, "member", true).await;
    for u in ["lee", "max"] {
        let mut c = unauthenticated(&s).await?;
        assert_eq!(c.iq_set(None, register_query(u, "password-1").child(preauth(&t))).await?.attr("type"), Some("result"));
    }
    let mut c = unauthenticated(&s).await?;
    assert_eq!(condition(&c.iq_set(None, register_query("root", "password-1").child(preauth(&t))).await?), "not-acceptable");
    Ok(())
}

#[tokio::test]
async fn named_and_reset_invites() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let t = invite(&s, Some("support"), "member", false).await;
    let mut c = unauthenticated(&s).await?;
    c.iq_set(None, preauth(&t)).await?;
    let form = c.iq_get(None, Element::new("query", ns::REGISTER)).await?;
    assert!(form.to_xml().contains("<username>support</username>"), "{form}");
    assert_eq!(condition(&c.iq_set(None, register_query("someone", "password-1")).await?), "not-allowed");
    // Named by the invite, so a reserved name is fine.
    assert_eq!(c.iq_set(None, register_query("support", "password-1")).await?.attr("type"), Some("result"));

    let mut old = s.login_as("support", "password-1", "phone").await?;
    let reset = admin_ok(
        &s,
        json!({ "cmd": "invite.create", "args": { "host": s.domain(), "username": "support", "role": "member", "days": 1, "reusable": false, "reset": true } }),
    )
    .await;
    let mut c = unauthenticated(&s).await?;
    c.iq_set(None, preauth(reset["token"].as_str().unwrap_or_default())).await?;
    assert_eq!(c.iq_set(None, register_query("support", "password-2")).await?.attr("type"), Some("result"));
    assert_eq!(stream_error(&mut old).await, "reset");
    assert!(can_sign_in(&s, "support", "password-2").await);
    assert!(!can_sign_in(&s, "support", "password-1").await);
    Ok(())
}

#[tokio::test]
async fn people_change_their_password_and_delete_their_account() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("sam", "password-1").await?;
    // Not the resource `can_sign_in` uses, which would take this session over.
    let mut sam = s.login_as("sam", "password-1", "phone").await?;
    let r = sam.iq_get(None, Element::new("query", ns::REGISTER)).await?;
    assert!(r.to_xml().contains("<registered/>") || r.to_xml().contains("registered"), "{r}");
    let other = register_query("kim", "password-2");
    assert_eq!(condition(&sam.iq_set(None, other).await?), "not-allowed");
    assert_eq!(condition(&sam.iq_set(None, register_query("sam", "short")).await?), "not-acceptable");
    assert_eq!(sam.iq_set(None, register_query("sam", "password-2")).await?.attr("type"), Some("result"));
    assert!(can_sign_in(&s, "sam", "password-2").await);

    let r = sam.iq_set(None, Element::new("query", ns::REGISTER).child(Element::new("remove", ns::REGISTER))).await?;
    assert_eq!(r.attr("type"), Some("result"));
    assert_eq!(stream_error(&mut sam).await, "not-authorized");
    assert!(!s.srv.accounts.exists(s.domain(), "sam").await?);

    // Not before signing in.
    let mut c = unauthenticated(&s).await?;
    let r = c.iq_set(None, Element::new("query", ns::REGISTER).child(Element::new("remove", ns::REGISTER))).await?;
    assert_eq!(condition(&r), "not-authorized");
    Ok(())
}
