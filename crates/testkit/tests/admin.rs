//! The admin API (docs/admin-api.md): the socket, HTTP, accounts, invites, the snapshot, and
//! account export and import (XEP-0227).

use crate::common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use common::*;
use quark::accounts::ScramHash;
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{message, Client, Options, TestServer};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn the_socket_and_token_are_private_and_answer() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let s = TestServer::start().await?;
    let dir = s.srv.config().server.data_dir.clone();
    for f in [quark::admin::SOCKET, quark::admin::TOKEN] {
        assert_eq!(std::fs::metadata(dir.join(f))?.permissions().mode() & 0o777, 0o600, "{f}");
    }
    let line = quark::admin::request(&dir.join(quark::admin::SOCKET), "{\n  \"cmd\": \"status\"\n}").await?;
    let v: serde_json::Value = serde_json::from_str(&line)?;
    assert_eq!((v["ok"].clone(), v["value"]["server"].clone()), (json!(true), json!("quark")));

    let bad = quark::admin::request(&dir.join(quark::admin::SOCKET), "{nope").await?;
    assert!(bad.contains("\"code\":\"invalid\""), "{bad}");
    assert_eq!(admin_code(&s, json!({ "cmd": "no.such" })).await, "invalid");
    Ok(())
}

/// Sends one HTTP request to `router` and returns the status line and body.
async fn http(router: axum::Router, auth: Option<&str>, body: &str) -> anyhow::Result<(u16, String)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move { axum::serve(listener, router).await });
    let mut c = tokio::net::TcpStream::connect(addr).await?;
    let auth = auth.map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
    let req = format!(
        "POST /admin/api HTTP/1.1\r\nHost: x\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    c.write_all(req.as_bytes()).await?;
    let mut out = String::new();
    c.read_to_string(&mut out).await?;
    let status = out.split(' ').nth(1).unwrap_or_default().parse()?;
    Ok((status, out.split("\r\n\r\n").nth(1).unwrap_or_default().to_string()))
}

#[tokio::test]
async fn http_needs_the_token_and_the_setting() -> anyhow::Result<()> {
    let on = TestServer::start_with(Options { extra_config: "[http]\nadmin_api = true\n".into(), ..Default::default() }).await?;
    let token = quark::admin::load_or_create_token(&on.srv.config().server.data_dir)?;
    let status = r#"{"cmd":"status"}"#;
    assert_eq!(http(quark::admin::http_router(&on.srv), None, status).await?.0, 401);
    assert_eq!(http(quark::admin::http_router(&on.srv), Some("wrong"), status).await?.0, 401);
    let (code, body) = http(quark::admin::http_router(&on.srv), Some(&token), status).await?;
    assert_eq!(code, 200);
    assert!(body.contains("\"ok\":true"), "{body}");

    let off = TestServer::start().await?;
    let token = quark::admin::load_or_create_token(&off.srv.config().server.data_dir)?;
    assert_eq!(http(quark::admin::http_router(&off.srv), Some(&token), status).await?.0, 404);
    Ok(())
}

#[tokio::test]
async fn accounts_are_made_changed_and_deleted() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let host = s.domain();
    admin_ok(&s, json!({ "cmd": "account.create", "args": { "host": host, "user": "Sam", "password": "password-1", "role": "member" } }))
        .await;
    assert!(can_sign_in(&s, "sam", "password-1").await);
    assert_eq!(
        admin_code(&s, json!({ "cmd": "account.create", "args": { "host": host, "user": "sam", "password": "password-1" } })).await,
        "exists"
    );
    assert_eq!(
        admin_code(&s, json!({ "cmd": "account.create", "args": { "host": host, "user": "-x", "password": "password-1" } })).await,
        "invalid"
    );
    assert_eq!(
        admin_code(&s, json!({ "cmd": "account.create", "args": { "host": host, "user": "kim", "password": "short" } })).await,
        "invalid"
    );
    assert_eq!(
        admin_code(&s, json!({ "cmd": "account.create", "args": { "host": "elsewhere.test", "user": "kim", "password": "password-1" } }))
            .await,
        "not_found"
    );

    // A bad password changes nothing, not even the role given with it.
    let bad = json!({ "cmd": "account.update", "args": { "host": host, "user": "sam", "password": "short", "role": "admin" } });
    assert_eq!(admin_code(&s, bad).await, "invalid");
    assert_eq!(s.srv.accounts.info(host, "sam").await?.map(|i| i.role), Some(quark::accounts::Role::Member));

    let mut phone = s.login_as("sam", "password-1", "phone").await?;
    let v = admin_ok(&s, json!({ "cmd": "account.update", "args": { "host": host, "user": "sam", "password": "password-2" } })).await;
    assert_eq!(v["closed"], 1);
    assert_eq!(stream_error(&mut phone).await, "reset");
    assert!(!can_sign_in(&s, "sam", "password-1").await);
    assert!(can_sign_in(&s, "sam", "password-2").await);

    let _laptop = s.login_as("sam", "password-2", "laptop").await?;
    let mut phone = s.login_as("sam", "password-2", "phone").await?;
    let v = admin_ok(&s, json!({ "cmd": "account.update", "args": { "host": host, "user": "sam", "signOut": "phone" } })).await;
    assert_eq!(v["closed"], 1);
    assert_eq!(stream_error(&mut phone).await, "reset");

    admin_ok(&s, json!({ "cmd": "account.delete", "args": { "host": host, "user": "sam" } })).await;
    admin_ok(&s, json!({ "cmd": "account.delete", "args": { "host": host, "user": "sam" } })).await;
    assert!(!s.srv.accounts.exists(host, "sam").await?);
    assert_eq!(
        admin_code(&s, json!({ "cmd": "account.update", "args": { "host": host, "user": "sam", "enabled": true } })).await,
        "not_found"
    );
    Ok(())
}

#[tokio::test]
async fn turning_an_account_off_closes_its_sessions() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("sam", "password-1").await?;
    let mut phone = s.online("sam", "password-1", "phone").await?;
    let mut laptop = s.online("sam", "password-1", "laptop").await?;
    let v = admin_ok(&s, json!({ "cmd": "account.update", "args": { "host": s.domain(), "user": "sam", "enabled": false } })).await;
    assert_eq!(v["closed"], 2);
    assert_eq!(stream_error(&mut phone).await, "not-authorized");
    assert_eq!(stream_error(&mut laptop).await, "not-authorized");
    assert!(!can_sign_in(&s, "sam", "password-1").await);

    // Off and a new password at once: still one sign-out per device, and it stays off.
    let _ = admin_ok(
        &s,
        json!({ "cmd": "account.update", "args": { "host": s.domain(), "user": "sam", "enabled": false, "password": "password-2", "signOut": true } }),
    )
    .await;
    assert!(!can_sign_in(&s, "sam", "password-2").await);

    admin_ok(&s, json!({ "cmd": "account.update", "args": { "host": s.domain(), "user": "sam", "enabled": true } })).await;
    assert!(can_sign_in(&s, "sam", "password-2").await);
    Ok(())
}

#[tokio::test]
async fn invites_are_made_peeked_and_revoked() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let host = s.domain();
    let inv = admin_ok(
        &s,
        json!({ "cmd": "invite.create", "args": { "host": host, "username": null, "role": "member", "days": 7, "reusable": false } }),
    )
    .await;
    let token = inv["token"].as_str().unwrap_or_default().to_string();
    assert_eq!(inv["uri"], format!("xmpp:{host}?register;preauth={token}"));
    assert_eq!(inv["page"], format!("https://{host}/invite/{token}"));
    let peek = admin_ok(&s, json!({ "cmd": "invite.peek", "args": { "host": host, "token": token } })).await;
    assert_eq!(peek["uri"], inv["uri"]);

    let named = admin_ok(
        &s,
        json!({ "cmd": "invite.create", "args": { "host": host, "username": "Kim", "role": "admin", "days": 1, "reusable": false } }),
    )
    .await;
    assert_eq!(named["uri"], format!("xmpp:kim@{host}?register;preauth={}", named["token"].as_str().unwrap_or_default()));

    s.add_user("sam", "password-1").await?;
    let taken =
        json!({ "cmd": "invite.create", "args": { "host": host, "username": "sam", "role": "member", "days": 1, "reusable": false } });
    assert_eq!(admin_code(&s, taken).await, "exists");
    for days in [0.0, -1.0, 4000.0] {
        let bad = json!({ "cmd": "invite.create", "args": { "host": host, "username": null, "role": "member", "days": days, "reusable": false } });
        assert_eq!(admin_code(&s, bad).await, "invalid");
    }

    admin_ok(&s, json!({ "cmd": "invite.revoke", "args": { "host": host, "token": token } })).await;
    assert_eq!(admin_ok(&s, json!({ "cmd": "invite.peek", "args": { "host": host, "token": token } })).await, json!(null));
    Ok(())
}

#[tokio::test]
async fn the_snapshot_shows_accounts_devices_and_invites() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("sam", "password-1").await?;
    s.add_admin("kim", "password-2").await?;
    let _phone = s.online("sam", "password-1", "Conversations.Ab3x").await?;
    admin_ok(
        &s,
        json!({ "cmd": "invite.create", "args": { "host": s.domain(), "username": null, "role": "member", "days": 7, "reusable": true } }),
    )
    .await;

    let snap = admin_ok(&s, json!({ "cmd": "snapshot" })).await;
    assert_eq!(snap["server"], "quark");
    assert_eq!(snap["stats"]["c2s"], 1);
    let h = &snap["hosts"][0];
    assert_eq!(h["host"], s.domain());
    assert_eq!(h["settings"]["signUp"], "invite");
    assert_eq!(h["admins"], json!([format!("admin@{}", s.domain())]));
    assert_eq!(h["groupsHost"], format!("rooms.{}", s.domain()));
    let accounts = h["accounts"].as_array().cloned().unwrap_or_default();
    assert_eq!(accounts.iter().map(|a| a["user"].as_str().unwrap_or_default()).collect::<Vec<_>>(), ["kim", "sam"]);
    assert_eq!(accounts[0]["role"], "admin");
    let devices = accounts[1]["devices"].as_array().cloned().unwrap_or_default();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["resource"], "Conversations.Ab3x");
    assert_eq!(devices[0]["client"], "Conversations");
    assert_eq!(devices[0]["secure"], true);
    assert_eq!(h["invites"].as_array().map(Vec::len), Some(1));
    let modules: Vec<&str> = h["modules"].as_array().map(|m| m.iter().filter_map(|v| v.as_str()).collect()).unwrap_or_default();
    for m in ["tls", "saslauth", "smacks", "register", "invites", "roster", "s2s"] {
        assert!(modules.contains(&m), "{m} missing from {modules:?}");
    }
    assert_eq!(modules.len(), modules.iter().collect::<std::collections::HashSet<_>>().len(), "listed twice: {modules:?}");
    assert_eq!(h["requireEncryption"], true);
    Ok(())
}

#[tokio::test]
async fn server_messages_reach_people() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("sam", "password-1").await?;
    let mut sam = s.online("sam", "password-1", "phone").await?;
    let to = format!("sam@{}", s.domain());
    admin_ok(&s, json!({ "cmd": "message.send", "args": { "from": s.domain(), "to": to, "body": "Backups failed", "subject": "Alert" } }))
        .await;
    let m = sam.expect(|e| e.name() == "message").await?;
    assert_eq!(m.attr("from"), Some(s.domain()));
    assert_eq!(m.child_text("body", ns::CLIENT).as_deref(), Some("Backups failed"));
    let nobody = json!({ "cmd": "message.send", "args": { "from": s.domain(), "to": format!("nobody@{}", s.domain()), "body": "x" } });
    assert_eq!(admin_code(&s, nobody).await, "not_found");
    Ok(())
}

// ------------------------------------------------------------------------------ export / import

async fn plain_sign_in(s: &TestServer, user: &str, password: &str) -> anyhow::Result<Client> {
    let mut c = unauthenticated(s).await?;
    c.auth_plain(user, password).await?;
    c.bind(Some("plain")).await?;
    Ok(c)
}

#[tokio::test]
async fn accounts_move_with_their_contacts_and_profile() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let host = s.domain().to_string();
    s.add_admin("sam", "password-1").await?;
    s.add_user("kim", "password-2").await?;
    let mut sam = s.online("sam", "password-1", "phone").await?;
    let item = Element::new("item", ns::ROSTER).attr_set("jid", format!("kim@{host}")).attr_set("name", "Kim").text_child(
        "group",
        ns::ROSTER,
        "Friends",
    );
    // Roster IQs go to the account's own address (the server domain doesn't answer them).
    let me = format!("sam@{host}");
    let r = sam.iq_set(Some(&me), Element::new("query", ns::ROSTER).child(item)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    sam.iq_set(None, Element::new("vCard", ns::VCARD).text_child("FN", ns::VCARD, "Sam Smith")).await?;
    sam.close().await?;
    // Something waits for kim while she's away.
    let mut kim_sender = s.online("sam", "password-1", "laptop").await?;
    kim_sender.send(&message(&format!("kim@{host}"), "chat", "see you at 8")).await?;
    kim_sender.iq_get(Some(&host), Element::new("ping", ns::PING)).await?;
    kim_sender.close().await?;

    let out = admin_ok(&s, json!({ "cmd": "account.export", "args": { "host": host } })).await;
    assert_eq!(out["accounts"], 2);
    let xml = out["xml"].as_str().unwrap_or_default().to_string();
    assert!(xml.starts_with("<?xml") && xml.contains("urn:xmpp:pie:0") && xml.contains("SCRAM-SHA-256"));
    assert!(!xml.contains("password-1"), "passwords never leave the server");
    let one = admin_ok(&s, json!({ "cmd": "account.export", "args": { "host": host, "users": ["kim"] } })).await;
    assert_eq!(one["accounts"], 1);
    assert_eq!(admin_code(&s, json!({ "cmd": "account.export", "args": { "host": host, "users": ["nobody"] } })).await, "not_found");

    // To a fresh server.
    let t = TestServer::start().await?;
    let r = admin_ok(&t, json!({ "cmd": "account.import", "args": { "xml": xml } })).await;
    assert_eq!(r["created"].as_array().map(Vec::len), Some(2), "{r}");
    assert!(r["notes"].as_array().is_some_and(Vec::is_empty), "{r}");
    assert_eq!(t.srv.accounts.info(&host, "sam").await?.map(|i| i.role), Some(quark::accounts::Role::Admin));

    let mut sam = t.online("sam", "password-1", "phone").await?;
    let roster = sam.iq_get(Some(&me), Element::new("query", ns::ROSTER)).await?;
    let item = roster
        .get_child("query", ns::ROSTER)
        .and_then(|q| q.get_child("item", ns::ROSTER))
        .cloned()
        .unwrap_or_else(|| Element::new("none", ""));
    assert_eq!(item.attr("jid"), Some(format!("kim@{host}").as_str()));
    assert_eq!(item.attr("name"), Some("Kim"));
    assert_eq!(item.child_text("group", ns::ROSTER).as_deref(), Some("Friends"));
    let vcard = sam.iq_get(None, Element::new("vCard", ns::VCARD)).await?;
    assert_eq!(vcard.get_child("vCard", ns::VCARD).and_then(|v| v.child_text("FN", ns::VCARD)).as_deref(), Some("Sam Smith"));

    let mut kim = t.online("kim", "password-2", "phone").await?;
    let waiting = kim.expect(|e| e.name() == "message").await?;
    assert_eq!(waiting.child_text("body", ns::CLIENT).as_deref(), Some("see you at 8"));
    assert!(waiting.has_child("delay", ns::DELAY));

    // Again: everything is there already.
    let again = admin_ok(&t, json!({ "cmd": "account.import", "args": { "xml": xml } })).await;
    assert_eq!(again["skipped"].as_array().map(Vec::len), Some(2), "{again}");
    Ok(())
}

/// What Prosody exports: SCRAM-SHA-1 keys only, and a plain-text password from older setups.
fn prosody_export(host: &str, password: &str) -> String {
    let h = ScramHash::Sha1;
    let salt = b"0123456789abcdef";
    let (stored, server) = h.keys(&h.salted_password(password.as_bytes(), salt, 4096));
    format!(
        "<?xml version='1.0' encoding='utf-8'?>\
         <server-data xmlns='urn:xmpp:pie:0'><host jid='{host}'>\
           <user name='Ana'><scram-credentials xmlns='urn:xmpp:pie:0#scram' mechanism='SCRAM-SHA-1'>\
             <iter-count>4096</iter-count><salt>{}</salt><server-key>{}</server-key><stored-key>{}</stored-key>\
           </scram-credentials>\
           <query xmlns='jabber:iq:roster'><item jid='bo@{host}' subscription='both'/></query></user>\
           <user name='bo' password='abc'/>\
           <user name='cy'/>\
           <user name='Not Valid'/>\
         </host><host jid='other.test'><user name='dee' password='password-9'/></host></server-data>",
        B64.encode(salt),
        B64.encode(server),
        B64.encode(stored)
    )
}

#[tokio::test]
async fn prosody_exports_import_and_weak_keys_heal() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let r = admin_ok(&s, json!({ "cmd": "account.import", "args": { "xml": prosody_export(s.domain(), "old password") } })).await;
    let created: Vec<&str> = r["created"].as_array().map(|a| a.iter().filter_map(|v| v.as_str()).collect()).unwrap_or_default();
    assert_eq!(created, [format!("ana@{}", s.domain()), format!("bo@{}", s.domain()), format!("cy@{}", s.domain())]);
    let skipped = r["skipped"].as_array().cloned().unwrap_or_default();
    assert_eq!(skipped.len(), 2, "{r}");
    assert!(skipped.iter().any(|v| v["jid"] == "dee@other.test"));
    let notes = r["notes"].to_string();
    assert!(notes.contains("ana@") && notes.contains("SCRAM-SHA-1") && notes.contains("cy@"), "{notes}");

    // Short legacy passwords keep working.
    assert!(can_sign_in(&s, "bo", "abc").await);
    // SHA-1 keys only: SCRAM-SHA-256 fails, SCRAM-SHA-1 works, and one PLAIN sign-in heals it.
    assert!(!can_sign_in(&s, "ana", "old password").await);
    let mut c = unauthenticated(&s).await?;
    c.auth_scram("SCRAM-SHA-1", "ana", "old password").await?;
    let mut ana = plain_sign_in(&s, "ana", "old password").await?;
    let roster = ana.iq_get(Some(&format!("ana@{}", s.domain())), Element::new("query", ns::ROSTER)).await?;
    assert!(roster.to_xml().contains(&format!("bo@{}", s.domain())));
    assert!(can_sign_in(&s, "ana", "old password").await);

    assert_eq!(admin_code(&s, json!({ "cmd": "account.import", "args": { "xml": "<x/>" } })).await, "invalid");
    assert_eq!(
        admin_code(&s, json!({ "cmd": "account.import", "args": { "xml": "<server-data xmlns='urn:xmpp:pie:0'/>" } })).await,
        "invalid"
    );
    Ok(())
}
