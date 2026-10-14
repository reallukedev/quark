//! The MCP tools against a fake admin socket that records requests and answers canned JSON.

// Test helpers: a failure should panic the test.
#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use quark_mcp::{AdminClient, QuarkMcp};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::ServiceExt;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

type Answer = dyn Fn(&str, &Value) -> Value + Send + Sync;

struct Fake {
    _dir: tempfile::TempDir,
    socket: std::path::PathBuf,
    requests: Arc<Mutex<Vec<Value>>>,
}

impl Fake {
    fn client(&self) -> QuarkMcp {
        QuarkMcp::new(AdminClient::new(&self.socket))
    }

    /// The requests seen so far, as (cmd, args).
    fn seen(&self) -> Vec<(String, Value)> {
        self.requests.lock().unwrap().iter().map(|r| (r["cmd"].as_str().unwrap_or_default().to_string(), r["args"].clone())).collect()
    }

    fn last(&self, cmd: &str) -> Value {
        self.seen().into_iter().rev().find(|(c, _)| c == cmd).map(|(_, a)| a).unwrap_or_else(|| panic!("no {cmd} request"))
    }
}

/// A fake admin socket: one JSON line in, one JSON line out, per connection.
async fn fake(answer: impl Fn(&str, &Value) -> Value + Send + Sync + 'static) -> Fake {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("admin.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let (reqs, answer): (_, Arc<Answer>) = (requests.clone(), Arc::new(answer));
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (reqs, answer) = (reqs.clone(), answer.clone());
            tokio::spawn(async move {
                let (rd, mut wr) = stream.into_split();
                let mut line = String::new();
                BufReader::new(rd).read_line(&mut line).await.unwrap();
                let req: Value = serde_json::from_str(&line).unwrap();
                let cmd = req["cmd"].as_str().unwrap_or_default().to_string();
                let out = answer(&cmd, &req["args"]);
                reqs.lock().unwrap().push(req);
                wr.write_all(format!("{out}\n").as_bytes()).await.unwrap();
            });
        }
    });
    Fake { _dir: dir, socket, requests }
}

fn ok(v: Value) -> Value {
    json!({ "ok": true, "value": v })
}

fn settings() -> Value {
    json!({
        "signUp": "invite", "history": "3m",
        "groups": { "on": true, "host": "rooms.chat.test", "whoCreates": "everyone" },
        "files": { "on": true, "host": "upload.chat.test", "maxMb": 100, "keepDays": 30 },
        "push": true, "federation": true, "web": true,
        "calls": { "on": true, "host": "chat.test" },
        "welcome": null, "contact": null
    })
}

fn snapshot(hosts: &[&str]) -> Value {
    let hosts: Vec<Value> = hosts
        .iter()
        .map(|h| {
            json!({
                "host": h,
                "settings": settings(),
                "admins": [],
                "accounts": [
                    { "user": "alice", "role": "admin", "enabled": true, "created": 1, "passwordChanged": null, "lastActive": 5,
                      "devices": [{ "resource": "phone", "client": "Conversations", "ip": "192.0.2.1", "secure": true,
                                    "since": 3, "resumable": true, "inactive": false }] },
                    { "user": "bob", "role": "member", "enabled": false, "created": 2, "passwordChanged": null, "lastActive": null,
                      "devices": [] }
                ],
                "invites": [],
                "rooms": [{ "jid": format!("family@rooms.{h}"), "name": "Family", "description": null, "public": false,
                            "membersOnly": true, "persistent": true, "occupants": 2 }],
                "groupsHost": format!("rooms.{h}"),
                "filesHost": format!("upload.{h}"),
                "modules": ["muc"],
                "requireEncryption": true,
                "tls": null
            })
        })
        .collect();
    json!({
        "server": "quark", "version": "0.1.0", "startedAt": 1_000, "configFile": "/etc/quark/quark.toml",
        "certDir": "/etc/quark/certs", "hosts": hosts,
        "turn": { "builtIn": true, "port": 3478, "relayMin": 49160, "relayMax": 49200, "running": true },
        "stats": { "c2s": 1, "s2sIn": 0, "s2sOut": 0, "stanzasIn": 10, "stanzasOut": 12 }
    })
}

/// A server with one domain that says yes to everything.
async fn one_domain() -> Fake {
    fake(|cmd, _| match cmd {
        "snapshot" => ok(snapshot(&["chat.test"])),
        "account.update" => ok(json!({ "closed": 2 })),
        "settings.get" => ok(settings()),
        "settings.set" => ok(json!({ "applied": true, "notes": ["Sign-up is open now."] })),
        "invite.create" => ok(json!({ "token": "tok", "uri": "xmpp:chat.test?register;preauth=tok" })),
        "room.create" => ok(json!({ "jid": "book-club@rooms.chat.test" })),
        "config.get" => ok(json!({ "file": "/etc/quark/quark.toml", "text": "[server]\n" })),
        "config.check" => ok(json!({ "ok": true, "line": null, "message": "Fine." })),
        "reload" => ok(json!({ "reloaded": true, "certs": 1 })),
        _ => ok(json!(true)),
    })
    .await
}

fn parsed(r: Result<String, String>) -> Value {
    serde_json::from_str(&r.expect("the tool succeeds")).expect("tools answer JSON")
}

#[tokio::test]
async fn create_account_generates_a_password_and_returns_it_once() {
    let f = one_domain().await;
    let out = parsed(
        f.client()
            .create_account(Parameters(quark_mcp::CreateAccountParams {
                host: None,
                user: "Sam".into(),
                password: None,
                role: quark_mcp::Role::Member,
            }))
            .await,
    );
    let args = f.last("account.create");
    assert_eq!(args["host"], "chat.test");
    assert_eq!(args["user"], "sam");
    assert_eq!(args["role"], "member");
    assert_eq!(out["password"], args["password"]);
    assert_eq!(out["created"], "sam@chat.test");
}

#[tokio::test]
async fn a_given_password_is_used_and_not_echoed() {
    let f = one_domain().await;
    let out = parsed(
        f.client()
            .create_account(Parameters(quark_mcp::CreateAccountParams {
                host: Some("chat.test".into()),
                user: "sam".into(),
                password: Some("hunter2hunter2".into()),
                role: quark_mcp::Role::Admin,
            }))
            .await,
    );
    assert_eq!(f.last("account.create")["password"], "hunter2hunter2");
    assert_eq!(f.last("account.create")["role"], "admin");
    assert!(out.get("password").is_none());
    // The host was given, so no snapshot was needed.
    assert!(f.seen().iter().all(|(c, _)| c != "snapshot"));
}

#[tokio::test]
async fn refusals_come_back_as_tool_errors_with_the_servers_sentence() {
    let f = fake(|cmd, _| match cmd {
        "snapshot" => ok(snapshot(&["chat.test"])),
        _ => json!({ "ok": false, "code": "exists", "error": "There's already an account called sam@chat.test." }),
    })
    .await;
    let r = f
        .client()
        .create_account(Parameters(quark_mcp::CreateAccountParams {
            host: None,
            user: "sam".into(),
            password: None,
            role: Default::default(),
        }))
        .await;
    assert_eq!(r.unwrap_err(), "There's already an account called sam@chat.test.");
}

#[tokio::test]
async fn several_domains_need_the_host_spelled_out() {
    let f = fake(|_, _| ok(snapshot(&["a.test", "b.test"]))).await;
    let c = f.client();
    let e = c.reset_password(Parameters(quark_mcp::UserParams { host: None, user: "alice".into() })).await.unwrap_err();
    assert!(e.contains("a.test, b.test"), "{e}");
    let e = c.list_accounts(Parameters(quark_mcp::HostParam { host: Some("c.test".into()) })).await.unwrap_err();
    assert!(e.contains("isn't a domain"), "{e}");
    let ok = parsed(c.list_accounts(Parameters(quark_mcp::HostParam { host: Some("B.test".into()) })).await);
    assert_eq!(ok["host"], "b.test");
}

#[tokio::test]
async fn reset_password_sets_a_new_one_and_reports_signed_out_devices() {
    let f = one_domain().await;
    let out = parsed(f.client().reset_password(Parameters(quark_mcp::UserParams { host: None, user: "alice".into() })).await);
    let args = f.last("account.update");
    assert_eq!(args["user"], "alice");
    assert_eq!(out["password"], args["password"]);
    assert_eq!(out["devicesSignedOut"], 2);
    assert_eq!(args.as_object().map(|o| o.len()), Some(3));
}

#[tokio::test]
async fn enable_disable_and_sign_out_map_to_account_update() {
    let f = one_domain().await;
    let c = f.client();
    c.disable_account(Parameters(quark_mcp::UserParams { host: None, user: "bob".into() })).await.unwrap();
    assert_eq!(f.last("account.update")["enabled"], false);
    c.enable_account(Parameters(quark_mcp::UserParams { host: None, user: "bob".into() })).await.unwrap();
    assert_eq!(f.last("account.update")["enabled"], true);
    c.sign_out_device(Parameters(quark_mcp::SignOutParams { host: None, user: "alice".into(), resource: Some("phone".into()) }))
        .await
        .unwrap();
    assert_eq!(f.last("account.update")["signOut"], "phone");
    c.sign_out_device(Parameters(quark_mcp::SignOutParams { host: None, user: "alice".into(), resource: None })).await.unwrap();
    assert_eq!(f.last("account.update")["signOut"], true);
    c.delete_account(Parameters(quark_mcp::UserParams { host: None, user: "bob".into() })).await.unwrap();
    assert_eq!(f.last("account.delete"), json!({ "host": "chat.test", "user": "bob" }));
}

#[tokio::test]
async fn listings_come_from_the_snapshot() {
    let f = one_domain().await;
    let c = f.client();
    let accounts = parsed(c.list_accounts(Parameters(Default::default())).await);
    assert_eq!(accounts["accounts"][0]["devicesOnline"], 1);
    assert_eq!(accounts["accounts"][1]["enabled"], false);
    assert!(accounts["accounts"][0].get("devices").is_none());

    let devices = parsed(c.list_devices(Parameters(quark_mcp::DevicesParams { host: None, user: Some("alice".into()) })).await);
    assert_eq!(devices["accounts"].as_array().map(Vec::len), Some(1));
    assert_eq!(devices["accounts"][0]["devices"][0]["client"], "Conversations");
    let e = c.list_devices(Parameters(quark_mcp::DevicesParams { host: None, user: Some("zed".into()) })).await.unwrap_err();
    assert_eq!(e, "There's no account called zed@chat.test.");

    let rooms = parsed(c.list_rooms(Parameters(Default::default())).await);
    assert_eq!(rooms["rooms"][0]["jid"], "family@rooms.chat.test");

    let status = parsed(c.server_status().await);
    assert_eq!(status["hosts"][0]["accounts"], 2);
    assert_eq!(status["hosts"][0]["devicesOnline"], 1);
    assert_eq!(status["turn"]["running"], true);
}

#[tokio::test]
async fn update_settings_merges_the_changes_into_the_current_settings() {
    let f = one_domain().await;
    let changes = json!({ "signUp": "open", "files": { "maxMb": 500 } }).as_object().cloned().unwrap();
    let out = parsed(f.client().update_settings(Parameters(quark_mcp::UpdateSettingsParams { host: None, changes })).await);
    let sent = &f.last("settings.set")["settings"];
    assert_eq!(sent["signUp"], "open");
    assert_eq!(sent["files"], json!({ "on": true, "host": "upload.chat.test", "maxMb": 500, "keepDays": 30 }));
    assert_eq!(sent["groups"], settings()["groups"]);
    assert_eq!(out["notes"], json!(["Sign-up is open now."]));

    let none = serde_json::Map::new();
    assert!(f.client().update_settings(Parameters(quark_mcp::UpdateSettingsParams { host: None, changes: none })).await.is_err());
}

#[tokio::test]
async fn invites_rooms_messages_and_config_map_to_their_commands() {
    let f = one_domain().await;
    let c = f.client();
    let inv = parsed(
        c.create_invite(Parameters(quark_mcp::CreateInviteParams {
            host: None,
            username: Some("Kim".into()),
            role: Default::default(),
            days: None,
            reusable: false,
        }))
        .await,
    );
    assert_eq!(inv["token"], "tok");
    assert_eq!(f.last("invite.create"), json!({ "host": "chat.test", "username": "kim", "role": "member", "days": 7, "reusable": false }));
    c.revoke_invite(Parameters(quark_mcp::RevokeInviteParams { host: None, token: " tok ".into() })).await.unwrap();
    assert_eq!(f.last("invite.revoke"), json!({ "host": "chat.test", "token": "tok" }));

    c.create_room(Parameters(quark_mcp::CreateRoomParams {
        host: None,
        room: "Book-Club".into(),
        service: None,
        name: Some("Book club".into()),
        description: None,
        public: None,
        members_only: false,
        owner: None,
    }))
    .await
    .unwrap();
    let room = f.last("room.create");
    assert_eq!(
        (room["service"].as_str(), room["room"].as_str(), room["public"].as_bool()),
        (Some("rooms.chat.test"), Some("book-club"), Some(true))
    );
    c.destroy_room(Parameters(quark_mcp::DestroyRoomParams { jid: "family@rooms.chat.test".into(), reason: None })).await.unwrap();
    assert_eq!(f.last("room.destroy")["jid"], "family@rooms.chat.test");

    c.send_message(Parameters(quark_mcp::SendMessageParams {
        from: None,
        to: "alice@chat.test".into(),
        body: "Backup done.".into(),
        subject: None,
    }))
    .await
    .unwrap();
    assert_eq!(f.last("message.send"), json!({ "from": "chat.test", "to": "alice@chat.test", "body": "Backup done." }));

    let check = parsed(c.check_config(Parameters(Default::default())).await);
    assert_eq!(check["ok"], true);
    assert_eq!(f.last("config.check")["text"], "[server]\n");
    assert_eq!(parsed(c.reload().await)["reloaded"], true);
}

#[tokio::test]
async fn an_unreachable_server_is_a_plain_tool_error() {
    let c = QuarkMcp::new(AdminClient::new("/nonexistent/admin.sock"));
    let e = c.server_status().await.unwrap_err();
    assert!(e.contains("isn't answering"), "{e}");
}

/// Sends one JSON-RPC message; for requests, reads lines until the answer with the same id.
async fn rpc(
    w: &mut (impl tokio::io::AsyncWrite + Unpin),
    lines: &mut tokio::io::Lines<BufReader<impl tokio::io::AsyncRead + Unpin>>,
    msg: Value,
) -> Option<Value> {
    w.write_all(format!("{msg}\n").as_bytes()).await.unwrap();
    let id = msg.get("id")?.clone();
    loop {
        let line = tokio::time::timeout(std::time::Duration::from_secs(5), lines.next_line()).await.unwrap().unwrap()?;
        let v: Value = serde_json::from_str(&line).unwrap();
        if v.get("id") == Some(&id) {
            return Some(v);
        }
    }
}

/// Drives the real MCP protocol (JSON-RPC lines) over an in-memory pipe.
#[tokio::test]
async fn speaks_mcp_over_a_stream() {
    let f = fake(|cmd, _| match cmd {
        "snapshot" => ok(snapshot(&["chat.test"])),
        _ => json!({ "ok": false, "code": "not_found", "error": "There's no account called zed@chat.test." }),
    })
    .await;
    let (client, server) = tokio::io::duplex(1 << 16);
    let mcp = f.client();
    let task = tokio::spawn(async move {
        let running = mcp.serve(tokio::io::split(server)).await.expect("the handshake works");
        let _ = running.waiting().await;
    });
    let (rd, mut w) = tokio::io::split(client);
    let mut lines = BufReader::new(rd).lines();

    let init = rpc(
        &mut w,
        &mut lines,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "test", "version": "1" } } }),
    )
    .await
    .unwrap();
    assert_eq!(init["result"]["serverInfo"]["name"], "quark");
    assert!(init["result"]["capabilities"]["tools"].is_object());
    assert!(init["result"]["instructions"].as_str().is_some_and(|i| i.contains("Quark")));
    rpc(&mut w, &mut lines, json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })).await;

    let list = rpc(&mut w, &mut lines, json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" })).await.unwrap();
    let tools = list["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 19);
    let delete = tools.iter().find(|t| t["name"] == "delete_account").unwrap();
    assert_eq!(delete["annotations"]["destructiveHint"], true);
    assert_eq!(delete["inputSchema"]["required"], json!(["user"]));

    let call = rpc(
        &mut w,
        &mut lines,
        json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": { "name": "list_accounts", "arguments": {} } }),
    )
    .await
    .unwrap();
    assert_ne!(call["result"]["isError"], true);
    assert!(call["result"]["content"][0]["text"].as_str().is_some_and(|t| t.contains("alice")));

    let refused = rpc(
        &mut w,
        &mut lines,
        json!({ "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": { "name": "delete_account", "arguments": { "user": "zed", "host": "chat.test" } } }),
    )
    .await
    .unwrap();
    assert_eq!(refused["result"]["isError"], true);
    assert_eq!(refused["result"]["content"][0]["text"], "There's no account called zed@chat.test.");
    task.abort();
}
