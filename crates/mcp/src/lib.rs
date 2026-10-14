//! `quark mcp`: a Model Context Protocol server (stdio) that lets an AI assistant look after a
//! running Quark: accounts, devices, invites, group chats, settings, the config file. It speaks
//! the same admin protocol as `quark ctl` over the admin socket, so it needs no port and no
//! token, and can do exactly what the socket's owner can.

pub mod admin;

use std::path::PathBuf;

use rand::Rng;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Map, Value};

pub use admin::{AdminClient, AdminError};

/// What every tool returns: JSON text on success, a plain sentence on failure (a tool error).
pub type ToolResult = Result<String, String>;

/// Serves the tools on stdin/stdout until the client goes away.
pub async fn serve_stdio(socket: PathBuf) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let service = QuarkMcp::new(AdminClient::new(socket)).serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}

/// A readable password: four groups of four from an alphabet without look-alikes (about 79 bits).
pub fn readable_password() -> String {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    let mut rng = rand::rngs::OsRng;
    let mut s = String::with_capacity(19);
    for i in 0..16 {
        if i > 0 && i % 4 == 0 {
            s.push('-');
        }
        s.push(char::from(ALPHABET[rng.gen_range(0..ALPHABET.len())]));
    }
    s
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct HostParam {
    /// The chat domain, e.g. chat.example.com. Can be left out when the server has only one.
    #[serde(default)]
    pub host: Option<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct DevicesParams {
    /// The chat domain. Can be left out when the server has only one.
    #[serde(default)]
    pub host: Option<String>,
    /// Only this account's devices (the part before the @).
    #[serde(default)]
    pub user: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    #[default]
    Member,
    Admin,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Role::Member => "member",
            Role::Admin => "admin",
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateAccountParams {
    #[serde(default)]
    pub host: Option<String>,
    /// The username (the part before the @): lowercase letters, digits, dots, dashes, underscores.
    pub user: String,
    /// A password to set. Leave it out to have a readable one generated and shown once.
    #[serde(default)]
    pub password: Option<String>,
    /// "member" (the default) or "admin".
    #[serde(default)]
    pub role: Role,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UserParams {
    #[serde(default)]
    pub host: Option<String>,
    /// The username (the part before the @).
    pub user: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SignOutParams {
    #[serde(default)]
    pub host: Option<String>,
    /// The username (the part before the @).
    pub user: String,
    /// The device to sign out (its resource, from list_devices). Leave it out to sign out all.
    #[serde(default)]
    pub resource: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateInviteParams {
    #[serde(default)]
    pub host: Option<String>,
    /// Reserve this username for the person invited. Leave it out to let them choose.
    #[serde(default)]
    pub username: Option<String>,
    /// "member" (the default) or "admin".
    #[serde(default)]
    pub role: Role,
    /// Days until the invite stops working (default 7).
    #[serde(default)]
    pub days: Option<u32>,
    /// Whether several people can use it (default: one person).
    #[serde(default)]
    pub reusable: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RevokeInviteParams {
    #[serde(default)]
    pub host: Option<String>,
    /// The invite's token, from create_invite or the invites in server_status.
    pub token: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateRoomParams {
    #[serde(default)]
    pub host: Option<String>,
    /// The room's address part before the @, e.g. "family".
    pub room: String,
    /// The group chat service, e.g. rooms.chat.example.com. Defaults to the domain's own.
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Listed for everyone to find (default true).
    #[serde(default)]
    pub public: Option<bool>,
    /// Only members can join (default false).
    #[serde(default)]
    pub members_only: bool,
    /// The owner's chat address (bare JID), if someone should own it.
    #[serde(default)]
    pub owner: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DestroyRoomParams {
    /// The room's address, e.g. family@rooms.chat.example.com.
    pub jid: String,
    /// Shown to the people in the room.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateSettingsParams {
    #[serde(default)]
    pub host: Option<String>,
    /// Only the settings to change, in the shape get_settings returns, e.g.
    /// {"signUp": "open"} or {"files": {"maxMb": 500}}. Nested objects are merged.
    pub changes: Map<String, Value>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SendMessageParams {
    /// Who it's from: an account on this server (bare or full address) or the domain itself.
    /// Defaults to the domain, for a server notice.
    #[serde(default)]
    pub from: Option<String>,
    /// The recipient's chat address.
    pub to: String,
    pub body: String,
    #[serde(default)]
    pub subject: Option<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct CheckConfigParams {
    /// Config file text to check. Leave it out to check the file the server uses now.
    #[serde(default)]
    pub text: Option<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct NoParams {}

#[derive(Debug, Clone)]
pub struct QuarkMcp {
    admin: AdminClient,
    tool_router: ToolRouter<Self>,
}

fn pretty(v: &Value) -> ToolResult {
    serde_json::to_string_pretty(v).map_err(|e| e.to_string())
}

/// Merges `changes` into `base`: objects key by key, anything else replaced.
pub fn merge(base: &mut Value, changes: &Map<String, Value>) {
    let Value::Object(b) = base else {
        *base = Value::Object(changes.clone());
        return;
    };
    for (k, v) in changes {
        match (b.get_mut(k), v) {
            (Some(cur @ Value::Object(_)), Value::Object(inner)) => merge(cur, inner),
            _ => {
                b.insert(k.clone(), v.clone());
            }
        }
    }
}

#[tool_router(router = tool_router)]
impl QuarkMcp {
    pub fn new(admin: AdminClient) -> QuarkMcp {
        QuarkMcp { admin, tool_router: Self::tool_router() }
    }

    async fn call(&self, cmd: &str, args: Value) -> Result<Value, String> {
        self.admin.call(cmd, args).await.map_err(|e| e.to_string())
    }

    async fn snapshot(&self) -> Result<Value, String> {
        self.call("snapshot", json!({})).await
    }

    /// The snapshot entry for `host`, or the only domain when none is given. A blank name counts
    /// as none, as in [`QuarkMcp::host`], so `""` from a client picks the only domain.
    fn pick_host<'a>(snap: &'a Value, host: Option<&str>) -> Result<&'a Value, String> {
        let hosts = snap.get("hosts").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
        let name = |h: &Value| h.get("host").and_then(Value::as_str).unwrap_or_default().to_string();
        match host.map(str::trim).filter(|h| !h.is_empty()) {
            Some(want) => {
                let want = want.trim().to_ascii_lowercase();
                hosts.iter().find(|h| name(h) == want).ok_or_else(|| {
                    format!("{want} isn't a domain on this server. It serves: {}.", hosts.iter().map(name).collect::<Vec<_>>().join(", "))
                })
            }
            None => match hosts {
                [one] => Ok(one),
                [] => Err("This server has no domains yet.".into()),
                many => Err(format!(
                    "This server has several domains ({}); say which one.",
                    many.iter().map(name).collect::<Vec<_>>().join(", ")
                )),
            },
        }
    }

    /// The domain to act on: as given, or the only one.
    async fn host(&self, host: Option<String>) -> Result<String, String> {
        if let Some(h) = host.filter(|h| !h.trim().is_empty()) {
            return Ok(h.trim().to_ascii_lowercase());
        }
        let snap = self.snapshot().await?;
        Ok(Self::pick_host(&snap, None)?.get("host").and_then(Value::as_str).unwrap_or_default().to_string())
    }

    #[tool(
        description = "Shows whether the server is up, its version and uptime, and per domain how many accounts, online devices, invites and group chats it has, plus the call relay's state and traffic counters.",
        annotations(title = "Server status", read_only_hint = true, open_world_hint = false)
    )]
    pub async fn server_status(&self) -> ToolResult {
        let s = self.snapshot().await?;
        let started = s.get("startedAt").and_then(Value::as_i64).unwrap_or(0);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
        let hosts: Vec<Value> = s
            .get("hosts")
            .and_then(Value::as_array)
            .map(|hs| {
                hs.iter()
                    .map(|h| {
                        let accounts = h.get("accounts").and_then(Value::as_array);
                        let online = accounts
                            .map(|a| a.iter().map(|x| x.get("devices").and_then(Value::as_array).map_or(0, Vec::len)).sum::<usize>())
                            .unwrap_or(0);
                        let len = |k: &str| h.get(k).and_then(Value::as_array).map_or(0, Vec::len);
                        json!({
                            "host": h.get("host"),
                            "accounts": accounts.map_or(0, Vec::len),
                            "devicesOnline": online,
                            "invites": len("invites"),
                            "rooms": len("rooms"),
                            "groupsHost": h.get("groupsHost"),
                            "filesHost": h.get("filesHost"),
                            "tls": h.get("tls"),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        pretty(&json!({
            "server": s.get("server"),
            "version": s.get("version"),
            "startedAt": started,
            "uptimeMinutes": (now - started).max(0) / 60_000,
            "configFile": s.get("configFile"),
            "hosts": hosts,
            "turn": s.get("turn"),
            "stats": s.get("stats"),
        }))
    }

    #[tool(
        description = "Lists the accounts on a domain with their role, whether they're enabled, when they were created and last active, and how many devices are online.",
        annotations(title = "List accounts", read_only_hint = true, open_world_hint = false)
    )]
    pub async fn list_accounts(&self, Parameters(p): Parameters<HostParam>) -> ToolResult {
        let snap = self.snapshot().await?;
        let h = Self::pick_host(&snap, p.host.as_deref())?;
        let list: Vec<Value> = h
            .get("accounts")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|x| {
                        let mut x = x.clone();
                        if let Some(o) = x.as_object_mut() {
                            let n = o.remove("devices").and_then(|d| d.as_array().map(Vec::len)).unwrap_or(0);
                            o.insert("devicesOnline".into(), n.into());
                        }
                        x
                    })
                    .collect()
            })
            .unwrap_or_default();
        pretty(&json!({ "host": h.get("host"), "accounts": list }))
    }

    #[tool(
        description = "Lists the devices signed in right now (per account: resource, client, IP address, whether the connection is encrypted, since when), for a domain or one account.",
        annotations(title = "List devices", read_only_hint = true, open_world_hint = false)
    )]
    pub async fn list_devices(&self, Parameters(p): Parameters<DevicesParams>) -> ToolResult {
        let snap = self.snapshot().await?;
        let h = Self::pick_host(&snap, p.host.as_deref())?;
        let host = h.get("host").and_then(Value::as_str).unwrap_or_default();
        let want = p.user.as_deref().map(|u| u.trim().to_ascii_lowercase());
        let accounts = h.get("accounts").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
        if let Some(w) = &want {
            if !accounts.iter().any(|a| a.get("user").and_then(Value::as_str) == Some(w)) {
                return Err(format!("There's no account called {w}@{host}."));
            }
        }
        let list: Vec<Value> = accounts
            .iter()
            .filter(|a| want.as_deref().is_none_or(|w| a.get("user").and_then(Value::as_str) == Some(w)))
            .map(|a| json!({ "user": a.get("user"), "devices": a.get("devices").cloned().unwrap_or(json!([])) }))
            .collect();
        pretty(&json!({ "host": host, "accounts": list }))
    }

    #[tool(
        description = "Creates an account. Without a password, a readable one is generated and returned once: pass it on to the person.",
        annotations(
            title = "Create account",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    pub async fn create_account(&self, Parameters(p): Parameters<CreateAccountParams>) -> ToolResult {
        let host = self.host(p.host).await?;
        let user = p.user.trim().to_ascii_lowercase();
        let generated = p.password.is_none();
        let password = p.password.unwrap_or_else(readable_password);
        self.call("account.create", json!({ "host": host, "user": user, "password": password, "role": p.role.as_str() })).await?;
        let mut out = json!({ "created": format!("{user}@{host}"), "role": p.role.as_str() });
        if generated {
            out["password"] = json!(password);
            out["note"] = json!("This password is shown only now.");
        }
        pretty(&out)
    }

    #[tool(
        description = "Gives an account a new generated password (returned once) and signs out all its devices. Use when someone forgot theirs.",
        annotations(
            title = "Reset password",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    pub async fn reset_password(&self, Parameters(p): Parameters<UserParams>) -> ToolResult {
        let host = self.host(p.host).await?;
        let user = p.user.trim().to_ascii_lowercase();
        let password = readable_password();
        let r = self.call("account.update", json!({ "host": host, "user": user, "password": password })).await?;
        pretty(&json!({
            "account": format!("{user}@{host}"),
            "password": password,
            "devicesSignedOut": r.get("closed").cloned().unwrap_or(json!(0)),
            "note": "This password is shown only now.",
        }))
    }

    #[tool(
        description = "Turns an account off: it can't sign in and its devices are signed out. Nothing is deleted; enable_account undoes it.",
        annotations(
            title = "Disable account",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn disable_account(&self, Parameters(p): Parameters<UserParams>) -> ToolResult {
        self.set_enabled(p, false).await
    }

    #[tool(
        description = "Turns a disabled account back on.",
        annotations(
            title = "Enable account",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn enable_account(&self, Parameters(p): Parameters<UserParams>) -> ToolResult {
        self.set_enabled(p, true).await
    }

    async fn set_enabled(&self, p: UserParams, on: bool) -> ToolResult {
        let host = self.host(p.host).await?;
        let user = p.user.trim().to_ascii_lowercase();
        let r = self.call("account.update", json!({ "host": host, "user": user, "enabled": on })).await?;
        pretty(
            &json!({ "account": format!("{user}@{host}"), "enabled": on, "devicesSignedOut": r.get("closed").cloned().unwrap_or(json!(0)) }),
        )
    }

    #[tool(
        description = "Signs out one device of an account (by its resource from list_devices), or all of them. The password stays the same, so they can sign in again.",
        annotations(
            title = "Sign out device",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn sign_out_device(&self, Parameters(p): Parameters<SignOutParams>) -> ToolResult {
        let host = self.host(p.host).await?;
        let user = p.user.trim().to_ascii_lowercase();
        let which = p.resource.filter(|r| !r.is_empty()).map_or(json!(true), Value::String);
        let r = self.call("account.update", json!({ "host": host, "user": user, "signOut": which })).await?;
        pretty(&json!({ "account": format!("{user}@{host}"), "devicesSignedOut": r.get("closed").cloned().unwrap_or(json!(0)) }))
    }

    #[tool(
        description = "Deletes an account for good, with its contacts, message history and profile, and signs out its devices. This can't be undone; confirm with the person first.",
        annotations(
            title = "Delete account",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn delete_account(&self, Parameters(p): Parameters<UserParams>) -> ToolResult {
        let host = self.host(p.host).await?;
        let user = p.user.trim().to_ascii_lowercase();
        self.call("account.delete", json!({ "host": host, "user": user })).await?;
        pretty(&json!({ "deleted": format!("{user}@{host}") }))
    }

    #[tool(
        description = "Makes an invite link someone can use to create an account (even when sign-up is closed). Returns the xmpp: link and, when the web side is on, a web page link to share.",
        annotations(
            title = "Create invite",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    pub async fn create_invite(&self, Parameters(p): Parameters<CreateInviteParams>) -> ToolResult {
        let host = self.host(p.host).await?;
        let days = p.days.unwrap_or(7).clamp(1, 365);
        let username = p.username.map(|u| u.trim().to_ascii_lowercase()).filter(|u| !u.is_empty());
        let inv = self
            .call(
                "invite.create",
                json!({ "host": host, "username": username, "role": p.role.as_str(), "days": days, "reusable": p.reusable }),
            )
            .await?;
        pretty(&inv)
    }

    #[tool(
        description = "Stops an invite link from working.",
        annotations(
            title = "Revoke invite",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn revoke_invite(&self, Parameters(p): Parameters<RevokeInviteParams>) -> ToolResult {
        let host = self.host(p.host).await?;
        self.call("invite.revoke", json!({ "host": host, "token": p.token.trim() })).await?;
        pretty(&json!({ "revoked": p.token.trim() }))
    }

    #[tool(
        description = "Lists the group chats on a domain: address, name, whether public or members-only, and how many people are in them now.",
        annotations(title = "List group chats", read_only_hint = true, open_world_hint = false)
    )]
    pub async fn list_rooms(&self, Parameters(p): Parameters<HostParam>) -> ToolResult {
        let snap = self.snapshot().await?;
        let h = Self::pick_host(&snap, p.host.as_deref())?;
        pretty(&json!({ "service": h.get("groupsHost"), "rooms": h.get("rooms").cloned().unwrap_or(json!([])) }))
    }

    #[tool(
        description = "Creates a group chat that stays when everyone leaves.",
        annotations(
            title = "Create group chat",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    pub async fn create_room(&self, Parameters(p): Parameters<CreateRoomParams>) -> ToolResult {
        let service = match p.service.filter(|s| !s.trim().is_empty()) {
            Some(s) => s.trim().to_ascii_lowercase(),
            None => {
                let snap = self.snapshot().await?;
                let h = Self::pick_host(&snap, p.host.as_deref())?;
                h.get("groupsHost")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .ok_or("Group chats are turned off on this domain. Turn them on with update_settings first.")?
            }
        };
        let r = self
            .call(
                "room.create",
                json!({
                    "service": service,
                    "room": p.room.trim().to_ascii_lowercase(),
                    "name": p.name,
                    "description": p.description,
                    "public": p.public.unwrap_or(true),
                    "membersOnly": p.members_only,
                    "owner": p.owner,
                }),
            )
            .await?;
        pretty(&r)
    }

    #[tool(
        description = "Closes a group chat for good: everyone in it is removed and its history goes. This can't be undone; confirm with the person first.",
        annotations(
            title = "Destroy group chat",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn destroy_room(&self, Parameters(p): Parameters<DestroyRoomParams>) -> ToolResult {
        let jid = p.jid.trim().to_ascii_lowercase();
        self.call("room.destroy", json!({ "jid": jid, "reason": p.reason })).await?;
        pretty(&json!({ "destroyed": jid }))
    }

    #[tool(
        description = "Shows a domain's chat settings: sign-up (closed, invite, open), message history, group chats, file sharing, push, federation, web clients, calls, welcome message, contact address.",
        annotations(title = "Get settings", read_only_hint = true, open_world_hint = false)
    )]
    pub async fn get_settings(&self, Parameters(p): Parameters<HostParam>) -> ToolResult {
        let host = self.host(p.host).await?;
        pretty(&self.call("settings.get", json!({ "host": host })).await?)
    }

    #[tool(
        description = "Changes some of a domain's chat settings and leaves the rest as they are. Pass only what changes, in the shape get_settings returns, e.g. {\"signUp\": \"open\"} or {\"files\": {\"maxMb\": 500}}. Applies immediately.",
        annotations(
            title = "Update settings",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn update_settings(&self, Parameters(p): Parameters<UpdateSettingsParams>) -> ToolResult {
        if p.changes.is_empty() {
            return Err("Say which settings to change.".into());
        }
        let host = self.host(p.host).await?;
        let mut settings = self.call("settings.get", json!({ "host": host })).await?;
        merge(&mut settings, &p.changes);
        let r = self.call("settings.set", json!({ "host": host, "settings": settings })).await?;
        pretty(&json!({ "applied": true, "notes": r.get("notes").cloned().unwrap_or(json!([])), "settings": settings }))
    }

    #[tool(
        description = "Sends a chat message, by default from the server itself (a notice). Can also post into a group chat when sent from room@service/nick to room@service.",
        annotations(
            title = "Send message",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    pub async fn send_message(&self, Parameters(p): Parameters<SendMessageParams>) -> ToolResult {
        if p.body.trim().is_empty() {
            return Err("The message is empty.".into());
        }
        let from = match p.from.filter(|f| !f.trim().is_empty()) {
            Some(f) => f.trim().to_string(),
            None => self.host(None).await?,
        };
        let mut args = json!({ "from": from, "to": p.to.trim(), "body": p.body });
        if let Some(s) = p.subject {
            args["subject"] = json!(s);
        }
        self.call("message.send", args).await?;
        pretty(&json!({ "sent": true, "from": from, "to": p.to.trim() }))
    }

    #[tool(
        description = "Checks config file text (or, without text, the file the server runs with) and says what's wrong with it, with the line number.",
        annotations(title = "Check config", read_only_hint = true, open_world_hint = false)
    )]
    pub async fn check_config(&self, Parameters(p): Parameters<CheckConfigParams>) -> ToolResult {
        let text = match p.text {
            Some(t) => t,
            None => {
                let c = self.call("config.get", json!({})).await?;
                c.get("text").and_then(Value::as_str).ok_or("Quark didn't send its config file.")?.to_string()
            }
        };
        pretty(&self.call("config.check", json!({ "text": text })).await?)
    }

    #[tool(
        description = "Re-reads the config file and the TLS certificates without a restart.",
        annotations(title = "Reload", read_only_hint = false, destructive_hint = false, idempotent_hint = true, open_world_hint = false)
    )]
    pub async fn reload(&self) -> ToolResult {
        pretty(&self.call("reload", json!({})).await?)
    }
}

#[tool_handler(
    router = self.tool_router,
    name = "quark",
    instructions = "Tools for running a Quark chat (XMPP) server: list and manage accounts and their devices, invites, group chats, the server's chat settings and its config file. Changes apply immediately. Ask before deleting accounts or group chats. Passwords this server generates are shown once; pass them on to the person and don't store them."
)]
impl ServerHandler for QuarkMcp {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_passwords_are_readable_and_different() {
        let a = readable_password();
        assert_eq!(a.len(), 19);
        assert!(a.split('-').all(|g| g.len() == 4 && g.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())));
        assert!(!a.contains(['0', 'o', '1', 'l', 'i']));
        assert_ne!(a, readable_password());
    }

    #[test]
    fn merging_changes_keeps_the_rest() {
        let mut s = json!({ "signUp": "invite", "files": { "on": true, "maxMb": 100 }, "welcome": "hi" });
        let changes = json!({ "files": { "maxMb": 500 }, "welcome": null }).as_object().cloned().unwrap();
        merge(&mut s, &changes);
        assert_eq!(s, json!({ "signUp": "invite", "files": { "on": true, "maxMb": 500 }, "welcome": null }));
    }

    #[test]
    fn tools_carry_the_right_hints() {
        let delete = QuarkMcp::delete_account_tool_attr();
        let a = delete.annotations.expect("annotations");
        assert_eq!(a.destructive_hint, Some(true));
        let list = QuarkMcp::list_accounts_tool_attr().annotations.expect("annotations");
        assert_eq!(list.read_only_hint, Some(true));
        let create = QuarkMcp::create_account_tool_attr().annotations.expect("annotations");
        assert_eq!((create.read_only_hint, create.destructive_hint), (Some(false), Some(false)));
    }

    #[test]
    fn a_blank_host_means_the_only_domain() {
        let snap = json!({ "hosts": [{ "host": "quark.test" }] });
        for h in [None, Some(""), Some("  ")] {
            assert_eq!(QuarkMcp::pick_host(&snap, h).ok().and_then(|v| v["host"].as_str()), Some("quark.test"), "{h:?}");
        }
        assert!(QuarkMcp::pick_host(&snap, Some("elsewhere.test")).is_err());
    }
}
