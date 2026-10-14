//! The admin commands (docs/admin-api.md), one function each.

use std::path::Path;
use std::sync::Arc;

use quark_core::{ns, Element, Jid};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::ApiError;
use crate::accounts::{AccountError, Role};
use crate::config::Config;
use crate::modules::{invites, muc, register};
use crate::server::{Host, Server};
use crate::settings::{Settings, SignUp};

type R = Result<Value, ApiError>;

/// Commands that change something, for the audit log.
pub fn mutates(cmd: &str) -> bool {
    !matches!(cmd, "status" | "snapshot" | "invite.peek" | "settings.get" | "config.get" | "config.check" | "account.export")
}

/// The arguments worth logging: names and addresses, never passwords, secrets or file text.
pub fn summary(args: &Value) -> String {
    const SAFE: [&str; 14] =
        ["host", "user", "username", "role", "enabled", "signOut", "days", "reusable", "service", "room", "jid", "from", "to", "port"];
    let mut parts = Vec::new();
    if let Some(o) = args.as_object() {
        for k in SAFE {
            if let Some(v) = o.get(k).filter(|v| !v.is_null()) {
                let v = match v {
                    Value::String(s) => s.chars().take(128).collect(),
                    v => v.to_string(),
                };
                parts.push(format!("{k}={v}"));
            }
        }
        if o.get("password").is_some_and(|p| !p.is_null()) {
            parts.push("password=(changed)".into());
        }
        if let Some(t) = o.get("token").and_then(Value::as_str) {
            // Enough to tell invites apart in the log, not enough to use one.
            parts.push(format!("token={}…", t.chars().take(4).collect::<String>()));
        }
    }
    parts.join(" ")
}

fn args<T: DeserializeOwned>(v: Value) -> Result<T, ApiError> {
    serde_json::from_value(v).map_err(|e| ApiError::invalid(format!("The request's arguments aren't right: {e}.")))
}

fn host(srv: &Server, domain: &str) -> Result<Arc<Host>, ApiError> {
    srv.host(&domain.trim().to_ascii_lowercase()).ok_or_else(|| ApiError::not_found(format!("{domain} isn't a domain on this server.")))
}

fn account_error(e: AccountError) -> ApiError {
    match e {
        AccountError::Exists(j) => ApiError::exists(format!("There's already an account called {j}.")),
        AccountError::NotFound(j) => ApiError::not_found(format!("{j} doesn't exist.")),
        AccountError::Invalid(t) => ApiError::invalid(t),
        AccountError::Db(e) => ApiError::internal(e),
    }
}

pub async fn run(srv: &Arc<Server>, cmd: &str, a: Value) -> R {
    match cmd {
        "status" => Ok(status(srv)),
        "snapshot" => Ok(super::snapshot::snapshot(srv).await),
        "account.create" => account_create(srv, args(a)?).await,
        "account.update" => account_update(srv, args(a)?).await,
        "account.delete" => account_delete(srv, args(a)?).await,
        "account.export" => super::pie::export(srv, args(a)?).await,
        "account.import" => super::pie::import(srv, args(a)?).await,
        "invite.create" => invite_create(srv, args(a)?).await,
        "invite.revoke" => invite_revoke(srv, args(a)?).await,
        "invite.peek" => invite_peek(srv, args(a)?).await,
        "room.create" => room_create(srv, args(a)?).await,
        "room.destroy" => room_destroy(srv, args(a)?).await,
        "settings.get" => {
            let a: HostArg = args(a)?;
            Ok(serde_json::to_value(&*host(srv, &a.host)?.settings()).map_err(ApiError::internal)?)
        }
        "settings.set" => settings_set(srv, args(a)?).await,
        "config.get" => config_get(srv).await,
        "config.check" => {
            let a: TextArg = args(a)?;
            Ok(config_check(srv, &a.text))
        }
        "config.set" => config_set(srv, args(a)?).await,
        "reload" => reload(srv).await,
        "turn.set" => turn_set(srv, args(a)?).await,
        "message.send" => message_send(srv, args(a)?).await,
        _ => Err(ApiError::invalid(format!("There's no command called \"{}\".", cmd.chars().take(64).collect::<String>()))),
    }
}

fn status(srv: &Server) -> Value {
    let c = srv.config();
    json!({
        "server": "quark",
        "version": env!("CARGO_PKG_VERSION"),
        "startedAt": srv.started_at,
        "configFile": c.path.display().to_string(),
        "dataDir": c.server.data_dir.display().to_string(),
    })
}

#[derive(Deserialize)]
struct HostArg {
    host: String,
}

#[derive(Deserialize)]
struct TextArg {
    text: String,
}

// ------------------------------------------------------------------------------ accounts

#[derive(Deserialize)]
struct AccountCreate {
    host: String,
    user: String,
    password: String,
    #[serde(default)]
    role: Option<Role>,
}

fn username(u: &str) -> String {
    u.trim().to_lowercase()
}

async fn account_create(srv: &Arc<Server>, a: AccountCreate) -> R {
    let h = host(srv, &a.host)?;
    register::create_account(srv, &h, &username(&a.user), &a.password, a.role.unwrap_or(Role::Member)).await.map_err(account_error)?;
    Ok(json!(true))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountUpdate {
    host: String,
    user: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    role: Option<Role>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    sign_out: Option<Value>,
}

async fn account_update(srv: &Arc<Server>, a: AccountUpdate) -> R {
    let h = host(srv, &a.host)?;
    let user = username(&a.user);
    let jid = format!("{user}@{}", h.domain);
    if !srv.accounts.exists(&h.domain, &user).await? {
        return Err(ApiError::not_found(format!("{jid} doesn't exist.")));
    }
    enum SignOut {
        All,
        One(String),
    }
    let sign_out = match a.sign_out {
        None | Some(Value::Null) | Some(Value::Bool(false)) => None,
        Some(Value::Bool(true)) => Some(SignOut::All),
        Some(Value::String(r)) if !r.is_empty() => Some(SignOut::One(r)),
        Some(_) => return Err(ApiError::invalid("signOut is true or the resource of one device.")),
    };
    // Check everything before changing anything, so a bad password doesn't leave half an update.
    if let Some(p) = &a.password {
        crate::accounts::check_password(p).map_err(account_error)?;
    }
    if let Some(role) = a.role {
        register::set_role(srv, &h, &user, role).await.map_err(account_error)?;
    }
    // The shared helpers sign devices out as they go (turning off and new passwords both do).
    let mut closed = 0;
    if let Some(on) = a.enabled {
        closed += register::set_enabled(srv, &h, &user, on).await.map_err(account_error)?;
    }
    if let Some(p) = &a.password {
        let why = (a.enabled != Some(false)).then_some("The password was changed.");
        closed += register::change_password(srv, &h, &user, p, why).await.map_err(account_error)?;
    }
    // Closing is asynchronous, so sessions closed above are still listed; don't count them twice.
    let already = a.enabled == Some(false) || a.password.is_some();
    let bare = Jid::bare_unchecked(&user, &h.domain);
    match &sign_out {
        _ if already => {}
        Some(SignOut::All) => closed += register::close_sessions(srv, &bare, "reset", "Signed out by an admin."),
        Some(SignOut::One(r)) => {
            if let Some(s) = bare.with_resource(r).ok().and_then(|full| srv.sessions.get(&full)) {
                s.close("reset", Some("Signed out by an admin.".into()));
                closed += 1;
            }
        }
        None => {}
    }
    Ok(json!({ "closed": closed }))
}

#[derive(Deserialize)]
struct AccountRef {
    host: String,
    user: String,
}

async fn account_delete(srv: &Arc<Server>, a: AccountRef) -> R {
    let h = host(srv, &a.host)?;
    register::delete_account(srv, &h, &username(&a.user), "This account was deleted.").await?;
    Ok(json!(true))
}

// ------------------------------------------------------------------------------ invites

#[derive(Deserialize)]
struct InviteCreate {
    host: String,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    role: Option<Role>,
    days: f64,
    #[serde(default)]
    reusable: bool,
    #[serde(default)]
    reset: bool,
}

async fn invite_create(srv: &Arc<Server>, a: InviteCreate) -> R {
    let h = host(srv, &a.host)?;
    if !a.days.is_finite() || a.days <= 0.0 || a.days * invites::DAY_MS as f64 > invites::MAX_TTL_MS as f64 {
        return Err(ApiError::invalid("days is a number of days above 0, at most ten years."));
    }
    let user = a.username.as_deref().map(username).filter(|u| !u.is_empty());
    if let Some(u) = &user {
        if !a.reset && srv.accounts.exists(&h.domain, u).await? {
            return Err(ApiError::exists(format!("There's already an account called {u}@{}.", h.domain)));
        }
    }
    let n = invites::NewInvite {
        host: &h.domain,
        username: user.as_deref(),
        inviter: None,
        role: a.role.unwrap_or(Role::Member),
        ttl_ms: (a.days * invites::DAY_MS as f64) as i64,
        reusable: a.reusable,
        reset: a.reset,
    };
    match invites::create(srv, n).await {
        Ok(inv) => Ok(serde_json::to_value(inv).map_err(ApiError::internal)?),
        Err(invites::InviteError::Invalid(t)) => Err(ApiError::invalid(t)),
        Err(invites::InviteError::Db(e)) => Err(e.into()),
    }
}

#[derive(Deserialize)]
struct InviteRef {
    host: String,
    token: String,
}

async fn invite_revoke(srv: &Arc<Server>, a: InviteRef) -> R {
    let h = host(srv, &a.host)?;
    invites::revoke(srv, &h.domain, &a.token).await?;
    Ok(json!(true))
}

async fn invite_peek(srv: &Arc<Server>, a: InviteRef) -> R {
    let h = host(srv, &a.host)?;
    Ok(match invites::find(srv, &h.domain, &a.token).await? {
        Some(s) => {
            let inv = invites::to_api(srv, &h, &s);
            json!({ "expires": inv.expires, "username": inv.username, "uri": inv.uri })
        }
        None => Value::Null,
    })
}

// ------------------------------------------------------------------------------ rooms

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoomCreate {
    service: String,
    room: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    public: bool,
    #[serde(default)]
    members_only: bool,
    #[serde(default)]
    owner: Option<String>,
}

fn room_error(e: muc::RoomError) -> ApiError {
    match e {
        muc::RoomError::NotFound(t) => ApiError::not_found(t),
        muc::RoomError::Exists(t) => ApiError::exists(t),
        muc::RoomError::Invalid(t) => ApiError::invalid(t),
    }
}

/// The domain whose group chat service is `service`.
fn groups_host(srv: &Server, service: &str) -> Result<Arc<Host>, ApiError> {
    let h = srv
        .hosts()
        .into_iter()
        .find(|h| h.settings().groups.host == service)
        .ok_or_else(|| ApiError::not_found(format!("{service} isn't a group chat service on this server.")))?;
    if !h.settings().groups.on {
        return Err(ApiError::new("not_enabled", format!("Group chats are turned off for {}.", h.domain)));
    }
    Ok(h)
}

async fn room_create(srv: &Arc<Server>, a: RoomCreate) -> R {
    let service = a.service.trim().to_ascii_lowercase();
    groups_host(srv, &service)?;
    let room = a.room.trim().to_lowercase();
    if Jid::from_parts(Some(&room), &service, None).is_err() {
        return Err(ApiError::invalid(format!("\"{}\" can't be a group chat address.", a.room)));
    }
    let owner = match a.owner.as_deref().map(str::trim).filter(|o| !o.is_empty()) {
        Some(o) => {
            Some(Jid::parse(o).map_err(|_| ApiError::invalid(format!("The owner \"{o}\" isn't a chat address.")))?.to_bare().to_string())
        }
        None => None,
    };
    let r = muc::NewRoom {
        service: &service,
        room: &room,
        name: &a.name,
        description: a.description.as_deref().filter(|d| !d.is_empty()),
        public: a.public,
        members_only: a.members_only,
        owner: owner.as_deref(),
    };
    let jid = muc::create_room(srv, r).await.map_err(room_error)?;
    Ok(json!({ "jid": jid }))
}

#[derive(Deserialize)]
struct RoomDestroy {
    jid: String,
    #[serde(default)]
    reason: Option<String>,
}

async fn room_destroy(srv: &Arc<Server>, a: RoomDestroy) -> R {
    let j = Jid::parse(a.jid.trim()).map_err(|_| ApiError::invalid(format!("\"{}\" isn't a group chat address.", a.jid)))?.to_bare();
    groups_host(srv, j.domain())?;
    muc::destroy_room(srv, &j.to_string(), a.reason.as_deref().filter(|r| !r.is_empty())).await.map_err(room_error)?;
    Ok(json!(true))
}

// ------------------------------------------------------------------------------ settings

#[derive(Deserialize)]
struct SettingsSet {
    host: String,
    settings: Value,
}

async fn settings_set(srv: &Arc<Server>, a: SettingsSet) -> R {
    let h = host(srv, &a.host)?;
    let new: Settings = serde_json::from_value(a.settings).map_err(|e| ApiError::invalid(format!("Those settings aren't right: {e}.")))?;
    let old = h.settings();
    srv.set_settings(&h.domain, new.clone()).await.map_err(ApiError::invalid)?;
    Ok(json!({ "applied": true, "notes": notes(srv, &h.domain, &old, &new) }))
}

/// What people should know about a settings change, in plain sentences.
pub fn notes(srv: &Server, domain: &str, old: &Settings, new: &Settings) -> Vec<String> {
    let mut n = Vec::new();
    if old.sign_up != new.sign_up {
        n.push(match new.sign_up {
            SignUp::Open => format!(
                "Anyone can make an account on {domain} now (at most {} an hour from one address).",
                srv.config().limits.registrations_per_hour
            ),
            SignUp::Invite => "New accounts need an invite link now. Members can invite friends from their chat app.".into(),
            SignUp::Closed => "Only admins can make accounts now. Invite links admins made still work.".into(),
        });
    }
    if old.history != new.history {
        n.push(if new.history.on() {
            "The message archive keeps the new period; older messages are removed in the next cleanup.".into()
        } else {
            "Message history is off: the archive is cleared and new messages aren't kept.".into()
        });
    }
    if old.federation != new.federation {
        n.push(if new.federation {
            "Chatting with people on other servers is on again.".into()
        } else {
            "Chats with people on other servers stop until federation is turned back on.".into()
        });
    }
    if old.web != new.web && !new.web {
        n.push("Web chat and invite pages are off. Invite links still work in chat apps.".into());
    }
    for (what, o, w) in [
        ("Group chats", (&old.groups.on, &old.groups.host), (&new.groups.on, &new.groups.host)),
        ("Files", (&old.files.on, &old.files.host), (&new.files.on, &new.files.host)),
    ] {
        if *w.0 && (!*o.0 || o.1 != w.1) {
            n.push(format!("{what} use {}. Make sure that name points at this server (DNS) so apps and other servers reach it.", w.1));
        } else if *o.0 && !*w.0 {
            n.push(format!("{what} are off."));
        }
    }
    if old.calls.on && !new.calls.on {
        n.push("Calls are off: apps no longer get relay details.".into());
    }
    if new.calls.on && !old.calls.on && !srv.config().turn.enabled {
        n.push("Calls are on, but the built-in relay is off in the config file; set an external one with turn.set.".into());
    }
    n
}

// ------------------------------------------------------------------------------ config file

fn config_path(srv: &Server) -> Result<std::path::PathBuf, ApiError> {
    let p = srv.config().path.clone();
    if p.as_os_str().is_empty() {
        return Err(ApiError::new("config", "This server wasn't started from a config file."));
    }
    Ok(p)
}

async fn config_get(srv: &Server) -> R {
    let path = config_path(srv)?;
    let text =
        tokio::fs::read_to_string(&path).await.map_err(|e| ApiError::new("config", format!("Couldn't read {}: {e}.", path.display())))?;
    Ok(json!({ "file": path.display().to_string(), "text": text }))
}

/// Parses config text the way a reload would (with the environment applied).
fn parse_config(text: &str, path: &Path) -> Result<Config, (Option<usize>, String)> {
    let mut c = Config::parse(text, path).map_err(|e| (e.line(), e.to_string()))?;
    c.apply_env(|k| std::env::var(k).ok()).map_err(|e| (e.line(), e.to_string()))?;
    if c.hosts.is_empty() {
        return Err((None, "There are no domains to serve: add a [[host]].".into()));
    }
    Ok(c)
}

fn config_check(srv: &Server, text: &str) -> Value {
    let path = srv.config().path.clone();
    match parse_config(text, &path) {
        Ok(c) => json!({ "ok": true, "line": null, "message": format!("The config is fine: {} domain(s).", c.hosts.len()) }),
        Err((line, m)) => json!({ "ok": false, "line": line, "message": m }),
    }
}

async fn config_set(srv: &Arc<Server>, a: TextArg) -> R {
    let path = config_path(srv)?;
    if let Err((line, m)) = parse_config(&a.text, &path) {
        let at = line.map(|l| format!(" (line {l})")).unwrap_or_default();
        return Err(ApiError::new("config", format!("The config wasn't saved{at}: {m}")));
    }
    let p = path.clone();
    let text = a.text;
    tokio::task::spawn_blocking(move || write_keeping_mode(&p, text.as_bytes()))
        .await
        .map_err(ApiError::internal)?
        .map_err(|e| ApiError::new("config", format!("Couldn't write {}: {e}.", path.display())))?;
    reload(srv).await?;
    Ok(json!({ "ok": true }))
}

/// Replaces a file atomically, keeping its permissions (the config is often readable by others).
fn write_keeping_mode(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let perms = std::fs::metadata(path).ok().map(|m| m.permissions());
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    if let Some(p) = perms {
        std::fs::set_permissions(&tmp, p)?;
    }
    std::fs::rename(&tmp, path)
}

async fn reload(srv: &Arc<Server>) -> R {
    let path = config_path(srv)?;
    let s = srv.clone();
    let r = tokio::task::spawn_blocking(move || -> Result<usize, ApiError> {
        let text =
            std::fs::read_to_string(&path).map_err(|e| ApiError::new("config", format!("Couldn't read {}: {e}.", path.display())))?;
        let cfg = parse_config(&text, &path).map_err(|(line, m)| {
            let at = line.map(|l| format!(" (line {l})")).unwrap_or_default();
            ApiError::new("config", format!("The config file has a problem{at}: {m}"))
        })?;
        s.set_config(cfg).map_err(|e| ApiError::new("config", e.to_string()))?;
        s.certs.reload().map_err(|e| ApiError::new("config", e.to_string()))
    })
    .await
    .map_err(ApiError::internal)??;
    tracing::info!(certificates = r, "config reloaded");
    Ok(json!({ "reloaded": true, "certs": r }))
}

// ------------------------------------------------------------------------------ calls

/// An external TURN relay (coturn's `use-auth-secret`), set with `turn.set`. Read by external
/// service discovery (XEP-0215) to hand out credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalTurn {
    pub secret: String,
    /// Where phones reach it; the domain when None.
    pub host: Option<String>,
    /// 3478 when None.
    pub port: Option<u16>,
}

const TURN_SCOPE: &str = "calls";
const TURN_KEY: &str = "turn_external";

/// The external TURN relay, when one is set.
pub async fn external_turn(srv: &Server) -> Option<ExternalTurn> {
    match srv.kv_get(TURN_SCOPE, TURN_KEY).await {
        Ok(Some(v)) => serde_json::from_slice(&v).ok(),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(error = %e, "couldn't read the external TURN settings");
            None
        }
    }
}

#[derive(Deserialize)]
struct TurnSet {
    #[serde(default)]
    secret: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    port: Option<u32>,
}

async fn turn_set(srv: &Server, a: TurnSet) -> R {
    let secret = a.secret.filter(|s| !s.is_empty());
    let Some(secret) = secret else {
        srv.kv_set(TURN_SCOPE, TURN_KEY, None).await?;
        return Ok(json!(true));
    };
    if secret.len() > 1024 || secret.chars().any(char::is_control) {
        return Err(ApiError::invalid("That secret has characters a relay can't use."));
    }
    let host = a.host.map(|h| h.trim().to_ascii_lowercase()).filter(|h| !h.is_empty());
    if let Some(h) = &host {
        if h.parse::<std::net::IpAddr>().is_err() && Jid::domain_jid(h).is_err() {
            return Err(ApiError::invalid(format!("\"{h}\" isn't a host name or address.")));
        }
    }
    let port = match a.port {
        None => None,
        Some(p @ 1..=65535) => Some(p as u16),
        Some(_) => return Err(ApiError::invalid("The port is between 1 and 65535.")),
    };
    let v = serde_json::to_vec(&ExternalTurn { secret, host, port }).map_err(ApiError::internal)?;
    srv.kv_set(TURN_SCOPE, TURN_KEY, Some(v)).await?;
    Ok(json!(true))
}

// ------------------------------------------------------------------------------ messages

#[derive(Deserialize)]
struct MessageSend {
    from: String,
    to: String,
    body: String,
    #[serde(default)]
    subject: Option<String>,
}

const MAX_BODY: usize = 64 * 1024;

async fn message_send(srv: &Arc<Server>, a: MessageSend) -> R {
    let parse = |s: &str| Jid::parse(s.trim()).map_err(|_| ApiError::invalid(format!("\"{s}\" isn't a chat address.")));
    let (from, to) = (parse(&a.from)?, parse(&a.to)?);
    if a.body.trim().is_empty() {
        return Err(ApiError::invalid("The message is empty."));
    }
    if a.body.len() > MAX_BODY {
        return Err(ApiError::invalid("The message is too long (64 KB at most)."));
    }
    // From a nickname in one of our group chats: post into the room.
    if let (Some(_), Some(nick)) = (from.node(), from.resource()) {
        if srv.hosts().iter().any(|h| h.settings().groups.host == from.domain()) {
            groups_host(srv, from.domain())?;
            if to.to_bare() != from.to_bare() || to.resource().is_some() {
                return Err(ApiError::invalid("To post in a group chat, send it to the group's own address."));
            }
            muc::post(srv, &to.to_string(), nick, &a.body).await.map_err(room_error)?;
            return Ok(json!(true));
        }
    }
    let h = srv.host(from.domain()).ok_or_else(|| ApiError::invalid(format!("{} isn't a domain on this server.", from.domain())))?;
    if let Some(u) = from.node() {
        if !srv.accounts.exists(&h.domain, u).await? {
            return Err(ApiError::not_found(format!("{} doesn't exist.", from.to_bare())));
        }
    }
    match srv.host(to.domain()) {
        Some(th) => {
            let Some(u) = to.node() else { return Err(ApiError::invalid("Send it to an account, not to a domain.")) };
            if !srv.accounts.exists(&th.domain, u).await? {
                return Err(ApiError::not_found(format!("{} doesn't exist.", to.to_bare())));
            }
        }
        None if srv.is_local(to.domain()) => {}
        None if !h.settings().federation => {
            return Err(ApiError::new("not_enabled", format!("Chatting with other servers is turned off on {}.", h.domain)));
        }
        None => {}
    }
    let mut m = quark_core::stanza::chat_message(&from.to_string(), &to.to_string(), "chat", &a.body);
    if let Some(s) = a.subject.filter(|s| !s.is_empty()) {
        m.append(Element::new("subject", ns::CLIENT).text(s));
    }
    srv.route(m).await;
    Ok(json!(true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summaries_leave_secrets_out() {
        let s =
            summary(&json!({ "host": "a.test", "user": "sam", "password": "hunter22", "token": "abcdefgh", "secret": "x", "text": "y" }));
        assert_eq!(s, "host=a.test user=sam password=(changed) token=abcd…");
    }

    #[test]
    fn reads_are_not_audited() {
        assert!(!mutates("snapshot") && !mutates("config.get") && mutates("account.create") && mutates("reload"));
    }
}
