//! Invitations (XEP-0401 / XEP-0379): links that create an account, or add a contact, in one tap.
//!
//! An invite is a random token with an expiry. Admin invites create an account (optionally with a
//! fixed username or role, or reset the password of an existing one). Invites people make for
//! their friends (`urn:xmpp:invite#invite`) are roster invites: the friend either signs up with
//! the token and both are subscribed to each other, or, already having an account anywhere,
//! sends a subscription request carrying the token and is approved without asking.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use quark_core::{ns, Element, Jid};
use rand::RngCore;
use serde::Serialize;

use super::{Event, Flow, Module, StanzaCtx};
use crate::accounts::Role;
use crate::db::{params, DbError, Migration, OptionalExtension};
use crate::server::{Host, Server};

pub static MIGRATION: Migration = Migration {
    module: "invites",
    steps: &[
        "CREATE TABLE invites (
        token TEXT PRIMARY KEY,
        host TEXT NOT NULL,
        -- The username the new account must take, or the account a reset invite is for.
        username TEXT,
        -- The local user who invited (roster invites): both are subscribed on redemption.
        inviter TEXT,
        role TEXT NOT NULL DEFAULT 'member',
        created INTEGER NOT NULL,
        expires INTEGER NOT NULL,
        reusable INTEGER NOT NULL DEFAULT 0,
        uses INTEGER NOT NULL DEFAULT 0,
        reset INTEGER NOT NULL DEFAULT 0
    ) WITHOUT ROWID;
    CREATE INDEX invites_by_host ON invites (host, expires);
    CREATE INDEX invites_by_inviter ON invites (host, inviter);",
        // Accounts made with invites people made for friends, kept for NEW_MEMBER_WAIT_MS:
        // what limits how fast invite trees grow.
        "CREATE TABLE invite_signups (
        token TEXT NOT NULL,
        host TEXT NOT NULL,
        inviter TEXT NOT NULL,
        invitee TEXT NOT NULL,
        at INTEGER NOT NULL
    );
    CREATE INDEX invite_signups_by_inviter ON invite_signups (host, inviter, at);
    CREATE INDEX invite_signups_by_invitee ON invite_signups (host, invitee);
    CREATE INDEX invite_signups_by_token ON invite_signups (token);",
    ],
};

/// Invites one member may have open at once, so a member can't fill the table.
const MAX_PER_INVITER: i64 = 10;
/// Accounts one member's invites may make a day. With [`NEW_MEMBER_WAIT_MS`] this keeps a
/// member's invites from snowballing into thousands of accounts in days.
pub const SIGNUPS_PER_INVITER_PER_DAY: i64 = 5;
/// How long an account made with a member's invite waits before it can invite others.
pub const NEW_MEMBER_WAIT_MS: i64 = 7 * DAY_MS;
/// The longest an invite can last.
pub const MAX_TTL_MS: i64 = 3_650 * DAY_MS;
pub const DAY_MS: i64 = 86_400_000;
/// How long invites people make for friends last.
pub const FRIEND_TTL_MS: i64 = 7 * DAY_MS;

pub struct Invites;

#[async_trait]
impl Module for Invites {
    fn name(&self) -> &'static str {
        "invites"
    }

    fn migrations(&self) -> Vec<&'static Migration> {
        vec![&MIGRATION]
    }

    fn snapshot_names(&self, _host: &Host) -> Vec<&'static str> {
        // Always on: admins can invite even when sign-up is closed (docs/gluon-contract.md §3).
        vec!["invites", "invites_register", "invites_adhoc", "invites_page"]
    }

    fn start(&self, srv: &Arc<Server>) {
        let db = srv.db.clone();
        let mut shutdown = srv.shutdown_signal();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(3600));
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = shutdown.changed() => return,
                }
                let now = quark_core::time::now_ms();
                let r = db
                    .write(move |t| {
                        t.execute("DELETE FROM invite_signups WHERE at <= ?1", [now - NEW_MEMBER_WAIT_MS])?;
                        t.execute("DELETE FROM invites WHERE expires <= ?1 OR (reusable = 0 AND uses > 0)", [now])
                    })
                    .await;
                match r {
                    Ok(n) if n > 0 => tracing::debug!(removed = n, "expired invites removed"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "invite expiry failed"),
                }
            }
        });
    }

    /// XEP-0379: a subscription request carrying a valid roster invite token is approved for the
    /// inviter, who subscribes back, so both see each other without a prompt.
    async fn stanza_in(&self, cx: &StanzaCtx<'_>, stanza: &mut Element) -> Flow {
        if stanza.name() != "presence" || stanza.attr("type") != Some("subscribe") {
            return Flow::Continue;
        }
        let Some(token) = stanza.get_child("preauth", ns::PARS).and_then(|p| p.attr("token")) else {
            return Flow::Continue;
        };
        let Some(inviter) = cx.to.node() else { return Flow::Continue };
        if let Err(e) = approve_preauth(cx.srv, cx.host, inviter, &cx.from.to_bare(), token).await {
            tracing::warn!(error = %e, "couldn't apply a roster invite");
        }
        Flow::Continue
    }

    async fn on_event(&self, srv: &Arc<Server>, ev: &Event) {
        if let Event::AccountDeleted { jid } = ev {
            let (Some(user), host) = (jid.node().map(str::to_string), jid.domain().to_string()) else { return };
            let r = srv
                .db
                .write(move |t| {
                    t.execute(
                        "DELETE FROM invites WHERE host = ?1 AND (inviter = ?2 OR (reset = 1 AND username = ?2))",
                        params![host, user],
                    )
                })
                .await;
            if let Err(e) = r {
                tracing::warn!(error = %e, "couldn't remove a deleted account's invites");
            }
        }
    }
}

/// An invite as the admin API returns it (docs/admin-api.md).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Invite {
    pub token: String,
    pub username: Option<String>,
    pub role: Role,
    pub created: i64,
    pub expires: i64,
    pub uri: String,
    pub page: Option<String>,
    pub reusable: bool,
    pub reset: bool,
    /// Who made it, for invites people make for friends (an extra over the documented shape).
    pub inviter: Option<String>,
    /// Accounts made with it so far.
    pub uses: u32,
}

/// An invite as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub token: String,
    pub host: String,
    pub username: Option<String>,
    pub inviter: Option<String>,
    pub role: Role,
    pub created: i64,
    pub expires: i64,
    pub reusable: bool,
    pub uses: u32,
    pub reset: bool,
}

impl Stored {
    /// Not expired and not used up.
    pub fn usable(&self, now: i64) -> bool {
        self.expires > now && (self.reusable || self.uses == 0)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InviteError {
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Db(#[from] DbError),
}

/// What [`create`] needs.
#[derive(Debug, Clone)]
pub struct NewInvite<'a> {
    pub host: &'a str,
    pub username: Option<&'a str>,
    pub inviter: Option<&'a str>,
    pub role: Role,
    pub ttl_ms: i64,
    pub reusable: bool,
    /// Lets the holder set a new password for `username` instead of creating an account.
    pub reset: bool,
}

const COLS: &str = "token, host, username, inviter, role, created, expires, reusable, uses, reset";

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Stored> {
    Ok(Stored {
        token: r.get(0)?,
        host: r.get(1)?,
        username: r.get(2)?,
        inviter: r.get(3)?,
        role: if r.get::<_, String>(4)? == "admin" { Role::Admin } else { Role::Member },
        created: r.get(5)?,
        expires: r.get(6)?,
        reusable: r.get(7)?,
        uses: r.get::<_, i64>(8)?.clamp(0, u32::MAX as i64) as u32,
        reset: r.get(9)?,
    })
}

/// 144 random bits, URL-safe: fine in `xmpp:` URIs and paths alike.
fn new_token() -> String {
    let mut raw = [0u8; 18];
    rand::thread_rng().fill_bytes(&mut raw);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

/// Tokens we hand out look like this; anything else is refused before touching the database.
pub fn plausible_token(t: &str) -> bool {
    (16..=64).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Makes an invite.
pub async fn create(srv: &Arc<Server>, n: NewInvite<'_>) -> Result<Invite, InviteError> {
    let host = srv.host(n.host).ok_or_else(|| InviteError::Invalid(format!("{} isn't a domain on this server.", n.host)))?;
    if n.ttl_ms <= 0 || n.ttl_ms > MAX_TTL_MS {
        return Err(InviteError::Invalid("Invites last between a few minutes and ten years.".into()));
    }
    if let Some(u) = n.username {
        if !crate::accounts::valid_username(u) {
            return Err(InviteError::Invalid(format!(
                "\"{u}\" can't be a username: use lowercase letters, numbers, dots, dashes or underscores."
            )));
        }
        let exists = srv.accounts.exists(&host.domain, u).await?;
        if exists && !n.reset {
            return Err(InviteError::Invalid(format!("There's already an account called {u}@{}.", host.domain)));
        }
        if !exists && n.reset {
            return Err(InviteError::Invalid(format!("{u}@{} doesn't exist, so there's no password to reset.", host.domain)));
        }
        // Config admins are admins by name, so that account is never made by redeeming a link.
        if !n.reset && host.is_admin_jid(&Jid::bare_unchecked(u, &host.domain)) {
            return Err(InviteError::Invalid(format!(
                "{u}@{} is an admin in the config file: make that account with quark ctl or the admin API instead.",
                host.domain
            )));
        }
    } else if n.reset {
        return Err(InviteError::Invalid("A password reset invite needs the username it's for.".into()));
    }
    // Admins invite as much as they like; members are held to the limits above.
    let limited = n.inviter.filter(|u| !host.is_admin_jid(&Jid::bare_unchecked(u, &host.domain))).is_some();
    let now = quark_core::time::now_ms();
    let s = Stored {
        token: new_token(),
        host: host.domain.clone(),
        username: n.username.map(str::to_string),
        inviter: n.inviter.map(str::to_string),
        role: n.role,
        created: now,
        expires: now + n.ttl_ms,
        reusable: n.reusable,
        uses: 0,
        reset: n.reset,
    };
    let r = s.clone();
    let refused = srv
        .db
        .write(move |t| {
            if let Some(inv) = r.inviter.as_ref().filter(|_| limited) {
                let invited: bool = t.query_row(
                    "SELECT EXISTS (SELECT 1 FROM invite_signups WHERE host = ?1 AND invitee = ?2 AND at > ?3)",
                    params![r.host, inv, now - NEW_MEMBER_WAIT_MS],
                    |x| x.get(0),
                )?;
                if invited {
                    return Ok(Some("New accounts made with an invite can invite others after a week.".to_string()));
                }
                // Only unused invites count: used ones stay until the hourly cleanup.
                let open: i64 = t.query_row(
                    "SELECT COUNT(*) FROM invites WHERE host = ?1 AND inviter = ?2 AND expires > ?3 AND uses = 0",
                    params![r.host, inv, now],
                    |x| x.get(0),
                )?;
                if open >= MAX_PER_INVITER {
                    return Ok(Some(format!("You have {MAX_PER_INVITER} open invites already. Wait for some to be used or expire.")));
                }
            }
            t.execute(
                &format!("INSERT INTO invites ({COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9)"),
                params![r.token, r.host, r.username, r.inviter, r.role.as_str(), r.created, r.expires, r.reusable, r.reset],
            )?;
            Ok(None)
        })
        .await?;
    if let Some(why) = refused {
        return Err(InviteError::Invalid(why));
    }
    Ok(to_api(srv, &host, &s))
}

/// The invite behind a token, whatever its state.
pub async fn get(srv: &Server, token: &str) -> Result<Option<Stored>, DbError> {
    if !plausible_token(token) {
        return Ok(None);
    }
    let t = token.to_string();
    srv.db.read(move |c| c.query_row(&format!("SELECT {COLS} FROM invites WHERE token = ?1"), [t], row).optional()).await
}

/// A usable invite for `host`.
pub async fn find(srv: &Server, host: &str, token: &str) -> Result<Option<Stored>, DbError> {
    let now = quark_core::time::now_ms();
    Ok(get(srv, token).await?.filter(|s| s.host == host && s.usable(now)))
}

/// Active invites of a domain, newest first.
pub async fn list(srv: &Arc<Server>, host: &str) -> Vec<Invite> {
    let Some(h) = srv.host(host) else { return Vec::new() };
    let (d, now) = (host.to_string(), quark_core::time::now_ms());
    let rows = srv
        .db
        .read(move |c| {
            let mut st = c.prepare_cached(&format!(
                "SELECT {COLS} FROM invites WHERE host = ?1 AND expires > ?2 AND (reusable = 1 OR uses = 0) ORDER BY created DESC"
            ))?;
            let rows = st.query_map(params![d, now], row)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })
        .await;
    match rows {
        Ok(r) => r.iter().map(|s| to_api(srv, &h, s)).collect(),
        Err(e) => {
            tracing::warn!(error = %e, "couldn't list invites");
            Vec::new()
        }
    }
}

/// Deletes an invite. True when there was one.
pub async fn revoke(srv: &Server, host: &str, token: &str) -> Result<bool, DbError> {
    let (h, t) = (host.to_string(), token.to_string());
    srv.db.write(move |x| x.execute("DELETE FROM invites WHERE host = ?1 AND token = ?2", params![h, t])).await.map(|n| n > 0)
}

/// Takes one use of an invite, atomically: two people can't both redeem a single-use invite.
/// Returns the invite as it was before, or None when it isn't usable.
pub async fn claim(srv: &Server, host: &str, token: &str) -> Result<Option<Stored>, DbError> {
    if !plausible_token(token) {
        return Ok(None);
    }
    let (h, t, now) = (host.to_string(), token.to_string(), quark_core::time::now_ms());
    srv.db
        .write(move |x| {
            let Some(s) =
                x.query_row(&format!("SELECT {COLS} FROM invites WHERE token = ?1 AND host = ?2"), params![t, h], row).optional()?
            else {
                return Ok(None);
            };
            if !s.usable(now) {
                return Ok(None);
            }
            x.execute("UPDATE invites SET uses = uses + 1 WHERE token = ?1", [&t])?;
            Ok(Some(s))
        })
        .await
}

/// What [`claim_signup`] found.
#[derive(Debug)]
pub enum SignupClaim {
    /// The invite as it was before this use.
    Claimed(Stored),
    /// Expired, used up, or not for this domain.
    Gone,
    /// The member who made it has had [`SIGNUPS_PER_INVITER_PER_DAY`] people join today.
    InviterBusy,
}

/// [`claim`] for making the account `invitee`. A member's invite also takes one of the member's
/// sign-ups for the day and records who invited whom, in the same transaction as the use, so
/// parallel sign-ups can't get past the limit. [`unclaim`] gives both back.
pub async fn claim_signup(srv: &Server, host: &Arc<Host>, token: &str, invitee: &str) -> Result<SignupClaim, DbError> {
    if !plausible_token(token) {
        return Ok(SignupClaim::Gone);
    }
    let (h, t, who, now) = (host.clone(), token.to_string(), invitee.to_string(), quark_core::time::now_ms());
    srv.db
        .write(move |x| {
            let Some(s) = x
                .query_row(&format!("SELECT {COLS} FROM invites WHERE token = ?1 AND host = ?2"), params![t, h.domain], row)
                .optional()?
                .filter(|s| s.usable(now))
            else {
                return Ok(SignupClaim::Gone);
            };
            if let Some(inv) = &s.inviter {
                if !h.is_admin_jid(&Jid::bare_unchecked(inv, &h.domain)) {
                    let today: i64 = x.query_row(
                        "SELECT COUNT(*) FROM invite_signups WHERE host = ?1 AND inviter = ?2 AND at > ?3",
                        params![h.domain, inv, now - DAY_MS],
                        |r| r.get(0),
                    )?;
                    if today >= SIGNUPS_PER_INVITER_PER_DAY {
                        return Ok(SignupClaim::InviterBusy);
                    }
                }
                x.execute(
                    "INSERT INTO invite_signups (token, host, inviter, invitee, at) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![t, h.domain, inv, who, now],
                )?;
            }
            x.execute("UPDATE invites SET uses = uses + 1 WHERE token = ?1", [&t])?;
            Ok(SignupClaim::Claimed(s))
        })
        .await
}

/// Gives back a use taken by [`claim`] or [`claim_signup`] when the redemption failed after all.
pub async fn unclaim(srv: &Server, token: &str) {
    let t = token.to_string();
    let r = srv
        .db
        .write(move |x| {
            x.execute(
                "DELETE FROM invite_signups WHERE rowid = (SELECT rowid FROM invite_signups WHERE token = ?1 ORDER BY rowid DESC LIMIT 1)",
                [&t],
            )?;
            x.execute("UPDATE invites SET uses = MAX(uses - 1, 0) WHERE token = ?1", [&t])
        })
        .await;
    if let Err(e) = r {
        tracing::warn!(error = %e, "couldn't give an invite use back");
    }
}

/// The base URL of the web listener for a domain, without a trailing slash.
pub fn public_url(srv: &Server, host: &str) -> String {
    match srv.config().http.public_url.as_deref().map(|u| u.trim().trim_end_matches('/')).filter(|u| !u.is_empty()) {
        Some(u) => u.to_string(),
        None => format!("https://{host}"),
    }
}

/// The `xmpp:` URI for an invite (XEP-0401 §4, XEP-0379 §3).
pub fn uri(s: &Stored, signup_open_to_friends: bool) -> String {
    match (&s.inviter, &s.username) {
        (Some(inv), _) => {
            let ibr = if signup_open_to_friends { ";ibr=y" } else { "" };
            format!("xmpp:{inv}@{}?roster;preauth={}{ibr}", s.host, s.token)
        }
        (None, Some(u)) => format!("xmpp:{u}@{}?register;preauth={}", s.host, s.token),
        (None, None) => format!("xmpp:{}?register;preauth={}", s.host, s.token),
    }
}

/// The admin API shape of a stored invite.
pub fn to_api(srv: &Server, host: &Host, s: &Stored) -> Invite {
    let settings = host.settings();
    let friends = settings.sign_up != crate::settings::SignUp::Closed;
    Invite {
        token: s.token.clone(),
        username: s.username.clone(),
        role: s.role,
        created: s.created,
        expires: s.expires,
        uri: uri(s, friends),
        page: settings.web.then(|| format!("{}/invite/{}", public_url(srv, &host.domain), s.token)),
        reusable: s.reusable,
        reset: s.reset,
        inviter: s.inviter.as_ref().map(|u| format!("{u}@{}", s.host)),
        uses: s.uses,
    }
}

/// Whether an invite lets its holder make an account right now. Invites people make for friends
/// only do while sign-up isn't closed; admin invites always do.
pub fn allows_signup(s: &Stored, host: &Host) -> bool {
    s.inviter.is_none() || host.settings().sign_up != crate::settings::SignUp::Closed
}

/// Two local accounts see each other's presence from now on (an invite was redeemed).
pub async fn befriend(srv: &Arc<Server>, host: &Arc<Host>, a: &str, b: &str) -> Result<(), DbError> {
    use super::roster::{self, Item, Subscription};
    if a == b || !srv.accounts.exists(&host.domain, a).await? || !srv.accounts.exists(&host.domain, b).await? {
        return Ok(());
    }
    for (user, contact) in [(a, b), (b, a)] {
        let cj = Jid::bare_unchecked(contact, &host.domain);
        let mut it = roster::item(srv, &host.domain, user, &cj).await?.unwrap_or_else(|| Item::new(cj.clone()));
        it.subscription = Subscription::Both;
        it.ask = false;
        it.approved = false;
        it.pending_in = None;
        it.visible = true;
        roster::save_and_push(srv, host, user, &it).await?;
    }
    for (user, contact) in [(a, b), (b, a)] {
        let ev = Event::SubscriptionApproved {
            user: Jid::bare_unchecked(user, &host.domain),
            contact: Jid::bare_unchecked(contact, &host.domain),
        };
        srv.emit(&ev).await;
    }
    Ok(())
}

/// Pre-approves `contact`'s subscription request to `inviter` when it carries the inviter's
/// token, and subscribes the inviter back (XEP-0379 §3).
async fn approve_preauth(srv: &Arc<Server>, host: &Arc<Host>, inviter: &str, contact: &Jid, token: &str) -> Result<(), DbError> {
    use super::roster::{self, Item};
    let Some(s) = find(srv, &host.domain, token).await? else { return Ok(()) };
    if s.inviter.as_deref() != Some(inviter) || claim(srv, &host.domain, token).await?.is_none() {
        return Ok(());
    }
    let mut it = roster::item(srv, &host.domain, inviter, contact).await?.unwrap_or_else(|| Item::new(contact.clone()));
    if !it.subscription.sends_to_contact() {
        it.approved = true;
    }
    let subscribe_back = !it.subscription.receives_from_contact() && !it.ask;
    if subscribe_back {
        it.ask = true;
    }
    it.visible = true;
    roster::save_and_push(srv, host, inviter, &it).await?;
    if subscribe_back {
        let me = Jid::bare_unchecked(inviter, &host.domain);
        let p = Element::new("presence", ns::CLIENT)
            .attr_set("from", me.to_string())
            .attr_set("to", contact.to_string())
            .attr_set("type", "subscribe");
        srv.route(p).await;
    }
    tracing::debug!(%contact, inviter, "roster invite redeemed");
    Ok(())
}

// ------------------------------------------------------------------------------ landing page

/// Web routes for invite landing pages (`/invite/<token>`), merged into the web listener.
pub fn router(srv: &Arc<Server>) -> axum::Router {
    axum::Router::new().route("/invite/{token}", axum::routing::get(page)).with_state(srv.clone())
}

async fn page(State(srv): State<Arc<Server>>, Path(token): Path<String>, headers: HeaderMap) -> Response {
    let now = quark_core::time::now_ms();
    let found = match get(&srv, &token).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "couldn't read an invite");
            return html(StatusCode::INTERNAL_SERVER_ERROR, gone_page("Something went wrong", "Try again in a moment."));
        }
    };
    let host = found.as_ref().and_then(|s| srv.host(&s.host));
    let (Some(s), Some(host)) = (found.filter(|s| s.usable(now)), host.filter(|h| h.settings().web)) else {
        return html(
            StatusCode::NOT_FOUND,
            gone_page("This invite isn't valid", "It may have expired or been used already. Ask the person who sent it for a new one."),
        );
    };
    let platform = Platform::from_agent(headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or(""));
    let friends = host.settings().sign_up != crate::settings::SignUp::Closed;
    html(StatusCode::OK, invite_page(&s, &uri(&s, friends), allows_signup(&s, &host), platform))
}

fn html(status: StatusCode, body: String) -> Response {
    let mut r = (status, body).into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    // The token is in the URL: never send it on to app stores or anyone else.
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ),
    );
    h.insert(header::HeaderName::from_static("x-robots-tag"), HeaderValue::from_static("noindex, nofollow"));
    r
}

/// Escapes text for HTML element content and quoted attributes.
pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

/// Percent-encodes everything but unreserved characters (RFC 3986), for query values.
fn url_encode(s: &str) -> String {
    let mut o = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Platform {
    Android,
    Apple,
    Desktop,
}

impl Platform {
    fn from_agent(ua: &str) -> Platform {
        let ua = ua.to_ascii_lowercase();
        if ua.contains("android") {
            Platform::Android
        } else if ua.contains("iphone") || ua.contains("ipad") || ua.contains("ipod") || ua.contains("macintosh") {
            Platform::Apple
        } else {
            Platform::Desktop
        }
    }
}

struct App {
    name: &'static str,
    blurb: &'static str,
    /// (label, link). `{uri}` in a link becomes the percent-encoded invite URI.
    links: &'static [(&'static str, &'static str)],
}

const ANDROID: &[App] = &[
    App {
        name: "Conversations",
        blurb: "Simple and reliable. Picks up this invite by itself after installing.",
        links: &[
            ("Google Play", "https://play.google.com/store/apps/details?id=eu.siacs.conversations&referrer={uri}"),
            ("F-Droid", "https://f-droid.org/packages/eu.siacs.conversations/"),
        ],
    },
    App {
        name: "Monocles Chat",
        blurb: "Conversations with extra features.",
        links: &[("F-Droid", "https://f-droid.org/packages/de.monocles.chat/")],
    },
];
const APPLE: &[App] = &[
    App { name: "Monal", blurb: "For iPhone, iPad and Mac.", links: &[("Get Monal", "https://monal-im.org/")] },
    App { name: "Siskin IM", blurb: "For iPhone and iPad.", links: &[("Get Siskin", "https://siskin.im/")] },
];
const DESKTOP: &[App] = &[
    App { name: "Gajim", blurb: "For Windows and Linux.", links: &[("Get Gajim", "https://gajim.org/download/")] },
    App { name: "Dino", blurb: "For Linux.", links: &[("Get Dino", "https://dino.im/")] },
    App { name: "Movim", blurb: "In the browser, nothing to install.", links: &[("Open Movim", "https://movim.eu/")] },
];

fn apps_html(apps: &[App], uri: &str) -> String {
    let enc = url_encode(uri);
    let mut o = String::new();
    for a in apps {
        o.push_str(&format!("<li><div><strong>{}</strong><span>{}</span></div><p>", esc(a.name), esc(a.blurb)));
        for (label, link) in a.links {
            o.push_str(&format!(
                "<a class=\"store\" href=\"{}\" rel=\"noreferrer noopener\">{}</a>",
                esc(&link.replace("{uri}", &enc)),
                esc(label)
            ));
        }
        o.push_str("</p></li>");
    }
    o
}

/// "13 October 2026" for a time in ms (UTC).
pub fn human_date(ms: i64) -> String {
    const MONTHS: [&str; 12] =
        ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
    let d = quark_core::time::xep82(ms);
    let (y, m, day) =
        (d.get(0..4).unwrap_or(""), d.get(5..7).and_then(|m| m.parse::<usize>().ok()).unwrap_or(1), d.get(8..10).unwrap_or(""));
    format!("{} {} {y}", day.trim_start_matches('0'), MONTHS[(m.clamp(1, 12)) - 1])
}

const STYLE: &str = "
:root{--bg:#f6f7f9;--card:#fff;--text:#1b1d21;--muted:#5c6370;--line:#e3e6ea;--accent:#2f6fde;--accent-text:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#121417;--card:#1c1f24;--text:#e8eaed;--muted:#9aa1ab;--line:#2c3138;--accent:#6c9cff;--accent-text:#0b1220}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}
main{max-width:34rem;margin:0 auto;padding:2rem 1rem 3rem}
h1{font-size:1.6rem;line-height:1.25;margin:0 0 .5rem}
h2{font-size:1.05rem;margin:2rem 0 .75rem}
p{margin:.5rem 0}
.muted{color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:1.25rem;margin-top:1.25rem}
.step{display:flex;gap:.75rem;align-items:flex-start}
.n{flex:none;width:1.75rem;height:1.75rem;border-radius:50%;background:var(--accent);color:var(--accent-text);display:grid;place-items:center;font-weight:600;font-size:.9rem}
.button{display:block;text-align:center;background:var(--accent);color:var(--accent-text);text-decoration:none;font-weight:600;padding:.9rem 1rem;border-radius:10px;margin-top:.75rem}
ul{list-style:none;padding:0;margin:0}
li{padding:.75rem 0;border-top:1px solid var(--line)}
li:first-child{border-top:0}
li div{display:flex;flex-direction:column}
li span{color:var(--muted);font-size:.92rem}
li p{display:flex;flex-wrap:wrap;gap:.5rem;margin:.5rem 0 0}
a{color:var(--accent)}
.store{border:1px solid var(--line);border-radius:8px;padding:.35rem .7rem;text-decoration:none;font-size:.92rem}
.qr{display:flex;justify-content:center;margin:.5rem 0}
.qr svg{width:12rem;height:12rem;background:#fff;border-radius:10px;padding:.5rem}
code{display:block;word-break:break-all;font-size:.82rem;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:.6rem;margin-top:.5rem}
details summary{cursor:pointer;color:var(--accent)}
";

fn shell(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <meta name=\"robots\" content=\"noindex,nofollow\"><meta name=\"referrer\" content=\"no-referrer\"><title>{}</title><style>{STYLE}</style></head>\
         <body><main>{body}</main></body></html>",
        esc(title)
    )
}

fn gone_page(title: &str, text: &str) -> String {
    shell(title, &format!("<h1>{}</h1><p class=\"muted\">{}</p>", esc(title), esc(text)))
}

fn invite_page(s: &Stored, uri: &str, signup: bool, platform: Platform) -> String {
    let host = esc(&s.host);
    let (title, lead) = match (&s.inviter, s.reset) {
        (Some(inv), _) => (
            format!("{inv} invited you to chat"),
            format!("<strong>{}@{host}</strong> wants to chat with you. It's free, private, and works with many apps.", esc(inv)),
        ),
        (None, true) => {
            (format!("Reset your password on {}", s.host), "Open this link in your chat app to choose a new password.".to_string())
        }
        (None, false) => (format!("Join {}", s.host), format!("You're invited to make a chat account on <strong>{host}</strong>.")),
    };
    let order: [(Platform, &str, &[App]); 3] = [
        (Platform::Android, "Android", ANDROID),
        (Platform::Apple, "iPhone, iPad and Mac", APPLE),
        (Platform::Desktop, "Computer", DESKTOP),
    ];
    let mut first = String::new();
    let mut others = String::new();
    for (p, label, apps) in order {
        let section = format!("<h2>{label}</h2><ul>{}</ul>", apps_html(apps, uri));
        if p == platform {
            first = section;
        } else {
            others.push_str(&section);
        }
    }
    let account = match (&s.username, s.reset) {
        (Some(u), false) => format!("<p class=\"muted\">Your username will be <strong>{}</strong>.</p>", esc(u)),
        _ => String::new(),
    };
    let have_app = if s.inviter.is_some() && signup {
        format!(
            "<p class=\"muted\">Already have a chat account? The button adds {} to your contacts.</p>",
            esc(&format!("{}@{}", s.inviter.as_deref().unwrap_or_default(), s.host))
        )
    } else {
        String::new()
    };
    let body = format!(
        "<h1>{title}</h1><p class=\"muted\">{lead}</p>{account}\
         <div class=\"card\"><div class=\"step\"><span class=\"n\">1</span><div><strong>Get a chat app</strong>\
         <p class=\"muted\">Any app that speaks XMPP works. These are good picks for your device:</p></div></div>{first}\
         <details><summary>Apps for other devices</summary>{others}</details></div>\
         <div class=\"card\"><div class=\"step\"><span class=\"n\">2</span><div><strong>Open the invite</strong>\
         <p class=\"muted\">Once the app is installed, tap the button. On another device, scan the code instead.</p></div></div>\
         <a class=\"button\" href=\"{uri_e}\">Open in my chat app</a>{have_app}\
         <div class=\"qr\" role=\"img\" aria-label=\"QR code of the invite\">{qr}</div>\
         <details><summary>Copy the invite by hand</summary><code>{uri_e}</code></details></div>\
         <p class=\"muted\">This invite works until {expires}.</p>",
        title = esc(&title),
        uri_e = esc(uri),
        qr = qr_svg(uri),
        expires = esc(&human_date(s.expires)),
    );
    shell(&title, &body)
}

/// The QR code of `text` as inline SVG, one path for every dark module.
pub fn qr_svg(text: &str) -> String {
    let Ok(code) = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M) else {
        return String::new();
    };
    let w = code.width();
    let quiet = 4;
    let mut path = String::with_capacity(w * w * 4);
    for (i, c) in code.to_colors().iter().enumerate() {
        if *c == qrcode::Color::Dark {
            path.push_str(&format!("M{} {}h1v1h-1z", i % w + quiet, i / w + quiet));
        }
    }
    let size = w + 2 * quiet;
    format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {size} {size}\" shape-rendering=\"crispEdges\"><path fill=\"#000\" d=\"{path}\"/></svg>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(inviter: Option<&str>, username: Option<&str>) -> Stored {
        Stored {
            token: "abcdefghijklmnopqrstuvwx".into(),
            host: "a.test".into(),
            username: username.map(Into::into),
            inviter: inviter.map(Into::into),
            role: Role::Member,
            created: 0,
            expires: 10,
            reusable: false,
            uses: 0,
            reset: false,
        }
    }

    #[test]
    fn uris_follow_xep_0401_and_0379() {
        assert_eq!(uri(&stored(None, None), true), "xmpp:a.test?register;preauth=abcdefghijklmnopqrstuvwx");
        assert_eq!(uri(&stored(None, Some("sam")), true), "xmpp:sam@a.test?register;preauth=abcdefghijklmnopqrstuvwx");
        assert_eq!(uri(&stored(Some("kim"), None), true), "xmpp:kim@a.test?roster;preauth=abcdefghijklmnopqrstuvwx;ibr=y");
        assert_eq!(uri(&stored(Some("kim"), None), false), "xmpp:kim@a.test?roster;preauth=abcdefghijklmnopqrstuvwx");
    }

    #[test]
    fn single_use_invites_stop_working_once_used() {
        let mut s = stored(None, None);
        assert!(s.usable(5));
        assert!(!s.usable(10));
        s.uses = 1;
        assert!(!s.usable(5));
        s.reusable = true;
        assert!(s.usable(5));
    }

    #[test]
    fn tokens_are_plausible_and_odd_input_is_not() {
        assert!(plausible_token(&new_token()));
        assert!(!plausible_token("short"));
        assert!(!plausible_token("<script>alert(1)</script>xx"));
        assert!(!plausible_token(&"a".repeat(65)));
    }

    #[test]
    fn html_escaping_covers_attributes() {
        assert_eq!(esc("<a href=\"x\">'&'</a>"), "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;");
    }

    #[test]
    fn page_escapes_and_links_the_uri() {
        let mut s = stored(Some("kim"), None);
        s.host = "a.test".into();
        let page = invite_page(&s, "xmpp:kim@a.test?roster;preauth=x\"><script>", true, Platform::Android);
        assert!(!page.contains("<script>"));
        assert!(page.contains("referrer=xmpp%3Akim%40a.test%3Froster%3Bpreauth%3Dx%22%3E%3Cscript%3E"));
        assert!(page.contains("<svg"));
    }

    #[test]
    fn platform_from_user_agent() {
        assert_eq!(Platform::from_agent("Mozilla/5.0 (Linux; Android 14; Pixel 8)"), Platform::Android);
        assert_eq!(Platform::from_agent("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"), Platform::Apple);
        assert_eq!(Platform::from_agent("Mozilla/5.0 (X11; Linux x86_64)"), Platform::Desktop);
    }

    #[test]
    fn human_dates() {
        assert_eq!(human_date(1_791_849_600_000), "13 October 2026");
    }

    #[test]
    fn qr_is_svg_with_modules() {
        let s = qr_svg("xmpp:a.test?register;preauth=abcdefghijklmnopqrstuvwx");
        assert!(s.starts_with("<svg") && s.contains("h1v1h-1z"));
    }
}
