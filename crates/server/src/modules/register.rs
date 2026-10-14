//! In-band registration (XEP-0077) with invites (XEP-0401 / XEP-0379, XEP-0445 tokens), and
//! changing the password or deleting the account once signed in.
//!
//! Also home to the account lifecycle every entry point shares (admin API, ad-hoc commands,
//! registration): creating, deleting, turning off and changing passwords, so sessions, FAST
//! tokens, the admin cache and module events stay consistent whichever way it happens.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use quark_core::stanza::{error_reply, iq_result, iq_type, IqType};
use quark_core::{ns, Condition, Element, Jid, StanzaError};

use super::forms::{Form, Values};
use super::{invites, ok, ok_empty, Event, IqCtx, IqReply, IqResult, IqTarget, Module};
use crate::accounts::{AccountError, Role};
use crate::db::{params, DbError, Migration};
use crate::server::{Host, Server};
use crate::settings::SignUp;

pub static MIGRATION: Migration = Migration {
    module: "register",
    steps: &[
        "CREATE TABLE ibr_log (ip TEXT NOT NULL, at INTEGER NOT NULL);
              CREATE INDEX ibr_log_by_ip ON ibr_log (ip, at);",
        // `ip` is now an address key (see `ip_key`); `ok` is 0 for a sign-up that failed.
        "ALTER TABLE ibr_log ADD COLUMN ok INTEGER NOT NULL DEFAULT 1;",
    ],
};

/// Usernames nobody gets by signing up themselves: they look official. Admins can still make
/// them, and an invite for that exact username works.
const RESERVED: &[&str] = &[
    "abuse",
    "admin",
    "administrator",
    "help",
    "helpdesk",
    "hostmaster",
    "info",
    "mod",
    "moderator",
    "noc",
    "noreply",
    "no-reply",
    "operator",
    "postmaster",
    "quark",
    "gluon",
    "root",
    "security",
    "server",
    "staff",
    "support",
    "sysadmin",
    "system",
    "webmaster",
    "xmpp",
];

pub fn reserved(user: &str) -> bool {
    RESERVED.contains(&user)
}

/// Wrong invite tokens one connection may send before it's refused, though guessing 144 bits is
/// hopeless.
const MAX_TOKEN_TRIES: u8 = 5;
const HOUR_MS: i64 = 3_600_000;
/// Sign-ups with a member's invite get this many times `registrations_per_hour` from one
/// address: friends sign up together, but invite links shouldn't open the floodgates.
const INVITED_FACTOR: u32 = 4;
/// Attempts, failed ones included, one address may make per allowed sign-up. Failures are cheap
/// now, but someone trying name after name is still someone to slow down.
const ATTEMPTS_FACTOR: u32 = 4;

pub struct Register;

#[async_trait]
impl Module for Register {
    fn name(&self) -> &'static str {
        "register"
    }

    fn migrations(&self) -> Vec<&'static Migration> {
        vec![&MIGRATION]
    }

    fn snapshot_names(&self, _host: &Host) -> Vec<&'static str> {
        vec!["register", "register_ibr", "account_activity"]
    }

    fn server_features(&self, _host: &Host) -> Vec<&'static str> {
        vec![ns::REGISTER]
    }

    fn iq_namespaces(&self) -> &'static [(&'static str, IqTarget)] {
        &[(ns::REGISTER, IqTarget::Server)]
    }

    fn start(&self, srv: &Arc<Server>) {
        let db = srv.db.clone();
        let mut shutdown = srv.shutdown_signal();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = shutdown.changed() => return,
                }
                let cutoff = quark_core::time::now_ms() - HOUR_MS;
                if let Err(e) = db.write(move |t| t.execute("DELETE FROM ibr_log WHERE at < ?1", [cutoff])).await {
                    tracing::warn!(error = %e, "registration log cleanup failed");
                }
            }
        });
    }

    /// Signed in: read the registration, change the password, or delete the account.
    async fn handle_iq(&self, cx: &IqCtx<'_>) -> IqResult {
        let Some(me) = cx.local_sender() else {
            return Err(StanzaError::forbidden().with_text("Only accounts on this server can change their registration."));
        };
        let user = me.node().unwrap_or_default().to_string();
        let q = cx.payload;
        match cx.kind {
            IqType::Get => ok(Element::new("query", ns::REGISTER).child(Element::new("registered", ns::REGISTER)).text_child(
                "username",
                ns::REGISTER,
                user,
            )),
            IqType::Set if q.has_child("remove", ns::REGISTER) => {
                // Answer first: the session closes as the account goes (XEP-0077 §3.2).
                crate::router::reply(cx.srv, cx.session, iq_result(cx.iq)).await;
                if let Err(e) = delete_account(cx.srv, cx.host, &user, "This account was deleted.").await {
                    tracing::warn!(error = %e, "couldn't delete an account");
                }
                tracing::info!(account = %me, "account deleted by its owner");
                Ok(IqReply::Handled)
            }
            IqType::Set => {
                let f = Fields::read(q);
                if f.username.as_deref().is_some_and(|u| u.to_lowercase() != user) {
                    return Err(StanzaError::new(Condition::NotAllowed).with_text("You can only change your own password."));
                }
                let Some(pw) = f.password.filter(|p| !p.is_empty()) else {
                    return Err(StanzaError::new(Condition::NotAcceptable).with_text("Choose a new password."));
                };
                match change_password(cx.srv, cx.host, &user, &pw, None).await {
                    Ok(_) => {
                        tracing::info!(account = %me, "password changed in-band");
                        ok_empty()
                    }
                    Err(AccountError::Invalid(t)) => Err(StanzaError::new(Condition::NotAcceptable).with_text(t)),
                    Err(e) => {
                        tracing::warn!(error = %e, "couldn't change a password");
                        Err(StanzaError::internal())
                    }
                }
            }
            _ => Err(StanzaError::bad_request()),
        }
    }
}

// ------------------------------------------------------------------------------ lifecycle

/// Closes every session of an account. Returns how many there were.
pub fn close_sessions(srv: &Server, bare: &Jid, condition: &'static str, text: &str) -> usize {
    let list = srv.sessions.of(bare);
    for s in &list {
        s.close(condition, Some(text.to_string()));
    }
    list.len()
}

/// Creates an account and tells the modules (welcome message, invites…).
pub async fn create_account(srv: &Arc<Server>, host: &Arc<Host>, user: &str, password: &str, role: Role) -> Result<(), AccountError> {
    srv.accounts.create(&host.domain, user, password, role).await?;
    host.set_role_cache(user, role);
    srv.emit(&Event::AccountCreated { jid: Jid::bare_unchecked(user, &host.domain) }).await;
    Ok(())
}

/// Deletes an account and everything stored for it, signing its devices out. True when it
/// existed.
pub async fn delete_account(srv: &Arc<Server>, host: &Arc<Host>, user: &str, why: &str) -> Result<bool, DbError> {
    if !srv.accounts.exists(&host.domain, user).await? {
        return Ok(false);
    }
    let bare = Jid::bare_unchecked(user, &host.domain);
    close_sessions(srv, &bare, "not-authorized", why);
    host.set_role_cache(user, Role::Member);
    // Modules clean up first (files on disk, caches); the rows go with the account (cascade).
    srv.emit(&Event::AccountDeleted { jid: bare }).await;
    srv.accounts.delete(&host.domain, user).await
}

/// Sets a new password and forgets the account's FAST tokens, so devices that only had a token
/// need the new password. `close`: also sign every device out, keeping none.
pub async fn change_password(
    srv: &Arc<Server>,
    host: &Arc<Host>,
    user: &str,
    password: &str,
    close: Option<&str>,
) -> Result<usize, AccountError> {
    srv.accounts.set_password(&host.domain, user, password).await?;
    srv.fast_tokens.revoke_all(&host.domain, user).await?;
    Ok(match close {
        Some(why) => close_sessions(srv, &Jid::bare_unchecked(user, &host.domain), "reset", why),
        None => 0,
    })
}

/// Turns an account on or off. Off signs every device out and forgets its FAST tokens.
/// Returns the sessions closed.
pub async fn set_enabled(srv: &Arc<Server>, host: &Arc<Host>, user: &str, enabled: bool) -> Result<usize, AccountError> {
    srv.accounts.set_enabled(&host.domain, user, enabled).await?;
    if enabled {
        return Ok(0);
    }
    srv.fast_tokens.revoke_all(&host.domain, user).await?;
    Ok(close_sessions(srv, &Jid::bare_unchecked(user, &host.domain), "not-authorized", "This account was turned off."))
}

/// Changes an account's role, keeping the admin cache in step.
pub async fn set_role(srv: &Server, host: &Host, user: &str, role: Role) -> Result<(), AccountError> {
    srv.accounts.set_role(&host.domain, user, role).await?;
    host.set_role_cache(user, role);
    Ok(())
}

// ------------------------------------------------------------------------------ before sign-in

/// What a connection told us before signing in: an invite token from `<preauth/>`.
#[derive(Debug, Default)]
pub struct PreauthState {
    token: Option<String>,
    tries: u8,
}

/// Stream features before sign-in: registration, with invites (Conversations looks for
/// `urn:xmpp:invite` before sending `<preauth/>`; XEP-0445 clients for `urn:xmpp:ibr-token:0`).
/// Always offered, since invites work even when sign-up is closed.
pub fn preauth_features(srv: &Server, _host: &Host, secure: bool) -> Vec<Element> {
    if !secure && srv.config().tls.require_c2s {
        return Vec::new();
    }
    vec![Element::new("register", ns::REGISTER_FEATURE), Element::new("register", ns::INVITE), Element::new("register", ns::IBR_TOKEN)]
}

/// A registration IQ before sign-in, remembering an invite token across IQs on the same
/// connection. Returns the reply to send.
pub async fn preauth_with(
    srv: &Arc<Server>,
    host: &Arc<Host>,
    iq: &Element,
    secure: bool,
    ip: Option<IpAddr>,
    state: &mut PreauthState,
) -> Option<Element> {
    let fail = |e: StanzaError| error_reply(iq, &e);
    let Some(q) = iq.first_child() else { return fail(StanzaError::bad_request()) };
    if !secure && srv.config().tls.require_c2s {
        return fail(StanzaError::new(Condition::NotAllowed).with_text("Use TLS first (STARTTLS)."));
    }
    let kind = iq_type(iq);
    if q.is("preauth", ns::PARS) {
        if kind != Some(IqType::Set) {
            return fail(StanzaError::bad_request());
        }
        return match check_token(srv, host, q.attr("token"), state).await {
            Ok(t) => {
                state.token = Some(t);
                Some(iq_result(iq))
            }
            Err(e) => fail(e),
        };
    }
    if !q.is("query", ns::REGISTER) {
        return fail(StanzaError::service_unavailable());
    }
    match kind {
        Some(IqType::Get) => {
            let invite = match &state.token {
                Some(t) => invites::find(srv, &host.domain, t).await.ok().flatten().filter(|s| invites::allows_signup(s, host)),
                None => None,
            };
            Some(iq_result(iq).child(form(host, invite.as_ref())))
        }
        Some(IqType::Set) => {
            if q.has_child("remove", ns::REGISTER) {
                return fail(StanzaError::new(Condition::NotAuthorized).with_text("Sign in first to delete an account."));
            }
            let f = Fields::read(q);
            // A token already taken on this connection isn't checked again here (`register`
            // checks it as it's used), so retries with it don't count as guesses.
            if let Some(t) = f.token.as_ref().filter(|t| state.token.as_ref() != Some(*t)) {
                match check_token(srv, host, Some(t), state).await {
                    Ok(t) => state.token = Some(t),
                    Err(e) => return fail(e),
                }
            }
            match register(srv, host, f, ip, state.token.as_deref()).await {
                Ok(()) => {
                    state.token = None;
                    Some(iq_result(iq))
                }
                Err(e) => fail(e),
            }
        }
        _ => fail(StanzaError::bad_request()),
    }
}

/// Checks an invite token. Only wrong ones count against the connection's tries.
async fn check_token(srv: &Server, host: &Host, token: Option<&str>, state: &mut PreauthState) -> Result<String, StanzaError> {
    if state.tries >= MAX_TOKEN_TRIES {
        return Err(StanzaError::new(Condition::PolicyViolation).with_text("Too many invite codes tried on this connection."));
    }
    let found = match token.filter(|t| invites::plausible_token(t)) {
        Some(t) => invites::find(srv, &host.domain, t).await.map_err(|e| {
            tracing::warn!(error = %e, "couldn't check an invite");
            StanzaError::internal()
        })?,
        None => None,
    };
    match found.filter(|s| invites::allows_signup(s, host)) {
        Some(s) => Ok(s.token),
        None => {
            state.tries = state.tries.saturating_add(1);
            Err(StanzaError::item_not_found().with_text("This invite has expired or was already used."))
        }
    }
}

/// The registration form: legacy fields and the same as a data form (XEP-0077 §5).
fn form(host: &Host, invite: Option<&invites::Stored>) -> Element {
    let open = host.settings().sign_up == SignUp::Open;
    let instructions = match invite {
        Some(s) if s.reset => format!("Choose a new password for {}@{}.", s.username.as_deref().unwrap_or_default(), host.domain),
        Some(_) => format!("Choose a username and password for your account on {}.", host.domain),
        None if open => format!("Choose a username and password for your account on {}.", host.domain),
        None => format!("You need an invite to make an account on {}. Ask someone who has one.", host.domain),
    };
    let fixed = invite.and_then(|s| s.username.clone());
    let mut username = Element::new("username", ns::REGISTER);
    if let Some(u) = &fixed {
        username.set_text(u.clone());
    }
    let x = Form::new("form", ns::REGISTER)
        .instructions(&instructions)
        .title(&format!("Make an account on {}", host.domain))
        .field("username", "text-single", "Username", fixed.as_deref())
        .required()
        .field("password", "text-private", "Password", None)
        .required()
        .build();
    Element::new("query", ns::REGISTER)
        .text_child("instructions", ns::REGISTER, instructions)
        .child(username)
        .child(Element::new("password", ns::REGISTER))
        .child(x)
}

/// Username, password and token from a registration set: legacy fields or a submitted form.
#[derive(Debug, Default)]
struct Fields {
    username: Option<String>,
    password: Option<String>,
    token: Option<String>,
}

impl Fields {
    /// Empty legacy fields count as absent: clients echo the form's `<username/>` and
    /// `<password/>` next to a filled-in data form.
    fn read(q: &Element) -> Fields {
        let given = |v: Option<String>| v.filter(|s| !s.trim().is_empty());
        let mut f = Fields {
            username: given(q.child_text("username", ns::REGISTER)),
            password: q.child_text("password", ns::REGISTER).filter(|s| !s.is_empty()),
            token: q.get_child("preauth", ns::PARS).and_then(|p| p.attr("token")).map(str::to_string),
        };
        if let Some(x) = q.get_child("x", ns::DATA_FORMS).filter(|x| x.attr("type") == Some("submit")) {
            let v = Values::parse(x);
            let first = |var: &str| v.get(var).filter(|s| !s.is_empty()).map(str::to_string);
            f.username = f.username.or_else(|| first("username"));
            f.password = f.password.or_else(|| first("password"));
            f.token = f.token.or_else(|| first("token")).or_else(|| first("preauth"));
        }
        f
    }
}

/// Makes the account (or resets a password with a reset invite).
async fn register(srv: &Arc<Server>, host: &Arc<Host>, f: Fields, ip: Option<IpAddr>, token: Option<&str>) -> Result<(), StanzaError> {
    let unacceptable = |t: &str| StanzaError::new(Condition::NotAcceptable).with_text(t);
    let internal = |e: &dyn std::fmt::Display| {
        tracing::warn!(error = %e, "registration failed");
        StanzaError::internal()
    };
    let user = f.username.as_deref().map(str::trim).unwrap_or_default().to_lowercase();
    if user.is_empty() {
        return Err(unacceptable("Choose a username."));
    }
    if !crate::accounts::valid_username(&user) {
        return Err(unacceptable(
            "Usernames use lowercase letters, numbers, dots, dashes or underscores, starting with a letter or number.",
        ));
    }
    let password = f.password.unwrap_or_default();
    if let Err(AccountError::Invalid(t)) = crate::accounts::check_password(&password) {
        return Err(unacceptable(&t));
    }

    let settings = host.settings();
    let gone = || StanzaError::item_not_found().with_text("This invite has expired or was already used.");
    let invite = match token {
        // Checked again as it's used: sign-up may have closed since `<preauth/>`.
        Some(t) => Some(
            invites::find(srv, &host.domain, t)
                .await
                .map_err(|e| internal(&e))?
                .filter(|s| invites::allows_signup(s, host))
                .ok_or_else(gone)?,
        ),
        None => None,
    };
    if let Some(s) = &invite {
        if let Some(fixed) = s.username.as_deref().filter(|u| *u != user) {
            return Err(StanzaError::new(Condition::NotAllowed).with_text(format!("This invite is for the username {fixed}.")));
        }
    } else {
        match settings.sign_up {
            SignUp::Open => {}
            SignUp::Invite => {
                return Err(StanzaError::new(Condition::NotAllowed)
                    .with_text(format!("Sign-up on {} is by invitation. Ask someone for an invite link.", host.domain)))
            }
            SignUp::Closed => {
                return Err(StanzaError::new(Condition::NotAllowed)
                    .with_text(format!("Sign-up is closed on {}. Ask an admin for an account.", host.domain)))
            }
        }
    }
    let reset = invite.as_ref().is_some_and(|s| s.reset);
    let named_by_invite = invite.as_ref().is_some_and(|s| s.username.as_deref() == Some(user.as_str()));
    if reserved(&user) && !named_by_invite {
        return Err(StanzaError::new(Condition::NotAcceptable).with_text("That username is reserved. Choose another one."));
    }
    // An admin in the config file is one by name, whoever makes the account: that's done with
    // `quark ctl` or the admin API, never by signing up, with an invite or without.
    if !reset && host.is_admin_jid(&Jid::bare_unchecked(&user, &host.domain)) {
        return Err(StanzaError::new(Condition::NotAcceptable).with_text("That username is reserved. Choose another one."));
    }

    if reset {
        let t = token.unwrap_or_default();
        let claimed = invites::claim(srv, &host.domain, t).await.map_err(|e| internal(&e))?.ok_or_else(gone)?;
        return match change_password(srv, host, &user, &password, Some("The password was reset.")).await {
            Ok(_) => {
                tracing::info!(account = %format!("{user}@{}", host.domain), "password reset with an invite");
                Ok(())
            }
            Err(e) => {
                invites::unclaim(srv, &claimed.token).await;
                Err(match e {
                    AccountError::Invalid(t) => unacceptable(&t),
                    AccountError::NotFound(_) => StanzaError::item_not_found().with_text("That account doesn't exist anymore."),
                    e => internal(&e),
                })
            }
        };
    }

    // Sign-ups from one address: open ones, and with a member's invite (more of those). Admin
    // invites aren't limited. The attempt is logged before anything slow, so parallel sign-ups
    // can't all slip under the limit.
    let ip_key = ip_key(ip);
    let limit = srv.config().limits.registrations_per_hour;
    let allowance = match &invite {
        None => Some(limit),
        Some(s) if s.inviter.is_some() => Some(limit.saturating_mul(INVITED_FACTOR)),
        Some(_) => None,
    };
    let slot = match allowance {
        Some(n) => match reserve(srv, &ip_key, n).await.map_err(|e| internal(&e))? {
            Some(id) => Some(id),
            None => {
                return Err(StanzaError::new(Condition::PolicyViolation)
                    .with_type(quark_core::ErrorType::Wait)
                    .with_text("Too many accounts were made from your address. Try again in an hour."))
            }
        },
        None => None,
    };

    // Take the invite's use now, so two people can't both redeem a single-use invite.
    let claimed = match token {
        Some(t) => match invites::claim_signup(srv, host, t, &user).await {
            Ok(invites::SignupClaim::Claimed(s)) => Some(s),
            Ok(invites::SignupClaim::Gone) => {
                settle(srv, slot, Attempt::Void).await;
                return Err(gone());
            }
            Ok(invites::SignupClaim::InviterBusy) => {
                settle(srv, slot, Attempt::Void).await;
                return Err(StanzaError::new(Condition::PolicyViolation)
                    .with_type(quark_core::ErrorType::Wait)
                    .with_text("Many people joined with this person's invites today. Try again tomorrow."));
            }
            Err(e) => {
                settle(srv, slot, Attempt::Void).await;
                return Err(internal(&e));
            }
        },
        None => None,
    };

    let role = claimed.as_ref().map_or(Role::Member, |s| s.role);
    if let Err(e) = create_account(srv, host, &user, &password, role).await {
        if let Some(s) = &claimed {
            invites::unclaim(srv, &s.token).await;
        }
        let taken = matches!(e, AccountError::Exists(_));
        settle(srv, slot, if taken { Attempt::Failed } else { Attempt::Void }).await;
        return Err(match e {
            AccountError::Exists(_) => StanzaError::new(Condition::Conflict).with_text("That username is taken. Choose another one."),
            AccountError::Invalid(t) => unacceptable(&t),
            e => internal(&e),
        });
    }
    if let Some(inviter) = claimed.as_ref().and_then(|s| s.inviter.as_deref()) {
        if let Err(e) = invites::befriend(srv, host, inviter, &user).await {
            tracing::warn!(error = %e, "couldn't add the inviter as a contact");
        }
    }
    tracing::info!(account = %format!("{user}@{}", host.domain), ip = %ip_key, invited = claimed.is_some(), "account registered in-band");
    Ok(())
}

/// The key sign-ups are counted under: the IPv4 address, or the /64 of an IPv6 one, since one
/// connection usually has a whole /64 to pick addresses from.
fn ip_key(ip: Option<IpAddr>) -> String {
    match ip.map(|i| i.to_canonical()) {
        None => "unknown".to_string(),
        Some(IpAddr::V4(v4)) => v4.to_string(),
        Some(IpAddr::V6(v6)) => match ipnet::Ipv6Net::new(v6, 64) {
            Ok(net) => net.trunc().to_string(),
            Err(_) => v6.to_string(),
        },
    }
}

/// Logs a sign-up attempt from `key` unless the address is out of attempts: `allowance`
/// accounts an hour, and [`ATTEMPTS_FACTOR`] times that in attempts. One transaction on the
/// single writer, so concurrent attempts are counted one by one. Returns the log row.
async fn reserve(srv: &Server, key: &str, allowance: u32) -> Result<Option<i64>, DbError> {
    let (key, now) = (key.to_string(), quark_core::time::now_ms());
    let (made_max, tried_max) = (i64::from(allowance), i64::from(allowance) * i64::from(ATTEMPTS_FACTOR));
    srv.db
        .write(move |t| {
            let (made, tried): (i64, i64) = t.query_row(
                "SELECT COALESCE(SUM(ok), 0), COUNT(*) FROM ibr_log WHERE ip = ?1 AND at > ?2",
                params![key, now - HOUR_MS],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if made >= made_max || tried >= tried_max {
                return Ok(None);
            }
            t.execute("INSERT INTO ibr_log (ip, at, ok) VALUES (?1, ?2, 1)", params![key, now])?;
            Ok(Some(t.last_insert_rowid()))
        })
        .await
}

/// How a logged attempt that didn't make an account ends.
enum Attempt {
    /// Counts as an attempt (a taken username).
    Failed,
    /// Not the person's doing (an invite used up meanwhile, a server error): forgotten.
    Void,
}

async fn settle(srv: &Server, slot: Option<i64>, how: Attempt) {
    let Some(id) = slot else { return };
    let r = srv
        .db
        .write(move |t| match how {
            Attempt::Failed => t.execute("UPDATE ibr_log SET ok = 0 WHERE rowid = ?1", [id]),
            Attempt::Void => t.execute("DELETE FROM ibr_log WHERE rowid = ?1", [id]),
        })
        .await;
    if let Err(e) = r {
        tracing::warn!(error = %e, "couldn't update the registration log");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_from_legacy_and_forms() {
        let q = Element::parse("<query xmlns='jabber:iq:register'><username>sam</username><password>pw</password></query>").unwrap();
        let f = Fields::read(&q);
        assert_eq!((f.username.as_deref(), f.password.as_deref()), (Some("sam"), Some("pw")));
        let q = Element::parse(
            "<query xmlns='jabber:iq:register'><x xmlns='jabber:x:data' type='submit'>\
             <field var='FORM_TYPE'><value>jabber:iq:register</value></field>\
             <field var='username'><value>kim</value></field><field var='password'><value>secret12</value></field></x>\
             <preauth xmlns='urn:xmpp:pars:0' token='tok'/></query>",
        )
        .unwrap();
        let f = Fields::read(&q);
        assert_eq!((f.username.as_deref(), f.password.as_deref(), f.token.as_deref()), (Some("kim"), Some("secret12"), Some("tok")));
    }

    #[test]
    fn empty_legacy_fields_leave_the_form_in_charge() {
        let q = Element::parse(
            "<query xmlns='jabber:iq:register'><username/><password></password><x xmlns='jabber:x:data' type='submit'>\
             <field var='username'><value>kim</value></field><field var='password'><value>secret12</value></field></x></query>",
        )
        .unwrap();
        let f = Fields::read(&q);
        assert_eq!((f.username.as_deref(), f.password.as_deref()), (Some("kim"), Some("secret12")));
    }

    #[test]
    fn addresses_are_counted_by_ipv4_or_ipv6_64() {
        let key = |s: &str| ip_key(Some(s.parse().unwrap()));
        assert_eq!(key("192.0.2.7"), "192.0.2.7");
        assert_eq!(key("::ffff:192.0.2.7"), "192.0.2.7");
        assert_eq!(key("2001:db8:1:2:aaaa::1"), "2001:db8:1:2::/64");
        assert_eq!(key("2001:db8:1:2:bbbb:cccc:dddd:eeee"), key("2001:db8:1:2::9"));
        assert_ne!(key("2001:db8:1:3::1"), key("2001:db8:1:2::1"));
        assert_eq!(ip_key(None), "unknown");
    }

    #[test]
    fn official_names_are_reserved() {
        assert!(reserved("admin") && reserved("postmaster") && reserved("root"));
        assert!(!reserved("sam"));
    }
}
