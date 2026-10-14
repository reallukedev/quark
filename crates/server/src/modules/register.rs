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

use super::{invites, ok, ok_empty, Event, IqCtx, IqReply, IqResult, IqTarget, Module};
use crate::accounts::{AccountError, Role};
use crate::db::{params, DbError, Migration};
use crate::server::{Host, Server};
use crate::settings::SignUp;

pub static MIGRATION: Migration = Migration {
    module: "register",
    steps: &["CREATE TABLE ibr_log (ip TEXT NOT NULL, at INTEGER NOT NULL);
              CREATE INDEX ibr_log_by_ip ON ibr_log (ip, at);"],
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

/// Invite tokens one connection may try before it's refused, though guessing 144 bits is hopeless.
const MAX_TOKEN_TRIES: u8 = 5;
const HOUR_MS: i64 = 3_600_000;

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

/// A registration IQ before sign-in. Returns the reply to send.
pub async fn preauth(srv: &Arc<Server>, host: &Arc<Host>, iq: &Element, secure: bool, ip: Option<IpAddr>) -> Option<Element> {
    preauth_with(srv, host, iq, secure, ip, &mut PreauthState::default()).await
}

/// [`preauth`], remembering an invite token across IQs on the same connection.
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
                Some(t) => invites::find(srv, &host.domain, t).await.ok().flatten(),
                None => None,
            };
            Some(iq_result(iq).child(form(host, invite.as_ref())))
        }
        Some(IqType::Set) => {
            if q.has_child("remove", ns::REGISTER) {
                return fail(StanzaError::new(Condition::NotAuthorized).with_text("Sign in first to delete an account."));
            }
            let f = Fields::read(q);
            if let Some(t) = &f.token {
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

async fn check_token(srv: &Server, host: &Host, token: Option<&str>, state: &mut PreauthState) -> Result<String, StanzaError> {
    state.tries = state.tries.saturating_add(1);
    if state.tries > MAX_TOKEN_TRIES {
        return Err(StanzaError::new(Condition::PolicyViolation).with_text("Too many invite codes tried on this connection."));
    }
    let gone = || StanzaError::item_not_found().with_text("This invite has expired or was already used.");
    let token = token.filter(|t| invites::plausible_token(t)).ok_or_else(gone)?;
    match invites::find(srv, &host.domain, token).await {
        Ok(Some(s)) if invites::allows_signup(&s, host) || s.reset => Ok(s.token),
        Ok(_) => Err(gone()),
        Err(e) => {
            tracing::warn!(error = %e, "couldn't check an invite");
            Err(StanzaError::internal())
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
    let field = |var: &str, kind: &str, label: &str, value: Option<&str>| {
        let mut f = Element::new("field", ns::DATA_FORMS)
            .attr_set("var", var)
            .attr_set("type", kind)
            .attr_set("label", label)
            .child(Element::new("required", ns::DATA_FORMS));
        if let Some(v) = value {
            f.append(Element::new("value", ns::DATA_FORMS).text(v));
        }
        f
    };
    let x = Element::new("x", ns::DATA_FORMS)
        .attr_set("type", "form")
        .text_child("title", ns::DATA_FORMS, format!("Make an account on {}", host.domain))
        .text_child("instructions", ns::DATA_FORMS, instructions.clone())
        .child(
            Element::new("field", ns::DATA_FORMS)
                .attr_set("var", "FORM_TYPE")
                .attr_set("type", "hidden")
                .child(Element::new("value", ns::DATA_FORMS).text(ns::REGISTER)),
        )
        .child(field("username", "text-single", "Username", fixed.as_deref()))
        .child(field("password", "text-private", "Password", None));
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
    fn read(q: &Element) -> Fields {
        let mut f = Fields {
            username: q.child_text("username", ns::REGISTER),
            password: q.child_text("password", ns::REGISTER),
            token: q.get_child("preauth", ns::PARS).and_then(|p| p.attr("token")).map(str::to_string),
        };
        if let Some(x) = q.get_child("x", ns::DATA_FORMS).filter(|x| x.attr("type") == Some("submit")) {
            for field in x.children().filter(|c| c.is("field", ns::DATA_FORMS)) {
                let v = field.child_text("value", ns::DATA_FORMS);
                match field.attr("var") {
                    Some("username") if f.username.is_none() => f.username = v,
                    Some("password") if f.password.is_none() => f.password = v,
                    Some("token" | "preauth") if f.token.is_none() => f.token = v,
                    _ => {}
                }
            }
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
    let invite = match token {
        Some(t) => Some(
            invites::find(srv, &host.domain, t)
                .await
                .map_err(|e| internal(&e))?
                .ok_or_else(|| StanzaError::item_not_found().with_text("This invite has expired or was already used."))?,
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
    let named_by_invite = invite.as_ref().is_some_and(|s| s.username.as_deref() == Some(user.as_str()));
    if reserved(&user) && !named_by_invite {
        return Err(StanzaError::new(Condition::NotAcceptable).with_text("That username is reserved. Choose another one."));
    }
    let ip_key = ip.map_or_else(|| "unknown".to_string(), |i| i.to_string());
    if invite.is_none() {
        let limit = srv.config().limits.registrations_per_hour;
        if recent_registrations(srv, &ip_key).await.map_err(|e| internal(&e))? >= u64::from(limit) {
            return Err(StanzaError::new(Condition::PolicyViolation)
                .with_type(quark_core::ErrorType::Wait)
                .with_text("Too many accounts were made from your address. Try again in an hour."));
        }
    }

    // Take the invite's use now, so two people can't both redeem a single-use invite.
    let claimed = match token {
        Some(t) => Some(
            invites::claim(srv, &host.domain, t)
                .await
                .map_err(|e| internal(&e))?
                .ok_or_else(|| StanzaError::item_not_found().with_text("This invite has expired or was already used."))?,
        ),
        None => None,
    };
    let give_back = |s: &Option<invites::Stored>| {
        let t = s.as_ref().map(|s| s.token.clone());
        async move {
            if let Some(t) = t {
                invites::unclaim(srv, &t).await;
            }
        }
    };

    if claimed.as_ref().is_some_and(|s| s.reset) {
        return match change_password(srv, host, &user, &password, Some("The password was reset.")).await {
            Ok(_) => {
                tracing::info!(account = %format!("{user}@{}", host.domain), "password reset with an invite");
                Ok(())
            }
            Err(e) => {
                give_back(&claimed).await;
                Err(match e {
                    AccountError::Invalid(t) => unacceptable(&t),
                    AccountError::NotFound(_) => StanzaError::item_not_found().with_text("That account doesn't exist anymore."),
                    e => internal(&e),
                })
            }
        };
    }

    let role = claimed.as_ref().map_or(Role::Member, |s| s.role);
    match create_account(srv, host, &user, &password, role).await {
        Ok(()) => {}
        Err(e) => {
            give_back(&claimed).await;
            return Err(match e {
                AccountError::Exists(_) => StanzaError::new(Condition::Conflict).with_text("That username is taken. Choose another one."),
                AccountError::Invalid(t) => unacceptable(&t),
                e => internal(&e),
            });
        }
    }
    if claimed.is_none() {
        let now = quark_core::time::now_ms();
        let key = ip_key.clone();
        if let Err(e) = srv.db.write(move |t| t.execute("INSERT INTO ibr_log (ip, at) VALUES (?1, ?2)", params![key, now])).await {
            tracing::warn!(error = %e, "couldn't log a registration");
        }
    }
    if let Some(inviter) = claimed.as_ref().and_then(|s| s.inviter.as_deref()) {
        if let Err(e) = invites::befriend(srv, host, inviter, &user).await {
            tracing::warn!(error = %e, "couldn't add the inviter as a contact");
        }
    }
    tracing::info!(account = %format!("{user}@{}", host.domain), ip = %ip_key, invited = claimed.is_some(), "account registered in-band");
    Ok(())
}

async fn recent_registrations(srv: &Server, ip: &str) -> Result<u64, DbError> {
    let (ip, since) = (ip.to_string(), quark_core::time::now_ms() - HOUR_MS);
    srv.db
        .read(move |c| {
            c.prepare_cached("SELECT COUNT(*) FROM ibr_log WHERE ip = ?1 AND at > ?2")?
                .query_row(params![ip, since], |r| r.get::<_, i64>(0))
        })
        .await
        .map(|n| n.max(0) as u64)
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
    fn official_names_are_reserved() {
        assert!(reserved("admin") && reserved("postmaster") && reserved("root"));
        assert!(!reserved("sam"));
    }
}
