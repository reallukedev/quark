//! Ad-Hoc Commands (XEP-0050) with service administration (XEP-0133), and invites from chat
//! apps the way Prosody's mod_invites_adhoc offers them (Conversations and others show an
//! "invite" button when the server lists `urn:xmpp:invite#invite`).
//!
//! Every command here takes at most one form, so there's no session state to keep: executing
//! returns the form, submitting it (with any `sessionid`) completes the command.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use quark_core::stanza::IqType;
use quark_core::{ns, Condition, Element, Jid, StanzaError};

use super::{invites, ok, register, IqCtx, IqResult, IqTarget, Module};
use crate::accounts::{AccountError, Role};
use crate::server::{Host, Server};
use crate::settings::SignUp;

const ADMIN: &str = "http://jabber.org/protocol/admin";
/// Accounts one command touches at most, and users an online list shows.
const MAX_JIDS: usize = 500;
const MAX_ANNOUNCE: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Who {
    Admins,
    /// Any local account, while sign-up isn't closed.
    Members,
}

struct Command {
    node: &'static str,
    name: &'static str,
    who: Who,
}

const COMMANDS: &[Command] = &[
    Command { node: "urn:xmpp:invite#invite", name: "Invite someone", who: Who::Members },
    Command { node: "urn:xmpp:invite#create-account", name: "Create an account invite", who: Who::Admins },
    Command { node: "http://jabber.org/protocol/admin#add-user", name: "Add a user", who: Who::Admins },
    Command { node: "http://jabber.org/protocol/admin#delete-user", name: "Delete users", who: Who::Admins },
    Command { node: "http://jabber.org/protocol/admin#disable-user", name: "Turn users off", who: Who::Admins },
    Command { node: "http://jabber.org/protocol/admin#reenable-user", name: "Turn users back on", who: Who::Admins },
    Command { node: "http://jabber.org/protocol/admin#change-user-password", name: "Change a user's password", who: Who::Admins },
    Command { node: "http://jabber.org/protocol/admin#end-user-session", name: "Sign users out", who: Who::Admins },
    Command { node: "http://jabber.org/protocol/admin#get-online-users-list", name: "List online users", who: Who::Admins },
    Command { node: "http://jabber.org/protocol/admin#get-online-users-num", name: "Count online users", who: Who::Admins },
    Command { node: "http://jabber.org/protocol/admin#get-registered-users-num", name: "Count accounts", who: Who::Admins },
    Command { node: "http://jabber.org/protocol/admin#announce", name: "Message everyone online", who: Who::Admins },
];

fn allowed(cx: &IqCtx<'_>, c: &Command) -> bool {
    match c.who {
        Who::Admins => cx.is_admin(),
        Who::Members => cx.local_sender().is_some() && cx.host.settings().sign_up != SignUp::Closed,
    }
}

pub struct AdHoc;

#[async_trait]
impl Module for AdHoc {
    fn name(&self) -> &'static str {
        "adhoc"
    }

    fn snapshot_names(&self, _host: &Host) -> Vec<&'static str> {
        vec!["adhoc", "admin_adhoc"]
    }

    fn server_features(&self, _host: &Host) -> Vec<&'static str> {
        vec![ns::COMMANDS]
    }

    fn iq_namespaces(&self) -> &'static [(&'static str, IqTarget)] {
        &[(ns::COMMANDS, IqTarget::Server)]
    }

    async fn server_node(&self, cx: &IqCtx<'_>, node: &str) -> Option<Vec<Element>> {
        let info = cx.payload.ns() == ns::DISCO_INFO;
        if node == ns::COMMANDS {
            return Some(if info {
                vec![
                    identity("automation", "command-list", "Commands"),
                    Element::new("feature", ns::DISCO_INFO).attr_set("var", ns::COMMANDS),
                ]
            } else {
                COMMANDS
                    .iter()
                    .filter(|c| allowed(cx, c))
                    .map(|c| {
                        Element::new("item", ns::DISCO_ITEMS)
                            .attr_set("jid", cx.host.domain.clone())
                            .attr_set("node", c.node)
                            .attr_set("name", c.name)
                    })
                    .collect()
            });
        }
        let c = COMMANDS.iter().find(|c| c.node == node)?;
        if !allowed(cx, c) {
            return Some(Vec::new());
        }
        Some(if info {
            vec![
                identity("automation", "command-node", c.name),
                Element::new("feature", ns::DISCO_INFO).attr_set("var", ns::COMMANDS),
                Element::new("feature", ns::DISCO_INFO).attr_set("var", ns::DATA_FORMS),
            ]
        } else {
            Vec::new()
        })
    }

    async fn handle_iq(&self, cx: &IqCtx<'_>) -> IqResult {
        if cx.kind != IqType::Set || cx.payload.name() != "command" {
            return Err(StanzaError::bad_request());
        }
        let node = cx.payload.attr("node").unwrap_or_default();
        let Some(c) = COMMANDS.iter().find(|c| c.node == node) else {
            return Err(StanzaError::item_not_found().with_text("There's no such command."));
        };
        if !allowed(cx, c) {
            return Err(StanzaError::forbidden().with_text("You aren't allowed to run this command."));
        }
        let sessionid = cx.payload.attr("sessionid").map_or_else(quark_core::new_id, str::to_string);
        let action = cx.payload.attr("action").unwrap_or("execute");
        let reply = |status: &str| {
            Element::new("command", ns::COMMANDS)
                .attr_set("node", c.node)
                .attr_set("sessionid", sessionid.clone())
                .attr_set("status", status)
        };
        if action == "cancel" {
            return ok(reply("canceled"));
        }
        if !matches!(action, "execute" | "complete" | "next") {
            return Err(StanzaError::bad_request().with_app(Element::new("malformed-action", ns::COMMANDS)));
        }
        let submitted = cx.payload.get_child("x", ns::DATA_FORMS).filter(|x| x.attr("type") == Some("submit")).map(values);
        let out = run(cx, c.node, submitted, action == "complete").await?;
        Ok(match out {
            Out::Form(x) => {
                let actions =
                    Element::new("actions", ns::COMMANDS).attr_set("execute", "complete").child(Element::new("complete", ns::COMMANDS));
                super::IqReply::Result(Some(reply("executing").child(actions).child(x)))
            }
            Out::Done { note, result } => {
                let mut r = reply("completed");
                if let Some((kind, text)) = note {
                    r.append(Element::new("note", ns::COMMANDS).attr_set("type", kind).text(text));
                }
                if let Some(x) = result {
                    r.append(x);
                }
                super::IqReply::Result(Some(r))
            }
        })
    }
}

enum Out {
    /// Ask for input.
    Form(Element),
    Done {
        note: Option<(&'static str, String)>,
        result: Option<Element>,
    },
}

fn info(text: impl Into<String>) -> Out {
    Out::Done { note: Some(("info", text.into())), result: None }
}

fn problem(text: impl Into<String>) -> Out {
    Out::Done { note: Some(("error", text.into())), result: None }
}

type Values = HashMap<String, Vec<String>>;

/// A submitted form's values by field.
fn values(x: &Element) -> Values {
    let mut m = Values::new();
    for f in x.children().filter(|c| c.is("field", ns::DATA_FORMS)) {
        let Some(var) = f.attr("var") else { continue };
        let vs = f.children().filter(|c| c.is("value", ns::DATA_FORMS)).map(Element::text_content).take(MAX_JIDS);
        m.entry(var.to_string()).or_default().extend(vs);
    }
    m
}

fn one<'a>(v: &'a Values, k: &str) -> Option<&'a str> {
    v.get(k).and_then(|l| l.first()).map(|s| s.trim()).filter(|s| !s.is_empty())
}

fn flag(v: &Values, k: &str) -> bool {
    matches!(one(v, k), Some("1" | "true"))
}

fn identity(category: &str, kind: &str, name: &str) -> Element {
    Element::new("identity", ns::DISCO_INFO).attr_set("category", category).attr_set("type", kind).attr_set("name", name)
}

fn form(kind: &str, title: &str, instructions: Option<&str>, form_type: &str, fields: Vec<Element>) -> Element {
    let mut x = Element::new("x", ns::DATA_FORMS).attr_set("type", kind).text_child("title", ns::DATA_FORMS, title);
    if let Some(i) = instructions {
        x.append(Element::new("instructions", ns::DATA_FORMS).text(i));
    }
    x.append(field("FORM_TYPE", "hidden", None, false, &[form_type]));
    x.children_from(fields)
}

fn field(var: &str, kind: &str, label: Option<&str>, required: bool, vals: &[&str]) -> Element {
    let mut f = Element::new("field", ns::DATA_FORMS).attr_set("var", var).attr_set("type", kind).attr_opt("label", label);
    if required {
        f.append(Element::new("required", ns::DATA_FORMS));
    }
    for v in vals {
        f.append(Element::new("value", ns::DATA_FORMS).text(*v));
    }
    f
}

/// Local usernames from a form's JID fields: `sam`, `sam@host` or `xmpp:sam@host`.
fn usernames(host: &Host, vals: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for v in vals.iter().map(|v| v.trim()).filter(|v| !v.is_empty()) {
        let raw = v.trim_start_matches("xmpp:");
        let j = if raw.contains('@') { Jid::parse(raw) } else { Jid::from_parts(Some(raw), &host.domain, None) };
        match j {
            Ok(j) if j.domain() == host.domain && j.node().is_some() => {
                let u = j.node().unwrap_or_default().to_string();
                if !out.contains(&u) {
                    out.push(u);
                }
            }
            Ok(j) if j.node().is_some() => return Err(format!("{} isn't on {}.", j.to_bare(), host.domain)),
            _ => return Err(format!("\"{v}\" isn't a chat address.")),
        }
    }
    Ok(out)
}

fn accountjids_form(title: &str, instructions: &str) -> Out {
    Out::Form(form("form", title, Some(instructions), ADMIN, vec![field("accountjids", "jid-multi", Some("Accounts"), true, &[])]))
}

async fn run(cx: &IqCtx<'_>, node: &str, input: Option<Values>, complete: bool) -> Result<Out, StanzaError> {
    let srv = cx.srv;
    let host = cx.host;
    let internal = |e: &dyn std::fmt::Display| {
        tracing::warn!(error = %e, node, "ad-hoc command failed");
        StanzaError::internal()
    };
    let admin = cx.local_sender().map(|j| j.to_string()).unwrap_or_default();
    let cmd = node.rsplit('#').next().unwrap_or(node);
    Ok(match (node.starts_with("urn:xmpp:invite#"), cmd, input) {
        (true, "invite", _) => {
            let inviter = cx.local_sender().and_then(|j| j.node().map(str::to_string)).unwrap_or_default();
            let n = invites::NewInvite {
                host: &host.domain,
                username: None,
                inviter: Some(&inviter),
                role: Role::Member,
                ttl_ms: invites::FRIEND_TTL_MS,
                reusable: false,
                reset: false,
            };
            invite_result(srv, n, "Send this link to the person you want to chat with.").await.map_err(|e| internal(&e))?
        }
        (true, "create-account", None) if !complete => Out::Form(form(
            "form",
            "Create an account invite",
            Some("Leave the username empty to let the person choose one."),
            "urn:xmpp:invite#create-account",
            vec![
                field("username", "text-single", Some("Username (optional)"), false, &[]),
                field("admin", "boolean", Some("Make them an admin"), false, &["0"]),
                field("reusable", "boolean", Some("Can be used by several people"), false, &["0"]),
                field("days", "text-single", Some("Valid for (days)"), false, &["7"]),
            ],
        )),
        (true, "create-account", input) => {
            let v = input.unwrap_or_default();
            let username = one(&v, "username").map(str::to_lowercase);
            let days = match one(&v, "days").map(str::parse::<u32>) {
                None => 7,
                Some(Ok(d)) if (1..=3650).contains(&d) => d,
                Some(_) => return Ok(problem("Invites last between 1 and 3650 days.")),
            };
            let n = invites::NewInvite {
                host: &host.domain,
                username: username.as_deref(),
                inviter: None,
                role: if flag(&v, "admin") { Role::Admin } else { Role::Member },
                ttl_ms: i64::from(days) * invites::DAY_MS,
                reusable: flag(&v, "reusable"),
                reset: false,
            };
            tracing::info!(target: "quark::audit", by = %admin, host = %host.domain, "invite created over ad-hoc");
            invite_result(srv, n, "Send this link to the person you're inviting.").await.map_err(|e| internal(&e))?
        }
        (false, "add-user", None) => Out::Form(form(
            "form",
            "Add a user",
            Some("Choose the address and a password for the new account."),
            ADMIN,
            vec![
                field("accountjid", "jid-single", Some("Address"), true, &[]),
                field("password", "text-private", Some("Password"), true, &[]),
                field("password-verify", "text-private", Some("Password again"), false, &[]),
            ],
        )),
        (false, "add-user", Some(v)) => {
            let user = match usernames(host, v.get("accountjid").map(Vec::as_slice).unwrap_or_default()) {
                Ok(u) if u.len() == 1 => u.into_iter().next().unwrap_or_default(),
                Ok(_) => return Ok(problem("Give exactly one address.")),
                Err(e) => return Ok(problem(e)),
            };
            let pw = one(&v, "password").unwrap_or_default();
            if one(&v, "password-verify").is_some_and(|p| p != pw) {
                return Ok(problem("The passwords don't match."));
            }
            match register::create_account(srv, host, &user, pw, Role::Member).await {
                Ok(()) => {
                    tracing::info!(target: "quark::audit", by = %admin, account = %format!("{user}@{}", host.domain), "account created over ad-hoc");
                    info(format!("Created {user}@{}.", host.domain))
                }
                Err(AccountError::Db(e)) => return Err(internal(&e)),
                Err(e) => problem(e.to_string()),
            }
        }
        (false, "delete-user", None) => accountjids_form("Delete users", "Everything stored for these accounts is deleted."),
        (false, "disable-user", None) => accountjids_form("Turn users off", "They're signed out and can't sign in until turned back on."),
        (false, "reenable-user", None) => accountjids_form("Turn users back on", "They can sign in again."),
        (false, "end-user-session", None) => accountjids_form("Sign users out", "Every device of these accounts is disconnected."),
        (false, c @ ("delete-user" | "disable-user" | "reenable-user" | "end-user-session"), Some(v)) => {
            let users = match usernames(host, v.get("accountjids").map(Vec::as_slice).unwrap_or_default()) {
                Ok(u) if !u.is_empty() => u,
                Ok(_) => return Ok(problem("Give at least one address.")),
                Err(e) => return Ok(problem(e)),
            };
            let mut missing = Vec::new();
            let mut done = 0usize;
            for u in &users {
                let bare = Jid::bare_unchecked(u, &host.domain);
                let r: Result<bool, AccountError> = match c {
                    "delete-user" => {
                        register::delete_account(srv, host, u, "This account was deleted by an admin.").await.map_err(Into::into)
                    }
                    "disable-user" => register::set_enabled(srv, host, u, false).await.map(|_| true),
                    "reenable-user" => register::set_enabled(srv, host, u, true).await.map(|_| true),
                    _ => match register::close_sessions(srv, &bare, "reset", "An admin signed you out.") {
                        0 => srv.accounts.exists(&host.domain, u).await.map_err(Into::into),
                        _ => Ok(true),
                    },
                };
                match r {
                    Ok(true) => done += 1,
                    Ok(false) | Err(AccountError::NotFound(_)) => missing.push(format!("{u}@{}", host.domain)),
                    Err(e) => return Err(internal(&e)),
                }
            }
            tracing::info!(target: "quark::audit", by = %admin, command = c, accounts = ?users, "accounts changed over ad-hoc");
            let verb = match c {
                "delete-user" => "Deleted",
                "disable-user" => "Turned off",
                "reenable-user" => "Turned on",
                _ => "Signed out",
            };
            let mut text = format!("{verb} {done} account{}.", if done == 1 { "" } else { "s" });
            if !missing.is_empty() {
                text.push_str(&format!(" Not found: {}.", missing.join(", ")));
            }
            info(text)
        }
        (false, "change-user-password", None) => Out::Form(form(
            "form",
            "Change a user's password",
            Some("Their devices are signed out and need the new password."),
            ADMIN,
            vec![
                field("accountjid", "jid-single", Some("Address"), true, &[]),
                field("password", "text-private", Some("New password"), true, &[]),
            ],
        )),
        (false, "change-user-password", Some(v)) => {
            let user = match usernames(host, v.get("accountjid").map(Vec::as_slice).unwrap_or_default()) {
                Ok(u) if u.len() == 1 => u.into_iter().next().unwrap_or_default(),
                Ok(_) => return Ok(problem("Give exactly one address.")),
                Err(e) => return Ok(problem(e)),
            };
            match register::change_password(
                srv,
                host,
                &user,
                one(&v, "password").unwrap_or_default(),
                Some("An admin changed the password."),
            )
            .await
            {
                Ok(_) => {
                    tracing::info!(target: "quark::audit", by = %admin, account = %format!("{user}@{}", host.domain), "password changed over ad-hoc");
                    info(format!("Changed the password of {user}@{}.", host.domain))
                }
                Err(AccountError::Db(e)) => return Err(internal(&e)),
                Err(e) => problem(e.to_string()),
            }
        }
        (false, "get-online-users-list", _) => {
            let mut users: Vec<String> = srv.sessions.on_host(&host.domain).iter().map(|s| s.jid.to_bare().to_string()).collect();
            users.sort_unstable();
            users.dedup();
            users.truncate(MAX_JIDS);
            let refs: Vec<&str> = users.iter().map(String::as_str).collect();
            Out::Done {
                note: None,
                result: Some(form(
                    "result",
                    "Online users",
                    None,
                    ADMIN,
                    vec![field("onlineuserjids", "jid-multi", Some("Online users"), false, &refs)],
                )),
            }
        }
        (false, "get-online-users-num", _) => {
            let mut users: Vec<Jid> = srv.sessions.on_host(&host.domain).iter().map(|s| s.jid.to_bare()).collect();
            users.sort_unstable();
            users.dedup();
            let n = users.len().to_string();
            Out::Done {
                note: None,
                result: Some(form(
                    "result",
                    "Online users",
                    None,
                    ADMIN,
                    vec![field("onlineusersnum", "text-single", Some("Online users"), false, &[&n])],
                )),
            }
        }
        (false, "get-registered-users-num", _) => {
            let n = srv.accounts.count(&host.domain).await.map_err(|e| internal(&e))?.to_string();
            Out::Done {
                note: None,
                result: Some(form(
                    "result",
                    "Accounts",
                    None,
                    ADMIN,
                    vec![field("registeredusersnum", "text-single", Some("Accounts"), false, &[&n])],
                )),
            }
        }
        (false, "announce", None) => Out::Form(form(
            "form",
            "Message everyone online",
            Some("Everyone signed in right now gets this message from the server."),
            ADMIN,
            vec![
                field("subject", "text-single", Some("Subject"), false, &[]),
                field("announcement", "text-multi", Some("Message"), true, &[]),
            ],
        )),
        (false, "announce", Some(v)) => {
            let body = v.get("announcement").map(|l| l.join("\n")).unwrap_or_default();
            if body.trim().is_empty() {
                return Ok(problem("Write a message first."));
            }
            if body.len() > MAX_ANNOUNCE {
                return Ok(problem("That message is too long."));
            }
            let n = announce(srv, host, one(&v, "subject"), &body).await;
            tracing::info!(target: "quark::audit", by = %admin, host = %host.domain, recipients = n, "announcement sent");
            info(format!("Sent to {n} account{}.", if n == 1 { "" } else { "s" }))
        }
        _ => return Err(StanzaError::new(Condition::BadRequest).with_app(Element::new("bad-payload", ns::COMMANDS))),
    })
}

/// Sends a message from the domain to every account with a device online. Returns how many.
pub async fn announce(srv: &Arc<Server>, host: &Host, subject: Option<&str>, body: &str) -> usize {
    let mut users: Vec<Jid> = srv.sessions.on_host(&host.domain).iter().filter(|s| s.available()).map(|s| s.jid.to_bare()).collect();
    users.sort_unstable();
    users.dedup();
    for u in &users {
        let mut m = quark_core::stanza::chat_message(&host.domain, &u.to_string(), "chat", body);
        if let Some(s) = subject {
            m.append(Element::new("subject", ns::CLIENT).text(s));
        }
        srv.route(m).await;
    }
    users.len()
}

async fn invite_result(srv: &Arc<Server>, n: invites::NewInvite<'_>, note: &str) -> Result<Out, crate::db::DbError> {
    match invites::create(srv, n).await {
        Ok(inv) => {
            let expire = quark_core::time::xep82(inv.expires);
            let mut fields = vec![field("uri", "text-single", Some("Invite link"), false, &[&inv.uri])];
            if let Some(p) = &inv.page {
                fields.push(field("landing-url", "text-single", Some("Invite page"), false, &[p]));
            }
            fields.push(field("expire", "text-single", Some("Valid until"), false, &[&expire]));
            Ok(Out::Done {
                note: Some(("info", note.to_string())),
                result: Some(form("result", "Invite", None, "urn:xmpp:invite", fields)),
            })
        }
        Err(invites::InviteError::Invalid(t)) => Ok(problem(t)),
        Err(invites::InviteError::Db(e)) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_values_by_field() {
        let x = Element::parse(
            "<x xmlns='jabber:x:data' type='submit'><field var='accountjids'><value>a@b</value><value>c@b</value></field>\
             <field var='admin'><value>1</value></field></x>",
        )
        .unwrap();
        let v = values(&x);
        assert_eq!(v["accountjids"], ["a@b", "c@b"]);
        assert!(flag(&v, "admin"));
        assert!(!flag(&v, "reusable"));
    }
}
