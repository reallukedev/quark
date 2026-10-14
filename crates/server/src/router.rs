//! Where stanzas go (RFC 6120 §10, RFC 6121 §8): from clients, from other servers and
//! components, and from the server itself, to sessions, modules, components or other servers.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use quark_core::stanza::{error_reply, iq_result, iq_type, IqType};
use quark_core::{ns, Condition, Element, Jid, StanzaError};

use crate::modules::{Flow, IqCtx, IqReply, IqTarget, StanzaCtx};
use crate::server::{Dest, Host, Server};
use crate::sessions::SessionHandle;

/// A stanza a signed-in client sent. `from` is set from the session, whatever the client wrote.
pub async fn from_client(srv: &Arc<Server>, host: &Arc<Host>, session: &Arc<SessionHandle>, mut el: Element) {
    el.set_attr("from", session.jid.to_string());
    let to = match quark_core::stanza::jid_attr(&el, "to") {
        Ok(t) => t,
        Err(e) => return bounce(srv, &el, e).await,
    };
    let me = &session.jid;
    let to = match to {
        Some(t) => t,
        None if el.name() == "presence" => return crate::modules::presence::from_client_broadcast(srv, host, session, el).await,
        // No `to`: the account itself (RFC 6120 §10.3.3). IQs stay without one, so the reply
        // comes back without a `from`, as clients expect for roster and the like.
        None if el.name() == "iq" => me.to_bare(),
        None => {
            el.set_attr("to", me.to_bare().to_string());
            me.to_bare()
        }
    };
    // Stanzas to the server itself or the account's own bare JID aren't "to someone else".
    let to_other = to.domain() != host.domain || to.node().is_some() && to.to_bare() != me.to_bare();
    if to_other {
        let cx = StanzaCtx { srv, host, from: me, to: &to, session: Some(session) };
        for m in &srv.modules {
            match m.stanza_out(&cx, &mut el).await {
                Flow::Continue => {}
                Flow::Stop => return,
                Flow::Reject(e) => return reply_error(session, &el, e),
            }
        }
    }
    match el.name() {
        "presence" => return crate::modules::presence::from_client_directed(srv, host, session, &to, el).await,
        "message" if to_other || to.resource().is_some() => {
            let cx = StanzaCtx { srv, host, from: me, to: &to, session: Some(session) };
            for m in &srv.modules {
                match m.message_out(&cx, &mut el).await {
                    Flow::Continue => {}
                    Flow::Stop => return,
                    Flow::Reject(e) => return reply_error(session, &el, e),
                }
            }
            carbon_sent(srv, session, &to, &el);
            // The sender's archive id was for its own devices (the sent carbons), not the recipient.
            let mine = me.to_bare().to_string();
            crate::modules::mam::strip_stanza_ids(&mut el, &mine);
        }
        _ => {}
    }
    dispatch(srv, me.clone(), to, el, Some(session)).await;
}

/// Routes a stanza with `from` and `to` already set and trusted (from another server after its
/// checks, a component, or the server itself).
pub fn route(srv: &Arc<Server>, el: Element) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
    Box::pin(async move {
        let (from, to) = match (quark_core::stanza::jid_attr(&el, "from"), quark_core::stanza::jid_attr(&el, "to")) {
            (Ok(Some(f)), Ok(Some(t))) => (f, t),
            (Ok(Some(f)), Ok(None)) => {
                let to = if el.name() == "iq" { Jid::domain_jid(f.domain()).ok() } else { Some(f.to_bare()) };
                match to {
                    Some(t) => (f, t),
                    None => return,
                }
            }
            _ => {
                tracing::debug!(stanza = %el, "dropping stanza without valid addresses");
                return;
            }
        };
        dispatch(srv, from, to, el, None).await;
    })
}

impl Server {
    /// Routes a stanza from the server or a module (see [`route`]).
    pub async fn route(self: &Arc<Self>, el: Element) {
        route(self, el).await;
    }
}

async fn dispatch(srv: &Arc<Server>, from: Jid, to: Jid, el: Element, session: Option<&Arc<SessionHandle>>) {
    // Nothing an account sends, or the server sends for it (presence, PEP), reaches someone it blocked.
    if !crate::modules::blocking::outbound_allowed(srv, &from, &to, &el).await {
        return;
    }
    match srv.resolve(to.domain()) {
        Dest::Local(host) => local(srv, &host, from, to, el, session).await,
        Dest::Component(c) => c.handle(srv, from, to, el).await,
        Dest::Remote => {
            let from_host = srv.host(from.domain()).or_else(|| srv.component_host(from.domain()));
            // Push notifications to phone app servers (XEP-0357) go out even when chatting with
            // other servers is off: they're the server's own traffic, not people's.
            let allowed = from_host.as_ref().is_some_and(|h| {
                let s = h.settings();
                s.federation || (s.push && crate::modules::push::is_notification(&el))
            });
            match srv.remote() {
                Some(r) if allowed && !srv.config().s2s.blocked.iter().any(|b| b == to.domain()) => r.send(from.domain(), to.domain(), el),
                _ => {
                    let e = StanzaError::new(Condition::RemoteServerNotFound).with_text(if allowed {
                        "That server can't be reached from here."
                    } else {
                        "Chatting with other servers is turned off."
                    });
                    bounce(srv, &el, e).await;
                }
            }
        }
    }
}

/// Sends an error reply for `el` back to its sender (when one is allowed).
pub async fn bounce(srv: &Arc<Server>, el: &Element, err: StanzaError) {
    if let Some(r) = error_reply(el, &err) {
        if r.attr("to").is_some() {
            srv.route(r).await;
        }
    }
}

/// Refuses something the client sent, straight back to that client.
fn reply_error(session: &Arc<SessionHandle>, el: &Element, err: StanzaError) {
    if let Some(r) = error_reply(el, &err) {
        session.send(r);
    }
}

async fn local(srv: &Arc<Server>, host: &Arc<Host>, from: Jid, to: Jid, mut el: Element, session: Option<&Arc<SessionHandle>>) {
    // Inbound filters (blocking, privacy) apply to stanzas for accounts, not to the server.
    if to.node().is_some() && from.to_bare() != to.to_bare() {
        let cx = StanzaCtx { srv, host, from: &from, to: &to, session };
        for m in &srv.modules {
            match m.stanza_in(&cx, &mut el).await {
                Flow::Continue => {}
                Flow::Stop => return,
                Flow::Reject(e) => return bounce(srv, &el, e).await,
            }
        }
    }
    match el.name() {
        "iq" => local_iq(srv, host, from, to, el, session).await,
        "message" => {
            if to.node().is_none() {
                // Messages to the domain itself: nothing reads them.
                return;
            }
            deliver_message(srv, host, &from, &to, el, true).await;
        }
        "presence" => {
            if to.node().is_none() {
                return;
            }
            crate::modules::presence::inbound(srv, host, &from, &to, el).await;
        }
        _ => {}
    }
}

async fn local_iq(srv: &Arc<Server>, host: &Arc<Host>, from: Jid, to: Jid, el: Element, session: Option<&Arc<SessionHandle>>) {
    let Some(kind) = iq_type(&el) else {
        return bounce_iq(srv, session, &el, StanzaError::bad_request()).await;
    };
    let target = if to.node().is_none() {
        Some(IqTarget::Server)
    } else if to.resource().is_none() {
        Some(IqTarget::Account)
    } else {
        None
    };
    let Some(target) = target else {
        // To a full JID: pass it to that session.
        match srv.sessions.get(&to) {
            Some(s) => {
                s.send(el);
            }
            None if matches!(kind, IqType::Get | IqType::Set) => bounce_iq(srv, session, &el, StanzaError::service_unavailable()).await,
            None => {}
        }
        return;
    };
    if matches!(kind, IqType::Result | IqType::Error) {
        // An answer to something the server asked.
        srv.answer_pending(&el);
        return;
    }
    // A get or set carries exactly one payload (RFC 6120 §8.2.3).
    let mut children = el.children();
    let (Some(payload), None) = (children.next(), children.next()) else {
        return bounce_iq(srv, session, &el, StanzaError::bad_request()).await;
    };
    if target == IqTarget::Account && !srv.accounts.exists(&host.domain, to.node().unwrap_or_default()).await.unwrap_or(false) {
        return bounce_iq(srv, session, &el, StanzaError::service_unavailable()).await;
    }
    if payload.is("session", ns::SESSION) && kind == IqType::Set && (target == IqTarget::Server || from.to_bare() == to) {
        return reply(srv, session, iq_result(&el)).await;
    }
    // An account asking its own bare JID about something only the server answers (a ping
    // without `to`, say) gets the server's answer.
    let module = srv
        .iq_module(payload.ns(), target)
        .or_else(|| (target == IqTarget::Account && from.to_bare() == to).then(|| srv.iq_module(payload.ns(), IqTarget::Server)).flatten());
    let Some(m) = module.cloned() else {
        return bounce_iq(srv, session, &el, StanzaError::service_unavailable()).await;
    };
    let cx = IqCtx { srv, host, from: &from, to: &to, iq: &el, payload, kind, session };
    let result = m.handle_iq(&cx).await;
    match result {
        Ok(IqReply::Handled) => {}
        Ok(IqReply::Result(p)) => {
            let mut r = iq_result(&el);
            if let Some(p) = p {
                r.append(p);
            }
            reply(srv, session, r).await;
        }
        Err(e) => {
            if let Some(r) = error_reply(&el, &e) {
                reply(srv, session, r).await;
            }
        }
    }
}

/// Sends a reply: straight to the asking session when there is one (keeps order with anything
/// the module already sent it), else through the router.
pub async fn reply(srv: &Arc<Server>, session: Option<&Arc<SessionHandle>>, el: Element) {
    match session {
        Some(s) if el.attr("to") == Some(&s.jid.to_string()) => {
            s.send(el);
        }
        _ => srv.route(el).await,
    }
}

/// An error reply to an IQ, sent the same way as a result would be.
async fn bounce_iq(srv: &Arc<Server>, session: Option<&Arc<SessionHandle>>, el: &Element, err: StanzaError) {
    if let Some(r) = error_reply(el, &err) {
        reply(srv, session, r).await;
    }
}

/// Carbons (XEP-0280) apply to one-to-one messages people read; not to group chats, errors,
/// or messages marked private.
pub fn carbon_eligible(msg: &Element) -> bool {
    let kind = msg.attr("type").unwrap_or("normal");
    if kind == "groupchat" || kind == "error" || kind == "headline" {
        return false;
    }
    if msg.has_child("private", ns::CARBONS)
        || msg.has_child("no-copy", ns::HINTS)
        || msg.has_child("received", ns::CARBONS)
        || msg.has_child("sent", ns::CARBONS)
    {
        return false;
    }
    // XEP-0280 §6: chat messages, and normal ones with a body or the payloads of an IM
    // conversation (receipts, markers, calls, reactions, retractions).
    kind == "chat"
        || msg.has_child("body", ns::CLIENT)
        || msg.has_child("encrypted", ns::OMEMO)
        || msg.has_child("encrypted", "urn:xmpp:omemo:2")
        || msg.child_ns(ns::RECEIPTS).is_some()
        || msg.child_ns(ns::CHAT_MARKERS).is_some()
        || msg.child_ns("urn:xmpp:jingle-message:0").is_some()
        || msg.has_child("reactions", "urn:xmpp:reactions:0")
        || msg.has_child("retract", ns::RETRACT)
}

/// Whether a message delivered to one of the account's devices is copied to the others.
fn carbon_received_eligible(from: &Jid, to: &Jid, msg: &Element) -> bool {
    // A group chat's private message goes to the one device that joined (XEP-0280 §6.1).
    if to.is_full() && msg.has_child("x", ns::MUC_USER) {
        return false;
    }
    // Bounces of messages sent to a bare JID, so every device learns it didn't arrive.
    if msg.attr("type") == Some("error") {
        return from.is_bare() && !msg.has_child("private", ns::CARBONS) && !msg.has_child("no-copy", ns::HINTS);
    }
    carbon_eligible(msg)
}

fn carbon(direction: &str, account: &Jid, to: &Jid, msg: &Element) -> Element {
    Element::new("message", ns::CLIENT)
        .attr_set("from", account.to_bare().to_string())
        .attr_set("to", to.to_string())
        .attr_set("type", msg.attr("type").unwrap_or("normal"))
        .child(Element::new(direction, ns::CARBONS).child(Element::new("forwarded", ns::FORWARD).child(msg.clone())))
}

/// Copies a message a client sent to its other devices that asked for carbons.
fn carbon_sent(srv: &Arc<Server>, session: &Arc<SessionHandle>, to: &Jid, msg: &Element) {
    if !carbon_eligible(msg) {
        return;
    }
    for s in srv.sessions.of(&session.jid.to_bare()) {
        // The device it was sent to (one's own other resource) gets the message itself.
        if s.id != session.id && s.carbons() && s.jid != *to {
            s.send(carbon("sent", &session.jid, &s.jid, msg));
        }
    }
}

/// Delivers a message to a local account (RFC 6121 §8.5). `hooks`: run the message pipeline
/// (false when re-delivering something that already went through it).
pub async fn deliver_message(srv: &Arc<Server>, host: &Arc<Host>, from: &Jid, to: &Jid, mut msg: Element, hooks: bool) {
    let Some(user) = to.node() else { return };
    let bare = to.to_bare();
    let kind = msg.attr("type").unwrap_or("normal").to_string();
    if !srv.accounts.exists(&host.domain, user).await.unwrap_or(false) {
        if kind != "error" && kind != "groupchat" && kind != "headline" {
            bounce(srv, &msg, StanzaError::service_unavailable()).await;
        }
        return;
    }
    if hooks {
        let cx = StanzaCtx { srv, host, from, to, session: None };
        for m in &srv.modules {
            match m.message_in(&cx, &mut msg).await {
                Flow::Continue => {}
                Flow::Stop => return,
                Flow::Reject(e) => return bounce(srv, &msg, e).await,
            }
        }
    }

    // To a resource that's online: that session, plus carbons to the others.
    if to.resource().is_some() {
        if let Some(s) = srv.sessions.get(to) {
            if carbon_received_eligible(from, to, &msg) {
                for o in srv.sessions.of(&bare) {
                    if o.id != s.id && o.carbons() {
                        o.send(carbon("received", to, &o.jid, &msg));
                    }
                }
            }
            s.send(msg);
            return;
        }
        // RFC 6121 §8.5.3.2.1: chat goes to the account; groupchat and headline are dropped;
        // normal (and anything else) is refused.
        match kind.as_str() {
            "chat" => {}
            "groupchat" | "headline" | "error" => return,
            _ => return bounce(srv, &msg, StanzaError::service_unavailable()).await,
        }
    }

    let available = srv.sessions.available_of(&bare);
    if kind == "groupchat" {
        return bounce(srv, &msg, StanzaError::service_unavailable()).await;
    }
    // Every device that's online and not hiding (priority ≥ 0) gets one-to-one messages: people
    // use several devices at once and expect the message on each.
    let targets: Vec<_> = available.into_iter().filter(|s| s.priority() >= 0).collect();
    if targets.is_empty() {
        if kind == "headline" || kind == "error" {
            return;
        }
        let cx = StanzaCtx { srv, host, from, to: &bare, session: None };
        for m in &srv.modules {
            match m.message_undelivered(&cx, &msg).await {
                Flow::Continue => {}
                Flow::Stop => return,
                Flow::Reject(e) => return bounce(srv, &msg, e).await,
            }
        }
        return;
    }
    // Devices with carbons on that don't take messages to the bare JID (negative priority, no
    // presence yet) still follow the conversation (XEP-0280 §5.2).
    if carbon_received_eligible(from, &bare, &msg) {
        for o in srv.sessions.of(&bare) {
            if o.carbons() && !targets.iter().any(|t| t.id == o.id) {
                o.send(carbon("received", &bare, &o.jid, &msg));
            }
        }
    }
    let last = targets.len() - 1;
    for (i, s) in targets.into_iter().enumerate() {
        let mut m = if i == last { std::mem::replace(&mut msg, Element::new("message", ns::CLIENT)) } else { msg.clone() };
        m.set_attr("to", s.jid.to_string());
        s.send(m);
    }
}

/// A message a session took but never confirmed, given back to the account after the session
/// ended (to other devices, or offline storage).
pub async fn redeliver(srv: &Arc<Server>, host: &Arc<Host>, owner: &Jid, mut msg: Element) {
    let Some(from) = msg.attr("from").and_then(|f| Jid::parse(f).ok()) else { return };
    let bare = owner.to_bare();
    msg.set_attr("to", bare.to_string());
    if !msg.has_child("delay", ns::DELAY) {
        msg.append(quark_core::stanza::delay(&host.domain, quark_core::time::now_ms()));
    }
    deliver_message(srv, host, &from, &bare, msg, false).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(xml: &str) -> Element {
        Element::parse(xml).unwrap()
    }

    #[test]
    fn carbons_skip_group_chats_and_private_messages() {
        assert!(carbon_eligible(&msg("<message xmlns='jabber:client' type='chat'><body>x</body></message>")));
        assert!(!carbon_eligible(&msg("<message xmlns='jabber:client' type='groupchat'><body>x</body></message>")));
        assert!(!carbon_eligible(&msg(
            "<message xmlns='jabber:client' type='chat'><body>x</body><private xmlns='urn:xmpp:carbons:2'/></message>"
        )));
        assert!(!carbon_eligible(&msg(
            "<message xmlns='jabber:client' type='chat'><body>x</body><no-copy xmlns='urn:xmpp:hints'/></message>"
        )));
        assert!(!carbon_eligible(&msg("<message xmlns='jabber:client' type='normal'/>")));
        assert!(carbon_eligible(&msg(
            "<message xmlns='jabber:client' type='chat'><composing xmlns='http://jabber.org/protocol/chatstates'/></message>"
        )));
    }
}
