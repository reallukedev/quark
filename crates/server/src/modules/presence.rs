//! Presence (RFC 6121 §3–4): broadcasts, probes, directed presence, and the subscription state
//! machine that keeps both rosters in step.

use std::sync::Arc;

use async_trait::async_trait;
use quark_core::{ns, Element, Jid, StanzaError};

use super::roster::{self, Item};
use super::{Event, Module};
use crate::server::{Host, Server};
use crate::sessions::SessionHandle;

pub struct Presence;

#[async_trait]
impl Module for Presence {
    fn name(&self) -> &'static str {
        "presence"
    }
    fn snapshot_names(&self, _host: &Host) -> Vec<&'static str> {
        vec!["presence"]
    }
}

fn presence(from: &Jid, to: &Jid, kind: Option<&str>) -> Element {
    Element::new("presence", ns::CLIENT).attr_set("from", from.to_string()).attr_set("to", to.to_string()).attr_opt("type", kind)
}

fn log_db(e: crate::db::DbError) {
    tracing::warn!(error = %e, "presence: roster storage");
}

/// `<presence/>` without `to` from a client: its availability, broadcast to contacts.
pub async fn from_client_broadcast(srv: &Arc<Server>, host: &Arc<Host>, session: &Arc<SessionHandle>, mut el: Element) {
    for m in &srv.modules {
        m.presence_out(srv, session, &mut el).await;
    }
    let kind = el.attr("type").map(str::to_string);
    match kind.as_deref() {
        None => {}
        Some("unavailable") => return go_unavailable(srv, host, session, el).await,
        Some("error") => return,
        Some(_) => {
            if let Some(r) =
                quark_core::stanza::error_reply(&el, &StanzaError::bad_request().with_text("Subscription requests need a 'to'."))
            {
                session.send(r);
            }
            return;
        }
    }
    let priority = el.child_text("priority", ns::CLIENT).and_then(|p| p.trim().parse::<i32>().ok()).map_or(0, |p| p.clamp(-128, 127) as i8);
    el.remove_attr("to");
    let caps = el.get_child("c", ns::CAPS).and_then(|c| Some((c.attr("node")?.to_string(), c.attr("ver")?.to_string())));
    let initial = {
        let mut p = session.presence.lock();
        let initial = !p.available;
        p.available = true;
        p.priority = priority;
        p.last = Some(el.clone());
        p.caps = caps;
        initial
    };
    let me = &session.jid;
    let bare = me.to_bare();
    let user = me.node().unwrap_or_default();
    let items = roster::presence_items(srv, &host.domain, user, initial).await.unwrap_or_else(|e| {
        log_db(e);
        Vec::new()
    });

    // To contacts who see us, and to our own other devices.
    for it in items.iter().filter(|i| i.subscription.sends_to_contact()) {
        let mut p = el.clone();
        p.set_attr("to", it.contact.to_string());
        srv.route(p).await;
    }
    // Every available resource of the account, the sender included (RFC 6121 §4.2.2).
    for o in srv.sessions.available_of(&bare) {
        let mut p = el.clone();
        p.set_attr("to", o.jid.to_string());
        o.send(p);
    }

    if initial {
        // What contacts we follow are doing now. Local ones answer straight to this device;
        // other servers get a probe (from the bare JID, RFC 6121 §4.3). Handed over without the
        // router, so the block lists it would apply are checked here: neither side's may forbid it.
        for it in items.iter().filter(|i| i.subscription.receives_from_contact()) {
            if srv.host(it.contact.domain()).is_some() {
                for s in srv.sessions.available_of(&it.contact) {
                    if let Some(mut p) = s.last_presence() {
                        p.set_attr("to", me.to_string());
                        if super::blocking::allowed_between(srv, &s.jid, me, &p).await {
                            session.send(p);
                        }
                    }
                }
            } else {
                srv.route(presence(&bare, &it.contact, Some("probe"))).await;
            }
        }
        // Our own other devices' presence.
        for o in srv.sessions.available_of(&bare) {
            if o.id != session.id {
                if let Some(mut p) = o.last_presence() {
                    p.set_attr("to", me.to_string());
                    session.send(p);
                }
            }
        }
        // Requests that came in while we were away (RFC 6121 §3.1.3), unless we've blocked
        // the sender since.
        for it in items.iter().filter(|i| i.pending_in.is_some()) {
            if super::blocking::is_blocked(srv, &bare, &it.contact).await {
                continue;
            }
            let p = it
                .pending_in
                .as_deref()
                .and_then(|x| Element::parse(x).ok())
                .unwrap_or_else(|| presence(&it.contact, &bare, Some("subscribe")));
            let mut p = p;
            p.set_attr("to", me.to_string());
            session.send(p);
        }
        if priority >= 0 {
            super::offline::flush(srv, host, session).await;
        }
    }
    srv.emit(&Event::Available { jid: me.clone(), presence: el }).await;
}

async fn go_unavailable(srv: &Arc<Server>, host: &Arc<Host>, session: &Arc<SessionHandle>, mut el: Element) {
    // Directed presence recipients are owed this even if the client never went available.
    let directed = {
        let mut p = session.presence.lock();
        p.available = false;
        p.last = None;
        std::mem::take(&mut p.directed)
    };
    el.remove_attr("to");
    broadcast_unavailable(srv, host, session, el, directed).await;
}

async fn broadcast_unavailable(
    srv: &Arc<Server>,
    host: &Arc<Host>,
    session: &Arc<SessionHandle>,
    el: Element,
    directed: std::collections::HashSet<Jid>,
) {
    let me = &session.jid;
    let bare = me.to_bare();
    let items = roster::presence_items(srv, &host.domain, me.node().unwrap_or_default(), false).await.unwrap_or_default();
    let mut sent = std::collections::HashSet::new();
    for it in items.iter().filter(|i| i.subscription.sends_to_contact()) {
        let mut p = el.clone();
        p.set_attr("to", it.contact.to_string());
        sent.insert(it.contact.clone());
        srv.route(p).await;
    }
    for j in directed {
        if !sent.contains(&j) {
            let mut p = el.clone();
            p.set_attr("to", j.to_string());
            srv.route(p).await;
        }
    }
    for o in srv.sessions.available_of(&bare) {
        if o.id != session.id {
            let mut p = el.clone();
            p.set_attr("to", o.jid.to_string());
            o.send(p);
        }
    }
}

/// A session ended for good: if it was online, everyone who saw it learns it's gone.
pub async fn session_ended(srv: &Arc<Server>, host: &Arc<Host>, session: &Arc<SessionHandle>) {
    let (was, directed) = {
        let mut p = session.presence.lock();
        let was = p.available;
        p.available = false;
        (was, std::mem::take(&mut p.directed))
    };
    if was || !directed.is_empty() {
        let el = Element::new("presence", ns::CLIENT).attr_set("from", session.jid.to_string()).attr_set("type", "unavailable");
        broadcast_unavailable(srv, host, session, el, directed).await;
    }
}

/// Unavailable from each of our online devices to `contact` (after they lose the subscription).
pub async fn send_unavailable_to(srv: &Arc<Server>, me: &Jid, contact: &Jid) {
    for s in srv.sessions.available_of(&me.to_bare()) {
        srv.route(presence(&s.jid, contact, Some("unavailable"))).await;
    }
}

/// Presence with a `to` from a client: subscription management or directed presence.
pub async fn from_client_directed(srv: &Arc<Server>, host: &Arc<Host>, session: &Arc<SessionHandle>, to: &Jid, mut el: Element) {
    let me = session.jid.to_bare();
    let user = me.node().unwrap_or_default().to_string();
    let kind = el.attr("type").map(str::to_string);
    match kind.as_deref() {
        Some(k @ ("subscribe" | "subscribed" | "unsubscribe" | "unsubscribed")) => {
            let contact = to.to_bare();
            if contact == me {
                return;
            }
            // Subscription stanzas go out from the bare JID (RFC 6121 §3.1.2).
            el.set_attr("from", me.to_string());
            el.set_attr("to", contact.to_string());
            if let Err(e) = outbound_subscription(srv, host, &user, &contact, k, &el).await {
                log_db(e);
            }
        }
        Some("probe") => {}
        Some("error") => srv.route(el).await,
        None | Some("unavailable") => {
            {
                let mut p = session.presence.lock();
                if kind.is_none() {
                    p.directed.insert(to.clone());
                } else {
                    p.directed.remove(to);
                }
            }
            srv.route(el).await;
        }
        Some(_) => {
            if let Some(r) = quark_core::stanza::error_reply(&el, &StanzaError::bad_request()) {
                session.send(r);
            }
        }
    }
}

async fn outbound_subscription(
    srv: &Arc<Server>,
    host: &Arc<Host>,
    user: &str,
    contact: &Jid,
    kind: &str,
    el: &Element,
) -> Result<(), crate::db::DbError> {
    let me = Jid::bare_unchecked(user, &host.domain);
    let existing = roster::item(srv, &host.domain, user, contact).await?;
    let mut it = existing.clone().unwrap_or_else(|| Item::new(contact.clone()));
    match kind {
        "subscribe" => {
            if it.subscription.receives_from_contact() {
                // Already subscribed: confirm on the contact's behalf instead of asking again.
                let ok = Element::new("presence", ns::CLIENT).attr_set("from", contact.to_string()).attr_set("type", "subscribed");
                for s in srv.sessions.available_of(&me) {
                    s.send(ok.clone().attr_set("to", s.jid.to_string()));
                }
                return Ok(());
            }
            if !it.ask {
                it.ask = true;
                it.visible = true;
                roster::save_and_push(srv, host, user, &it).await?;
            }
            srv.route(el.clone()).await;
        }
        "subscribed" => {
            if it.pending_in.is_some() {
                it.pending_in = None;
                it.subscription = it.subscription.with_from(true);
                it.visible = true;
                roster::save_and_push(srv, host, user, &it).await?;
                srv.route(el.clone()).await;
                // They see us now: send our current presence.
                for s in srv.sessions.available_of(&me) {
                    if let Some(mut p) = s.last_presence() {
                        p.set_attr("to", contact.to_string());
                        srv.route(p).await;
                    }
                }
                srv.emit(&Event::SubscriptionApproved { user: me.clone(), contact: contact.clone() }).await;
            } else if !it.subscription.sends_to_contact() && !it.approved {
                // Pre-approval (RFC 6121 §3.4): accept their request when it comes.
                it.approved = true;
                it.visible = true;
                roster::save_and_push(srv, host, user, &it).await?;
            }
        }
        "unsubscribe" => {
            if it.subscription.receives_from_contact() || it.ask {
                it.subscription = it.subscription.with_to(false);
                it.ask = false;
                if existing.is_some() {
                    roster::save_and_push(srv, host, user, &it).await?;
                }
            }
            srv.route(el.clone()).await;
        }
        "unsubscribed" => {
            let had = it.subscription.sends_to_contact() || it.pending_in.is_some() || it.approved;
            if had {
                it.subscription = it.subscription.with_from(false);
                it.pending_in = None;
                it.approved = false;
                if existing.is_some() {
                    if it.visible {
                        roster::save_and_push(srv, host, user, &it).await?;
                    } else {
                        roster::delete(srv, &host.domain, user, contact).await?;
                    }
                }
                send_unavailable_to(srv, &me, contact).await;
                srv.emit(&Event::SubscriptionRevoked { user: me.clone(), contact: contact.clone() }).await;
            }
            srv.route(el.clone()).await;
        }
        _ => {}
    }
    Ok(())
}

/// Subscription requests kept per account until answered. Beyond this new ones are dropped
/// (people answer or ignore requests long before; a flood from one server stops here).
pub const MAX_PENDING: usize = 500;
/// Longest status text and nickname kept with a stored request, in bytes.
const MAX_STORED_TEXT: usize = 1024;

/// What's stored of a subscription request: who, and the status text and nickname (XEP-0172)
/// a person reads, cut to size. The rest of the stanza (anything a sender wants to park on our
/// disk) is dropped.
fn stored_request(el: &Element) -> Element {
    let mut p = Element::new("presence", ns::CLIENT).attr_opt("from", el.attr("from")).attr_set("type", "subscribe");
    for (name, child_ns) in [("status", ns::CLIENT), ("nick", ns::NICK)] {
        if let Some(t) = el.child_text(name, child_ns) {
            let mut end = t.len().min(MAX_STORED_TEXT);
            while !t.is_char_boundary(end) {
                end -= 1;
            }
            if end > 0 {
                p.append(Element::new(name, child_ns).text(&t[..end]));
            }
        }
    }
    p
}

/// Presence for a local account, from anyone.
pub async fn inbound(srv: &Arc<Server>, host: &Arc<Host>, from: &Jid, to: &Jid, el: Element) {
    let Some(user) = to.node() else { return };
    let kind = el.attr("type").map(str::to_string);
    match kind.as_deref() {
        Some(k @ ("subscribe" | "subscribed" | "unsubscribe" | "unsubscribed")) => {
            if let Err(e) = inbound_subscription(srv, host, user, &from.to_bare(), k, el).await {
                log_db(e);
            }
        }
        Some("probe") => answer_probe(srv, host, user, from).await,
        _ => {
            // Availability from a contact (or a room): to the device it names, or all devices.
            if to.resource().is_some() {
                if let Some(s) = srv.sessions.get(to) {
                    s.send(el);
                }
            } else {
                for s in srv.sessions.available_of(to) {
                    let mut p = el.clone();
                    p.set_attr("to", s.jid.to_string());
                    s.send(p);
                }
            }
        }
    }
}

async fn answer_probe(srv: &Arc<Server>, host: &Arc<Host>, user: &str, from: &Jid) {
    let Ok(Some(it)) = roster::item(srv, &host.domain, user, &from.to_bare()).await else {
        return;
    };
    if !it.subscription.sends_to_contact() {
        return;
    }
    let me = Jid::bare_unchecked(user, &host.domain);
    let online = srv.sessions.available_of(&me);
    if online.is_empty() {
        let mut p = presence(&me, from, Some("unavailable"));
        if let Ok(Some(last)) = super::last::last_seen(srv, &host.domain, user).await {
            p.append(quark_core::stanza::delay(&me.to_string(), last));
        }
        srv.route(p).await;
        return;
    }
    for s in online {
        if let Some(mut p) = s.last_presence() {
            p.set_attr("to", from.to_string());
            srv.route(p).await;
        }
    }
}

async fn inbound_subscription(
    srv: &Arc<Server>,
    host: &Arc<Host>,
    user: &str,
    contact: &Jid,
    kind: &str,
    mut el: Element,
) -> Result<(), crate::db::DbError> {
    let me = Jid::bare_unchecked(user, &host.domain);
    el.set_attr("from", contact.to_string());
    let existing = roster::item(srv, &host.domain, user, contact).await?;
    let deliver = |el: Element| {
        for s in srv.sessions.available_of(&me) {
            let mut p = el.clone();
            p.set_attr("to", s.jid.to_string());
            s.send(p);
        }
    };
    match kind {
        "subscribe" => {
            let mut it = existing.unwrap_or_else(|| {
                let mut i = Item::new(contact.clone());
                i.visible = false;
                i
            });
            if it.subscription.sends_to_contact() {
                // Already approved: answer for the account (RFC 6121 §3.1.3 step 2).
                srv.route(presence(&me, contact, Some("subscribed"))).await;
                return Ok(());
            }
            if it.approved {
                it.approved = false;
                it.subscription = it.subscription.with_from(true);
                it.visible = true;
                roster::save_and_push(srv, host, user, &it).await?;
                srv.route(presence(&me, contact, Some("subscribed"))).await;
                for s in srv.sessions.available_of(&me) {
                    if let Some(mut p) = s.last_presence() {
                        p.set_attr("to", contact.to_string());
                        srv.route(p).await;
                    }
                }
                srv.emit(&Event::SubscriptionApproved { user: me.clone(), contact: contact.clone() }).await;
                return Ok(());
            }
            // Anyone can ask, so what's kept for later is bounded: a few hundred requests per
            // account, each only the parts a person reads.
            if it.pending_in.is_none() && roster::count_pending(srv, &host.domain, user).await? >= MAX_PENDING {
                tracing::debug!(%me, %contact, "dropping a subscription request: too many waiting");
                return Ok(());
            }
            // Keep it for when they sign in, and show it now if they're online.
            it.pending_in = Some(stored_request(&el).to_xml());
            roster::save(srv, &host.domain, user, &it).await?;
            deliver(el);
        }
        "subscribed" => {
            let Some(mut it) = existing else { return Ok(()) };
            if !it.ask {
                return Ok(());
            }
            it.ask = false;
            it.subscription = it.subscription.with_to(true);
            roster::save_and_push(srv, host, user, &it).await?;
            deliver(el);
        }
        "unsubscribe" => {
            let Some(mut it) = existing else { return Ok(()) };
            if !it.subscription.sends_to_contact() && it.pending_in.is_none() {
                return Ok(());
            }
            it.subscription = it.subscription.with_from(false);
            it.pending_in = None;
            if it.visible {
                roster::save_and_push(srv, host, user, &it).await?;
            } else {
                roster::delete(srv, &host.domain, user, contact).await?;
            }
            deliver(el);
            send_unavailable_to(srv, &me, contact).await;
            srv.emit(&Event::SubscriptionRevoked { user: me.clone(), contact: contact.clone() }).await;
        }
        "unsubscribed" => {
            let Some(mut it) = existing else { return Ok(()) };
            if !it.subscription.receives_from_contact() && !it.ask {
                return Ok(());
            }
            it.subscription = it.subscription.with_to(false);
            it.ask = false;
            roster::save_and_push(srv, host, user, &it).await?;
            deliver(el);
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_requests_keep_only_what_people_read() {
        let long = "\u{e9}".repeat(MAX_STORED_TEXT);
        let el = Element::new("presence", ns::CLIENT)
            .attr_set("from", "a@b")
            .attr_set("to", "c@d")
            .attr_set("type", "subscribe")
            .text_child("status", ns::CLIENT, long.as_str())
            .text_child("nick", ns::NICK, "Al")
            .child(Element::new("junk", "urn:x").text("x".repeat(100_000)));
        let p = stored_request(&el);
        assert_eq!(p.attr("from"), Some("a@b"));
        assert_eq!(p.attr("to"), None);
        assert_eq!(p.child_text("nick", ns::NICK).as_deref(), Some("Al"));
        let status = p.child_text("status", ns::CLIENT).unwrap_or_default();
        assert_eq!(status.len(), MAX_STORED_TEXT);
        assert!(p.get_child("junk", "urn:x").is_none());
    }
}
