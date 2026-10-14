//! Bookmarks kept in step across their three homes (XEP-0402 §5.3 compat, XEP-0411): PEP
//! bookmarks 2 (one item per room), the legacy `storage:bookmarks` PEP node and legacy private
//! XML storage (XEP-0048, one document). Whichever a client writes, the others follow, so an
//! old and a new client on the same account see the same rooms.

use std::collections::HashMap;
use std::sync::Arc;

use quark_core::{Element, Jid};

use super::config::{defaults_for, MAX_ITEMS};
use super::iq::Opts;
use super::store::{self, Owner};
use super::{Origin, State};
use crate::modules::private;
use crate::server::Server;

pub const NODE: &str = "urn:xmpp:bookmarks:1";
pub const LEGACY_NODE: &str = "storage:bookmarks";
const LEGACY_NS: &str = "storage:bookmarks";
pub const COMPAT: &str = "urn:xmpp:bookmarks:1#compat";
pub const COMPAT_PEP: &str = "urn:xmpp:bookmarks:1#compat-pep";
/// The legacy node's single item (XEP-0048 §3.3).
const LEGACY_ITEM: &str = "current";

/// One room bookmark, the fields both formats share.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Bookmark {
    name: Option<String>,
    autojoin: bool,
    nick: Option<String>,
    password: Option<String>,
}

fn truthy(v: Option<&str>) -> bool {
    matches!(v, Some("true" | "1"))
}

fn nonempty(s: Option<String>) -> Option<String> {
    s.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

impl Bookmark {
    /// From a bookmarks 2 `<conference/>` (the room JID is the item id).
    fn from_v2(c: &Element) -> Bookmark {
        Bookmark {
            name: nonempty(c.attr("name").map(String::from)),
            autojoin: truthy(c.attr("autojoin")),
            nick: nonempty(c.child_text("nick", NODE)),
            password: nonempty(c.child_text("password", NODE)),
        }
    }

    /// From a legacy `<conference jid=…/>`.
    fn from_legacy(c: &Element) -> Bookmark {
        Bookmark {
            name: nonempty(c.attr("name").map(String::from)),
            autojoin: truthy(c.attr("autojoin")),
            nick: nonempty(c.child_text("nick", LEGACY_NS)),
            password: nonempty(c.child_text("password", LEGACY_NS)),
        }
    }

    /// As bookmarks 2, keeping the `<extensions/>` of the item it replaces.
    fn to_v2(&self, extensions: Option<&Element>) -> Element {
        let mut c = Element::new("conference", NODE).attr_opt("name", self.name.clone()).attr_set("autojoin", self.autojoin.to_string());
        if let Some(n) = &self.nick {
            c.append(Element::new("nick", NODE).text(n.clone()));
        }
        if let Some(p) = &self.password {
            c.append(Element::new("password", NODE).text(p.clone()));
        }
        if let Some(x) = extensions {
            c.append(x.clone());
        }
        c
    }

    fn to_legacy(&self, jid: &str) -> Element {
        let mut c = Element::new("conference", LEGACY_NS)
            .attr_set("jid", jid)
            .attr_opt("name", self.name.clone())
            .attr_set("autojoin", self.autojoin.to_string());
        if let Some(n) = &self.nick {
            c.append(Element::new("nick", LEGACY_NS).text(n.clone()));
        }
        if let Some(p) = &self.password {
            c.append(Element::new("password", LEGACY_NS).text(p.clone()));
        }
        c
    }
}

/// The legacy document for `rooms`, keeping what else `previous` held (`<url/>` bookmarks).
fn legacy_doc(rooms: &[(String, Bookmark)], previous: Option<&Element>) -> Element {
    let mut s = Element::new("storage", LEGACY_NS);
    if let Some(p) = previous {
        for c in p.children().filter(|c| !c.is("conference", LEGACY_NS)) {
            s.append(c.clone());
        }
    }
    for (jid, b) in rooms {
        s.append(b.to_legacy(jid));
    }
    s
}

/// The rooms in a legacy document, by bare room JID.
fn legacy_rooms(storage: &Element) -> Vec<(String, Bookmark)> {
    let mut out: Vec<(String, Bookmark)> = Vec::new();
    for c in storage.children().filter(|c| c.is("conference", LEGACY_NS)).take(MAX_ITEMS as usize) {
        let Some(jid) = c.attr("jid").and_then(|j| Jid::parse(j).ok()).filter(|j| j.node().is_some()) else { continue };
        let jid = jid.to_bare().to_string();
        if !out.iter().any(|(j, _)| *j == jid) {
            out.push((jid, Bookmark::from_legacy(c)));
        }
    }
    out
}

/// Everything stored about bookmarks, read in one go.
struct Stored {
    /// Bookmarks 2 items: room JID → (bookmark, extensions).
    v2: Vec<(String, Bookmark, Option<Element>)>,
    legacy_pep: Option<Element>,
    private: Option<Element>,
}

fn load(c: &rusqlite::Connection, o: &Owner) -> rusqlite::Result<Stored> {
    let v2 = store::items(c, o, NODE, None)?
        .into_iter()
        .filter_map(|i| {
            let p = i.payload()?;
            p.is("conference", NODE).then(|| (i.id, Bookmark::from_v2(&p), p.get_child("extensions", NODE).cloned()))
        })
        .collect();
    let legacy_pep = store::last_item(c, o, LEGACY_NODE)?.and_then(|i| i.payload()).filter(|p| p.is("storage", LEGACY_NS));
    let private = private::load(c, &o.host, &o.user, LEGACY_NS, "storage")?;
    Ok(Stored { v2, legacy_pep, private })
}

/// A bookmarks 2 item id as the room JID legacy documents would name it, when it is one.
fn room_jid(id: &str) -> Option<String> {
    Jid::parse(id).ok().filter(|j| j.node().is_some()).map(|j| j.to_bare().to_string())
}

impl State {
    async fn load_bookmarks(&self, srv: &Arc<Server>, o: &Owner) -> Option<Stored> {
        let oo = o.clone();
        match srv.db.read(move |c| load(c, &oo)).await {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::warn!(error = %e, "pep: reading bookmarks");
                None
            }
        }
    }

    /// A client changed bookmarks 2: rewrite both legacy copies.
    pub(super) async fn bookmarks2_changed(self: &Arc<Self>, srv: &Arc<Server>, o: &Owner) {
        let Some(st) = self.load_bookmarks(srv, o).await else { return };
        let rooms: Vec<(String, Bookmark)> = st.v2.into_iter().map(|(j, b, _)| (j, b)).collect();
        let previous = st.legacy_pep.as_ref().or(st.private.as_ref());
        let doc = legacy_doc(&rooms, previous);
        self.write_legacy(srv, o, &doc, st.legacy_pep.as_ref(), st.private.as_ref(), true, true).await;
    }

    /// A client published the legacy PEP document: bring bookmarks 2 and private storage along.
    pub(super) async fn legacy_pep_bookmarks_changed(self: &Arc<Self>, srv: &Arc<Server>, o: &Owner) {
        let Some(st) = self.load_bookmarks(srv, o).await else { return };
        // Retracting the document isn't a request to forget every room.
        let Some(doc) = st.legacy_pep.clone() else { return };
        self.sync_v2(srv, o, &doc, &st.v2).await;
        self.write_legacy(srv, o, &doc, st.legacy_pep.as_ref(), st.private.as_ref(), false, true).await;
    }

    /// A client stored legacy bookmarks in private XML storage.
    pub(super) async fn private_changed(self: &Arc<Self>, srv: &Arc<Server>, jid: &Jid, data: &Element) {
        if !data.is("storage", LEGACY_NS) {
            return;
        }
        let Some(o) = Owner::of(jid) else { return };
        let Some(st) = self.load_bookmarks(srv, &o).await else { return };
        self.sync_v2(srv, &o, data, &st.v2).await;
        self.write_legacy(srv, &o, data, st.legacy_pep.as_ref(), st.private.as_ref(), true, false).await;
    }

    /// Makes bookmarks 2 hold exactly the rooms in a legacy document. Rooms are matched by
    /// their normalized JID (legacy documents are read that way), and an existing item is
    /// updated under its own id, keeping its extensions. Items whose id isn't a room JID can't
    /// be in a legacy document at all, so they're left alone.
    async fn sync_v2(self: &Arc<Self>, srv: &Arc<Server>, o: &Owner, doc: &Element, v2: &[(String, Bookmark, Option<Element>)]) {
        let want = legacy_rooms(doc);
        let mut have: HashMap<String, (&str, &Bookmark, Option<&Element>)> = HashMap::new();
        for (id, b, x) in v2 {
            if let Some(room) = room_jid(id) {
                have.entry(room).or_insert((id.as_str(), b, x.as_ref()));
            }
        }
        for (jid, b) in &want {
            let (id, ext) = match have.get(jid) {
                Some((_, old, _)) if *old == b => continue,
                Some((id, _, x)) => (id.to_string(), *x),
                None => (jid.clone(), None),
            };
            match self.store_item(srv, o, NODE, id, b.to_v2(ext), Opts::Create(defaults_for(NODE))).await {
                Ok(p) => self.after_publish(srv, o, &p, Origin::Sync).await,
                Err(e) => return tracing::debug!(error = %e, "pep: bookmark not converted"),
            }
        }
        let gone: Vec<String> = v2
            .iter()
            .filter(|(id, _, _)| room_jid(id).is_some_and(|room| !want.iter().any(|(w, _)| *w == room)))
            .map(|(id, _, _)| id.clone())
            .collect();
        if gone.is_empty() {
            return;
        }
        match self.remove_items(srv, o, NODE, gone).await {
            Ok((cfg, removed)) => self.after_retract(srv, o, NODE, &cfg, &removed, None).await,
            Err(e) => tracing::debug!(error = %e, "pep: removed bookmarks not converted"),
        }
    }

    /// Writes the legacy document to private storage and the legacy PEP node, where asked and
    /// where it differs.
    #[allow(clippy::too_many_arguments)]
    async fn write_legacy(
        self: &Arc<Self>,
        srv: &Arc<Server>,
        o: &Owner,
        doc: &Element,
        pep_now: Option<&Element>,
        private_now: Option<&Element>,
        to_pep: bool,
        to_private: bool,
    ) {
        if to_private && private_now != Some(doc) {
            let (oo, d) = (o.clone(), doc.clone());
            match srv.db.write(move |t| private::store(t, &oo.host, &oo.user, &d)).await {
                Ok(private::Stored::Yes) => {}
                Ok(_) => tracing::debug!("pep: legacy bookmarks don't fit in private storage"),
                Err(e) => tracing::warn!(error = %e, "pep: writing legacy bookmarks"),
            }
        }
        if to_pep && pep_now != Some(doc) {
            let opts = Opts::Create(defaults_for(LEGACY_NODE));
            match self.store_item(srv, o, LEGACY_NODE, LEGACY_ITEM.to_string(), doc.clone(), opts).await {
                Ok(p) => self.after_publish(srv, o, &p, Origin::Sync).await,
                Err(e) => tracing::debug!(error = %e, "pep: legacy bookmarks node not updated"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_and_v2_round_trip() {
        let legacy = Element::parse(
            "<storage xmlns='storage:bookmarks'>\
               <conference jid='Room@Chat.Example' name='Room' autojoin='1'><nick>me</nick></conference>\
               <conference jid='room@chat.example' name='duplicate'/>\
               <conference jid='chat.example'/>\
               <url name='site' url='https://example.org'/>\
             </storage>",
        )
        .unwrap();
        let rooms = legacy_rooms(&legacy);
        assert_eq!(rooms.len(), 1);
        let (jid, b) = &rooms[0];
        assert_eq!(jid, "room@chat.example");
        assert_eq!(b, &Bookmark { name: Some("Room".into()), autojoin: true, nick: Some("me".into()), password: None });
        let v2 = b.to_v2(Some(&Element::new("extensions", NODE).child(Element::new("x", "urn:t"))));
        assert_eq!(Bookmark::from_v2(&v2), *b);
        assert!(v2.has_child("extensions", NODE));
        let doc = legacy_doc(&rooms, Some(&legacy));
        assert!(doc.has_child("url", LEGACY_NS));
        assert_eq!(legacy_rooms(&doc), rooms);
    }
}
