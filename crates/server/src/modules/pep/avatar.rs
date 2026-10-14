//! vCard ⇄ PEP avatar conversion (XEP-0398): an avatar published with XEP-0084 shows up in the
//! account's vcard-temp and in its presence hash (XEP-0153), and a photo stored in vcard-temp
//! by an older client is published to PEP, so old and new clients see the same picture.
//!
//! vcard-temp is readable by anyone, so a PEP avatar is only copied there while its data node
//! is open; otherwise the vCard photo is removed rather than left out of date.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use quark_core::{ns, Element, Jid};
use sha1::Digest;

use super::config::{defaults_for, Access};
use super::iq::Opts;
use super::store::{self, Owner};
use super::{Origin, State};
use crate::modules::vcard;
use crate::server::Server;

pub const DATA: &str = "urn:xmpp:avatar:data";
pub const METADATA: &str = "urn:xmpp:avatar:metadata";
pub const CONVERSION: &str = "urn:xmpp:pep-vcard-conversion:0";

/// What the PEP avatar nodes say right now.
struct Current {
    /// The metadata's chosen id, `Some("")` when the avatar was turned off, None when unknown.
    id: Option<String>,
    /// The data node is readable by anyone.
    public: bool,
    /// The image, base64, and its type, when stored here.
    data: Option<(String, String)>,
}

impl Current {
    /// The hash for presence: only for an avatar anyone may fetch.
    fn presence_hash(&self) -> Option<String> {
        match self.id.as_deref() {
            Some("") => Some(String::new()),
            Some(id) if self.public && self.data.is_some() => Some(id.to_string()),
            _ => None,
        }
    }
}

fn load(c: &rusqlite::Connection, o: &Owner) -> rusqlite::Result<Current> {
    let mut cur = Current { id: None, public: false, data: None };
    let Some(meta) = store::last_item(c, o, METADATA)?.and_then(|i| i.payload()) else { return Ok(cur) };
    // The first inline image (`url` ones live elsewhere); PNG is what XEP-0084 requires.
    let infos: Vec<&Element> = meta.children().filter(|i| i.is("info", METADATA) && i.attr("url").is_none()).collect();
    let Some(info) = infos.iter().find(|i| i.attr("type") == Some("image/png")).or(infos.first()) else {
        cur.id = (meta.children().next().is_none()).then(String::new);
        return Ok(cur);
    };
    let Some(id) = info.attr("id") else { return Ok(cur) };
    cur.id = Some(id.to_string());
    cur.public = store::node(c, o, DATA)?.is_some_and(|cfg| cfg.access == Access::Open);
    if let Some(item) = store::items_by_id(c, o, DATA, &[id.to_string()], usize::MAX)?.pop().and_then(|i| i.payload()) {
        let kind = info.attr("type").unwrap_or("image/png").to_string();
        cur.data = Some((item.text_content().split_whitespace().collect(), kind));
    }
    Ok(cur)
}

/// The image type from its first bytes, for vCards that don't say.
fn sniff(bytes: &[u8]) -> &'static str {
    match bytes {
        [0x89, b'P', b'N', b'G', ..] => "image/png",
        [0xFF, 0xD8, ..] => "image/jpeg",
        [b'G', b'I', b'F', b'8', ..] => "image/gif",
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => "image/webp",
        _ => "image/png",
    }
}

impl State {
    /// The XEP-0153 hash for an account's presence, from the cache or the database.
    async fn avatar_hash(&self, srv: &Arc<Server>, bare: &Jid) -> Option<String> {
        if let Some(h) = self.avatars.lock().get(bare) {
            return h.clone();
        }
        let o = Owner::of(bare)?;
        let h = match srv.db.read(move |c| load(c, &o)).await {
            Ok(cur) => cur.presence_hash(),
            Err(e) => {
                tracing::warn!(error = %e, "pep: avatar for presence");
                return None;
            }
        };
        self.avatars.lock().put(bare.clone(), h.clone());
        h
    }

    /// Puts the account's avatar hash into an available presence it sends (XEP-0153 §4.1).
    pub(super) async fn decorate(&self, srv: &Arc<Server>, from: &Jid, presence: &mut Element) {
        if from.node().is_none() || srv.host(from.domain()).is_none() {
            return;
        }
        let Some(hash) = self.avatar_hash(srv, &from.to_bare()).await else { return };
        presence.remove_children(|c| c.is("x", ns::VCARD_UPDATE));
        let photo = Element::new("photo", ns::VCARD_UPDATE).text(hash);
        presence.append(Element::new("x", ns::VCARD_UPDATE).child(photo));
    }

    /// A client changed the PEP avatar: mirror it into vcard-temp and presence.
    pub(super) async fn avatar_changed(&self, srv: &Arc<Server>, o: &Owner) {
        let oo = o.clone();
        let done = srv
            .db
            .write(move |t| {
                let cur = load(t, &oo)?;
                let stored = vcard::load(t, &oo.host, &oo.user)?;
                let Some(mut vcard) = stored.or_else(|| cur.data.is_some().then(|| Element::new("vCard", ns::VCARD))) else {
                    return Ok(cur.presence_hash());
                };
                let before = vcard.clone();
                vcard.remove_children(|c| c.is("PHOTO", ns::VCARD));
                let without = vcard.clone();
                if let (true, Some((b64, kind))) = (cur.public, &cur.data) {
                    vcard.append(Element::new("PHOTO", ns::VCARD).text_child("TYPE", ns::VCARD, kind.clone()).text_child(
                        "BINVAL",
                        ns::VCARD,
                        b64.clone(),
                    ));
                }
                // A picture too big for a vCard leaves none there rather than an old one.
                if vcard != before && !vcard::store(t, &oo.host, &oo.user, &vcard)? && without != before {
                    vcard::store(t, &oo.host, &oo.user, &without)?;
                }
                Ok(cur.presence_hash())
            })
            .await;
        match done {
            Ok(hash) => self.set_avatar_hash(srv, o, hash).await,
            Err(e) => tracing::warn!(error = %e, "pep: mirroring the avatar to the vCard"),
        }
    }

    /// Remembers the hash and, when it changed, re-sends each online device's presence so
    /// contacts with older clients fetch the new picture.
    async fn set_avatar_hash(&self, srv: &Arc<Server>, o: &Owner, hash: Option<String>) {
        let bare = o.jid();
        let changed = {
            let mut a = self.avatars.lock();
            let changed = a.get(&bare) != Some(&hash);
            a.put(bare.clone(), hash);
            changed
        };
        let Some(host) = srv.host(&o.host) else { return };
        if !changed {
            return;
        }
        for s in srv.sessions.available_of(&bare) {
            if let Some(p) = s.last_presence() {
                crate::modules::presence::from_client_broadcast(srv, &host, &s, p).await;
            }
        }
    }

    /// An older client stored a vCard: publish its photo as the PEP avatar.
    pub(super) async fn vcard_changed(self: &Arc<Self>, srv: &Arc<Server>, jid: &Jid, vcard: &Element) {
        let Some(o) = Owner::of(jid) else { return };
        let Some(photo) = vcard.get_child("PHOTO", ns::VCARD) else { return };
        let Some(b64) = photo.child_text("BINVAL", ns::VCARD).map(|b| b.split_whitespace().collect::<String>()) else { return };
        let Ok(bytes) = B64.decode(&b64) else { return };
        if bytes.is_empty() {
            return;
        }
        let id = hex::encode(sha1::Sha1::digest(&bytes));
        let kind = photo.child_text("TYPE", ns::VCARD).map(|t| t.trim().to_string()).filter(|t| t.starts_with("image/"));
        let kind = kind.unwrap_or_else(|| sniff(&bytes).to_string());
        let oo = o.clone();
        let same = srv.db.read(move |c| load(c, &oo)).await.map(|cur| cur.id.as_deref() == Some(id.as_str()));
        if same.unwrap_or(true) {
            return;
        }
        // vCards are public, so an avatar that came from one is too.
        let mut cfg = defaults_for(DATA);
        cfg.access = Access::Open;
        let data = Element::new("data", DATA).text(b64);
        let meta = Element::new("metadata", METADATA).child(
            Element::new("info", METADATA).attr_set("id", id.clone()).attr_set("bytes", bytes.len().to_string()).attr_set("type", kind),
        );
        for (node, payload) in [(DATA, data), (METADATA, meta)] {
            match self.store_item(srv, &o, node, id.clone(), payload, Opts::Create(cfg.clone())).await {
                Ok(p) => self.after_publish(srv, &o, &p, Origin::Sync).await,
                Err(e) => return tracing::debug!(error = %e, "pep: avatar from vCard not published"),
            }
        }
        let oo = o.clone();
        if let Ok(cur) = srv.db.read(move |c| load(c, &oo)).await {
            self.set_avatar_hash(srv, &o, cur.presence_hash()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_common_image_types() {
        assert_eq!(sniff(&[0x89, b'P', b'N', b'G', 1]), "image/png");
        assert_eq!(sniff(&[0xFF, 0xD8, 0xFF]), "image/jpeg");
        assert_eq!(sniff(b"GIF89a"), "image/gif");
        assert_eq!(sniff(b"RIFF\0\0\0\0WEBPVP8"), "image/webp");
    }

    #[test]
    fn presence_hash_needs_a_public_stored_image() {
        let c = |id: Option<&str>, public, data: bool| Current {
            id: id.map(String::from),
            public,
            data: data.then(|| ("aGk=".to_string(), "image/png".to_string())),
        };
        assert_eq!(c(Some("ab"), true, true).presence_hash().as_deref(), Some("ab"));
        assert_eq!(c(Some("ab"), false, true).presence_hash(), None);
        assert_eq!(c(Some("ab"), true, false).presence_hash(), None);
        assert_eq!(c(Some(""), false, false).presence_hash().as_deref(), Some(""));
        assert_eq!(c(None, true, true).presence_hash(), None);
    }
}
