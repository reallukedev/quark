//! PEP in account exports (XEP-0227 §4): each node's configuration, affiliations and
//! subscriptions in a `pubsub#owner` element, and its items in a `pubsub` one, the way Prosody
//! and ejabberd write them.

use quark_core::{ns, Element, Jid};
use rusqlite::Connection;

use super::config::{defaults_for, NodeConfig};
use super::store::{self, Affiliation, Item, Owner};
use super::{MAX_ACCOUNT_BYTES, MAX_ITEM_BYTES, MAX_NAME, MAX_NODES, MAX_PER_NODE};

/// The account's nodes as export elements.
pub fn export(c: &Connection, o: &Owner) -> rusqlite::Result<Vec<Element>> {
    let nodes = store::nodes(c, o)?;
    if nodes.is_empty() {
        return Ok(Vec::new());
    }
    let mut owner = Element::new("pubsub", ns::PUBSUB_OWNER);
    let mut items = Element::new("pubsub", ns::PUBSUB);
    for (node, cfg) in &nodes {
        let mut form = cfg.to_form(Some(node));
        form.set_attr("type", "submit");
        owner.append(Element::new("configure", ns::PUBSUB_OWNER).attr_set("node", node.clone()).child(form));
        let affs = store::affiliations(c, o, node)?;
        if !affs.is_empty() {
            let mut el = Element::new("affiliations", ns::PUBSUB_OWNER).attr_set("node", node.clone());
            for (j, a) in affs {
                el.append(Element::new("affiliation", ns::PUBSUB_OWNER).attr_set("jid", j).attr_set("affiliation", a.as_str()));
            }
            owner.append(el);
        }
        let subs = store::subscribers(c, o, node)?;
        if !subs.is_empty() {
            let mut el = Element::new("subscriptions", ns::PUBSUB_OWNER).attr_set("node", node.clone());
            for j in subs {
                el.append(Element::new("subscription", ns::PUBSUB_OWNER).attr_set("jid", j).attr_set("subscription", "subscribed"));
            }
            owner.append(el);
        }
        let stored = store::items(c, o, node, None)?;
        if !stored.is_empty() {
            let mut el = Element::new("items", ns::PUBSUB).attr_set("node", node.clone());
            for it in &stored {
                el.append(it.to_element(ns::PUBSUB, true));
            }
            items.append(el);
        }
    }
    let mut out = vec![owner];
    if items.first_child().is_some() {
        out.push(items);
    }
    Ok(out)
}

fn node_name(el: &Element) -> Option<&str> {
    el.attr("node").filter(|n| !n.is_empty() && n.len() <= MAX_NAME)
}

/// Creates `node` with `cfg` unless it exists; false when the account has too many nodes.
fn ensure(c: &Connection, o: &Owner, node: &str, cfg: &NodeConfig) -> rusqlite::Result<Option<NodeConfig>> {
    if let Some(existing) = store::node(c, o, node)? {
        return Ok(Some(existing));
    }
    if store::node_count(c, o)? >= MAX_NODES {
        return Ok(None);
    }
    store::create(c, o, node, cfg)?;
    Ok(Some(cfg.clone()))
}

/// Takes the PEP parts of an exported `<user/>`, within the limits publishing has. Returns
/// what was left out, for the admin.
pub fn import(c: &Connection, o: &Owner, user: &Element) -> rusqlite::Result<Vec<String>> {
    let jid = o.jid();
    let mut notes = Vec::new();
    let mut skipped_nodes = 0usize;
    let mut skipped_items = 0usize;
    let owner_parts = user.children().filter(|p| p.is("pubsub", ns::PUBSUB_OWNER)).flat_map(|p| p.children());
    // Configuration first, so items land in nodes set up the way they were.
    let (mut configs, mut rest) = (Vec::new(), Vec::new());
    for el in owner_parts {
        if el.is("configure", ns::PUBSUB_OWNER) {
            configs.push(el);
        } else {
            rest.push(el);
        }
    }
    for el in configs {
        let Some(node) = node_name(el) else { continue };
        let mut cfg = defaults_for(node);
        if let Some(f) = el.get_child("x", ns::DATA_FORMS) {
            // An option this server can't do keeps its default rather than losing the node.
            for field in f.children().filter(|c| c.is("field", ns::DATA_FORMS)) {
                let one = Element::new("x", ns::DATA_FORMS).child(field.clone());
                let _ = cfg.apply_form(&one);
            }
        }
        match store::node(c, o, node)? {
            Some(_) => store::configure(c, o, node, &cfg).map(|_| ())?,
            None if ensure(c, o, node, &cfg)?.is_some() => {}
            None => skipped_nodes += 1,
        }
    }
    for el in rest {
        let Some(node) = node_name(el) else { continue };
        if store::node(c, o, node)?.is_none() {
            continue;
        }
        if el.is("affiliations", ns::PUBSUB_OWNER) {
            for a in el.children().filter(|a| a.is("affiliation", ns::PUBSUB_OWNER)) {
                let Some(j) = a.attr("jid").and_then(|j| Jid::parse(j).ok()).map(|j| j.to_bare()) else { continue };
                let Some(aff) = a.attr("affiliation").and_then(Affiliation::parse).filter(|a| *a != Affiliation::Owner) else { continue };
                if j == jid || store::affiliation_count(c, o, node)? >= MAX_PER_NODE {
                    continue;
                }
                store::set_affiliation(c, o, node, &j.to_string(), Some(aff))?;
            }
        } else if el.is("subscriptions", ns::PUBSUB_OWNER) {
            for s in el.children().filter(|s| s.is("subscription", ns::PUBSUB_OWNER)) {
                let Some(j) = s.attr("jid").and_then(|j| Jid::parse(j).ok()) else { continue };
                if s.attr("subscription").is_some_and(|v| v != "subscribed") || store::subscription_count(c, o, node)? >= MAX_PER_NODE {
                    continue;
                }
                store::subscribe(c, o, node, &j.to_string())?;
            }
        }
    }
    let item_parts = user.children().filter(|p| p.is("pubsub", ns::PUBSUB)).flat_map(|p| p.children());
    for el in item_parts.filter(|e| e.is("items", ns::PUBSUB)) {
        let Some(node) = node_name(el) else { continue };
        let Some(cfg) = ensure(c, o, node, &defaults_for(node))? else {
            skipped_nodes += 1;
            continue;
        };
        for item in el.children().filter(|i| i.is("item", ns::PUBSUB)) {
            let mut payloads = item.children();
            let (Some(payload), None) = (payloads.next(), payloads.next()) else { continue };
            let Some(id) = item.attr("id").filter(|i| !i.is_empty() && i.len() <= MAX_NAME) else { continue };
            let mut payload = payload.clone();
            payload.strip_whitespace();
            let xml = payload.to_xml();
            let (total, this) = store::usage(c, o, node, id)?;
            if xml.len() > MAX_ITEM_BYTES || total - this + xml.len() as i64 > MAX_ACCOUNT_BYTES {
                skipped_items += 1;
                continue;
            }
            let it = Item { id: id.to_string(), publisher: Some(jid.to_string()), xml, updated: quark_core::time::now_ms() };
            store::put_item(c, o, node, &it, cfg.keep())?;
        }
    }
    if skipped_nodes > 0 {
        notes.push(format!("{jid}: {skipped_nodes} PEP nodes were left out (accounts keep at most {MAX_NODES})."));
    }
    if skipped_items > 0 {
        notes.push(format!("{jid}: {skipped_items} PEP items were left out for being too big."));
    }
    Ok(notes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    fn db() -> (Db, Owner) {
        let db = Db::memory().unwrap();
        db.write_blocking(|t| {
            t.execute_batch(
                "CREATE TABLE accounts (host TEXT NOT NULL, user TEXT NOT NULL, PRIMARY KEY (host, user));
                 INSERT INTO accounts VALUES ('h', 'u'), ('h', 'v');",
            )
        })
        .unwrap();
        db.migrate(&[&store::MIGRATION]).unwrap();
        (db, Owner { host: "h".into(), user: "u".into() })
    }

    #[test]
    fn nodes_items_and_settings_survive_a_round_trip() {
        let (db, o) = db();
        let other = Owner { host: "h".into(), user: "v".into() };
        let exported = db
            .write_blocking(|t| {
                let cfg = NodeConfig { access: super::super::config::Access::Open, max_items: 5, ..NodeConfig::default() };
                store::create(t, &o, "n", &cfg)?;
                for id in ["a", "b"] {
                    let it = Item { id: id.into(), publisher: None, xml: format!("<x xmlns='urn:t'>{id}</x>"), updated: 1 };
                    store::put_item(t, &o, "n", &it, 5)?;
                }
                store::set_affiliation(t, &o, "n", "x@y", Some(Affiliation::Member))?;
                store::subscribe(t, &o, "n", "x@y/r")?;
                store::create(t, &o, "empty", &NodeConfig::default())?;
                export(t, &o)
            })
            .unwrap();
        let user = Element::new("user", "urn:xmpp:pie:0").children_from(exported);
        // Through text, as a real export travels.
        let user = Element::parse(&user.to_xml()).unwrap();
        db.write_blocking(|t| {
            assert!(import(t, &other, &user)?.is_empty());
            let cfg = store::node(t, &other, "n")?.unwrap();
            assert_eq!((cfg.access, cfg.max_items), (super::super::config::Access::Open, 5));
            assert_eq!(store::item_ids(t, &other, "n")?, ["a", "b"]);
            assert_eq!(store::items(t, &other, "n", None)?[1].xml, "<x xmlns='urn:t'>b</x>");
            assert_eq!(store::affiliation(t, &other, "n", "x@y")?, Some(Affiliation::Member));
            assert_eq!(store::subscribers(t, &other, "n")?, ["x@y/r"]);
            assert!(store::node(t, &other, "empty")?.is_some());
            Ok(())
        })
        .unwrap();
    }
}
