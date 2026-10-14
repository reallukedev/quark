//! PEP storage: nodes, items, affiliations and explicit subscriptions, per account. Everything
//! here is synchronous and runs inside `db.read`/`db.write` closures, so one request is one trip
//! to a blocking thread.

use quark_core::{Element, Jid};
use rusqlite::Connection;

use super::config::{defaults_for, ItemReply, NodeConfig};
use crate::db::{params, Migration, OptionalExtension};

pub static MIGRATION: Migration = Migration {
    module: "pep",
    steps: &["CREATE TABLE pep_nodes (
        host TEXT NOT NULL,
        user TEXT NOT NULL,
        node TEXT NOT NULL,
        -- NodeConfig as JSON.
        config TEXT NOT NULL,
        created INTEGER NOT NULL,
        PRIMARY KEY (host, user, node),
        FOREIGN KEY (host, user) REFERENCES accounts(host, user) ON DELETE CASCADE
    ) WITHOUT ROWID;
    CREATE TABLE pep_items (
        host TEXT NOT NULL,
        user TEXT NOT NULL,
        node TEXT NOT NULL,
        id TEXT NOT NULL,
        -- Publish order within the node; republishing an id moves it to the end.
        seq INTEGER NOT NULL,
        publisher TEXT,
        -- The item's payload element.
        xml TEXT NOT NULL,
        updated INTEGER NOT NULL,
        PRIMARY KEY (host, user, node, id),
        FOREIGN KEY (host, user, node) REFERENCES pep_nodes(host, user, node) ON DELETE CASCADE
    ) WITHOUT ROWID;
    CREATE INDEX pep_items_seq ON pep_items (host, user, node, seq);
    CREATE TABLE pep_affiliations (
        host TEXT NOT NULL,
        user TEXT NOT NULL,
        node TEXT NOT NULL,
        jid TEXT NOT NULL,
        affiliation TEXT NOT NULL,
        PRIMARY KEY (host, user, node, jid),
        FOREIGN KEY (host, user, node) REFERENCES pep_nodes(host, user, node) ON DELETE CASCADE
    ) WITHOUT ROWID;
    CREATE TABLE pep_subscriptions (
        host TEXT NOT NULL,
        user TEXT NOT NULL,
        node TEXT NOT NULL,
        jid TEXT NOT NULL,
        PRIMARY KEY (host, user, node, jid),
        FOREIGN KEY (host, user, node) REFERENCES pep_nodes(host, user, node) ON DELETE CASCADE
    ) WITHOUT ROWID;"],
};

/// The account a PEP service belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Owner {
    pub host: String,
    pub user: String,
}

impl Owner {
    pub fn of(j: &Jid) -> Option<Owner> {
        Some(Owner { host: j.domain().to_string(), user: j.node()?.to_string() })
    }
    pub fn jid(&self) -> Jid {
        Jid::bare_unchecked(&self.user, &self.host)
    }
}

/// A stored item.
#[derive(Debug, Clone)]
pub struct Item {
    pub id: String,
    pub publisher: Option<String>,
    pub xml: String,
    pub updated: i64,
}

impl Item {
    /// `<item id='…'>payload</item>` in `ns` (pubsub or pubsub#event).
    pub fn to_element(&self, ns: &str, payload: bool) -> Element {
        let mut el = Element::new("item", ns).attr_set("id", self.id.clone()).attr_opt("publisher", self.publisher.clone());
        if payload {
            if let Ok(p) = Element::parse(&self.xml) {
                el.append(p);
            }
        }
        el
    }

    /// The item as others see it, in `ns`: the publisher only when the node says to show it
    /// (`pubsub#itemreply`).
    pub fn shown(&self, ns: &str, cfg: &NodeConfig, payload: bool) -> Element {
        let mut el = self.to_element(ns, payload);
        if cfg.itemreply != ItemReply::Publisher {
            el.remove_attr("publisher");
        }
        el
    }

    pub fn payload(&self) -> Option<Element> {
        Element::parse(&self.xml).ok()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Affiliation {
    Owner,
    Publisher,
    Member,
    Outcast,
}

impl Affiliation {
    pub fn as_str(self) -> &'static str {
        match self {
            Affiliation::Owner => "owner",
            Affiliation::Publisher => "publisher",
            Affiliation::Member => "member",
            Affiliation::Outcast => "outcast",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "owner" => Affiliation::Owner,
            "publisher" => Affiliation::Publisher,
            "member" => Affiliation::Member,
            "outcast" => Affiliation::Outcast,
            _ => return None,
        })
    }
}

fn to_json(cfg: &NodeConfig) -> rusqlite::Result<String> {
    serde_json::to_string(cfg).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
}

fn from_json(node: &str, json: &str) -> NodeConfig {
    serde_json::from_str(json).unwrap_or_else(|e| {
        tracing::warn!(node, error = %e, "pep: unreadable node configuration, using defaults");
        defaults_for(node)
    })
}

pub fn node(c: &Connection, o: &Owner, node: &str) -> rusqlite::Result<Option<NodeConfig>> {
    let mut st = c.prepare_cached("SELECT config FROM pep_nodes WHERE host = ?1 AND user = ?2 AND node = ?3")?;
    let json: Option<String> = st.query_row(params![o.host, o.user, node], |r| r.get(0)).optional()?;
    Ok(json.map(|j| from_json(node, &j)))
}

pub fn nodes(c: &Connection, o: &Owner) -> rusqlite::Result<Vec<(String, NodeConfig)>> {
    let mut st = c.prepare_cached("SELECT node, config FROM pep_nodes WHERE host = ?1 AND user = ?2 ORDER BY node")?;
    let rows = st.query_map(params![o.host, o.user], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut out = Vec::new();
    for r in rows {
        let (n, j) = r?;
        let cfg = from_json(&n, &j);
        out.push((n, cfg));
    }
    Ok(out)
}

pub fn node_count(c: &Connection, o: &Owner) -> rusqlite::Result<u32> {
    c.prepare_cached("SELECT COUNT(*) FROM pep_nodes WHERE host = ?1 AND user = ?2")?.query_row(params![o.host, o.user], |r| r.get(0))
}

pub fn create(c: &Connection, o: &Owner, node: &str, cfg: &NodeConfig) -> rusqlite::Result<()> {
    c.prepare_cached("INSERT INTO pep_nodes (host, user, node, config, created) VALUES (?1, ?2, ?3, ?4, ?5)")?.execute(params![
        o.host,
        o.user,
        node,
        to_json(cfg)?,
        quark_core::time::now_ms()
    ])?;
    Ok(())
}

/// Saves a node's configuration and drops items past its new limit, returning their ids.
pub fn configure(c: &Connection, o: &Owner, node: &str, cfg: &NodeConfig) -> rusqlite::Result<Vec<String>> {
    c.prepare_cached("UPDATE pep_nodes SET config = ?4 WHERE host = ?1 AND user = ?2 AND node = ?3")?.execute(params![
        o.host,
        o.user,
        node,
        to_json(cfg)?
    ])?;
    trim(c, o, node, cfg.keep())
}

/// Deletes a node with its items, affiliations and subscriptions. False when there was none.
pub fn delete(c: &Connection, o: &Owner, node: &str) -> rusqlite::Result<bool> {
    let n =
        c.prepare_cached("DELETE FROM pep_nodes WHERE host = ?1 AND user = ?2 AND node = ?3")?.execute(params![o.host, o.user, node])?;
    Ok(n > 0)
}

/// Stores an item (replacing one with the same id, which then counts as newest) and keeps only
/// the newest `keep`, returning the ids of those dropped.
pub fn put_item(c: &Connection, o: &Owner, node: &str, it: &Item, keep: u32) -> rusqlite::Result<Vec<String>> {
    let seq: i64 = c
        .prepare_cached("SELECT COALESCE(MAX(seq), 0) + 1 FROM pep_items WHERE host = ?1 AND user = ?2 AND node = ?3")?
        .query_row(params![o.host, o.user, node], |r| r.get(0))?;
    c.prepare_cached(
        "INSERT INTO pep_items (host, user, node, id, seq, publisher, xml, updated) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(host, user, node, id) DO UPDATE SET seq = excluded.seq, publisher = excluded.publisher, xml = excluded.xml, updated = excluded.updated",
    )?
    .execute(params![o.host, o.user, node, it.id, seq, it.publisher, it.xml, it.updated])?;
    trim(c, o, node, keep)
}

/// Drops all but the newest `keep` items, returning the ids dropped (for retract notifications).
fn trim(c: &Connection, o: &Owner, node: &str, keep: u32) -> rusqlite::Result<Vec<String>> {
    let mut st = c.prepare_cached(
        "DELETE FROM pep_items WHERE host = ?1 AND user = ?2 AND node = ?3 AND seq <= (
            SELECT seq FROM pep_items WHERE host = ?1 AND user = ?2 AND node = ?3 ORDER BY seq DESC LIMIT 1 OFFSET ?4)
         RETURNING id",
    )?;
    let rows = st.query_map(params![o.host, o.user, node, keep], |r| r.get(0))?;
    rows.collect()
}

/// How many items a node holds, and whether `id` is one of them.
pub fn fill(c: &Connection, o: &Owner, node: &str, id: &str) -> rusqlite::Result<(u32, bool)> {
    c.prepare_cached("SELECT COUNT(*), COALESCE(SUM(id = ?4), 0) > 0 FROM pep_items WHERE host = ?1 AND user = ?2 AND node = ?3")?
        .query_row(params![o.host, o.user, node, id], |r| Ok((r.get(0)?, r.get(1)?)))
}

pub fn retract(c: &Connection, o: &Owner, node: &str, id: &str) -> rusqlite::Result<bool> {
    let n = c
        .prepare_cached("DELETE FROM pep_items WHERE host = ?1 AND user = ?2 AND node = ?3 AND id = ?4")?
        .execute(params![o.host, o.user, node, id])?;
    Ok(n > 0)
}

pub fn purge(c: &Connection, o: &Owner, node: &str) -> rusqlite::Result<()> {
    c.prepare_cached("DELETE FROM pep_items WHERE host = ?1 AND user = ?2 AND node = ?3")?.execute(params![o.host, o.user, node])?;
    Ok(())
}

fn row_item(r: &rusqlite::Row<'_>) -> rusqlite::Result<Item> {
    Ok(Item { id: r.get(0)?, publisher: r.get(1)?, xml: r.get(2)?, updated: r.get(3)? })
}

/// The newest `max` items (all when None), oldest first.
pub fn items(c: &Connection, o: &Owner, node: &str, max: Option<u32>) -> rusqlite::Result<Vec<Item>> {
    let mut st = c.prepare_cached(
        "SELECT id, publisher, xml, updated FROM pep_items WHERE host = ?1 AND user = ?2 AND node = ?3 ORDER BY seq DESC LIMIT ?4",
    )?;
    let limit = max.map_or(-1, i64::from);
    let mut v: Vec<Item> = st.query_map(params![o.host, o.user, node, limit], row_item)?.collect::<Result<_, _>>()?;
    v.reverse();
    Ok(v)
}

/// Items for a reply that must fit in a stanza: the newest `max` (all when None), newest first
/// until their payloads would pass `budget` bytes (at least one is always given), returned
/// oldest first, with how many the request asked for in all (XEP-0060 §6.5.7: when cut short, a
/// service sends the most recent).
pub fn items_within(c: &Connection, o: &Owner, node: &str, max: Option<u32>, budget: usize) -> rusqlite::Result<(Vec<Item>, u32)> {
    let total: u32 = c
        .prepare_cached("SELECT COUNT(*) FROM pep_items WHERE host = ?1 AND user = ?2 AND node = ?3")?
        .query_row(params![o.host, o.user, node], |r| r.get(0))?;
    let total = max.map_or(total, |m| m.min(total));
    let mut st = c.prepare_cached(
        "SELECT id, publisher, xml, updated FROM pep_items WHERE host = ?1 AND user = ?2 AND node = ?3 ORDER BY seq DESC LIMIT ?4",
    )?;
    let mut rows = st.query(params![o.host, o.user, node, total])?;
    let (mut out, mut used) = (Vec::new(), 0usize);
    while let Some(r) = rows.next()? {
        let it = row_item(r)?;
        used += it.xml.len();
        if used > budget && !out.is_empty() {
            break;
        }
        out.push(it);
    }
    out.reverse();
    Ok((out, total))
}

/// The items with these ids, in the order asked, until their payloads would pass `budget`
/// bytes (at least one is always given).
pub fn items_by_id(c: &Connection, o: &Owner, node: &str, ids: &[String], budget: usize) -> rusqlite::Result<Vec<Item>> {
    let mut st =
        c.prepare_cached("SELECT id, publisher, xml, updated FROM pep_items WHERE host = ?1 AND user = ?2 AND node = ?3 AND id = ?4")?;
    let (mut out, mut used) = (Vec::new(), 0usize);
    for id in ids {
        if let Some(it) = st.query_row(params![o.host, o.user, node, id], row_item).optional()? {
            used += it.xml.len();
            if used > budget && !out.is_empty() {
                break;
            }
            out.push(it);
        }
    }
    Ok(out)
}

/// A node's last item with what decides who gets it: (node, configuration, affiliation, item).
pub type LastItem = (String, NodeConfig, Option<Affiliation>, Item);

/// For each of `nodes` the account has, with an item: its configuration, `jid`'s affiliation
/// and the last item. One indexed query, however many nodes the account keeps.
pub fn last_items(c: &Connection, o: &Owner, nodes: &[String], jid: &str) -> rusqlite::Result<Vec<LastItem>> {
    let wanted = serde_json::to_string(nodes).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    let mut st = c.prepare_cached(
        "SELECT i.id, i.publisher, i.xml, i.updated, n.node, n.config, a.affiliation
         FROM json_each(?3) w
         JOIN pep_nodes n ON n.host = ?1 AND n.user = ?2 AND n.node = w.value
         JOIN pep_items i ON i.host = n.host AND i.user = n.user AND i.node = n.node
            AND i.seq = (SELECT MAX(seq) FROM pep_items m WHERE m.host = n.host AND m.user = n.user AND m.node = n.node)
         LEFT JOIN pep_affiliations a ON a.host = n.host AND a.user = n.user AND a.node = n.node AND a.jid = ?4",
    )?;
    let rows = st.query_map(params![o.host, o.user, wanted, jid], |r| {
        Ok((row_item(r)?, r.get::<_, String>(4)?, r.get::<_, String>(5)?, r.get::<_, Option<String>>(6)?))
    })?;
    let mut out = Vec::new();
    for r in rows {
        let (it, n, cfg, aff) = r?;
        let cfg = from_json(&n, &cfg);
        out.push((n, cfg, aff.as_deref().and_then(Affiliation::parse), it));
    }
    Ok(out)
}

pub fn last_item(c: &Connection, o: &Owner, node: &str) -> rusqlite::Result<Option<Item>> {
    Ok(items(c, o, node, Some(1))?.pop())
}

pub fn item_ids(c: &Connection, o: &Owner, node: &str) -> rusqlite::Result<Vec<String>> {
    let mut st = c.prepare_cached("SELECT id FROM pep_items WHERE host = ?1 AND user = ?2 AND node = ?3 ORDER BY seq")?;
    let rows = st.query_map(params![o.host, o.user, node], |r| r.get(0))?;
    rows.collect()
}

/// Bytes of payload the account stores, and how many of them the item `id` in `node` takes.
/// (Bytes, as Rust measures them: SQLite's LENGTH of text counts characters.)
pub fn usage(c: &Connection, o: &Owner, node: &str, id: &str) -> rusqlite::Result<(i64, i64)> {
    let total: i64 = c
        .prepare_cached("SELECT COALESCE(SUM(LENGTH(CAST(xml AS BLOB))), 0) FROM pep_items WHERE host = ?1 AND user = ?2")?
        .query_row(params![o.host, o.user], |r| r.get(0))?;
    let this: i64 = c
        .prepare_cached(
            "SELECT COALESCE(LENGTH(CAST(xml AS BLOB)), 0) FROM pep_items WHERE host = ?1 AND user = ?2 AND node = ?3 AND id = ?4",
        )?
        .query_row(params![o.host, o.user, node, id], |r| r.get(0))
        .optional()?
        .unwrap_or(0);
    Ok((total, this))
}

pub fn affiliation(c: &Connection, o: &Owner, node: &str, jid: &str) -> rusqlite::Result<Option<Affiliation>> {
    let a: Option<String> = c
        .prepare_cached("SELECT affiliation FROM pep_affiliations WHERE host = ?1 AND user = ?2 AND node = ?3 AND jid = ?4")?
        .query_row(params![o.host, o.user, node, jid], |r| r.get(0))
        .optional()?;
    Ok(a.as_deref().and_then(Affiliation::parse))
}

pub fn affiliations(c: &Connection, o: &Owner, node: &str) -> rusqlite::Result<Vec<(String, Affiliation)>> {
    let mut st =
        c.prepare_cached("SELECT jid, affiliation FROM pep_affiliations WHERE host = ?1 AND user = ?2 AND node = ?3 ORDER BY jid")?;
    let rows = st.query_map(params![o.host, o.user, node], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut out = Vec::new();
    for r in rows {
        let (j, a) = r?;
        if let Some(a) = Affiliation::parse(&a) {
            out.push((j, a));
        }
    }
    Ok(out)
}

/// Every node where `jid` has an affiliation.
pub fn affiliations_of(c: &Connection, o: &Owner, jid: &str) -> rusqlite::Result<Vec<(String, Affiliation)>> {
    let mut st = c.prepare_cached("SELECT node, affiliation FROM pep_affiliations WHERE host = ?1 AND user = ?2 AND jid = ?3")?;
    let rows = st.query_map(params![o.host, o.user, jid], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut out = Vec::new();
    for r in rows {
        let (n, a) = r?;
        if let Some(a) = Affiliation::parse(&a) {
            out.push((n, a));
        }
    }
    Ok(out)
}

pub fn affiliation_count(c: &Connection, o: &Owner, node: &str) -> rusqlite::Result<u32> {
    c.prepare_cached("SELECT COUNT(*) FROM pep_affiliations WHERE host = ?1 AND user = ?2 AND node = ?3")?
        .query_row(params![o.host, o.user, node], |r| r.get(0))
}

pub fn set_affiliation(c: &Connection, o: &Owner, node: &str, jid: &str, a: Option<Affiliation>) -> rusqlite::Result<()> {
    match a {
        Some(a) => c
            .prepare_cached(
                "INSERT INTO pep_affiliations (host, user, node, jid, affiliation) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(host, user, node, jid) DO UPDATE SET affiliation = excluded.affiliation",
            )?
            .execute(params![o.host, o.user, node, jid, a.as_str()])?,
        None => c
            .prepare_cached("DELETE FROM pep_affiliations WHERE host = ?1 AND user = ?2 AND node = ?3 AND jid = ?4")?
            .execute(params![o.host, o.user, node, jid])?,
    };
    Ok(())
}

pub fn subscribers(c: &Connection, o: &Owner, node: &str) -> rusqlite::Result<Vec<String>> {
    let mut st = c.prepare_cached("SELECT jid FROM pep_subscriptions WHERE host = ?1 AND user = ?2 AND node = ?3 ORDER BY jid")?;
    let rows = st.query_map(params![o.host, o.user, node], |r| r.get(0))?;
    rows.collect()
}

/// Every explicit subscription on the account's nodes, as (node, jid).
pub fn all_subscriptions(c: &Connection, o: &Owner) -> rusqlite::Result<Vec<(String, String)>> {
    let mut st = c.prepare_cached("SELECT node, jid FROM pep_subscriptions WHERE host = ?1 AND user = ?2 ORDER BY node, jid")?;
    let rows = st.query_map(params![o.host, o.user], |r| Ok((r.get(0)?, r.get(1)?)))?;
    rows.collect()
}

pub fn subscription_count(c: &Connection, o: &Owner, node: &str) -> rusqlite::Result<u32> {
    c.prepare_cached("SELECT COUNT(*) FROM pep_subscriptions WHERE host = ?1 AND user = ?2 AND node = ?3")?
        .query_row(params![o.host, o.user, node], |r| r.get(0))
}

pub fn subscribe(c: &Connection, o: &Owner, node: &str, jid: &str) -> rusqlite::Result<()> {
    c.prepare_cached("INSERT OR IGNORE INTO pep_subscriptions (host, user, node, jid) VALUES (?1, ?2, ?3, ?4)")?
        .execute(params![o.host, o.user, node, jid])?;
    Ok(())
}

pub fn unsubscribe(c: &Connection, o: &Owner, node: &str, jid: &str) -> rusqlite::Result<bool> {
    let n = c
        .prepare_cached("DELETE FROM pep_subscriptions WHERE host = ?1 AND user = ?2 AND node = ?3 AND jid = ?4")?
        .execute(params![o.host, o.user, node, jid])?;
    Ok(n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    fn db() -> (Db, Owner) {
        let db = Db::memory().unwrap();
        db.write_blocking(|t| {
            t.execute_batch("CREATE TABLE accounts (host TEXT NOT NULL, user TEXT NOT NULL, PRIMARY KEY (host, user)); INSERT INTO accounts VALUES ('h', 'u');")
        })
        .unwrap();
        db.migrate(&[&MIGRATION]).unwrap();
        (db, Owner { host: "h".into(), user: "u".into() })
    }

    fn item(id: &str) -> Item {
        Item { id: id.into(), publisher: None, xml: format!("<x xmlns='urn:t'>{id}</x>"), updated: 1 }
    }

    #[test]
    fn items_keep_the_newest_and_republishing_moves_to_the_end() {
        let (db, o) = db();
        db.write_blocking(|t| {
            create(t, &o, "n", &NodeConfig::default())?;
            for id in ["a", "b", "c"] {
                put_item(t, &o, "n", &item(id), 2)?;
            }
            put_item(t, &o, "n", &item("b"), 2)?;
            let ids: Vec<String> = items(t, &o, "n", None)?.into_iter().map(|i| i.id).collect();
            assert_eq!(ids, ["c", "b"]);
            assert_eq!(items(t, &o, "n", Some(1))?[0].id, "b");
            assert_eq!(last_item(t, &o, "n")?.unwrap().id, "b");
            assert!(retract(t, &o, "n", "b")?);
            assert!(!retract(t, &o, "n", "b")?);
            assert_eq!(item_ids(t, &o, "n")?, ["c"]);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn deleting_a_node_takes_everything_with_it() {
        let (db, o) = db();
        db.write_blocking(|t| {
            create(t, &o, "n", &NodeConfig::default())?;
            put_item(t, &o, "n", &item("a"), 5)?;
            subscribe(t, &o, "n", "x@y")?;
            set_affiliation(t, &o, "n", "x@y", Some(Affiliation::Member))?;
            assert!(delete(t, &o, "n")?);
            create(t, &o, "n", &NodeConfig::default())?;
            assert!(items(t, &o, "n", None)?.is_empty());
            assert!(subscribers(t, &o, "n")?.is_empty());
            assert!(affiliation(t, &o, "n", "x@y")?.is_none());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn usage_counts_payload_bytes() {
        let (db, o) = db();
        db.write_blocking(|t| {
            create(t, &o, "n", &NodeConfig::default())?;
            // Four bytes per character: counting characters would let 4x the quota in.
            let it = Item { xml: format!("<x xmlns='urn:t'>{}</x>", "😀".repeat(100)), ..item("a") };
            put_item(t, &o, "n", &it, 5)?;
            let (total, this) = usage(t, &o, "n", "a")?;
            assert_eq!(total, this);
            assert_eq!(total, it.xml.len() as i64);
            assert_eq!(usage(t, &o, "n", "zz")?.1, 0);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn trimming_reports_what_it_dropped() {
        let (db, o) = db();
        db.write_blocking(|t| {
            create(t, &o, "n", &NodeConfig::default())?;
            assert!(put_item(t, &o, "n", &item("a"), 2)?.is_empty());
            assert!(put_item(t, &o, "n", &item("b"), 2)?.is_empty());
            assert_eq!(put_item(t, &o, "n", &item("c"), 2)?, ["a"]);
            assert_eq!(fill(t, &o, "n", "c")?, (2, true));
            assert_eq!(fill(t, &o, "n", "a")?, (2, false));
            let cfg = NodeConfig { max_items: 1, ..NodeConfig::default() };
            assert_eq!(configure(t, &o, "n", &cfg)?, ["b"]);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn replies_keep_the_newest_items_that_fit() {
        let (db, o) = db();
        db.write_blocking(|t| {
            create(t, &o, "n", &NodeConfig::default())?;
            for id in ["a", "b", "c", "d"] {
                put_item(t, &o, "n", &item(id), 10)?;
            }
            let one = item("a").xml.len();
            let (got, total) = items_within(t, &o, "n", None, one * 2)?;
            assert_eq!((got.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), total), (vec!["c", "d"], 4));
            let (got, total) = items_within(t, &o, "n", Some(3), 1)?;
            assert_eq!((got.len(), got[0].id.as_str(), total), (1, "d", 3));
            let ids: Vec<String> = ["b", "zz", "a", "c"].iter().map(|s| s.to_string()).collect();
            assert_eq!(items_by_id(t, &o, "n", &ids, one * 2)?.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), ["b", "a"]);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn last_items_come_only_for_the_nodes_asked() {
        let (db, o) = db();
        db.write_blocking(|t| {
            for n in ["a", "b", "c"] {
                create(t, &o, n, &NodeConfig::default())?;
            }
            put_item(t, &o, "a", &item("1"), 5)?;
            put_item(t, &o, "a", &item("2"), 5)?;
            put_item(t, &o, "c", &item("3"), 5)?;
            set_affiliation(t, &o, "a", "x@y", Some(Affiliation::Member))?;
            let wanted: Vec<String> = ["a", "b", "zz"].iter().map(|s| s.to_string()).collect();
            let got = last_items(t, &o, &wanted, "x@y")?;
            assert_eq!(got.len(), 1);
            let (n, _, aff, it) = &got[0];
            assert_eq!((n.as_str(), *aff, it.id.as_str()), ("a", Some(Affiliation::Member), "2"));
            Ok(())
        })
        .unwrap();
    }
}
