//! Message Archive Management (XEP-0313, `urn:xmpp:mam:2` with `#extended`), preferences
//! (XEP-0441), full-text search (XEP-0431) and stanza ids (XEP-0359): per-account archives,
//! and the storage and query engine group chats reuse for their own archives.
//!
//! Every archived message gets a 64-bit id that is its time in milliseconds shifted left by
//! [`SEQ_BITS`] plus a counter, so ids are unique, sort by time and double as the time index.
//! Clients see them as 13 base32 characters. Stanzas are stored without what the archive
//! already knows and compressed with a preset dictionary of common stanza text (see [`codec`]).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Weak};
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use quark_core::stanza::{iq_result, IqType};
use quark_core::{ns, Condition, Element, Jid, StanzaError};
use rusqlite::types::Value;

use super::{ok, Event, Flow, IqCtx, IqReply, IqResult, IqTarget, Module, StanzaCtx};
use crate::db::{params, DbError, Migration, OptionalExtension};
use crate::server::{Host, Server};

pub static MIGRATION: Migration = Migration {
    module: "mam",
    steps: &["CREATE TABLE mam_archives (
        id INTEGER PRIMARY KEY,
        jid TEXT NOT NULL UNIQUE,
        -- The local domain whose history setting applies (a room's parent domain).
        host TEXT NOT NULL,
        -- Set for account archives, so they go with the account; NULL for rooms.
        user TEXT,
        FOREIGN KEY (host, user) REFERENCES accounts(host, user) ON DELETE CASCADE
    );
    CREATE INDEX mam_archives_by_host ON mam_archives (host);
    CREATE TABLE mam (
        -- Milliseconds << 12 | sequence: unique, time ordered, and the time index.
        id INTEGER PRIMARY KEY,
        archive INTEGER NOT NULL REFERENCES mam_archives(id) ON DELETE CASCADE,
        with_bare TEXT NOT NULL,
        with_res TEXT,
        -- In the full-text index.
        indexed INTEGER NOT NULL DEFAULT 0,
        xml BLOB NOT NULL
    );
    CREATE INDEX mam_by_archive ON mam (archive, id);
    CREATE INDEX mam_by_with ON mam (archive, with_bare, id);
    CREATE VIRTUAL TABLE mam_fts USING fts5(body, content='', contentless_delete=1, tokenize='unicode61 remove_diacritics 2');
    CREATE TRIGGER mam_fts_gone AFTER DELETE ON mam WHEN old.indexed BEGIN
        DELETE FROM mam_fts WHERE rowid = old.id;
    END;
    CREATE TABLE mam_prefs (
        host TEXT NOT NULL,
        user TEXT NOT NULL,
        mode TEXT NOT NULL,
        always TEXT NOT NULL,
        never TEXT NOT NULL,
        PRIMARY KEY (host, user),
        FOREIGN KEY (host, user) REFERENCES accounts(host, user) ON DELETE CASCADE
    ) WITHOUT ROWID;"],
};

pub const FULLTEXT: &str = "urn:xmpp:fulltext:0";
const FULLTEXT_FIELD: &str = "{urn:xmpp:fulltext:0}fulltext";
const XDATA_VALIDATE: &str = "http://jabber.org/protocol/xdata-validate";

/// Low bits of an id that count messages within one millisecond.
const SEQ_BITS: u32 = 12;
/// Results per page when the client doesn't say, and at most.
const DEFAULT_PAGE: usize = 50;
const MAX_PAGE: usize = 250;
/// Ids in one `ids` filter.
const MAX_IDS: usize = 250;
/// JIDs in each preferences list.
const MAX_PREF_JIDS: usize = 1_000;
/// Search terms and their length, so a query stays cheap.
const MAX_TERMS: usize = 16;
const MAX_TERM: usize = 64;
/// Body text put in the full-text index.
const MAX_INDEXED: usize = 4_096;
/// Rows deleted per transaction by the expiry sweep, so the writer is never held for long.
const SWEEP_BATCH: i64 = 5_000;
/// Accounts whose preferences are kept in memory.
const PREFS_CACHE: usize = 10_000;

pub struct Mam;

#[derive(Default)]
struct State {
    /// Archiving preferences by account (absent: not loaded yet).
    prefs: Mutex<HashMap<Jid, Arc<Prefs>>>,
}

#[async_trait]
impl Module for Mam {
    fn name(&self) -> &'static str {
        "mam"
    }

    fn migrations(&self) -> Vec<&'static Migration> {
        vec![&MIGRATION]
    }

    fn snapshot_names(&self, host: &Host) -> Vec<&'static str> {
        if host.settings().history.on() {
            vec!["mam"]
        } else {
            Vec::new()
        }
    }

    fn account_features(&self, host: &Host) -> Vec<&'static str> {
        if host.settings().history.on() {
            vec![ns::MAM, ns::MAM_EXTENDED, ns::SID, FULLTEXT]
        } else {
            Vec::new()
        }
    }

    fn iq_namespaces(&self) -> &'static [(&'static str, IqTarget)] {
        // Without a `to` an IQ is addressed to the server; MAM then means the sender's archive.
        &[(ns::MAM, IqTarget::Account), (ns::MAM, IqTarget::Server)]
    }

    fn start(&self, srv: &Arc<Server>) {
        let weak = Arc::downgrade(srv);
        let mut stop = srv.shutdown_signal();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(3600));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = stop.changed() => return,
                }
                let Some(srv) = weak.upgrade() else { return };
                for h in srv.hosts() {
                    sweep(&srv, &h).await;
                }
            }
        });
    }

    async fn handle_iq(&self, cx: &IqCtx<'_>) -> IqResult {
        // Only the account itself reads or changes its archive.
        let archive = match cx.to.node() {
            Some(_) if cx.from_self() => cx.to.to_bare(),
            Some(_) => return Err(StanzaError::forbidden().with_text("Only the account itself can read its message history.")),
            None => cx.local_sender().ok_or_else(StanzaError::service_unavailable)?,
        };
        if !cx.host.settings().history.on() {
            return Err(StanzaError::service_unavailable().with_text("Message history is turned off on this server."));
        }
        match (cx.payload.name(), cx.kind) {
            ("query", IqType::Get) => ok(Element::new("query", ns::MAM).child(query_form())),
            ("query", IqType::Set) => query(cx.srv, &archive, cx.iq, cx.from).await,
            ("metadata", IqType::Get) => ok(metadata(cx.srv, &archive).await?),
            ("prefs", IqType::Get) => ok(prefs(cx.srv, &archive).await.map_err(db_error)?.to_element()),
            ("prefs", IqType::Set) => {
                let p = Prefs::parse(cx.payload)?;
                save_prefs(cx.srv, &archive, &p).await.map_err(db_error)?;
                let el = p.to_element();
                cx.srv.ext::<State>().prefs.lock().insert(archive, Arc::new(p));
                ok(el)
            }
            _ => Err(StanzaError::feature_not_implemented()),
        }
    }

    async fn message_out(&self, cx: &StanzaCtx<'_>, msg: &mut Element) -> Flow {
        let me = cx.from.to_bare();
        let mine = me.to_string();
        strip_stanza_ids(msg, &mine);
        // To one's own account: archived once, on the way in.
        if cx.to.to_bare() == me || !cx.host.settings().history.on() || !archivable(msg) {
            return Flow::Continue;
        }
        if !wants(cx.srv, cx.host, &me, cx.to).await {
            return Flow::Continue;
        }
        if let Ok(id) = store_account(cx.srv, cx.host, &me, cx.to, msg).await {
            // Rides on the sent carbons; the router strips it before the message leaves.
            msg.append(stanza_id(&mine, &id));
        }
        Flow::Continue
    }

    async fn message_in(&self, cx: &StanzaCtx<'_>, msg: &mut Element) -> Flow {
        let me = cx.to.to_bare();
        let mine = me.to_string();
        // Nobody else may claim an id in this archive (XEP-0359 §5).
        strip_stanza_ids(msg, &mine);
        if msg.attr("type") == Some("groupchat") || !cx.host.settings().history.on() || !archivable(msg) {
            return Flow::Continue;
        }
        if cx.from.to_bare() != me && !wants(cx.srv, cx.host, &me, cx.from).await {
            return Flow::Continue;
        }
        if let Ok(id) = store_account(cx.srv, cx.host, &me, cx.from, msg).await {
            msg.append(stanza_id(&mine, &id));
        }
        Flow::Continue
    }

    async fn on_event(&self, srv: &Arc<Server>, ev: &Event) {
        match ev {
            Event::AccountDeleted { jid } => {
                srv.ext::<State>().prefs.lock().remove(&jid.to_bare());
                if let Err(e) = delete_archive(srv, &jid.to_bare()).await {
                    tracing::warn!(error = %e, "couldn't delete an archive");
                }
            }
            Event::SettingsChanged { domain } => {
                // Shorter retention (or history turned off) applies right away.
                if let Some(h) = srv.host(domain) {
                    let weak: Weak<Server> = Arc::downgrade(srv);
                    tokio::spawn(async move {
                        if let Some(srv) = weak.upgrade() {
                            sweep(&srv, &h).await;
                        }
                    });
                }
            }
            _ => {}
        }
    }
}

fn db_error(e: DbError) -> StanzaError {
    tracing::warn!(error = %e, "message archive storage");
    StanzaError::internal().with_text("The message history couldn't be read or saved right now.")
}

// ---------------------------------------------------------------- ids

const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// An archive id as clients see it: 13 base32 characters that sort like the number.
pub fn encode_id(id: i64) -> String {
    let v = id as u64;
    (0..13).rev().map(|i| ALPHABET[((v >> (i * 5)) & 31) as usize] as char).collect()
}

pub fn decode_id(s: &str) -> Option<i64> {
    if s.len() != 13 {
        return None;
    }
    let mut v: u64 = 0;
    for b in s.bytes() {
        let d = ALPHABET.iter().position(|&a| a == b.to_ascii_lowercase())? as u64;
        v = v.checked_mul(32)?.checked_add(d)?;
    }
    i64::try_from(v).ok()
}

fn id_floor(ms: i64) -> i64 {
    ms.max(0).saturating_mul(1 << SEQ_BITS)
}

fn id_ceil(ms: i64) -> i64 {
    id_floor(ms) | ((1 << SEQ_BITS) - 1)
}

fn id_stamp(id: i64) -> i64 {
    id >> SEQ_BITS
}

fn stanza_id(by: &str, id: &str) -> Element {
    Element::new("stanza-id", ns::SID).attr_set("by", by).attr_set("id", id)
}

/// Removes stanza ids claiming to be from `by` (only that archive may set them).
pub fn strip_stanza_ids(msg: &mut Element, by: &str) {
    msg.remove_children(|c| c.is("stanza-id", ns::SID) && c.attr("by").is_some_and(|b| b.eq_ignore_ascii_case(by)));
}

// ---------------------------------------------------------------- what gets archived

/// Messages with content people read or that change what they see (corrections, retractions,
/// reactions, read markers, calls); not chat states, receipts alone, errors or headlines.
pub fn archivable(msg: &Element) -> bool {
    if matches!(msg.attr("type"), Some("error" | "headline")) {
        return false;
    }
    if msg.has_child("no-store", ns::HINTS) || msg.has_child("no-permanent-store", ns::HINTS) {
        return false;
    }
    // Carbons and archive results are copies of messages archived elsewhere.
    if msg.child_ns(ns::CARBONS).is_some() || msg.has_child("result", ns::MAM) {
        return false;
    }
    msg.has_child("store", ns::HINTS)
        || msg.has_child("body", ns::CLIENT)
        || msg.has_child("subject", ns::CLIENT)
        || msg.has_child("encrypted", ns::OMEMO)
        || msg.has_child("encrypted", "urn:xmpp:omemo:2")
        || msg.has_child("openpgp", "urn:xmpp:openpgp:0")
        || msg.has_child("x", "jabber:x:encrypted")
        || msg.has_child("retract", ns::RETRACT)
        || msg.has_child("reactions", "urn:xmpp:reactions:0")
        || msg.has_child("apply-to", "urn:xmpp:fasten:0")
        || msg.has_child("x", "jabber:x:conference")
        || msg.get_child("x", ns::MUC_USER).is_some_and(|x| x.has_child("invite", ns::MUC_USER))
        || msg.child_ns("urn:xmpp:jingle-message:0").is_some()
        || ["displayed", "received", "acknowledged"].iter().any(|n| msg.has_child(n, ns::CHAT_MARKERS))
}

/// What's kept of a message: chat states, our own stanza id and whitespace go (the archive has
/// the id, and states mean nothing later).
fn for_storage(msg: &Element, by: &str) -> Element {
    let mut m = msg.clone();
    m.remove_children(|c| c.ns() == ns::CHAT_STATES || (c.is("stanza-id", ns::SID) && c.attr("by") == Some(by)));
    m.strip_whitespace();
    m
}

/// Text for the full-text index: plain bodies only (an encrypted message's body is a fallback).
fn searchable(msg: &Element) -> Option<String> {
    if msg.has_child("encrypted", ns::OMEMO)
        || msg.has_child("encrypted", "urn:xmpp:omemo:2")
        || msg.has_child("openpgp", "urn:xmpp:openpgp:0")
    {
        return None;
    }
    let mut b = msg.child_text("body", ns::CLIENT)?;
    if b.trim().is_empty() {
        return None;
    }
    if b.len() > MAX_INDEXED {
        let mut cut = MAX_INDEXED;
        while !b.is_char_boundary(cut) {
            cut -= 1;
        }
        b.truncate(cut);
    }
    Some(b)
}

// ---------------------------------------------------------------- storage

/// Archives `msg` in `archive` (a bare account JID or a room JID) and returns its stanza id.
/// `with` is the other party (the contact, or the occupant's real/room JID). Refused when the
/// archive isn't on this server or its domain keeps no history.
pub async fn store(srv: &Arc<Server>, archive: &Jid, with: &Jid, msg: &Element) -> Result<String, StanzaError> {
    let archive = archive.to_bare();
    let (host, user) = match srv.host(archive.domain()) {
        Some(h) => (h, archive.node().map(str::to_string)),
        None => (srv.component_host(archive.domain()).ok_or_else(StanzaError::item_not_found)?, None),
    };
    if !host.settings().history.on() {
        return Err(StanzaError::service_unavailable().with_text("Message history is turned off on this server."));
    }
    let id = insert(srv, &host.domain, user, &archive, with, msg).await.map_err(db_error)?;
    Ok(encode_id(id))
}

async fn store_account(srv: &Arc<Server>, host: &Host, me: &Jid, with: &Jid, msg: &Element) -> Result<String, ()> {
    match insert(srv, &host.domain, me.node().map(str::to_string), me, with, msg).await {
        Ok(id) => Ok(encode_id(id)),
        Err(e) => {
            tracing::warn!(error = %e, archive = %me, "couldn't archive a message");
            Err(())
        }
    }
}

async fn insert(srv: &Server, host: &str, user: Option<String>, archive: &Jid, with: &Jid, msg: &Element) -> Result<i64, DbError> {
    let jid = archive.to_string();
    let stored = for_storage(msg, &jid);
    let text = searchable(&stored);
    // Packing is a few microseconds; done here so the writer lock is only held for the insert.
    let xml = codec::pack(&stored);
    let (host, with_bare, with_res) = (host.to_string(), with.bare_str(), with.resource().map(str::to_string));
    let now = quark_core::time::now_ms();
    srv.db
        .write(move |t| {
            let aid: Option<i64> =
                t.prepare_cached("SELECT id FROM mam_archives WHERE jid = ?1")?.query_row([&jid], |r| r.get(0)).optional()?;
            let aid = match aid {
                Some(a) => a,
                None => t
                    .prepare_cached("INSERT INTO mam_archives (jid, host, user) VALUES (?1, ?2, ?3) RETURNING id")?
                    .query_row(params![jid, host, user], |r| r.get(0))?,
            };
            let last: Option<i64> = t.prepare_cached("SELECT max(id) FROM mam")?.query_row([], |r| r.get(0))?;
            let id = id_floor(now).max(last.map_or(0, |l| l + 1));
            t.prepare_cached("INSERT INTO mam (id, archive, with_bare, with_res, indexed, xml) VALUES (?1, ?2, ?3, ?4, ?5, ?6)")?
                .execute(params![id, aid, with_bare, with_res, text.is_some(), xml])?;
            if let Some(text) = text {
                t.prepare_cached("INSERT INTO mam_fts (rowid, body) VALUES (?1, ?2)")?.execute(params![id, text])?;
            }
            Ok(id)
        })
        .await
}

/// Deletes an archive (account or room gone).
pub async fn delete_archive(srv: &Arc<Server>, archive: &Jid) -> Result<(), StanzaError> {
    let jid = archive.to_bare().to_string();
    srv.db.write(move |t| t.execute("DELETE FROM mam_archives WHERE jid = ?1", [jid])).await.map_err(db_error)?;
    Ok(())
}

/// Drops messages older than the domain keeps them (everything when history is off), a batch
/// per transaction.
async fn sweep(srv: &Server, host: &Host) {
    let Some(keep) = host.settings().history.keep_ms() else { return };
    let cutoff = id_floor(quark_core::time::now_ms() - keep);
    let mut total = 0usize;
    loop {
        let h = host.domain.clone();
        let r = srv
            .db
            .write(move |t| {
                t.prepare_cached(
                    "DELETE FROM mam WHERE id IN (SELECT m.id FROM mam_archives a JOIN mam m ON m.archive = a.id
                     WHERE a.host = ?1 AND m.id < ?2 LIMIT ?3)",
                )?
                .execute(params![h, cutoff, SWEEP_BATCH])
            })
            .await;
        match r {
            Ok(n) => {
                total += n;
                if (n as i64) < SWEEP_BATCH {
                    break;
                }
                tokio::task::yield_now().await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "message history expiry failed");
                return;
            }
        }
    }
    if total > 0 {
        tracing::debug!(host = %host.domain, removed = total, "expired archived messages");
    }
}

/// Archived messages by stanza id, oldest first (evidence for spam reports). Unknown ids are
/// skipped.
pub async fn fetch(srv: &Server, archive: &Jid, ids: &[String]) -> Vec<(String, Element)> {
    let ids: Vec<i64> = ids.iter().filter_map(|i| decode_id(i)).take(MAX_IDS).collect();
    if ids.is_empty() {
        return Vec::new();
    }
    let jid = archive.to_bare().to_string();
    let r = srv
        .db
        .read(move |c| {
            let mut st =
                c.prepare_cached("SELECT m.id, m.xml FROM mam m JOIN mam_archives a ON a.id = m.archive WHERE a.jid = ?1 AND m.id = ?2")?;
            let mut out = Vec::new();
            for id in ids {
                if let Some(blob) = st.query_row(params![jid, id], |r| r.get::<_, Vec<u8>>(1)).optional()? {
                    if let Some(el) = codec::unpack(&blob) {
                        out.push((encode_id(id), el));
                    }
                }
            }
            out.sort_by(|a, b| a.0.cmp(&b.0));
            Ok(out)
        })
        .await;
    r.unwrap_or_else(|e| {
        tracing::warn!(error = %e, "couldn't read archived messages");
        Vec::new()
    })
}

// ---------------------------------------------------------------- preferences (XEP-0441)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Always,
    Roster,
    Never,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Always => "always",
            Mode::Roster => "roster",
            Mode::Never => "never",
        }
    }
    fn parse(s: &str) -> Option<Mode> {
        match s {
            "always" => Some(Mode::Always),
            "roster" => Some(Mode::Roster),
            "never" => Some(Mode::Never),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefs {
    pub mode: Mode,
    pub always: HashSet<String>,
    pub never: HashSet<String>,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs { mode: Mode::Always, always: HashSet::new(), never: HashSet::new() }
    }
}

impl Prefs {
    fn parse(el: &Element) -> Result<Prefs, StanzaError> {
        let mode = Mode::parse(el.attr("default").unwrap_or_default())
            .ok_or_else(|| StanzaError::bad_request().with_text("The default must be always, roster or never."))?;
        let list = |name: &str| -> Result<HashSet<String>, StanzaError> {
            let mut out = HashSet::new();
            for j in el.get_child(name, ns::MAM).into_iter().flat_map(|l| l.children().filter(|c| c.is("jid", ns::MAM))) {
                let j = Jid::parse(j.text_content().trim()).map_err(|_| StanzaError::new(Condition::JidMalformed))?;
                out.insert(j.to_string());
            }
            if out.len() > MAX_PREF_JIDS {
                return Err(StanzaError::new(Condition::NotAcceptable).with_text("That list of addresses is too long."));
            }
            Ok(out)
        };
        let (always, never) = (list("always")?, list("never")?);
        Ok(Prefs { mode, always, never })
    }

    fn to_element(&self) -> Element {
        let list = |name: &str, set: &HashSet<String>| {
            let mut v: Vec<&String> = set.iter().collect();
            v.sort();
            Element::new(name, ns::MAM).children_from(v.into_iter().map(|j| Element::new("jid", ns::MAM).text(j.clone())))
        };
        Element::new("prefs", ns::MAM)
            .attr_set("default", self.mode.as_str())
            .child(list("always", &self.always))
            .child(list("never", &self.never))
    }

    /// Some(decision) from the lists, None to fall back on the default. A listed bare JID
    /// matches every resource; `never` wins when both match, as the more private choice.
    fn listed(&self, with: &Jid) -> Option<bool> {
        let hit = |set: &HashSet<String>| {
            !set.is_empty() && (set.contains(&with.bare_str()) || (with.is_full() && set.contains(&with.to_string())))
        };
        if hit(&self.never) {
            Some(false)
        } else if hit(&self.always) {
            Some(true)
        } else {
            None
        }
    }
}

async fn prefs(srv: &Arc<Server>, account: &Jid) -> Result<Arc<Prefs>, DbError> {
    let st = srv.ext::<State>();
    if let Some(p) = st.prefs.lock().get(account) {
        return Ok(p.clone());
    }
    let (h, u) = (account.domain().to_string(), account.node().unwrap_or_default().to_string());
    let row: Option<(String, String, String)> = srv
        .db
        .read(move |c| {
            c.prepare_cached("SELECT mode, always, never FROM mam_prefs WHERE host = ?1 AND user = ?2")?
                .query_row(params![h, u], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .optional()
        })
        .await?;
    let p = match row {
        Some((m, a, n)) => Prefs {
            mode: Mode::parse(&m).unwrap_or(Mode::Always),
            always: serde_json::from_str(&a).unwrap_or_default(),
            never: serde_json::from_str(&n).unwrap_or_default(),
        },
        None => Prefs::default(),
    };
    let p = Arc::new(p);
    let mut cache = st.prefs.lock();
    if cache.len() >= PREFS_CACHE {
        cache.clear();
    }
    // A concurrent `prefs set` wins over what we just read.
    Ok(cache.entry(account.clone()).or_insert(p).clone())
}

async fn save_prefs(srv: &Server, account: &Jid, p: &Prefs) -> Result<(), DbError> {
    let (h, u) = (account.domain().to_string(), account.node().unwrap_or_default().to_string());
    let (m, a, n) = (
        p.mode.as_str(),
        serde_json::to_string(&p.always).unwrap_or_else(|_| "[]".into()),
        serde_json::to_string(&p.never).unwrap_or_else(|_| "[]".into()),
    );
    srv.db
        .write(move |t| {
            t.execute(
                "INSERT INTO mam_prefs (host, user, mode, always, never) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(host, user) DO UPDATE SET mode = excluded.mode, always = excluded.always, never = excluded.never",
                params![h, u, m, a, n],
            )
        })
        .await
        .map(|_| ())
}

/// Whether the account's preferences archive messages with `with`.
async fn wants(srv: &Arc<Server>, host: &Host, me: &Jid, with: &Jid) -> bool {
    let p = match prefs(srv, me).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "couldn't read archiving preferences");
            return true;
        }
    };
    if let Some(d) = p.listed(with) {
        return d;
    }
    match p.mode {
        Mode::Always => true,
        Mode::Never => false,
        Mode::Roster => {
            let user = me.node().unwrap_or_default();
            matches!(super::roster::item(srv, &host.domain, user, &with.to_bare()).await, Ok(Some(it)) if it.visible)
        }
    }
}

// ---------------------------------------------------------------- queries

/// The query form clients fetch to learn the supported filters.
pub fn query_form() -> Element {
    let field = |var: &str, kind: &str| Element::new("field", ns::DATA_FORMS).attr_set("var", var).attr_set("type", kind);
    Element::new("x", ns::DATA_FORMS)
        .attr_set("type", "form")
        .child(field("FORM_TYPE", "hidden").text_child("value", ns::DATA_FORMS, ns::MAM))
        .child(field("with", "jid-single"))
        .child(field("start", "text-single"))
        .child(field("end", "text-single"))
        .child(field("before-id", "text-single"))
        .child(field("after-id", "text-single"))
        .child(
            field("ids", "list-multi").child(
                Element::new("validate", XDATA_VALIDATE).attr_set("datatype", "xs:string").child(Element::new("open", XDATA_VALIDATE)),
            ),
        )
        .child(field(FULLTEXT_FIELD, "text-single"))
}

/// A parsed query: filters, then the page asked for.
#[derive(Debug, Default, PartialEq)]
struct Query {
    with: Option<Jid>,
    /// Inclusive id bounds from start/end/after-id/before-id.
    lo: Option<i64>,
    hi: Option<i64>,
    /// Ids that must exist in the archive (after-id, before-id, RSM after/before).
    must_exist: Vec<i64>,
    ids: Vec<i64>,
    fulltext: Option<String>,
    max: usize,
    after: Option<i64>,
    /// Some(None): the last page (`<before/>`).
    before: Option<Option<i64>>,
    index: Option<usize>,
    flip: bool,
}

fn bad(text: &str) -> StanzaError {
    StanzaError::bad_request().with_text(text)
}

fn parse_id(s: &str) -> Result<i64, StanzaError> {
    decode_id(s.trim()).ok_or_else(|| StanzaError::item_not_found().with_text("There's no message with that id in the history."))
}

fn parse_query(q: &Element) -> Result<Query, StanzaError> {
    let mut out = Query { max: DEFAULT_PAGE, ..Default::default() };
    if let Some(x) = q.get_child("x", ns::DATA_FORMS) {
        for f in x.children().filter(|c| c.is("field", ns::DATA_FORMS)) {
            let var = f.attr("var").unwrap_or_default();
            let values: Vec<String> = f
                .children()
                .filter(|c| c.is("value", ns::DATA_FORMS))
                .map(|v| v.text_content().trim().to_string())
                .filter(|v| !v.is_empty())
                .collect();
            let one = values.first().map(String::as_str);
            match var {
                "FORM_TYPE" => {
                    if one.is_some_and(|t| t != ns::MAM) {
                        return Err(bad("That isn't a message history query form."));
                    }
                }
                "with" => {
                    if let Some(v) = one {
                        out.with = Some(Jid::parse(v).map_err(|_| StanzaError::new(Condition::JidMalformed))?);
                    }
                }
                "start" | "end" => {
                    if let Some(v) = one {
                        let ms = quark_core::time::parse_xep82(v).ok_or_else(|| bad("That isn't a valid time."))?;
                        if var == "start" {
                            out.lo = Some(out.lo.map_or(id_floor(ms), |l| l.max(id_floor(ms))));
                        } else {
                            out.hi = Some(out.hi.map_or(id_ceil(ms), |h| h.min(id_ceil(ms))));
                        }
                    }
                }
                "after-id" | "before-id" => {
                    if let Some(v) = one {
                        let id = parse_id(v)?;
                        out.must_exist.push(id);
                        if var == "after-id" {
                            out.lo = Some(out.lo.map_or(id + 1, |l| l.max(id + 1)));
                        } else {
                            out.hi = Some(out.hi.map_or(id - 1, |h| h.min(id - 1)));
                        }
                    }
                }
                "ids" => {
                    if values.len() > MAX_IDS {
                        return Err(StanzaError::new(Condition::PolicyViolation).with_text("Too many ids in one query."));
                    }
                    // Unknown ids simply match nothing.
                    out.ids = values.iter().map(|v| decode_id(v).unwrap_or(-1)).collect();
                    if out.ids.is_empty() {
                        out.ids.push(-1);
                    }
                }
                FULLTEXT_FIELD => out.fulltext = one.map(fts_query).transpose()?,
                // We never put group chat messages in account archives, so there's nothing to include.
                "include-groupchat" => {}
                other => {
                    return Err(StanzaError::feature_not_implemented().with_text(format!("The history can't be filtered by \"{other}\".")))
                }
            }
        }
    }
    if let Some(set) = q.get_child("set", ns::RSM) {
        if let Some(m) = set.child_text("max", ns::RSM) {
            out.max = m.trim().parse::<usize>().map_err(|_| bad("The page size must be a number."))?.min(MAX_PAGE);
        }
        if let Some(a) = set.child_text("after", ns::RSM) {
            let id = parse_id(&a)?;
            out.must_exist.push(id);
            out.after = Some(id);
        }
        if let Some(b) = set.get_child("before", ns::RSM) {
            let t = b.text_content();
            out.before = Some(if t.trim().is_empty() {
                None
            } else {
                let id = parse_id(&t)?;
                out.must_exist.push(id);
                Some(id)
            });
        }
        if let Some(i) = set.child_text("index", ns::RSM) {
            out.index = Some(i.trim().parse::<usize>().map_err(|_| bad("The page index must be a number."))?);
        }
        if out.after.is_some() && out.before.is_some() {
            return Err(bad("A page can't be both before and after an id."));
        }
    }
    out.flip = q.has_child("flip-page", ns::MAM);
    Ok(out)
}

/// Turns what someone typed into an FTS5 query: each word must appear, the last one may be the
/// start of a word. Quoting every term keeps FTS5 operators out of people's hands.
fn fts_query(s: &str) -> Result<String, StanzaError> {
    let terms: Vec<&str> = s.split_whitespace().take(MAX_TERMS).collect();
    if terms.is_empty() {
        return Err(bad("Type something to search for."));
    }
    let mut q = String::new();
    for (i, t) in terms.iter().enumerate() {
        let t: String = t.chars().take(MAX_TERM).collect();
        if i > 0 {
            q.push(' ');
        }
        q.push('"');
        q.push_str(&t.replace('"', "\"\""));
        q.push('"');
        if i == terms.len() - 1 {
            q.push('*');
        }
    }
    Ok(q)
}

struct Page {
    items: Vec<(i64, Element)>,
    count: i64,
    complete: bool,
}

/// Why a query couldn't run, decided inside the database closure.
enum QueryError {
    Db(rusqlite::Error),
    UnknownId,
}

impl From<rusqlite::Error> for QueryError {
    fn from(e: rusqlite::Error) -> Self {
        QueryError::Db(e)
    }
}

async fn run(srv: &Server, archive: &Jid, q: Query) -> Result<Page, StanzaError> {
    let jid = archive.to_bare().to_string();
    let r = srv
        .db
        .read(move |c| {
            let aid: Option<i64> =
                c.prepare_cached("SELECT id FROM mam_archives WHERE jid = ?1")?.query_row([&jid], |r| r.get(0)).optional()?;
            Ok(run_sql(c, aid, &q))
        })
        .await
        .map_err(db_error)?;
    match r {
        Ok(p) => Ok(p),
        Err(QueryError::UnknownId) => Err(StanzaError::item_not_found().with_text("There's no message with that id in the history.")),
        Err(QueryError::Db(e)) => Err(db_error(DbError::Sqlite(e))),
    }
}

fn run_sql(c: &rusqlite::Connection, aid: Option<i64>, q: &Query) -> Result<Page, QueryError> {
    let Some(aid) = aid else {
        if q.must_exist.is_empty() {
            return Ok(Page { items: Vec::new(), count: 0, complete: true });
        }
        return Err(QueryError::UnknownId);
    };
    {
        let mut st = c.prepare_cached("SELECT 1 FROM mam WHERE id = ?1 AND archive = ?2")?;
        for id in &q.must_exist {
            if !st.exists(params![id, aid])? {
                return Err(QueryError::UnknownId);
            }
        }
    }
    // The filters, shared by the count and the page.
    let mut filter = String::from(" WHERE archive = ?");
    let mut args: Vec<Value> = vec![Value::Integer(aid)];
    if let Some(w) = &q.with {
        filter.push_str(" AND with_bare = ?");
        args.push(Value::Text(w.bare_str()));
        if let Some(r) = w.resource() {
            filter.push_str(" AND with_res = ?");
            args.push(Value::Text(r.to_string()));
        }
    }
    if let Some(lo) = q.lo {
        filter.push_str(" AND id >= ?");
        args.push(Value::Integer(lo));
    }
    if let Some(hi) = q.hi {
        filter.push_str(" AND id <= ?");
        args.push(Value::Integer(hi));
    }
    if !q.ids.is_empty() {
        filter.push_str(" AND id IN (");
        for (i, id) in q.ids.iter().enumerate() {
            filter.push_str(if i == 0 { "?" } else { ", ?" });
            args.push(Value::Integer(*id));
        }
        filter.push(')');
    }
    if let Some(f) = &q.fulltext {
        filter.push_str(" AND id IN (SELECT rowid FROM mam_fts WHERE mam_fts MATCH ?)");
        args.push(Value::Text(f.clone()));
    }
    let count: i64 =
        c.prepare_cached(&format!("SELECT count(*) FROM mam{filter}"))?.query_row(rusqlite::params_from_iter(args.iter()), |r| r.get(0))?;
    if q.max == 0 {
        return Ok(Page { items: Vec::new(), count, complete: count == 0 });
    }

    let mut sql = format!("SELECT id, xml FROM mam{filter}");
    let backward = q.before.is_some();
    if let Some(a) = q.after {
        sql.push_str(" AND id > ?");
        args.push(Value::Integer(a));
    }
    if let Some(Some(b)) = q.before {
        sql.push_str(" AND id < ?");
        args.push(Value::Integer(b));
    }
    sql.push_str(if backward { " ORDER BY id DESC" } else { " ORDER BY id ASC" });
    // One extra row tells whether there's more beyond this page.
    sql.push_str(" LIMIT ? OFFSET ?");
    args.push(Value::Integer(q.max as i64 + 1));
    args.push(Value::Integer(if backward { 0 } else { q.index.unwrap_or(0) as i64 }));
    let mut st = c.prepare_cached(&sql)?;
    let rows = st.query_map(rusqlite::params_from_iter(args.iter()), |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
    let mut items = Vec::with_capacity(q.max.min(64));
    let mut more = false;
    for row in rows {
        let (id, blob) = row?;
        if items.len() == q.max {
            more = true;
            break;
        }
        match codec::unpack(&blob) {
            Some(el) => items.push((id, el)),
            None => tracing::warn!(id, "skipping an archived message that can't be read"),
        }
    }
    if backward {
        items.reverse();
    }
    Ok(Page { items, count, complete: !more })
}

/// Answers a MAM query `iq` against `archive`: results are sent from `archive` to `to`, then the
/// final IQ result. Access control is the caller's job.
pub async fn query(srv: &Arc<Server>, archive: &Jid, iq: &Element, to: &Jid) -> Result<IqReply, StanzaError> {
    let q_el = iq.get_child("query", ns::MAM).ok_or_else(StanzaError::bad_request)?;
    let q = parse_query(q_el)?;
    let flip = q.flip;
    // The position of the first result is only known when the client paged by index.
    let index = q.index.filter(|_| q.after.is_none() && q.before.is_none());
    let page = run(srv, archive, q).await?;
    let queryid = q_el.attr("queryid");
    let from = archive.to_bare().to_string();
    let first = page.items.first().map(|(id, _)| encode_id(*id));
    let last = page.items.last().map(|(id, _)| encode_id(*id));
    let mut items = page.items;
    if flip {
        items.reverse();
    }
    // Straight to a local session keeps order without the routing pipeline; others are routed.
    let session = srv.sessions.get(to);
    for (id, m) in items {
        let r = Element::new("message", ns::CLIENT).attr_set("from", from.clone()).attr_set("to", to.to_string()).child(
            Element::new("result", ns::MAM)
                .attr_opt("queryid", queryid)
                .attr_set("id", encode_id(id))
                .child(Element::new("forwarded", ns::FORWARD).child(quark_core::stanza::delay(&from, id_stamp(id))).child(m)),
        );
        match &session {
            Some(s) => {
                s.send(r);
            }
            None => srv.route(r).await,
        }
    }
    let mut set = Element::new("set", ns::RSM);
    if let (Some(f), Some(l)) = (first, last) {
        set.append(Element::new("first", ns::RSM).text(f).attr_opt("index", index.map(|i| i.to_string())));
        set.append(Element::new("last", ns::RSM).text(l));
    }
    set.append(Element::new("count", ns::RSM).text(page.count.to_string()));
    let mut fin = Element::new("fin", ns::MAM).attr_opt("queryid", queryid);
    if page.complete {
        fin.set_attr("complete", "true");
    }
    let result = iq_result(iq).child(fin.child(set));
    match &session {
        Some(s) if result.attr("to") == Some(&s.jid.to_string()) => {
            s.send(result);
        }
        _ => srv.route(result).await,
    }
    Ok(IqReply::Handled)
}

/// The first and last message of an archive (`#extended` metadata).
pub async fn metadata(srv: &Server, archive: &Jid) -> Result<Element, StanzaError> {
    let jid = archive.to_bare().to_string();
    let ends: Option<(i64, i64)> = srv
        .db
        .read(move |c| {
            c.prepare_cached("SELECT min(m.id), max(m.id) FROM mam m JOIN mam_archives a ON a.id = m.archive WHERE a.jid = ?1")?
                .query_row([&jid], |r| Ok(r.get::<_, Option<i64>>(0)?.zip(r.get::<_, Option<i64>>(1)?)))
        })
        .await
        .map_err(db_error)?;
    let mut el = Element::new("metadata", ns::MAM);
    if let Some((a, b)) = ends {
        for (name, id) in [("start", a), ("end", b)] {
            el.append(
                Element::new(name, ns::MAM).attr_set("id", encode_id(id)).attr_set("timestamp", quark_core::time::xep82(id_stamp(id))),
            );
        }
    }
    Ok(el)
}

// ---------------------------------------------------------------- data forms

/// Small helpers for XEP-0004 forms, shared with other modules.
pub(crate) mod form {
    use quark_core::{ns, Element};

    /// The values of field `var`.
    pub fn values(x: &Element, var: &str) -> Vec<String> {
        x.children()
            .filter(|f| f.is("field", ns::DATA_FORMS) && f.attr("var") == Some(var))
            .flat_map(|f| f.children().filter(|v| v.is("value", ns::DATA_FORMS)).map(Element::text_content))
            .collect()
    }

    /// The first value of field `var`.
    pub fn value(x: &Element, var: &str) -> Option<String> {
        values(x, var).into_iter().next()
    }

    /// A field with one value.
    pub fn field(var: &str, value: &str) -> Element {
        Element::new("field", ns::DATA_FORMS).attr_set("var", var).text_child("value", ns::DATA_FORMS, value)
    }
}

// ---------------------------------------------------------------- storage format

/// How stanzas are stored: a format byte, then the XML either as is or as raw deflate primed
/// with [`DICTIONARY`]. The dictionary holds the text nearly every stanza repeats (namespaces,
/// attribute names), which deflate alone can't exploit in a few hundred bytes: a typical chat
/// message shrinks by more than half instead of by a third.
pub(crate) mod codec {
    use std::cell::RefCell;
    use std::sync::LazyLock;

    use miniz_oxide::deflate::core::{compress, create_comp_flags_from_zip_params, CompressorOxide, TDEFLFlush, TDEFLStatus};
    use quark_core::Element;

    const PLAIN: u8 = 0;
    const DEFLATE_V1: u8 = 1;
    /// Stored stanzas never get near this; it bounds what a corrupt row could expand to.
    const MAX_XML: usize = 4 << 20;

    /// Never change: stored rows depend on it. A new dictionary needs a new format byte.
    /// The most common text comes last, where back-references are shortest.
    const DICTIONARY: &[u8] = b"<encrypted xmlns='urn:xmpp:omemo:2'><header sid='<keys jid='<key kex='true' rid='</key></keys></header>\
<payload></payload></encrypted><encrypted xmlns='eu.siacs.conversations.axolotl'><header sid='<key prekey='true' rid='\
<iv></iv></header><payload></payload></encrypted><encryption xmlns='urn:xmpp:eme:0' namespace='eu.siacs.conversations.axolotl'/>\
<store xmlns='urn:xmpp:hints'/><replace xmlns='urn:xmpp:message-correct:0' id='<reactions xmlns='urn:xmpp:reactions:0' id='\
<reaction></reaction></reactions><retract xmlns='urn:xmpp:message-retract:1' id='<fallback xmlns='urn:xmpp:fallback:0' for='\
<reply xmlns='urn:xmpp:reply:0' to='<x xmlns='jabber:x:oob'><url>https://</url></x><propose xmlns='urn:xmpp:jingle-message:0' id='\
<description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'/><thread></thread><delay xmlns='urn:xmpp:delay' from=' stamp='\
<displayed xmlns='urn:xmpp:chat-markers:0' id='<received xmlns='urn:xmpp:receipts' id='<request xmlns='urn:xmpp:receipts'/>\
<markable xmlns='urn:xmpp:chat-markers:0'/><origin-id xmlns='urn:xmpp:sid:0' id='<message xmlns='jabber:client' from=' to=' \
type='chat' id='><body></body></message>";

    /// What a decoder feeds itself before a stored row: the dictionary as one uncompressed,
    /// non-final deflate block, so the row's back-references land in it.
    static PREFIX: LazyLock<Vec<u8>> = LazyLock::new(|| {
        let n = DICTIONARY.len() as u16;
        let mut p = vec![0u8];
        p.extend_from_slice(&n.to_le_bytes());
        p.extend_from_slice(&(!n).to_le_bytes());
        p.extend_from_slice(DICTIONARY);
        p
    });

    thread_local! {
        // A compressor is a few hundred KB of tables; one per thread, reset between uses.
        static COMPRESSOR: RefCell<Option<Box<CompressorOxide>>> = const { RefCell::new(None) };
    }

    pub fn pack(el: &Element) -> Vec<u8> {
        let xml = el.to_xml();
        let mut out = Vec::with_capacity(xml.len() / 2 + 16);
        match deflate(xml.as_bytes()) {
            Some(z) if z.len() < xml.len() => {
                out.push(DEFLATE_V1);
                out.extend_from_slice(&z);
            }
            _ => {
                out.push(PLAIN);
                out.extend_from_slice(xml.as_bytes());
            }
        }
        out
    }

    fn deflate(data: &[u8]) -> Option<Vec<u8>> {
        COMPRESSOR.with(|cell| {
            let mut slot = cell.borrow_mut();
            let c = slot.get_or_insert_with(|| Box::new(CompressorOxide::new(create_comp_flags_from_zip_params(6, -15, 0))));
            c.reset();
            // The dictionary's own output is thrown away; only its place in the window matters.
            let mut scratch = vec![0u8; DICTIONARY.len() + 64];
            let (st, used, _) = compress(c, DICTIONARY, &mut scratch, TDEFLFlush::Sync);
            if st != TDEFLStatus::Okay || used != DICTIONARY.len() {
                return None;
            }
            let mut out = vec![0u8; data.len() + data.len() / 8 + 64];
            let (st, used, n) = compress(c, data, &mut out, TDEFLFlush::Finish);
            if st != TDEFLStatus::Done || used != data.len() {
                return None;
            }
            out.truncate(n);
            Some(out)
        })
    }

    pub fn unpack(blob: &[u8]) -> Option<Element> {
        let (&kind, rest) = blob.split_first()?;
        let xml = match kind {
            PLAIN => std::str::from_utf8(rest).ok()?.to_string(),
            DEFLATE_V1 => {
                let mut input = Vec::with_capacity(PREFIX.len() + rest.len());
                input.extend_from_slice(&PREFIX);
                input.extend_from_slice(rest);
                let mut out = miniz_oxide::inflate::decompress_to_vec_with_limit(&input, DICTIONARY.len() + MAX_XML).ok()?;
                out.drain(..DICTIONARY.len());
                String::from_utf8(out).ok()?
            }
            _ => return None,
        };
        Element::parse(&xml).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn el(xml: &str) -> Element {
        Element::parse(xml).unwrap()
    }

    #[test]
    fn ids_round_trip_and_sort_like_numbers() {
        let a = id_floor(1_791_900_420_123);
        let b = a + 1;
        let c = id_floor(1_791_900_420_124);
        for id in [0, a, b, c, i64::MAX] {
            assert_eq!(decode_id(&encode_id(id)), Some(id));
        }
        assert!(encode_id(a) < encode_id(b) && encode_id(b) < encode_id(c));
        assert_eq!(id_stamp(b), 1_791_900_420_123);
        assert_eq!(decode_id("not-an-id"), None);
        assert_eq!(decode_id("zzzzzzzzzzzzz"), None);
        assert_eq!(decode_id(&encode_id(a).to_uppercase()), Some(a));
    }

    #[test]
    fn archives_content_but_not_states_errors_or_no_store() {
        assert!(archivable(&el("<message xmlns='jabber:client' type='chat'><body>hi</body></message>")));
        assert!(archivable(&el("<message xmlns='jabber:client'><encrypted xmlns='eu.siacs.conversations.axolotl'/></message>")));
        assert!(archivable(&el(
            "<message xmlns='jabber:client' type='chat'><retract xmlns='urn:xmpp:message-retract:1' id='x'/></message>"
        )));
        assert!(archivable(&el("<message xmlns='jabber:client' type='chat'><reactions xmlns='urn:xmpp:reactions:0' id='x'/></message>")));
        assert!(archivable(&el(
            "<message xmlns='jabber:client' type='chat'><displayed xmlns='urn:xmpp:chat-markers:0' id='x'/></message>"
        )));
        assert!(!archivable(&el(
            "<message xmlns='jabber:client' type='chat'><composing xmlns='http://jabber.org/protocol/chatstates'/></message>"
        )));
        assert!(!archivable(&el("<message xmlns='jabber:client' type='error'><body>x</body></message>")));
        assert!(!archivable(&el("<message xmlns='jabber:client' type='chat'><body>x</body><no-store xmlns='urn:xmpp:hints'/></message>")));
        assert!(!archivable(&el("<message xmlns='jabber:client' type='headline'><body>x</body></message>")));
        assert!(!archivable(&el(
            "<message xmlns='jabber:client'><received xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'/></received></message>"
        )));
    }

    #[test]
    fn spoofed_stanza_ids_are_removed_but_others_kept() {
        let mut m = el("<message xmlns='jabber:client'><stanza-id xmlns='urn:xmpp:sid:0' by='a@b' id='1'/><stanza-id xmlns='urn:xmpp:sid:0' by='room@c' id='2'/></message>");
        strip_stanza_ids(&mut m, "a@b");
        assert_eq!(m.children().count(), 1);
        assert_eq!(m.first_child().and_then(|c| c.attr("by")), Some("room@c"));
    }

    #[test]
    fn storage_drops_chat_states_and_round_trips() {
        let m = el("<message xmlns='jabber:client' from='a@b/c' to='d@e' type='chat' id='x1'>\n <body>Hello &amp; welcome</body><active xmlns='http://jabber.org/protocol/chatstates'/><origin-id xmlns='urn:xmpp:sid:0' id='x1'/></message>");
        let s = for_storage(&m, "a@b");
        assert!(!s.has_child("active", ns::CHAT_STATES));
        let packed = codec::pack(&s);
        assert_eq!(codec::unpack(&packed), Some(s.clone()));
        assert!(packed.len() < s.to_xml().len(), "{} vs {}", packed.len(), s.to_xml().len());
    }

    #[test]
    fn typical_message_compresses_well() {
        let m = el("<message xmlns='jabber:client' from='alice@quark.test/phone' to='bob@quark.test' type='chat' id='a8f3c9d2e1b04f77'><body>Hey, are we still on for dinner tonight? I can bring dessert.</body><origin-id xmlns='urn:xmpp:sid:0' id='4b1e6a2c-9f0d-4c3b-8a7e-1d2f3e4a5b6c'/><markable xmlns='urn:xmpp:chat-markers:0'/><request xmlns='urn:xmpp:receipts'/></message>");
        let packed = codec::pack(&m);
        assert!(packed.len() * 2 < m.to_xml().len(), "{} of {}", packed.len(), m.to_xml().len());
        assert_eq!(codec::unpack(&packed), Some(m));
    }

    #[test]
    fn incompressible_stanzas_are_stored_plain_and_garbage_is_refused() {
        // Too short for deflate to win, even with the dictionary.
        let m = el("<q/>");
        let packed = codec::pack(&m);
        assert_eq!(packed[0], 0);
        assert_eq!(codec::unpack(&packed), Some(m));
        assert_eq!(codec::unpack(&[1, 2, 3, 4]), None);
        assert_eq!(codec::unpack(&[9]), None);
        assert_eq!(codec::unpack(&[]), None);
    }

    #[test]
    fn search_text_skips_encrypted_fallbacks() {
        assert_eq!(
            searchable(&el("<message xmlns='jabber:client'><body>pizza tonight</body></message>")).as_deref(),
            Some("pizza tonight")
        );
        assert_eq!(
            searchable(&el("<message xmlns='jabber:client'><body>I sent you an OMEMO encrypted message</body><encrypted xmlns='eu.siacs.conversations.axolotl'/></message>")),
            None
        );
    }

    #[test]
    fn fulltext_terms_are_quoted() {
        assert_eq!(fts_query("pizza tonight").unwrap(), "\"pizza\" \"tonight\"*");
        assert_eq!(fts_query("a\"b OR").unwrap(), "\"a\"\"b\" \"OR\"*");
        assert!(fts_query("   ").is_err());
    }

    fn query_el(inner: &str) -> Element {
        el(&format!("<query xmlns='urn:xmpp:mam:2'>{inner}</query>"))
    }

    #[test]
    fn parses_filters_and_paging() {
        let q = parse_query(&query_el(
            "<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>urn:xmpp:mam:2</value></field>\
             <field var='with'><value>bob@b</value></field><field var='start'><value>1970-01-01T00:00:01Z</value></field></x>\
             <set xmlns='http://jabber.org/protocol/rsm'><max>500</max><before/></set><flip-page/>",
        ))
        .unwrap();
        assert_eq!(q.with, Some(Jid::parse("bob@b").unwrap()));
        assert_eq!(q.lo, Some(id_floor(1000)));
        assert_eq!(q.max, MAX_PAGE);
        assert_eq!(q.before, Some(None));
        assert!(q.flip);
    }

    #[test]
    fn refuses_unknown_fields_and_bad_values() {
        let unknown = parse_query(&query_el("<x xmlns='jabber:x:data'><field var='colour'><value>red</value></field></x>")).unwrap_err();
        assert_eq!(unknown.condition, Condition::FeatureNotImplemented);
        let time = parse_query(&query_el("<x xmlns='jabber:x:data'><field var='start'><value>yesterday</value></field></x>")).unwrap_err();
        assert_eq!(time.condition, Condition::BadRequest);
        let id = parse_query(&query_el("<set xmlns='http://jabber.org/protocol/rsm'><after>nope</after></set>")).unwrap_err();
        assert_eq!(id.condition, Condition::ItemNotFound);
        let max = parse_query(&query_el("<set xmlns='http://jabber.org/protocol/rsm'><max>-1</max></set>")).unwrap_err();
        assert_eq!(max.condition, Condition::BadRequest);
    }

    #[test]
    fn never_wins_and_bare_entries_cover_resources() {
        let p = Prefs::parse(&el(
            "<prefs xmlns='urn:xmpp:mam:2' default='roster'><always><jid>a@b</jid><jid>c@d/phone</jid></always><never><jid>a@b</jid></never></prefs>",
        ))
        .unwrap();
        assert_eq!(p.listed(&Jid::parse("a@b/x").unwrap()), Some(false));
        assert_eq!(p.listed(&Jid::parse("c@d/phone").unwrap()), Some(true));
        assert_eq!(p.listed(&Jid::parse("c@d/laptop").unwrap()), None);
        assert_eq!(Prefs::parse(&p.to_element()).unwrap(), p);
        assert!(Prefs::parse(&el("<prefs xmlns='urn:xmpp:mam:2' default='sometimes'/>")).is_err());
    }
}
