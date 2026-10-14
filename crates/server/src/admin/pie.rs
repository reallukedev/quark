//! `account.export` and `account.import`: accounts in the Portable Import/Export Format
//! (XEP-0227), the format Prosody (`prosodyctl mod_storage_xep0227`) and ejabberd
//! (`ejabberdctl export_piefxis`) read and write, so people can move servers.
//!
//! An account carries its SCRAM keys (never a password; Quark has none), roster, vCard, private
//! XML and offline messages, plus a Quark element with its role, state and age. Modules add
//! their own data through `Module::export_account` / `import_account` (PEP, archives).

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use quark_core::{ns, Element, Jid};
use serde::Deserialize;
use serde_json::{json, Value};

use super::ApiError;
use crate::accounts::{AccountError, Imported, Role, ScramHash, StoredKeys, HASHES};
use crate::db::{params, DbError};
use crate::modules::roster::{self, Subscription};
use crate::server::{Host, Server};

pub const PIE: &str = "urn:xmpp:pie:0";
const SCRAM: &str = "urn:xmpp:pie:0#scram";
/// Quark's own facts about an account (role, on or off, when it was made).
const QUARK: &str = "urn:quark:pie:0";
/// Nesting deeper than this isn't an export (and would be slow to take apart).
const MAX_DEPTH: usize = 64;
/// The most stored per account, as the modules themselves allow.
const MAX_VCARD: usize = 192 * 1024;
const MAX_PRIVATE: usize = 64 * 1024;
const MAX_OFFLINE: usize = 1_000;

type R = Result<Value, ApiError>;

// ------------------------------------------------------------------------------ export

#[derive(Deserialize)]
pub struct Export {
    #[serde(default)]
    host: Option<String>,
    /// Only these accounts (needs `host`).
    #[serde(default)]
    users: Option<Vec<String>>,
}

pub async fn export(srv: &Arc<Server>, a: Export) -> R {
    let hosts = match &a.host {
        Some(d) => {
            vec![srv.host(&d.trim().to_lowercase()).ok_or_else(|| ApiError::not_found(format!("This server doesn't serve {d}.")))?]
        }
        None if a.users.is_some() => return Err(ApiError::invalid("Choosing users needs a host too.")),
        None => srv.hosts(),
    };
    let mut root = Element::new("server-data", PIE);
    let mut count = 0usize;
    for h in hosts {
        let users: Vec<String> = match &a.users {
            Some(list) => {
                let mut out = Vec::new();
                for u in list {
                    let u = u.trim().to_lowercase();
                    if !srv.accounts.exists(&h.domain, &u).await? {
                        return Err(ApiError::not_found(format!("{u}@{} doesn't exist.", h.domain)));
                    }
                    out.push(u);
                }
                out
            }
            None => srv.accounts.list(&h.domain).await?.into_iter().map(|i| i.user).collect(),
        };
        let mut host_el = Element::new("host", PIE).attr_set("jid", h.domain.clone());
        for u in users {
            if let Some(el) = export_user(srv, &h, &u).await? {
                host_el.append(el);
                count += 1;
            }
        }
        root.append(host_el);
    }
    Ok(json!({ "xml": format!("<?xml version='1.0' encoding='UTF-8'?>\n{}", root.to_xml()), "accounts": count }))
}

async fn export_user(srv: &Arc<Server>, h: &Arc<Host>, user: &str) -> Result<Option<Element>, ApiError> {
    let (Some(info), Some(keys)) = (srv.accounts.info(&h.domain, user).await?, srv.accounts.keys(&h.domain, user).await?) else {
        return Ok(None);
    };
    let mut el = Element::new("user", PIE).attr_set("name", user);
    for (hash, pair) in HASHES.iter().zip(&keys.keys) {
        let Some((stored, server)) = pair else { continue };
        el.append(
            Element::new("scram-credentials", SCRAM)
                .attr_set("mechanism", hash.mechanism())
                .text_child("iter-count", SCRAM, keys.iterations.to_string())
                .text_child("salt", SCRAM, B64.encode(&keys.salt))
                .text_child("server-key", SCRAM, B64.encode(server))
                .text_child("stored-key", SCRAM, B64.encode(stored)),
        );
    }
    el.append(
        Element::new("account", QUARK)
            .attr_set("role", info.role.as_str())
            .attr_set("enabled", info.enabled.to_string())
            .attr_set("created", info.created.to_string()),
    );

    let items: Vec<Element> =
        roster::items(srv, &h.domain, user).await?.iter().filter(|i| i.visible).map(roster::Item::to_element).collect();
    if !items.is_empty() {
        el.append(Element::new("query", ns::ROSTER).children_from(items));
    }

    let (d, u) = (h.domain.clone(), user.to_string());
    let (vcard, private, offline) = srv
        .db
        .read(move |c| {
            use crate::db::OptionalExtension;
            let vcard: Option<String> =
                c.query_row("SELECT xml FROM vcards WHERE host = ?1 AND user = ?2", params![d, u], |r| r.get(0)).optional()?;
            let mut st = c.prepare_cached("SELECT xml FROM private_xml WHERE host = ?1 AND user = ?2 ORDER BY ns, name")?;
            let private: Vec<String> = st.query_map(params![d, u], |r| r.get(0))?.collect::<Result<_, _>>()?;
            let mut st = c.prepare_cached("SELECT stamp, xml FROM offline WHERE host = ?1 AND user = ?2 ORDER BY id")?;
            let offline: Vec<(i64, String)> = st.query_map(params![d, u], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
            Ok((vcard, private, offline))
        })
        .await?;
    if let Some(v) = vcard.and_then(|x| Element::parse(&x).ok()) {
        el.append(v);
    }
    let private: Vec<Element> = private.iter().filter_map(|x| Element::parse(x).ok()).collect();
    if !private.is_empty() {
        el.append(Element::new("query", ns::PRIVATE).children_from(private));
    }
    let offline: Vec<Element> = offline
        .into_iter()
        .filter_map(|(stamp, x)| {
            let mut m = Element::parse(&x).ok()?;
            if !m.has_child("delay", ns::DELAY) {
                m.append(quark_core::stanza::delay(&h.domain, stamp));
            }
            Some(m)
        })
        .collect();
    if !offline.is_empty() {
        el.append(Element::new("offline-messages", PIE).children_from(offline));
    }

    for m in &srv.modules {
        for child in m.export_account(srv, h, user).await? {
            el.append(child);
        }
    }
    Ok(Some(el))
}

// ------------------------------------------------------------------------------ import

#[derive(Deserialize)]
pub struct Import {
    xml: String,
    /// Only import this domain's accounts.
    #[serde(default)]
    host: Option<String>,
}

pub async fn import(srv: &Arc<Server>, a: Import) -> R {
    let doc = parse_document(&a.xml).map_err(ApiError::invalid)?;
    let only = a.host.as_deref().map(|h| h.trim().to_lowercase());
    let mut created = Vec::new();
    let mut skipped = Vec::new();
    let mut notes = Vec::new();
    for host_el in doc.children().filter(|c| c.is("host", PIE)) {
        let domain = host_el.attr("jid").unwrap_or_default().trim().to_lowercase();
        if only.as_ref().is_some_and(|o| *o != domain) {
            continue;
        }
        let users = host_el.children().filter(|c| c.is("user", PIE));
        let Some(h) = srv.host(&domain) else {
            for u in users {
                skipped.push(json!({ "jid": format!("{}@{domain}", u.attr("name").unwrap_or_default()), "reason": format!("This server doesn't serve {domain}.") }));
            }
            continue;
        };
        for u in users {
            let name = u.attr("name").unwrap_or_default().trim().to_lowercase();
            let jid = format!("{name}@{domain}");
            match import_user(srv, &h, &name, u).await {
                Ok(mut n) => {
                    created.push(jid);
                    notes.append(&mut n);
                }
                Err(Skip(reason)) => skipped.push(json!({ "jid": jid, "reason": reason })),
            }
        }
    }
    if created.is_empty() && skipped.is_empty() {
        return Err(ApiError::invalid(match &only {
            Some(d) => format!("There are no accounts for {d} in that export."),
            None => "There are no accounts in that export.".into(),
        }));
    }
    Ok(json!({ "created": created, "skipped": skipped, "notes": notes }))
}

/// Why an account wasn't imported, for people.
struct Skip(String);

impl From<DbError> for Skip {
    fn from(e: DbError) -> Self {
        tracing::warn!(error = %e, "account import failed");
        Skip("Something went wrong on the server. Its log has the details.".into())
    }
}

/// Checks the shape and parses: `<server-data xmlns='urn:xmpp:pie:0'>` with an optional XML
/// declaration in front.
fn parse_document(xml: &str) -> Result<Element, String> {
    let mut text = xml.trim_start_matches('\u{feff}').trim();
    if text.starts_with("<?xml") {
        text = text.find("?>").map(|i| text[i + 2..].trim_start()).unwrap_or(text);
    }
    if depth(text) > MAX_DEPTH {
        return Err("That export nests elements too deeply.".into());
    }
    let doc = Element::parse(text).map_err(|e| format!("That isn't readable XML: {e}"))?;
    if !doc.is("server-data", PIE) {
        return Err("That isn't an account export: it should start with <server-data xmlns='urn:xmpp:pie:0'>.".into());
    }
    Ok(doc)
}

/// The deepest element nesting, roughly (tags inside comments and CDATA count too, which only
/// errs on the safe side).
fn depth(text: &str) -> usize {
    let b = text.as_bytes();
    let (mut d, mut max) = (0usize, 0usize);
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'<' {
            match b.get(i + 1) {
                Some(b'/') => d = d.saturating_sub(1),
                Some(b'?' | b'!') => {}
                _ => {
                    let end = b[i..].iter().position(|&c| c == b'>').map(|p| i + p);
                    if !end.is_some_and(|e| e > i && b[e - 1] == b'/') {
                        d += 1;
                        max = max.max(d);
                    }
                }
            }
        }
        i += 1;
    }
    max
}

async fn import_user(srv: &Arc<Server>, h: &Arc<Host>, user: &str, el: &Element) -> Result<Vec<String>, Skip> {
    let jid = format!("{user}@{}", h.domain);
    if !crate::accounts::valid_username(user) {
        return Err(Skip(format!("\"{user}\" isn't a username Quark can use.")));
    }
    if srv.accounts.exists(&h.domain, user).await? {
        return Err(Skip("There's already an account with that name.".into()));
    }
    let mut notes = Vec::new();
    let keys = match credentials(el) {
        Ok(Some(k)) => k,
        Ok(None) => {
            let pw = match el.attr("password").filter(|p| !p.is_empty()) {
                Some(p) => p.to_string(),
                None => {
                    notes.push(format!("{jid} came without a password, so it got a random one. Send them a password reset invite."));
                    let mut raw = [0u8; 24];
                    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut raw);
                    hex::encode(raw)
                }
            };
            tokio::task::spawn_blocking(move || crate::accounts::keys_for(&pw)).await.map_err(|e| DbError::Join(e.to_string()))?
        }
        Err(why) => return Err(Skip(why)),
    };
    if keys.keys[1].is_none() {
        notes.push(format!(
            "{jid} only has {} keys, so apps that use stronger sign-in fail until it signs in with its password once (PLAIN) or gets a new one.",
            HASHES.iter().zip(&keys.keys).filter(|(_, k)| k.is_some()).map(|(h, _)| h.mechanism()).collect::<Vec<_>>().join(", "),
        ));
    }
    let facts = el.get_child("account", QUARK);
    let role = match facts.and_then(|f| f.attr("role")) {
        Some("admin") => Role::Admin,
        _ => Role::Member,
    };
    let imported = Imported {
        role,
        enabled: facts.and_then(|f| f.attr("enabled")) != Some("false"),
        created: facts.and_then(|f| f.attr("created")).and_then(|c| c.parse().ok()),
    };
    match srv.accounts.create_with_keys(&h.domain, user, &keys, &imported).await {
        Ok(()) => {}
        Err(AccountError::Exists(_)) => return Err(Skip("There's already an account with that name.".into())),
        Err(AccountError::Invalid(t)) | Err(AccountError::NotFound(t)) => return Err(Skip(t)),
        Err(AccountError::Db(e)) => return Err(e.into()),
    }
    h.set_role_cache(user, role);

    // From here on the account exists: problems become notes, not a skipped account.
    let mut part = |what: &str, r: Result<(), DbError>| {
        if let Err(e) = r {
            tracing::warn!(error = %e, %jid, what, "part of an account import failed");
            notes.push(format!("{jid}: the {what} couldn't be imported (the server log has the details)."));
        }
    };
    if let Some(q) = el.get_child("query", ns::ROSTER) {
        part("contacts", import_roster(srv, h, user, q).await);
    }
    if let Some(v) = el.get_child("vCard", ns::VCARD) {
        part("profile", import_vcard(srv, h, user, v).await);
    }
    if let Some(q) = el.get_child("query", ns::PRIVATE) {
        part("private storage", import_private(srv, h, user, q).await);
    }
    if let Some(o) = el.get_child("offline-messages", PIE) {
        part("waiting messages", import_offline(srv, h, user, o).await);
    }
    for m in &srv.modules {
        match m.import_account(srv, h, user, el).await {
            Ok(mut n) => notes.append(&mut n),
            Err(e) => {
                tracing::warn!(error = %e, %jid, module = m.name(), "part of an account import failed");
                notes.push(format!("{jid}: the {} data couldn't be imported (the server log has the details).", m.name()));
            }
        }
    }
    Ok(notes)
}

/// The SCRAM keys in `<scram-credentials/>` elements, all sharing one salt and iteration count
/// (the strongest hash's; others with a different salt can't be kept). None when there are none.
fn credentials(el: &Element) -> Result<Option<StoredKeys>, String> {
    // (hash index, salt, iterations, StoredKey, ServerKey)
    type Found = (usize, Vec<u8>, u32, Vec<u8>, Vec<u8>);
    let mut found: Vec<Found> = Vec::new();
    for c in el.children().filter(|c| c.is("scram-credentials", SCRAM)) {
        let mech = c.attr("mechanism").unwrap_or_default().to_ascii_uppercase();
        let Some(i) = HASHES.iter().position(|h| h.mechanism() == mech) else { continue };
        let field = |n: &str| c.child_text(n, SCRAM).map(|t| t.trim().to_string()).unwrap_or_default();
        let b64 = |n: &str| B64.decode(field(n)).map_err(|_| format!("The {mech} {n} isn't base64."));
        let iterations: u32 = field("iter-count").parse().map_err(|_| format!("The {mech} iter-count isn't a number."))?;
        let (salt, server, stored) = (b64("salt")?, b64("server-key")?, b64("stored-key")?);
        let len = key_len(HASHES[i]);
        if salt.is_empty() || iterations == 0 || server.len() != len || stored.len() != len {
            return Err(format!("The {mech} keys are incomplete."));
        }
        if !crate::accounts::IMPORT_ITERATIONS.contains(&iterations) {
            return Err(crate::accounts::iterations_refused(iterations));
        }
        found.push((i, salt, iterations, stored, server));
    }
    // Strongest first: SHA-512, SHA-256, SHA-1.
    found.sort_by_key(|f| std::cmp::Reverse(f.0));
    let Some((_, salt, iterations, ..)) = found.first().cloned() else { return Ok(None) };
    let mut keys: [Option<(Vec<u8>, Vec<u8>)>; 3] = Default::default();
    for (i, s, it, stored, server) in found {
        if s == salt && it == iterations && keys[i].is_none() {
            keys[i] = Some((stored, server));
        }
    }
    Ok(Some(StoredKeys { salt, iterations, keys }))
}

fn key_len(h: ScramHash) -> usize {
    match h {
        ScramHash::Sha1 => 20,
        ScramHash::Sha256 => 32,
        ScramHash::Sha512 => 64,
    }
}

async fn import_roster(srv: &Server, h: &Host, user: &str, q: &Element) -> Result<(), DbError> {
    for item in q.children().filter(|c| c.is("item", ns::ROSTER)) {
        let Some(contact) = item.attr("jid").and_then(|j| Jid::parse(j).ok()).map(|j| j.to_bare()) else { continue };
        if contact.node() == Some(user) && contact.domain() == h.domain {
            continue;
        }
        let mut it = roster::Item::new(contact);
        it.name = item.attr("name").map(str::trim).filter(|n| !n.is_empty()).map(|n| n.chars().take(256).collect());
        it.subscription = match item.attr("subscription") {
            Some("to") => Subscription::To,
            Some("from") => Subscription::From,
            Some("both") => Subscription::Both,
            _ => Subscription::None,
        };
        it.ask = item.attr("ask") == Some("subscribe");
        it.approved = matches!(item.attr("approved"), Some("true" | "1"));
        it.groups = item
            .children()
            .filter(|g| g.is("group", ns::ROSTER))
            .map(|g| g.text_content())
            .filter(|g| !g.trim().is_empty())
            .take(64)
            .collect();
        roster::save(srv, &h.domain, user, &it).await?;
    }
    Ok(())
}

async fn import_vcard(srv: &Server, h: &Host, user: &str, v: &Element) -> Result<(), DbError> {
    let mut v = v.clone();
    v.strip_whitespace();
    let xml = v.to_xml();
    if xml.len() > MAX_VCARD {
        return Ok(());
    }
    let (d, u) = (h.domain.clone(), user.to_string());
    srv.db
        .write(move |t| {
            t.execute(
                "INSERT INTO vcards (host, user, xml) VALUES (?1, ?2, ?3) ON CONFLICT(host, user) DO UPDATE SET xml = excluded.xml",
                params![d, u, xml],
            )
        })
        .await
        .map(|_| ())
}

async fn import_private(srv: &Server, h: &Host, user: &str, q: &Element) -> Result<(), DbError> {
    let mut rows = Vec::new();
    for item in q.children() {
        if item.ns() == ns::PRIVATE || item.ns().is_empty() || item.ns() == ns::CLIENT {
            continue;
        }
        let mut v = item.clone();
        v.strip_whitespace();
        let xml = v.to_xml();
        if xml.len() <= MAX_PRIVATE {
            rows.push((item.ns().to_string(), item.name().to_string(), xml));
        }
    }
    let (d, u) = (h.domain.clone(), user.to_string());
    srv.db
        .write(move |t| {
            for (n, name, xml) in &rows {
                t.execute(
                    "INSERT INTO private_xml (host, user, ns, name, xml) VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(host, user, ns, name) DO UPDATE SET xml = excluded.xml",
                    params![d, u, n, name, xml],
                )?;
            }
            Ok(())
        })
        .await
}

async fn import_offline(srv: &Server, h: &Host, user: &str, o: &Element) -> Result<(), DbError> {
    let now = quark_core::time::now_ms();
    let mut rows = Vec::new();
    for m in o.children().filter(|c| c.name() == "message").take(MAX_OFFLINE) {
        let mut m = m.clone();
        // Exports from servers that write the default namespace out differently.
        m.set_ns(ns::CLIENT);
        let stamp = m.get_child("delay", ns::DELAY).and_then(|d| d.attr("stamp")).and_then(quark_core::time::parse_xep82).unwrap_or(now);
        rows.push((stamp, m.to_xml()));
    }
    let (d, u) = (h.domain.clone(), user.to_string());
    srv.db
        .write(move |t| {
            for (stamp, xml) in &rows {
                t.execute("INSERT INTO offline (host, user, stamp, xml) VALUES (?1, ?2, ?3, ?4)", params![d, u, stamp, xml])?;
            }
            Ok(())
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measures_nesting() {
        assert_eq!(depth("<a><b/><c><d></d></c></a>"), 3);
        assert_eq!(depth("<?xml version='1.0'?><!-- x --><a/>"), 0);
        assert!(depth(&"<a>".repeat(100)) > MAX_DEPTH);
    }

    #[test]
    fn refuses_what_is_not_an_export() {
        assert!(parse_document("<foo/>").is_err());
        assert!(parse_document("not xml").is_err());
        assert!(parse_document(&format!("<server-data xmlns='{PIE}'>{}", "<a>".repeat(100))).is_err());
        assert!(parse_document(&format!("<?xml version='1.0'?>\n<server-data xmlns='{PIE}'/>")).is_ok());
    }

    #[test]
    fn keeps_keys_that_share_the_strongest_salt() {
        let k = |m: &str, salt: &str, len: usize| {
            format!(
                "<scram-credentials xmlns='{SCRAM}' mechanism='{m}'><iter-count>4096</iter-count><salt>{}</salt>\
                 <server-key>{}</server-key><stored-key>{}</stored-key></scram-credentials>",
                B64.encode(salt),
                B64.encode(vec![1u8; len]),
                B64.encode(vec![2u8; len])
            )
        };
        let el = Element::parse(&format!(
            "<user xmlns='{PIE}' name='sam'>{}{}</user>",
            k("SCRAM-SHA-1", "s1", 20),
            k("SCRAM-SHA-256", "s2", 32)
        ))
        .unwrap();
        let got = credentials(&el).unwrap().unwrap();
        assert_eq!(got.salt, b"s2");
        assert!(got.keys[0].is_none() && got.keys[1].is_some() && got.keys[2].is_none());

        let only_sha1 = Element::parse(&format!("<user xmlns='{PIE}' name='sam'>{}</user>", k("SCRAM-SHA-1", "s1", 20))).unwrap();
        let got = credentials(&only_sha1).unwrap().unwrap();
        assert_eq!((got.iterations, got.keys[0].as_ref().map(|k| k.0.len())), (4096, Some(20)));

        let short = Element::parse(&format!("<user xmlns='{PIE}' name='sam'>{}</user>", k("SCRAM-SHA-256", "s1", 20))).unwrap();
        assert!(credentials(&short).is_err());
        assert!(credentials(&Element::parse(&format!("<user xmlns='{PIE}' name='sam'/>")).unwrap()).unwrap().is_none());
    }

    #[test]
    fn refuses_absurd_iteration_counts() {
        let k = |n: u64| {
            let c = format!(
                "<scram-credentials xmlns='{SCRAM}' mechanism='SCRAM-SHA-256'><iter-count>{n}</iter-count><salt>{}</salt>\
                 <server-key>{}</server-key><stored-key>{}</stored-key></scram-credentials>",
                B64.encode("salt"),
                B64.encode([1u8; 32]),
                B64.encode([2u8; 32])
            );
            credentials(&Element::parse(&format!("<user xmlns='{PIE}' name='sam'>{c}</user>")).unwrap())
        };
        assert!(k(4_000_000_000).is_err());
        assert!(k(1_000_001).is_err());
        assert!(k(999).is_err());
        assert_eq!(k(1_000_000).unwrap().unwrap().iterations, 1_000_000);
    }
}
