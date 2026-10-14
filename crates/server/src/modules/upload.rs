//! HTTP File Upload (XEP-0363, `urn:xmpp:http:upload:0`): the slot-granting component on
//! `files.host`. Files are received and served by `http::files`.
//!
//! A slot is a row here plus an upload URL signed with a secret from the kv store, valid for a
//! few minutes. The download URL carries an unguessable token, so only people the link was
//! shared with can fetch the file. Accounts have a storage quota and an hourly slot limit, and
//! files go away after `files.keepDays`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use quark_core::stanza::{error_reply, iq_result, IqType};
use quark_core::{ns, Condition, Element, ErrorType, Jid, StanzaError};
use rand::RngCore;
use sha2::Sha256;

use super::{Component, Module};
use crate::db::{params, DbError, Migration, OptionalExtension};
use crate::server::{Host, Server};

pub static MIGRATION: Migration = Migration {
    module: "upload",
    steps: &[
        "CREATE TABLE uploads (
        token TEXT PRIMARY KEY,
        host TEXT NOT NULL,
        user TEXT NOT NULL,
        name TEXT NOT NULL,
        ctype TEXT NOT NULL,
        -- The size asked for, then the size stored.
        size INTEGER NOT NULL,
        -- 0: slot granted, 1: upload in progress, 2: stored.
        state INTEGER NOT NULL,
        -- When the slot was granted, then when the file was stored.
        created INTEGER NOT NULL,
        slot_expires INTEGER NOT NULL,
        FOREIGN KEY (host, user) REFERENCES accounts(host, user) ON DELETE CASCADE
    ) WITHOUT ROWID;
    CREATE INDEX uploads_by_user ON uploads (host, user, created);
    CREATE INDEX uploads_by_state ON uploads (state, created);",
        // 1 when the client named the type in its slot request (so the PUT must match it); 0
        // when it was guessed from the file name.
        "ALTER TABLE uploads ADD COLUMN ctype_given INTEGER NOT NULL DEFAULT 0",
    ],
};

/// How long an upload URL works.
pub const SLOT_MS: i64 = 10 * 60 * 1000;
/// Slots one account can ask for per hour.
pub const SLOTS_PER_HOUR: i64 = 60;
/// Storage per account: twenty files of the largest size allowed, and never less than 1 GiB.
const QUOTA_FILES: u64 = 20;
const MIN_QUOTA: u64 = 1 << 30;
const MAX_NAME_CHARS: usize = 120;
const DAY_MS: i64 = 86_400_000;
const SWEEP_EVERY: Duration = Duration::from_secs(3600);
/// Uploads one account may have streaming in at once.
pub const CONCURRENT_UPLOADS: i64 = 4;

pub const STATE_SLOT: i64 = 0;
pub const STATE_UPLOADING: i64 = 1;
pub const STATE_STORED: i64 = 2;
/// A failed upload's files are being removed ([`abort_upload`]); the slot is unused again after.
pub const STATE_RELEASING: i64 = 3;

/// Where uploaded files live: `<data_dir>/uploads/<token>`.
pub fn dir(srv: &Server) -> PathBuf {
    srv.config().server.data_dir.join("uploads")
}

/// The largest file `host` accepts, in bytes.
pub fn max_bytes(host: &Host) -> u64 {
    u64::from(host.settings().files.max_mb) * 1024 * 1024
}

fn quota(host: &Host) -> u64 {
    (max_bytes(host) * QUOTA_FILES).max(MIN_QUOTA)
}

/// The HMAC key for upload URLs, made on first use and kept in the kv store.
pub(crate) async fn secret(srv: &Server) -> Result<Vec<u8>, DbError> {
    if let Some(s) = srv.kv_get("upload", "secret").await? {
        return Ok(s);
    }
    let mut fresh = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut fresh);
    // Whoever writes first wins, so concurrent first uploads agree on one key.
    srv.db
        .write(move |t| {
            t.execute("INSERT OR IGNORE INTO kv (scope, key, value) VALUES ('upload', 'secret', ?1)", [fresh])?;
            t.query_row("SELECT value FROM kv WHERE scope = 'upload' AND key = 'secret'", [], |r| r.get(0))
        })
        .await
}

fn mac(secret: &[u8], token: &str, expires: i64) -> Hmac<Sha256> {
    let mut m = <Hmac<Sha256>>::new_from_slice(secret).expect("HMAC takes keys of any length");
    m.update(token.as_bytes());
    m.update(b"\n");
    m.update(expires.to_string().as_bytes());
    m
}

/// The signature in an upload URL.
pub(crate) fn sign(secret: &[u8], token: &str, expires: i64) -> String {
    hex::encode(mac(secret, token, expires).finalize().into_bytes())
}

/// Checks an upload URL's signature in constant time.
pub(crate) fn verify(secret: &[u8], token: &str, expires: i64, sig: &str) -> bool {
    hex::decode(sig).is_ok_and(|s| mac(secret, token, expires).verify_slice(&s).is_ok())
}

/// Tokens are 32 lowercase hex characters; anything else is never looked up.
pub(crate) fn valid_token(t: &str) -> bool {
    t.len() == 32 && t.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A file name safe to put in a URL path and a `Content-Disposition`: no directories, no control
/// characters, no leading dots, a sane length.
pub fn sanitize_filename(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or_default();
    let mut out: String = base
        .chars()
        .map(|c| if c.is_control() || matches!(c, '"' | '<' | '>' | '|' | ':' | '*' | '?' | '\u{202e}' | '\u{202d}') { '_' } else { c })
        .take(MAX_NAME_CHARS)
        .collect();
    out = out.trim().trim_start_matches('.').to_string();
    if out.is_empty() {
        "file".into()
    } else {
        out
    }
}

/// A content type from the extension, for slots that don't name one.
pub fn guess_type(name: &str) -> &'static str {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "heic" => "image/heic",
        "heif" => "image/heif",
        "svg" => "image/svg+xml",
        "mp4" | "m4v" => "video/mp4",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        "mkv" => "video/x-matroska",
        "3gp" => "video/3gpp",
        "mp3" => "audio/mpeg",
        "m4a" | "aac" => "audio/mp4",
        "ogg" | "oga" => "audio/ogg",
        "opus" => "audio/opus",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "pdf" => "application/pdf",
        "txt" => "text/plain; charset=utf-8",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

/// A client's content type, kept only when it's a plain `type/subtype` (plus parameters).
fn clean_ctype(t: &str) -> Option<String> {
    let t = t.trim();
    let (essence, _) = t.split_once(';').unwrap_or((t, ""));
    let (a, b) = essence.trim().split_once('/')?;
    let token = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"!#$&^_.+-".contains(&c));
    (t.len() <= 100 && token(a) && token(b) && t.bytes().all(|c| (0x20..0x7f).contains(&c))).then(|| t.to_ascii_lowercase())
}

/// Percent-encodes a URL path segment.
pub fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A slot or stored file.
#[derive(Debug, Clone)]
pub(crate) struct Slot {
    pub host: String,
    pub name: String,
    pub ctype: String,
    /// The client named `ctype` itself (rather than it being guessed from the name).
    pub ctype_given: bool,
    pub size: u64,
    pub state: i64,
    pub created: i64,
}

pub(crate) async fn slot(srv: &Server, token: &str) -> Result<Option<Slot>, DbError> {
    let t = token.to_string();
    srv.db
        .read(move |c| {
            c.prepare_cached("SELECT host, name, ctype, ctype_given, size, state, created FROM uploads WHERE token = ?1")?
                .query_row([t], |r| {
                    Ok(Slot {
                        host: r.get(0)?,
                        name: r.get(1)?,
                        ctype: r.get(2)?,
                        ctype_given: r.get::<_, i64>(3)? != 0,
                        size: r.get::<_, i64>(4)?.max(0) as u64,
                        state: r.get(5)?,
                        created: r.get(6)?,
                    })
                })
                .optional()
        })
        .await
}

/// Whether an upload may start.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Begin {
    Ok,
    /// The slot is taken, used or expired.
    Taken,
    /// The account has `CONCURRENT_UPLOADS` running already.
    Busy,
}

/// Claims a slot for one upload at a time, and at most `CONCURRENT_UPLOADS` per account.
pub(crate) async fn begin_upload(srv: &Server, token: &str) -> Result<Begin, DbError> {
    let (t, now) = (token.to_string(), quark_core::time::now_ms());
    srv.db
        .write(move |tx| {
            let running: Option<i64> = tx
                .prepare_cached(
                    "SELECT COUNT(o.token) FROM uploads s LEFT JOIN uploads o ON o.host = s.host AND o.user = s.user AND o.state = 1
                     WHERE s.token = ?1 GROUP BY s.token",
                )?
                .query_row([&t], |r| r.get(0))
                .optional()?;
            if running.is_some_and(|n| n >= CONCURRENT_UPLOADS) {
                return Ok(Begin::Busy);
            }
            let n = tx.execute("UPDATE uploads SET state = 1 WHERE token = ?1 AND state = 0 AND slot_expires > ?2", params![t, now])?;
            Ok(if n == 1 { Begin::Ok } else { Begin::Taken })
        })
        .await
}

/// Gives the slot back after a failed upload, so the client can try again while it's valid,
/// removing what the upload left on disk (its file too, if it was renamed into place but never
/// marked stored).
///
/// The slot moves from uploading to releasing in one statement before any file is touched, and
/// only then are files removed: a finish that commits first leaves nothing to release (its file
/// stays), one that comes after finds the slot no longer uploading and fails. While releasing,
/// no new upload of the slot can start and write a part file this would remove.
pub(crate) async fn abort_upload(srv: &Server, token: &str) {
    let t = token.to_string();
    let claimed = srv.db.write(move |tx| tx.execute("UPDATE uploads SET state = 3 WHERE token = ?1 AND state = 1", [t])).await;
    match claimed {
        Ok(1) => {}
        Ok(_) => return,
        Err(e) => {
            tracing::warn!(error = %e, "couldn't release an upload slot");
            return;
        }
    }
    let dir = dir(srv);
    let _ = tokio::fs::remove_file(dir.join(format!(".{token}.part"))).await;
    let _ = tokio::fs::remove_file(dir.join(token)).await;
    let t = token.to_string();
    if let Err(e) = srv.db.write(move |tx| tx.execute("UPDATE uploads SET state = 0 WHERE token = ?1 AND state = 3", [t])).await {
        // Left releasing: the expiry sweep or the next start cleans it up.
        tracing::warn!(error = %e, "couldn't release an upload slot");
    }
}

/// At start, before the web listener takes uploads: none can be running, so slots a restart
/// cut off go back to unused, without the partial files that would block a new try.
pub(crate) async fn reset_interrupted(srv: &Server) {
    let tokens: Vec<String> = match srv
        .db
        .write(|tx| {
            let mut st = tx.prepare("UPDATE uploads SET state = 0 WHERE state IN (1, 3) RETURNING token")?;
            let rows = st.query_map([], |r| r.get(0))?;
            rows.collect()
        })
        .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "couldn't release interrupted upload slots");
            return;
        }
    };
    let dir = dir(srv);
    for t in tokens.iter().filter(|t| valid_token(t)) {
        let _ = tokio::fs::remove_file(dir.join(format!(".{t}.part"))).await;
        let _ = tokio::fs::remove_file(dir.join(t)).await;
    }
}

/// Marks the file stored, with the size actually kept. False when the row is gone (the account
/// was deleted meanwhile).
pub(crate) async fn finish_upload(srv: &Server, token: &str, stored: u64) -> Result<bool, DbError> {
    let (t, now) = (token.to_string(), quark_core::time::now_ms());
    let size = i64::try_from(stored).unwrap_or(i64::MAX);
    srv.db
        .write(move |tx| {
            tx.execute("UPDATE uploads SET state = 2, size = ?2, created = ?3 WHERE token = ?1 AND state = 1", params![t, size, now])
                .map(|n| n == 1)
        })
        .await
}

/// When a stored file stops being served, if ever.
pub(crate) fn expires_at(srv: &Server, s: &Slot) -> Option<i64> {
    let days = srv.host(&s.host)?.settings().files.keep_days;
    (days > 0).then(|| s.created + i64::from(days) * DAY_MS)
}

/// (files, bytes) stored, for metrics.
pub async fn stored(srv: &Server) -> (u64, u64) {
    srv.db
        .read(|c| {
            c.query_row("SELECT COUNT(*), COALESCE(SUM(size), 0) FROM uploads WHERE state = 2", [], |r| {
                Ok((r.get::<_, i64>(0)?.max(0) as u64, r.get::<_, i64>(1)?.max(0) as u64))
            })
        })
        .await
        .unwrap_or((0, 0))
}

/// Deletes expired files, stale slots and files nothing refers to, as of `now` (ms). Returns how
/// many files were removed from disk.
pub async fn sweep(srv: &Arc<Server>, now: i64) -> usize {
    let keep: Vec<(String, i64)> = srv
        .hosts()
        .iter()
        .filter_map(|h| Some((h.domain.clone(), h.settings().files.keep_days)).filter(|(_, d)| *d > 0))
        .map(|(d, k)| (d, i64::from(k)))
        .collect();
    let gone = srv
        .db
        .write(move |t| {
            let mut gone: Vec<String> = Vec::new();
            for (host, days) in &keep {
                let mut st = t.prepare_cached("DELETE FROM uploads WHERE host = ?1 AND state = 2 AND created < ?2 RETURNING token")?;
                let rows = st.query_map(params![host, now - days * DAY_MS], |r| r.get(0))?;
                for r in rows {
                    gone.push(r?);
                }
            }
            // Slots never used, and uploads that died halfway a day ago.
            t.execute("DELETE FROM uploads WHERE state = 0 AND slot_expires < ?1", [now])?;
            let mut st = t.prepare_cached("DELETE FROM uploads WHERE state IN (1, 3) AND slot_expires < ?1 RETURNING token")?;
            let rows = st.query_map([now - DAY_MS], |r| r.get(0))?;
            for r in rows {
                gone.push(r?);
            }
            Ok(gone)
        })
        .await;
    let gone = match gone {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!(error = %e, "upload expiry failed");
            return 0;
        }
    };
    // Files whose rows went with a deleted account are found by listing the folder, before
    // asking which rows exist: an upload claims its slot before it creates its file, so any
    // file listed here that belongs to a running upload is known by the time we ask. (Asking
    // first would miss an upload that starts in between and delete its file.)
    let dir = dir(srv);
    let listed: Vec<(String, std::path::PathBuf)> = {
        let dir = dir.clone();
        tokio::task::spawn_blocking(move || {
            let Ok(entries) = std::fs::read_dir(&dir) else { return Vec::new() };
            entries
                .flatten()
                .filter_map(|e| {
                    let name = e.file_name().to_str()?.to_string();
                    let token = name.strip_prefix('.').and_then(|n| n.strip_suffix(".part")).unwrap_or(&name).to_string();
                    valid_token(&token).then(|| (token, e.path()))
                })
                .collect()
        })
        .await
        .unwrap_or_default()
    };
    let known: std::collections::HashSet<String> = match srv
        .db
        .read(|c| {
            let mut st = c.prepare("SELECT token FROM uploads WHERE state IN (1, 2, 3)")?;
            let rows = st.query_map([], |r| r.get(0))?;
            rows.collect()
        })
        .await
    {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(error = %e, "upload expiry couldn't list files");
            return 0;
        }
    };
    let removed = tokio::task::spawn_blocking(move || {
        let mut removed = 0;
        for t in &gone {
            if std::fs::remove_file(dir.join(t)).is_ok() {
                removed += 1;
            }
            let _ = std::fs::remove_file(dir.join(format!(".{t}.part")));
        }
        for (token, path) in &listed {
            if !known.contains(token) && std::fs::remove_file(path).is_ok() {
                removed += 1;
            }
        }
        removed
    })
    .await
    .unwrap_or(0);
    if removed > 0 {
        tracing::info!(removed, "removed expired uploads");
    }
    removed
}

pub struct Upload;

#[async_trait]
impl Module for Upload {
    fn name(&self) -> &'static str {
        "http_file_share"
    }

    fn migrations(&self) -> Vec<&'static Migration> {
        vec![&MIGRATION]
    }

    fn snapshot_names(&self, host: &Host) -> Vec<&'static str> {
        if host.settings().files.on {
            vec!["http_file_share"]
        } else {
            Vec::new()
        }
    }

    fn server_items(&self, host: &Host) -> Vec<Element> {
        let s = host.settings();
        if !s.files.on {
            return Vec::new();
        }
        vec![Element::new("item", ns::DISCO_ITEMS).attr_set("jid", s.files.host.clone()).attr_set("name", "File sharing")]
    }

    fn components(&self, _srv: &Arc<Server>, host: &Arc<Host>) -> Vec<Arc<dyn Component>> {
        let s = host.settings();
        if !s.files.on {
            return Vec::new();
        }
        vec![Arc::new(UploadService { domain: s.files.host.clone(), host: host.clone() })]
    }

    fn start(&self, srv: &Arc<Server>) {
        let srv = Arc::downgrade(srv);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(SWEEP_EVERY);
            loop {
                tick.tick().await;
                let Some(srv) = srv.upgrade() else { return };
                sweep(&srv, quark_core::time::now_ms()).await;
            }
        });
    }
}

/// The upload service on `files.host`.
struct UploadService {
    domain: String,
    host: Arc<Host>,
}

#[async_trait]
impl Component for UploadService {
    fn domain(&self) -> &str {
        &self.domain
    }

    async fn handle(&self, srv: &Arc<Server>, from: Jid, to: Jid, stanza: Element) {
        if stanza.name() != "iq" {
            return;
        }
        let Some(kind) = quark_core::stanza::iq_type(&stanza) else { return };
        if matches!(kind, IqType::Result | IqType::Error) {
            return;
        }
        let mut iq = stanza;
        iq.set_attr("from", from.to_string());
        iq.set_attr("to", to.to_string());
        let reply = match self.answer(srv, &from, &to, &iq, kind).await {
            Ok(payload) => {
                let mut r = iq_result(&iq);
                if let Some(p) = payload {
                    r.append(p);
                }
                Some(r)
            }
            Err(e) => error_reply(&iq, &e),
        };
        if let Some(r) = reply {
            srv.route(r).await;
        }
    }
}

impl UploadService {
    async fn answer(&self, srv: &Arc<Server>, from: &Jid, to: &Jid, iq: &Element, kind: IqType) -> Result<Option<Element>, StanzaError> {
        let payload = iq.first_child().ok_or_else(StanzaError::bad_request)?;
        if to.node().is_some() || to.resource().is_some() {
            return Err(StanzaError::service_unavailable());
        }
        match (payload.ns(), payload.name(), kind) {
            (ns::DISCO_INFO, "query", IqType::Get) => Ok(Some(self.disco_info(payload.attr("node")))),
            (ns::DISCO_ITEMS, "query", IqType::Get) => {
                Ok(Some(Element::new("query", ns::DISCO_ITEMS).attr_opt("node", payload.attr("node"))))
            }
            (ns::PING, "ping", IqType::Get) => Ok(None),
            (ns::HTTP_UPLOAD, "request", _) => self.request(srv, from, payload).await.map(Some),
            _ => Err(StanzaError::service_unavailable()),
        }
    }

    fn disco_info(&self, node: Option<&str>) -> Element {
        let max = max_bytes(&self.host);
        let form = Element::new("x", ns::DATA_FORMS)
            .attr_set("type", "result")
            .child(Element::new("field", ns::DATA_FORMS).attr_set("var", "FORM_TYPE").attr_set("type", "hidden").text_child(
                "value",
                ns::DATA_FORMS,
                ns::HTTP_UPLOAD,
            ))
            .child(Element::new("field", ns::DATA_FORMS).attr_set("var", "max-file-size").text_child(
                "value",
                ns::DATA_FORMS,
                max.to_string(),
            ));
        Element::new("query", ns::DISCO_INFO)
            .attr_opt("node", node)
            .child(
                Element::new("identity", ns::DISCO_INFO)
                    .attr_set("category", "store")
                    .attr_set("type", "file")
                    .attr_set("name", "File sharing"),
            )
            .child(Element::new("feature", ns::DISCO_INFO).attr_set("var", ns::DISCO_INFO))
            .child(Element::new("feature", ns::DISCO_INFO).attr_set("var", ns::HTTP_UPLOAD))
            .child(form)
    }

    /// A slot request (XEP-0363 §4).
    async fn request(&self, srv: &Arc<Server>, from: &Jid, req: &Element) -> Result<Element, StanzaError> {
        let domain = &self.host.domain;
        let Some(user) = from.node().filter(|_| from.domain() == domain) else {
            return Err(StanzaError::forbidden().with_text(format!("Only accounts on {domain} can share files here.")));
        };
        let size: u64 = req
            .attr("size")
            .and_then(|s| s.trim().parse().ok())
            .ok_or_else(|| StanzaError::bad_request().with_text("The request needs the file's size in bytes."))?;
        let raw_name = req.attr("filename").unwrap_or_default();
        if raw_name.trim().is_empty() {
            return Err(StanzaError::bad_request().with_text("The request needs a file name."));
        }
        if size == 0 {
            return Err(StanzaError::bad_request().with_text("The file is empty."));
        }
        let max = max_bytes(&self.host);
        if size > max {
            let app = Element::new("file-too-large", ns::HTTP_UPLOAD).text_child("max-file-size", ns::HTTP_UPLOAD, max.to_string());
            return Err(StanzaError::new(Condition::NotAcceptable)
                .with_text(format!("Files can be at most {} MB here.", self.host.settings().files.max_mb))
                .with_app(app));
        }
        let name = sanitize_filename(raw_name);
        let given = req.attr("content-type").and_then(clean_ctype);
        let ctype_given = given.is_some();
        let ctype = given.unwrap_or_else(|| guess_type(&name).to_string());

        let mut raw = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut raw);
        let token = hex::encode(raw);
        let now = quark_core::time::now_ms();
        let expires = now + SLOT_MS;
        let quota = quota(&self.host);
        let (h, u, t, n, c) = (domain.clone(), user.to_string(), token.clone(), name.clone(), ctype.clone());
        let isize = i64::try_from(size).unwrap_or(i64::MAX);
        let granted = srv
            .db
            .write(move |tx| {
                let recent: i64 = tx
                    .prepare_cached("SELECT COUNT(*) FROM uploads WHERE host = ?1 AND user = ?2 AND created > ?3")?
                    .query_row(params![h, u, now - 3_600_000], |r| r.get(0))?;
                if recent >= SLOTS_PER_HOUR {
                    let oldest: i64 = tx
                        .prepare_cached("SELECT MIN(created) FROM uploads WHERE host = ?1 AND user = ?2 AND created > ?3")?
                        .query_row(params![h, u, now - 3_600_000], |r| r.get(0))?;
                    return Ok(Grant::Rate(oldest + 3_600_000));
                }
                let used: i64 = tx
                    .prepare_cached("SELECT COALESCE(SUM(size), 0) FROM uploads WHERE host = ?1 AND user = ?2 AND (state = 2 OR slot_expires > ?3)")?
                    .query_row(params![h, u, now], |r| r.get(0))?;
                if (used.max(0) as u64).saturating_add(size) > quota {
                    return Ok(Grant::Quota(used.max(0) as u64));
                }
                tx.prepare_cached(
                    "INSERT INTO uploads (token, host, user, name, ctype, ctype_given, size, state, created, slot_expires) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, ?9)",
                )?
                .execute(params![t, h, u, n, c, ctype_given, isize, now, expires])?;
                Ok(Grant::Ok)
            })
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "couldn't grant an upload slot");
                StanzaError::internal()
            })?;
        match granted {
            Grant::Ok => {}
            Grant::Rate(retry) => {
                return Err(StanzaError::new(Condition::ResourceConstraint)
                    .with_type(ErrorType::Wait)
                    .with_text("That's a lot of files in one hour. Try again a bit later.")
                    .with_app(Element::new("retry", ns::HTTP_UPLOAD).attr_set("stamp", quark_core::time::xep82(retry))));
            }
            Grant::Quota(used) => {
                return Err(StanzaError::new(Condition::ResourceConstraint).with_type(ErrorType::Wait).with_text(format!(
                    "Your shared files use {} MB of {} MB. Older files make room as they expire.",
                    used.div_ceil(1 << 20),
                    quota >> 20
                )));
            }
        }
        let secret = secret(srv).await.map_err(|e| {
            tracing::warn!(error = %e, "couldn't read the upload key");
            StanzaError::internal()
        })?;
        let base = crate::http::public_base(srv, domain);
        let get = format!("{base}/upload/{token}/{}", pct(&name));
        let put = format!("{get}?e={expires}&s={}", sign(&secret, &token, expires));
        Ok(Element::new("slot", ns::HTTP_UPLOAD)
            .child(Element::new("put", ns::HTTP_UPLOAD).attr_set("url", put))
            .child(Element::new("get", ns::HTTP_UPLOAD).attr_set("url", get)))
    }
}

enum Grant {
    Ok,
    /// Too many slots this hour; retry at (ms).
    Rate(i64),
    /// Over quota; bytes in use.
    Quota(u64),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filenames_are_made_safe() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("C:\\Users\\me\\photo.jpg"), "photo.jpg");
        assert_eq!(sanitize_filename(".hidden"), "hidden");
        assert_eq!(sanitize_filename("a\u{0}b\nc.txt"), "a_b_c.txt");
        assert_eq!(sanitize_filename("evil\u{202e}gpj.exe"), "evil_gpj.exe");
        assert_eq!(sanitize_filename("   "), "file");
        assert_eq!(sanitize_filename("/"), "file");
        assert_eq!(sanitize_filename(&"x".repeat(500)).chars().count(), MAX_NAME_CHARS);
        assert_eq!(sanitize_filename("Ferien am Meer 🌊.jpg"), "Ferien am Meer 🌊.jpg");
    }

    #[test]
    fn content_types_are_checked() {
        assert_eq!(clean_ctype("image/JPEG").as_deref(), Some("image/jpeg"));
        assert_eq!(clean_ctype("text/plain; charset=utf-8").as_deref(), Some("text/plain; charset=utf-8"));
        assert_eq!(clean_ctype("image"), None);
        assert_eq!(clean_ctype("image/jpeg\r\nX-Evil: 1"), None);
        assert_eq!(clean_ctype("/"), None);
        assert_eq!(guess_type("a.JPG"), "image/jpeg");
        assert_eq!(guess_type("noext"), "application/octet-stream");
    }

    #[test]
    fn signatures_bind_token_and_expiry() {
        let k = b"key";
        let s = sign(k, "abc", 10);
        assert!(verify(k, "abc", 10, &s));
        assert!(!verify(k, "abc", 11, &s));
        assert!(!verify(k, "abd", 10, &s));
        assert!(!verify(b"other", "abc", 10, &s));
        assert!(!verify(k, "abc", 10, "zz"));
    }

    #[test]
    fn percent_encoding_keeps_unreserved() {
        assert_eq!(pct("a b/ü.jpg"), "a%20b%2F%C3%BC.jpg");
        assert!(valid_token("0123456789abcdef0123456789abcdef"));
        assert!(!valid_token("../0123456789abcdef0123456789abc"));
    }

    async fn server(dir: &std::path::Path) -> Arc<Server> {
        let path = dir.join("quark.toml");
        let text =
            format!("[server]\ndata_dir = {:?}\n[tls]\ncert_dir = {:?}\n[[host]]\ndomain = \"a.test\"\n", dir.join("data"), dir.join("certs"));
        std::fs::write(&path, text).unwrap();
        let srv = crate::run::build(crate::run::load_config(&path).unwrap()).unwrap();
        srv.accounts.create("a.test", "sam", "password", crate::accounts::Role::Member).await.unwrap();
        tokio::fs::create_dir_all(super::dir(&srv)).await.unwrap();
        srv
    }

    async fn new_slot(srv: &Server, token: &str) {
        let (t, now) = (token.to_string(), quark_core::time::now_ms());
        srv.db
            .write(move |tx| {
                tx.execute(
                    "INSERT INTO uploads (token, host, user, name, ctype, size, state, created, slot_expires)
                     VALUES (?1, 'a.test', 'sam', 'f.txt', 'text/plain', 3, 0, ?2, ?3)",
                    params![t, now, now + SLOT_MS],
                )
            })
            .await
            .unwrap();
    }

    async fn state(srv: &Server, token: &str) -> i64 {
        slot(srv, token).await.unwrap().unwrap().state
    }

    #[tokio::test]
    async fn releasing_a_slot_never_touches_a_stored_file() {
        let tmp = tempfile::tempdir().unwrap();
        let srv = server(tmp.path()).await;
        let dir = super::dir(&srv);
        let t = "0123456789abcdef0123456789abcdef";
        new_slot(&srv, t).await;
        assert_eq!(begin_upload(&srv, t).await.unwrap(), Begin::Ok);
        tokio::fs::write(dir.join(t), b"abc").await.unwrap();
        assert!(finish_upload(&srv, t, 3).await.unwrap());
        // A release that lost the race to the finish leaves the stored file alone.
        abort_upload(&srv, t).await;
        assert_eq!(state(&srv, t).await, STATE_STORED);
        assert!(dir.join(t).exists());

        // A failed upload's part file goes, and the slot can be used again.
        let u = "fedcba9876543210fedcba9876543210";
        new_slot(&srv, u).await;
        assert_eq!(begin_upload(&srv, u).await.unwrap(), Begin::Ok);
        tokio::fs::write(dir.join(format!(".{u}.part")), b"ab").await.unwrap();
        abort_upload(&srv, u).await;
        assert_eq!(state(&srv, u).await, STATE_SLOT);
        assert!(!dir.join(format!(".{u}.part")).exists());
        assert_eq!(begin_upload(&srv, u).await.unwrap(), Begin::Ok);
    }

    #[tokio::test]
    async fn a_slot_being_released_can_neither_finish_nor_start_again() {
        let tmp = tempfile::tempdir().unwrap();
        let srv = server(tmp.path()).await;
        let t = "0123456789abcdef0123456789abcdef";
        new_slot(&srv, t).await;
        assert_eq!(begin_upload(&srv, t).await.unwrap(), Begin::Ok);
        let tt = t.to_string();
        srv.db.write(move |tx| tx.execute("UPDATE uploads SET state = 3 WHERE token = ?1", [tt])).await.unwrap();
        assert!(!finish_upload(&srv, t, 3).await.unwrap(), "the release removes the file, so it can't be marked stored");
        assert_eq!(begin_upload(&srv, t).await.unwrap(), Begin::Taken);
        assert_eq!(state(&srv, t).await, STATE_RELEASING);
    }
}
