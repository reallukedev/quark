//! Receiving and serving uploaded files (XEP-0363). `PUT` streams to a temporary file and renames
//! it into place once exactly the announced number of bytes arrived; `GET`/`HEAD` serve with
//! ranges, caching headers and CORS for web clients. Slots and signatures are in
//! `modules::upload`.

use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Path as UrlPath, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use super::AppState;
use crate::modules::upload::{self, Slot, STATE_SLOT, STATE_STORED};

/// How long an upload may stall between two chunks.
const CHUNK_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_BUFFER: usize = 256 * 1024;
const READ_BUFFER: usize = 64 * 1024;
const YEAR_SECS: i64 = 365 * 86_400;

type Refusal = (StatusCode, &'static str);

fn with_cors(mut r: Response) -> Response {
    let h = r.headers_mut();
    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    h.insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, HeaderValue::from_static("Content-Length, Content-Range, Content-Disposition, ETag"));
    r
}

fn refuse((status, text): Refusal) -> Response {
    with_cors((status, [(header::CONTENT_TYPE, "text/plain; charset=utf-8")], format!("{text}\n")).into_response())
}

pub(super) async fn preflight() -> Response {
    with_cors(
        (
            StatusCode::NO_CONTENT,
            [
                (header::ACCESS_CONTROL_ALLOW_METHODS, "GET, HEAD, PUT, OPTIONS"),
                (header::ACCESS_CONTROL_ALLOW_HEADERS, "Content-Type, Authorization, Range"),
                (header::ACCESS_CONTROL_MAX_AGE, "86400"),
            ],
        )
            .into_response(),
    )
}

fn essence(ctype: &str) -> String {
    ctype.split(';').next().unwrap_or_default().trim().to_ascii_lowercase()
}

pub(super) async fn put(
    State(st): AppState,
    UrlPath((token, name)): UrlPath<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let srv = &st.srv;
    if !upload::valid_token(&token) {
        return refuse((StatusCode::NOT_FOUND, "There's no upload slot here."));
    }
    let (Some(expires), Some(sig)) = (q.get("e").and_then(|e| e.parse::<i64>().ok()), q.get("s")) else {
        return refuse((StatusCode::FORBIDDEN, "This upload link isn't signed."));
    };
    let secret = match upload::secret(srv).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "couldn't read the upload key");
            return refuse((StatusCode::INTERNAL_SERVER_ERROR, "The server couldn't take the file."));
        }
    };
    if !upload::verify(&secret, &token, expires, sig) {
        return refuse((StatusCode::FORBIDDEN, "This upload link isn't valid."));
    }
    if expires < quark_core::time::now_ms() {
        return refuse((StatusCode::FORBIDDEN, "This upload link has expired. Ask for a new one."));
    }
    let slot = match upload::slot(srv, &token).await {
        Ok(Some(s)) if s.state == STATE_SLOT && s.name == name => s,
        Ok(Some(s)) if s.name == name => return refuse((StatusCode::CONFLICT, "This file was already uploaded.")),
        Ok(_) => return refuse((StatusCode::NOT_FOUND, "There's no upload slot here.")),
        Err(e) => {
            tracing::warn!(error = %e, "couldn't look up an upload slot");
            return refuse((StatusCode::INTERNAL_SERVER_ERROR, "The server couldn't take the file."));
        }
    };
    let Some(length) = headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok()) else {
        return refuse((StatusCode::LENGTH_REQUIRED, "The upload needs a Content-Length."));
    };
    if length != slot.size {
        return refuse((StatusCode::BAD_REQUEST, "The upload must be exactly as big as the slot said."));
    }
    if let Some(ct) = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) {
        if essence(ct) != essence(&slot.ctype) && essence(&slot.ctype) != "application/octet-stream" {
            return refuse((StatusCode::BAD_REQUEST, "The upload's Content-Type doesn't match the slot."));
        }
    }
    match upload::begin_upload(srv, &token).await {
        Ok(true) => {}
        Ok(false) => return refuse((StatusCode::CONFLICT, "This slot is in use or has expired.")),
        Err(e) => {
            tracing::warn!(error = %e, "couldn't claim an upload slot");
            return refuse((StatusCode::INTERNAL_SERVER_ERROR, "The server couldn't take the file."));
        }
    }
    let dir = upload::dir(srv);
    let part = dir.join(format!(".{token}.part"));
    let jpeg = essence(&slot.ctype) == "image/jpeg";
    let stored = match receive(body, &part, slot.size, jpeg).await {
        Ok(n) => n,
        Err(r) => {
            let _ = tokio::fs::remove_file(&part).await;
            upload::abort_upload(srv, &token).await;
            return refuse(r);
        }
    };
    let finished = async {
        tokio::fs::rename(&part, dir.join(&token)).await.map_err(|e| e.to_string())?;
        upload::finish_upload(srv, &token, stored).await.map_err(|e| e.to_string())
    };
    match finished.await {
        Ok(true) => {
            st.stats.uploads.fetch_add(1, Ordering::Relaxed);
            st.stats.upload_bytes.fetch_add(slot.size, Ordering::Relaxed);
            with_cors((StatusCode::CREATED, "Stored.\n").into_response())
        }
        Ok(false) => {
            let _ = tokio::fs::remove_file(dir.join(&token)).await;
            refuse((StatusCode::GONE, "This slot no longer exists."))
        }
        Err(e) => {
            tracing::warn!(error = %e, "couldn't store an upload");
            let _ = tokio::fs::remove_file(&part).await;
            let _ = tokio::fs::remove_file(dir.join(&token)).await;
            upload::abort_upload(srv, &token).await;
            refuse((StatusCode::INTERNAL_SERVER_ERROR, "The server couldn't store the file."))
        }
    }
}

/// Streams the body to `part`, never holding more than a chunk in memory. Returns the bytes
/// written, which is less than `size` when JPEG metadata was stripped.
async fn receive(body: Body, part: &Path, size: u64, jpeg: bool) -> Result<u64, Refusal> {
    let internal = (StatusCode::INTERNAL_SERVER_ERROR, "The server couldn't store the file.");
    let file = tokio::fs::OpenOptions::new().write(true).create_new(true).open(part).await.map_err(|e| {
        tracing::warn!(error = %e, path = %part.display(), "couldn't create an upload file");
        internal
    })?;
    let mut w = tokio::io::BufWriter::with_capacity(WRITE_BUFFER, file);
    let mut stream = body.into_data_stream();
    let mut scrubber = jpeg.then(super::jpeg::Scrubber::new);
    let mut scrubbed = Vec::new();
    let (mut got, mut written) = (0u64, 0u64);
    loop {
        let chunk = match tokio::time::timeout(CHUNK_TIMEOUT, stream.next()).await {
            Err(_) => return Err((StatusCode::REQUEST_TIMEOUT, "The upload stalled.")),
            Ok(None) => break,
            Ok(Some(Err(_))) => return Err((StatusCode::BAD_REQUEST, "The upload was cut off.")),
            Ok(Some(Ok(c))) => c,
        };
        got += chunk.len() as u64;
        if got > size {
            return Err((StatusCode::PAYLOAD_TOO_LARGE, "The upload is bigger than the slot said."));
        }
        let data: &[u8] = match scrubber.as_mut() {
            Some(s) => {
                scrubbed.clear();
                s.push(&chunk, &mut scrubbed);
                &scrubbed
            }
            None => &chunk,
        };
        w.write_all(data).await.map_err(|_| internal)?;
        written += data.len() as u64;
    }
    if got != size {
        return Err((StatusCode::BAD_REQUEST, "The upload is smaller than the slot said."));
    }
    w.flush().await.map_err(|_| internal)?;
    w.get_ref().sync_data().await.map_err(|_| internal)?;
    Ok(written)
}

/// A `Range` header against a file of `len` bytes (RFC 9110 §14). Only single ranges are
/// honored; anything else gets the whole file, as the RFC allows.
#[derive(Debug, PartialEq, Eq)]
enum Range {
    Full,
    /// Inclusive byte offsets.
    Part(u64, u64),
    Unsatisfiable,
}

fn parse_range(h: &str, len: u64) -> Range {
    let Some(spec) = h.trim().strip_prefix("bytes=") else { return Range::Full };
    if spec.contains(',') {
        return Range::Full;
    }
    let Some((a, b)) = spec.trim().split_once('-') else { return Range::Full };
    let (a, b) = (a.trim(), b.trim());
    match (a.parse::<u64>(), b.parse::<u64>()) {
        (Ok(start), Ok(end)) if start <= end => {
            if start >= len {
                Range::Unsatisfiable
            } else {
                Range::Part(start, end.min(len - 1))
            }
        }
        (Ok(start), Err(_)) if b.is_empty() => {
            if start >= len {
                Range::Unsatisfiable
            } else {
                Range::Part(start, len - 1)
            }
        }
        (Err(_), Ok(n)) if a.is_empty() => {
            if n == 0 || len == 0 {
                Range::Unsatisfiable
            } else {
                Range::Part(len.saturating_sub(n), len - 1)
            }
        }
        _ => Range::Full,
    }
}

/// Types a browser may show inline. Everything else downloads, so an uploaded HTML or SVG file
/// can't run script on this origin.
fn inline(ctype: &str) -> bool {
    let e = essence(ctype);
    (e.starts_with("image/") && e != "image/svg+xml")
        || e.starts_with("video/")
        || e.starts_with("audio/")
        || e == "text/plain"
        || e == "application/pdf"
}

fn disposition(s: &Slot) -> String {
    let kind = if inline(&s.ctype) { "inline" } else { "attachment" };
    // An ASCII fallback for old clients, and the exact name for everyone else (RFC 6266).
    let ascii: String = s.name.chars().map(|c| if c.is_ascii_graphic() && c != '"' && c != '\\' || c == ' ' { c } else { '_' }).collect();
    format!("{kind}; filename=\"{ascii}\"; filename*=UTF-8''{}", upload::pct(&s.name))
}

pub(super) async fn get(State(st): AppState, UrlPath((token, _name)): UrlPath<(String, String)>, headers: HeaderMap) -> Response {
    let srv = &st.srv;
    let missing = (StatusCode::NOT_FOUND, "There's no file here (it may have expired).");
    if !upload::valid_token(&token) {
        return refuse(missing);
    }
    let slot = match upload::slot(srv, &token).await {
        Ok(Some(s)) if s.state == STATE_STORED => s,
        Ok(_) => return refuse(missing),
        Err(e) => {
            tracing::warn!(error = %e, "couldn't look up a file");
            return refuse((StatusCode::INTERNAL_SERVER_ERROR, "The server couldn't find the file."));
        }
    };
    let now = quark_core::time::now_ms();
    let expires = upload::expires_at(srv, &slot);
    if expires.is_some_and(|e| e <= now) {
        return refuse(missing);
    }
    let etag = format!("\"{token}\"");
    let max_age = expires.map_or(YEAR_SECS, |e| ((e - now) / 1000).clamp(0, YEAR_SECS));
    let mut h = HeaderMap::new();
    let mut set = |k: header::HeaderName, v: String| {
        if let Ok(v) = HeaderValue::try_from(v) {
            h.insert(k, v);
        }
    };
    set(header::ETAG, etag.clone());
    set(header::CACHE_CONTROL, format!("public, max-age={max_age}, immutable"));
    set(header::LAST_MODIFIED, http_date(slot.created));
    set(header::CONTENT_TYPE, slot.ctype.clone());
    set(header::CONTENT_DISPOSITION, disposition(&slot));
    set(header::ACCEPT_RANGES, "bytes".into());
    set(header::X_CONTENT_TYPE_OPTIONS, "nosniff".into());
    set(header::CONTENT_SECURITY_POLICY, "default-src 'none'; media-src 'self'; img-src 'self'; style-src 'unsafe-inline'; sandbox".into());
    set(header::HeaderName::from_static("cross-origin-resource-policy"), "cross-origin".into());

    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim() == etag || t.trim() == "*"))
    {
        return with_cors((StatusCode::NOT_MODIFIED, h).into_response());
    }
    let path = upload::dir(srv).join(&token);
    let mut file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(_) => return refuse(missing),
    };
    let len = match file.metadata().await {
        Ok(m) => m.len(),
        Err(_) => return refuse(missing),
    };
    let if_range_ok = headers.get(header::IF_RANGE).and_then(|v| v.to_str().ok()).is_none_or(|v| v.trim() == etag);
    let range = match headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        Some(r) if if_range_ok => parse_range(r, len),
        _ => Range::Full,
    };
    let (status, start, count) = match range {
        Range::Full => (StatusCode::OK, 0, len),
        Range::Part(a, b) => {
            set(header::CONTENT_RANGE, format!("bytes {a}-{b}/{len}"));
            (StatusCode::PARTIAL_CONTENT, a, b - a + 1)
        }
        Range::Unsatisfiable => {
            set(header::CONTENT_RANGE, format!("bytes */{len}"));
            h.remove(header::CONTENT_TYPE);
            return with_cors((StatusCode::RANGE_NOT_SATISFIABLE, h).into_response());
        }
    };
    if start > 0 && file.seek(SeekFrom::Start(start)).await.is_err() {
        return refuse((StatusCode::INTERNAL_SERVER_ERROR, "The server couldn't read the file."));
    }
    set(header::CONTENT_LENGTH, count.to_string());
    let stream = tokio_util::io::ReaderStream::with_capacity(tokio::io::AsyncReadExt::take(file, count), READ_BUFFER);
    with_cors((status, h, Body::from_stream(stream)).into_response())
}

/// An IMF-fixdate (RFC 9110 §5.6.7) for a time in ms since the epoch.
fn http_date(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    const WD: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MON: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    format!(
        "{}, {day:02} {} {year} {:02}:{:02}:{:02} GMT",
        WD[days.rem_euclid(7) as usize],
        MON[(month - 1).clamp(0, 11) as usize],
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert_eq!(parse_range("bytes=0-9", 100), Range::Part(0, 9));
        assert_eq!(parse_range("bytes=90-200", 100), Range::Part(90, 99));
        assert_eq!(parse_range("bytes=50-", 100), Range::Part(50, 99));
        assert_eq!(parse_range("bytes=-10", 100), Range::Part(90, 99));
        assert_eq!(parse_range("bytes=-500", 100), Range::Part(0, 99));
        assert_eq!(parse_range("bytes=100-", 100), Range::Unsatisfiable);
        assert_eq!(parse_range("bytes=-0", 100), Range::Unsatisfiable);
        assert_eq!(parse_range("bytes=5-1", 100), Range::Full);
        assert_eq!(parse_range("bytes=0-1,5-6", 100), Range::Full);
        assert_eq!(parse_range("items=0-1", 100), Range::Full);
        assert_eq!(parse_range("bytes=x-y", 100), Range::Full);
        assert_eq!(parse_range("bytes=0-0", 0), Range::Unsatisfiable);
    }

    #[test]
    fn dates() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(784_111_777_000), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(http_date(1_709_210_096_000), "Thu, 29 Feb 2024 12:34:56 GMT");
    }

    #[test]
    fn active_content_downloads() {
        assert!(inline("image/jpeg"));
        assert!(inline("video/mp4"));
        assert!(!inline("image/svg+xml"));
        assert!(!inline("text/html"));
        assert!(!inline("application/octet-stream"));
    }
}
