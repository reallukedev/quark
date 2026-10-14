//! Helpers shared by the black-box conformance tests (`blind_*.rs`).
//!
//! Everything here is written from the RFCs and XEPs, not from the server's code.

#![allow(dead_code)]

use std::time::Duration;

use anyhow::{bail, Context as _};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{Client, ScramClient, TestServer, DOMAIN, TIMEOUT};

/// Short wait used to check that something is *not* delivered.
pub const QUIET: Duration = Duration::from_millis(400);

pub const SM: &str = "urn:xmpp:sm:3";
pub const CSI: &str = "urn:xmpp:csi:0";
pub const SASL2: &str = "urn:xmpp:sasl:2";
pub const BIND2: &str = "urn:xmpp:bind:0";
pub const FAST: &str = "urn:xmpp:fast:0";
pub const SASL_CB: &str = "urn:xmpp:sasl-cb:0";
pub const CHAT_STATES: &str = "http://jabber.org/protocol/chatstates";

pub fn b64(data: impl AsRef<[u8]>) -> String {
    B64.encode(data)
}

pub fn unb64(text: &str) -> anyhow::Result<Vec<u8>> {
    let t = text.trim();
    if t == "=" {
        return Ok(Vec::new());
    }
    Ok(B64.decode(t)?)
}

/// A client stream header (RFC 6120 §4.7) with the given pieces.
pub fn header_with(to: &str, stream_ns: &str, content_ns: &str, version: Option<&str>) -> String {
    let version = version.map(|v| format!(" version='{v}'")).unwrap_or_default();
    format!("<stream:stream xmlns='{content_ns}' xmlns:stream='{stream_ns}' to='{to}'{version}>")
}

/// A normal client stream header for `to`.
pub fn header(to: &str) -> String {
    header_with(to, ns::STREAM, ns::CLIENT, Some("1.0"))
}

/// The defined condition of a `<stream:error/>`, if `el` is one.
pub fn stream_error_condition(el: &Element) -> Option<String> {
    if !el.is("error", ns::STREAM) {
        return None;
    }
    el.children().find(|c| c.ns() == ns::STREAMS && c.name() != "text").map(|c| c.name().to_string())
}

/// The condition of a SASL `<failure/>` (RFC 6120 or XEP-0388), if `el` is one.
pub fn sasl_failure_condition(el: &Element) -> Option<String> {
    if el.name() != "failure" || (el.ns() != ns::SASL && el.ns() != SASL2) {
        return None;
    }
    el.children().find(|c| c.ns() == ns::SASL && c.name() != "text").map(|c| c.name().to_string())
}

/// `(type, condition)` of the `<error/>` in a stanza of type error.
pub fn stanza_error(el: &Element) -> Option<(String, String)> {
    let e = el.get_child("error", ns::CLIENT)?;
    let cond = e.children().find(|c| c.ns() == ns::STANZAS && c.name() != "text")?;
    Some((e.attr("type").unwrap_or_default().to_string(), cond.name().to_string()))
}

/// Reads the next element and asserts it is a stream error with one of `conds`, then that the
/// server closes the stream (RFC 6120 §4.9.1.1: the stream error is followed by the close).
pub async fn expect_stream_error(c: &mut Client, conds: &[&str]) -> anyhow::Result<Element> {
    let el = c.recv().await.context("waiting for a stream error")?;
    let Some(cond) = stream_error_condition(&el) else { bail!("expected a stream error ({conds:?}), got {el}") };
    if !conds.contains(&cond.as_str()) {
        bail!("expected stream error {conds:?}, got {el}");
    }
    expect_closed(c).await?;
    Ok(el)
}

/// Asserts the server closes the stream or connection within the kit's timeout.
pub async fn expect_closed(c: &mut Client) -> anyhow::Result<()> {
    match c.recv_within(TIMEOUT).await {
        Err(_) => Ok(()),
        Ok(None) => bail!("the server did not close the stream"),
        Ok(Some(e)) => bail!("expected the stream to close, got {e}"),
    }
}

/// Reads and discards whatever arrives until the stream is quiet for `QUIET`.
pub async fn drain(c: &mut Client) -> anyhow::Result<Vec<Element>> {
    let mut got = Vec::new();
    while let Some(e) = c.recv_within(QUIET).await? {
        got.push(e);
    }
    Ok(got)
}

/// Connects and does STARTTLS.
pub async fn tls_client(s: &TestServer) -> anyhow::Result<Client> {
    let mut c = Client::connect(s.c2s(), DOMAIN).await?;
    c.starttls().await?;
    Ok(c)
}

/// Connects, does STARTTLS and SASL (SCRAM-SHA-256), without binding.
pub async fn authed_client(s: &TestServer, user: &str, pw: &str) -> anyhow::Result<Client> {
    let mut c = tls_client(s).await?;
    c.auth_scram("SCRAM-SHA-256", user, pw).await?;
    Ok(c)
}

/// The child of the current stream features with that name and namespace.
pub fn feature<'a>(c: &'a Client, name: &str, namespace: &str) -> Option<&'a Element> {
    c.features.as_ref()?.get_child(name, namespace)
}

pub fn has_feature(c: &Client, name: &str, namespace: &str) -> bool {
    feature(c, name, namespace).is_some()
}

/// What a SASL exchange ended with.
#[derive(Debug)]
pub enum SaslEnd {
    /// `<success/>` (the stream has not been restarted).
    Success(Element),
    /// `<failure/>`.
    Failure(Element),
    /// A stream error.
    StreamError(Element),
}

impl SaslEnd {
    pub fn failure_condition(&self) -> Option<String> {
        match self {
            SaslEnd::Failure(f) => sasl_failure_condition(f),
            _ => None,
        }
    }
}

fn classify(el: Element) -> anyhow::Result<SaslEnd> {
    if el.name() == "success" && (el.ns() == ns::SASL || el.ns() == SASL2) {
        Ok(SaslEnd::Success(el))
    } else if el.name() == "failure" && (el.ns() == ns::SASL || el.ns() == SASL2) {
        Ok(SaslEnd::Failure(el))
    } else if el.is("error", ns::STREAM) {
        Ok(SaslEnd::StreamError(el))
    } else {
        bail!("unexpected element during SASL: {el}")
    }
}

/// One RFC 6120 SCRAM attempt; checks the server signature on success. Does not restart.
pub async fn scram_attempt(c: &mut Client, mech: &str, user: &str, pw: &str, cb: Option<Vec<u8>>) -> anyhow::Result<SaslEnd> {
    let mut scram = ScramClient::new(mech, user, pw, cb)?;
    c.send(&Element::new("auth", ns::SASL).attr_set("mechanism", mech).text(b64(scram.client_first()))).await?;
    let ch = c.recv().await?;
    if !ch.is("challenge", ns::SASL) {
        return classify(ch);
    }
    let server_first = String::from_utf8(unb64(&ch.text_content())?)?;
    let fin = scram.client_final(&server_first)?;
    c.send(&Element::new("response", ns::SASL).text(b64(fin))).await?;
    let end = classify(c.recv().await?)?;
    if let SaslEnd::Success(s) = &end {
        scram.verify_server(&String::from_utf8(unb64(&s.text_content())?)?)?;
    }
    Ok(end)
}

// --- A hand-rolled SCRAM-SHA-256 so tests can send GS2 headers the kit's client never sends. ---

fn hmac256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::Mac;
    let mut m = <hmac::Hmac<sha2::Sha256>>::new_from_slice(key).expect("any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac256(key, data)
}

/// SCRAM-SHA-256 with an arbitrary GS2 header (e.g. `y,,`) and channel binding data.
pub async fn scram256_custom(c: &mut Client, gs2: &str, cb_data: &[u8], user: &str, pw: &str) -> anyhow::Result<SaslEnd> {
    use sha2::Digest;
    let nonce = format!("blind{}", quark_testkit::quark_core::new_id().replace(|ch: char| !ch.is_ascii_alphanumeric(), ""));
    let bare = format!("n={user},r={nonce}");
    let mech = if gs2.starts_with('p') { "SCRAM-SHA-256-PLUS" } else { "SCRAM-SHA-256" };
    c.send(&Element::new("auth", ns::SASL).attr_set("mechanism", mech).text(b64(format!("{gs2}{bare}")))).await?;
    let ch = c.recv().await?;
    if !ch.is("challenge", ns::SASL) {
        return classify(ch);
    }
    let server_first = String::from_utf8(unb64(&ch.text_content())?)?;
    let mut r = None;
    let mut salt = None;
    let mut iters = None;
    for p in server_first.split(',') {
        if let Some(v) = p.strip_prefix("r=") {
            r = Some(v.to_string());
        } else if let Some(v) = p.strip_prefix("s=") {
            salt = Some(unb64(v)?);
        } else if let Some(v) = p.strip_prefix("i=") {
            iters = Some(v.parse::<u32>()?);
        }
    }
    let (r, salt, iters) = (r.context("nonce")?, salt.context("salt")?, iters.context("iterations")?);
    let salted = pbkdf2::pbkdf2_hmac_array::<sha2::Sha256, 32>(pw.as_bytes(), &salt, iters);
    let client_key = hmac256(&salted, b"Client Key");
    let stored = sha2::Sha256::digest(&client_key).to_vec();
    let mut cbind = gs2.as_bytes().to_vec();
    cbind.extend_from_slice(cb_data);
    let without = format!("c={},r={r}", b64(cbind));
    let auth = format!("{bare},{server_first},{without}");
    let sig = hmac256(&stored, auth.as_bytes());
    let proof: Vec<u8> = client_key.iter().zip(&sig).map(|(a, b)| a ^ b).collect();
    c.send(&Element::new("response", ns::SASL).text(b64(format!("{without},p={}", b64(proof))))).await?;
    classify(c.recv().await?)
}

// --- SASL2 (XEP-0388), Bind2 (XEP-0386), FAST (XEP-0484). ---

/// `<user-agent id='…'><software/><device/></user-agent>`.
pub fn user_agent(id: &str) -> Element {
    Element::new("user-agent", SASL2)
        .attr_set("id", id)
        .text_child("software", SASL2, "Blind Conformance")
        .text_child("device", SASL2, "CI")
}

/// A Bind2 request with a tag and inline feature requests.
pub fn bind2(tag: &str, inline: Vec<Element>) -> Element {
    let mut b = Element::new("bind", BIND2).text_child("tag", BIND2, tag);
    for e in inline {
        b.append(e);
    }
    b
}

/// A fresh UUID-like id for user agents.
pub fn agent_id() -> String {
    let a: u128 = rand::random();
    let h = format!("{a:032x}");
    format!("{}-{}-4{}-a{}-{}", &h[0..8], &h[8..12], &h[13..16], &h[17..20], &h[20..32])
}

/// SASL2 authentication with SCRAM-SHA-256; `extra` children go into `<authenticate/>`.
/// Verifies the server signature in `<additional-data/>` on success.
pub async fn sasl2_scram(c: &mut Client, user: &str, pw: &str, extra: Vec<Element>) -> anyhow::Result<SaslEnd> {
    let mut scram = ScramClient::new("SCRAM-SHA-256", user, pw, None)?;
    let mut auth = Element::new("authenticate", SASL2).attr_set("mechanism", "SCRAM-SHA-256").text_child(
        "initial-response",
        SASL2,
        b64(scram.client_first()),
    );
    for e in extra {
        auth.append(e);
    }
    c.send(&auth).await?;
    loop {
        let el = c.recv().await?;
        if el.is("challenge", SASL2) {
            let server_first = String::from_utf8(unb64(&el.text_content())?)?;
            let fin = scram.client_final(&server_first)?;
            c.send(&Element::new("response", SASL2).text(b64(fin))).await?;
            continue;
        }
        let end = classify(el)?;
        if let SaslEnd::Success(s) = &end {
            let data = s.child_text("additional-data", SASL2).context("SASL2 SCRAM success without <additional-data/>")?;
            scram.verify_server(&String::from_utf8(unb64(&data)?)?)?;
        }
        return Ok(end);
    }
}

/// The `<authorization-identifier/>` of a SASL2 success.
pub fn authz_id(success: &Element) -> Option<String> {
    success.child_text("authorization-identifier", SASL2)
}

/// Finds a descendant (depth-first) with that name and namespace.
pub fn find_deep<'a>(el: &'a Element, name: &str, namespace: &str) -> Option<&'a Element> {
    if el.name() == name && el.ns() == namespace {
        return Some(el);
    }
    el.children().find_map(|c| find_deep(c, name, namespace))
}

// --- Stream management (XEP-0198). ---

/// Sends `<enable/>` and returns the server's answer (`<enabled/>` or `<failed/>`).
pub async fn sm_enable(c: &mut Client, resume: bool) -> anyhow::Result<Element> {
    let mut e = Element::new("enable", SM);
    if resume {
        e.set_attr("resume", "true");
    }
    c.send(&e).await?;
    c.expect(|e| e.ns() == SM && (e.name() == "enabled" || e.name() == "failed")).await
}

/// Sends `<r/>` and returns the `h` of the server's `<a/>`.
pub async fn sm_request_ack(c: &mut Client) -> anyhow::Result<u32> {
    c.send(&Element::new("r", SM)).await?;
    let a = c.expect(|e| e.is("a", SM)).await?;
    Ok(a.attr("h").context("<a/> without h")?.parse()?)
}

pub fn is_true(v: Option<&str>) -> bool {
    matches!(v, Some("true" | "1"))
}

// --- Time (XEP-0082). ---

/// Seconds since the Unix epoch for an XEP-0082 DateTime like `2026-10-13T12:00:00.123Z`.
pub fn parse_xep82(s: &str) -> anyhow::Result<i64> {
    let (date, time) = s.split_once('T').context("no T")?;
    let mut d = date.split('-');
    let y: i64 = d.next().context("year")?.parse()?;
    let m: i64 = d.next().context("month")?.parse()?;
    let day: i64 = d.next().context("day")?.parse()?;
    let (clock, offset) = if let Some(c) = time.strip_suffix('Z') {
        (c, 0)
    } else {
        let i = time.rfind(['+', '-']).context("no zone")?;
        let (c, z) = time.split_at(i);
        let sign = if z.starts_with('-') { -1 } else { 1 };
        let (zh, zm) = z[1..].split_once(':').context("zone format")?;
        (c, sign * (zh.parse::<i64>()? * 3600 + zm.parse::<i64>()? * 60))
    };
    let mut t = clock.split(':');
    let hh: i64 = t.next().context("hour")?.parse()?;
    let mm: i64 = t.next().context("minute")?.parse()?;
    let ss: f64 = t.next().context("second")?.parse()?;
    // Days from civil (Howard Hinnant).
    let (y2, m2) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * m2 + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Ok(days * 86400 + hh * 3600 + mm * 60 + ss as i64 - offset)
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or_default()
}
