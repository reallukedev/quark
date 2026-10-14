//! XEP-0363 HTTP File Upload. Black-box: written from the XEP only.

mod blind_xep;

use anyhow::{bail, ensure, Context as _};
use blind_xep::*;
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{http_request, Client, HttpResponse, TestServer, VIA_TLS_PROXY};

async fn server() -> anyhow::Result<(TestServer, Client)> {
    let s = TestServer::start().await?;
    s.add_user("alice", PW).await?;
    let c = s.login("alice", PW).await?;
    Ok((s, c))
}

/// §3: finds the upload service among the server's disco items; returns its JID and the
/// max-file-size it announces.
async fn find_service(c: &mut Client, domain: &str) -> anyhow::Result<(String, Option<u64>)> {
    for item in disco_items(c, Some(domain)).await? {
        let info = disco_info(c, Some(&item)).await?;
        if !disco_features(&info).iter().any(|f| f == ns::HTTP_UPLOAD) {
            continue;
        }
        let q = info.get_child("query", ns::DISCO_INFO).context("no query")?;
        let max = q
            .children()
            .filter(|x| x.is("x", ns::DATA_FORMS))
            .find(|x| form_type(x).as_deref() == Some(ns::HTTP_UPLOAD))
            .and_then(|x| field_values(x, "max-file-size").into_iter().next())
            .map(|v| v.trim().parse::<u64>())
            .transpose()?;
        return Ok((item, max));
    }
    bail!("no item of {domain} advertises {}", ns::HTTP_UPLOAD)
}

struct Slot {
    put: String,
    get: String,
    headers: Vec<(String, String)>,
}

fn slot_request(name: &str, size: u64, content_type: Option<&str>) -> Element {
    Element::new("request", ns::HTTP_UPLOAD)
        .attr_set("filename", name)
        .attr_set("size", size.to_string())
        .attr_opt("content-type", content_type)
}

async fn slot(c: &mut Client, service: &str, name: &str, size: u64, content_type: Option<&str>) -> anyhow::Result<Slot> {
    let r = c.iq_get(Some(service), slot_request(name, size, content_type)).await?;
    ensure!(is_result(&r), "slot request failed: {r}");
    let slot = r.get_child("slot", ns::HTTP_UPLOAD).with_context(|| format!("no slot: {r}"))?;
    let put = slot.get_child("put", ns::HTTP_UPLOAD).context("no put")?;
    let get = slot.get_child("get", ns::HTTP_UPLOAD).context("no get")?;
    let headers = put
        .children()
        .filter(|h| h.is("header", ns::HTTP_UPLOAD))
        .map(|h| (h.attr("name").unwrap_or("").to_string(), h.text_content()))
        .collect();
    Ok(Slot { put: put.attr("url").context("no put url")?.to_string(), get: get.attr("url").context("no get url")?.to_string(), headers })
}

/// Splits an absolute URL into (host, path).
fn split_url(url: &str) -> anyhow::Result<(String, String)> {
    let rest = url.split_once("://").map(|(_, r)| r).context("not absolute")?;
    let (host, path) = rest.find('/').map_or((rest, "/"), |i| (&rest[..i], &rest[i..]));
    Ok((host.to_string(), path.to_string()))
}

/// Sends a request for `url` to the web listener, as a TLS proxy in front of it would.
async fn http(s: &TestServer, method: &str, url: &str, extra: &[(&str, &str)], body: &[u8]) -> anyhow::Result<HttpResponse> {
    let (host, path) = split_url(url)?;
    let mut headers = vec![("Host", host.as_str()), VIA_TLS_PROXY];
    headers.extend_from_slice(extra);
    http_request(s.web(), method, &path, &headers, body).await
}

async fn put(s: &TestServer, slot: &Slot, body: &[u8], content_type: Option<&str>, length: Option<usize>) -> anyhow::Result<HttpResponse> {
    let len = length.unwrap_or(body.len()).to_string();
    let mut extra: Vec<(&str, &str)> = vec![("Content-Length", len.as_str())];
    if let Some(ct) = content_type {
        extra.push(("Content-Type", ct));
    }
    for (k, v) in &slot.headers {
        extra.push((k.as_str(), v.as_str()));
    }
    http(s, "PUT", &slot.put, &extra, body).await
}

/// A URL like `url` but with its next-to-last path segment (or file name) changed.
fn mangle(url: &str) -> String {
    let (base, last) = url.rsplit_once('/').unwrap_or((url, ""));
    match base.rsplit_once('/') {
        Some((head, seg)) if !seg.is_empty() && !head.ends_with('/') => format!("{head}/zz{seg}zz/{last}"),
        _ => format!("{url}-missing"),
    }
}

/// §3: the service is listed in the server's disco#items, advertises the feature and a
/// max-file-size form (XEP-0128).
#[tokio::test]
async fn service_discovery() -> anyhow::Result<()> {
    let (s, mut c) = server().await?;
    let (service, max) = find_service(&mut c, s.domain()).await?;
    let max = max.context("no max-file-size in the upload form")?;
    ensure!(max > 0, "max-file-size {max} for {service}");
    Ok(())
}

/// §4 / §7: slot, PUT (201), GET returns the same bytes, for anyone with the URL.
#[tokio::test]
async fn upload_and_download_roundtrip() -> anyhow::Result<()> {
    let (s, mut c) = server().await?;
    let (service, _) = find_service(&mut c, s.domain()).await?;
    let data: Vec<u8> = (0..=255u8).cycle().take(3000).collect();
    let sl = slot(&mut c, &service, "blob näme.bin", data.len() as u64, Some("application/octet-stream")).await?;
    ensure!(sl.put.starts_with("https://") && sl.get.starts_with("https://"), "§4: HTTPS URLs: {} {}", sl.put, sl.get);
    for (k, _) in &sl.headers {
        ensure!(["authorization", "cookie", "expires"].contains(&k.to_ascii_lowercase().as_str()), "§4: header {k} isn't allowed");
    }

    let r = put(&s, &sl, &data, Some("application/octet-stream"), None).await?;
    assert_eq!(r.status, 201, "§7: PUT must answer 201: {}", r.text());

    let r = http(&s, "GET", &sl.get, &[], b"").await?;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.body, data, "GET returns the uploaded bytes");

    // Another user (no cookies, nothing but the URL) gets it too.
    s.add_user("bob", PW).await?;
    let mut bob = s.login("bob", PW).await?;
    let (service_b, _) = find_service(&mut bob, s.domain()).await?;
    assert_eq!(service_b, service);
    let r = http(&s, "GET", &sl.get, &[], b"").await?;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, data);
    Ok(())
}

/// §6: a too-large request is refused (modify / not-acceptable) with `<file-too-large/>`
/// carrying the limit.
#[tokio::test]
async fn oversized_request_is_refused_with_max() -> anyhow::Result<()> {
    let (s, mut c) = server().await?;
    let (service, max) = find_service(&mut c, s.domain()).await?;
    let max = max.context("no max-file-size advertised")?;
    let r = c.iq_get(Some(&service), slot_request("huge.bin", max + 1, Some("application/octet-stream"))).await?;
    assert_eq!(r.attr("type"), Some("error"), "{r}");
    let (kind, cond) = error_of(&r).context("no condition")?;
    assert_eq!(cond, "not-acceptable", "{r}");
    assert_eq!(kind, "modify", "{r}");
    let too = app_error(&r, ns::HTTP_UPLOAD).with_context(|| format!("no file-too-large: {r}"))?;
    assert_eq!(too.name(), "file-too-large", "{r}");
    assert_eq!(too.child_text("max-file-size", ns::HTTP_UPLOAD).map(|v| v.trim().to_string()), Some(max.to_string()), "{r}");

    // Exactly the limit is fine.
    let r = c.iq_get(Some(&service), slot_request("max.bin", max, None)).await?;
    ensure!(is_result(&r), "a request of exactly max-file-size is allowed: {r}");
    Ok(())
}

/// §4: `size` and `filename` are required.
#[tokio::test]
async fn request_without_size_is_an_error() -> anyhow::Result<()> {
    let (s, mut c) = server().await?;
    let (service, _) = find_service(&mut c, s.domain()).await?;
    let r = c.iq_get(Some(&service), Element::new("request", ns::HTTP_UPLOAD).attr_set("filename", "a.txt")).await?;
    assert_eq!(r.attr("type"), Some("error"), "{r}");
    let r = c.iq_get(Some(&service), Element::new("request", ns::HTTP_UPLOAD).attr_set("size", "10")).await?;
    assert_eq!(r.attr("type"), Some("error"), "{r}");
    Ok(())
}

/// §7: the upload MUST be rejected when Content-Length doesn't match the requested size;
/// nothing is served afterwards.
#[tokio::test]
async fn put_with_wrong_length_is_rejected() -> anyhow::Result<()> {
    let (s, mut c) = server().await?;
    let (service, _) = find_service(&mut c, s.domain()).await?;

    let sl = slot(&mut c, &service, "ten.txt", 10, Some("text/plain")).await?;
    let r = put(&s, &sl, b"eleven byte", Some("text/plain"), None).await?;
    ensure!((400..500).contains(&r.status), "11 bytes for a 10-byte slot: HTTP {} {}", r.status, r.text());
    let r = http(&s, "GET", &sl.get, &[], b"").await?;
    ensure!(r.status != 200, "a rejected upload must not be served: HTTP {}", r.status);

    let sl = slot(&mut c, &service, "ten2.txt", 10, Some("text/plain")).await?;
    let r = put(&s, &sl, b"nine byte", Some("text/plain"), None).await?;
    ensure!((400..500).contains(&r.status), "9 bytes for a 10-byte slot: HTTP {} {}", r.status, r.text());

    // The slot still works with the right size afterwards, or is spent; either way a correct
    // upload to a fresh slot works.
    let sl = slot(&mut c, &service, "ten3.txt", 10, Some("text/plain")).await?;
    let r = put(&s, &sl, b"0123456789", Some("text/plain"), None).await?;
    assert_eq!(r.status, 201, "{}", r.text());
    Ok(())
}

/// A PUT to a URL the service never handed out isn't accepted; a GET of an unknown file is
/// 404.
#[tokio::test]
async fn unknown_urls() -> anyhow::Result<()> {
    let (s, mut c) = server().await?;
    let (service, _) = find_service(&mut c, s.domain()).await?;
    let sl = slot(&mut c, &service, "real.txt", 4, Some("text/plain")).await?;

    let forged = Slot { put: mangle(&sl.put), get: mangle(&sl.get), headers: sl.headers.clone() };
    ensure!(forged.put != sl.put);
    // (A reset connection also means "not accepted"; `rejected_put_gets_a_response` checks
    // the response itself.)
    if let Ok(r) = put(&s, &forged, b"evil", Some("text/plain"), None).await {
        ensure!(!(200..300).contains(&r.status), "PUT to an unissued URL {} was accepted: HTTP {}", forged.put, r.status);
    }

    let r = http(&s, "GET", &sl.get, &[], b"").await?;
    assert_eq!(r.status, 404, "GET before the upload: {}", r.text());
    let r = http(&s, "GET", &forged.get, &[], b"").await?;
    assert_eq!(r.status, 404, "GET of an unknown file {}: {}", forged.get, r.text());
    Ok(())
}

/// The slot URL carries its own expiry; moving it into the past (or otherwise touching the
/// signed query) must not yield a usable upload URL (§8: PUT URLs time out).
#[tokio::test]
async fn tampered_or_expired_put_url_is_refused() -> anyhow::Result<()> {
    let (s, mut c) = server().await?;
    let (service, _) = find_service(&mut c, s.domain()).await?;
    let sl = slot(&mut c, &service, "late.txt", 4, Some("text/plain")).await?;
    let Some((base, query)) = sl.put.split_once('?') else { return Ok(()) };
    let past: Vec<String> = query
        .split('&')
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) if v.len() >= 10 && v.chars().all(|ch| ch.is_ascii_digit()) => format!("{k}=1000"),
            _ => kv.to_string(),
        })
        .collect();
    let late = Slot { put: format!("{base}?{}", past.join("&")), get: sl.get.clone(), headers: sl.headers.clone() };
    if late.put == sl.put {
        return Ok(()); // no timestamp in the URL to move
    }
    if let Ok(r) = put(&s, &late, b"late", Some("text/plain"), None).await {
        ensure!(!(200..300).contains(&r.status), "PUT with an expired/tampered URL {} was accepted: HTTP {}", late.put, r.status);
    }
    let r = http(&s, "GET", &sl.get, &[], b"").await?;
    assert_eq!(r.status, 404, "nothing was stored");
    Ok(())
}

/// RFC 9112 §9.6: a server refusing an upload early should close in stages so the client
/// can still read its error response, instead of resetting the connection over the unread
/// body. (The client here keeps reading while it writes, as RFC 9112 §9.5 asks of clients.)
#[tokio::test]
async fn rejected_put_gets_a_response() -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let (s, mut c) = server().await?;
    let (service, _) = find_service(&mut c, s.domain()).await?;
    let body = vec![b'x'; 4 << 20];
    let sl = slot(&mut c, &service, "big.bin", body.len() as u64, None).await?;
    let (host, path) = split_url(&mangle(&sl.put))?;
    let mut head = format!("PUT {path} HTTP/1.1\r\nHost: {host}\r\nX-Forwarded-Proto: https\r\nContent-Length: {}\r\n", body.len());
    for (k, v) in &sl.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("Connection: close\r\n\r\n");
    let (mut rd, mut wr) = tokio::net::TcpStream::connect(s.web()).await?.into_split();
    let writer = tokio::spawn(async move {
        let _ = wr.write_all(head.as_bytes()).await;
        let _ = wr.write_all(&body).await;
    });
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    let read = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => return Ok(()),
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(e) => return Err(e),
            }
        }
    })
    .await;
    writer.abort();
    let text = String::from_utf8_lossy(&got).into_owned();
    let status = text.split(' ').nth(1).and_then(|c| c.parse::<u16>().ok());
    ensure!(
        status.is_some_and(|c| (400..500).contains(&c)),
        "no 4xx response readable before the connection ended ({read:?}); got {text:?}"
    );
    Ok(())
}
