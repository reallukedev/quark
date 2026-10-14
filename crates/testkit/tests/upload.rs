//! HTTP File Upload (XEP-0363): discovery, slots, PUT, GET with ranges, limits and expiry.

use std::net::SocketAddr;
use std::time::Duration;

use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{http_request, Client, Options, TestServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SERVICE: &str = "upload.quark.test";

fn slot_request(name: &str, size: u64, ctype: Option<&str>) -> Element {
    Element::new("request", ns::HTTP_UPLOAD).attr_set("filename", name).attr_set("size", size.to_string()).attr_opt("content-type", ctype)
}

/// (put path, get path) from a slot, relative to the web listener.
async fn slot(c: &mut Client, name: &str, size: u64, ctype: Option<&str>) -> anyhow::Result<(String, String)> {
    let r = c.iq_get(Some(SERVICE), slot_request(name, size, ctype)).await?;
    anyhow::ensure!(r.attr("type") == Some("result"), "slot refused: {r}");
    let slot = r.get_child("slot", ns::HTTP_UPLOAD).expect("a slot");
    let put = slot.get_child("put", ns::HTTP_UPLOAD).and_then(|p| p.attr("url")).expect("a put url");
    let get = slot.get_child("get", ns::HTTP_UPLOAD).and_then(|p| p.attr("url")).expect("a get url");
    let strip = |u: &str| u.strip_prefix("https://quark.test").expect("urls on the domain").to_string();
    Ok((strip(put), strip(get)))
}

fn error_condition(r: &Element) -> Option<String> {
    r.get_child("error", ns::CLIENT)?.children().find(|c| c.ns() == ns::STANZAS && c.name() != "text").map(|c| c.name().to_string())
}

#[tokio::test]
async fn the_upload_service_is_discoverable() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    let mut alice = s.login("alice", "password-a").await?;
    let items = alice.iq_get(Some(s.domain()), Element::new("query", ns::DISCO_ITEMS)).await?;
    let q = items.get_child("query", ns::DISCO_ITEMS).unwrap();
    assert!(q.children().any(|i| i.attr("jid") == Some(SERVICE)), "{items}");

    let info = alice.iq_get(Some(SERVICE), Element::new("query", ns::DISCO_INFO)).await?;
    let q = info.get_child("query", ns::DISCO_INFO).unwrap();
    assert!(q.children().any(|c| c.name() == "identity" && c.attr("category") == Some("store") && c.attr("type") == Some("file")));
    assert!(q.children().any(|c| c.name() == "feature" && c.attr("var") == Some(ns::HTTP_UPLOAD)));
    let form = q.get_child("x", ns::DATA_FORMS).expect("the size form");
    let max = form.children().find(|f| f.attr("var") == Some("max-file-size")).and_then(|f| f.child_text("value", ns::DATA_FORMS));
    assert_eq!(max.as_deref(), Some("104857600"));
    Ok(())
}

#[tokio::test]
async fn upload_then_download_with_ranges_and_caching() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    let mut alice = s.login("alice", "password-a").await?;
    let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    let (put, get) = slot(&mut alice, "../Holiday notes ü.txt", data.len() as u64, Some("text/plain")).await?;
    assert!(get.starts_with("/upload/"));
    assert!(get.ends_with("/Holiday%20notes%20%C3%BC.txt"), "the name is cleaned and encoded: {get}");

    // Nothing to fetch until it's uploaded.
    assert_eq!(http_request(s.web(), "GET", &get, &[], b"").await?.status, 404);
    let r = http_request(s.web(), "PUT", &put, &[("Content-Type", "text/plain")], &data).await?;
    assert_eq!(r.status, 201, "{}", r.text());
    assert_eq!(r.header("access-control-allow-origin"), Some("*"));

    let r = http_request(s.web(), "GET", &get, &[], b"").await?;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, data);
    assert_eq!(r.header("content-type"), Some("text/plain"));
    assert_eq!(r.header("content-length"), Some("10000"));
    assert_eq!(r.header("accept-ranges"), Some("bytes"));
    assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
    assert!(r.header("cache-control").is_some_and(|c| c.contains("max-age=")));
    assert!(r
        .header("content-disposition")
        .is_some_and(|d| d.starts_with("inline") && d.contains("filename*=UTF-8''Holiday%20notes%20%C3%BC.txt")));
    let etag = r.header("etag").expect("an etag").to_string();

    let r = http_request(s.web(), "GET", &get, &[("Range", "bytes=100-199")], b"").await?;
    assert_eq!(r.status, 206);
    assert_eq!(r.body, &data[100..200]);
    assert_eq!(r.header("content-range"), Some("bytes 100-199/10000"));
    let r = http_request(s.web(), "GET", &get, &[("Range", "bytes=-10")], b"").await?;
    assert_eq!(r.body, &data[9990..]);
    let r = http_request(s.web(), "GET", &get, &[("Range", "bytes=20000-")], b"").await?;
    assert_eq!(r.status, 416);
    assert_eq!(r.header("content-range"), Some("bytes */10000"));

    let r = http_request(s.web(), "HEAD", &get, &[], b"").await?;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-length"), Some("10000"));
    let r = http_request(s.web(), "GET", &get, &[("If-None-Match", &etag)], b"").await?;
    assert_eq!(r.status, 304);
    assert!(r.body.is_empty());

    // A slot is good for one upload.
    let r = http_request(s.web(), "PUT", &put, &[("Content-Length", "10000")], b"").await?;
    assert_eq!(r.status, 409);
    Ok(())
}

#[tokio::test]
async fn uploads_must_match_their_slot() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    let mut alice = s.login("alice", "password-a").await?;
    let (put, get) = slot(&mut alice, "a.bin", 100, None).await?;

    let r = http_request(s.web(), "PUT", &put, &[("Content-Length", "99")], b"").await?;
    assert_eq!(r.status, 400, "a different length is refused before reading");
    // Refused before the body is read, so these send only the headers.
    let announce = [("Content-Length", "100")];
    let forged = format!("{}0", put);
    assert_eq!(http_request(s.web(), "PUT", &forged, &announce, b"").await?.status, 403);
    let unsigned = put.split('?').next().unwrap().to_string();
    assert_eq!(http_request(s.web(), "PUT", &unsigned, &announce, b"").await?.status, 403);
    let renamed = put.replace("/a.bin?", "/b.bin?");
    assert_eq!(http_request(s.web(), "PUT", &renamed, &announce, b"").await?.status, 404);
    let r = http_request(s.web(), "PUT", &put, &[("Content-Type", "image/png")], &[0u8; 100]).await?;
    assert_eq!(r.status, 201, "octet-stream slots take any type: {}", r.text());
    assert_eq!(
        http_request(s.web(), "GET", &get, &[], b"").await?.header("content-disposition").map(|d| d.starts_with("attachment")),
        Some(true)
    );

    let (put, _) = slot(&mut alice, "pic.jpg", 10, Some("image/jpeg")).await?;
    let r = http_request(s.web(), "PUT", &put, &[("Content-Type", "text/html"), ("Content-Length", "10")], b"").await?;
    assert_eq!(r.status, 400, "the type must match the slot");
    // The failed attempt gave the slot back.
    let r = http_request(s.web(), "PUT", &put, &[("Content-Type", "image/jpeg")], &[0u8; 10]).await?;
    assert_eq!(r.status, 201);

    assert_eq!(http_request(s.web(), "GET", "/upload/0123456789abcdef0123456789abcdef/x", &[], b"").await?.status, 404);
    assert_eq!(http_request(s.web(), "GET", "/upload/..%2F..%2Fquark.db/x", &[], b"").await?.status, 404);
    Ok(())
}

#[tokio::test]
async fn too_large_files_are_refused_with_the_limit() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    let mut alice = s.login("alice", "password-a").await?;
    let r = alice.iq_get(Some(SERVICE), slot_request("huge.mkv", 200 * 1024 * 1024, None)).await?;
    assert_eq!(error_condition(&r).as_deref(), Some("not-acceptable"));
    let max = r
        .get_child("error", ns::CLIENT)
        .and_then(|e| e.get_child("file-too-large", ns::HTTP_UPLOAD))
        .and_then(|f| f.child_text("max-file-size", ns::HTTP_UPLOAD));
    assert_eq!(max.as_deref(), Some("104857600"));
    let r = alice.iq_get(Some(SERVICE), slot_request("empty", 0, None)).await?;
    assert_eq!(error_condition(&r).as_deref(), Some("bad-request"));
    let r = alice.iq_get(Some(SERVICE), Element::new("request", ns::HTTP_UPLOAD).attr_set("size", "10")).await?;
    assert_eq!(error_condition(&r).as_deref(), Some("bad-request"));
    Ok(())
}

#[tokio::test]
async fn slots_count_against_the_quota() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    let mut alice = s.login("alice", "password-a").await?;
    // The quota is twenty files of the largest size (2000 MiB here), and pending slots count.
    for i in 0..20 {
        slot(&mut alice, &format!("{i}.mp4"), 99 * 1024 * 1024, None).await?;
    }
    let r = alice.iq_get(Some(SERVICE), slot_request("20.mp4", 100 * 1024 * 1024, None)).await?;
    assert_eq!(error_condition(&r).as_deref(), Some("resource-constraint"), "{r}");
    // Small files still fit in what's left.
    slot(&mut alice, "note.txt", 1000, None).await?;
    Ok(())
}

#[tokio::test]
async fn slots_are_rate_limited_per_hour() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    s.add_user("bob", "password-b").await?;
    let mut alice = s.login("alice", "password-a").await?;
    for i in 0..60 {
        slot(&mut alice, &format!("{i}.txt"), 10, None).await?;
    }
    let r = alice.iq_get(Some(SERVICE), slot_request("61.txt", 10, None)).await?;
    assert_eq!(error_condition(&r).as_deref(), Some("resource-constraint"));
    let err = r.get_child("error", ns::CLIENT).unwrap();
    assert_eq!(err.attr("type"), Some("wait"));
    assert!(err.get_child("retry", ns::HTTP_UPLOAD).and_then(|x| x.attr("stamp")).is_some());
    // Other accounts aren't affected.
    let mut bob = s.login("bob", "password-b").await?;
    slot(&mut bob, "b.txt", 10, None).await?;
    Ok(())
}

#[tokio::test]
async fn files_expire_after_keep_days() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    let mut alice = s.login("alice", "password-a").await?;
    let (put, get) = slot(&mut alice, "old.txt", 5, None).await?;
    assert_eq!(http_request(s.web(), "PUT", &put, &[], b"hello").await?.status, 201);
    let token = get.split('/').nth(2).unwrap().to_string();
    let on_disk = s.srv.config().server.data_dir.join("uploads").join(&token);
    assert!(on_disk.exists());

    let now = quark_testkit::quark_core::time::now_ms();
    assert_eq!(quark::modules::upload::sweep(&s.srv, now + 86_400_000).await, 0, "still within 30 days");
    assert_eq!(http_request(s.web(), "GET", &get, &[], b"").await?.status, 200);
    assert_eq!(quark::modules::upload::sweep(&s.srv, now + 31 * 86_400_000).await, 1);
    assert!(!on_disk.exists());
    assert_eq!(http_request(s.web(), "GET", &get, &[], b"").await?.status, 404);
    Ok(())
}

#[tokio::test]
async fn files_of_deleted_accounts_are_swept() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    let mut alice = s.login("alice", "password-a").await?;
    let (put, get) = slot(&mut alice, "x.txt", 3, None).await?;
    assert_eq!(http_request(s.web(), "PUT", &put, &[], b"abc").await?.status, 201);
    drop(alice);
    s.srv.accounts.delete(s.domain(), "alice").await?;
    assert_eq!(http_request(s.web(), "GET", &get, &[], b"").await?.status, 404);
    assert_eq!(quark::modules::upload::sweep(&s.srv, quark_testkit::quark_core::time::now_ms()).await, 1);
    Ok(())
}

/// A PUT that sends its headers and the first bytes of the body, and leaves the rest for later.
async fn start_put(addr: SocketAddr, path: &str, length: usize, first: &[u8]) -> anyhow::Result<TcpStream> {
    let mut tcp = TcpStream::connect(addr).await?;
    let head = format!("PUT {path} HTTP/1.1\r\nHost: quark.test\r\nConnection: close\r\nContent-Length: {length}\r\n\r\n");
    tcp.write_all(head.as_bytes()).await?;
    tcp.write_all(first).await?;
    tcp.flush().await?;
    Ok(tcp)
}

/// PUTs `data` until it's taken (a slot given back by a dropped upload frees up shortly after).
async fn put_eventually(addr: SocketAddr, put: &str, data: &[u8]) -> anyhow::Result<u16> {
    let mut status = 0;
    for _ in 0..50 {
        status = http_request(addr, "PUT", put, &[], data).await?.status;
        if status == 201 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(status)
}

#[tokio::test]
async fn an_upload_cut_off_midway_gives_its_slot_back() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    let mut alice = s.login("alice", "password-a").await?;
    let data = vec![7u8; 1000];
    let (put, get) = slot(&mut alice, "a.bin", data.len() as u64, None).await?;
    let token = get.split('/').nth(2).unwrap().to_string();
    let part = s.srv.config().server.data_dir.join("uploads").join(format!(".{token}.part"));
    let tcp = start_put(s.web(), &put, data.len(), &data[..100]).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(part.exists(), "the upload is under way");
    // The phone loses its connection.
    drop(tcp);
    assert_eq!(put_eventually(s.web(), &put, &data).await?, 201, "the slot was given back, not left in use");
    assert!(!part.exists());
    assert_eq!(http_request(s.web(), "GET", &get, &[], b"").await?.body, data);
    Ok(())
}

#[tokio::test]
async fn an_upload_dropped_by_a_shutdown_cleans_up_and_its_slot_works_after_a_restart() -> anyhow::Result<()> {
    let mut s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    let mut alice = s.login("alice", "password-a").await?;
    let data = vec![9u8; 1000];
    let (put, get) = slot(&mut alice, "a.bin", data.len() as u64, None).await?;
    let token = get.split('/').nth(2).unwrap().to_string();
    let part = s.srv.config().server.data_dir.join("uploads").join(format!(".{token}.part"));
    let _tcp = start_put(s.web(), &put, data.len(), &data[..100]).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(part.exists());
    // The server stops; after the drain the unfinished request is dropped, not answered.
    s.srv.shut_down();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while part.exists() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(!part.exists(), "the dropped upload removed its partial file");
    s.restart().await?;
    assert_eq!(http_request(s.web(), "PUT", &put, &[], &data).await?.status, 201, "the slot is usable again");
    Ok(())
}

#[tokio::test]
async fn one_account_can_run_only_a_few_uploads_at_once() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    s.add_user("bob", "password-b").await?;
    let mut alice = s.login("alice", "password-a").await?;
    let mut running = Vec::new();
    for i in 0..4 {
        let (put, _) = slot(&mut alice, &format!("{i}.bin"), 100, None).await?;
        running.push(start_put(s.web(), &put, 100, &[1; 10]).await?);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (put, _) = slot(&mut alice, "5.bin", 3, None).await?;
    assert_eq!(http_request(s.web(), "PUT", &put, &[], b"abc").await?.status, 429);
    let mut bob = s.login("bob", "password-b").await?;
    let (bobs, _) = slot(&mut bob, "b.bin", 3, None).await?;
    assert_eq!(http_request(s.web(), "PUT", &bobs, &[], b"abc").await?.status, 201, "other accounts aren't affected");
    // One of the four gives up, which makes room.
    drop(running.pop());
    assert_eq!(put_eventually(s.web(), &put, b"abc").await?, 201);
    Ok(())
}

#[tokio::test]
async fn the_sweep_leaves_running_uploads_alone() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    let mut alice = s.login("alice", "password-a").await?;
    let dir = s.srv.config().server.data_dir.join("uploads");
    let orphan = dir.join(".0123456789abcdef0123456789abcdef.part");
    std::fs::write(&orphan, b"left behind")?;
    let data = vec![3u8; 500];
    let (put, get) = slot(&mut alice, "run.bin", 500, None).await?;
    let mut tcp = start_put(s.web(), &put, 500, &data[..200]).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(quark::modules::upload::sweep(&s.srv, quark_testkit::quark_core::time::now_ms()).await, 1, "only the orphan goes");
    assert!(!orphan.exists());
    tcp.write_all(&data[200..]).await?;
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), tcp.read_to_end(&mut raw)).await??;
    assert!(raw.starts_with(b"HTTP/1.1 201"), "{}", String::from_utf8_lossy(&raw));
    assert_eq!(http_request(s.web(), "GET", &get, &[], b"").await?.body, data);
    Ok(())
}

#[tokio::test]
async fn a_guessed_type_does_not_bind_the_upload() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    let mut alice = s.login("alice", "password-a").await?;
    // The client named no type; the server guessed image/jpeg from the name, for serving only.
    let (put, get) = slot(&mut alice, "photo.jpg", 4, None).await?;
    let r = http_request(s.web(), "PUT", &put, &[("Content-Type", "application/octet-stream")], b"\xFF\xD8\xFF\xD9").await?;
    assert_eq!(r.status, 201, "{}", r.text());
    assert_eq!(http_request(s.web(), "GET", &get, &[], b"").await?.header("content-type"), Some("image/jpeg"));
    Ok(())
}

/// A JPEG whose EXIF carries a location.
fn jpeg_with_gps() -> Vec<u8> {
    let exif = b"Exif\0\0MM\0\x2a\0\0\0\x08\0\x01\x88\x25\0\x04\0\0\0\x01\0\0\0\x1a\0\0\0\0GPS 52.52N 13.40E";
    let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE1, 0, (exif.len() + 2) as u8];
    jpeg.extend_from_slice(exif);
    jpeg.extend_from_slice(&[0xFF, 0xDA, 0, 8, 1, 1, 0, 0, 63, 0, 0x11, 0x22, 0xFF, 0xD9]);
    jpeg
}

#[tokio::test]
async fn photos_are_stored_exactly_as_sent_by_default() -> anyhow::Result<()> {
    // Clients check the file against the hash and size they shared with the link (XEP-0447).
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    let mut alice = s.login("alice", "password-a").await?;
    let jpeg = jpeg_with_gps();
    let (put, get) = slot(&mut alice, "IMG_0002.JPG", jpeg.len() as u64, Some("image/jpeg")).await?;
    assert_eq!(http_request(s.web(), "PUT", &put, &[("Content-Type", "image/jpeg")], &jpeg).await?.status, 201);
    assert_eq!(http_request(s.web(), "GET", &get, &[], b"").await?.body, jpeg);
    Ok(())
}

#[tokio::test]
async fn jpeg_location_metadata_is_stripped() -> anyhow::Result<()> {
    let s = TestServer::start_with(Options { extra_config: "[http]\nstrip_photo_metadata = true\n".into(), ..Default::default() }).await?;
    s.add_user("alice", "password-a").await?;
    let mut alice = s.login("alice", "password-a").await?;
    let jpeg = jpeg_with_gps();
    let (put, get) = slot(&mut alice, "IMG_0001.JPG", jpeg.len() as u64, Some("image/jpeg")).await?;
    assert_eq!(http_request(s.web(), "PUT", &put, &[("Content-Type", "image/jpeg")], &jpeg).await?.status, 201);
    let r = http_request(s.web(), "GET", &get, &[], b"").await?;
    assert_eq!(r.body, [0xFF, 0xD8, 0xFF, 0xDA, 0, 8, 1, 1, 0, 0, 63, 0, 0x11, 0x22, 0xFF, 0xD9]);
    assert_eq!(r.header("content-type"), Some("image/jpeg"));
    Ok(())
}

#[tokio::test]
async fn uploads_off_removes_the_service() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    s.set_settings(|st| st.files.on = false).await?;
    let mut alice = s.login("alice", "password-a").await?;
    let items = alice.iq_get(Some(s.domain()), Element::new("query", ns::DISCO_ITEMS)).await?;
    assert!(!items.to_xml().contains(SERVICE));
    let r = alice.iq_get(Some(SERVICE), slot_request("a.txt", 1, None)).await?;
    assert_eq!(r.attr("type"), Some("error"));
    Ok(())
}

#[tokio::test]
async fn upload_preflight_allows_web_clients() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let r = http_request(s.web(), "OPTIONS", "/upload/0123456789abcdef0123456789abcdef/a.txt", &[("Origin", "https://app.example")], b"")
        .await?;
    assert_eq!(r.status, 204);
    assert_eq!(r.header("access-control-allow-origin"), Some("*"));
    assert!(r.header("access-control-allow-methods").is_some_and(|m| m.contains("PUT")));
    Ok(())
}
