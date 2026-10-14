//! Black-box conformance: stream setup, TLS and stream-level errors (RFC 6120 §4, §5, §11;
//! XEP-0368). Written from the specifications only.

mod blind_common;

use anyhow::Context as _;
use blind_common::*;
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{message, Client, Options, TestServer, DOMAIN};
use tokio::io::AsyncWriteExt as _;

/// RFC 6120 §4.9.1.2: an error triggered by the initial header still needs the receiving entity's
/// own stream header first, so the error is well-formed and in the right namespace.
const HEADER_FIRST: &str = "the server must send its own stream header before the stream error (RFC 6120 §4.9.1.2)";

// --- RFC 6120 §4.7: the response stream header ---

#[tokio::test]
async fn response_header_has_from_id_and_version_1_0() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let c = Client::connect(s.c2s(), DOMAIN).await?;
    // §4.7.1: 'from' is the receiving entity's domain.
    assert_eq!(c.header_attr("from"), Some(DOMAIN), "header: {:?}", c.header);
    // §4.7.3: the receiving entity MUST include a stream id.
    let id = c.header_attr("id").expect("stream header without an id");
    assert!(!id.is_empty());
    // §4.7.5: version is the lower of both, here 1.0.
    assert_eq!(c.header_attr("version"), Some("1.0"), "header: {:?}", c.header);
    Ok(())
}

#[tokio::test]
async fn stream_ids_are_unique_per_stream_and_per_restart() -> anyhow::Result<()> {
    // RFC 6120 §4.7.3: the id MUST be unique; every restarted stream is a new stream.
    let s = TestServer::start().await?;
    s.add_user("alice", "password1").await?;
    let mut ids = Vec::new();
    let other = Client::connect(s.c2s(), DOMAIN).await?;
    ids.push(other.header_attr("id").unwrap_or_default().to_string());
    let mut c = Client::connect(s.c2s(), DOMAIN).await?;
    ids.push(c.header_attr("id").unwrap_or_default().to_string());
    c.starttls().await?;
    ids.push(c.header_attr("id").unwrap_or_default().to_string());
    c.auth_scram("SCRAM-SHA-256", "alice", "password1").await?;
    ids.push(c.header_attr("id").unwrap_or_default().to_string());
    let mut uniq = ids.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(uniq.len(), ids.len(), "stream ids repeat: {ids:?}");
    assert!(ids.iter().all(|i| !i.is_empty()), "empty stream id: {ids:?}");
    Ok(())
}

#[tokio::test]
async fn header_with_and_without_xml_declaration_is_accepted() -> anyhow::Result<()> {
    // RFC 6120 §11.5: the XML declaration SHOULD be sent; it is not a processing instruction.
    let s = TestServer::start().await?;
    for prefix in ["<?xml version='1.0'?>", "<?xml version='1.0' encoding='UTF-8'?>", ""] {
        let mut c = Client::connect_raw(s.c2s(), DOMAIN).await?;
        c.open_with(&format!("{prefix}{}", header(DOMAIN))).await?;
        let f = c.recv().await?;
        assert!(f.is("features", ns::STREAM), "with prefix {prefix:?} got {f}");
    }
    Ok(())
}

// --- RFC 6120 §5: STARTTLS ---

#[tokio::test]
async fn tls_required_by_default_starttls_is_offered_as_required() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let c = Client::connect(s.c2s(), DOMAIN).await?;
    let tls = feature(&c, "starttls", ns::TLS).expect("no <starttls/> feature before TLS");
    // §5.3.1 / §5.4.1: mandatory-to-negotiate TLS is flagged with <required/>.
    assert!(tls.has_child("required", ns::TLS), "STARTTLS is required but not flagged: {tls}");
    // PLAIN is never offered over a plaintext connection.
    assert!(!c.mechanisms().iter().any(|m| m == "PLAIN"), "PLAIN offered before TLS: {:?}", c.mechanisms());
    Ok(())
}

#[tokio::test]
async fn after_starttls_features_offer_sasl_and_not_starttls() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let c = tls_client(&s).await?;
    // §5.3.1: STARTTLS MUST NOT be offered again once TLS is in place.
    assert!(!has_feature(&c, "starttls", ns::TLS), "STARTTLS offered after TLS: {:?}", c.features);
    let mechs = c.mechanisms();
    for m in ["SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-512", "PLAIN"] {
        assert!(mechs.iter().any(|x| x == m), "{m} not offered after TLS: {mechs:?}");
    }
    Ok(())
}

#[tokio::test]
async fn sasl_before_tls_is_refused_when_tls_is_required() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password1").await?;
    let mut c = Client::connect(s.c2s(), DOMAIN).await?;
    let end = scram_attempt(&mut c, "SCRAM-SHA-256", "alice", "password1", None).await;
    match end {
        // RFC 6120 §6.5.4 encryption-required, or the mechanism simply isn't available.
        Ok(SaslEnd::Failure(f)) => {
            let cond = sasl_failure_condition(&f).unwrap_or_default();
            assert!(
                ["encryption-required", "invalid-mechanism", "mechanism-too-weak", "not-authorized"].contains(&cond.as_str()),
                "unexpected failure {f}"
            );
        }
        // Or the stream is closed (§4.3.5 not-authorized, §5 policy-violation).
        Ok(SaslEnd::StreamError(e)) => {
            let cond = stream_error_condition(&e).unwrap_or_default();
            assert!(["not-authorized", "policy-violation", "encryption-required"].contains(&cond.as_str()), "{e}");
        }
        Ok(SaslEnd::Success(x)) => panic!("authenticated over plaintext although TLS is required: {x}"),
        Err(e) => {
            let msg = e.to_string();
            assert!(msg.contains("closed"), "unexpected: {msg}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn stanza_before_tls_closes_the_stream() -> anyhow::Result<()> {
    // RFC 6120 §4.3.5: stanzas before negotiation completes → <not-authorized/>
    // (§5.3.1 also allows <policy-violation/> when TLS is mandatory).
    let s = TestServer::start().await?;
    let mut c = Client::connect(s.c2s(), DOMAIN).await?;
    c.send(&message("someone@quark.test", "chat", "too early")).await?;
    expect_stream_error(&mut c, &["not-authorized", "policy-violation"]).await?;
    Ok(())
}

#[tokio::test]
async fn stanza_after_tls_before_sasl_is_not_authorized() -> anyhow::Result<()> {
    // RFC 6120 §4.3.5 / §4.9.3.12.
    let s = TestServer::start().await?;
    let mut c = tls_client(&s).await?;
    c.send(&message("someone@quark.test", "chat", "too early")).await?;
    expect_stream_error(&mut c, &["not-authorized"]).await?;
    Ok(())
}

#[tokio::test]
async fn iq_after_tls_before_sasl_is_not_authorized() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut c = tls_client(&s).await?;
    c.send_raw("<iq type='get' id='p1' to='quark.test'><ping xmlns='urn:xmpp:ping'/></iq>").await?;
    expect_stream_error(&mut c, &["not-authorized"]).await?;
    Ok(())
}

#[tokio::test]
async fn stanza_to_another_entity_before_bind_is_not_authorized() -> anyhow::Result<()> {
    // RFC 6120 §7.1: before binding, a stanza to anyone but the server or the account
    // MUST NOT be processed and the stream is closed with <not-authorized/>.
    let s = TestServer::start().await?;
    s.add_user("alice", "password1").await?;
    s.add_user("bob", "password1").await?;
    let mut bob = s.login("bob", "password1").await?;
    let mut c = authed_client(&s, "alice", "password1").await?;
    c.send(&message(bob.jid.as_deref().unwrap_or("bob@quark.test"), "chat", "before bind")).await?;
    expect_stream_error(&mut c, &["not-authorized"]).await?;
    bob.expect_silence(QUIET).await?;
    Ok(())
}

// --- allow_plain ---

#[tokio::test]
async fn allow_plain_offers_starttls_optionally_and_no_plain_mechanism() -> anyhow::Result<()> {
    let s = TestServer::start_with(Options { allow_plain: true, ..Default::default() }).await?;
    let c = Client::connect(s.c2s(), DOMAIN).await?;
    let tls = feature(&c, "starttls", ns::TLS).expect("STARTTLS should still be offered");
    assert!(!tls.has_child("required", ns::TLS), "TLS is optional but flagged required: {tls}");
    let mechs = c.mechanisms();
    assert!(!mechs.is_empty(), "allow_plain: no SASL mechanisms before TLS");
    // RFC 4616 §1 / RFC 6120 §13.8: PLAIN only over a protected channel.
    assert!(!mechs.iter().any(|m| m == "PLAIN"), "PLAIN offered without TLS: {mechs:?}");
    // -PLUS needs TLS channel binding, so it can't be offered here either.
    assert!(!mechs.iter().any(|m| m.ends_with("-PLUS")), "-PLUS offered without TLS: {mechs:?}");
    Ok(())
}

#[tokio::test]
async fn allow_plain_scram_without_tls_works() -> anyhow::Result<()> {
    let s = TestServer::start_with(Options { allow_plain: true, ..Default::default() }).await?;
    s.add_user("alice", "password1").await?;
    let mut c = Client::connect(s.c2s(), DOMAIN).await?;
    c.auth_scram("SCRAM-SHA-256", "alice", "password1").await?;
    let jid = c.bind(Some("plain")).await?;
    assert_eq!(jid, "alice@quark.test/plain");
    Ok(())
}

#[tokio::test]
async fn allow_plain_plain_mechanism_without_tls_is_refused() -> anyhow::Result<()> {
    let s = TestServer::start_with(Options { allow_plain: true, ..Default::default() }).await?;
    s.add_user("alice", "password1").await?;
    let mut c = Client::connect(s.c2s(), DOMAIN).await?;
    c.send(&Element::new("auth", ns::SASL).attr_set("mechanism", "PLAIN").text(b64("\0alice\0password1"))).await?;
    let r = c.recv().await?;
    let cond = sasl_failure_condition(&r).unwrap_or_else(|| panic!("PLAIN over plaintext was not refused: {r}"));
    assert!(["encryption-required", "invalid-mechanism", "mechanism-too-weak"].contains(&cond.as_str()), "{r}");
    Ok(())
}

#[tokio::test]
async fn allow_plain_starttls_still_works_and_then_plain_is_offered() -> anyhow::Result<()> {
    let s = TestServer::start_with(Options { allow_plain: true, ..Default::default() }).await?;
    s.add_user("alice", "password1").await?;
    let mut c = tls_client(&s).await?;
    assert!(c.mechanisms().iter().any(|m| m == "PLAIN"), "{:?}", c.mechanisms());
    c.auth_plain("alice", "password1").await?;
    c.bind(Some("tls")).await?;
    Ok(())
}

// --- XEP-0368 direct TLS ---

#[tokio::test]
async fn direct_tls_offers_sasl_without_starttls_and_signs_in() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password1").await?;
    let mut c = Client::connect_tls(s.c2s_tls(), DOMAIN).await?;
    if let Some(alpn) = &c.alpn {
        assert_eq!(alpn.as_slice(), b"xmpp-client", "server picked a different ALPN protocol");
    }
    assert_eq!(c.header_attr("from"), Some(DOMAIN));
    assert!(!has_feature(&c, "starttls", ns::TLS), "STARTTLS offered on a direct TLS connection: {:?}", c.features);
    let mechs = c.mechanisms();
    assert!(mechs.iter().any(|m| m == "SCRAM-SHA-256") && mechs.iter().any(|m| m == "PLAIN"), "{mechs:?}");
    c.auth_scram("SCRAM-SHA-256", "alice", "password1").await?;
    c.bind(Some("direct")).await?;
    let pong = c.iq_get(Some(DOMAIN), Element::new("ping", ns::PING)).await?;
    assert_eq!(pong.attr("type"), Some("result"));
    Ok(())
}

// --- RFC 6120 §4.9.3: stream errors on the header ---

#[tokio::test]
async fn unknown_domain_gets_host_unknown() -> anyhow::Result<()> {
    // §4.9.3.6. §4.9.1.2: the receiving entity first sends its own stream header.
    let s = TestServer::start().await?;
    let mut c = Client::connect_raw(s.c2s(), DOMAIN).await?;
    c.open_with(&format!("<?xml version='1.0'?>{}", header("unknown.example"))).await.context(HEADER_FIRST)?;
    expect_stream_error(&mut c, &["host-unknown"]).await?;
    Ok(())
}

#[tokio::test]
async fn wrong_stream_namespace_gets_invalid_namespace() -> anyhow::Result<()> {
    // §4.8.1 / §4.9.3.10.
    let s = TestServer::start().await?;
    let mut c = Client::connect_raw(s.c2s(), DOMAIN).await?;
    c.open_with(&header_with(DOMAIN, "http://example.com/not-streams", ns::CLIENT, Some("1.0"))).await.context(HEADER_FIRST)?;
    expect_stream_error(&mut c, &["invalid-namespace"]).await?;
    Ok(())
}

#[tokio::test]
async fn wrong_content_namespace_gets_invalid_namespace() -> anyhow::Result<()> {
    // §4.8.2 / §4.9.3.10: a default namespace other than jabber:client on a client port.
    let s = TestServer::start().await?;
    let mut c = Client::connect_raw(s.c2s(), DOMAIN).await?;
    c.open_with(&header_with(DOMAIN, ns::STREAM, "jabber:bogus", Some("1.0"))).await.context(HEADER_FIRST)?;
    expect_stream_error(&mut c, &["invalid-namespace"]).await?;
    Ok(())
}

#[tokio::test]
async fn higher_major_version_gets_1_0_or_unsupported_version() -> anyhow::Result<()> {
    // §4.7.5: the response carries the lower version (1.0); §4.9.3.25 allows the server to
    // follow it with <unsupported-version/>; otherwise negotiation continues.
    let s = TestServer::start().await?;
    let mut c = Client::connect_raw(s.c2s(), DOMAIN).await?;
    c.open_with(&header_with(DOMAIN, ns::STREAM, ns::CLIENT, Some("11.0"))).await?;
    assert_eq!(c.header_attr("version"), Some("1.0"), "header: {:?}", c.header);
    let next = c.recv().await?;
    if next.is("error", ns::STREAM) {
        assert_eq!(stream_error_condition(&next).as_deref(), Some("unsupported-version"), "{next}");
    } else {
        assert!(next.is("features", ns::STREAM), "{next}");
    }
    Ok(())
}

#[tokio::test]
async fn minor_versions_compare_as_integers() -> anyhow::Result<()> {
    // §4.7.5: "1.10" is higher than "1.0"... and the server answers with 1.0, not an error.
    let s = TestServer::start().await?;
    let mut c = Client::connect_raw(s.c2s(), DOMAIN).await?;
    c.open_with(&header_with(DOMAIN, ns::STREAM, ns::CLIENT, Some("1.10"))).await?;
    assert_eq!(c.header_attr("version"), Some("1.0"), "header: {:?}", c.header);
    let f = c.recv().await?;
    assert!(f.is("features", ns::STREAM), "{f}");
    Ok(())
}

// --- RFC 6120 §11: XML restrictions ---

#[tokio::test]
async fn not_well_formed_xml_gets_not_well_formed() -> anyhow::Result<()> {
    // §4.9.3.13 / §11.4.
    let s = TestServer::start().await?;
    let mut c = Client::connect(s.c2s(), DOMAIN).await?;
    c.send_raw("<message to='x@quark.test'><body>hi</message>").await?;
    expect_stream_error(&mut c, &["not-well-formed"]).await?;
    Ok(())
}

#[tokio::test]
async fn unbound_prefix_is_not_well_formed() -> anyhow::Result<()> {
    // Namespace well-formedness (§11.4, XML Namespaces): an undeclared prefix.
    let s = TestServer::start().await?;
    let mut c = Client::connect(s.c2s(), DOMAIN).await?;
    c.send_raw("<foo:bar/>").await?;
    expect_stream_error(&mut c, &["not-well-formed", "bad-namespace-prefix", "invalid-namespace"]).await?;
    Ok(())
}

#[tokio::test]
async fn xml_comment_gets_restricted_xml() -> anyhow::Result<()> {
    // §11.1: comments MUST NOT be sent; receiving one closes the stream with <restricted-xml/>.
    let s = TestServer::start().await?;
    let mut c = Client::connect(s.c2s(), DOMAIN).await?;
    c.send_raw("<!-- a comment -->").await?;
    expect_stream_error(&mut c, &["restricted-xml"]).await?;
    Ok(())
}

#[tokio::test]
async fn xml_comment_inside_a_stanza_gets_restricted_xml() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password1").await?;
    let mut c = s.login("alice", "password1").await?;
    c.send_raw("<message to='alice@quark.test' type='chat'><body>hi<!-- sneaky --></body></message>").await?;
    expect_stream_error(&mut c, &["restricted-xml"]).await?;
    Ok(())
}

#[tokio::test]
async fn processing_instruction_gets_restricted_xml() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut c = Client::connect(s.c2s(), DOMAIN).await?;
    c.send_raw("<?foo bar?>").await?;
    expect_stream_error(&mut c, &["restricted-xml"]).await?;
    Ok(())
}

#[tokio::test]
async fn dtd_gets_restricted_xml() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut c = Client::connect(s.c2s(), DOMAIN).await?;
    c.send_raw("<!DOCTYPE message [<!ENTITY x 'y'>]>").await?;
    expect_stream_error(&mut c, &["restricted-xml", "not-well-formed"]).await?;
    Ok(())
}

#[tokio::test]
async fn dtd_before_stream_header_gets_restricted_xml() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut c = Client::connect_raw(s.c2s(), DOMAIN).await?;
    c.send_raw("<?xml version='1.0'?><!DOCTYPE stream:stream [<!ENTITY boom 'boom'>]>").await?;
    // The server answers with its header (§4.9.1.2) and then <restricted-xml/> (§11.1).
    c.open_with(&header(DOMAIN)).await.context(HEADER_FIRST)?;
    expect_stream_error(&mut c, &["restricted-xml"]).await?;
    Ok(())
}

#[tokio::test]
async fn undeclared_entity_reference_is_rejected() -> anyhow::Result<()> {
    // §11.1: only the five predefined entities are allowed.
    let s = TestServer::start().await?;
    s.add_user("alice", "password1").await?;
    let mut c = s.login("alice", "password1").await?;
    c.send_raw("<message to='alice@quark.test' type='chat'><body>&nbsp;</body></message>").await?;
    expect_stream_error(&mut c, &["restricted-xml", "not-well-formed"]).await?;
    Ok(())
}

#[tokio::test]
async fn predefined_entities_and_char_refs_are_fine() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password1").await?;
    let mut c = s.login("alice", "password1").await?;
    let me = c.jid.clone().expect("jid");
    c.send_raw(&format!("<message to='{me}' type='chat' id='e1'><body>&lt;&amp;&gt;&quot;&apos;&#65;&#x42;</body></message>")).await?;
    let m = c.expect(|e| e.name() == "message" && e.attr("id") == Some("e1")).await?;
    assert_eq!(m.child_text("body", ns::CLIENT).as_deref(), Some("<&>\"'AB"));
    Ok(())
}

// --- Size limits ---

#[tokio::test]
async fn oversized_stanza_gets_policy_violation() -> anyhow::Result<()> {
    // §4.9.3.14: "a stanza exceeds a configured size limit".
    let s = TestServer::start().await?;
    s.add_user("alice", "password1").await?;
    let mut c = s.login("alice", "password1").await?;
    let me = c.jid.clone().expect("jid");
    c.send_raw(&format!("<message to='{me}' type='chat'><body>")).await?;
    let chunk = "x".repeat(64 * 1024);
    // 16 MiB is far beyond any sane c2s stanza limit. Stop writing once the server reacts.
    for _ in 0..256 {
        if c.send_raw(&chunk).await.is_err() {
            break;
        }
        if let Ok(Some(e)) = c.recv_within(std::time::Duration::from_millis(1)).await {
            let cond = stream_error_condition(&e).unwrap_or_else(|| panic!("expected a stream error, got {e}"));
            assert_eq!(cond, "policy-violation", "{e}");
            return Ok(());
        }
    }
    let _ = c.send_raw("</body></message>").await;
    expect_stream_error(&mut c, &["policy-violation"]).await?;
    Ok(())
}

// --- Closing ---

#[tokio::test]
async fn closing_the_stream_is_answered_with_a_close() -> anyhow::Result<()> {
    // §4.4: the other side closes its stream too and then the connection.
    let s = TestServer::start().await?;
    s.add_user("alice", "password1").await?;
    let mut c = s.login("alice", "password1").await?;
    c.send_raw("</stream:stream>").await?;
    let r = c.recv().await;
    let err = r.expect_err("the server kept the stream open after </stream:stream>");
    assert!(!err.to_string().contains("timed out"), "{err}");
    Ok(())
}

#[tokio::test]
async fn raw_tcp_garbage_is_not_accepted() -> anyhow::Result<()> {
    // Not XML at all before the header: the server must not hang open forever or answer with
    // features. A stream error (not-well-formed / bad-format) or a closed connection are fine.
    let s = TestServer::start().await?;
    let mut tcp = tokio::net::TcpStream::connect(s.c2s()).await?;
    tcp.write_all(b"GET / HTTP/1.1\r\nHost: quark.test\r\n\r\n").await?;
    let mut buf = Vec::new();
    let res = tokio::time::timeout(quark_testkit::TIMEOUT, tokio::io::AsyncReadExt::read_to_end(&mut tcp, &mut buf)).await;
    assert!(res.is_ok(), "the server kept a garbage connection open");
    let text = String::from_utf8_lossy(&buf);
    assert!(!text.contains("features"), "features after garbage: {text}");
    Ok(())
}
