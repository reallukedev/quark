//! Black-box conformance: SASL (RFC 6120 §6, RFC 4616, RFC 5802, RFC 7677, XEP-0440).
//! Written from the specifications only.

use crate::blind_common;

use blind_common::*;
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{Client, TestServer, DOMAIN};

async fn server_with_alice() -> anyhow::Result<TestServer> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password1").await?;
    Ok(s)
}

// --- SCRAM ---

#[tokio::test]
async fn scram_sha1_sha256_sha512_are_offered_and_succeed() -> anyhow::Result<()> {
    // RFC 6120 §13.8 (SCRAM-SHA-1 mandatory), RFC 7677 (SHA-256), SHA-512 as advertised.
    let s = server_with_alice().await?;
    for mech in ["SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-512"] {
        let mut c = tls_client(&s).await?;
        assert!(c.mechanisms().iter().any(|m| m == mech), "{mech} not offered: {:?}", c.mechanisms());
        // auth_scram verifies the server signature (RFC 5802 §5.1 'v').
        c.auth_scram(mech, "alice", "password1").await?;
        let jid = c.bind(Some(mech)).await?;
        assert_eq!(jid, format!("alice@quark.test/{mech}"));
    }
    Ok(())
}

#[tokio::test]
async fn scram_wrong_password_fails_with_not_authorized() -> anyhow::Result<()> {
    // RFC 6120 §6.5.10.
    let s = server_with_alice().await?;
    for mech in ["SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-512"] {
        let mut c = tls_client(&s).await?;
        let end = scram_attempt(&mut c, mech, "alice", "wrong-password", None).await?;
        assert_eq!(end.failure_condition().as_deref(), Some("not-authorized"), "{mech}: {end:?}");
    }
    Ok(())
}

#[tokio::test]
async fn scram_unknown_user_fails_with_not_authorized() -> anyhow::Result<()> {
    // The failure must look like a wrong password (no account enumeration; RFC 6120 §6.5.10).
    let s = server_with_alice().await?;
    let mut c = tls_client(&s).await?;
    let end = scram_attempt(&mut c, "SCRAM-SHA-256", "nobody", "password1", None).await?;
    assert_eq!(end.failure_condition().as_deref(), Some("not-authorized"), "{end:?}");
    Ok(())
}

#[tokio::test]
async fn retries_after_failure_are_allowed_on_the_same_stream() -> anyhow::Result<()> {
    // RFC 6120 §6.4.5: the server SHOULD allow at least 2 retries.
    let s = server_with_alice().await?;
    let mut c = tls_client(&s).await?;
    for _ in 0..2 {
        let end = scram_attempt(&mut c, "SCRAM-SHA-256", "alice", "typo-password", None).await?;
        assert_eq!(end.failure_condition().as_deref(), Some("not-authorized"), "{end:?}");
    }
    c.auth_scram("SCRAM-SHA-256", "alice", "password1").await?;
    c.bind(Some("retry")).await?;
    Ok(())
}

#[tokio::test]
async fn too_many_failures_close_the_stream() -> anyhow::Result<()> {
    // RFC 6120 §6.4.5: no more than 5 retries; then the server MUST close the stream with a
    // stream error, which SHOULD be <policy-violation/> (some use <not-authorized/>).
    let s = server_with_alice().await?;
    let mut c = tls_client(&s).await?;
    let mut failures = 0;
    for attempt in 1..=7 {
        match scram_attempt(&mut c, "SCRAM-SHA-256", "alice", "wrong-password", None).await {
            Ok(SaslEnd::Failure(_)) => failures += 1,
            Ok(SaslEnd::StreamError(e)) => {
                let cond = stream_error_condition(&e).unwrap_or_default();
                assert!(["policy-violation", "not-authorized"].contains(&cond.as_str()), "{e}");
                assert!(attempt >= 3, "closed after only {failures} failures; at least 2 retries must be allowed");
                expect_closed(&mut c).await?;
                return Ok(());
            }
            Ok(SaslEnd::Success(x)) => panic!("wrong password accepted: {x}"),
            Err(e) => panic!("attempt {attempt}: the stream ended without a stream error: {e}"),
        }
    }
    panic!("{failures} failed attempts on one stream and the server still accepts more (RFC 6120 §6.4.5 allows at most 5 retries)");
}

#[tokio::test]
async fn abort_gets_aborted_and_a_new_attempt_works() -> anyhow::Result<()> {
    // RFC 6120 §6.4.4 and §6.5.1.
    let s = server_with_alice().await?;
    let mut c = tls_client(&s).await?;
    let scram = quark_testkit::ScramClient::new("SCRAM-SHA-256", "alice", "password1", None)?;
    c.send(&Element::new("auth", ns::SASL).attr_set("mechanism", "SCRAM-SHA-256").text(b64(scram.client_first()))).await?;
    let ch = c.recv().await?;
    assert!(ch.is("challenge", ns::SASL), "{ch}");
    c.send(&Element::new("abort", ns::SASL)).await?;
    let f = c.recv().await?;
    assert_eq!(sasl_failure_condition(&f).as_deref(), Some("aborted"), "{f}");
    c.auth_scram("SCRAM-SHA-256", "alice", "password1").await?;
    Ok(())
}

#[tokio::test]
async fn malformed_base64_in_auth_gets_incorrect_encoding() -> anyhow::Result<()> {
    // RFC 6120 §6.5.2.
    let s = server_with_alice().await?;
    let mut c = tls_client(&s).await?;
    c.send(&Element::new("auth", ns::SASL).attr_set("mechanism", "PLAIN").text("!!!not*base64%%%")).await?;
    let f = c.recv().await?;
    assert_eq!(sasl_failure_condition(&f).as_deref(), Some("incorrect-encoding"), "{f}");
    Ok(())
}

#[tokio::test]
async fn malformed_base64_in_response_gets_incorrect_encoding() -> anyhow::Result<()> {
    let s = server_with_alice().await?;
    let mut c = tls_client(&s).await?;
    let scram = quark_testkit::ScramClient::new("SCRAM-SHA-256", "alice", "password1", None)?;
    c.send(&Element::new("auth", ns::SASL).attr_set("mechanism", "SCRAM-SHA-256").text(b64(scram.client_first()))).await?;
    let ch = c.recv().await?;
    assert!(ch.is("challenge", ns::SASL), "{ch}");
    c.send(&Element::new("response", ns::SASL).text("@@@ definitely not base64 @@@")).await?;
    let f = c.recv().await?;
    assert_eq!(sasl_failure_condition(&f).as_deref(), Some("incorrect-encoding"), "{f}");
    Ok(())
}

#[tokio::test]
async fn unknown_mechanism_gets_invalid_mechanism() -> anyhow::Result<()> {
    // RFC 6120 §6.5.6.
    let s = server_with_alice().await?;
    let mut c = tls_client(&s).await?;
    c.send(&Element::new("auth", ns::SASL).attr_set("mechanism", "X-NOT-A-MECHANISM").text("=")).await?;
    let f = c.recv().await?;
    assert_eq!(sasl_failure_condition(&f).as_deref(), Some("invalid-mechanism"), "{f}");
    // The stream stays usable.
    c.auth_scram("SCRAM-SHA-256", "alice", "password1").await?;
    Ok(())
}

#[tokio::test]
async fn features_after_sasl_offer_bind_and_no_mechanisms() -> anyhow::Result<()> {
    // RFC 6120 §6.4.6 / §7.4: after the restart, resource binding is offered, SASL is not.
    let s = server_with_alice().await?;
    let c = authed_client(&s, "alice", "password1").await?;
    assert!(has_feature(&c, "bind", ns::BIND), "no bind feature: {:?}", c.features);
    assert!(!has_feature(&c, "mechanisms", ns::SASL), "SASL offered again: {:?}", c.features);
    assert!(!has_feature(&c, "starttls", ns::TLS), "STARTTLS offered again: {:?}", c.features);
    Ok(())
}

// --- PLAIN ---

#[tokio::test]
async fn plain_after_tls_succeeds_and_wrong_password_fails() -> anyhow::Result<()> {
    let s = server_with_alice().await?;
    let mut c = tls_client(&s).await?;
    c.send(&Element::new("auth", ns::SASL).attr_set("mechanism", "PLAIN").text(b64("\0alice\0wrong-password"))).await?;
    let f = c.recv().await?;
    assert_eq!(sasl_failure_condition(&f).as_deref(), Some("not-authorized"), "{f}");
    c.auth_plain("alice", "password1").await?;
    c.bind(Some("plain")).await?;
    Ok(())
}

#[tokio::test]
async fn plain_without_initial_response_gets_empty_challenge() -> anyhow::Result<()> {
    // RFC 6120 §6.4.2 / §6.4.3: with no initial response the server sends an empty challenge.
    let s = server_with_alice().await?;
    let mut c = tls_client(&s).await?;
    c.send(&Element::new("auth", ns::SASL).attr_set("mechanism", "PLAIN")).await?;
    let ch = c.recv().await?;
    assert!(ch.is("challenge", ns::SASL), "expected an empty challenge, got {ch}");
    assert!(unb64(&ch.text_content())?.is_empty(), "challenge not empty: {ch}");
    c.send(&Element::new("response", ns::SASL).text(b64("\0alice\0password1"))).await?;
    let r = c.recv().await?;
    assert!(r.is("success", ns::SASL), "{r}");
    Ok(())
}

#[tokio::test]
async fn plain_with_own_authzid_succeeds() -> anyhow::Result<()> {
    // RFC 6120 §6.3.8: an authzid equal to the account's bare JID is fine.
    let s = server_with_alice().await?;
    let mut c = tls_client(&s).await?;
    c.send(&Element::new("auth", ns::SASL).attr_set("mechanism", "PLAIN").text(b64("alice@quark.test\0alice\0password1"))).await?;
    let r = c.recv().await?;
    assert!(r.is("success", ns::SASL), "{r}");
    Ok(())
}

#[tokio::test]
async fn plain_with_someone_elses_authzid_gets_invalid_authzid() -> anyhow::Result<()> {
    // RFC 6120 §6.5.5.
    let s = server_with_alice().await?;
    s.add_user("bob", "password1").await?;
    let mut c = tls_client(&s).await?;
    c.send(&Element::new("auth", ns::SASL).attr_set("mechanism", "PLAIN").text(b64("bob@quark.test\0alice\0password1"))).await?;
    let f = c.recv().await?;
    assert_eq!(sasl_failure_condition(&f).as_deref(), Some("invalid-authzid"), "{f}");
    Ok(())
}

// --- Channel binding (RFC 5802 §6, RFC 9266, XEP-0440) ---

#[tokio::test]
async fn scram_plus_with_tls_exporter_when_offered() -> anyhow::Result<()> {
    let s = server_with_alice().await?;
    let probe = tls_client(&s).await?;
    let plus: Vec<String> = probe.mechanisms().into_iter().filter(|m| m.ends_with("-PLUS")).collect();
    if plus.is_empty() {
        eprintln!("no -PLUS mechanisms offered; nothing to check");
        return Ok(());
    }
    // XEP-0440: offering -PLUS means advertising which channel-binding types are supported.
    let cb = feature(&probe, "sasl-channel-binding", SASL_CB).expect("-PLUS offered without <sasl-channel-binding/> (XEP-0440)");
    let types: Vec<&str> = cb.children().filter_map(|t| t.attr("type")).collect();
    assert!(types.contains(&"tls-exporter"), "tls-exporter not advertised: {cb}");
    for mech in plus {
        let mut c = tls_client(&s).await?;
        assert!(c.exporter.is_some(), "TLS 1.3 expected for tls-exporter");
        c.auth_scram(&mech, "alice", "password1").await?;
        c.bind(Some("plus")).await?;
    }
    Ok(())
}

#[tokio::test]
async fn scram_plus_over_direct_tls() -> anyhow::Result<()> {
    let s = server_with_alice().await?;
    let mut c = Client::connect_tls(s.c2s_tls(), DOMAIN).await?;
    if !c.mechanisms().iter().any(|m| m == "SCRAM-SHA-256-PLUS") {
        eprintln!("SCRAM-SHA-256-PLUS not offered on direct TLS");
        return Ok(());
    }
    c.auth_scram("SCRAM-SHA-256-PLUS", "alice", "password1").await?;
    c.bind(None).await?;
    Ok(())
}

#[tokio::test]
async fn scram_plus_with_wrong_binding_data_fails() -> anyhow::Result<()> {
    // RFC 5802 §5.1 'c': the server checks the channel binding data.
    let s = server_with_alice().await?;
    let mut c = tls_client(&s).await?;
    if !c.mechanisms().iter().any(|m| m == "SCRAM-SHA-256-PLUS") {
        eprintln!("SCRAM-SHA-256-PLUS not offered");
        return Ok(());
    }
    let end = scram_attempt(&mut c, "SCRAM-SHA-256-PLUS", "alice", "password1", Some(vec![0u8; 32])).await?;
    assert!(matches!(end, SaslEnd::Failure(_)), "bogus channel binding accepted: {end:?}");
    Ok(())
}

#[tokio::test]
async fn scram_y_flag_fails_when_server_offers_plus() -> anyhow::Result<()> {
    // RFC 5802 §6: GS2 flag 'y' means "client supports binding but thinks the server doesn't".
    // A server that does support it MUST fail the authentication (downgrade protection).
    let s = server_with_alice().await?;
    let mut c = tls_client(&s).await?;
    if !c.mechanisms().iter().any(|m| m.ends_with("-PLUS")) {
        eprintln!("no -PLUS offered; 'y' is legitimate");
        return Ok(());
    }
    let end = scram256_custom(&mut c, "y,,", b"", "alice", "password1").await?;
    assert!(matches!(end, SaslEnd::Failure(_)), "'y' flag accepted although -PLUS is offered: {end:?}");
    Ok(())
}

#[tokio::test]
async fn hand_rolled_scram_n_flag_succeeds() -> anyhow::Result<()> {
    // Sanity check of the hand-rolled SCRAM used above: 'n,,' must work.
    let s = server_with_alice().await?;
    let mut c = tls_client(&s).await?;
    let end = scram256_custom(&mut c, "n,,", b"", "alice", "password1").await?;
    assert!(matches!(end, SaslEnd::Success(_)), "{end:?}");
    Ok(())
}

// --- Disabled accounts ---

#[tokio::test]
async fn disabled_account_cannot_sign_in_and_can_again_once_enabled() -> anyhow::Result<()> {
    // RFC 6120 §6.5.1 <account-disabled/> (or <not-authorized/>, which leaks less).
    let s = server_with_alice().await?;
    s.set_enabled("alice", false).await?;
    for mech in ["SCRAM-SHA-256", "PLAIN"] {
        let mut c = tls_client(&s).await?;
        let end = if mech == "PLAIN" {
            c.send(&Element::new("auth", ns::SASL).attr_set("mechanism", "PLAIN").text(b64("\0alice\0password1"))).await?;
            let r = c.recv().await?;
            if r.is("success", ns::SASL) {
                SaslEnd::Success(r)
            } else {
                SaslEnd::Failure(r)
            }
        } else {
            scram_attempt(&mut c, mech, "alice", "password1", None).await?
        };
        let cond = end.failure_condition();
        assert!(matches!(cond.as_deref(), Some("account-disabled" | "not-authorized")), "{mech}: {end:?}");
    }
    s.set_enabled("alice", true).await?;
    s.login("alice", "password1").await?;
    Ok(())
}

#[tokio::test]
async fn disabling_an_account_ends_its_sessions() -> anyhow::Result<()> {
    // A disabled account must not keep using the service; RFC 6120 §4.9.3 offers
    // <policy-violation/>, <not-authorized/> or <reset/> for ending such a stream.
    let s = server_with_alice().await?;
    let mut c = s.login("alice", "password1").await?;
    s.set_enabled("alice", false).await?;
    let e = c.recv().await;
    match e {
        Ok(el) => {
            let cond = stream_error_condition(&el).unwrap_or_else(|| panic!("expected a stream error, got {el}"));
            assert!(["policy-violation", "not-authorized", "reset", "conflict"].contains(&cond.as_str()), "{el}");
        }
        Err(err) => assert!(!err.to_string().contains("timed out"), "the session of a disabled account stayed open"),
    }
    Ok(())
}
