//! Black-box IQ tests: semantics (RFC 6120 §8.2.3), routing (RFC 6121 §8.5), vcard-temp
//! (XEP-0054), private XML storage (XEP-0049), last activity (XEP-0012), account disco (XEP-0030).

use crate::blind_util;

use std::collections::HashMap;
use std::time::Duration;

use blind_util::*;
use quark_testkit::quark_core::{ns, Element};

const UNKNOWN_NS: &str = "urn:example:blind:unknown";

// ---------- IQ semantics ----------

#[tokio::test]
async fn every_get_and_set_gets_exactly_one_reply_with_the_same_id() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    settle(&mut a).await?;
    let d = s.domain().to_string();
    let requests = vec![
        raw_iq("get", "q-ping", Some(&d), vec![Element::new("ping", ns::PING)]),
        raw_iq("get", "q-disco", Some(&d), vec![Element::new("query", ns::DISCO_INFO)]),
        raw_iq("get", "q-roster", None, vec![Element::new("query", ns::ROSTER)]),
        raw_iq("get", "q-unknown", Some(&d), vec![Element::new("x", UNKNOWN_NS)]),
        raw_iq("set", "q-unknown-set", Some(&d), vec![Element::new("x", UNKNOWN_NS)]),
        raw_iq("get", "q-account-unknown", Some(&bare("bob")), vec![Element::new("x", UNKNOWN_NS)]),
        raw_iq("get", "q-nobody", Some(&bare("nobody")), vec![Element::new("query", ns::DISCO_INFO)]),
    ];
    for r in &requests {
        a.send(r).await?;
    }
    let mut replies: HashMap<String, Vec<Element>> = HashMap::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        if let Some(e) = a.recv_within(Duration::from_millis(200)).await? {
            if e.name() == "iq" && matches!(e.attr("type"), Some("result" | "error")) {
                replies.entry(e.attr("id").unwrap_or_default().to_string()).or_default().push(e);
            }
        }
    }
    let mut problems = Vec::new();
    for r in &requests {
        let id = r.attr("id").unwrap_or_default();
        match replies.get(id).map(Vec::as_slice) {
            Some([one]) => {
                if let Some(to) = r.attr("to") {
                    if one.attr("from") != Some(to) {
                        problems.push(format!("{id}: reply from {:?}, expected {to}: {one}", one.attr("from")));
                    }
                }
                if one.attr("to").is_some_and(|t| Some(t) != a.jid.as_deref()) {
                    problems.push(format!("{id}: reply to {:?}: {one}", one.attr("to")));
                }
            }
            Some(many) => problems.push(format!("{id}: {} replies: {many:?}", many.len())),
            None => problems.push(format!("{id}: no reply to {r}")),
        }
    }
    // The malformed and unknown ones must be errors.
    for id in ["q-unknown", "q-unknown-set", "q-account-unknown", "q-nobody"] {
        if let Some([one]) = replies.get(id).map(Vec::as_slice) {
            if one.attr("type") != Some("error") {
                problems.push(format!("{id}: expected an error, got {one}"));
            }
        }
    }
    assert!(problems.is_empty(), "RFC 6120 §8.2.3 violations:\n{}", problems.join("\n"));
    Ok(())
}

#[tokio::test]
async fn get_without_exactly_one_payload_is_an_error() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut a = s.login("alice", PW).await?;
    let d = s.domain().to_string();
    // RFC 6120 §8.2.3: "An IQ stanza of type "get" or "set" MUST contain exactly one child
    // element"; such a stanza does not conform to the schema (§8.3.3.1 <bad-request/>).
    for (id, kids) in [("none", vec![]), ("two", vec![Element::new("ping", ns::PING), Element::new("query", ns::DISCO_INFO)])] {
        a.send(&raw_iq("get", id, Some(&d), kids)).await?;
        let r = a.expect(|e| e.name() == "iq" && e.attr("id") == Some(id)).await?;
        assert_error(&r, &["bad-request", "not-acceptable", "service-unavailable", "feature-not-implemented"]);
    }
    Ok(())
}

#[tokio::test]
async fn error_replies_keep_the_id_and_swap_from_and_to() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut a = s.login("alice", PW).await?;
    let r = a.iq_get(Some(s.domain()), Element::new("x", UNKNOWN_NS)).await?;
    // RFC 6120 §8.3.1/§8.2.3: an IQ of an unknown namespace to the server.
    assert_error(&r, &["service-unavailable", "feature-not-implemented"]);
    assert_eq!(r.attr("from"), Some(s.domain()), "{r}");
    assert_eq!(r.attr("to"), a.jid.as_deref(), "{r}");
    let e = r.get_child("error", ns::CLIENT).expect("error child");
    assert!(e.attr("type").is_some(), "RFC 6120 §8.3.2: <error/> has a type: {r}");
    Ok(())
}

#[tokio::test]
async fn unknown_namespace_to_an_account_is_service_unavailable() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.login("alice", PW).await?;
    let r = a.iq_get(Some(&bare("bob")), Element::new("x", UNKNOWN_NS)).await?;
    // RFC 6121 §8.5.2.1.3 / §8.5.2.2.3: the server answers for the account.
    assert_error(&r, &["service-unavailable", "feature-not-implemented"]);
    assert_eq!(r.attr("from"), Some(bare("bob").as_str()), "{r}");
    Ok(())
}

#[tokio::test]
async fn iq_to_a_nonexistent_account_is_service_unavailable() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut a = s.login("alice", PW).await?;
    for to in [bare("nobody"), full("nobody", "x")] {
        let r = a.iq_get(Some(&to), Element::new("query", ns::DISCO_INFO)).await?;
        assert_error(&r, &["service-unavailable"]); // RFC 6121 §8.5.1
        assert_eq!(r.attr("from"), Some(to.as_str()), "{r}");
    }
    Ok(())
}

#[tokio::test]
async fn iq_to_an_offline_full_jid_is_service_unavailable() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.login("alice", PW).await?;
    let _b = s.online("bob", PW, "laptop").await?;
    let r = a.iq_get(Some(&full("bob", "gone")), Element::new("query", ns::VERSION)).await?;
    // RFC 6121 §8.5.3.2.1: "For an IQ stanza, the server MUST return a <service-unavailable/>".
    assert_error(&r, &["service-unavailable"]);
    assert_eq!(r.attr("from"), Some(full("bob", "gone").as_str()), "{r}");
    Ok(())
}

#[tokio::test]
async fn iq_to_an_online_full_jid_is_routed_and_the_answer_comes_back() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    a.send(&raw_iq("get", "v1", Some(&full("bob", "laptop")), vec![Element::new("query", ns::VERSION)])).await?;
    let req = b.expect(|e| e.name() == "iq" && e.attr("id") == Some("v1")).await?;
    assert_eq!(req.attr("from"), Some(full("alice", "phone").as_str()), "{req}");
    let reply = raw_iq(
        "result",
        "v1",
        Some(&full("alice", "phone")),
        vec![Element::new("query", ns::VERSION).text_child("name", ns::VERSION, "Blind")],
    );
    b.send(&reply).await?;
    let got = a.expect(|e| e.name() == "iq" && e.attr("id") == Some("v1")).await?;
    assert_eq!(got.attr("type"), Some("result"));
    assert_eq!(got.attr("from"), Some(full("bob", "laptop").as_str()), "{got}");
    Ok(())
}

#[tokio::test]
async fn result_and_error_iqs_are_never_answered() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    settle(&mut a).await?;
    let d = s.domain().to_string();
    a.send(&raw_iq("result", "stray-result", Some(&d), vec![])).await?;
    let err = Element::new("error", ns::CLIENT).attr_set("type", "cancel").child(Element::new("service-unavailable", ns::STANZAS));
    a.send(&raw_iq("error", "stray-error", Some(&d), vec![err])).await?;
    // RFC 6120 §8.2.3: an entity MUST NOT respond to result or error IQs.
    assert_none(&mut a, "a reply to a result/error IQ", |e| e.name() == "iq" && e.attr("id").is_some_and(|i| i.starts_with("stray-")))
        .await?;
    // The stream is still fine.
    let r = a.iq_get(Some(&d), Element::new("ping", ns::PING)).await?;
    assert_eq!(r.attr("type"), Some("result"));
    Ok(())
}

// ---------- vcard-temp (XEP-0054) ----------

fn vcard(fn_: &str) -> Element {
    Element::new("vCard", ns::VCARD).text_child("FN", ns::VCARD, fn_).text_child("NICKNAME", ns::VCARD, "ali")
}

#[tokio::test]
async fn vcard_set_and_get_own() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut a = s.login("alice", PW).await?;
    let r = a.iq_set(None, vcard("Alice Liddell")).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let r = a.iq_get(None, Element::new("vCard", ns::VCARD)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let v = r.get_child("vCard", ns::VCARD).expect("vCard in result");
    assert_eq!(v.child_text("FN", ns::VCARD).as_deref(), Some("Alice Liddell"));
    assert_eq!(v.child_text("NICKNAME", ns::VCARD).as_deref(), Some("ali"));
    Ok(())
}

#[tokio::test]
async fn vcard_get_of_another_account() -> anyhow::Result<()> {
    let s = server(&["alice", "bob", "carol"]).await?;
    let mut a = s.login("alice", PW).await?;
    a.iq_set(None, vcard("Alice Liddell")).await?;
    let mut b = s.login("bob", PW).await?;
    let r = b.iq_get(Some(&bare("alice")), Element::new("vCard", ns::VCARD)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    assert_eq!(r.attr("from"), Some(bare("alice").as_str()), "{r}");
    let v = r.get_child("vCard", ns::VCARD).expect("vCard in result");
    assert_eq!(v.child_text("FN", ns::VCARD).as_deref(), Some("Alice Liddell"));

    // XEP-0054 §3.1: no vCard → service-unavailable (older: item-not-found) or an empty vCard.
    let r = b.iq_get(Some(&bare("carol")), Element::new("vCard", ns::VCARD)).await?;
    if r.attr("type") == Some("error") {
        assert_error(&r, &["service-unavailable", "item-not-found"]);
    } else {
        let v = r.get_child("vCard", ns::VCARD);
        assert!(v.is_none_or(|v| v.children().next().is_none()), "carol has no vCard: {r}");
    }
    Ok(())
}

#[tokio::test]
async fn vcard_set_on_someone_elses_account_is_forbidden() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.login("alice", PW).await?;
    a.iq_set(None, vcard("Alice Liddell")).await?;
    let mut b = s.login("bob", PW).await?;
    let r = b.iq_set(Some(&bare("alice")), vcard("Hacked")).await?;
    assert_error(&r, &["forbidden", "not-allowed"]); // XEP-0054 §3.2
    let r = a.iq_get(None, Element::new("vCard", ns::VCARD)).await?;
    assert_eq!(r.get_child("vCard", ns::VCARD).and_then(|v| v.child_text("FN", ns::VCARD)).as_deref(), Some("Alice Liddell"));
    Ok(())
}

// ---------- Private XML storage (XEP-0049) ----------

const PREFS_NS: &str = "urn:example:blind:prefs";

fn private(child: Element) -> Element {
    Element::new("query", ns::PRIVATE).child(child)
}

#[tokio::test]
async fn private_storage_set_and_get_own() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut a = s.login("alice", PW).await?;
    let data = Element::new("prefs", PREFS_NS).text_child("colour", PREFS_NS, "teal");
    let r = a.iq_set(None, private(data)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let r = a.iq_get(None, private(Element::new("prefs", PREFS_NS))).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let got = r.get_child("query", ns::PRIVATE).and_then(|q| q.get_child("prefs", PREFS_NS)).expect("stored data comes back");
    assert_eq!(got.child_text("colour", PREFS_NS).as_deref(), Some("teal"));

    // A namespace never stored comes back empty (or as an error); never someone else's data.
    let r = a.iq_get(None, private(Element::new("other", "urn:example:blind:other"))).await?;
    if r.attr("type") == Some("result") {
        let q = r.get_child("query", ns::PRIVATE).expect("query");
        assert!(q.children().all(|c| c.children().next().is_none()), "nothing stored there: {r}");
    }
    Ok(())
}

#[tokio::test]
async fn private_storage_of_another_account_is_refused() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.login("alice", PW).await?;
    a.iq_set(None, private(Element::new("prefs", PREFS_NS).text_child("colour", PREFS_NS, "teal"))).await?;
    let mut b = s.login("bob", PW).await?;
    // XEP-0049 §3: "MUST return a Forbidden or Service Unavailable error".
    let r = b.iq_get(Some(&bare("alice")), private(Element::new("prefs", PREFS_NS))).await?;
    assert_error(&r, &["forbidden", "service-unavailable"]);
    let r = b.iq_set(Some(&bare("alice")), private(Element::new("prefs", PREFS_NS).text_child("colour", PREFS_NS, "red"))).await?;
    assert_error(&r, &["forbidden", "service-unavailable"]);
    let r = a.iq_get(None, private(Element::new("prefs", PREFS_NS))).await?;
    let got = r.get_child("query", ns::PRIVATE).and_then(|q| q.get_child("prefs", PREFS_NS)).and_then(|p| p.child_text("colour", PREFS_NS));
    assert_eq!(got.as_deref(), Some("teal"), "alice's data unchanged: {r}");
    Ok(())
}

#[tokio::test]
async fn private_storage_without_a_namespaced_child_is_refused() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut a = s.login("alice", PW).await?;
    // XEP-0049 §2.3: no namespaced child → Not Acceptable (§3 also mentions Bad Format).
    let r = a.iq_set(None, Element::new("query", ns::PRIVATE)).await?;
    assert_error(&r, &["not-acceptable", "bad-request"]);
    let r = a.iq_get(None, Element::new("query", ns::PRIVATE)).await?;
    assert_error(&r, &["not-acceptable", "bad-request"]);
    // Storing in jabber:iq:private itself is meaningless.
    let r = a.iq_set(None, private(Element::new("query", ns::PRIVATE))).await?;
    assert_error(&r, &["not-acceptable", "bad-request"]);
    Ok(())
}

// ---------- Last activity (XEP-0012) ----------

#[tokio::test]
async fn last_activity_of_an_online_contact_is_zero() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    subscribe(&mut b, &mut a).await?;
    let r = b.iq_get(Some(&bare("alice")), Element::new("query", ns::LAST)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    assert_eq!(r.get_child("query", ns::LAST).and_then(|q| q.attr("seconds")), Some("0"), "XEP-0012 §5: online → seconds='0': {r}");
    Ok(())
}

#[tokio::test]
async fn last_activity_of_an_offline_contact_is_seconds_since_logout() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    subscribe(&mut b, &mut a).await?;
    a.send(&Element::new("presence", ns::CLIENT).attr_set("type", "unavailable").text_child("status", ns::CLIENT, "Heading home")).await?;
    expect_presence(&mut b, &full("alice", "phone"), "unavailable").await?;
    a.close().await?;
    tokio::time::sleep(Duration::from_millis(2100)).await;

    let r = b.iq_get(Some(&bare("alice")), Element::new("query", ns::LAST)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let secs: u64 = r.get_child("query", ns::LAST).and_then(|q| q.attr("seconds")).expect("seconds").parse()?;
    assert!((2..60).contains(&secs), "XEP-0012 §5: seconds since logout, got {secs}: {r}");
    Ok(())
}

#[tokio::test]
async fn last_activity_for_a_non_contact_is_forbidden() -> anyhow::Result<()> {
    let s = server(&["alice", "carol"]).await?;
    let _a = s.online("alice", PW, "phone").await?;
    let mut c = s.online("carol", PW, "desk").await?;
    let r = c.iq_get(Some(&bare("alice")), Element::new("query", ns::LAST)).await?;
    assert_error(&r, &["forbidden"]); // XEP-0012 §5
    Ok(())
}

// ---------- Service discovery on an account (XEP-0030) ----------

#[tokio::test]
async fn disco_info_on_an_account_shows_account_registered() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    mutual(&mut a, &mut b).await?;
    let r = b.iq_get(Some(&bare("alice")), Element::new("query", ns::DISCO_INFO)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    assert_eq!(r.attr("from"), Some(bare("alice").as_str()), "{r}");
    let q = r.get_child("query", ns::DISCO_INFO).expect("query");
    assert!(
        q.children().any(|i| i.name() == "identity" && i.attr("category") == Some("account") && i.attr("type") == Some("registered")),
        "XEP-0030 / registry: identity account/registered in {r}"
    );
    assert!(q.children().any(|f| f.name() == "feature" && f.attr("var") == Some(ns::DISCO_INFO)), "disco#info listed in {r}");

    // Own account too.
    let r = a.iq_get(Some(&bare("alice")), Element::new("query", ns::DISCO_INFO)).await?;
    let q = r.get_child("query", ns::DISCO_INFO).expect("query");
    assert!(q.children().any(|i| i.name() == "identity" && i.attr("category") == Some("account")), "{r}");
    Ok(())
}
