//! Black-box conformance: what a client asks the server right after connecting — ping
//! (XEP-0199), version (XEP-0092), time (XEP-0202), uptime (XEP-0012), disco#info (XEP-0030)
//! and IQ semantics (RFC 6120 §8.2.3, §8.4). Written from the specifications only.

mod blind_common;

use blind_common::*;
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{Client, TestServer, DOMAIN};

async fn alice() -> anyhow::Result<(TestServer, Client)> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password1").await?;
    let c = s.login("alice", "password1").await?;
    Ok((s, c))
}

async fn disco_features(c: &mut Client) -> anyhow::Result<(Element, Vec<String>)> {
    let r = c.iq_get(Some(DOMAIN), Element::new("query", ns::DISCO_INFO)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let q = r.get_child("query", ns::DISCO_INFO).expect("query").clone();
    let vars = q.children().filter(|f| f.name() == "feature").filter_map(|f| f.attr("var")).map(String::from).collect();
    Ok((q, vars))
}

#[tokio::test]
async fn ping_to_server_returns_empty_result_from_the_domain() -> anyhow::Result<()> {
    // XEP-0199 §4.2; RFC 6120 §8.1.2.1: the reply comes from the server's JID.
    let (_s, mut c) = alice().await?;
    let r = c.iq_get(Some(DOMAIN), Element::new("ping", ns::PING)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    assert_eq!(r.attr("from"), Some(DOMAIN), "{r}");
    assert_eq!(r.attr("to"), c.jid.as_deref(), "{r}");
    Ok(())
}

#[tokio::test]
async fn version_has_name_and_version() -> anyhow::Result<()> {
    // XEP-0092 §2: <name/> and <version/> are REQUIRED; <os/> optional.
    let (_s, mut c) = alice().await?;
    let r = c.iq_get(Some(DOMAIN), Element::new("query", ns::VERSION)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let q = r.get_child("query", ns::VERSION).expect("query");
    assert!(q.child_text("name", ns::VERSION).is_some_and(|n| !n.trim().is_empty()), "{r}");
    assert!(q.child_text("version", ns::VERSION).is_some_and(|n| !n.trim().is_empty()), "{r}");
    Ok(())
}

#[tokio::test]
async fn time_has_tzo_and_utc_close_to_now() -> anyhow::Result<()> {
    // XEP-0202 §4: <tzo/> as ±hh:mm or Z, <utc/> as XEP-0082 DateTime in UTC.
    let (_s, mut c) = alice().await?;
    let r = c.iq_get(Some(DOMAIN), Element::new("time", ns::TIME)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let t = r.get_child("time", ns::TIME).expect("time");
    let tzo = t.child_text("tzo", ns::TIME).expect("no <tzo/>");
    let ok_tzo = tzo == "Z"
        || (tzo.len() == 6
            && (tzo.starts_with('+') || tzo.starts_with('-'))
            && tzo.as_bytes()[3] == b':'
            && tzo[1..3].chars().all(|ch| ch.is_ascii_digit())
            && tzo[4..6].chars().all(|ch| ch.is_ascii_digit()));
    assert!(ok_tzo, "bad tzo {tzo:?}");
    let utc = t.child_text("utc", ns::TIME).expect("no <utc/>");
    assert!(utc.ends_with('Z'), "utc must be in UTC: {utc}");
    let when = parse_xep82(&utc)?;
    assert!((when - now_unix()).abs() < 60, "server time {utc} is far from now");
    Ok(())
}

#[tokio::test]
async fn last_activity_on_the_server_is_its_uptime() -> anyhow::Result<()> {
    // XEP-0012 §5: a query to a server returns its uptime in 'seconds'.
    let (_s, mut c) = alice().await?;
    let r = c.iq_get(Some(DOMAIN), Element::new("query", ns::LAST)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let q = r.get_child("query", ns::LAST).expect("query");
    let secs: u64 = q.attr("seconds").expect("no seconds").parse()?;
    assert!(secs < 600, "a server started just now reports {secs}s uptime");
    Ok(())
}

#[tokio::test]
async fn disco_info_identity_is_server_im() -> anyhow::Result<()> {
    // XEP-0030 §3.1 + registry: an IM server is category 'server', type 'im'.
    let (_s, mut c) = alice().await?;
    let (q, _) = disco_features(&mut c).await?;
    assert!(
        q.children().any(|i| i.name() == "identity" && i.attr("category") == Some("server") && i.attr("type") == Some("im")),
        "no server/im identity: {q}"
    );
    Ok(())
}

#[tokio::test]
async fn disco_info_lists_features_clients_rely_on() -> anyhow::Result<()> {
    let (_s, mut c) = alice().await?;
    let (_, vars) = disco_features(&mut c).await?;
    let missing = [
        ns::DISCO_INFO, // XEP-0030 §3.1: MUST
        ns::DISCO_ITEMS,
        ns::PING,     // XEP-0199 §8
        ns::VCARD,    // XEP-0054
        "msgoffline", // XEP-0160 §6
        ns::VERSION,  // XEP-0092, since it answers
        ns::TIME,     // XEP-0202, since it answers
        ns::LAST,     // XEP-0012, since it answers
    ]
    .into_iter()
    .filter(|f| !vars.iter().any(|v| v == f))
    .collect::<Vec<_>>();
    assert!(missing.is_empty(), "server disco#info lacks {missing:?}; has {vars:?}");
    Ok(())
}

#[tokio::test]
async fn features_that_work_are_advertised_in_disco() -> anyhow::Result<()> {
    // XEP-0280 §2 ("MUST advertise"), XEP-0191 §2, XEP-0077 §3.3: clients only use these when
    // the server's disco#info lists them, so a working feature must be advertised.
    let (_s, mut c) = alice().await?;
    let (_, vars) = disco_features(&mut c).await?;
    let probes = [
        (ns::CARBONS, "set", None, Element::new("enable", ns::CARBONS)),
        (ns::BLOCKING, "get", None, Element::new("blocklist", ns::BLOCKING)),
        (ns::REGISTER, "get", Some(DOMAIN), Element::new("query", ns::REGISTER)),
    ];
    let mut missing = Vec::new();
    for (feature, kind, to, payload) in probes {
        let r = c.iq(kind, to, payload).await?;
        if r.attr("type") == Some("result") && !vars.iter().any(|v| v == feature) {
            missing.push(feature);
        }
    }
    assert!(missing.is_empty(), "these work but are not in the server's disco#info: {missing:?}; has {vars:?}");
    Ok(())
}

#[tokio::test]
async fn carbons_can_be_enabled_with_an_iq() -> anyhow::Result<()> {
    // XEP-0280 §4: clients without SASL2 enable carbons with this IQ (no 'to').
    let (_s, mut c) = alice().await?;
    let r = c.iq_set(None, Element::new("enable", ns::CARBONS)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    Ok(())
}

#[tokio::test]
async fn disco_info_has_no_duplicate_features_or_identities() -> anyhow::Result<()> {
    // XEP-0115 §5.4 (verification string) relies on there being no duplicates.
    let (_s, mut c) = alice().await?;
    let (q, vars) = disco_features(&mut c).await?;
    let mut sorted = vars.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), vars.len(), "duplicate features: {vars:?}");
    let mut ids: Vec<String> = q
        .children()
        .filter(|i| i.name() == "identity")
        .map(|i| {
            format!(
                "{}/{}/{}/{}",
                i.attr("category").unwrap_or(""),
                i.attr("type").unwrap_or(""),
                i.attr("xml:lang").unwrap_or(""),
                i.attr("name").unwrap_or("")
            )
        })
        .collect();
    let n = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), n, "duplicate identities: {q}");
    Ok(())
}

#[tokio::test]
async fn disco_items_on_the_server_answers() -> anyhow::Result<()> {
    let (_s, mut c) = alice().await?;
    let r = c.iq_get(Some(DOMAIN), Element::new("query", ns::DISCO_ITEMS)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    assert!(r.has_child("query", ns::DISCO_ITEMS), "{r}");
    Ok(())
}

#[tokio::test]
async fn disco_info_on_unknown_node_is_item_not_found() -> anyhow::Result<()> {
    // XEP-0030 §3.1: an unknown node → <item-not-found/>.
    let (_s, mut c) = alice().await?;
    let r = c.iq_get(Some(DOMAIN), Element::new("query", ns::DISCO_INFO).attr_set("node", "urn:example:no-such-node")).await?;
    assert_eq!(r.attr("type"), Some("error"), "{r}");
    assert_eq!(stanza_error(&r).map(|e| e.1).as_deref(), Some("item-not-found"), "{r}");
    Ok(())
}

#[tokio::test]
async fn unknown_iq_namespace_gets_service_unavailable() -> anyhow::Result<()> {
    // RFC 6120 §8.4: an IQ get/set with an unknown payload → <service-unavailable/>.
    let (_s, mut c) = alice().await?;
    let r = c.iq_get(Some(DOMAIN), Element::new("query", "urn:example:unknown:0")).await?;
    assert_eq!(r.attr("type"), Some("error"), "{r}");
    assert_eq!(stanza_error(&r), Some(("cancel".into(), "service-unavailable".into())), "{r}");
    // RFC 6120 §8.3.1: the error reply carries the same id and comes from the addressee.
    assert_eq!(r.attr("from"), Some(DOMAIN), "{r}");
    Ok(())
}

#[tokio::test]
async fn iq_get_without_payload_is_an_error() -> anyhow::Result<()> {
    // RFC 6120 §8.2.3: get/set MUST contain exactly one payload child.
    let (_s, mut c) = alice().await?;
    c.send_raw("<iq type='get' id='empty1' to='quark.test'/>").await?;
    let r = c.expect(|e| e.name() == "iq" && e.attr("id") == Some("empty1")).await?;
    assert_eq!(r.attr("type"), Some("error"), "{r}");
    let cond = stanza_error(&r).map(|e| e.1).unwrap_or_default();
    assert!(["bad-request", "service-unavailable", "feature-not-implemented"].contains(&cond.as_str()), "{r}");
    Ok(())
}

#[tokio::test]
async fn unsolicited_iq_result_to_server_gets_no_reply() -> anyhow::Result<()> {
    // RFC 6120 §8.2.3: an entity MUST NOT respond to a result or error.
    let (_s, mut c) = alice().await?;
    c.send_raw("<iq type='result' id='stray1' to='quark.test'/>").await?;
    c.send_raw("<iq type='error' id='stray2' to='quark.test'><error type='cancel'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>").await?;
    c.expect_silence(QUIET).await?;
    // And the stream survives.
    let r = c.iq_get(Some(DOMAIN), Element::new("ping", ns::PING)).await?;
    assert_eq!(r.attr("type"), Some("result"));
    Ok(())
}

#[tokio::test]
async fn ping_without_to_is_answered_on_behalf_of_the_account() -> anyhow::Result<()> {
    // RFC 6120 §10.3.3: no 'to' means the account itself; the server answers for it.
    let (_s, mut c) = alice().await?;
    let r = c.iq_get(None, Element::new("ping", ns::PING)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    Ok(())
}
