//! IQs addressed to the server domain are about the server, not the sender's own account (RFC
//! 6120 §10.3.3: only an IQ without `to` is handled for the account).

use quark_testkit::quark_core::{ns, Element};
use quark_testkit::TestServer;

use crate::common;

const PW: &str = "password-1";

fn vcard(name: &str) -> Element {
    Element::new("vCard", ns::VCARD).text_child("FN", ns::VCARD, name)
}

#[tokio::test]
async fn a_vcard_to_the_domain_is_the_servers_own() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", PW).await?;
    let mut a = s.login("alice", PW).await?;
    let r = a.iq_set(None, vcard("Alice")).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");

    let r = a.iq_get(Some(s.domain()), Element::new("vCard", ns::VCARD)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let v = r.get_child("vCard", ns::VCARD).expect("a vCard");
    assert!(v.child_text("FN", ns::VCARD).is_none(), "the server's vCard, not alice's: {r}");

    let r = a.iq_set(Some(s.domain()), vcard("Mallory")).await?;
    assert_eq!(common::condition(&r), "not-allowed", "{r}");
    let r = a.iq_get(None, Element::new("vCard", ns::VCARD)).await?;
    assert_eq!(r.get_child("vCard", ns::VCARD).and_then(|v| v.child_text("FN", ns::VCARD)).as_deref(), Some("Alice"), "{r}");
    Ok(())
}

#[tokio::test]
async fn history_and_private_storage_to_the_domain_are_not_the_accounts() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", PW).await?;
    let mut a = s.login("alice", PW).await?;

    let r = a.iq_set(Some(s.domain()), Element::new("query", ns::MAM)).await?;
    assert_eq!(common::condition(&r), "service-unavailable", "{r}");
    let r = a.iq_set(None, Element::new("query", ns::MAM).attr_set("queryid", "q1")).await?;
    assert_eq!(r.attr("type"), Some("result"), "the account's own archive still answers: {r}");

    let item = || Element::new("query", ns::PRIVATE).child(Element::new("prefs", "urn:example:prefs"));
    let r = a.iq_set(Some(s.domain()), item()).await?;
    assert_eq!(common::condition(&r), "service-unavailable", "{r}");
    let r = a.iq_set(None, item()).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    Ok(())
}
