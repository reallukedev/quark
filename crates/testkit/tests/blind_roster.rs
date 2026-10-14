//! Black-box roster tests (RFC 6121 §2), written from the spec.

use crate::blind_util;

use blind_util::*;
use quark_testkit::quark_core::{ns, Element};

#[tokio::test]
async fn roster_get_on_a_new_account_is_an_empty_result() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut a = s.login("alice", PW).await?;
    let r = a.iq_get(None, Element::new("query", ns::ROSTER)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let q = r.get_child("query", ns::ROSTER).expect("RFC 6121 §2.1.3: the result carries a <query/> (no ver was sent)");
    assert!(items(q).is_empty(), "a new roster is empty: {r}");
    Ok(())
}

#[tokio::test]
async fn roster_set_adds_an_item_with_name_and_groups() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.login("alice", PW).await?;
    roster(&mut a).await?;
    let it = item(&bare("bob")).attr_set("name", "Bob").text_child("group", ns::ROSTER, "Work").text_child("group", ns::ROSTER, "Friends");
    let r = roster_set(&mut a, it).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");

    // §2.3.2: the server pushes the new item to every interested resource, this one included.
    let pushed = expect_push(&mut a, &bare("bob")).await?;
    assert_eq!(pushed.name.as_deref(), Some("Bob"));
    assert_eq!(pushed.subscription, "none");
    assert_eq!(pushed.ask, None);
    assert_eq!(pushed.groups, vec!["Friends".to_string(), "Work".to_string()]);

    let all = roster(&mut a).await?;
    assert_eq!(all, vec![pushed], "the roster now holds exactly that item");
    Ok(())
}

#[tokio::test]
async fn roster_set_updates_name_and_groups_of_an_existing_item() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.login("alice", PW).await?;
    roster(&mut a).await?;
    roster_set(&mut a, item(&bare("bob")).attr_set("name", "Bob").text_child("group", ns::ROSTER, "Work")).await?;
    expect_push(&mut a, &bare("bob")).await?;

    let r = roster_set(&mut a, item(&bare("bob")).attr_set("name", "Robert").text_child("group", ns::ROSTER, "Family")).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let pushed = expect_push(&mut a, &bare("bob")).await?;
    assert_eq!(pushed.name.as_deref(), Some("Robert"));
    assert_eq!(pushed.groups, vec!["Family".to_string()], "groups are replaced, not merged (§2.4)");

    let all = roster(&mut a).await?;
    assert_eq!(all.len(), 1, "updating does not duplicate: {all:?}");
    assert_eq!(all[0].name.as_deref(), Some("Robert"));
    assert_eq!(all[0].groups, vec!["Family".to_string()]);
    Ok(())
}

#[tokio::test]
async fn roster_remove_deletes_the_item_and_pushes_remove() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.login("alice", PW).await?;
    roster(&mut a).await?;
    roster_set(&mut a, item(&bare("bob"))).await?;
    expect_push(&mut a, &bare("bob")).await?;

    let r = roster_set(&mut a, item(&bare("bob")).attr_set("subscription", "remove")).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let pushed = expect_push(&mut a, &bare("bob")).await?;
    assert_eq!(pushed.subscription, "remove", "§2.5.2: the push has subscription='remove'");
    assert!(roster(&mut a).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn roster_remove_of_an_unknown_item_is_item_not_found() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut a = s.login("alice", PW).await?;
    let r = roster_set(&mut a, item(&bare("nobody")).attr_set("subscription", "remove")).await?;
    // RFC 6121 §2.5.3.
    assert_error(&r, &["item-not-found"]);
    Ok(())
}

#[tokio::test]
async fn roster_pushes_go_only_to_interested_resources() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut phone = s.online("alice", PW, "phone").await?;
    // Interested (fetched the roster) but not available.
    let mut desk = s.login_as("alice", PW, "desk").await?;
    roster(&mut desk).await?;
    // Available but never asked for the roster: not interested (§2.1.6).
    let mut quiet = s.login_as("alice", PW, "quiet").await?;
    quiet.send(&Element::new("presence", ns::CLIENT)).await?;
    settle(&mut phone).await?;
    settle(&mut quiet).await?;

    roster_set(&mut phone, item(&bare("bob")).attr_set("name", "Bob")).await?;
    expect_push(&mut phone, &bare("bob")).await?;
    expect_push(&mut desk, &bare("bob")).await?;
    assert_none(&mut quiet, "a roster push (it never requested the roster)", is_roster_push).await?;
    Ok(())
}

#[tokio::test]
async fn roster_versioning_is_advertised() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let a = s.login("alice", PW).await?;
    let f = a.features.as_ref().expect("features");
    assert!(f.get_child("ver", ns::ROSTER_VER).is_some(), "RFC 6121 §2.6.1: <ver xmlns='urn:xmpp:features:rosterver'/> in {f}");
    Ok(())
}

fn ver_query(ver: &str) -> Element {
    Element::new("query", ns::ROSTER).attr_set("ver", ver)
}

#[tokio::test]
async fn roster_versioning_unchanged_version_sends_nothing_new() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.login_as("alice", PW, "one").await?;
    roster_set(&mut a, item(&bare("bob")).attr_set("name", "Bob")).await?;
    let r = a.iq_get(None, ver_query("")).await?;
    let q = r.get_child("query", ns::ROSTER).expect("§2.6.3: an empty ver asks for the full roster");
    let ver = q.attr("ver").expect("§2.6.3: the result carries a ver").to_string();
    assert_eq!(items(q).len(), 1);

    let mut b = s.login_as("alice", PW, "two").await?;
    let r = b.iq_get(None, ver_query(&ver)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    // Either an empty result, or the complete roster with the same version (§2.6.3).
    if let Some(q) = r.get_child("query", ns::ROSTER) {
        assert_eq!(q.attr("ver"), Some(ver.as_str()), "unchanged roster keeps its version: {r}");
        assert_eq!(items(q).len(), 1, "a returned roster must be complete: {r}");
    }
    assert_none(&mut b, "a roster push (the roster did not change)", is_roster_push).await?;
    Ok(())
}

#[tokio::test]
async fn roster_versioning_changed_version_gets_full_roster_or_pushes() -> anyhow::Result<()> {
    let s = server(&["alice", "bob", "carol"]).await?;
    let mut a = s.login_as("alice", PW, "one").await?;
    let r = a.iq_get(None, ver_query("")).await?;
    let v1 = r.get_child("query", ns::ROSTER).and_then(|q| q.attr("ver")).expect("ver in result").to_string();

    roster_set(&mut a, item(&bare("bob"))).await?;
    // §2.6.3/§2.1.6: with versioning on, every push carries the new version.
    let push = a.expect(is_roster_push).await?;
    a.answer(&push).await?;
    let v2 = push.get_child("query", ns::ROSTER).and_then(|q| q.attr("ver")).expect("ver in roster push").to_string();
    assert_ne!(v1, v2, "the version changes when the roster changes");

    let mut b = s.login_as("alice", PW, "two").await?;
    let r = b.iq_get(None, ver_query(&v1)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    match r.get_child("query", ns::ROSTER) {
        Some(q) => {
            assert_ne!(q.attr("ver"), Some(v1.as_str()), "a changed roster has a new ver: {r}");
            assert!(items(q).iter().any(|i| i.jid == bare("bob")), "full roster includes bob: {r}");
        }
        None => {
            let pushed = expect_push(&mut b, &bare("bob")).await?;
            assert_eq!(pushed.subscription, "none");
        }
    }
    Ok(())
}

#[tokio::test]
async fn roster_set_with_two_items_is_bad_request() -> anyhow::Result<()> {
    let s = server(&["alice", "bob", "carol"]).await?;
    let mut a = s.login("alice", PW).await?;
    let q = Element::new("query", ns::ROSTER).child(item(&bare("bob"))).child(item(&bare("carol")));
    let r = a.iq_set(None, q).await?;
    assert_error(&r, &["bad-request"]); // RFC 6121 §2.3.3
    assert!(roster(&mut a).await?.is_empty(), "nothing was added");
    Ok(())
}

#[tokio::test]
async fn roster_set_with_duplicate_groups_is_bad_request() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.login("alice", PW).await?;
    let it = item(&bare("bob")).text_child("group", ns::ROSTER, "Friends").text_child("group", ns::ROSTER, "Friends");
    let r = roster_set(&mut a, it).await?;
    assert_error(&r, &["bad-request"]); // RFC 6121 §2.3.3
    assert!(roster(&mut a).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn roster_set_with_an_empty_group_is_not_acceptable() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.login("alice", PW).await?;
    let r = roster_set(&mut a, item(&bare("bob")).text_child("group", ns::ROSTER, "")).await?;
    assert_error(&r, &["not-acceptable"]); // RFC 6121 §2.3.3
    Ok(())
}

#[tokio::test]
async fn roster_set_with_an_invalid_jid_is_refused() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut a = s.login("alice", PW).await?;
    for bad in ["bad@@quark.test", "@quark.test", "a b@quark.test"] {
        let r = roster_set(&mut a, item(bad)).await?;
        assert_error(&r, &["jid-malformed", "bad-request", "not-acceptable"]);
    }
    let r = a.iq_set(None, roster_query(Element::new("item", ns::ROSTER).attr_set("name", "no jid"))).await?;
    assert_error(&r, &["jid-malformed", "bad-request", "not-acceptable"]);
    assert!(roster(&mut a).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn roster_iq_to_someone_elses_account_is_refused() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    let mut a = s.login("alice", PW).await?;
    let mut b = s.login("bob", PW).await?;
    roster_set(&mut b, item(&bare("carol")).attr_set("name", "Carol")).await?;

    let r = a.iq_get(Some(&bare("bob")), Element::new("query", ns::ROSTER)).await?;
    assert_error(&r, &["forbidden", "service-unavailable", "not-allowed", "not-authorized"]);
    assert!(r.get_child("query", ns::ROSTER).is_none_or(|q| items(q).is_empty()), "bob's roster must not leak: {r}");
    assert_eq!(r.attr("from"), Some(bare("bob").as_str()), "error comes from the addressed entity: {r}");

    let r = a.iq_set(Some(&bare("bob")), roster_query(item(&bare("mallory")))).await?;
    assert_error(&r, &["forbidden", "service-unavailable", "not-allowed", "not-authorized"]); // §2.3.3
    let bobs = roster(&mut b).await?;
    assert_eq!(bobs.len(), 1, "bob's roster unchanged: {bobs:?}");
    assert_eq!(bobs[0].jid, bare("carol"));
    Ok(())
}
