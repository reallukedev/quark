//! XEP-0163 Personal Eventing Protocol over XEP-0060, the way OMEMO, avatar, bookmark and nick
//! clients use it. Black-box: written from the XEPs only.

mod blind_xep;

use std::time::Duration;

use anyhow::{bail, ensure, Context as _};
use base64::Engine as _;
use blind_xep::*;
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{caps_ver, Client, TestServer};

const TUNE: &str = "http://jabber.org/protocol/tune";
const TUNE_NOTIFY: &str = "http://jabber.org/protocol/tune+notify";

fn tune(title: &str) -> Element {
    Element::new("tune", TUNE).text_child("title", TUNE, title)
}

async fn server(users: &[&str]) -> anyhow::Result<TestServer> {
    let s = TestServer::start().await?;
    for u in users {
        s.add_user(u, PW).await?;
    }
    Ok(s)
}

async fn publish_ok(c: &mut Client, node: &str, id: &str, payload: Element, options: &[(&str, &str)]) -> anyhow::Result<()> {
    let r = c.iq_set(None, publish(node, Some(id), payload, options)).await?;
    ensure!(is_result(&r), "publish to {node} failed: {r}");
    Ok(())
}

/// Reads for a while and fails if an event for `node` arrives.
async fn no_event(c: &mut Client, node: &str) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + QUIET;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match c.recv_within(left).await? {
            None => return Ok(()),
            Some(e) if is_event_for(&e, node) => bail!("expected no event for {node}, got {e}"),
            Some(_) => {}
        }
    }
}

async fn event(c: &mut Client, node: &str) -> anyhow::Result<Element> {
    c.expect(|e| is_event_for(e, node)).await.with_context(|| format!("no event for {node}"))
}

/// XEP-0115 §5.2 / §5.3 worked example: our client computes `ver` the way the spec does, so
/// the server can verify the caps we send.
#[test]
fn caps_ver_matches_xep0115_example() {
    let mut q = Element::new("query", ns::DISCO_INFO).child(
        Element::new("identity", ns::DISCO_INFO).attr_set("category", "client").attr_set("type", "pc").attr_set("name", "Exodus 0.9.1"),
    );
    for f in ["http://jabber.org/protocol/caps", ns::DISCO_INFO, ns::DISCO_ITEMS, "http://jabber.org/protocol/muc"] {
        q.append(Element::new("feature", ns::DISCO_INFO).attr_set("var", f));
    }
    assert_eq!(caps_ver(&q), "QgayPKawpkPSDYmwT/WM94uAlu0=");
}

/// XEP-0163 §6.1: the account advertises the pubsub/pep identity; XEP-0060 §7.1.5 / XEP-0223:
/// publish-options support is advertised.
#[tokio::test]
async fn account_disco_shows_pep_identity() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut a = s.login("alice", PW).await?;
    let info = disco_info(&mut a, Some(&jid("alice"))).await?;
    ensure!(is_result(&info), "disco#info on the account failed: {info}");
    ensure!(has_identity(&info, "pubsub", "pep"), "no pubsub/pep identity: {info}");
    let f = disco_features(&info);
    ensure!(f.iter().any(|v| v == "http://jabber.org/protocol/pubsub#publish-options"), "publish-options not advertised: {f:?}");
    Ok(())
}

/// XEP-0163 §4.3 / §4.3.1: publishing auto-creates the node; contacts with a presence
/// subscription that advertise `+notify` get the event, as do the owner's own interested
/// resources; contacts without `+notify` and non-contacts get nothing.
#[tokio::test]
async fn publish_autocreates_and_notifies_only_interested_contacts() -> anyhow::Result<()> {
    let s = server(&["alice", "bob", "carol", "dave"]).await?;
    s.make_contacts("alice", "bob").await?;
    s.make_contacts("alice", "dave").await?;
    let mut bob = online_caps(&s, "bob", "b", &[TUNE_NOTIFY]).await?;
    let mut dave = online_caps(&s, "dave", "d", &[]).await?;
    let mut carol = online_caps(&s, "carol", "c", &[TUNE_NOTIFY]).await?;
    let mut alice2 = online_caps(&s, "alice", "two", &[TUNE_NOTIFY]).await?;
    let mut alice = online_caps(&s, "alice", "one", &[]).await?;

    publish_ok(&mut alice, TUNE, "t1", tune("Song"), &[]).await?;

    let ev = event(&mut bob, TUNE).await?;
    assert_eq!(ev.attr("from"), Some(jid("alice").as_str()), "events come from the account's bare JID: {ev}");
    assert_eq!(item_ids(&ev), vec!["t1".to_string()], "{ev}");
    let item = &items_of(&ev)[0];
    assert_eq!(item.get_child("tune", TUNE).and_then(|t| t.child_text("title", TUNE)).as_deref(), Some("Song"), "{ev}");

    let own = event(&mut alice2, TUNE).await?;
    assert_eq!(item_ids(&own), vec!["t1".to_string()], "{own}");

    no_event(&mut dave, TUNE).await?;
    no_event(&mut carol, TUNE).await?;
    Ok(())
}

/// XEP-0163 "Recommended Defaults" (send_last_published_item = on_sub_and_presence): a contact coming online
/// with `+notify` gets the last published item.
#[tokio::test]
async fn last_item_sent_when_contact_comes_online() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    s.make_contacts("alice", "bob").await?;
    let mut alice = s.online("alice", PW, "one").await?;
    publish_ok(&mut alice, TUNE, "t1", tune("First"), &[]).await?;
    publish_ok(&mut alice, TUNE, "t2", tune("Second"), &[]).await?;

    let mut bob = s.login_as("bob", PW, "b").await?;
    bob.iq_get(None, Element::new("query", ns::ROSTER)).await?;
    let caps = bob.caps(&[TUNE_NOTIFY]);
    bob.send(&quark_testkit::presence(None, None).child(caps)).await?;
    let ev = event(&mut bob, TUNE).await?;
    assert_eq!(item_ids(&ev), vec!["t2".to_string()], "only the last item is sent: {ev}");
    Ok(())
}

/// XEP-0060 §4.5 / XEP-0163 "Recommended Defaults": default access model `presence`: a contact with a
/// subscription can fetch items, a stranger can't (XEP-0060 §6.5.9, presence-subscription-required).
#[tokio::test]
async fn presence_access_model_is_default() -> anyhow::Result<()> {
    let s = server(&["alice", "bob", "carol"]).await?;
    s.make_contacts("alice", "bob").await?;
    let mut alice = s.online("alice", PW, "one").await?;
    publish_ok(&mut alice, TUNE, "t1", tune("Song"), &[]).await?;

    let mut bob = s.online("bob", PW, "b").await?;
    let r = bob.iq_get(Some(&jid("alice")), items_request(TUNE, &[])).await?;
    ensure!(is_result(&r), "a contact may fetch presence-model items: {r}");
    assert_eq!(item_ids(&r), vec!["t1".to_string()], "{r}");

    let mut carol = s.online("carol", PW, "c").await?;
    let r = carol.iq_get(Some(&jid("alice")), items_request(TUNE, &[])).await?;
    ensure!(r.attr("type") == Some("error"), "a stranger must not get presence-model items: {r}");
    let c = condition(&r).unwrap_or_default();
    ensure!(matches!(c.as_str(), "not-authorized" | "forbidden" | "item-not-found"), "unexpected condition {c}: {r}");
    ensure!(items_of(&r).is_empty(), "no items may leak in the error: {r}");
    Ok(())
}

/// The OMEMO case (XEP-0384 §5.3 + XEP-0060 §7.1.5): publishing the device list with
/// `pubsub#access_model=open` lets anyone, contact or not, fetch it; bundles likewise by id.
#[tokio::test]
async fn open_access_via_publish_options_lets_strangers_fetch() -> anyhow::Result<()> {
    let s = server(&["alice", "carol"]).await?;
    let mut alice = s.online("alice", PW, "one").await?;
    let devicelist = "eu.siacs.conversations.axolotl.devicelist";
    let list = Element::new("list", ns::OMEMO).child(Element::new("device", ns::OMEMO).attr_set("id", "12345"));
    publish_ok(&mut alice, devicelist, "current", list, &[("pubsub#access_model", "open")]).await?;

    let devices = "urn:xmpp:omemo:2:devices";
    let list2 = Element::new("devices", "urn:xmpp:omemo:2").child(Element::new("device", "urn:xmpp:omemo:2").attr_set("id", "777"));
    publish_ok(&mut alice, devices, "current", list2, &[("pubsub#access_model", "open")]).await?;
    let bundles = "urn:xmpp:omemo:2:bundles";
    let opts = [("pubsub#access_model", "open"), ("pubsub#max_items", "max")];
    publish_ok(&mut alice, bundles, "777", Element::new("bundle", "urn:xmpp:omemo:2").text("b777"), &opts).await?;
    publish_ok(&mut alice, bundles, "778", Element::new("bundle", "urn:xmpp:omemo:2").text("b778"), &opts).await?;

    let mut carol = s.online("carol", PW, "c").await?;
    let r = carol.iq_get(Some(&jid("alice")), items_request(devicelist, &[])).await?;
    ensure!(is_result(&r), "open node must be readable by anyone: {r}");
    let items = items_of(&r);
    ensure!(items.len() == 1, "{r}");
    let id = items[0].get_child("list", ns::OMEMO).and_then(|l| l.get_child("device", ns::OMEMO)).and_then(|d| d.attr("id"));
    assert_eq!(id, Some("12345"), "{r}");

    let r = carol.iq_get(Some(&jid("alice")), items_request(devices, &[])).await?;
    ensure!(is_result(&r) && item_ids(&r) == ["current"], "{r}");
    let r = carol.iq_get(Some(&jid("alice")), items_request(bundles, &["778"])).await?;
    ensure!(is_result(&r), "{r}");
    let items = items_of(&r);
    ensure!(items.len() == 1 && items[0].attr("id") == Some("778"), "only the requested bundle: {r}");
    assert_eq!(items[0].child_text("bundle", "urn:xmpp:omemo:2").as_deref(), Some("b778"));
    Ok(())
}

/// XEP-0060 §7.1.5: publish-options are preconditions; a mismatch fails with `<conflict/>` +
/// `<precondition-not-met/>`, a match succeeds, and the default model is `presence`.
#[tokio::test]
async fn publish_options_precondition_not_met() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut alice = s.online("alice", PW, "one").await?;
    let node = "urn:example:blind:pre";
    publish_ok(&mut alice, node, "a", payload(node, "1"), &[("pubsub#access_model", "whitelist")]).await?;

    let r = alice.iq_set(None, publish(node, Some("b"), payload(node, "2"), &[("pubsub#access_model", "open")])).await?;
    ensure!(r.attr("type") == Some("error"), "a mismatching precondition must fail: {r}");
    let (kind, cond) = error_of(&r).context("no error condition")?;
    assert_eq!(cond, "conflict", "{r}");
    assert_eq!(kind, "cancel", "{r}");
    ensure!(app_error(&r, ns::PUBSUB_ERRORS).is_some_and(|e| e.name() == "precondition-not-met"), "{r}");

    let r = alice.iq_get(None, items_request(node, &[])).await?;
    ensure!(is_result(&r) && item_ids(&r) == ["a"], "the refused item must not be stored: {r}");

    publish_ok(&mut alice, node, "c", payload(node, "3"), &[("pubsub#access_model", "whitelist")]).await?;

    // A node created without options has the default (presence) model.
    let node2 = "urn:example:blind:pre2";
    publish_ok(&mut alice, node2, "a", payload(node2, "1"), &[]).await?;
    publish_ok(&mut alice, node2, "b", payload(node2, "2"), &[("pubsub#access_model", "presence")]).await?;
    Ok(())
}

/// XEP-0060 §7.1.5 / §16.4.4 `pubsub#max_items` caps the stored items, oldest go first.
#[tokio::test]
async fn max_items_limits_stored_items() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut alice = s.online("alice", PW, "one").await?;
    let node = "urn:example:blind:max2";
    let opts = [("pubsub#persist_items", "true"), ("pubsub#max_items", "2")];
    for id in ["a", "b", "c"] {
        publish_ok(&mut alice, node, id, payload(node, id), &opts).await?;
    }
    let r = alice.iq_get(None, items_request(node, &[])).await?;
    ensure!(is_result(&r), "{r}");
    let mut ids = item_ids(&r);
    ids.sort();
    assert_eq!(ids, vec!["b".to_string(), "c".to_string()], "{r}");
    Ok(())
}

/// XEP-0060 §16.4.4 `max` as `pubsub#max_items` (used by bookmarks and OMEMO 2): as many as
/// the service allows, certainly more than one.
#[tokio::test]
async fn max_items_max_keeps_all() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut alice = s.online("alice", PW, "one").await?;
    let node = "urn:example:blind:maxmax";
    let opts = [("pubsub#persist_items", "true"), ("pubsub#max_items", "max")];
    for id in ["a", "b", "c", "d", "e"] {
        publish_ok(&mut alice, node, id, payload(node, id), &opts).await?;
    }
    let r = alice.iq_get(None, items_request(node, &[])).await?;
    ensure!(is_result(&r), "{r}");
    let mut ids = item_ids(&r);
    ids.sort();
    assert_eq!(ids, ["a", "b", "c", "d", "e"].map(String::from).to_vec(), "{r}");
    Ok(())
}

/// XEP-0060 §6.5.8: items by id; persisted items keep their payload; republishing the same id
/// overwrites (§7.1.2).
#[tokio::test]
async fn persist_items_and_fetch_by_id() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut alice = s.online("alice", PW, "one").await?;
    let node = "urn:example:blind:persist";
    let opts = [("pubsub#persist_items", "true"), ("pubsub#max_items", "10")];
    publish_ok(&mut alice, node, "a", payload(node, "A"), &opts).await?;
    publish_ok(&mut alice, node, "b", payload(node, "B"), &opts).await?;
    publish_ok(&mut alice, node, "a", payload(node, "A2"), &opts).await?;

    let r = alice.iq_get(None, items_request(node, &["b"])).await?;
    ensure!(is_result(&r), "{r}");
    let items = items_of(&r);
    ensure!(items.len() == 1 && items[0].attr("id") == Some("b"), "{r}");
    assert_eq!(items[0].child_text("data", node).as_deref(), Some("B"));

    let r = alice.iq_get(None, items_request(node, &[])).await?;
    let items = items_of(&r);
    ensure!(items.len() == 2, "same id overwrites: {r}");
    let a = items.iter().find(|i| i.attr("id") == Some("a")).context("no a")?;
    assert_eq!(a.child_text("data", node).as_deref(), Some("A2"));
    Ok(())
}

/// XEP-0060 §7.2: retract with `notify='true'` removes the item and tells interested contacts.
#[tokio::test]
async fn retract_with_notify() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    s.make_contacts("alice", "bob").await?;
    let mut bob = online_caps(&s, "bob", "b", &[TUNE_NOTIFY]).await?;
    let mut alice = s.online("alice", PW, "one").await?;
    publish_ok(&mut alice, TUNE, "t1", tune("Song"), &[]).await?;
    event(&mut bob, TUNE).await?;

    let retract = pubsub(
        Element::new("retract", ns::PUBSUB)
            .attr_set("node", TUNE)
            .attr_set("notify", "true")
            .child(Element::new("item", ns::PUBSUB).attr_set("id", "t1")),
    );
    let r = alice.iq_set(None, retract).await?;
    ensure!(is_result(&r), "retract failed: {r}");

    let ev = event(&mut bob, TUNE).await?;
    let retracted: Vec<_> = ev
        .get_child("event", ns::PUBSUB_EVENT)
        .and_then(|e| e.get_child("items", ns::PUBSUB_EVENT))
        .map(|i| i.children().filter(|c| c.is("retract", ns::PUBSUB_EVENT)).filter_map(|c| c.attr("id")).collect())
        .unwrap_or_default();
    assert_eq!(retracted, vec!["t1"], "{ev}");

    let r = alice.iq_get(None, items_request(TUNE, &[])).await?;
    ensure!(!item_ids(&r).contains(&"t1".to_string()), "retracted item still there: {r}");
    Ok(())
}

/// XEP-0060 §8.4: the owner deletes a node; subscribers are told; the node is gone.
#[tokio::test]
async fn node_delete() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    s.make_contacts("alice", "bob").await?;
    let mut bob = online_caps(&s, "bob", "b", &[TUNE_NOTIFY]).await?;
    let mut alice = s.online("alice", PW, "one").await?;
    publish_ok(&mut alice, TUNE, "t1", tune("Song"), &[]).await?;
    event(&mut bob, TUNE).await?;

    let del = Element::new("pubsub", ns::PUBSUB_OWNER).child(Element::new("delete", ns::PUBSUB_OWNER).attr_set("node", TUNE));
    let r = alice.iq_set(None, del).await?;
    ensure!(is_result(&r), "delete failed: {r}");

    let ev = event(&mut bob, TUNE).await?;
    ensure!(ev.get_child("event", ns::PUBSUB_EVENT).is_some_and(|e| e.has_child("delete", ns::PUBSUB_EVENT)), "{ev}");

    let r = alice.iq_get(None, items_request(TUNE, &[])).await?;
    ensure!(r.attr("type") == Some("error"), "deleted node still answers items: {r}");
    assert_eq!(condition(&r).as_deref(), Some("item-not-found"), "{r}");
    Ok(())
}

/// XEP-0402 §3: bookmarks are published with a whitelist access model; they reach the owner's
/// own interested resources but never contacts, and contacts can't fetch them.
#[tokio::test]
async fn bookmarks2_node_is_private() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    s.make_contacts("alice", "bob").await?;
    let notify = "urn:xmpp:bookmarks:1+notify";
    let mut bob = online_caps(&s, "bob", "b", &[notify]).await?;
    let mut alice2 = online_caps(&s, "alice", "two", &[notify]).await?;
    let mut alice = online_caps(&s, "alice", "one", &[notify]).await?;

    let conf = Element::new("conference", ns::BOOKMARKS2).attr_set("name", "Coven").attr_set("autojoin", "true").text_child(
        "nick",
        ns::BOOKMARKS2,
        "al",
    );
    let opts = [
        ("pubsub#persist_items", "true"),
        ("pubsub#max_items", "max"),
        ("pubsub#send_last_published_item", "never"),
        ("pubsub#access_model", "whitelist"),
    ];
    publish_ok(&mut alice, ns::BOOKMARKS2, "coven@rooms.quark.test", conf, &opts).await?;

    let ev = event(&mut alice2, ns::BOOKMARKS2).await?;
    assert_eq!(item_ids(&ev), vec!["coven@rooms.quark.test".to_string()], "{ev}");
    no_event(&mut bob, ns::BOOKMARKS2).await?;

    let r = bob.iq_get(Some(&jid("alice")), items_request(ns::BOOKMARKS2, &[])).await?;
    ensure!(r.attr("type") == Some("error") && items_of(&r).is_empty(), "contacts must not read bookmarks: {r}");

    // A contact's new resource doesn't get the last item either.
    let mut bob2 = online_caps(&s, "bob", "b2", &[notify]).await?;
    no_event(&mut bob2, ns::BOOKMARKS2).await?;

    let r = alice.iq_get(None, items_request(ns::BOOKMARKS2, &[])).await?;
    ensure!(is_result(&r) && item_ids(&r) == ["coven@rooms.quark.test"], "{r}");
    let c = &items_of(&r)[0];
    assert_eq!(c.get_child("conference", ns::BOOKMARKS2).and_then(|c| c.child_text("nick", ns::BOOKMARKS2)).as_deref(), Some("al"));
    Ok(())
}

/// XEP-0084 §4: avatar data then metadata; contacts interested in metadata get it (not the
/// data); the data item is fetched by id. XEP-0398 §3.1: when the account advertises
/// `urn:xmpp:pep-vcard-conversion:0`, PEP-to-vCard conversion is a MUST (for open avatars,
/// §7), so vCard-temp shows the same photo.
#[tokio::test]
async fn avatar_data_and_metadata() -> anyhow::Result<()> {
    use sha1::Digest as _;
    const DATA: &str = "urn:xmpp:avatar:data";
    const META: &str = "urn:xmpp:avatar:metadata";
    let s = server(&["alice", "bob"]).await?;
    s.make_contacts("alice", "bob").await?;
    let mut bob = online_caps(&s, "bob", "b", &["urn:xmpp:avatar:metadata+notify"]).await?;
    let mut alice = s.online("alice", PW, "one").await?;

    let bytes: Vec<u8> = b"\x89PNG\r\n\x1a\nnot really a png but fine".to_vec();
    let id: String = sha1::Sha1::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    // Open, as XEP-0398 §7 lets copy-on-publish servers convert only open avatars.
    let open = [("pubsub#access_model", "open")];
    publish_ok(&mut alice, DATA, &id, Element::new("data", DATA).text(b64.clone()), &open).await?;
    let info = Element::new("info", META)
        .attr_set("bytes", bytes.len().to_string())
        .attr_set("id", id.clone())
        .attr_set("type", "image/png")
        .attr_set("height", "64")
        .attr_set("width", "64");
    publish_ok(&mut alice, META, &id, Element::new("metadata", META).child(info), &open).await?;

    let ev = event(&mut bob, META).await?;
    let got = items_of(&ev);
    let info = got.first().and_then(|i| i.get_child("metadata", META)).and_then(|m| m.get_child("info", META)).context("no info")?;
    assert_eq!(info.attr("id"), Some(id.as_str()));
    no_event(&mut bob, DATA).await?;

    let r = bob.iq_get(Some(&jid("alice")), items_request(DATA, &[&id])).await?;
    ensure!(is_result(&r), "{r}");
    let data = items_of(&r).first().and_then(|i| i.child_text("data", DATA)).context("no data")?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(data.split_whitespace().collect::<String>())?;
    assert_eq!(decoded, bytes);

    let account = disco_info(&mut alice, Some(&jid("alice"))).await?;
    if disco_features(&account).iter().any(|f| f == "urn:xmpp:pep-vcard-conversion:0") {
        let v = bob.iq_get(Some(&jid("alice")), Element::new("vCard", ns::VCARD)).await?;
        ensure!(is_result(&v), "vCard of an avatar owner: {v}");
        let photo = v.get_child("vCard", ns::VCARD).and_then(|c| c.get_child("PHOTO", ns::VCARD)).context(format!("no PHOTO: {v}"))?;
        let binval = photo.child_text("BINVAL", ns::VCARD).context("no BINVAL")?;
        let decoded = base64::engine::general_purpose::STANDARD.decode(binval.split_whitespace().collect::<String>())?;
        assert_eq!(decoded, bytes, "XEP-0398: the vCard photo is the PEP avatar");
        assert_eq!(photo.child_text("TYPE", ns::VCARD).as_deref(), Some("image/png"));
    }
    Ok(())
}

/// XEP-0398 §4: setting a vCard-temp photo publishes the matching XEP-0084 metadata.
#[tokio::test]
async fn vcard_photo_converts_to_pep_avatar_when_advertised() -> anyhow::Result<()> {
    use sha1::Digest as _;
    let s = server(&["alice"]).await?;
    let mut alice = s.online("alice", PW, "one").await?;
    let account = disco_info(&mut alice, Some(&jid("alice"))).await?;
    if !disco_features(&account).iter().any(|f| f == "urn:xmpp:pep-vcard-conversion:0") {
        return Ok(());
    }
    let bytes = b"GIF89a tiny".to_vec();
    let id: String = sha1::Sha1::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
    let photo = Element::new("PHOTO", ns::VCARD).text_child("TYPE", ns::VCARD, "image/gif").text_child(
        "BINVAL",
        ns::VCARD,
        base64::engine::general_purpose::STANDARD.encode(&bytes),
    );
    let r = alice.iq_set(None, Element::new("vCard", ns::VCARD).child(photo)).await?;
    ensure!(is_result(&r), "{r}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let r = alice.iq_get(None, items_request("urn:xmpp:avatar:metadata", &[])).await?;
    ensure!(is_result(&r), "{r}");
    let info = items_of(&r)
        .first()
        .and_then(|i| i.get_child("metadata", "urn:xmpp:avatar:metadata"))
        .and_then(|m| m.get_child("info", "urn:xmpp:avatar:metadata"))
        .cloned()
        .context(format!("no avatar metadata: {r}"))?;
    assert_eq!(info.attr("id"), Some(id.as_str()), "{info}");
    assert_eq!(info.attr("bytes"), Some(bytes.len().to_string().as_str()), "{info}");
    Ok(())
}

/// XEP-0172 (nick over PEP): nicknames over PEP reach interested contacts.
#[tokio::test]
async fn nickname_published_over_pep() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    s.make_contacts("alice", "bob").await?;
    let mut bob = online_caps(&s, "bob", "b", &["http://jabber.org/protocol/nick+notify"]).await?;
    let mut alice = s.online("alice", PW, "one").await?;
    publish_ok(&mut alice, ns::NICK, "current", Element::new("nick", ns::NICK).text("Alice A."), &[]).await?;
    let ev = event(&mut bob, ns::NICK).await?;
    let nick = items_of(&ev).first().and_then(|i| i.child_text("nick", ns::NICK));
    assert_eq!(nick.as_deref(), Some("Alice A."), "{ev}");
    Ok(())
}

/// XEP-0060 §7.1.3.1: only the owner publishes to an account's PEP service.
#[tokio::test]
async fn others_cannot_publish_to_my_pep() -> anyhow::Result<()> {
    let s = server(&["alice", "bob"]).await?;
    s.make_contacts("alice", "bob").await?;
    let mut bob = s.online("bob", PW, "b").await?;
    let r = bob.iq_set(Some(&jid("alice")), publish(TUNE, Some("x"), tune("Not mine"), &[])).await?;
    assert_eq!(r.attr("type"), Some("error"), "{r}");
    assert_eq!(condition(&r).as_deref(), Some("forbidden"), "{r}");
    Ok(())
}

/// XEP-0060 §6.5.9: items of a node that doesn't exist: item-not-found.
#[tokio::test]
async fn items_of_missing_node() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut alice = s.online("alice", PW, "one").await?;
    let r = alice.iq_get(None, items_request("urn:example:blind:nothing-here", &[])).await?;
    assert_eq!(r.attr("type"), Some("error"), "{r}");
    assert_eq!(condition(&r).as_deref(), Some("item-not-found"), "{r}");
    Ok(())
}

/// XEP-0060 §6.5.7: `max_items` on an items request returns the most recent N.
#[tokio::test]
async fn items_request_max_items_returns_most_recent() -> anyhow::Result<()> {
    let s = server(&["alice"]).await?;
    let mut alice = s.online("alice", PW, "one").await?;
    let node = "urn:example:blind:recent";
    let opts = [("pubsub#persist_items", "true"), ("pubsub#max_items", "10")];
    for id in ["a", "b", "c"] {
        publish_ok(&mut alice, node, id, payload(node, id), &opts).await?;
    }
    let req = pubsub(Element::new("items", ns::PUBSUB).attr_set("node", node).attr_set("max_items", "1"));
    let r = alice.iq_get(None, req).await?;
    ensure!(is_result(&r), "{r}");
    assert_eq!(item_ids(&r), vec!["c".to_string()], "{r}");
    Ok(())
}
