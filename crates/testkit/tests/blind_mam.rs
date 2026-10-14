//! XEP-0313 Message Archive Management for accounts and rooms, black-box. Also XEP-0359 stanza-id
//! on delivery, XEP-0441 preferences and XEP-0334 hints.

mod blind_xep;

use std::time::Duration;

use blind_xep::*;
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{Client, TestServer};

async fn pair(s: &TestServer) -> anyhow::Result<(Client, Client)> {
    s.make_contacts("alice", "bob").await?;
    let a = s.online("alice", PW, "phone").await?;
    let b = s.online("bob", PW, "laptop").await?;
    Ok((a, b))
}

/// Alice sends bob `n` messages "m1".."mn"; returns the stanza-ids bob saw.
async fn send_n(a: &mut Client, b: &mut Client, n: usize) -> anyhow::Result<Vec<String>> {
    let mut ids = Vec::new();
    for i in 1..=n {
        let got = chat(a, b, &format!("m{i}")).await?;
        ids.push(stanza_id_by(&got, &bare("bob")).unwrap_or_default());
    }
    Ok(ids)
}

// --- §4 Discovery ---------------------------------------------------------------------------------

#[tokio::test]
async fn account_advertises_mam() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.login("alice", PW).await?;
    let info = disco_info(&mut a, &bare("alice")).await?;
    assert_eq!(info.attr("type"), Some("result"), "{info}");
    assert!(has_feature(&info, ns::MAM), "§6 account must advertise {}: {info}", ns::MAM);
    Ok(())
}

// --- Archiving + XEP-0359 -------------------------------------------------------------------------

#[tokio::test]
async fn chat_is_archived_both_directions_with_stanza_id() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, mut b) = pair(&s).await?;
    let got = chat(&mut a, &mut b, "hello bob").await?;
    let sid = stanza_id_by(&got, &bare("bob"))
        .unwrap_or_else(|| panic!("XEP-0313 §3.5 / XEP-0359: delivered message lacks <stanza-id by=bob@>: {got}"));
    assert!(!sid.is_empty());

    // Receiver's archive: same id as the stanza-id.
    let page = mam_all(&mut b, None).await?;
    assert!(page.ok(), "{}", page.iq);
    assert_eq!(page.bodies(), vec!["hello bob"], "{:?}", page.wrappers);
    assert_eq!(page.ids(), vec![sid.clone()], "archive id must equal the stanza-id the recipient got");
    let fwd = page.messages()[0];
    assert!(fwd.attr("from").is_some_and(|f| f.starts_with(&bare("alice"))), "{fwd}");

    // Sender's archive has the outgoing message.
    let page = mam_all(&mut a, None).await?;
    assert!(page.ok(), "{}", page.iq);
    assert_eq!(page.bodies(), vec!["hello bob"], "sender's archive: {:?}", page.wrappers);
    let fwd = page.messages()[0];
    assert!(fwd.attr("to").is_some_and(|t| t.starts_with(&bare("bob"))), "{fwd}");
    Ok(())
}

#[tokio::test]
async fn spoofed_stanza_id_is_removed() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, mut b) = pair(&s).await?;
    let m = quark_testkit::message(b.jid.as_deref().unwrap_or_default(), "chat", "spoof")
        .child(Element::new("stanza-id", ns::SID).attr_set("by", bare("bob")).attr_set("id", "forged-id"));
    a.send(&m).await?;
    let got = b.expect(|e| e.name() == "message" && e.child_text("body", ns::CLIENT).as_deref() == Some("spoof")).await?;
    let mine: Vec<_> = stanza_ids(&got).into_iter().filter(|(by, _)| by == &bare("bob")).collect();
    assert!(mine.iter().all(|(_, id)| id != "forged-id"), "XEP-0359 §5: stanza-id by=bob@ from alice kept: {got}");
    assert_eq!(mine.len(), 1, "exactly one stanza-id by bob@ (the server's): {got}");
    Ok(())
}

#[tokio::test]
async fn result_format_queryid_forwarded_delay_and_order() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, mut b) = pair(&s).await?;
    send_n(&mut a, &mut b, 3).await?;
    let page = mam_all(&mut b, None).await?;
    assert!(page.ok(), "{}", page.iq);
    assert!(page.late.is_empty(), "§4.2 results after the IQ result: {:?}", page.late);
    assert_eq!(page.bodies(), vec!["m1", "m2", "m3"], "chronological order");
    for w in &page.wrappers {
        let from = w.attr("from");
        assert!(from.is_none() || from == Some(bare("bob").as_str()), "result wrapper from someone else: {w}");
        assert_eq!(w.attr("to"), b.jid.as_deref(), "{w}");
        let r = w.get_child("result", ns::MAM).expect("result");
        assert!(r.attr("id").is_some_and(|i| !i.is_empty()), "{w}");
        let f = r.get_child("forwarded", ns::FORWARD).expect("forwarded");
        let d = f.get_child("delay", ns::DELAY).unwrap_or_else(|| panic!("§4.2 forwarded without delay: {w}"));
        assert!(d.attr("stamp").is_some_and(|s| s.contains('T')), "{w}");
    }
    let fin = page.fin().unwrap_or_else(|| panic!("no <fin/>: {}", page.iq));
    assert_eq!(fin.attr("complete"), Some("true"), "§4.3.2 whole archive returned: {}", page.iq);
    assert_eq!(page.rsm("first"), page.ids().first().cloned(), "{}", page.iq);
    assert_eq!(page.rsm("last"), page.ids().last().cloned(), "{}", page.iq);
    Ok(())
}

#[tokio::test]
async fn chat_states_and_no_store_are_not_archived() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, mut b) = pair(&s).await?;
    let to = b.jid.clone().unwrap_or_default();
    let cs = Element::new("message", ns::CLIENT)
        .attr_set("to", &to)
        .attr_set("type", "chat")
        .attr_set("id", "cs1")
        .child(Element::new("composing", ns::CHAT_STATES));
    a.send(&cs).await?;
    b.expect(|e| e.name() == "message" && e.has_child("composing", ns::CHAT_STATES)).await?;
    let ns_msg = quark_testkit::message(&to, "chat", "forget me").child(Element::new("no-store", ns::HINTS));
    a.send(&ns_msg).await?;
    let got = b.expect(|e| e.child_text("body", ns::CLIENT).as_deref() == Some("forget me")).await?;
    assert!(stanza_id_by(&got, &bare("bob")).is_none(), "no-store message got an archive stanza-id: {got}");
    chat(&mut a, &mut b, "keep me").await?;
    for (who, c) in [("bob", &mut b), ("alice", &mut a)] {
        let page = mam_all(c, None).await?;
        assert_eq!(page.bodies(), vec!["keep me"], "{who}: chat states / no-store archived: {:?}", page.wrappers);
    }
    Ok(())
}

#[tokio::test]
async fn error_messages_are_not_archived() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, mut b) = pair(&s).await?;
    let to = b.jid.clone().unwrap_or_default();
    let mut e = quark_testkit::message(&to, "error", "bounced");
    e.append(Element::new("error", ns::CLIENT).attr_set("type", "cancel").child(Element::new("item-not-found", ns::STANZAS)));
    a.send(&e).await?;
    b.expect(|e| e.child_text("body", ns::CLIENT).as_deref() == Some("bounced")).await?;
    chat(&mut a, &mut b, "real").await?;
    let page = mam_all(&mut b, None).await?;
    assert_eq!(page.bodies(), vec!["real"], "type=error archived: {:?}", page.wrappers);
    Ok(())
}

// --- §4.1.1 Filtering -------------------------------------------------------------------------------

#[tokio::test]
async fn filter_with() -> anyhow::Result<()> {
    let s = server().await?;
    s.make_contacts("carol", "bob").await?;
    let (mut a, mut b) = pair(&s).await?;
    let mut c = s.online("carol", PW, "pc").await?;
    chat(&mut a, &mut b, "from alice 1").await?;
    chat(&mut c, &mut b, "from carol").await?;
    chat(&mut b, &mut a, "to alice").await?;
    let page = mam_query(&mut b, None, &[("with", &[&bare("alice")])], None, false).await?;
    assert!(page.ok(), "{}", page.iq);
    assert_eq!(page.bodies(), vec!["from alice 1", "to alice"], "{:?}", page.wrappers);
    let page = mam_query(&mut b, None, &[("with", &[&bare("carol")])], None, false).await?;
    assert_eq!(page.bodies(), vec!["from carol"]);
    // A full JID matches only that resource.
    let full = c.jid.clone().unwrap_or_default();
    let page = mam_query(&mut b, None, &[("with", &[&full])], None, false).await?;
    assert_eq!(page.bodies(), vec!["from carol"], "with=full JID: {:?}", page.wrappers);
    let page = mam_query(&mut b, None, &[("with", &[&format!("{}/other", bare("carol"))])], None, false).await?;
    assert!(page.bodies().is_empty(), "with=other resource matched: {:?}", page.wrappers);
    Ok(())
}

#[tokio::test]
async fn filter_start_end() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, mut b) = pair(&s).await?;
    send_n(&mut a, &mut b, 2).await?;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    chat(&mut a, &mut b, "m3").await?;
    chat(&mut a, &mut b, "m4").await?;
    let all = mam_all(&mut b, None).await?;
    let stamps: Vec<String> = all
        .results()
        .iter()
        .map(|r| {
            r.get_child("forwarded", ns::FORWARD)
                .and_then(|f| f.get_child("delay", ns::DELAY))
                .and_then(|d| d.attr("stamp"))
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    assert_eq!(stamps.len(), 4);
    let page = mam_query(&mut b, None, &[("start", &[&stamps[2]])], None, false).await?;
    assert!(page.ok(), "{}", page.iq);
    assert_eq!(page.bodies(), vec!["m3", "m4"], "start={} {:?}", stamps[2], page.wrappers);
    let page = mam_query(&mut b, None, &[("end", &[&stamps[1]])], None, false).await?;
    assert_eq!(page.bodies(), vec!["m1", "m2"], "end={} {:?}", stamps[1], page.wrappers);
    let page = mam_query(&mut b, None, &[("start", &[&stamps[1]]), ("end", &[&stamps[2]])], None, false).await?;
    assert_eq!(page.bodies(), vec!["m2", "m3"], "start..end");
    Ok(())
}

#[tokio::test]
async fn bad_timestamp_is_bad_request() -> anyhow::Result<()> {
    let s = server().await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    let page = mam_query(&mut b, None, &[("start", &["yesterday"])], None, false).await?;
    assert_eq!(page.iq.attr("type"), Some("error"), "{}", page.iq);
    assert_eq!(cond(&page.iq), "bad-request", "{}", page.iq);
    Ok(())
}

#[tokio::test]
async fn filter_after_before_ids_extended() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, mut b) = pair(&s).await?;
    let info = disco_info(&mut b, &bare("bob")).await?;
    if !has_feature(&info, ns::MAM_EXTENDED) {
        eprintln!("no {}; skipping", ns::MAM_EXTENDED);
        return Ok(());
    }
    let ids = send_n(&mut a, &mut b, 5).await?;
    let page = mam_query(&mut b, None, &[("after-id", &[&ids[1]])], None, false).await?;
    assert!(page.ok(), "{}", page.iq);
    assert_eq!(page.bodies(), vec!["m3", "m4", "m5"], "after-id");
    let page = mam_query(&mut b, None, &[("before-id", &[&ids[3]])], None, false).await?;
    assert_eq!(page.bodies(), vec!["m1", "m2", "m3"], "before-id");
    let page = mam_query(&mut b, None, &[("after-id", &[&ids[0]]), ("before-id", &[&ids[4]])], None, false).await?;
    assert_eq!(page.bodies(), vec!["m2", "m3", "m4"], "after-id + before-id");
    let page = mam_query(&mut b, None, &[("ids", &[&ids[1], &ids[3]])], None, false).await?;
    assert_eq!(page.bodies(), vec!["m2", "m4"], "ids");
    // The form advertises them.
    let r = b.iq_get(None, Element::new("query", ns::MAM)).await?;
    let form =
        r.get_child("query", ns::MAM).and_then(|q| q.get_child("x", ns::DATA_FORMS)).unwrap_or_else(|| panic!("§4.1.3 no form: {r}"));
    for v in ["with", "start", "end", "before-id", "after-id", "ids"] {
        assert!(form.children().any(|f| f.attr("var") == Some(v)), "form lacks {v}: {form}");
    }
    Ok(())
}

#[tokio::test]
async fn form_fields_query() -> anyhow::Result<()> {
    let s = server().await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    let r = b.iq_get(None, Element::new("query", ns::MAM)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let form = r.get_child("query", ns::MAM).and_then(|q| q.get_child("x", ns::DATA_FORMS)).unwrap_or_else(|| panic!("no form: {r}"));
    assert_eq!(form_values(form, "FORM_TYPE"), Some(vec![ns::MAM.to_string()]), "{form}");
    for v in ["with", "start", "end"] {
        assert!(form.children().any(|f| f.attr("var") == Some(v)), "form lacks {v}: {form}");
    }
    assert!(!form.children().any(|f| f.has_child("required", ns::DATA_FORMS)), "§4.1.3 MUST NOT mark fields required: {form}");
    Ok(())
}

#[tokio::test]
async fn unknown_after_id_is_item_not_found() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, mut b) = pair(&s).await?;
    send_n(&mut a, &mut b, 1).await?;
    let page = mam_query(&mut b, None, &[], Some(rsm(Some(10), Some("no-such-id"), None)), false).await?;
    assert_eq!(page.iq.attr("type"), Some("error"), "{}", page.iq);
    assert_eq!(cond(&page.iq), "item-not-found", "§4.3.1 RSM after unknown: {}", page.iq);
    let info = disco_info(&mut b, &bare("bob")).await?;
    if has_feature(&info, ns::MAM_EXTENDED) {
        let page = mam_query(&mut b, None, &[("before-id", &["no-such-id"])], None, false).await?;
        assert_eq!(cond(&page.iq), "item-not-found", "before-id unknown: {}", page.iq);
    }
    Ok(())
}

// --- §5 Paging ------------------------------------------------------------------------------------

#[tokio::test]
async fn paging_forward() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, mut b) = pair(&s).await?;
    send_n(&mut a, &mut b, 5).await?;
    let p1 = mam_query(&mut b, None, &[], Some(rsm(Some(2), None, None)), false).await?;
    assert!(p1.ok(), "{}", p1.iq);
    assert_eq!(p1.bodies(), vec!["m1", "m2"]);
    assert!(!p1.complete(), "first page marked complete: {}", p1.iq);
    assert_eq!(p1.rsm("first"), p1.ids().first().cloned(), "{}", p1.iq);
    assert_eq!(p1.rsm("last"), p1.ids().last().cloned(), "{}", p1.iq);
    if let Some(c) = p1.count() {
        assert_eq!(c, 5, "{}", p1.iq);
    }
    let last = p1.rsm("last").expect("last");
    let p2 = mam_query(&mut b, None, &[], Some(rsm(Some(2), Some(&last), None)), false).await?;
    assert_eq!(p2.bodies(), vec!["m3", "m4"]);
    assert!(!p2.complete(), "{}", p2.iq);
    let last = p2.rsm("last").expect("last");
    let p3 = mam_query(&mut b, None, &[], Some(rsm(Some(2), Some(&last), None)), false).await?;
    assert_eq!(p3.bodies(), vec!["m5"]);
    assert!(p3.complete(), "§4.3.2 last page must have complete=true: {}", p3.iq);
    // Past the end: empty, complete.
    let last = p3.rsm("last").expect("last");
    let p4 = mam_query(&mut b, None, &[], Some(rsm(Some(2), Some(&last), None)), false).await?;
    assert!(p4.ok(), "{}", p4.iq);
    assert!(p4.bodies().is_empty());
    assert!(p4.complete(), "{}", p4.iq);
    Ok(())
}

#[tokio::test]
async fn paging_backward() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, mut b) = pair(&s).await?;
    send_n(&mut a, &mut b, 5).await?;
    let p1 = mam_query(&mut b, None, &[], Some(rsm(Some(2), None, Some(""))), false).await?;
    assert!(p1.ok(), "{}", p1.iq);
    assert_eq!(p1.bodies(), vec!["m4", "m5"], "§4.3.2 <before/> = last page, in chronological order");
    assert!(!p1.complete(), "{}", p1.iq);
    if let Some(c) = p1.count() {
        assert_eq!(c, 5, "{}", p1.iq);
    }
    assert_eq!(p1.rsm("first"), p1.ids().first().cloned(), "{}", p1.iq);
    let first = p1.rsm("first").expect("first");
    let p2 = mam_query(&mut b, None, &[], Some(rsm(Some(2), None, Some(&first))), false).await?;
    assert_eq!(p2.bodies(), vec!["m2", "m3"]);
    assert!(!p2.complete(), "{}", p2.iq);
    let first = p2.rsm("first").expect("first");
    let p3 = mam_query(&mut b, None, &[], Some(rsm(Some(2), None, Some(&first))), false).await?;
    assert_eq!(p3.bodies(), vec!["m1"]);
    assert!(p3.complete(), "backward paging reached the start: complete=true expected: {}", p3.iq);
    Ok(())
}

#[tokio::test]
async fn count_only_with_max_zero() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, mut b) = pair(&s).await?;
    send_n(&mut a, &mut b, 3).await?;
    let p = mam_query(&mut b, None, &[], Some(rsm(Some(0), None, None)), false).await?;
    assert!(p.ok(), "{}", p.iq);
    assert!(p.bodies().is_empty(), "max=0 returned items");
    assert_eq!(p.count(), Some(3), "XEP-0059 §2.6 count with max=0: {}", p.iq);
    Ok(())
}

#[tokio::test]
async fn flip_page_reverses_order() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, mut b) = pair(&s).await?;
    let info = disco_info(&mut b, &bare("bob")).await?;
    if !has_feature(&info, ns::MAM_EXTENDED) {
        eprintln!("no {}; skipping", ns::MAM_EXTENDED);
        return Ok(());
    }
    send_n(&mut a, &mut b, 4).await?;
    let p = mam_query(&mut b, None, &[], Some(rsm(Some(2), None, Some(""))), true).await?;
    assert!(p.ok(), "{}", p.iq);
    assert_eq!(p.bodies(), vec!["m4", "m3"], "flip-page on the last page");
    let p = mam_query(&mut b, None, &[], Some(rsm(Some(3), None, None)), true).await?;
    assert_eq!(p.bodies(), vec!["m3", "m2", "m1"], "flip-page forward");
    Ok(())
}

// --- XEP-0441 preferences ------------------------------------------------------------------------

#[tokio::test]
async fn prefs_get_and_never_stops_archiving() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, mut b) = pair(&s).await?;
    let r = b.iq_get(None, Element::new("prefs", ns::MAM)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let p = r.get_child("prefs", ns::MAM).unwrap_or_else(|| panic!("no prefs: {r}"));
    assert!(matches!(p.attr("default"), Some("always" | "never" | "roster")), "{r}");

    chat(&mut a, &mut b, "kept").await?;
    let set = Element::new("prefs", ns::MAM)
        .attr_set("default", "never")
        .child(Element::new("always", ns::MAM))
        .child(Element::new("never", ns::MAM));
    let r = b.iq_set(None, set).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let p = r.get_child("prefs", ns::MAM).unwrap_or_else(|| panic!("XEP-0441: set result must carry the prefs: {r}"));
    assert_eq!(p.attr("default"), Some("never"), "{r}");
    let r = b.iq_get(None, Element::new("prefs", ns::MAM)).await?;
    assert_eq!(r.get_child("prefs", ns::MAM).and_then(|p| p.attr("default")), Some("never"), "{r}");

    let got = chat(&mut a, &mut b, "dropped").await?;
    assert!(stanza_id_by(&got, &bare("bob")).is_none(), "not archived, but given an archive stanza-id: {got}");
    let page = mam_all(&mut b, None).await?;
    assert_eq!(page.bodies(), vec!["kept"], "default=never still archived: {:?}", page.wrappers);
    // Alice's archive is hers: still written.
    let page = mam_all(&mut a, None).await?;
    assert_eq!(page.bodies(), vec!["kept", "dropped"]);
    Ok(())
}

#[tokio::test]
async fn prefs_always_list_overrides_never_default() -> anyhow::Result<()> {
    let s = server().await?;
    s.make_contacts("carol", "bob").await?;
    let (mut a, mut b) = pair(&s).await?;
    let mut c = s.online("carol", PW, "pc").await?;
    let set = Element::new("prefs", ns::MAM)
        .attr_set("default", "never")
        .child(Element::new("always", ns::MAM).text_child("jid", ns::MAM, bare("carol")))
        .child(Element::new("never", ns::MAM));
    let r = b.iq_set(None, set).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    chat(&mut a, &mut b, "from alice").await?;
    chat(&mut c, &mut b, "from carol").await?;
    let page = mam_all(&mut b, None).await?;
    assert_eq!(page.bodies(), vec!["from carol"], "XEP-0441 <always/> jid: {:?}", page.wrappers);
    Ok(())
}

// --- metadata -------------------------------------------------------------------------------------

#[tokio::test]
async fn metadata_extended() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, mut b) = pair(&s).await?;
    let info = disco_info(&mut b, &bare("bob")).await?;
    if !has_feature(&info, ns::MAM_EXTENDED) {
        eprintln!("no {}; skipping", ns::MAM_EXTENDED);
        return Ok(());
    }
    let r = b.iq_get(None, Element::new("metadata", ns::MAM)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let m = r.get_child("metadata", ns::MAM).unwrap_or_else(|| panic!("no metadata: {r}"));
    assert_eq!(m.children().count(), 0, "empty archive: metadata must be empty: {r}");

    let ids = send_n(&mut a, &mut b, 3).await?;
    let r = b.iq_get(None, Element::new("metadata", ns::MAM)).await?;
    let m = r.get_child("metadata", ns::MAM).unwrap_or_else(|| panic!("no metadata: {r}"));
    let start = m.get_child("start", ns::MAM).unwrap_or_else(|| panic!("no start: {r}"));
    let end = m.get_child("end", ns::MAM).unwrap_or_else(|| panic!("no end: {r}"));
    assert_eq!(start.attr("id"), Some(ids[0].as_str()), "{r}");
    assert_eq!(end.attr("id"), Some(ids[2].as_str()), "{r}");
    assert!(start.attr("timestamp").is_some() && end.attr("timestamp").is_some(), "{r}");
    Ok(())
}

// --- Access ---------------------------------------------------------------------------------------

#[tokio::test]
async fn someone_elses_archive_is_refused() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, mut b) = pair(&s).await?;
    chat(&mut a, &mut b, "private").await?;
    let page = mam_all(&mut a, Some(&bare("bob"))).await?;
    assert_eq!(page.iq.attr("type"), Some("error"), "§8.1 alice read bob's archive: {}", page.iq);
    assert!(page.wrappers.is_empty() && page.late.is_empty(), "results leaked: {:?}", page.wrappers);
    assert_eq!(cond(&page.iq), "forbidden", "§8.1 SHOULD be forbidden: {}", page.iq);
    // Own bare JID as 'to' works.
    let page = mam_all(&mut b, Some(&bare("bob"))).await?;
    assert!(page.ok(), "{}", page.iq);
    assert_eq!(page.bodies(), vec!["private"]);
    Ok(())
}

#[tokio::test]
async fn history_off_hides_feature_and_refuses_queries() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, mut b) = pair(&s).await?;
    chat(&mut a, &mut b, "before").await?;
    s.set_settings(|st| st.history = quark::settings::History::Off).await?;
    let info = disco_info(&mut b, &bare("bob")).await?;
    assert!(!has_feature(&info, ns::MAM), "history off but MAM advertised: {info}");
    let page = mam_all(&mut b, None).await?;
    assert_eq!(page.iq.attr("type"), Some("error"), "history off but query answered: {}", page.iq);
    assert!(page.wrappers.is_empty(), "{:?}", page.wrappers);
    let got = chat(&mut a, &mut b, "during").await?;
    assert!(stanza_id_by(&got, &bare("bob")).is_none(), "history off but archive stanza-id added: {got}");
    Ok(())
}

// --- Room archives -------------------------------------------------------------------------------

async fn room_with_chat(s: &TestServer, name: &str, cfg: &[(&str, &[&str])]) -> anyhow::Result<(Client, String)> {
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room(name);
    if cfg.is_empty() {
        create_instant(&mut a, &r, "Alice").await?;
    } else {
        create_configured(&mut a, &r, "Alice", cfg).await?;
    }
    for i in 1..=3 {
        a.send(&groupchat(&r, &format!("g{i}"))).await?;
        a.expect(|e| is_groupchat_body(e, &format!("g{i}"))).await?;
    }
    Ok((a, r))
}

#[tokio::test]
async fn room_archive_returns_groupchat() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, r) = room_with_chat(&s, "archived", &[]).await?;
    let info = disco_info(&mut a, &r).await?;
    if !has_feature(&info, ns::MAM) {
        eprintln!("room doesn't advertise MAM; skipping");
        return Ok(());
    }
    let mut b = s.online("bob", PW, "laptop").await?;
    join(&mut b, &r, "Bob").await?;
    let reflected_sid = {
        a.send(&groupchat(&r, "g4")).await?;
        let got = b.expect(|e| is_groupchat_body(e, "g4")).await?;
        stanza_id_by(&got, &r)
    };
    let page = mam_all(&mut b, Some(&r)).await?;
    assert!(page.ok(), "{}", page.iq);
    assert!(page.late.is_empty(), "results after the IQ: {:?}", page.late);
    assert_eq!(page.bodies(), vec!["g1", "g2", "g3", "g4"], "{:?}", page.wrappers);
    for w in &page.wrappers {
        assert_eq!(w.attr("from"), Some(r.as_str()), "room results come from the room: {w}");
    }
    for m in page.messages() {
        assert_eq!(m.attr("type"), Some("groupchat"), "{m}");
        assert_eq!(m.attr("from"), Some(occ(&r, "Alice").as_str()), "§6.1.2 from MUST be the occupant JID: {m}");
        assert!(m.attr("to").is_none(), "§6.1.2 forwarded MUC message MUST NOT have 'to': {m}");
    }
    if let Some(sid) = reflected_sid {
        assert_eq!(page.ids().last(), Some(&sid), "room stanza-id differs from archive id");
    }
    // Paging works on rooms too.
    let p = mam_query(&mut b, Some(&r), &[], Some(rsm(Some(2), None, Some(""))), false).await?;
    assert_eq!(p.bodies(), vec!["g3", "g4"]);
    Ok(())
}

#[tokio::test]
async fn room_archive_refuses_non_members_of_members_only_room() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, r) = room_with_chat(&s, "closedarchive", &[("muc#roomconfig_membersonly", &["1"])]).await?;
    let info = disco_info(&mut a, &r).await?;
    if !has_feature(&info, ns::MAM) {
        eprintln!("room doesn't advertise MAM; skipping");
        return Ok(());
    }
    let mut b = s.online("bob", PW, "laptop").await?;
    let page = mam_all(&mut b, Some(&r)).await?;
    assert_eq!(page.iq.attr("type"), Some("error"), "§6.1.2 non-member read a members-only room archive: {}", page.iq);
    assert!(page.wrappers.is_empty() && page.late.is_empty(), "results leaked: {:?}", page.wrappers);
    // The owner can.
    let page = mam_all(&mut a, Some(&r)).await?;
    assert!(page.ok(), "{}", page.iq);
    assert_eq!(page.bodies(), vec!["g1", "g2", "g3"]);
    // Once a member, bob can.
    let res = a.iq_set(Some(&r), admin_item(&[("affiliation", "member"), ("jid", &bare("bob"))], None)).await?;
    assert_eq!(res.attr("type"), Some("result"));
    let page = mam_all(&mut b, Some(&r)).await?;
    assert!(page.ok(), "member refused: {}", page.iq);
    Ok(())
}

#[tokio::test]
async fn room_archive_refuses_outcasts() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, r) = room_with_chat(&s, "banarchive", &[]).await?;
    let info = disco_info(&mut a, &r).await?;
    if !has_feature(&info, ns::MAM) {
        return Ok(());
    }
    let res = a.iq_set(Some(&r), admin_item(&[("affiliation", "outcast"), ("jid", &bare("bob"))], None)).await?;
    assert_eq!(res.attr("type"), Some("result"));
    let mut b = s.online("bob", PW, "laptop").await?;
    let page = mam_all(&mut b, Some(&r)).await?;
    assert_eq!(page.iq.attr("type"), Some("error"), "§6.1.2 outcast read the room archive: {}", page.iq);
    assert!(page.wrappers.is_empty(), "{:?}", page.wrappers);
    Ok(())
}

#[tokio::test]
async fn room_archive_excludes_private_messages() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, r) = room_with_chat(&s, "pmarchive", &[]).await?;
    let info = disco_info(&mut a, &r).await?;
    if !has_feature(&info, ns::MAM) {
        return Ok(());
    }
    let mut b = s.online("bob", PW, "laptop").await?;
    join(&mut b, &r, "Bob").await?;
    b.send(&quark_testkit::message(&occ(&r, "Alice"), "chat", "secret pm")).await?;
    a.expect(|e| e.child_text("body", ns::CLIENT).as_deref() == Some("secret pm")).await?;
    let page = mam_all(&mut b, Some(&r)).await?;
    assert!(page.ok(), "{}", page.iq);
    assert!(!page.bodies().iter().any(|b| b == "secret pm"), "§6.1.2 MUC archive MUST NOT include private messages: {:?}", page.bodies());
    Ok(())
}

#[tokio::test]
async fn room_mam_feature_and_queries_agree() -> anyhow::Result<()> {
    // With history on or off, a room that advertises MAM answers queries, and one that doesn't refuses them.
    let s = server().await?;
    for (i, off) in [false, true].into_iter().enumerate() {
        if off {
            s.set_settings(|st| st.history = quark::settings::History::Off).await?;
        }
        let (mut a, r) = room_with_chat(&s, &format!("agree{i}"), &[]).await?;
        let info = disco_info(&mut a, &r).await?;
        let page = mam_all(&mut a, Some(&r)).await?;
        if has_feature(&info, ns::MAM) {
            assert!(page.ok(), "history off={off}: room advertises MAM but refuses: {}", page.iq);
        } else {
            assert_eq!(page.iq.attr("type"), Some("error"), "history off={off}: room without MAM answered: {}", page.iq);
        }
        if off {
            assert!(!has_feature(&info, ns::MAM), "history off but the room still advertises MAM: {info}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn unknown_form_field_is_feature_not_implemented() -> anyhow::Result<()> {
    let s = server().await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    let page = mam_query(&mut b, None, &[("urn:example:no-such-field", &["x"])], None, false).await?;
    assert_eq!(page.iq.attr("type"), Some("error"), "{}", page.iq);
    assert_eq!(cond(&page.iq), "feature-not-implemented", "§4.1.1: {}", page.iq);
    Ok(())
}

#[tokio::test]
async fn outgoing_message_carries_no_stanza_id_of_sender() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, mut b) = pair(&s).await?;
    let got = chat(&mut a, &mut b, "no leak").await?;
    assert!(stanza_id_by(&got, &bare("alice")).is_none(), "§3.5 sender's archive id leaked to the recipient: {got}");
    Ok(())
}

#[tokio::test]
async fn with_own_bare_jid_returns_only_self_messages() -> anyhow::Result<()> {
    let s = server().await?;
    let (mut a, mut b) = pair(&s).await?;
    let mut a2 = s.online("alice", PW, "laptop").await?;
    chat(&mut a, &mut b, "to bob").await?;
    chat(&mut a, &mut a2, "note to self").await?;
    let page = mam_query(&mut a, None, &[("with", &[&bare("alice")])], None, false).await?;
    assert!(page.ok(), "{}", page.iq);
    assert_eq!(page.bodies(), vec!["note to self"], "§4.1.1 with=own bare JID: {:?}", page.wrappers);
    Ok(())
}

#[tokio::test]
async fn offline_message_is_archived_with_matching_stanza_id() -> anyhow::Result<()> {
    let s = server().await?;
    s.make_contacts("alice", "bob").await?;
    let mut a = s.online("alice", PW, "phone").await?;
    a.send(&quark_testkit::message(&bare("bob"), "chat", "while you were out")).await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut b = s.login_as("bob", PW, "laptop").await?;
    b.send(&Element::new("presence", ns::CLIENT)).await?;
    let got = b.expect(|e| e.child_text("body", ns::CLIENT).as_deref() == Some("while you were out")).await?;
    let sid = stanza_id_by(&got, &bare("bob"));
    let page = mam_all(&mut b, None).await?;
    assert_eq!(page.bodies(), vec!["while you were out"], "offline message not archived once: {:?}", page.wrappers);
    if let Some(sid) = sid {
        assert_eq!(page.ids(), vec![sid], "offline copy's stanza-id differs from the archive id");
    } else {
        panic!("§3.5 offline-delivered message lacks the archive stanza-id: {got}");
    }
    Ok(())
}
