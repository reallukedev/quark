//! XEP-0045 Multi-User Chat, black-box, as Conversations / Gajim / Dino use it. Also XEP-0359
//! stanza-id, XEP-0421 occupant-id and XEP-0410 self-ping on rooms.

use crate::blind_xep;

use std::time::Duration;

use blind_xep::*;
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{presence, DOMAIN};

const SHORT: Duration = Duration::from_millis(300);

// --- §6 Service discovery ---------------------------------------------------------------------

#[tokio::test]
async fn server_items_list_the_muc_service() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.login("alice", PW).await?;
    let r = a.iq_get(Some(DOMAIN), Element::new("query", ns::DISCO_ITEMS)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let q = r.get_child("query", ns::DISCO_ITEMS).expect("query");
    assert!(q.children().any(|i| i.attr("jid") == Some(MUC)), "disco#items of the server doesn't list {MUC}: {r}");
    Ok(())
}

#[tokio::test]
async fn service_info_has_conference_identity_and_muc_feature() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.login("alice", PW).await?;
    let r = disco_info(&mut a, MUC).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let q = r.get_child("query", ns::DISCO_INFO).expect("query");
    assert!(
        q.children()
            .any(|i| i.is("identity", ns::DISCO_INFO) && i.attr("category") == Some("conference") && i.attr("type") == Some("text")),
        "no conference/text identity: {r}"
    );
    assert!(has_feature(&r, ns::MUC), "no {} feature: {r}", ns::MUC);
    Ok(())
}

// --- §10.1 Creating a room ---------------------------------------------------------------------

#[tokio::test]
async fn creating_a_room_gives_201_and_owner_and_instant_submit_works() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("coven");
    let j = join(&mut a, &r, "Alice").await?;
    let own = j.own.as_ref().expect("self-presence");
    assert!(has_code(own, "110"), "self-presence lacks 110: {own}");
    assert!(has_code(own, "201"), "new-room self-presence lacks 201: {own}");
    let item = muc_item(own).expect("item");
    assert_eq!(item.attr("affiliation"), Some("owner"), "{own}");
    assert_eq!(item.attr("role"), Some("moderator"), "{own}");
    let form = Element::new("x", ns::DATA_FORMS).attr_set("type", "submit");
    let res = a.iq_set(Some(&r), Element::new("query", ns::MUC_OWNER).child(form)).await?;
    assert_eq!(res.attr("type"), Some("result"), "instant room submit: {res}");
    // Now someone else can join.
    let mut b = s.online("bob", PW, "laptop").await?;
    let jb = join_with(&mut b, &r, "Bob", None, None).await?;
    assert!(jb.error.is_none(), "bob can't join the instant room: {:?}", jb.error);
    assert!(!has_code(jb.own.as_ref().expect("own"), "201"), "201 on joining an existing room");
    Ok(())
}

#[tokio::test]
async fn reserved_room_config_form_has_roomconfig_fields() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("reserved");
    let j = join(&mut a, &r, "Alice").await?;
    assert!(has_code(j.own.as_ref().expect("own"), "201"));
    let res = a.iq_get(Some(&r), Element::new("query", ns::MUC_OWNER)).await?;
    assert_eq!(res.attr("type"), Some("result"), "{res}");
    let q = res.get_child("query", ns::MUC_OWNER).expect("query");
    let form = q.get_child("x", ns::DATA_FORMS).expect("form");
    assert_eq!(form.attr("type"), Some("form"), "{form}");
    assert_eq!(form_values(form, "FORM_TYPE").and_then(|v| v.into_iter().next()).as_deref(), Some(MUC_ROOMCONFIG), "{form}");
    for var in ["muc#roomconfig_roomname", "muc#roomconfig_persistentroom", "muc#roomconfig_membersonly"] {
        assert!(form.children().any(|f| f.attr("var") == Some(var)), "config form lacks {var}: {form}");
    }
    // Submitting a name sticks.
    configure(&mut a, &r, &[("muc#roomconfig_roomname", &["Witches"])]).await?;
    let res = a.iq_get(Some(&r), Element::new("query", ns::MUC_OWNER)).await?;
    let form = res.get_child("query", ns::MUC_OWNER).and_then(|q| q.get_child("x", ns::DATA_FORMS)).expect("form");
    assert_eq!(form_values(form, "muc#roomconfig_roomname"), Some(vec!["Witches".to_string()]), "{form}");
    Ok(())
}

#[tokio::test]
async fn non_owner_cannot_get_config_form() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("cfg");
    create_instant(&mut a, &r, "Alice").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    join(&mut b, &r, "Bob").await?;
    let res = b.iq_get(Some(&r), Element::new("query", ns::MUC_OWNER)).await?;
    assert_eq!(res.attr("type"), Some("error"), "{res}");
    assert_eq!(cond(&res), "forbidden", "§10.1.3 non-owner config request: {res}");
    Ok(())
}

// --- §7.2 Entering a room ----------------------------------------------------------------------

#[tokio::test]
async fn join_order_occupants_then_self_then_subject() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("order");
    create_instant(&mut a, &r, "Alice").await?;
    let mut c = s.online("carol", PW, "pc").await?;
    join(&mut c, &r, "Carol").await?;
    drain(&mut a, SHORT).await?;

    let mut b = s.online("bob", PW, "laptop").await?;
    b.send(&join_presence(&r, "Bob", None, None)).await?;
    let mut seq = Vec::new();
    loop {
        let e = b.recv().await?;
        let done = is_subject(&e);
        seq.push(e);
        if done {
            break;
        }
    }
    let pos = |from: &str| seq.iter().position(|e| is_presence_from(e, from));
    let alice = pos(&occ(&r, "Alice")).expect("alice's presence");
    let carol = pos(&occ(&r, "Carol")).expect("carol's presence");
    let me = pos(&occ(&r, "Bob")).expect("self-presence");
    assert!(alice < me && carol < me, "self-presence must come after the occupants: {seq:?}");
    let own = &seq[me];
    assert!(has_code(own, "110"), "self-presence lacks 110: {own}");
    assert!(seq.iter().skip(me + 1).all(|e| e.name() != "presence"), "presence after the self-presence during join: {seq:?}");
    // The occupant presences carry muc#user items.
    for i in [alice, carol] {
        let it = muc_item(&seq[i]).unwrap_or_else(|| panic!("no muc#user item: {}", seq[i]));
        assert!(it.attr("role").is_some() && it.attr("affiliation").is_some(), "{}", seq[i]);
    }
    let subj = seq.last().expect("subject");
    assert!(is_subject(subj), "{subj}");
    // Alice sees bob arrive.
    a.expect(|e| is_presence_from(e, &occ(&r, "Bob"))).await?;
    Ok(())
}

#[tokio::test]
async fn subject_sent_even_when_empty() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("nosubject");
    create_instant(&mut a, &r, "Alice").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    b.send(&join_presence(&r, "Bob", None, None)).await?;
    b.expect(|e| is_presence_from(e, &occ(&r, "Bob"))).await?;
    let subj = b.expect(|e| e.name() == "message" && e.attr("from").is_some_and(|f| f.starts_with(&r))).await?;
    assert!(is_subject(&subj), "first message after joining must be the subject: {subj}");
    assert_eq!(subj.child_text("subject", ns::CLIENT).unwrap_or_default(), "", "{subj}");
    Ok(())
}

#[tokio::test]
async fn subject_change_is_broadcast_and_given_to_newcomers() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("subj");
    create_instant(&mut a, &r, "Alice").await?;
    let m =
        Element::new("message", ns::CLIENT).attr_set("to", &r).attr_set("type", "groupchat").text_child("subject", ns::CLIENT, "Spells");
    a.send(&m).await?;
    let echo = a.expect(is_subject).await?;
    assert_eq!(echo.child_text("subject", ns::CLIENT).as_deref(), Some("Spells"));
    assert_eq!(echo.attr("from"), Some(occ(&r, "Alice").as_str()), "{echo}");
    let mut b = s.online("bob", PW, "laptop").await?;
    let j = join(&mut b, &r, "Bob").await?;
    let subj = j.subject().expect("subject on join");
    assert_eq!(subj.child_text("subject", ns::CLIENT).as_deref(), Some("Spells"), "{subj}");
    Ok(())
}

#[tokio::test]
async fn nick_conflict_is_refused_with_409_conflict() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("conflict");
    create_instant(&mut a, &r, "Witch").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    let j = join_with(&mut b, &r, "Witch", None, None).await?;
    let e = j.error.expect("error presence");
    assert_eq!(e.attr("type"), Some("error"));
    assert_eq!(e.attr("from"), Some(occ(&r, "Witch").as_str()), "{e}");
    assert_eq!(error_of(&e), Some(("conflict".into(), "cancel".into())), "{e}");
    a.expect_silence(SHORT).await?;
    Ok(())
}

#[tokio::test]
async fn same_account_second_device_can_join_with_same_nick() -> anyhow::Result<()> {
    // §7.2.? multi-session nicks are a MAY; but a second device of the same bare JID must never get
    // a broken state: either a join or a conflict.
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("multi");
    create_instant(&mut a, &r, "Alice").await?;
    let mut a2 = s.online("alice", PW, "laptop").await?;
    let j = join_with(&mut a2, &r, "Alice", None, None).await?;
    match &j.error {
        Some(e) => assert_eq!(cond(e), "conflict", "{e}"),
        None => assert!(has_code(j.own.as_ref().expect("own"), "110")),
    }
    Ok(())
}

// --- §7.6 Changing nickname --------------------------------------------------------------------

#[tokio::test]
async fn nick_change_sends_303_then_new_presence() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("rename");
    create_instant(&mut a, &r, "Alice").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    join(&mut b, &r, "Bob").await?;
    drain(&mut a, SHORT).await?;

    b.send(&presence(Some(&occ(&r, "Robert")), None)).await?;
    // Bob: unavailable from old nick with 303 + 110 and nick, then available from new nick with 110.
    let old = b.expect(|e| is_presence_from(e, &occ(&r, "Bob"))).await?;
    assert_eq!(old.attr("type"), Some("unavailable"), "{old}");
    assert!(has_code(&old, "303"), "{old}");
    assert!(has_code(&old, "110"), "{old}");
    assert_eq!(muc_item(&old).and_then(|i| i.attr("nick")), Some("Robert"), "{old}");
    let new = b.expect(|e| is_presence_from(e, &occ(&r, "Robert"))).await?;
    assert_eq!(new.attr("type"), None, "{new}");
    assert!(has_code(&new, "110"), "{new}");
    // Alice: the same without 110.
    let old = a.expect(|e| is_presence_from(e, &occ(&r, "Bob"))).await?;
    assert_eq!(old.attr("type"), Some("unavailable"));
    assert!(has_code(&old, "303") && !has_code(&old, "110"), "{old}");
    assert_eq!(muc_item(&old).and_then(|i| i.attr("nick")), Some("Robert"), "{old}");
    let new = a.expect(|e| is_presence_from(e, &occ(&r, "Robert"))).await?;
    assert_eq!(new.attr("type"), None, "{new}");
    // Messages now come from the new nick.
    b.send(&groupchat(&r, "renamed")).await?;
    let m = a.expect(|e| is_groupchat_body(e, "renamed")).await?;
    assert_eq!(m.attr("from"), Some(occ(&r, "Robert").as_str()));
    Ok(())
}

#[tokio::test]
async fn nick_change_to_taken_nick_is_conflict() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("rename2");
    create_instant(&mut a, &r, "Alice").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    join(&mut b, &r, "Bob").await?;
    b.send(&presence(Some(&occ(&r, "Alice")), None)).await?;
    let e = b.expect(|e| e.name() == "presence" && e.attr("type") == Some("error")).await?;
    assert_eq!(cond(&e), "conflict", "{e}");
    Ok(())
}

// --- §7.14 Exiting a room ----------------------------------------------------------------------

#[tokio::test]
async fn leaving_gives_unavailable_with_110() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("leave");
    create_instant(&mut a, &r, "Alice").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    join(&mut b, &r, "Bob").await?;
    drain(&mut a, SHORT).await?;
    b.send(&presence(Some(&occ(&r, "Bob")), Some("unavailable"))).await?;
    let own = b.expect(|e| is_presence_from(e, &occ(&r, "Bob"))).await?;
    assert_eq!(own.attr("type"), Some("unavailable"), "{own}");
    assert!(has_code(&own, "110"), "{own}");
    let other = a.expect(|e| is_presence_from(e, &occ(&r, "Bob"))).await?;
    assert_eq!(other.attr("type"), Some("unavailable"), "{other}");
    assert!(!has_code(&other, "110"), "{other}");
    assert_eq!(muc_item(&other).and_then(|i| i.attr("role")), Some("none"), "{other}");
    // Bob no longer gets room traffic.
    a.send(&groupchat(&r, "after")).await?;
    a.expect(|e| is_groupchat_body(e, "after")).await?;
    b.expect_silence(SHORT).await?;
    Ok(())
}

#[tokio::test]
async fn going_offline_removes_the_occupant() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("offline");
    create_instant(&mut a, &r, "Alice").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    join(&mut b, &r, "Bob").await?;
    drain(&mut a, SHORT).await?;
    b.send(&presence(None, Some("unavailable"))).await?;
    let other = a.expect(|e| is_presence_from(e, &occ(&r, "Bob"))).await?;
    assert_eq!(other.attr("type"), Some("unavailable"), "{other}");
    Ok(())
}

// --- §7.4 Groupchat messages ------------------------------------------------------------------

#[tokio::test]
async fn groupchat_is_reflected_to_everyone_with_same_id() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("talk");
    create_instant(&mut a, &r, "Alice").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    join(&mut b, &r, "Bob").await?;
    drain(&mut a, SHORT).await?;
    let m = groupchat(&r, "hello all").attr_set("id", "gc-1");
    a.send(&m).await?;
    for (who, c) in [("alice", &mut a), ("bob", &mut b)] {
        let got = c.expect(|e| is_groupchat_body(e, "hello all")).await?;
        assert_eq!(got.attr("from"), Some(occ(&r, "Alice").as_str()), "{who}: {got}");
        assert_eq!(got.attr("id"), Some("gc-1"), "{who}: §7.4 SHOULD reflect the same id: {got}");
        assert_eq!(got.attr("to"), c.jid.as_deref(), "{who}: {got}");
    }
    Ok(())
}

#[tokio::test]
async fn groupchat_from_non_occupant_is_not_acceptable() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("outsider");
    create_instant(&mut a, &r, "Alice").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    b.send(&groupchat(&r, "let me in")).await?;
    let e = b.expect(|e| e.name() == "message" && e.attr("type") == Some("error")).await?;
    assert_eq!(cond(&e), "not-acceptable", "§7.4: {e}");
    a.expect_silence(SHORT).await?;
    Ok(())
}

// --- §7.5 Private messages --------------------------------------------------------------------

#[tokio::test]
async fn private_messages_between_occupants() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("pm");
    create_instant(&mut a, &r, "Alice").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    join(&mut b, &r, "Bob").await?;
    let mut c = s.online("carol", PW, "pc").await?;
    join(&mut c, &r, "Carol").await?;
    drain(&mut a, SHORT).await?;
    drain(&mut b, SHORT).await?;

    b.send(&quark_testkit::message(&occ(&r, "Alice"), "chat", "psst")).await?;
    let got = a.expect(|e| e.name() == "message" && e.child_text("body", ns::CLIENT).as_deref() == Some("psst")).await?;
    assert_eq!(got.attr("from"), Some(occ(&r, "Bob").as_str()), "{got}");
    assert_eq!(got.attr("type"), Some("chat"), "{got}");
    assert!(muc_x(&got).is_some(), "§7.5 SHOULD add <x xmlns=muc#user/>: {got}");
    c.expect_silence(SHORT).await?;
    // Reply works.
    a.send(&quark_testkit::message(&occ(&r, "Bob"), "chat", "yes?")).await?;
    let got = b.expect(|e| e.name() == "message" && e.child_text("body", ns::CLIENT).as_deref() == Some("yes?")).await?;
    assert_eq!(got.attr("from"), Some(occ(&r, "Alice").as_str()), "{got}");
    Ok(())
}

#[tokio::test]
async fn private_message_to_missing_nick_is_item_not_found() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("pm2");
    create_instant(&mut a, &r, "Alice").await?;
    a.send(&quark_testkit::message(&occ(&r, "Nobody"), "chat", "hello?")).await?;
    let e = a.expect(|e| e.name() == "message" && e.attr("type") == Some("error")).await?;
    assert_eq!(cond(&e), "item-not-found", "§7.5: {e}");
    Ok(())
}

// --- §7.2.6 / §9.3 Members-only ---------------------------------------------------------------

#[tokio::test]
async fn members_only_refuses_non_members_then_admits_members() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("club");
    create_configured(&mut a, &r, "Alice", &[("muc#roomconfig_membersonly", &["1"])]).await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    let j = join_with(&mut b, &r, "Bob", None, None).await?;
    let e = j.error.expect("refused");
    assert_eq!(error_of(&e), Some(("registration-required".into(), "auth".into())), "§7.2.6: {e}");

    let res = a.iq_set(Some(&r), admin_item(&[("affiliation", "member"), ("jid", &bare("bob"))], None)).await?;
    assert_eq!(res.attr("type"), Some("result"), "{res}");
    let j = join_with(&mut b, &r, "Bob", None, None).await?;
    assert!(j.error.is_none(), "member refused: {:?}", j.error);
    assert_eq!(muc_item(j.own.as_ref().expect("own")).and_then(|i| i.attr("affiliation")), Some("member"));
    Ok(())
}

#[tokio::test]
async fn affiliation_lists_can_be_queried_by_owner() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("lists");
    create_instant(&mut a, &r, "Alice").await?;
    for (who, aff) in [("bob", "member"), ("carol", "admin"), ("dave", "outcast")] {
        let res = a.iq_set(Some(&r), admin_item(&[("affiliation", aff), ("jid", &bare(who))], None)).await?;
        assert_eq!(res.attr("type"), Some("result"), "{aff}: {res}");
    }
    for (who, aff) in [("bob", "member"), ("carol", "admin"), ("dave", "outcast"), ("alice", "owner")] {
        let res = a.iq_get(Some(&r), admin_item(&[("affiliation", aff)], None)).await?;
        assert_eq!(res.attr("type"), Some("result"), "{aff} list: {res}");
        let q = res.get_child("query", ns::MUC_ADMIN).expect("query");
        let items: Vec<_> = q.children().filter(|i| i.is("item", ns::MUC_ADMIN)).collect();
        assert!(
            items.iter().any(|i| i.attr("jid") == Some(bare(who).as_str()) && i.attr("affiliation") == Some(aff)),
            "{aff} list lacks {who}: {res}"
        );
        assert!(items.iter().all(|i| i.attr("affiliation") == Some(aff)), "{aff} list has other affiliations: {res}");
    }
    Ok(())
}

#[tokio::test]
async fn non_admin_cannot_modify_affiliations() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("noaff");
    create_instant(&mut a, &r, "Alice").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    join(&mut b, &r, "Bob").await?;
    let res = b.iq_set(Some(&r), admin_item(&[("affiliation", "member"), ("jid", &bare("carol"))], None)).await?;
    assert_eq!(res.attr("type"), Some("error"), "{res}");
    assert_eq!(cond(&res), "forbidden", "§9: {res}");
    Ok(())
}

// --- §7.2.5 Password-protected rooms -----------------------------------------------------------

#[tokio::test]
async fn password_protected_room() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("secret");
    create_configured(
        &mut a,
        &r,
        "Alice",
        &[("muc#roomconfig_passwordprotectedroom", &["1"]), ("muc#roomconfig_roomsecret", &["cauldron"])],
    )
    .await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    let j = join_with(&mut b, &r, "Bob", None, None).await?;
    let e = j.error.expect("refused without password");
    assert_eq!(error_of(&e), Some(("not-authorized".into(), "auth".into())), "§7.2.5: {e}");
    let j = join_with(&mut b, &r, "Bob", Some("wrong"), None).await?;
    let e = j.error.expect("refused with wrong password");
    assert_eq!(cond(&e), "not-authorized", "{e}");
    let j = join_with(&mut b, &r, "Bob", Some("cauldron"), None).await?;
    assert!(j.error.is_none(), "right password refused: {:?}", j.error);
    Ok(())
}

// --- §9.1 Ban, §8.2 Kick -----------------------------------------------------------------------

#[tokio::test]
async fn ban_sends_301_and_keeps_the_user_out() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("ban");
    create_instant(&mut a, &r, "Alice").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    join(&mut b, &r, "Bob").await?;
    drain(&mut a, SHORT).await?;

    let res = a.iq_set(Some(&r), admin_item(&[("affiliation", "outcast"), ("jid", &bare("bob"))], Some("spam"))).await?;
    assert_eq!(res.attr("type"), Some("result"), "{res}");
    let gone = b.expect(|e| is_presence_from(e, &occ(&r, "Bob"))).await?;
    assert_eq!(gone.attr("type"), Some("unavailable"), "{gone}");
    assert!(has_code(&gone, "301"), "§9.1: {gone}");
    let it = muc_item(&gone).expect("item");
    assert_eq!(it.attr("affiliation"), Some("outcast"), "{gone}");
    assert_eq!(it.attr("role"), Some("none"), "{gone}");
    let seen = a.expect(|e| is_presence_from(e, &occ(&r, "Bob"))).await?;
    assert_eq!(seen.attr("type"), Some("unavailable"));
    assert!(has_code(&seen, "301"), "{seen}");

    let j = join_with(&mut b, &r, "Bob", None, None).await?;
    let e = j.error.expect("banned user rejoined");
    assert_eq!(error_of(&e), Some(("forbidden".into(), "auth".into())), "§7.2.7: {e}");
    Ok(())
}

#[tokio::test]
async fn kick_sends_307() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("kick");
    create_instant(&mut a, &r, "Alice").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    join(&mut b, &r, "Bob").await?;
    drain(&mut a, SHORT).await?;

    let res = a.iq_set(Some(&r), admin_item(&[("nick", "Bob"), ("role", "none")], Some("behave"))).await?;
    assert_eq!(res.attr("type"), Some("result"), "{res}");
    let gone = b.expect(|e| is_presence_from(e, &occ(&r, "Bob"))).await?;
    assert_eq!(gone.attr("type"), Some("unavailable"), "{gone}");
    assert!(has_code(&gone, "307"), "§8.2: {gone}");
    assert_eq!(muc_item(&gone).and_then(|i| i.attr("role")), Some("none"), "{gone}");
    let seen = a.expect(|e| is_presence_from(e, &occ(&r, "Bob"))).await?;
    assert!(has_code(&seen, "307"), "{seen}");
    // A kick is not a ban: bob may come back.
    let j = join_with(&mut b, &r, "Bob", None, None).await?;
    assert!(j.error.is_none(), "kicked user can't rejoin: {:?}", j.error);
    Ok(())
}

#[tokio::test]
async fn participants_cannot_kick_or_ban() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("mutiny");
    create_instant(&mut a, &r, "Alice").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    join(&mut b, &r, "Bob").await?;
    let mut c = s.online("carol", PW, "pc").await?;
    join(&mut c, &r, "Carol").await?;

    let res = b.iq_set(Some(&r), admin_item(&[("nick", "Carol"), ("role", "none")], None)).await?;
    assert_eq!(res.attr("type"), Some("error"), "{res}");
    assert!(matches!(cond(&res).as_str(), "forbidden" | "not-allowed"), "§8: {res}");
    let res = b.iq_set(Some(&r), admin_item(&[("affiliation", "outcast"), ("jid", &bare("carol"))], None)).await?;
    assert_eq!(res.attr("type"), Some("error"), "{res}");
    assert_eq!(cond(&res), "forbidden", "§9: {res}");
    // Carol is still there.
    a.send(&groupchat(&r, "still here?")).await?;
    c.expect(|e| is_groupchat_body(e, "still here?")).await?;
    Ok(())
}

#[tokio::test]
async fn moderator_cannot_kick_owner() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("coup");
    create_instant(&mut a, &r, "Alice").await?;
    let res = a.iq_set(Some(&r), admin_item(&[("affiliation", "admin"), ("jid", &bare("bob"))], None)).await?;
    assert_eq!(res.attr("type"), Some("result"), "{res}");
    let mut b = s.online("bob", PW, "laptop").await?;
    let j = join(&mut b, &r, "Bob").await?;
    assert_eq!(muc_item(j.own.as_ref().expect("own")).and_then(|i| i.attr("role")), Some("moderator"));
    let res = b.iq_set(Some(&r), admin_item(&[("nick", "Alice"), ("role", "none")], None)).await?;
    assert_eq!(res.attr("type"), Some("error"), "{res}");
    assert_eq!(cond(&res), "not-allowed", "§8.2: {res}");
    Ok(())
}

// --- §8.3-8.4 Voice ------------------------------------------------------------------------------

#[tokio::test]
async fn moderated_room_visitors_need_voice() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("stage");
    create_configured(&mut a, &r, "Alice", &[("muc#roomconfig_moderatedroom", &["1"])]).await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    let j = join(&mut b, &r, "Bob").await?;
    assert_eq!(muc_item(j.own.as_ref().expect("own")).and_then(|i| i.attr("role")), Some("visitor"), "§7.1 default role in moderated room");
    drain(&mut a, SHORT).await?;

    b.send(&groupchat(&r, "can I speak")).await?;
    let e = b.expect(|e| e.name() == "message" && (e.attr("type") == Some("error") || is_groupchat_body(e, "can I speak"))).await?;
    assert_eq!(e.attr("type"), Some("error"), "visitor's message was reflected: {e}");
    assert_eq!(cond(&e), "forbidden", "§7.4: {e}");
    a.expect_silence(SHORT).await?;

    let res = a.iq_set(Some(&r), admin_item(&[("nick", "Bob"), ("role", "participant")], None)).await?;
    assert_eq!(res.attr("type"), Some("result"), "{res}");
    let p = b.expect(|e| is_presence_from(e, &occ(&r, "Bob"))).await?;
    assert_eq!(muc_item(&p).and_then(|i| i.attr("role")), Some("participant"), "{p}");
    b.send(&groupchat(&r, "thanks")).await?;
    a.expect(|e| is_groupchat_body(e, "thanks")).await?;

    // Revoke.
    let res = a.iq_set(Some(&r), admin_item(&[("nick", "Bob"), ("role", "visitor")], None)).await?;
    assert_eq!(res.attr("type"), Some("result"), "{res}");
    let p = b.expect(|e| is_presence_from(e, &occ(&r, "Bob"))).await?;
    assert_eq!(muc_item(&p).and_then(|i| i.attr("role")), Some("visitor"), "{p}");
    Ok(())
}

// --- §7.8.1 Mediated invitations ---------------------------------------------------------------

#[tokio::test]
async fn mediated_invitation_reaches_invitee() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("party");
    create_instant(&mut a, &r, "Alice").await?;
    let mut c = s.online("carol", PW, "pc").await?;
    let inv = Element::new("message", ns::CLIENT).attr_set("to", &r).child(
        Element::new("x", ns::MUC_USER).child(Element::new("invite", ns::MUC_USER).attr_set("to", bare("carol")).text_child(
            "reason",
            ns::MUC_USER,
            "come along",
        )),
    );
    a.send(&inv).await?;
    let got = c.expect(|e| e.name() == "message" && muc_x(e).is_some_and(|x| x.has_child("invite", ns::MUC_USER))).await?;
    assert_eq!(got.attr("from"), Some(r.as_str()), "§7.8.1 invitation comes from the room: {got}");
    let invite = muc_x(&got).and_then(|x| x.get_child("invite", ns::MUC_USER)).expect("invite");
    assert!(invite.attr("from").is_some_and(|f| f.starts_with(&bare("alice"))), "invite/@from must be the inviter: {got}");
    assert_eq!(invite.child_text("reason", ns::MUC_USER).as_deref(), Some("come along"), "{got}");
    Ok(())
}

#[tokio::test]
async fn members_only_invite_by_non_admin_is_forbidden() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("vip");
    create_configured(&mut a, &r, "Alice", &[("muc#roomconfig_membersonly", &["1"]), ("muc#roomconfig_allowinvites", &["0"])]).await?;
    let res = a.iq_set(Some(&r), admin_item(&[("affiliation", "member"), ("jid", &bare("bob"))], None)).await?;
    assert_eq!(res.attr("type"), Some("result"));
    let mut b = s.online("bob", PW, "laptop").await?;
    join(&mut b, &r, "Bob").await?;
    let mut c = s.online("carol", PW, "pc").await?;
    let inv = Element::new("message", ns::CLIENT)
        .attr_set("to", &r)
        .child(Element::new("x", ns::MUC_USER).child(Element::new("invite", ns::MUC_USER).attr_set("to", bare("carol"))));
    b.send(&inv).await?;
    let e = b.expect(|e| e.name() == "message" && e.attr("type") == Some("error")).await?;
    assert_eq!(cond(&e), "forbidden", "§9.5: {e}");
    c.expect_silence(SHORT).await?;
    Ok(())
}

// --- §10.9 Destroying a room -------------------------------------------------------------------

#[tokio::test]
async fn destroy_with_reason_notifies_occupants() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("doomed");
    create_instant(&mut a, &r, "Alice").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    join(&mut b, &r, "Bob").await?;
    drain(&mut a, SHORT).await?;

    let d = Element::new("query", ns::MUC_OWNER)
        .child(Element::new("destroy", ns::MUC_OWNER).attr_set("jid", room("newplace")).text_child("reason", ns::MUC_OWNER, "moving"));
    let res = a.iq_set(Some(&r), d).await?;
    assert_eq!(res.attr("type"), Some("result"), "{res}");
    let p = b.expect(|e| is_presence_from(e, &occ(&r, "Bob"))).await?;
    assert_eq!(p.attr("type"), Some("unavailable"), "{p}");
    let it = muc_item(&p).expect("item");
    assert_eq!((it.attr("affiliation"), it.attr("role")), (Some("none"), Some("none")), "{p}");
    let destroy = muc_x(&p).and_then(|x| x.get_child("destroy", ns::MUC_USER)).unwrap_or_else(|| panic!("§10.9 no destroy: {p}"));
    assert_eq!(destroy.child_text("reason", ns::MUC_USER).as_deref(), Some("moving"), "{p}");
    assert_eq!(destroy.attr("jid"), Some(room("newplace").as_str()), "{p}");
    // The room is gone.
    let info = disco_info(&mut a, &r).await?;
    assert_eq!(info.attr("type"), Some("error"), "destroyed room still answers disco: {info}");
    assert_eq!(cond(&info), "item-not-found", "{info}");
    Ok(())
}

#[tokio::test]
async fn non_owner_cannot_destroy() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("sturdy");
    create_instant(&mut a, &r, "Alice").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    join(&mut b, &r, "Bob").await?;
    let res = b.iq_set(Some(&r), Element::new("query", ns::MUC_OWNER).child(Element::new("destroy", ns::MUC_OWNER))).await?;
    assert_eq!(res.attr("type"), Some("error"), "{res}");
    assert_eq!(cond(&res), "forbidden", "§10.9: {res}");
    Ok(())
}

// --- §6.4 Room disco#info ------------------------------------------------------------------------

#[tokio::test]
async fn room_info_has_identity_features_and_roominfo_form() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("info");
    create_configured(&mut a, &r, "Alice", &[("muc#roomconfig_roomname", &["The Info Room"])]).await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    join(&mut b, &r, "Bob").await?;

    let info = disco_info(&mut b, &r).await?;
    assert_eq!(info.attr("type"), Some("result"), "{info}");
    let q = info.get_child("query", ns::DISCO_INFO).expect("query");
    let id = q.children().find(|i| i.is("identity", ns::DISCO_INFO)).unwrap_or_else(|| panic!("no identity: {info}"));
    assert_eq!((id.attr("category"), id.attr("type")), (Some("conference"), Some("text")), "{info}");
    assert_eq!(id.attr("name"), Some("The Info Room"), "identity name should be the room name: {info}");
    assert!(has_feature(&info, ns::MUC), "{info}");
    // One of each pair of room-type features (§6.4 / registrar).
    let f = features(&info);
    for pair in [
        ("muc_public", "muc_hidden"),
        ("muc_open", "muc_membersonly"),
        ("muc_unmoderated", "muc_moderated"),
        ("muc_temporary", "muc_persistent"),
    ] {
        assert!(f.iter().any(|x| x == pair.0 || x == pair.1), "neither {} nor {} in {info}", pair.0, pair.1);
    }
    let form = form_of_type(q, MUC_ROOMINFO).unwrap_or_else(|| panic!("no muc#roominfo form (XEP-0128): {info}"));
    if let Some(v) = form_values(form, "muc#roominfo_occupants") {
        assert_eq!(v, vec!["2".to_string()], "occupant count: {form}");
    }
    Ok(())
}

#[tokio::test]
async fn room_info_for_missing_room_is_item_not_found() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let info = disco_info(&mut a, &room("nowhere")).await?;
    assert_eq!(info.attr("type"), Some("error"), "{info}");
    assert_eq!(cond(&info), "item-not-found", "{info}");
    Ok(())
}

// --- §7.2.13 / §7.2.15 History -----------------------------------------------------------------

#[tokio::test]
async fn history_on_join_respects_maxstanzas() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("history");
    create_instant(&mut a, &r, "Alice").await?;
    for i in 1..=4 {
        a.send(&groupchat(&r, &format!("line {i}"))).await?;
        a.expect(|e| is_groupchat_body(e, &format!("line {i}"))).await?;
    }
    let mut b = s.online("bob", PW, "laptop").await?;
    let j = join_with(&mut b, &r, "Bob", None, Some(2)).await?;
    let h: Vec<_> = j.history().iter().map(|m| m.child_text("body", ns::CLIENT).unwrap_or_default()).collect();
    assert_eq!(h, vec!["line 3", "line 4"], "maxstanzas=2: {:?}", j.all);
    for m in j.history() {
        assert_eq!(m.attr("from"), Some(occ(&r, "Alice").as_str()), "{m}");
        let d = m.get_child("delay", ns::DELAY).unwrap_or_else(|| panic!("history without delay: {m}"));
        assert!(d.attr("stamp").is_some(), "{m}");
        assert_eq!(d.attr("from"), Some(r.as_str()), "§7.2.15 delay/@from SHOULD be the room: {m}");
    }
    // History comes after the self-presence and before the subject.
    let own = j.all.iter().position(|e| has_code(e, "110")).expect("own");
    let first = j.all.iter().position(|e| is_groupchat_body(e, "line 3")).expect("hist");
    let subj = j.all.iter().position(is_subject).expect("subject");
    assert!(own < first && first < subj, "{:?}", j.all);

    let mut c = s.online("carol", PW, "pc").await?;
    let j = join_with(&mut c, &r, "Carol", None, Some(0)).await?;
    assert!(j.history().is_empty(), "maxstanzas=0 still sent history: {:?}", j.all);
    Ok(())
}

// --- Persistence ----------------------------------------------------------------------------------

#[tokio::test]
async fn persistent_room_survives_restart() -> anyhow::Result<()> {
    let mut s = server().await?;
    let r = room("castle");
    {
        let mut a = s.online("alice", PW, "phone").await?;
        create_configured(&mut a, &r, "Alice", &[("muc#roomconfig_persistentroom", &["1"]), ("muc#roomconfig_roomname", &["Castle"])])
            .await?;
        let res = a.iq_set(Some(&r), admin_item(&[("affiliation", "member"), ("jid", &bare("bob"))], None)).await?;
        assert_eq!(res.attr("type"), Some("result"));
        a.send(&groupchat(&r, "before restart")).await?;
        a.expect(|e| is_groupchat_body(e, "before restart")).await?;
    }
    s.restart().await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    let info = disco_info(&mut b, &r).await?;
    assert_eq!(info.attr("type"), Some("result"), "room lost on restart: {info}");
    let q = info.get_child("query", ns::DISCO_INFO).expect("query");
    assert!(q.children().any(|i| i.attr("name") == Some("Castle")), "room name lost: {info}");
    assert!(has_feature(&info, "muc_persistent"), "{info}");
    let j = join(&mut b, &r, "Bob").await?;
    let own = j.own.as_ref().expect("own");
    assert!(!has_code(own, "201"), "room recreated after restart: {own}");
    assert_eq!(muc_item(own).and_then(|i| i.attr("affiliation")), Some("member"), "affiliation lost: {own}");
    Ok(())
}

#[tokio::test]
async fn temporary_room_disappears_when_empty() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("ephemeral");
    create_configured(&mut a, &r, "Alice", &[("muc#roomconfig_persistentroom", &["0"])]).await?;
    a.send(&presence(Some(&occ(&r, "Alice")), Some("unavailable"))).await?;
    a.expect(|e| is_unavailable_from(e, &occ(&r, "Alice"))).await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let info = disco_info(&mut a, &r).await?;
    assert_eq!(cond(&info), "item-not-found", "§10.1 temporary room should be destroyed when the last occupant leaves: {info}");
    Ok(())
}

// --- XEP-0359 on rooms -------------------------------------------------------------------------

#[tokio::test]
async fn groupchat_carries_stanza_id_by_room() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("sid");
    create_instant(&mut a, &r, "Alice").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    join(&mut b, &r, "Bob").await?;
    let info = disco_info(&mut b, &r).await?;
    if !has_feature(&info, ns::SID) && !has_feature(&info, ns::MAM) {
        eprintln!("room advertises neither {} nor {}; skipping", ns::SID, ns::MAM);
        return Ok(());
    }
    drain(&mut a, SHORT).await?;
    // A spoofed stanza-id by the room must not survive.
    let m = groupchat(&r, "with id").child(Element::new("stanza-id", ns::SID).attr_set("by", &r).attr_set("id", "spoofed"));
    a.send(&m).await?;
    let ga = a.expect(|e| is_groupchat_body(e, "with id")).await?;
    let gb = b.expect(|e| is_groupchat_body(e, "with id")).await?;
    let ia = stanza_id_by(&ga, &r).unwrap_or_else(|| panic!("XEP-0359 §6 no stanza-id by room on the reflection: {ga}"));
    let ib = stanza_id_by(&gb, &r).unwrap_or_else(|| panic!("no stanza-id by room: {gb}"));
    assert_eq!(ia, ib, "same message, different stanza-ids");
    assert_ne!(ib, "spoofed", "spoofed stanza-id kept: {gb}");
    assert_eq!(stanza_ids(&gb).iter().filter(|(by, _)| by == &r).count(), 1, "{gb}");
    Ok(())
}

// --- XEP-0421 occupant-id -------------------------------------------------------------------------

#[tokio::test]
async fn occupant_id_is_stable_per_occupant() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("occid");
    create_instant(&mut a, &r, "Alice").await?;
    let info = disco_info(&mut a, &r).await?;
    if !has_feature(&info, ns::OCCUPANT_ID) {
        eprintln!("room doesn't advertise {}; skipping", ns::OCCUPANT_ID);
        return Ok(());
    }
    let mut b = s.online("bob", PW, "laptop").await?;
    let j = join(&mut b, &r, "Bob").await?;
    let oid = |e: &Element| e.get_child("occupant-id", ns::OCCUPANT_ID).and_then(|o| o.attr("id")).map(str::to_string);
    let alice_p = j.presences().into_iter().find(|p| p.attr("from") == Some(occ(&r, "Alice").as_str())).expect("alice presence").clone();
    let bob_p = j.own.clone().expect("own");
    let alice_id = oid(&alice_p).unwrap_or_else(|| panic!("XEP-0421: presence without occupant-id: {alice_p}"));
    let bob_id = oid(&bob_p).unwrap_or_else(|| panic!("self-presence without occupant-id: {bob_p}"));
    assert_ne!(alice_id, bob_id);
    // A spoofed occupant-id is replaced.
    let m = groupchat(&r, "who am i").child(Element::new("occupant-id", ns::OCCUPANT_ID).attr_set("id", "fake"));
    a.send(&m).await?;
    let got = b.expect(|e| is_groupchat_body(e, "who am i")).await?;
    assert_eq!(oid(&got), Some(alice_id.clone()), "message occupant-id differs from presence: {got}");
    assert_eq!(got.children().filter(|c| c.is("occupant-id", ns::OCCUPANT_ID)).count(), 1, "{got}");
    // Same after rejoin with another nick (stable per bare JID).
    a.send(&presence(Some(&occ(&r, "Alice")), Some("unavailable"))).await?;
    a.expect(|e| is_unavailable_from(e, &occ(&r, "Alice"))).await?;
    let j = join(&mut a, &r, "Alicia").await?;
    assert_eq!(j.own.as_ref().and_then(oid), Some(alice_id), "occupant-id changed on rejoin");
    Ok(())
}

// --- XEP-0410 self-ping ----------------------------------------------------------------------------

async fn self_ping(c: &mut quark_testkit::Client, to: &str) -> anyhow::Result<Element> {
    let id = quark_testkit::quark_core::new_id();
    let iq = quark_testkit::quark_core::stanza::iq("get", &id, None, Some(to), Element::new("ping", ns::PING));
    c.send(&iq).await?;
    loop {
        let e = c.recv().await?;
        if e.name() == "iq" && e.attr("id") == Some(id.as_str()) {
            return Ok(e);
        }
        if e.name() == "iq" && matches!(e.attr("type"), Some("get" | "set")) {
            // The service may forward the ping to us (no optimization): answer it.
            c.answer(&e).await?;
        }
    }
}

#[tokio::test]
async fn self_ping_while_joined_and_not_joined() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("ping");
    create_instant(&mut a, &r, "Alice").await?;
    let res = self_ping(&mut a, &occ(&r, "Alice")).await?;
    assert_eq!(res.attr("type"), Some("result"), "XEP-0410 joined: {res}");
    let mut b = s.online("bob", PW, "laptop").await?;
    let res = self_ping(&mut b, &occ(&r, "Bob")).await?;
    assert_eq!(res.attr("type"), Some("error"), "XEP-0410 not joined: {res}");
    assert_eq!(cond(&res), "not-acceptable", "XEP-0410 not joined: {res}");
    // Pinging someone else's nick while not joined is also not-acceptable.
    let res = self_ping(&mut b, &occ(&r, "Alice")).await?;
    assert_eq!(res.attr("type"), Some("error"), "{res}");
    Ok(())
}

// --- groups setting ---------------------------------------------------------------------------

#[tokio::test]
async fn groups_off_removes_the_service() -> anyhow::Result<()> {
    let s = server().await?;
    s.set_settings(|st| st.groups.on = false).await?;
    let mut a = s.login("alice", PW).await?;
    let r = a.iq_get(Some(DOMAIN), Element::new("query", ns::DISCO_ITEMS)).await?;
    let q = r.get_child("query", ns::DISCO_ITEMS).expect("query");
    assert!(!q.children().any(|i| i.attr("jid") == Some(MUC)), "groups off but service still listed: {r}");
    let info = disco_info(&mut a, MUC).await?;
    assert_eq!(info.attr("type"), Some("error"), "groups off but service answers: {info}");
    Ok(())
}

// --- More business rules --------------------------------------------------------------------------

#[tokio::test]
async fn semi_anonymous_hides_jids_from_participants_non_anonymous_shows_them() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("masks");
    create_configured(&mut a, &r, "Alice", &[("muc#roomconfig_whois", &["moderators"])]).await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    let j = join(&mut b, &r, "Bob").await?;
    let ap = j.presences().into_iter().find(|p| p.attr("from") == Some(occ(&r, "Alice").as_str())).expect("alice").clone();
    assert!(muc_item(&ap).and_then(|i| i.attr("jid")).is_none(), "§7.2.3 semi-anonymous room shows a JID to a participant: {ap}");
    // The moderator does see bob's JID.
    let bp = a.expect(|e| is_presence_from(e, &occ(&r, "Bob"))).await?;
    assert!(muc_item(&bp).and_then(|i| i.attr("jid")).is_some_and(|j| j.starts_with(&bare("bob"))), "§7.2.3 moderator must see JIDs: {bp}");

    let r2 = room("faces");
    create_configured(&mut a, &r2, "Alice", &[("muc#roomconfig_whois", &["anyone"])]).await?;
    let j = join(&mut b, &r2, "Bob").await?;
    let own = j.own.as_ref().expect("own");
    assert!(has_code(own, "100"), "§7.2.4 non-anonymous room: self-presence must have status 100: {own}");
    let ap = j.presences().into_iter().find(|p| p.attr("from") == Some(occ(&r2, "Alice").as_str())).expect("alice").clone();
    assert!(muc_item(&ap).and_then(|i| i.attr("jid")).is_some_and(|j| j.starts_with(&bare("alice"))), "§7.2.4: {ap}");
    Ok(())
}

#[tokio::test]
async fn presence_updates_are_broadcast() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("moods");
    create_instant(&mut a, &r, "Alice").await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    join(&mut b, &r, "Bob").await?;
    drain(&mut a, SHORT).await?;
    let p = presence(Some(&occ(&r, "Bob")), None).text_child("show", ns::CLIENT, "away");
    b.send(&p).await?;
    let got = a.expect(|e| is_presence_from(e, &occ(&r, "Bob"))).await?;
    assert_eq!(got.child_text("show", ns::CLIENT).as_deref(), Some("away"), "§7.7: {got}");
    let own = b.expect(|e| is_presence_from(e, &occ(&r, "Bob"))).await?;
    assert!(has_code(&own, "110"), "{own}");
    // No history or subject replay on a presence update.
    b.expect_silence(SHORT).await?;
    Ok(())
}

#[tokio::test]
async fn removing_membership_in_members_only_room_kicks_with_321() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("exclusive");
    create_configured(&mut a, &r, "Alice", &[("muc#roomconfig_membersonly", &["1"])]).await?;
    let res = a.iq_set(Some(&r), admin_item(&[("affiliation", "member"), ("jid", &bare("bob"))], None)).await?;
    assert_eq!(res.attr("type"), Some("result"));
    let mut b = s.online("bob", PW, "laptop").await?;
    join(&mut b, &r, "Bob").await?;
    let res = a.iq_set(Some(&r), admin_item(&[("affiliation", "none"), ("jid", &bare("bob"))], None)).await?;
    assert_eq!(res.attr("type"), Some("result"), "{res}");
    let gone = b.expect(|e| is_presence_from(e, &occ(&r, "Bob"))).await?;
    assert_eq!(gone.attr("type"), Some("unavailable"), "§9.4: {gone}");
    assert!(has_code(&gone, "321"), "§9.4: {gone}");
    Ok(())
}

#[tokio::test]
async fn outcast_set_before_join_is_refused() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("blacklist");
    create_instant(&mut a, &r, "Alice").await?;
    let res = a.iq_set(Some(&r), admin_item(&[("affiliation", "outcast"), ("jid", &bare("dave"))], None)).await?;
    assert_eq!(res.attr("type"), Some("result"));
    let mut d = s.online("dave", PW, "pc").await?;
    let j = join_with(&mut d, &r, "Dave", None, None).await?;
    let e = j.error.expect("outcast joined");
    assert_eq!(error_of(&e), Some(("forbidden".into(), "auth".into())), "§7.2.7: {e}");
    Ok(())
}

#[tokio::test]
async fn owner_cannot_be_banned_by_admin() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("throne");
    create_instant(&mut a, &r, "Alice").await?;
    let res = a.iq_set(Some(&r), admin_item(&[("affiliation", "admin"), ("jid", &bare("bob"))], None)).await?;
    assert_eq!(res.attr("type"), Some("result"));
    let mut b = s.online("bob", PW, "laptop").await?;
    join(&mut b, &r, "Bob").await?;
    let res = b.iq_set(Some(&r), admin_item(&[("affiliation", "outcast"), ("jid", &bare("alice"))], None)).await?;
    assert_eq!(res.attr("type"), Some("error"), "admin banned the owner: {res}");
    assert!(matches!(cond(&res).as_str(), "not-allowed" | "forbidden"), "§9.1: {res}");
    Ok(())
}

#[tokio::test]
async fn sole_owner_cannot_drop_own_ownership() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("lonely");
    create_instant(&mut a, &r, "Alice").await?;
    let res = a.iq_set(Some(&r), admin_item(&[("affiliation", "member"), ("jid", &bare("alice"))], None)).await?;
    assert_eq!(res.attr("type"), Some("error"), "§10.6 the last owner gave up ownership: {res}");
    assert_eq!(cond(&res), "conflict", "§10.6: {res}");
    Ok(())
}

#[tokio::test]
async fn history_since_seconds() -> anyhow::Result<()> {
    let s = server().await?;
    let mut a = s.online("alice", PW, "phone").await?;
    let r = room("seconds");
    create_instant(&mut a, &r, "Alice").await?;
    a.send(&groupchat(&r, "old")).await?;
    a.expect(|e| is_groupchat_body(e, "old")).await?;
    let mut b = s.online("bob", PW, "laptop").await?;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    a.send(&groupchat(&r, "new")).await?;
    a.expect(|e| is_groupchat_body(e, "new")).await?;
    let x = Element::new("x", ns::MUC).child(Element::new("history", ns::MUC).attr_set("seconds", "2"));
    b.send(&Element::new("presence", ns::CLIENT).attr_set("to", occ(&r, "Bob")).child(x)).await?;
    b.expect(|e| is_presence_from(e, &occ(&r, "Bob"))).await?;
    let mut bodies = Vec::new();
    loop {
        let e = b.expect(|e| e.name() == "message").await?;
        if is_subject(&e) {
            break;
        }
        bodies.push(e.child_text("body", ns::CLIENT).unwrap_or_default());
    }
    assert_eq!(bodies, vec!["new"], "§7.2.15 seconds=1");
    Ok(())
}
