//! Group chats (XEP-0045 and friends) driven through a real server by several clients.

use std::time::Duration;

use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{message, presence, Client, TestServer};

const ROOMS: &str = "rooms.quark.test";
const QUIET: Duration = Duration::from_millis(300);
const MUC_OWNER: &str = "http://jabber.org/protocol/muc#owner";
const MUC_ADMIN: &str = "http://jabber.org/protocol/muc#admin";
const ROOMCONFIG: &str = "http://jabber.org/protocol/muc#roomconfig";

fn room(name: &str) -> String {
    format!("{name}@{ROOMS}")
}

fn occ(name: &str, nick: &str) -> String {
    format!("{name}@{ROOMS}/{nick}")
}

/// Signs in a new account with one device.
async fn person(s: &TestServer, user: &str) -> anyhow::Result<Client> {
    s.add_user(user, "password").await?;
    s.online(user, "password", "phone").await
}

fn codes(p: &Element) -> Vec<u16> {
    p.get_child("x", ns::MUC_USER)
        .map(|x| x.children().filter(|c| c.name() == "status").filter_map(|c| c.attr("code")?.parse().ok()).collect())
        .unwrap_or_default()
}

fn item(p: &Element) -> Element {
    p.get_child("x", ns::MUC_USER)
        .and_then(|x| x.get_child("item", ns::MUC_USER))
        .cloned()
        .unwrap_or_else(|| Element::new("item", ns::MUC_USER))
}

fn error_condition(e: &Element) -> Option<String> {
    e.get_child("error", ns::CLIENT)?.children().find(|c| c.ns() == ns::STANZAS && c.name() != "text").map(|c| c.name().to_string())
}

fn join_presence(to: &str) -> Element {
    presence(Some(to), None).child(Element::new("x", ns::MUC))
}

/// Joins and waits for the self-presence (status 110) and the subject that ends the join.
async fn join(c: &mut Client, to: &str) -> anyhow::Result<Element> {
    join_with(c, to, join_presence(to)).await
}

async fn join_with(c: &mut Client, to: &str, p: Element) -> anyhow::Result<Element> {
    c.send(&p).await?;
    let me = c
        .expect(|e| e.name() == "presence" && e.attr("from") == Some(to) && (codes(e).contains(&110) || e.attr("type") == Some("error")))
        .await?;
    if me.attr("type") == Some("error") {
        anyhow::bail!("join refused: {me}");
    }
    let bare = to.split('/').next().unwrap_or_default().to_string();
    c.expect(|e| e.name() == "message" && e.has_child("subject", ns::CLIENT) && e.attr("from").is_some_and(|f| f.starts_with(&bare)))
        .await?;
    Ok(me)
}

/// A join that should fail; returns the error condition.
async fn join_refused(c: &mut Client, to: &str, p: Element) -> anyhow::Result<String> {
    c.send(&p).await?;
    let e = c.expect(|e| e.name() == "presence" && e.attr("from") == Some(to) && e.attr("type") == Some("error")).await?;
    Ok(error_condition(&e).unwrap_or_default())
}

fn owner_submit(fields: &[(&str, &str)]) -> Element {
    let mut x = Element::new("x", ns::DATA_FORMS)
        .attr_set("type", "submit")
        .child(Element::new("field", ns::DATA_FORMS).attr_set("var", "FORM_TYPE").text_child("value", ns::DATA_FORMS, ROOMCONFIG));
    for (k, v) in fields {
        x.append(Element::new("field", ns::DATA_FORMS).attr_set("var", *k).text_child("value", ns::DATA_FORMS, *v));
    }
    Element::new("query", MUC_OWNER).child(x)
}

/// Creates a room as an instant room (default settings), joined as `nick`.
async fn make_room(c: &mut Client, name: &str, nick: &str) -> anyhow::Result<()> {
    let me = join(c, &occ(name, nick)).await?;
    assert!(codes(&me).contains(&201), "a new room says it was created: {me}");
    let r = c
        .iq_set(Some(&room(name)), Element::new("query", MUC_OWNER).child(Element::new("x", ns::DATA_FORMS).attr_set("type", "submit")))
        .await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    Ok(())
}

async fn configure(c: &mut Client, name: &str, fields: &[(&str, &str)]) -> anyhow::Result<Element> {
    c.iq_set(Some(&room(name)), owner_submit(fields)).await
}

fn admin_item(attrs: &[(&str, &str)]) -> Element {
    let mut it = Element::new("item", MUC_ADMIN);
    for (k, v) in attrs {
        it.set_attr(k, *v);
    }
    Element::new("query", MUC_ADMIN).child(it)
}

fn register_form(nick: &str) -> Element {
    Element::new("query", ns::REGISTER).child(
        Element::new("x", ns::DATA_FORMS)
            .attr_set("type", "submit")
            .child(Element::new("field", ns::DATA_FORMS).attr_set("var", "FORM_TYPE").text_child(
                "value",
                ns::DATA_FORMS,
                "http://jabber.org/protocol/muc#register",
            ))
            .child(Element::new("field", ns::DATA_FORMS).attr_set("var", "muc#register_roomnick").text_child(
                "value",
                ns::DATA_FORMS,
                nick,
            )),
    )
}

/// Reads a room's archive: the archived messages, oldest first.
async fn room_archive(c: &mut Client, name: &str) -> anyhow::Result<Vec<Element>> {
    let id = quark_testkit::quark_core::new_id();
    let q = Element::new("query", ns::MAM).attr_set("queryid", "q1");
    c.send(&quark_testkit::quark_core::stanza::iq("set", &id, None, Some(&room(name)), q)).await?;
    let mut out = Vec::new();
    loop {
        let e = c.recv().await?;
        if e.name() == "iq" && e.attr("id") == Some(&id) {
            anyhow::ensure!(e.attr("type") == Some("result"), "query failed: {e}");
            return Ok(out);
        }
        if let Some(m) = e
            .get_child("result", ns::MAM)
            .and_then(|r| r.get_child("forwarded", ns::FORWARD))
            .and_then(|f| f.get_child("message", ns::CLIENT))
        {
            out.push(m.clone());
        }
    }
}

fn groupchat(name: &str, body: &str) -> Element {
    message(&room(name), "groupchat", body)
}

/// The next message, in order (presences that came in between are kept for later).
async fn next_message(c: &mut Client) -> anyhow::Result<Element> {
    c.expect(|e| e.name() == "message").await
}

async fn expect_body(c: &mut Client, from: &str, body: &str) -> anyhow::Result<Element> {
    c.expect(|e| e.name() == "message" && e.attr("from") == Some(from) && e.child_text("body", ns::CLIENT).as_deref() == Some(body)).await
}

#[tokio::test]
async fn the_service_is_discoverable() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    let items = alice.iq_get(Some(s.domain()), Element::new("query", ns::DISCO_ITEMS)).await?;
    let q = items.get_child("query", ns::DISCO_ITEMS).unwrap();
    assert!(q.children().any(|i| i.attr("jid") == Some(ROOMS)), "{items}");
    let info = alice.iq_get(Some(ROOMS), Element::new("query", ns::DISCO_INFO)).await?;
    let q = info.get_child("query", ns::DISCO_INFO).unwrap();
    assert!(q.children().any(|c| c.name() == "identity" && c.attr("category") == Some("conference")));
    assert!(q.children().any(|c| c.attr("var") == Some(ns::MUC)));
    let missing = alice.iq_get(Some(&room("nope")), Element::new("query", ns::DISCO_INFO)).await?;
    assert_eq!(error_condition(&missing).as_deref(), Some("item-not-found"));
    Ok(())
}

#[tokio::test]
async fn new_rooms_stay_locked_until_the_owner_configures_them() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    let mut bob = person(&s, "bob").await?;
    let me = join(&mut alice, &occ("tea", "alice")).await?;
    assert!(codes(&me).contains(&201) && codes(&me).contains(&110));
    assert_eq!(item(&me).attr("affiliation"), Some("owner"));
    assert_eq!(item(&me).attr("role"), Some("moderator"));
    assert_eq!(join_refused(&mut bob, &occ("tea", "bob"), join_presence(&occ("tea", "bob"))).await?, "item-not-found");

    let form = alice.iq_get(Some(&room("tea")), Element::new("query", MUC_OWNER)).await?;
    let x = form.get_child("query", MUC_OWNER).and_then(|q| q.get_child("x", ns::DATA_FORMS)).expect("a config form");
    assert!(x.children().any(|f| f.attr("var") == Some("muc#roomconfig_persistentroom")));
    configure(&mut alice, "tea", &[]).await?;
    join(&mut bob, &occ("tea", "bob")).await?;
    // Alice sees bob arrive, without his address (the room is semi-anonymous to non-moderators
    // but alice is a moderator, so she sees it).
    let p = alice.expect(|e| e.name() == "presence" && e.attr("from") == Some(&occ("tea", "bob"))).await?;
    assert_eq!(item(&p).attr("jid"), Some("bob@quark.test/phone"));
    assert!(p.has_child("occupant-id", ns::OCCUPANT_ID));
    Ok(())
}

#[tokio::test]
async fn messages_reach_everyone_with_stanza_and_occupant_ids() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    let mut bob = person(&s, "bob").await?;
    let mut carol = person(&s, "carol").await?;
    let mut dave = person(&s, "dave").await?;
    make_room(&mut alice, "tea", "alice").await?;
    join(&mut bob, &occ("tea", "bob")).await?;
    let me = join(&mut carol, &occ("tea", "carol")).await?;
    assert!(!codes(&me).contains(&100), "semi-anonymous by default");
    // Carol (not a moderator) doesn't see others' addresses.
    let p = carol.expect(|e| e.name() == "presence" && e.attr("from") == Some(&occ("tea", "alice"))).await?;
    assert_eq!(item(&p).attr("jid"), None);

    let m = groupchat("tea", "hello all");
    let id = m.attr("id").unwrap().to_string();
    alice.send(&m).await?;
    let mut sids = Vec::new();
    for c in [&mut alice, &mut bob, &mut carol] {
        let got = expect_body(c, &occ("tea", "alice"), "hello all").await?;
        assert_eq!(got.attr("id"), Some(id.as_str()), "the id is kept so the sender can match its echo");
        assert_eq!(got.attr("type"), Some("groupchat"));
        let sid = got.get_child("stanza-id", ns::SID).expect("stanza id");
        assert_eq!(sid.attr("by"), Some(room("tea").as_str()));
        sids.push(sid.attr("id").unwrap().to_string());
        assert!(got.has_child("occupant-id", ns::OCCUPANT_ID));
    }
    assert!(sids.windows(2).all(|w| w[0] == w[1]));

    // Someone outside can't post.
    dave.send(&groupchat("tea", "let me in")).await?;
    let e = dave.expect(|e| e.name() == "message" && e.attr("type") == Some("error")).await?;
    assert_eq!(error_condition(&e).as_deref(), Some("not-acceptable"));
    bob.expect_silence(QUIET).await.ok();
    Ok(())
}

#[tokio::test]
async fn joining_gets_the_history_asked_for_then_the_subject() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    let mut bob = person(&s, "bob").await?;
    let mut carol = person(&s, "carol").await?;
    make_room(&mut alice, "tea", "alice").await?;
    let subject = Element::new("message", ns::CLIENT).attr_set("to", room("tea")).attr_set("type", "groupchat").text_child(
        "subject",
        ns::CLIENT,
        "Tea time",
    );
    alice.send(&subject).await?;
    alice.expect(|e| e.child_text("subject", ns::CLIENT).as_deref() == Some("Tea time")).await?;
    for i in 1..=3 {
        alice.send(&groupchat("tea", &format!("m{i}"))).await?;
        expect_body(&mut alice, &occ("tea", "alice"), &format!("m{i}")).await?;
    }

    let to = occ("tea", "bob");
    bob.send(
        &presence(Some(&to), None).child(Element::new("x", ns::MUC).child(Element::new("history", ns::MUC).attr_set("maxstanzas", "2"))),
    )
    .await?;
    bob.expect(|e| e.name() == "presence" && e.attr("from") == Some(&to) && codes(e).contains(&110)).await?;
    let h1 = next_message(&mut bob).await?;
    let h2 = next_message(&mut bob).await?;
    let subj = next_message(&mut bob).await?;
    assert_eq!(h1.child_text("body", ns::CLIENT).as_deref(), Some("m2"));
    assert_eq!(h2.child_text("body", ns::CLIENT).as_deref(), Some("m3"));
    assert_eq!(h1.get_child("delay", ns::DELAY).and_then(|d| d.attr("from")), Some(room("tea").as_str()));
    assert_eq!(subj.child_text("subject", ns::CLIENT).as_deref(), Some("Tea time"));
    assert_eq!(subj.attr("from"), Some(occ("tea", "alice").as_str()));
    assert!(!subj.has_child("body", ns::CLIENT));

    let to = occ("tea", "carol");
    carol
        .send(
            &presence(Some(&to), None).child(Element::new("x", ns::MUC).child(Element::new("history", ns::MUC).attr_set("maxchars", "0"))),
        )
        .await?;
    carol.expect(|e| e.name() == "presence" && e.attr("from") == Some(&to) && codes(e).contains(&110)).await?;
    let next = next_message(&mut carol).await?;
    assert!(next.has_child("subject", ns::CLIENT), "no history, straight to the subject: {next}");

    // Only moderators may change the subject by default.
    bob.send(&Element::new("message", ns::CLIENT).attr_set("to", room("tea")).attr_set("type", "groupchat").text_child(
        "subject",
        ns::CLIENT,
        "Coffee",
    ))
    .await?;
    let e = bob.expect(|e| e.name() == "message" && e.attr("type") == Some("error")).await?;
    assert_eq!(error_condition(&e).as_deref(), Some("forbidden"));
    Ok(())
}

#[tokio::test]
async fn nicknames_conflict_and_change() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    let mut bob = person(&s, "bob").await?;
    make_room(&mut alice, "tea", "alice").await?;
    assert_eq!(join_refused(&mut bob, &occ("tea", "alice"), join_presence(&occ("tea", "alice"))).await?, "conflict");
    join(&mut bob, &occ("tea", "bob")).await?;
    alice.expect(|e| e.attr("from") == Some(&occ("tea", "bob"))).await?;

    bob.send(&presence(Some(&occ("tea", "robert")), None)).await?;
    let gone = alice.expect(|e| e.attr("from") == Some(&occ("tea", "bob")) && e.attr("type") == Some("unavailable")).await?;
    assert!(codes(&gone).contains(&303));
    assert_eq!(item(&gone).attr("nick"), Some("robert"));
    alice.expect(|e| e.attr("from") == Some(&occ("tea", "robert")) && e.attr("type").is_none()).await?;
    let mine = bob.expect(|e| e.attr("from") == Some(&occ("tea", "bob")) && e.attr("type") == Some("unavailable")).await?;
    assert!(codes(&mine).contains(&110) && codes(&mine).contains(&303));
    bob.expect(|e| e.attr("from") == Some(&occ("tea", "robert")) && codes(e).contains(&110)).await?;

    bob.send(&groupchat("tea", "new name")).await?;
    expect_body(&mut alice, &occ("tea", "robert"), "new name").await?;
    Ok(())
}

#[tokio::test]
async fn leaving_is_announced_and_temporary_rooms_vanish() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    let mut bob = person(&s, "bob").await?;
    make_room(&mut alice, "tea", "alice").await?;
    join(&mut bob, &occ("tea", "bob")).await?;
    bob.send(&presence(Some(&occ("tea", "bob")), Some("unavailable")).text_child("status", ns::CLIENT, "bye")).await?;
    let mine = bob.expect(|e| e.attr("from") == Some(&occ("tea", "bob")) && e.attr("type") == Some("unavailable")).await?;
    assert!(codes(&mine).contains(&110));
    let p = alice.expect(|e| e.attr("from") == Some(&occ("tea", "bob")) && e.attr("type") == Some("unavailable")).await?;
    assert_eq!(p.child_text("status", ns::CLIENT).as_deref(), Some("bye"));
    assert_eq!(item(&p).attr("role"), Some("none"));

    // Closing the stream counts as leaving (the server sends unavailable for directed presence).
    join(&mut bob, &occ("tea", "bob")).await?;
    bob.close().await?;
    alice.expect(|e| e.attr("from") == Some(&occ("tea", "bob")) && e.attr("type") == Some("unavailable")).await?;

    alice.send(&presence(Some(&occ("tea", "alice")), Some("unavailable"))).await?;
    alice.expect(|e| e.attr("from") == Some(&occ("tea", "alice")) && e.attr("type") == Some("unavailable")).await?;
    let info = alice.iq_get(Some(&room("tea")), Element::new("query", ns::DISCO_INFO)).await?;
    assert_eq!(error_condition(&info).as_deref(), Some("item-not-found"), "an empty temporary room is gone");
    Ok(())
}

#[tokio::test]
async fn private_messages_follow_the_room_setting() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    let mut bob = person(&s, "bob").await?;
    make_room(&mut alice, "tea", "alice").await?;
    join(&mut bob, &occ("tea", "bob")).await?;
    bob.send(&message(&occ("tea", "alice"), "chat", "psst")).await?;
    let pm = expect_body(&mut alice, &occ("tea", "bob"), "psst").await?;
    assert_eq!(pm.attr("type"), Some("chat"));
    assert!(pm.has_child("x", ns::MUC_USER), "marked as a group chat private message");

    bob.send(&message(&occ("tea", "nobody"), "chat", "hello?")).await?;
    let e = bob.expect(|e| e.name() == "message" && e.attr("type") == Some("error")).await?;
    assert_eq!(error_condition(&e).as_deref(), Some("item-not-found"));

    configure(&mut alice, "tea", &[("muc#roomconfig_allowpm", "none")]).await?;
    bob.send(&message(&occ("tea", "alice"), "chat", "psst again")).await?;
    let e = bob.expect(|e| e.name() == "message" && e.attr("type") == Some("error")).await?;
    assert_eq!(error_condition(&e).as_deref(), Some("not-allowed"));
    Ok(())
}

#[tokio::test]
async fn several_devices_share_one_nickname() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password").await?;
    let mut phone = s.online("alice", "password", "phone").await?;
    let mut laptop = s.online("alice", "password", "laptop").await?;
    let mut bob = person(&s, "bob").await?;
    make_room(&mut bob, "tea", "bob").await?;
    join(&mut phone, &occ("tea", "alice")).await?;
    bob.expect(|e| e.attr("from") == Some(&occ("tea", "alice"))).await?;
    let me = join(&mut laptop, &occ("tea", "alice")).await?;
    assert!(codes(&me).contains(&110));
    // Bob sees an update of the one occupant, not a second person.
    let upd = bob.expect(|e| e.attr("from") == Some(&occ("tea", "alice"))).await?;
    assert_eq!(upd.attr("type"), None);

    bob.send(&groupchat("tea", "both of you")).await?;
    expect_body(&mut phone, &occ("tea", "bob"), "both of you").await?;
    expect_body(&mut laptop, &occ("tea", "bob"), "both of you").await?;
    bob.send(&message(&occ("tea", "alice"), "chat", "private")).await?;
    expect_body(&mut phone, &occ("tea", "bob"), "private").await?;
    expect_body(&mut laptop, &occ("tea", "bob"), "private").await?;

    laptop.send(&presence(Some(&occ("tea", "alice")), Some("unavailable"))).await?;
    let mine = laptop.expect(|e| e.attr("from") == Some(&occ("tea", "alice")) && e.attr("type") == Some("unavailable")).await?;
    assert!(codes(&mine).contains(&110));
    // Alice is still there on her phone.
    let p = bob.expect(|e| e.attr("from") == Some(&occ("tea", "alice"))).await?;
    assert_eq!(p.attr("type"), None, "still present: {p}");
    phone.send(&groupchat("tea", "still here")).await?;
    expect_body(&mut bob, &occ("tea", "alice"), "still here").await?;
    Ok(())
}

#[tokio::test]
async fn moderators_kick_and_admins_ban() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    let mut bob = person(&s, "bob").await?;
    let mut carol = person(&s, "carol").await?;
    make_room(&mut alice, "tea", "alice").await?;
    join(&mut bob, &occ("tea", "bob")).await?;
    join(&mut carol, &occ("tea", "carol")).await?;

    // A participant can't kick.
    let r = bob.iq_set(Some(&room("tea")), admin_item(&[("nick", "carol"), ("role", "none")])).await?;
    assert_eq!(error_condition(&r).as_deref(), Some("forbidden"));

    let mut q = admin_item(&[("nick", "bob"), ("role", "none")]);
    if let Some(it) = q.get_child_mut("item", MUC_ADMIN) {
        it.append(Element::new("reason", MUC_ADMIN).text("too loud"));
    }
    let r = alice.iq_set(Some(&room("tea")), q).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let kicked = bob.expect(|e| e.attr("from") == Some(&occ("tea", "bob")) && e.attr("type") == Some("unavailable")).await?;
    assert!(codes(&kicked).contains(&307) && codes(&kicked).contains(&110));
    let it = item(&kicked);
    assert_eq!(it.child_text("reason", ns::MUC_USER).as_deref(), Some("too loud"));
    assert_eq!(it.get_child("actor", ns::MUC_USER).and_then(|a| a.attr("nick")), Some("alice"));
    let seen = carol.expect(|e| e.attr("from") == Some(&occ("tea", "bob")) && e.attr("type") == Some("unavailable")).await?;
    assert!(codes(&seen).contains(&307));

    let r = alice.iq_set(Some(&room("tea")), admin_item(&[("jid", "carol@quark.test"), ("affiliation", "outcast")])).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let banned = carol.expect(|e| e.attr("from") == Some(&occ("tea", "carol")) && e.attr("type") == Some("unavailable")).await?;
    assert!(codes(&banned).contains(&301));
    assert_eq!(join_refused(&mut carol, &occ("tea", "carol"), join_presence(&occ("tea", "carol"))).await?, "forbidden");

    let list = alice.iq_get(Some(&room("tea")), admin_item(&[("affiliation", "outcast")])).await?;
    let q = list.get_child("query", MUC_ADMIN).unwrap();
    assert_eq!(q.children().filter_map(|i| i.attr("jid")).collect::<Vec<_>>(), vec!["carol@quark.test"]);

    // The owner can't kick themselves out of ownership if they're the last one.
    let r = alice.iq_set(Some(&room("tea")), admin_item(&[("jid", "alice@quark.test"), ("affiliation", "member")])).await?;
    assert_eq!(error_condition(&r).as_deref(), Some("conflict"));
    Ok(())
}

#[tokio::test]
async fn members_only_rooms_keep_strangers_out() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    let mut bob = person(&s, "bob").await?;
    let mut carol = person(&s, "carol").await?;
    make_room(&mut alice, "club", "alice").await?;
    join(&mut carol, &occ("club", "carol")).await?;
    configure(&mut alice, "club", &[("muc#roomconfig_membersonly", "1"), ("muc#roomconfig_whois", "anyone")]).await?;
    // Carol, not a member, is removed (322); alice hears the configuration changed (104, 172).
    let out = carol.expect(|e| e.attr("from") == Some(&occ("club", "carol")) && e.attr("type") == Some("unavailable")).await?;
    assert!(codes(&out).contains(&322));
    let note = alice.expect(|e| e.name() == "message" && codes(e).contains(&104)).await?;
    assert!(codes(&note).contains(&172));

    assert_eq!(join_refused(&mut bob, &occ("club", "bob"), join_presence(&occ("club", "bob"))).await?, "registration-required");
    let r = alice.iq_set(Some(&room("club")), admin_item(&[("jid", "bob@quark.test"), ("affiliation", "member")])).await?;
    assert_eq!(r.attr("type"), Some("result"));
    let me = join(&mut bob, &occ("club", "bob")).await?;
    assert!(codes(&me).contains(&100), "non-anonymous now");
    assert_eq!(item(&me).attr("affiliation"), Some("member"));

    // Members can read the member list of a non-anonymous room; nobody else can.
    let list = bob.iq_get(Some(&room("club")), admin_item(&[("affiliation", "member")])).await?;
    assert_eq!(list.attr("type"), Some("result"), "{list}");
    let list = carol.iq_get(Some(&room("club")), admin_item(&[("affiliation", "member")])).await?;
    assert_eq!(error_condition(&list).as_deref(), Some("forbidden"));

    // Revoking membership removes bob (321).
    alice.iq_set(Some(&room("club")), admin_item(&[("jid", "bob@quark.test"), ("affiliation", "none")])).await?;
    let out = bob.expect(|e| e.attr("from") == Some(&occ("club", "bob")) && e.attr("type") == Some("unavailable")).await?;
    assert!(codes(&out).contains(&321));
    Ok(())
}

#[tokio::test]
async fn moderated_rooms_give_voice_on_request() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    let mut bob = person(&s, "bob").await?;
    let mut carol = person(&s, "carol").await?;
    make_room(&mut alice, "stage", "alice").await?;
    configure(&mut alice, "stage", &[("muc#roomconfig_moderatedroom", "1")]).await?;
    let me = join(&mut bob, &occ("stage", "bob")).await?;
    assert_eq!(item(&me).attr("role"), Some("visitor"));
    bob.send(&groupchat("stage", "can I talk?")).await?;
    let e = bob.expect(|e| e.name() == "message" && e.attr("type") == Some("error")).await?;
    assert_eq!(error_condition(&e).as_deref(), Some("forbidden"));

    let r = alice.iq_set(Some(&room("stage")), admin_item(&[("nick", "bob"), ("role", "participant")])).await?;
    assert_eq!(r.attr("type"), Some("result"));
    let p = bob.expect(|e| e.attr("from") == Some(&occ("stage", "bob")) && item(e).attr("role") == Some("participant")).await?;
    assert!(codes(&p).contains(&110));
    bob.send(&groupchat("stage", "thanks")).await?;
    expect_body(&mut alice, &occ("stage", "bob"), "thanks").await?;

    // Carol asks for voice; alice gets the form and approves it.
    join(&mut carol, &occ("stage", "carol")).await?;
    let req = Element::new("x", ns::DATA_FORMS)
        .attr_set("type", "submit")
        .child(Element::new("field", ns::DATA_FORMS).attr_set("var", "FORM_TYPE").text_child(
            "value",
            ns::DATA_FORMS,
            "http://jabber.org/protocol/muc#request",
        ))
        .child(Element::new("field", ns::DATA_FORMS).attr_set("var", "muc#role").text_child("value", ns::DATA_FORMS, "participant"));
    carol.send(&Element::new("message", ns::CLIENT).attr_set("to", room("stage")).child(req)).await?;
    let form = alice.expect(|e| e.name() == "message" && e.has_child("x", ns::DATA_FORMS)).await?;
    let x = form.get_child("x", ns::DATA_FORMS).unwrap();
    let field = |v: &str| x.children().find(|f| f.attr("var") == Some(v)).and_then(|f| f.child_text("value", ns::DATA_FORMS));
    assert_eq!(field("muc#roomnick").as_deref(), Some("carol"));
    let mut answer = x.clone();
    answer.set_attr("type", "submit");
    for f in answer.children_mut() {
        if f.attr("var") == Some("muc#request_allow") {
            f.clear_children();
            f.append(Element::new("value", ns::DATA_FORMS).text("true"));
        }
    }
    alice.send(&Element::new("message", ns::CLIENT).attr_set("to", room("stage")).child(answer)).await?;
    carol.expect(|e| e.attr("from") == Some(&occ("stage", "carol")) && item(e).attr("role") == Some("participant")).await?;
    Ok(())
}

#[tokio::test]
async fn configuration_shows_in_disco_and_password_protects() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    let mut bob = person(&s, "bob").await?;
    make_room(&mut alice, "tea", "alice").await?;
    let r = configure(
        &mut alice,
        "tea",
        &[
            ("muc#roomconfig_roomname", "Tea Room"),
            ("muc#roomconfig_roomdesc", "All about tea"),
            ("muc#roomconfig_passwordprotectedroom", "1"),
            ("muc#roomconfig_roomsecret", "oolong"),
            ("muc#roomconfig_publicroom", "0"),
        ],
    )
    .await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let info = bob.iq_get(Some(&room("tea")), Element::new("query", ns::DISCO_INFO)).await?;
    let q = info.get_child("query", ns::DISCO_INFO).unwrap();
    let features: Vec<&str> = q.children().filter_map(|f| f.attr("var")).collect();
    for f in ["muc_passwordprotected", "muc_hidden", "muc_temporary", "muc_semianonymous", ns::MUC, ns::OCCUPANT_ID, ns::MUC_SELF_PING] {
        assert!(features.contains(&f), "{f} in {features:?}");
    }
    assert_eq!(q.get_child("identity", ns::DISCO_INFO).and_then(|i| i.attr("name")), Some("Tea Room"));
    let form = q.get_child("x", ns::DATA_FORMS).unwrap();
    let field = |v: &str| form.children().find(|f| f.attr("var") == Some(v)).and_then(|f| f.child_text("value", ns::DATA_FORMS));
    assert_eq!(field("muc#roominfo_occupants").as_deref(), Some("1"));
    assert_eq!(field("muc#roominfo_description").as_deref(), Some("All about tea"));

    // Hidden rooms aren't listed.
    let items = bob.iq_get(Some(ROOMS), Element::new("query", ns::DISCO_ITEMS)).await?;
    assert!(!items.to_xml().contains("tea@"), "{items}");

    assert_eq!(join_refused(&mut bob, &occ("tea", "bob"), join_presence(&occ("tea", "bob"))).await?, "not-authorized");
    let wrong = presence(Some(&occ("tea", "bob")), None).child(Element::new("x", ns::MUC).text_child("password", ns::MUC, "earl grey"));
    assert_eq!(join_refused(&mut bob, &occ("tea", "bob"), wrong).await?, "not-authorized");
    let right = presence(Some(&occ("tea", "bob")), None).child(Element::new("x", ns::MUC).text_child("password", ns::MUC, "oolong"));
    join_with(&mut bob, &occ("tea", "bob"), right).await?;

    // Only owners see the form.
    let r = bob.iq_get(Some(&room("tea")), Element::new("query", MUC_OWNER)).await?;
    assert_eq!(error_condition(&r).as_deref(), Some("forbidden"));
    Ok(())
}

#[tokio::test]
async fn destroying_sends_everyone_elsewhere() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    let mut bob = person(&s, "bob").await?;
    make_room(&mut alice, "old", "alice").await?;
    join(&mut bob, &occ("old", "bob")).await?;
    let destroy = Element::new("query", MUC_OWNER)
        .child(Element::new("destroy", MUC_OWNER).attr_set("jid", room("new")).text_child("reason", MUC_OWNER, "We moved"));
    let r = bob.iq_set(Some(&room("old")), destroy.clone()).await?;
    assert_eq!(error_condition(&r).as_deref(), Some("forbidden"));
    let r = alice.iq_set(Some(&room("old")), destroy).await?;
    assert_eq!(r.attr("type"), Some("result"));
    let p = bob.expect(|e| e.attr("from") == Some(&occ("old", "bob")) && e.attr("type") == Some("unavailable")).await?;
    let d = p.get_child("x", ns::MUC_USER).and_then(|x| x.get_child("destroy", ns::MUC_USER)).expect("destroy element");
    assert_eq!(d.attr("jid"), Some(room("new").as_str()));
    assert_eq!(d.child_text("reason", ns::MUC_USER).as_deref(), Some("We moved"));
    let info = bob.iq_get(Some(&room("old")), Element::new("query", ns::DISCO_INFO)).await?;
    assert_eq!(error_condition(&info).as_deref(), Some("item-not-found"));
    Ok(())
}

#[tokio::test]
async fn persistent_rooms_survive_a_restart() -> anyhow::Result<()> {
    let mut s = TestServer::start().await?;
    s.add_user("alice", "password").await?;
    s.add_user("bob", "password").await?;
    {
        let mut alice = s.online("alice", "password", "phone").await?;
        make_room(&mut alice, "home", "alice").await?;
        configure(
            &mut alice,
            "home",
            &[("muc#roomconfig_persistentroom", "1"), ("muc#roomconfig_roomname", "Home"), ("muc#roomconfig_membersonly", "1")],
        )
        .await?;
        alice.iq_set(Some(&room("home")), admin_item(&[("jid", "bob@quark.test"), ("affiliation", "member")])).await?;
        let subject = Element::new("message", ns::CLIENT).attr_set("to", room("home")).attr_set("type", "groupchat").text_child(
            "subject",
            ns::CLIENT,
            "Family",
        );
        alice.send(&subject).await?;
        alice.send(&groupchat("home", "remember this")).await?;
        expect_body(&mut alice, &occ("home", "alice"), "remember this").await?;
        // Leaving keeps a persistent room.
        alice.send(&presence(Some(&occ("home", "alice")), Some("unavailable"))).await?;
        alice.expect(|e| e.attr("type") == Some("unavailable")).await?;
        let info = alice.iq_get(Some(&room("home")), Element::new("query", ns::DISCO_INFO)).await?;
        assert_eq!(info.attr("type"), Some("result"));
    }
    s.restart().await?;

    let mut bob = s.online("bob", "password", "phone").await?;
    let to = occ("home", "bob");
    bob.send(&join_presence(&to)).await?;
    let me = bob.expect(|e| e.name() == "presence" && e.attr("from") == Some(&to)).await?;
    assert!(codes(&me).contains(&110), "bob is still a member: {me}");
    let hist = bob.expect(|e| e.name() == "message" && e.has_child("body", ns::CLIENT)).await?;
    assert_eq!(hist.child_text("body", ns::CLIENT).as_deref(), Some("remember this"));
    assert!(hist.has_child("delay", ns::DELAY));
    let subj = bob.expect(|e| e.name() == "message" && e.has_child("subject", ns::CLIENT)).await?;
    assert_eq!(subj.child_text("subject", ns::CLIENT).as_deref(), Some("Family"));

    let mut alice = s.online("alice", "password", "phone").await?;
    let me = join(&mut alice, &occ("home", "alice")).await?;
    assert_eq!(item(&me).attr("affiliation"), Some("owner"));
    let info = alice.iq_get(Some(&room("home")), Element::new("query", ns::DISCO_INFO)).await?;
    assert!(info.to_xml().contains("muc_persistent") && info.to_xml().contains("muc_membersonly"));
    assert_eq!(
        info.get_child("query", ns::DISCO_INFO).and_then(|q| q.get_child("identity", ns::DISCO_INFO)).and_then(|i| i.attr("name")),
        Some("Home")
    );
    Ok(())
}

#[tokio::test]
async fn invitations_and_declines_are_relayed() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    s.add_user("bob", "password").await?;
    make_room(&mut alice, "tea", "alice").await?;
    let invite = |to: &str| {
        Element::new("message", ns::CLIENT).attr_set("to", room("tea")).child(
            Element::new("x", ns::MUC_USER).child(Element::new("invite", ns::MUC_USER).attr_set("to", to).text_child(
                "reason",
                ns::MUC_USER,
                "come",
            )),
        )
    };
    // Bob is offline: the invitation waits for him.
    alice.send(&invite("bob@quark.test")).await?;
    alice.expect_silence(QUIET).await?;
    let mut bob = s.online("bob", "password", "phone").await?;
    let got = bob.expect(|e| e.name() == "message" && e.attr("from") == Some(&room("tea"))).await?;
    let inv = got.get_child("x", ns::MUC_USER).and_then(|x| x.get_child("invite", ns::MUC_USER)).expect("invite");
    assert_eq!(inv.attr("from"), Some("alice@quark.test"));
    assert_eq!(inv.child_text("reason", ns::MUC_USER).as_deref(), Some("come"));

    let decline = Element::new("message", ns::CLIENT).attr_set("to", room("tea")).child(
        Element::new("x", ns::MUC_USER).child(Element::new("decline", ns::MUC_USER).attr_set("to", "alice@quark.test").text_child(
            "reason",
            ns::MUC_USER,
            "busy",
        )),
    );
    bob.send(&decline).await?;
    let got = alice.expect(|e| e.name() == "message" && e.attr("from") == Some(&room("tea"))).await?;
    let d = got.get_child("x", ns::MUC_USER).and_then(|x| x.get_child("decline", ns::MUC_USER)).expect("decline");
    assert_eq!(d.attr("from"), Some("bob@quark.test"));

    // In a members-only room, an admin's invitation makes the invitee a member.
    configure(&mut alice, "tea", &[("muc#roomconfig_membersonly", "1")]).await?;
    alice.send(&invite("bob@quark.test")).await?;
    bob.expect(|e| e.name() == "message" && e.has_child("x", ns::MUC_USER) && e.attr("from") == Some(&room("tea"))).await?;
    join(&mut bob, &occ("tea", "bob")).await?;
    Ok(())
}

#[tokio::test]
async fn registering_reserves_a_nickname() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    let mut bob = person(&s, "bob").await?;
    let mut carol = person(&s, "carol").await?;
    make_room(&mut alice, "tea", "alice").await?;
    // Only people in the room can make themselves members.
    let r = carol.iq_set(Some(&room("tea")), register_form("carol")).await?;
    assert_eq!(error_condition(&r).as_deref(), Some("not-acceptable"), "{r}");
    join(&mut bob, &occ("tea", "bob")).await?;
    let form = bob.iq_get(Some(&room("tea")), Element::new("query", ns::REGISTER)).await?;
    assert!(form.get_child("query", ns::REGISTER).and_then(|q| q.get_child("x", ns::DATA_FORMS)).is_some(), "{form}");
    let r = bob.iq_set(Some(&room("tea")), register_form("bobby")).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let again = bob.iq_get(Some(&room("tea")), Element::new("query", ns::REGISTER)).await?;
    let q = again.get_child("query", ns::REGISTER).unwrap();
    assert!(q.has_child("registered", ns::REGISTER));
    assert_eq!(q.child_text("username", ns::REGISTER).as_deref(), Some("bobby"));
    let nick = bob.iq_get(Some(&room("tea")), Element::new("query", ns::DISCO_INFO).attr_set("node", "x-roomuser-item")).await?;
    assert!(nick.to_xml().contains("name='bobby'"), "{nick}");

    assert_eq!(join_refused(&mut carol, &occ("tea", "bobby"), join_presence(&occ("tea", "bobby"))).await?, "conflict");
    bob.send(&presence(Some(&occ("tea", "bob")), Some("unavailable"))).await?;
    bob.expect(|e| e.name() == "presence" && e.attr("type") == Some("unavailable")).await?;
    let me = join(&mut bob, &occ("tea", "bobby")).await?;
    assert_eq!(item(&me).attr("affiliation"), Some("member"));
    Ok(())
}

#[tokio::test]
async fn self_ping_answers_for_joined_clients_only() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    let mut bob = person(&s, "bob").await?;
    make_room(&mut alice, "tea", "alice").await?;
    let r = alice.iq_get(Some(&occ("tea", "alice")), Element::new("ping", ns::PING)).await?;
    assert_eq!(r.attr("type"), Some("result"));
    let r = bob.iq_get(Some(&occ("tea", "bob")), Element::new("ping", ns::PING)).await?;
    assert_eq!(error_condition(&r).as_deref(), Some("not-acceptable"));
    Ok(())
}

#[tokio::test]
async fn vcards_of_occupants_come_from_their_accounts() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    let mut bob = person(&s, "bob").await?;
    let card = Element::new("vCard", ns::VCARD).text_child("FN", ns::VCARD, "Alice A.");
    alice.iq_set(None, card).await?;
    make_room(&mut alice, "tea", "alice").await?;
    join(&mut bob, &occ("tea", "bob")).await?;
    let r = bob.iq_get(Some(&occ("tea", "alice")), Element::new("vCard", ns::VCARD)).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    assert_eq!(r.attr("from"), Some(occ("tea", "alice").as_str()));
    assert_eq!(r.get_child("vCard", ns::VCARD).and_then(|v| v.child_text("FN", ns::VCARD)).as_deref(), Some("Alice A."));
    Ok(())
}

#[tokio::test]
async fn room_avatars_are_announced() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    let mut bob = person(&s, "bob").await?;
    make_room(&mut alice, "tea", "alice").await?;
    join(&mut bob, &occ("tea", "bob")).await?;
    let card = Element::new("vCard", ns::VCARD)
        .child(Element::new("PHOTO", ns::VCARD).text_child("TYPE", ns::VCARD, "image/png").text_child("BINVAL", ns::VCARD, "aGVsbG8="));
    let r = bob.iq_set(Some(&room("tea")), card.clone()).await?;
    assert_eq!(error_condition(&r).as_deref(), Some("forbidden"));
    let r = alice.iq_set(Some(&room("tea")), card).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    // sha1("hello")
    let hash = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
    let p = bob.expect(|e| e.name() == "presence" && e.attr("from") == Some(&room("tea"))).await?;
    assert_eq!(p.get_child("x", ns::VCARD_UPDATE).and_then(|x| x.child_text("photo", ns::VCARD_UPDATE)).as_deref(), Some(hash));
    let info = bob.iq_get(Some(&room("tea")), Element::new("query", ns::DISCO_INFO)).await?;
    assert!(info.to_xml().contains(hash));
    let got = bob.iq_get(Some(&room("tea")), Element::new("vCard", ns::VCARD)).await?;
    assert!(got.to_xml().contains("aGVsbG8="));
    Ok(())
}

#[tokio::test]
async fn moderators_can_remove_messages() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    let mut bob = person(&s, "bob").await?;
    let mut carol = person(&s, "carol").await?;
    make_room(&mut alice, "tea", "alice").await?;
    join(&mut bob, &occ("tea", "bob")).await?;
    bob.send(&groupchat("tea", "something rude")).await?;
    let m = expect_body(&mut alice, &occ("tea", "bob"), "something rude").await?;
    let sid = m.get_child("stanza-id", ns::SID).and_then(|s| s.attr("id")).unwrap().to_string();

    let moderate = Element::new("moderate", "urn:xmpp:message-moderate:1")
        .attr_set("id", sid.as_str())
        .child(Element::new("retract", "urn:xmpp:message-retract:1"))
        .text_child("reason", "urn:xmpp:message-moderate:1", "Be nice");
    let r = bob.iq_set(Some(&room("tea")), moderate.clone()).await?;
    assert_eq!(error_condition(&r).as_deref(), Some("forbidden"));
    let r = alice.iq_set(Some(&room("tea")), moderate).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let note = bob.expect(|e| e.name() == "message" && e.has_child("retract", "urn:xmpp:message-retract:1")).await?;
    let retract = note.get_child("retract", "urn:xmpp:message-retract:1").unwrap();
    assert_eq!(retract.attr("id"), Some(sid.as_str()));
    assert_eq!(
        retract.get_child("moderated", "urn:xmpp:message-moderate:1").and_then(|m| m.attr("by")),
        Some(occ("tea", "alice").as_str())
    );
    assert!(note.has_child("apply-to", "urn:xmpp:fasten:0"), "the older version too");

    // People joining later don't see it.
    let to = occ("tea", "carol");
    carol.send(&join_presence(&to)).await?;
    carol.expect(|e| e.name() == "presence" && e.attr("from") == Some(&to) && codes(e).contains(&110)).await?;
    let next = next_message(&mut carol).await?;
    assert!(next.has_child("subject", ns::CLIENT), "nothing in history: {next}");
    Ok(())
}

#[tokio::test]
async fn sending_too_fast_is_refused() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    make_room(&mut alice, "tea", "alice").await?;
    for i in 0..40 {
        alice.send(&groupchat("tea", &format!("spam {i}"))).await?;
    }
    let e = alice.expect(|e| e.name() == "message" && e.attr("type") == Some("error")).await?;
    assert_eq!(error_condition(&e).as_deref(), Some("resource-constraint"));
    Ok(())
}

#[tokio::test]
async fn only_admins_create_rooms_when_configured() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.set_settings(|st| st.groups.who_creates = quark::settings::WhoCreates::Admins).await?;
    let mut bob = person(&s, "bob").await?;
    assert_eq!(join_refused(&mut bob, &occ("new", "bob"), join_presence(&occ("new", "bob"))).await?, "not-allowed");
    s.add_user("admin", "password").await?;
    let mut admin = s.online("admin", "password", "phone").await?;
    make_room(&mut admin, "new", "boss").await?;
    join(&mut bob, &occ("new", "bob")).await?;
    Ok(())
}

#[tokio::test]
async fn turning_group_chats_off_closes_rooms() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    make_room(&mut alice, "tea", "alice").await?;
    s.set_settings(|st| st.groups.on = false).await?;
    let p = alice.expect(|e| e.attr("from") == Some(&occ("tea", "alice")) && e.attr("type") == Some("unavailable")).await?;
    assert!(codes(&p).contains(&332));
    let r = alice.iq_get(Some(ROOMS), Element::new("query", ns::DISCO_INFO)).await?;
    assert_eq!(r.attr("type"), Some("error"), "the service is gone: {r}");
    Ok(())
}

#[tokio::test]
async fn admin_functions_create_post_list_and_destroy() -> anyhow::Result<()> {
    use quark::modules::muc;
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    let jid = muc::create_room(
        &s.srv,
        muc::NewRoom {
            service: ROOMS,
            room: "news",
            name: "News",
            description: Some("Updates"),
            public: true,
            members_only: false,
            owner: Some("alice@quark.test"),
        },
    )
    .await?;
    assert_eq!(jid, room("news"));
    let again = muc::create_room(
        &s.srv,
        muc::NewRoom { service: ROOMS, room: "news", name: "News", description: None, public: true, members_only: false, owner: None },
    )
    .await;
    assert!(matches!(again, Err(muc::RoomError::Exists(_))));
    let off = muc::create_room(
        &s.srv,
        muc::NewRoom { service: "elsewhere.test", room: "x", name: "", description: None, public: true, members_only: false, owner: None },
    )
    .await;
    assert!(matches!(off, Err(muc::RoomError::Invalid(_))));

    let me = join(&mut alice, &occ("news", "alice")).await?;
    assert_eq!(item(&me).attr("affiliation"), Some("owner"));
    assert!(!codes(&me).contains(&201), "made already, and not locked");

    muc::post(&s.srv, &room("news"), "Gluon", "Backup finished").await?;
    let m = expect_body(&mut alice, &occ("news", "Gluon"), "Backup finished").await?;
    assert_eq!(m.attr("type"), Some("groupchat"));
    assert!(m.has_child("stanza-id", ns::SID));
    assert!(matches!(muc::post(&s.srv, &room("nowhere"), "Gluon", "x").await, Err(muc::RoomError::NotFound(_))));

    let rooms = muc::list_rooms(&s.srv, ROOMS).await;
    let news = rooms.iter().find(|r| r.jid == room("news")).expect("listed");
    assert_eq!(news.name.as_deref(), Some("News"));
    assert!(news.persistent && news.public);
    assert_eq!(news.occupants, 1);

    muc::destroy_room(&s.srv, &room("news"), Some("Closing")).await?;
    let p = alice.expect(|e| e.attr("from") == Some(&occ("news", "alice")) && e.attr("type") == Some("unavailable")).await?;
    assert!(p.to_xml().contains("Closing"));
    assert!(muc::list_rooms(&s.srv, ROOMS).await.iter().all(|r| r.jid != room("news")));
    assert!(matches!(muc::destroy_room(&s.srv, &room("news"), None).await, Err(muc::RoomError::NotFound(_))));
    Ok(())
}

fn sid_of(m: &Element) -> String {
    m.get_child("stanza-id", ns::SID).and_then(|s| s.attr("id")).unwrap_or_default().to_string()
}

#[tokio::test]
async fn retracted_messages_stay_gone_after_a_restart_and_from_the_archive() -> anyhow::Result<()> {
    let mut s = TestServer::start().await?;
    for u in ["alice", "bob", "carol"] {
        s.add_user(u, "password").await?;
    }
    {
        let mut alice = s.online("alice", "password", "phone").await?;
        let mut bob = s.online("bob", "password", "phone").await?;
        make_room(&mut alice, "home", "alice").await?;
        configure(&mut alice, "home", &[("muc#roomconfig_persistentroom", "1")]).await?;
        join(&mut bob, &occ("home", "bob")).await?;
        bob.send(&groupchat("home", "oops, wrong room")).await?;
        let m = expect_body(&mut bob, &occ("home", "bob"), "oops, wrong room").await?;
        let retract = Element::new("message", ns::CLIENT)
            .attr_set("to", room("home"))
            .attr_set("type", "groupchat")
            .child(Element::new("retract", ns::RETRACT).attr_set("id", sid_of(&m)));
        bob.send(&retract).await?;
        alice.expect(|e| e.name() == "message" && e.has_child("retract", ns::RETRACT)).await?;
        // In the archive, only a tombstone is left.
        let archived = room_archive(&mut alice, "home").await?;
        let gone = archived
            .iter()
            .find(|m| m.attr("from") == Some(&occ("home", "bob")) && !m.has_child("retract", ns::RETRACT))
            .expect("tombstone");
        assert!(!gone.has_child("body", ns::CLIENT), "{gone}");
        assert!(gone.has_child("retracted", ns::RETRACT), "{gone}");
    }
    s.restart().await?;
    let mut carol = s.online("carol", "password", "phone").await?;
    let to = occ("home", "carol");
    carol.send(&join_presence(&to)).await?;
    carol.expect(|e| e.name() == "presence" && e.attr("from") == Some(&to) && codes(e).contains(&110)).await?;
    let next = next_message(&mut carol).await?;
    assert!(next.has_child("subject", ns::CLIENT), "nothing in the history after a restart: {next}");
    Ok(())
}

#[tokio::test]
async fn moderated_messages_leave_only_a_tombstone_in_the_archive() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    let mut bob = person(&s, "bob").await?;
    make_room(&mut alice, "tea", "alice").await?;
    join(&mut bob, &occ("tea", "bob")).await?;
    bob.send(&groupchat("tea", "something rude")).await?;
    let m = expect_body(&mut alice, &occ("tea", "bob"), "something rude").await?;
    let moderate = Element::new("moderate", "urn:xmpp:message-moderate:1")
        .attr_set("id", sid_of(&m))
        .child(Element::new("retract", ns::RETRACT))
        .text_child("reason", "urn:xmpp:message-moderate:1", "Be nice");
    let r = alice.iq_set(Some(&room("tea")), moderate).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let archived = room_archive(&mut bob, "tea").await?;
    assert!(archived.iter().all(|m| m.child_text("body", ns::CLIENT).as_deref() != Some("something rude")), "{archived:?}");
    let t = archived.iter().find(|m| m.has_child("retracted", ns::RETRACT)).expect("tombstone");
    assert_eq!(t.attr("from"), Some(occ("tea", "bob").as_str()));
    let retracted = t.get_child("retracted", ns::RETRACT).unwrap();
    assert!(retracted.has_child("moderated", "urn:xmpp:message-moderate:1"), "{t}");
    assert_eq!(retracted.child_text("reason", ns::RETRACT).as_deref(), Some("Be nice"));
    Ok(())
}

fn block(jid: &str) -> Element {
    Element::new("block", ns::BLOCKING).child(Element::new("item", ns::BLOCKING).attr_set("jid", jid))
}

#[tokio::test]
async fn people_who_blocked_an_occupant_dont_hear_from_them() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    let mut bob = person(&s, "bob").await?;
    let mut carol = person(&s, "carol").await?;
    make_room(&mut alice, "tea", "alice").await?;
    join(&mut bob, &occ("tea", "bob")).await?;
    join(&mut carol, &occ("tea", "carol")).await?;
    let r = bob.iq_set(None, block(&occ("tea", "alice"))).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");

    alice.send(&groupchat("tea", "from alice")).await?;
    expect_body(&mut alice, &occ("tea", "alice"), "from alice").await?;
    carol.send(&groupchat("tea", "from carol")).await?;
    let next = next_message(&mut bob).await?;
    assert_eq!(next.child_text("body", ns::CLIENT).as_deref(), Some("from carol"), "{next}");

    // Her private messages don't reach him either, and he stays in the room.
    alice.send(&message(&occ("tea", "bob"), "chat", "psst")).await?;
    carol.send(&groupchat("tea", "still here?")).await?;
    let next = next_message(&mut bob).await?;
    assert_eq!(next.child_text("body", ns::CLIENT).as_deref(), Some("still here?"), "{next}");
    Ok(())
}

#[tokio::test]
async fn private_messages_go_to_the_recipients_archive() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    let mut bob = person(&s, "bob").await?;
    make_room(&mut alice, "tea", "alice").await?;
    join(&mut bob, &occ("tea", "bob")).await?;
    alice.send(&message(&occ("tea", "bob"), "chat", "just between us")).await?;
    let got = expect_body(&mut bob, &occ("tea", "alice"), "just between us").await?;
    assert!(got.has_child("x", ns::MUC_USER));
    let sid = got.get_child("stanza-id", ns::SID).expect("archived by bob's server");
    assert_eq!(sid.attr("by"), Some("bob@quark.test"));
    Ok(())
}

#[tokio::test]
async fn sleeping_occupants_are_woken_by_push() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    let mut alice = person(&s, "alice").await?;
    s.add_user("app", "password").await?;
    let mut app = s.login_as("app", "password", "svc").await?;
    let mut bob = person(&s, "bob").await?;
    let enable = Element::new("enable", ns::PUSH).attr_set("jid", "app@quark.test/svc").attr_set("node", "n1");
    let r = bob.iq_set(None, enable).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    make_room(&mut alice, "tea", "alice").await?;
    join(&mut bob, &occ("tea", "bob")).await?;
    bob.send_raw("<enable xmlns='urn:xmpp:sm:3' resume='true'/>").await?;
    bob.expect(|e| e.is("enabled", ns::SM)).await?;
    bob.drop_connection();
    let phone = quark_testkit::quark_core::Jid::parse("bob@quark.test/phone")?;
    for _ in 0..100 {
        if s.srv.sessions.get(&phone).is_some_and(|x| x.flags.lock().hibernating) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    alice.send(&groupchat("tea", "bob, you there?")).await?;
    let iq = app.expect(|e| e.name() == "iq" && e.attr("type") == Some("set") && e.has_child("pubsub", ns::PUBSUB)).await?;
    assert_eq!(iq.attr("from"), Some("bob@quark.test"));
    assert!(!iq.to_xml().contains("you there"), "{iq}");
    Ok(())
}

fn listed(items: &Element) -> Vec<String> {
    items
        .get_child("query", ns::DISCO_ITEMS)
        .map(|q| q.children().filter_map(|i| i.attr("jid").map(String::from)).collect())
        .unwrap_or_default()
}

#[tokio::test]
async fn the_public_listing_follows_rooms_as_they_change() -> anyhow::Result<()> {
    let mut s = TestServer::start().await?;
    s.add_user("alice", "password").await?;
    {
        let mut alice = s.online("alice", "password", "phone").await?;
        make_room(&mut alice, "club", "alice").await?;
        configure(&mut alice, "club", &[("muc#roomconfig_persistentroom", "1")]).await?;
        let items = alice.iq_get(Some(ROOMS), Element::new("query", ns::DISCO_ITEMS)).await?;
        assert!(listed(&items).contains(&room("club")), "{items}");
        configure(&mut alice, "club", &[("muc#roomconfig_publicroom", "0")]).await?;
        let items = alice.iq_get(Some(ROOMS), Element::new("query", ns::DISCO_ITEMS)).await?;
        assert!(!listed(&items).contains(&room("club")), "{items}");
        configure(&mut alice, "club", &[("muc#roomconfig_publicroom", "1"), ("muc#roomconfig_roomname", "The Club")]).await?;
    }
    // Read back from storage, as it was last saved.
    s.restart().await?;
    let mut alice = s.online("alice", "password", "phone").await?;
    let items = alice.iq_get(Some(ROOMS), Element::new("query", ns::DISCO_ITEMS)).await?;
    assert!(items.to_xml().contains("The Club"), "{items}");
    join(&mut alice, &occ("club", "alice")).await?;
    let destroy = Element::new("query", MUC_OWNER).child(Element::new("destroy", MUC_OWNER));
    let r = alice.iq_set(Some(&room("club")), destroy).await?;
    assert_eq!(r.attr("type"), Some("result"), "{r}");
    let items = alice.iq_get(Some(ROOMS), Element::new("query", ns::DISCO_ITEMS)).await?;
    assert!(!listed(&items).contains(&room("club")), "{items}");
    Ok(())
}
