//! One room's state and the XEP-0045 rules that change it: occupants (several devices may share
//! a nickname), roles and affiliations, presence broadcasts with their status codes, messages,
//! history and subject. Everything here is synchronous and does no I/O: handlers fill an
//! [`Out`] with stanzas and storage changes, and the service delivers and saves them.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use quark_core::{ns, Condition, Element, ErrorType, Jid, StanzaError};
use sha2::Digest;

use super::config::{AllowPm, Config};
use super::store::{AffRow, HistRow, Op, RoomRow, Snapshot};

pub const MSG_MODERATE_0: &str = "urn:xmpp:message-moderate:0";
pub const MSG_MODERATE_1: &str = "urn:xmpp:message-moderate:1";
pub const RETRACT_0: &str = "urn:xmpp:message-retract:0";
pub const FASTEN: &str = "urn:xmpp:fasten:0";
pub const REACTIONS: &str = "urn:xmpp:reactions:0";
const OMEMO_2: &str = "urn:xmpp:omemo:2";
/// XEP-0317: hats are the room's to hand out, and this one hands out none.
const HATS: &str = "urn:xmpp:hats:0";

/// Devices one person can join with under the same nickname.
const MAX_SESSIONS: usize = 20;
const MAX_NICK_CHARS: usize = 100;
const MAX_SUBJECT_BYTES: usize = 4096;
/// The join history never holds more than this, whatever the messages' sizes.
const MAX_HISTORY_BYTES: usize = 512 * 1024;
/// Messages (and presence changes) an occupant can send in a burst, and refilled per second.
const BURST: f32 = 20.0;
const REFILL_PER_SEC: f32 = 4.0;
/// IQs relayed between occupants that wait for an answer.
const MAX_PENDING_IQS: usize = 256;
const PENDING_IQ_TTL: Duration = Duration::from_secs(60);
const VOICE_REQUEST_EVERY: Duration = Duration::from_secs(60);
pub const MAX_ITEMS_PER_REQUEST: usize = 100;
/// Affiliations other than bans a room can hold (members, admins, owners).
const MAX_AFFILIATIONS: usize = 10_000;
/// Bans a room can hold, counted apart so that a full member list never stops a ban.
const MAX_BANS: usize = 10_000;
/// Above this many affiliations other than bans, only admins add more: people registering
/// themselves or members inviting others can't fill the room's list.
const MAX_SELF_SERVICE: usize = 5_000;
const MAX_INVITES_PER_MESSAGE: usize = 10;
/// The text of an invitation's or a decline's reason.
const MAX_REASON_BYTES: usize = 1024;
/// Invitations remembered so the invitee can decline them, and for how long.
const MAX_PENDING_INVITES: usize = 1_000;
const INVITE_TTL: Duration = Duration::from_secs(24 * 3600);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Affiliation {
    Outcast,
    None,
    Member,
    Admin,
    Owner,
}

impl Affiliation {
    pub fn as_str(self) -> &'static str {
        match self {
            Affiliation::Owner => "owner",
            Affiliation::Admin => "admin",
            Affiliation::Member => "member",
            Affiliation::None => "none",
            Affiliation::Outcast => "outcast",
        }
    }
    pub fn parse(s: &str) -> Option<Affiliation> {
        Some(match s {
            "owner" => Affiliation::Owner,
            "admin" => Affiliation::Admin,
            "member" => Affiliation::Member,
            "none" => Affiliation::None,
            "outcast" => Affiliation::Outcast,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    None,
    Visitor,
    Participant,
    Moderator,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Moderator => "moderator",
            Role::Participant => "participant",
            Role::Visitor => "visitor",
            Role::None => "none",
        }
    }
    pub fn parse(s: &str) -> Option<Role> {
        Some(match s {
            "moderator" => Role::Moderator,
            "participant" => Role::Participant,
            "visitor" => Role::Visitor,
            "none" => Role::None,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AffEntry {
    pub affiliation: Affiliation,
    pub reason: Option<String>,
    /// Registered with the room (reserved for this person).
    pub nick: Option<String>,
    pub last_nick: Option<String>,
}

/// One device in the room.
#[derive(Debug, Clone)]
pub struct Session {
    pub jid: Jid,
    /// The presence it last sent (what others see while it's the newest device).
    pub presence: Element,
}

#[derive(Debug)]
struct Bucket {
    tokens: f32,
    at: Instant,
}

impl Bucket {
    fn new() -> Bucket {
        Bucket { tokens: BURST, at: Instant::now() }
    }
    fn take(&mut self) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f32() * REFILL_PER_SEC).min(BURST);
        self.at = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct Occupant {
    pub nick: String,
    pub bare: Jid,
    pub role: Role,
    /// XEP-0421: stable per person and room, revealing nothing about the address.
    pub id: String,
    /// Oldest first; the last one is what others see.
    pub sessions: Vec<Session>,
    /// A server admin (treated as an owner).
    pub admin: bool,
    bucket: Bucket,
    voice_asked: Option<Instant>,
}

impl Occupant {
    pub fn primary(&self) -> Option<&Session> {
        self.sessions.last()
    }
}

#[derive(Debug, Clone)]
pub struct HistoryItem {
    /// As broadcast, without `to`.
    pub msg: Element,
    pub stamp: i64,
    pub sid: String,
    pub sender: Jid,
    bytes: usize,
}

#[derive(Debug, Clone)]
pub struct Subject {
    pub text: String,
    pub nick: Option<String>,
    pub at: i64,
}

#[derive(Debug)]
struct Proxied {
    requester: Jid,
    id: String,
    target: Jid,
    from_nick: String,
    at: Instant,
}

/// What handling a stanza produced.
#[derive(Debug, Default)]
pub struct Out {
    /// For people in the room (or asking it something), delivered in order.
    pub send: Vec<Element>,
    /// Invitations, declines and private messages: routed like any message to a person, so
    /// they're stored for people who are offline, archived, pushed to sleeping phones and kept
    /// from people who blocked the sender.
    pub route: Vec<Element>,
    pub db: Vec<Op>,
    /// The room is gone: destroyed, or temporary and empty.
    pub closed: bool,
    pub delete_archive: bool,
}

/// A groupchat message checked and ready to go out once it has its stanza id.
#[derive(Debug)]
pub struct Prepared {
    pub msg: Element,
    pub sender: Jid,
    /// Goes to the room's archive (and gets a stanza id).
    pub archive: bool,
    /// Shown to people joining later.
    pub history: bool,
    pub subject: Option<String>,
    pub nick: Option<String>,
    /// XEP-0424: the stanza id of the sender's own message this takes back.
    pub retracts: Option<String>,
    /// What replaces a message in the room's archive once this went out.
    pub tombstone: Option<Tombstone>,
}

/// A message to replace in the room's archive with what's left of it (XEP-0424, XEP-0425):
/// who sent it and when, and how it went, nothing of what it said.
#[derive(Debug, Clone)]
pub struct Tombstone {
    pub sid: String,
    /// Elements saying how the message went (`<retracted/>` and the like).
    pub marks: Vec<Element>,
    /// Only replaced when the archived message has this occupant id: people retract only
    /// their own messages, and the archive reaches further back than the join history.
    pub sender_id: Option<String>,
}

impl Tombstone {
    /// The archived message `original` as its tombstone, or None when it isn't one this
    /// tombstone may replace.
    pub fn apply(&self, original: &Element) -> Option<Element> {
        let oid = original.get_child("occupant-id", ns::OCCUPANT_ID);
        if let Some(want) = &self.sender_id {
            if oid.and_then(|o| o.attr("id")) != Some(want.as_str()) {
                return None;
            }
        }
        let mut t = Element::new("message", ns::CLIENT);
        for a in ["from", "type", "id"] {
            t.set_attr_opt(a, original.attr(a));
        }
        for m in &self.marks {
            t.append(m.clone());
        }
        if let Some(o) = oid {
            t.append(o.clone());
        }
        Some(t)
    }
}

/// A join request.
pub struct Join<'a> {
    pub from: &'a Jid,
    pub nick: &'a str,
    pub presence: &'a Element,
    /// A server admin.
    pub admin: bool,
    /// The room was just made by this join.
    pub created: bool,
    pub now: i64,
}

fn err(c: Condition, text: &str) -> StanzaError {
    StanzaError::new(c).with_text(text)
}

/// XEP-0421 occupant id: a salted hash of the real bare JID.
pub fn occupant_id(salt: &str, bare: &Jid) -> String {
    let mut h = sha2::Sha256::new();
    h.update(salt.as_bytes());
    h.update([0]);
    h.update(bare.to_string().as_bytes());
    hex::encode(&h.finalize()[..16])
}

/// What a client puts in its presence that the room replaces with its own.
fn room_owned(e: &Element) -> bool {
    e.ns() == ns::MUC || e.ns() == ns::MUC_USER || e.is("occupant-id", ns::OCCUPANT_ID) || e.ns() == HATS
}

fn default_role(aff: Affiliation, moderated: bool) -> Role {
    match aff {
        Affiliation::Owner | Affiliation::Admin => Role::Moderator,
        Affiliation::Member => Role::Participant,
        Affiliation::None if moderated => Role::Visitor,
        Affiliation::None => Role::Participant,
        Affiliation::Outcast => Role::None,
    }
}

/// Who may change a role (XEP-0045 §8, §9.7).
pub fn check_role_change(
    actor_aff: Affiliation,
    actor_role: Role,
    target_aff: Affiliation,
    target_role: Role,
    new: Role,
) -> Result<(), StanzaError> {
    if actor_role != Role::Moderator && actor_aff < Affiliation::Admin {
        return Err(err(Condition::Forbidden, "Only moderators can do that."));
    }
    if (new == Role::Moderator || target_role == Role::Moderator) && actor_aff < Affiliation::Admin && new != target_role {
        return Err(err(Condition::Forbidden, "Only admins and owners can make or unmake moderators."));
    }
    if target_aff >= Affiliation::Admin && new < Role::Moderator {
        return Err(err(Condition::NotAllowed, "Admins and owners can't be kicked or silenced; change their affiliation first."));
    }
    // §8.2, §8.4: nobody kicks or silences someone whose affiliation is at or above their own.
    // People without one are the exception: a moderator who has no affiliation either still
    // has to be able to deal with strangers, who are what moderation is for.
    if new < target_role && target_aff > Affiliation::None && target_aff >= actor_aff {
        return Err(err(Condition::NotAllowed, "You can't kick or silence someone whose affiliation is at or above yours."));
    }
    Ok(())
}

/// Who may change an affiliation (XEP-0045 §9, §10).
pub fn check_affiliation_change(actor_aff: Affiliation, old: Affiliation, new: Affiliation) -> Result<(), StanzaError> {
    if actor_aff < Affiliation::Admin {
        return Err(err(Condition::Forbidden, "Only admins and owners can change who's a member."));
    }
    if (new >= Affiliation::Admin || old >= Affiliation::Admin) && actor_aff < Affiliation::Owner {
        return Err(err(Condition::Forbidden, "Only owners can change who's an admin or owner."));
    }
    Ok(())
}

/// The `<history/>` limits a joining client asked for (XEP-0045 §7.2.15).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HistoryLimits {
    pub max_stanzas: Option<usize>,
    pub max_chars: Option<usize>,
    pub since: Option<i64>,
}

impl HistoryLimits {
    pub fn parse(h: Option<&Element>, now: i64) -> HistoryLimits {
        let Some(h) = h else { return HistoryLimits::default() };
        let num = |k: &str| h.attr(k).and_then(|v| v.trim().parse::<u64>().ok());
        let mut since = h.attr("since").and_then(quark_core::time::parse_xep82);
        if let Some(s) = num("seconds") {
            let t = now.saturating_sub(i64::try_from(s.saturating_mul(1000)).unwrap_or(i64::MAX));
            since = Some(since.map_or(t, |x| x.max(t)));
        }
        HistoryLimits {
            max_stanzas: num("maxstanzas").map(|n| usize::try_from(n).unwrap_or(usize::MAX)),
            max_chars: num("maxchars").map(|n| usize::try_from(n).unwrap_or(usize::MAX)),
            since,
        }
    }
}

/// A room's state.
pub struct Room {
    pub jid: Jid,
    pub config: Config,
    pub affiliations: HashMap<Jid, AffEntry>,
    occupants: HashMap<String, Occupant>,
    /// Real full JID → nickname.
    by_session: HashMap<Jid, String>,
    history: VecDeque<HistoryItem>,
    history_bytes: usize,
    pub subject: Option<Subject>,
    /// Created and not configured yet: only owners get in (XEP-0045 §10.1.1).
    pub locked_since: Option<Instant>,
    pub salt: String,
    pub created: i64,
    pub creator: Option<Jid>,
    pub vcard: Option<String>,
    pub avatar_hash: Option<String>,
    pending: HashMap<String, Proxied>,
    /// Invitee (bare) → who invited them and when, so only someone invited can decline.
    invited: HashMap<Jid, (Jid, Instant)>,
    /// Messages are archived: the room's setting and the domain's history setting both allow it.
    pub logging: bool,
    /// When the last person left (for unloading idle persistent rooms).
    pub empty_since: Option<Instant>,
    pub destroyed: bool,
}

impl Room {
    pub fn new(jid: Jid, config: Config, creator: Option<Jid>, now: i64) -> Room {
        Room {
            jid,
            config,
            affiliations: HashMap::new(),
            occupants: HashMap::new(),
            by_session: HashMap::new(),
            history: VecDeque::new(),
            history_bytes: 0,
            subject: None,
            locked_since: None,
            salt: hex::encode(rand::random::<[u8; 16]>()),
            created: now,
            creator,
            vcard: None,
            avatar_hash: None,
            pending: HashMap::new(),
            invited: HashMap::new(),
            logging: false,
            empty_since: Some(Instant::now()),
            destroyed: false,
        }
    }

    /// A persistent room read back from storage.
    pub fn from_snapshot(jid: Jid, s: Snapshot) -> Room {
        let config = serde_json::from_str(&s.row.config).unwrap_or_else(|e| {
            tracing::warn!(room = %jid, error = %e, "unreadable room configuration; using defaults");
            Config::default()
        });
        let mut r = Room::new(jid, config, s.row.creator.as_deref().and_then(|c| Jid::parse(c).ok()), s.row.created);
        r.config.persistent = true;
        r.salt = s.row.salt;
        r.subject = s.row.subject.map(|text| Subject { text, nick: s.row.subject_nick, at: s.row.subject_at.unwrap_or(0) });
        r.set_vcard_inner(s.row.vcard);
        for a in s.affiliations {
            if let Ok(j) = Jid::parse(&a.jid) {
                r.affiliations.insert(j, AffEntry { affiliation: a.affiliation, reason: a.reason, nick: a.nick, last_nick: a.last_nick });
            }
        }
        for h in s.history {
            let (Ok(msg), Ok(sender)) = (Element::parse(&h.xml), Jid::parse(&h.sender)) else { continue };
            r.push_history(HistoryItem { bytes: h.xml.len(), msg, stamp: h.stamp, sid: h.sid, sender });
        }
        r
    }

    pub fn row(&self) -> RoomRow {
        RoomRow {
            config: serde_json::to_string(&self.config).unwrap_or_else(|_| "{}".into()),
            subject: self.subject.as_ref().map(|s| s.text.clone()),
            subject_nick: self.subject.as_ref().and_then(|s| s.nick.clone()),
            subject_at: self.subject.as_ref().map(|s| s.at),
            salt: self.salt.clone(),
            creator: self.creator.as_ref().map(Jid::to_string),
            created: self.created,
            vcard: self.vcard.clone(),
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            row: self.row(),
            affiliations: self.affiliations.iter().map(|(j, a)| aff_row(j, a)).collect(),
            history: self
                .history
                .iter()
                .map(|h| HistRow { stamp: h.stamp, sid: h.sid.clone(), sender: h.sender.to_string(), xml: h.msg.to_xml() })
                .collect(),
        }
    }

    /// Saves the room row if the room is persistent.
    fn save(&self, out: &mut Out) {
        if self.config.persistent {
            out.db.push(Op::Room(Box::new(self.row())));
        }
    }

    fn save_affiliation(&self, bare: &Jid, out: &mut Out) {
        if !self.config.persistent {
            return;
        }
        let row = match self.affiliations.get(bare) {
            Some(a) => aff_row(bare, a),
            None => AffRow { jid: bare.to_string(), affiliation: Affiliation::None, reason: None, nick: None, last_nick: None },
        };
        out.db.push(Op::Affiliation(row));
    }

    pub fn occupant_count(&self) -> usize {
        self.occupants.len()
    }

    pub fn is_empty(&self) -> bool {
        self.occupants.is_empty()
    }

    pub fn occupants(&self) -> impl Iterator<Item = &Occupant> {
        self.occupants.values()
    }

    pub fn occupant(&self, nick: &str) -> Option<&Occupant> {
        self.occupants.get(nick)
    }

    /// The occupant a real full JID is in the room as.
    pub fn occupant_of(&self, real: &Jid) -> Option<&Occupant> {
        self.occupants.get(self.by_session.get(real)?)
    }

    pub fn nick_of(&self, real: &Jid) -> Option<&str> {
        self.by_session.get(real).map(String::as_str)
    }

    /// The affiliation a person has; server admins count as owners.
    pub fn aff(&self, bare: &Jid, admin: bool) -> Affiliation {
        if admin {
            return Affiliation::Owner;
        }
        self.affiliations.get(bare).map_or(Affiliation::None, |a| a.affiliation)
    }

    fn occ_aff(&self, o: &Occupant) -> Affiliation {
        self.aff(&o.bare, o.admin)
    }

    /// The role of whoever sent something from `real` (none when they aren't in the room).
    pub fn role_of(&self, real: &Jid) -> Role {
        self.occupant_of(real).map_or(Role::None, |o| o.role)
    }

    fn occ_jid(&self, nick: &str) -> Jid {
        self.jid.with_resource(nick).unwrap_or_else(|_| self.jid.clone())
    }

    fn reserved_by_other(&self, nick: &str, bare: &Jid) -> bool {
        self.affiliations.iter().any(|(j, a)| j != bare && a.nick.as_deref() == Some(nick))
    }

    pub fn owners(&self) -> Vec<String> {
        self.with_affiliation(Affiliation::Owner)
    }

    pub fn with_affiliation(&self, aff: Affiliation) -> Vec<String> {
        let mut v: Vec<String> = self.affiliations.iter().filter(|(_, a)| a.affiliation == aff).map(|(j, _)| j.to_string()).collect();
        v.sort();
        v
    }

    /// Affiliations other than bans, and bans (each has its own limit).
    fn affiliation_counts(&self) -> (usize, usize) {
        let bans = self.affiliations.values().filter(|a| a.affiliation == Affiliation::Outcast).count();
        (self.affiliations.len() - bans, bans)
    }

    // ---------------------------------------------------------------- presence

    fn item(aff: Affiliation, role: Role, jid: Option<&Jid>) -> Element {
        Element::new("item", ns::MUC_USER)
            .attr_set("affiliation", aff.as_str())
            .attr_set("role", role.as_str())
            .attr_opt("jid", jid.map(Jid::to_string))
    }

    /// `presence` from `nick` built on `base`'s content (show, status, caps, avatar…).
    fn presence_el(&self, nick: &str, base: Option<&Element>, unavailable: bool, x: Element, oid: &str) -> Element {
        let mut p = Element::new("presence", ns::CLIENT).attr_set("from", self.occ_jid(nick).to_string());
        if unavailable {
            p.set_attr("type", "unavailable");
        }
        if let Some(b) = base {
            for c in b.children().filter(|c| !room_owned(c)) {
                p.append(c.clone());
            }
        }
        p.append(x);
        p.append(Element::new("occupant-id", ns::OCCUPANT_ID).attr_set("id", oid));
        p
    }

    /// Sends `o`'s presence: to the other occupants (with the real JID for those allowed to see
    /// it), and with status 110 to `own` (the occupant's own devices that should hear it).
    fn send_presence(&self, o: &Occupant, spec: &Spec<'_>, own: &[&Jid], others: bool, out: &mut Out) {
        let (aff, role) = spec.item.unwrap_or((self.occ_aff(o), o.role));
        let base = spec.base.or_else(|| o.primary().map(|s| &s.presence));
        let real = o.primary().map(|s| &s.jid);
        let x = |jid: Option<&Jid>, own: bool| {
            let mut item = Self::item(aff, role, jid).attr_opt("nick", spec.new_nick);
            if let Some(a) = spec.actor {
                item.append(Element::new("actor", ns::MUC_USER).attr_set("nick", a));
            }
            if let Some(r) = spec.reason {
                item.append(Element::new("reason", ns::MUC_USER).text(r));
            }
            let mut x = Element::new("x", ns::MUC_USER).child(item);
            let mut codes: Vec<u16> = spec.codes.to_vec();
            if own {
                codes.push(110);
                codes.extend_from_slice(spec.own_codes);
            }
            codes.sort_unstable();
            codes.dedup();
            for c in codes {
                x.append(Element::new("status", ns::MUC_USER).attr_set("code", c.to_string()));
            }
            if let Some(d) = spec.destroy {
                x.append(d.clone());
            }
            x
        };
        if others {
            let open = self.presence_el(&o.nick, base, spec.unavailable, x(None, false), &o.id);
            let full = self.presence_el(&o.nick, base, spec.unavailable, x(real, false), &o.id);
            let anyone = self.config.non_anonymous();
            for other in self.occupants.values().filter(|x| x.nick != o.nick) {
                let p = if anyone || other.role == Role::Moderator { &full } else { &open };
                for s in &other.sessions {
                    let mut p = p.clone();
                    p.set_attr("to", s.jid.to_string());
                    out.send.push(p);
                }
            }
        }
        if !own.is_empty() {
            let mine = self.presence_el(&o.nick, base, spec.unavailable, x(real, true), &o.id);
            for to in own {
                let mut p = mine.clone();
                p.set_attr("to", to.to_string());
                out.send.push(p);
            }
        }
    }

    /// Everyone else's presence, for someone who just joined.
    fn send_roster(&self, to: &Jid, except: &str, out: &mut Out) {
        let viewer_mod = self.occupants.get(except).is_some_and(|o| o.role == Role::Moderator);
        let show_jid = self.config.non_anonymous() || viewer_mod;
        for o in self.occupants.values().filter(|o| o.nick != except) {
            let Some(primary) = o.primary() else { continue };
            let item = Self::item(self.occ_aff(o), o.role, show_jid.then_some(&primary.jid));
            let mut p = self.presence_el(&o.nick, Some(&primary.presence), false, Element::new("x", ns::MUC_USER).child(item), &o.id);
            p.set_attr("to", to.to_string());
            out.send.push(p);
        }
    }

    fn subject_message(&self, to: &Jid) -> Element {
        let from = match self.subject.as_ref().and_then(|s| s.nick.as_deref()) {
            Some(n) => self.occ_jid(n).to_string(),
            None => self.jid.to_string(),
        };
        let text = self.subject.as_ref().map(|s| s.text.as_str()).unwrap_or("");
        Element::new("message", ns::CLIENT)
            .attr_set("type", "groupchat")
            .attr_set("from", from)
            .attr_set("to", to.to_string())
            .attr_set("id", quark_core::new_id())
            .child(Element::new("subject", ns::CLIENT).text(text))
    }

    fn avatar_presence(&self, to: &Jid) -> Option<Element> {
        let hash = self.avatar_hash.as_ref()?;
        Some(
            Element::new("presence", ns::CLIENT)
                .attr_set("from", self.jid.to_string())
                .attr_set("to", to.to_string())
                .child(Element::new("x", ns::VCARD_UPDATE).text_child("photo", ns::VCARD_UPDATE, hash.as_str())),
        )
    }

    /// History a joining device asked for, oldest first.
    pub fn select_history(&self, lim: HistoryLimits) -> Vec<&HistoryItem> {
        let max = lim.max_stanzas.unwrap_or(self.config.history_length as usize).min(self.config.history_length as usize);
        let mut chars = 0usize;
        let mut v = Vec::new();
        for h in self.history.iter().rev() {
            if v.len() >= max || lim.since.is_some_and(|s| h.stamp < s) {
                break;
            }
            if let Some(mc) = lim.max_chars {
                chars += h.bytes;
                if chars > mc {
                    break;
                }
            }
            v.push(h);
        }
        v.reverse();
        v
    }

    fn send_join_state(&self, to: &Jid, lim: HistoryLimits, out: &mut Out) {
        if let Some(p) = self.avatar_presence(to) {
            out.send.push(p);
        }
        let room = self.jid.to_string();
        for h in self.select_history(lim) {
            let mut m = h.msg.clone();
            m.set_attr("to", to.to_string());
            m.append(quark_core::stanza::delay(&room, h.stamp));
            out.send.push(m);
        }
        out.send.push(self.subject_message(to));
    }

    /// Someone enters (XEP-0045 §7.2), or another of their devices joins under the same nick.
    pub fn join(&mut self, j: Join<'_>, out: &mut Out) -> Result<(), StanzaError> {
        let occ_jid = self.jid.with_resource(j.nick).map_err(|_| err(Condition::JidMalformed, "That nickname can't be used."))?;
        let nick = occ_jid.resource().unwrap_or_default().to_string();
        if nick.chars().count() > MAX_NICK_CHARS {
            return Err(err(Condition::NotAcceptable, "That nickname is too long."));
        }
        let bare = j.from.to_bare();
        let aff = self.aff(&bare, j.admin);
        if self.locked_since.is_some() && aff != Affiliation::Owner {
            return Err(err(Condition::ItemNotFound, "This group chat is still being set up."));
        }
        if aff == Affiliation::Outcast {
            return Err(err(Condition::Forbidden, "You've been banned from this group chat."));
        }
        if self.config.members_only && aff < Affiliation::Member {
            return Err(err(Condition::RegistrationRequired, "This group chat is for members only."));
        }
        let existing = self.occupants.get(&nick);
        if existing.is_some_and(|o| o.bare != bare) {
            return Err(err(Condition::Conflict, "That nickname is taken."));
        }
        if self.reserved_by_other(&nick, &bare) {
            return Err(err(Condition::Conflict, "That nickname is reserved by someone else."));
        }
        if let Some(pw) = &self.config.password {
            if aff < Affiliation::Admin {
                let given = j.presence.get_child("x", ns::MUC).and_then(|x| x.child_text("password", ns::MUC));
                match given {
                    None => return Err(err(Condition::NotAuthorized, "This group chat needs a password.")),
                    Some(g) if !bool::from(subtle::ConstantTimeEq::ct_eq(g.as_bytes(), pw.as_bytes())) => {
                        return Err(err(Condition::NotAuthorized, "That password is wrong."))
                    }
                    Some(_) => {}
                }
            }
        }
        match existing {
            None if self.occupants.len() >= self.config.max_users as usize && aff < Affiliation::Admin => {
                return Err(err(Condition::ServiceUnavailable, "This group chat is full.").with_type(ErrorType::Wait));
            }
            Some(o) if o.sessions.len() >= MAX_SESSIONS => {
                return Err(err(Condition::ResourceConstraint, "You've joined from too many devices at once."));
            }
            _ => {}
        }

        let lim = HistoryLimits::parse(j.presence.get_child("x", ns::MUC).and_then(|x| x.get_child("history", ns::MUC)), j.now);
        let mut base = j.presence.clone();
        base.remove_children(room_owned);
        let session = Session { jid: j.from.clone(), presence: base };
        self.by_session.insert(j.from.clone(), nick.clone());
        self.empty_since = None;
        let mut own_codes = Vec::new();
        if self.config.non_anonymous() {
            own_codes.push(100);
        }
        if self.logging {
            own_codes.push(170);
        }
        if j.created {
            own_codes.push(201);
        }
        if nick != j.nick {
            own_codes.push(210);
        }
        if let Some(o) = self.occupants.get_mut(&nick) {
            // Another device of someone already here.
            o.sessions.push(session);
        } else {
            let id = occupant_id(&self.salt, &bare);
            let role = default_role(aff, self.config.moderated);
            let admin = j.admin;
            self.occupants.insert(
                nick.clone(),
                Occupant {
                    nick: nick.clone(),
                    bare: bare.clone(),
                    role,
                    id,
                    sessions: vec![session],
                    admin,
                    bucket: Bucket::new(),
                    voice_asked: None,
                },
            );
        }
        if aff >= Affiliation::Member {
            if let Some(a) = self.affiliations.get_mut(&bare) {
                if a.last_nick.as_deref() != Some(&nick) {
                    a.last_nick = Some(nick.clone());
                    self.save_affiliation(&bare, out);
                }
            }
        }
        self.send_roster(j.from, &nick, out);
        let Some(o) = self.occupants.get(&nick) else { return Ok(()) };
        let others: Vec<&Jid> = o.sessions.iter().filter(|s| s.jid != *j.from).map(|s| &s.jid).collect();
        // Their other devices and everyone else see the newest device's presence; the new one
        // also gets its join codes.
        self.send_presence(o, &Spec { own_codes: &own_codes, ..Spec::default() }, &[j.from], true, out);
        if !others.is_empty() {
            self.send_presence(o, &Spec::default(), &others, false, out);
        }
        self.send_join_state(j.from, lim, out);
        Ok(())
    }

    /// Someone already in the room sent presence to it again: an update, a nickname change, or
    /// a client re-joining after it lost track (it gets the whole room again).
    pub fn presence_from_occupant(
        &mut self,
        from: &Jid,
        nick_req: &str,
        presence: &Element,
        now: i64,
        out: &mut Out,
    ) -> Result<(), StanzaError> {
        let Some(cur) = self.by_session.get(from).cloned() else { return Ok(()) };
        let target = self.jid.with_resource(nick_req).map_err(|_| err(Condition::JidMalformed, "That nickname can't be used."))?;
        let nick = target.resource().unwrap_or_default().to_string();
        if nick != cur {
            return self.change_nick(from, &cur, &nick, presence, out);
        }
        let mut base = presence.clone();
        base.remove_children(room_owned);
        let rejoin = presence.has_child("x", ns::MUC);
        let Some(o) = self.occupants.get_mut(&cur) else { return Ok(()) };
        let allowed = o.bucket.take();
        if let Some(i) = o.sessions.iter().position(|s| s.jid == *from) {
            let mut s = o.sessions.remove(i);
            s.presence = base;
            o.sessions.push(s);
        }
        let Some(o) = self.occupants.get(&cur) else { return Ok(()) };
        if rejoin {
            self.send_roster(from, &cur, out);
            let mut own = Vec::new();
            if self.config.non_anonymous() {
                own.push(100);
            }
            if self.logging {
                own.push(170);
            }
            self.send_presence(o, &Spec { own_codes: &own, ..Spec::default() }, &[from], allowed, out);
            let lim = HistoryLimits::parse(presence.get_child("x", ns::MUC).and_then(|x| x.get_child("history", ns::MUC)), now);
            self.send_join_state(from, lim, out);
        } else if allowed {
            let own: Vec<&Jid> = o.sessions.iter().map(|s| &s.jid).collect();
            self.send_presence(o, &Spec::default(), &own, true, out);
        }
        Ok(())
    }

    fn change_nick(&mut self, from: &Jid, cur: &str, nick: &str, presence: &Element, out: &mut Out) -> Result<(), StanzaError> {
        if nick.chars().count() > MAX_NICK_CHARS {
            return Err(err(Condition::NotAcceptable, "That nickname is too long."));
        }
        let Some(o) = self.occupants.get(cur) else { return Ok(()) };
        let bare = o.bare.clone();
        if self.occupants.get(nick).is_some_and(|t| t.bare != bare) {
            return Err(err(Condition::Conflict, "That nickname is taken."));
        }
        if self.reserved_by_other(nick, &bare) {
            return Err(err(Condition::Conflict, "That nickname is reserved by someone else."));
        }
        let mut base = presence.clone();
        base.remove_children(room_owned);
        let sole = o.sessions.len() == 1 && !self.occupants.contains_key(nick);
        if sole {
            // The classic rename (§7.6): unavailable with 303 from the old nick, then the new one.
            let Some(mut o) = self.occupants.remove(cur) else { return Ok(()) };
            self.send_presence(&o, &Spec { unavailable: true, codes: &[303], new_nick: Some(nick), ..Spec::default() }, &[from], true, out);
            o.nick = nick.to_string();
            if let Some(s) = o.sessions.first_mut() {
                s.presence = base;
            }
            self.by_session.insert(from.clone(), nick.to_string());
            self.send_presence(&o, &Spec::default(), &[from], true, out);
            self.occupants.insert(nick.to_string(), o);
        } else {
            // One device of several moves (or joins another nick of the same person).
            let Some(o) = self.occupants.get_mut(cur) else { return Ok(()) };
            let Some(i) = o.sessions.iter().position(|s| s.jid == *from) else { return Ok(()) };
            let mut s = o.sessions.remove(i);
            s.presence = base;
            let left_empty = o.sessions.is_empty();
            let (role, admin, id) = (o.role, o.admin, o.id.clone());
            let Some(o) = self.occupants.get(cur) else { return Ok(()) };
            self.send_presence(
                o,
                &Spec { unavailable: true, codes: &[303], new_nick: Some(nick), base: Some(&s.presence), ..Spec::default() },
                &[from],
                left_empty,
                out,
            );
            if left_empty {
                self.occupants.remove(cur);
            } else {
                let own: Vec<&Jid> = o.sessions.iter().map(|s| &s.jid).collect();
                self.send_presence(o, &Spec::default(), &own, true, out);
            }
            self.by_session.insert(from.clone(), nick.to_string());
            let o = self.occupants.entry(nick.to_string()).or_insert_with(|| Occupant {
                nick: nick.to_string(),
                bare: bare.clone(),
                role,
                id,
                sessions: Vec::new(),
                admin,
                bucket: Bucket::new(),
                voice_asked: None,
            });
            o.sessions.push(s);
            let Some(o) = self.occupants.get(nick) else { return Ok(()) };
            let own: Vec<&Jid> = o.sessions.iter().map(|s| &s.jid).collect();
            self.send_presence(o, &Spec::default(), &own, true, out);
        }
        Ok(())
    }

    /// A device leaves (unavailable presence, or its server reported an error with `codes`).
    pub fn leave(&mut self, from: &Jid, presence: Option<&Element>, codes: &[u16], out: &mut Out) {
        let Some(nick) = self.by_session.remove(from) else { return };
        let Some(o) = self.occupants.get_mut(&nick) else { return };
        let Some(i) = o.sessions.iter().position(|s| s.jid == *from) else { return };
        let s = o.sessions.remove(i);
        let base = presence.map(|p| {
            let mut b = p.clone();
            b.remove_children(room_owned);
            b
        });
        if o.sessions.is_empty() {
            if let Some(mut o) = self.occupants.remove(&nick) {
                o.sessions.push(s);
                let item = (self.occ_aff(&o), Role::None);
                self.send_presence(
                    &o,
                    &Spec { unavailable: true, codes, base: base.as_ref(), item: Some(item), ..Spec::default() },
                    &[from],
                    true,
                    out,
                );
            }
        } else {
            let Some(o) = self.occupants.get(&nick) else { return };
            // The device that left hears it left; everyone else sees the remaining device.
            let item = (self.occ_aff(o), Role::None);
            let spec = Spec { unavailable: true, codes, base: base.as_ref().or(Some(&s.presence)), item: Some(item), ..Spec::default() };
            self.send_presence(o, &spec, &[from], false, out);
            let own: Vec<&Jid> = o.sessions.iter().map(|s| &s.jid).collect();
            self.send_presence(o, &Spec::default(), &own, true, out);
        }
        self.after_leave(out);
    }

    fn after_leave(&mut self, out: &mut Out) {
        if self.occupants.is_empty() {
            self.empty_since = Some(Instant::now());
            if !self.config.persistent || self.locked_since.is_some() {
                self.close(out);
            }
        }
    }

    fn close(&mut self, out: &mut Out) {
        out.closed = true;
        self.destroyed = true;
        if self.logging || self.config.archive {
            out.delete_archive = true;
        }
    }

    /// Removes a whole occupant (kick, ban, membership change), telling everyone why.
    fn remove_occupant(&mut self, nick: &str, codes: &[u16], actor: Option<&str>, reason: Option<&str>, out: &mut Out) {
        let Some(o) = self.occupants.remove(nick) else { return };
        for s in &o.sessions {
            self.by_session.remove(&s.jid);
        }
        let own: Vec<&Jid> = o.sessions.iter().map(|s| &s.jid).collect();
        let item = (self.occ_aff(&o), Role::None);
        self.send_presence(&o, &Spec { unavailable: true, codes, actor, reason, item: Some(item), ..Spec::default() }, &own, true, out);
        self.after_leave(out);
    }

    /// Broadcasts an occupant's presence after its role or affiliation changed. A new moderator
    /// of a semi-anonymous room gets everyone's presence again, now with their addresses.
    fn announce(&self, nick: &str, actor: Option<&str>, reason: Option<&str>, was: Role, out: &mut Out) {
        let Some(o) = self.occupants.get(nick) else { return };
        let own: Vec<&Jid> = o.sessions.iter().map(|s| &s.jid).collect();
        self.send_presence(o, &Spec { actor, reason, ..Spec::default() }, &own, true, out);
        if o.role == Role::Moderator && was != Role::Moderator && !self.config.non_anonymous() {
            for s in &o.sessions {
                self.send_roster(&s.jid, nick, out);
            }
        }
    }

    /// Everyone leaves because the service is going away (status 332).
    pub fn shut_down(&mut self, out: &mut Out) {
        let nicks: Vec<String> = self.occupants.keys().cloned().collect();
        for n in nicks {
            self.remove_occupant(&n, &[332], None, None, out);
        }
        out.closed = true;
    }

    /// Ends the room (XEP-0045 §10.9): everyone is told, with an optional new place to go.
    pub fn destroy(&mut self, alternate: Option<&str>, reason: Option<&str>, out: &mut Out) {
        let mut d = Element::new("destroy", ns::MUC_USER).attr_opt("jid", alternate);
        if let Some(r) = reason {
            d.append(Element::new("reason", ns::MUC_USER).text(r));
        }
        let all: Vec<Occupant> = self.occupants.drain().map(|(_, o)| o).collect();
        self.by_session.clear();
        for o in &all {
            let own: Vec<&Jid> = o.sessions.iter().map(|s| &s.jid).collect();
            self.send_presence(
                o,
                &Spec { unavailable: true, destroy: Some(&d), item: Some((Affiliation::None, Role::None)), ..Spec::default() },
                &own,
                false,
                out,
            );
        }
        if self.config.persistent {
            out.db.push(Op::Delete);
        }
        self.close(out);
    }

    // ---------------------------------------------------------------- messages

    /// Checks a groupchat message from an occupant and turns it into what the room sends.
    pub fn prepare_message(&mut self, from: &Jid, msg: &Element) -> Result<Option<Prepared>, StanzaError> {
        let room = self.jid.to_string();
        let change_subject = self.config.change_subject;
        let Some(nick) = self.by_session.get(from).cloned() else {
            return Err(err(Condition::NotAcceptable, "You need to join this group chat before sending messages."));
        };
        let Some(o) = self.occupants.get_mut(&nick) else { return Ok(None) };
        let subject = msg.child_text("subject", ns::CLIENT);
        let has_body = msg.has_child("body", ns::CLIENT);
        let is_subject = subject.is_some() && !has_body;
        if o.role < Role::Participant {
            if !has_body && !is_subject && !msg.has_child("encrypted", ns::OMEMO) {
                // Chat states from visitors: nothing to say, nothing to refuse.
                return Ok(None);
            }
            return Err(err(Condition::Forbidden, "You need a voice to talk in this group chat."));
        }
        if !o.bucket.take() {
            return Err(err(Condition::ResourceConstraint, "You're sending messages too fast; wait a moment.").with_type(ErrorType::Wait));
        }
        if is_subject && !(change_subject || o.role == Role::Moderator) {
            return Err(err(Condition::Forbidden, "Only moderators can change the subject here."));
        }
        if subject.as_ref().is_some_and(|s| s.len() > MAX_SUBJECT_BYTES) {
            return Err(err(Condition::NotAcceptable, "That subject is too long."));
        }
        let oid = o.id.clone();
        let sender = o.bare.clone();
        let mut m = msg.clone();
        m.set_attr("from", self.occ_jid(&nick).to_string());
        m.remove_attr("to");
        m.set_attr("type", "groupchat");
        m.remove_children(|c| room_owned(c) || (c.is("stanza-id", ns::SID) && c.attr("by") == Some(&room)) || c.is("delay", ns::DELAY));
        m.append(Element::new("occupant-id", ns::OCCUPANT_ID).attr_set("id", oid.as_str()));
        let no_store = msg.has_child("no-store", ns::HINTS) || msg.has_child("no-permanent-store", ns::HINTS);
        let retract = msg.get_child("retract", ns::RETRACT).and_then(|r| r.attr("id")).map(str::to_string);
        let archive = !no_store
            && (has_body
                || is_subject
                || retract.is_some()
                || msg.has_child("encrypted", ns::OMEMO)
                || msg.has_child("encrypted", OMEMO_2)
                || msg.has_child("reactions", REACTIONS)
                || msg.has_child("apply-to", FASTEN)
                || msg.has_child("store", ns::HINTS));
        // XEP-0424 §6: the archive keeps that the sender took the message back, not what it said.
        let tombstone = retract.as_ref().filter(|_| archive).map(|id| Tombstone {
            sid: id.clone(),
            marks: vec![Element::new("retracted", ns::RETRACT).attr_set("stamp", quark_core::time::xep82(quark_core::time::now_ms()))],
            sender_id: Some(oid.clone()),
        });
        let history = archive && !is_subject && !msg.has_child("retract", ns::RETRACT) && !msg.has_child("apply-to", FASTEN);
        Ok(Some(Prepared {
            msg: m,
            sender,
            archive,
            history,
            subject: is_subject.then(|| subject.unwrap_or_default()),
            nick: Some(nick),
            retracts: retract,
            tombstone,
        }))
    }

    /// A message from the server under `nick`, with nobody joined as that nick (Gluon alerts).
    pub fn prepare_post(&self, nick: &str, body: &str) -> Result<Prepared, StanzaError> {
        let from = self.jid.with_resource(nick).map_err(|_| err(Condition::JidMalformed, "That nickname can't be used."))?;
        let msg = Element::new("message", ns::CLIENT)
            .attr_set("from", from.to_string())
            .attr_set("type", "groupchat")
            .attr_set("id", quark_core::new_id())
            .text_child("body", ns::CLIENT, body)
            .child(Element::new("occupant-id", ns::OCCUPANT_ID).attr_set("id", occupant_id(&self.salt, &self.jid)));
        Ok(Prepared {
            msg,
            sender: self.jid.clone(),
            archive: true,
            history: true,
            subject: None,
            nick: Some(nick.to_string()),
            retracts: None,
            tombstone: None,
        })
    }

    /// Sends a prepared message to everyone, with its stanza id, and keeps it for people joining.
    pub fn commit_message(&mut self, mut p: Prepared, sid: Option<String>, now: i64, out: &mut Out) {
        if let Some(sid) = &sid {
            p.msg.append(Element::new("stanza-id", ns::SID).attr_set("id", sid.as_str()).attr_set("by", self.jid.to_string()));
        }
        for o in self.occupants.values() {
            for s in &o.sessions {
                let mut m = p.msg.clone();
                m.set_attr("to", s.jid.to_string());
                out.send.push(m);
            }
        }
        if let Some(text) = p.subject.take() {
            self.subject = Some(Subject { text, nick: p.nick.clone(), at: now });
            self.save(out);
        }
        if let Some(id) = &p.retracts {
            // XEP-0424: the sender takes back their own message; people joining later won't
            // see it, here or after the room was read back from storage.
            if let Some(i) = self.history.iter().position(|h| h.sid == *id && h.sender == p.sender) {
                if let Some(h) = self.history.remove(i) {
                    self.history_bytes -= h.bytes;
                }
                if self.config.persistent {
                    out.db.push(Op::Unhistory { sid: id.clone() });
                }
            }
        }
        if p.history && self.config.history_length > 0 {
            let sid = sid.unwrap_or_else(quark_core::new_id);
            let xml = p.msg.to_xml();
            if self.config.persistent {
                out.db.push(Op::History {
                    row: HistRow { stamp: now, sid: sid.clone(), sender: p.sender.to_string(), xml: xml.clone() },
                    keep: self.config.history_length,
                });
            }
            self.push_history(HistoryItem { msg: p.msg, stamp: now, sid, sender: p.sender, bytes: xml.len() });
        }
    }

    fn push_history(&mut self, h: HistoryItem) {
        self.history_bytes += h.bytes;
        self.history.push_back(h);
        let keep = (self.config.history_length as usize).max(1);
        while self.history.len() > keep || (self.history_bytes > MAX_HISTORY_BYTES && self.history.len() > 1) {
            if let Some(old) = self.history.pop_front() {
                self.history_bytes -= old.bytes;
            }
        }
    }

    /// A private message to `nick` (XEP-0045 §7.5).
    pub fn private_message(&mut self, from: &Jid, nick: &str, msg: &Element, out: &mut Out) -> Result<(), StanzaError> {
        let allow = self.config.allow_pm;
        let Some(sender_nick) = self.by_session.get(from).cloned() else {
            return Err(err(Condition::NotAcceptable, "You need to join this group chat to send private messages."));
        };
        let Some(sender) = self.occupants.get_mut(&sender_nick) else { return Ok(()) };
        let allowed = match allow {
            AllowPm::Anyone => true,
            AllowPm::Participants => sender.role >= Role::Participant,
            AllowPm::Moderators => sender.role == Role::Moderator,
            AllowPm::None => false,
        };
        if !allowed {
            return Err(err(Condition::NotAllowed, "Private messages aren't allowed in this group chat."));
        }
        if !sender.bucket.take() {
            return Err(err(Condition::ResourceConstraint, "You're sending messages too fast; wait a moment.").with_type(ErrorType::Wait));
        }
        let oid = sender.id.clone();
        let key = self.jid.with_resource(nick).ok().and_then(|j| j.resource().map(str::to_string)).unwrap_or_default();
        let Some(target) = self.occupants.get(&key) else {
            return Err(err(Condition::ItemNotFound, "There's nobody with that nickname here."));
        };
        let mut m = msg.clone();
        m.set_attr("from", self.occ_jid(&sender_nick).to_string());
        m.remove_children(room_owned);
        m.append(Element::new("x", ns::MUC_USER));
        m.append(Element::new("occupant-id", ns::OCCUPANT_ID).attr_set("id", oid));
        // Routed, not sent straight to the device: it's a message to a person, which their
        // block list, archive and push notifications apply to.
        for s in &target.sessions {
            let mut m = m.clone();
            m.set_attr("to", s.jid.to_string());
            out.route.push(m);
        }
        Ok(())
    }

    /// Mediated invitations (XEP-0045 §7.8.2) and declines (§7.8.3) sent to the room.
    pub fn invitations(&mut self, from: &Jid, admin: bool, x: &Element, out: &mut Out) -> Result<(), StanzaError> {
        let bare = from.to_bare();
        let aff = self.aff(&bare, admin);
        let reason_of = |e: &Element| -> Result<Option<Element>, StanzaError> {
            match e.child_text("reason", ns::MUC_USER) {
                Some(r) if r.len() > MAX_REASON_BYTES => Err(err(Condition::NotAcceptable, "That reason is too long.")),
                // Rebuilt from its text: what a client nests inside isn't passed on.
                r => Ok(r.map(|r| Element::new("reason", ns::MUC_USER).text(r))),
            }
        };
        let now = Instant::now();
        self.invited.retain(|_, (_, at)| now.duration_since(*at) < INVITE_TTL);
        for d in x.children().filter(|c| c.is("decline", ns::MUC_USER)).take(1) {
            // Only someone the room invited can decline, and only once: the decline goes to
            // whoever invited them, so nobody can use the room to message people at will.
            let Some((to, _)) = self.invited.get(&bare).cloned() else {
                return Err(err(Condition::NotAcceptable, "You haven't been invited to this group chat."));
            };
            if d.attr("to").and_then(|t| Jid::parse(t).ok()).is_some_and(|t| t.to_bare() != to) {
                return Err(err(Condition::NotAcceptable, "You weren't invited by that person."));
            }
            let mut dec = Element::new("decline", ns::MUC_USER).attr_set("from", bare.to_string());
            if let Some(r) = reason_of(d)? {
                dec.append(r);
            }
            self.invited.remove(&bare);
            out.route.push(
                Element::new("message", ns::CLIENT)
                    .attr_set("from", self.jid.to_string())
                    .attr_set("to", to.to_string())
                    .attr_set("id", quark_core::new_id())
                    .child(Element::new("x", ns::MUC_USER).child(dec)),
            );
        }
        let invites: Vec<&Element> = x.children().filter(|c| c.is("invite", ns::MUC_USER)).collect();
        if invites.is_empty() {
            return Ok(());
        }
        if invites.len() > MAX_INVITES_PER_MESSAGE {
            return Err(err(Condition::PolicyViolation, "That's too many invitations at once."));
        }
        let inviter_nick = self.by_session.get(from).cloned();
        if inviter_nick.is_none() && aff < Affiliation::Admin {
            return Err(err(Condition::NotAcceptable, "You need to join this group chat to invite people."));
        }
        let may_add = aff >= Affiliation::Admin || self.config.allow_invites;
        if self.config.members_only && !may_add {
            return Err(err(Condition::Forbidden, "Only admins can invite people to this group chat."));
        }
        let mut targets = Vec::new();
        for i in invites {
            let Some(to) = i.attr("to").and_then(|t| Jid::parse(t).ok()) else {
                return Err(err(Condition::JidMalformed, "That invitation doesn't say who it's for."));
            };
            let cont =
                i.get_child("continue", ns::MUC_USER).map(|c| Element::new("continue", ns::MUC_USER).attr_opt("thread", c.attr("thread")));
            targets.push((to, reason_of(i)?, cont));
        }
        // Each invitation costs what a message does, so invitations can't flood people.
        if let Some(o) = inviter_nick.as_ref().and_then(|n| self.occupants.get_mut(n)) {
            if !(0..targets.len()).all(|_| o.bucket.take()) {
                return Err(
                    err(Condition::ResourceConstraint, "You're sending invitations too fast; wait a moment.").with_type(ErrorType::Wait)
                );
            }
        }
        let limit = if aff >= Affiliation::Admin { MAX_AFFILIATIONS } else { MAX_SELF_SERVICE };
        let (mut standing, _) = self.affiliation_counts();
        let name = self.config.name.clone().unwrap_or_else(|| self.jid.to_string());
        for (to, reason, cont) in targets {
            let invitee = to.to_bare();
            if self.config.members_only && self.aff(&invitee, false) == Affiliation::None {
                if standing >= limit {
                    return Err(err(Condition::ResourceConstraint, "This group chat has too many members."));
                }
                standing += 1;
                self.affiliations
                    .insert(invitee.clone(), AffEntry { affiliation: Affiliation::Member, reason: None, nick: None, last_nick: None });
                self.save_affiliation(&invitee, out);
            }
            if self.invited.len() >= MAX_PENDING_INVITES && !self.invited.contains_key(&invitee) {
                if let Some(oldest) = self.invited.iter().min_by_key(|(_, (_, at))| *at).map(|(j, _)| j.clone()) {
                    self.invited.remove(&oldest);
                }
            }
            self.invited.insert(invitee, (bare.clone(), now));
            let mut inv = Element::new("invite", ns::MUC_USER).attr_set("from", bare.to_string());
            if let Some(r) = reason {
                inv.append(r);
            }
            if let Some(c) = cont {
                inv.append(c);
            }
            let mut x = Element::new("x", ns::MUC_USER).child(inv);
            if let Some(pw) = &self.config.password {
                x.append(Element::new("password", ns::MUC_USER).text(pw.as_str()));
            }
            out.route.push(
                Element::new("message", ns::CLIENT)
                    .attr_set("from", self.jid.to_string())
                    .attr_set("to", to.to_string())
                    .attr_set("id", quark_core::new_id())
                    .child(x)
                    .text_child("body", ns::CLIENT, format!("{bare} invites you to {name}: xmpp:{}?join", self.jid)),
            );
        }
        Ok(())
    }

    /// A visitor asks for voice (XEP-0045 §8.6): the request goes to the moderators.
    pub fn voice_request(&mut self, from: &Jid, out: &mut Out) -> Result<(), StanzaError> {
        if !self.config.voice_requests {
            return Err(err(Condition::Forbidden, "Voice requests are turned off in this group chat."));
        }
        let Some(nick) = self.by_session.get(from).cloned() else {
            return Err(err(Condition::NotAcceptable, "You need to join this group chat first."));
        };
        let Some(o) = self.occupants.get_mut(&nick) else { return Ok(()) };
        if o.role != Role::Visitor {
            return Ok(());
        }
        if o.voice_asked.is_some_and(|t| t.elapsed() < VOICE_REQUEST_EVERY) {
            return Err(
                err(Condition::ResourceConstraint, "You've asked already; give the moderators a moment.").with_type(ErrorType::Wait)
            );
        }
        o.voice_asked = Some(Instant::now());
        let real = o.primary().map(|s| s.jid.to_string()).unwrap_or_default();
        let form = crate::modules::forms::Form::new("form", "http://jabber.org/protocol/muc#request")
            .title("Voice request")
            .instructions("To let this person talk, tick \"Grant voice\" and submit. To ignore the request, cancel.")
            .field("muc#role", "text-single", "Requested role", Some("participant"))
            .field("muc#jid", "jid-single", "Address", Some(&real))
            .field("muc#roomnick", "text-single", "Nickname", Some(&nick))
            .boolean("muc#request_allow", "Grant voice", false)
            .build();
        let msg =
            Element::new("message", ns::CLIENT).attr_set("from", self.jid.to_string()).attr_set("id", quark_core::new_id()).child(form);
        for m in self.occupants.values().filter(|o| o.role == Role::Moderator) {
            for s in &m.sessions {
                let mut x = msg.clone();
                x.set_attr("to", s.jid.to_string());
                out.send.push(x);
            }
        }
        Ok(())
    }

    /// A moderator answers a voice request.
    pub fn voice_approval(&mut self, from: &Jid, admin: bool, nick: &str, out: &mut Out) -> Result<(), StanzaError> {
        let actor_aff = self.aff(&from.to_bare(), admin);
        let actor_role = self.role_of(from);
        let actor_nick = self.nick_of(from).map(str::to_string);
        let Some(o) = self.occupants.get(nick) else {
            return Err(err(Condition::ItemNotFound, "There's nobody with that nickname here."));
        };
        check_role_change(actor_aff, actor_role, self.occ_aff(o), o.role, Role::Participant)?;
        if o.role == Role::Visitor {
            if let Some(o) = self.occupants.get_mut(nick) {
                o.role = Role::Participant;
            }
            self.announce(nick, actor_nick.as_deref(), None, Role::Visitor, out);
        }
        Ok(())
    }

    /// Removes a message for everyone (XEP-0425), returning the announcement to send.
    pub fn moderate(&mut self, from: &Jid, admin: bool, sid: &str, reason: Option<&str>, out: &mut Out) -> Result<Prepared, StanzaError> {
        let aff = self.aff(&from.to_bare(), admin);
        let Some(o) = self.occupant_of(from) else {
            return Err(err(Condition::Forbidden, "Only moderators in the group chat can remove messages."));
        };
        if o.role != Role::Moderator && aff < Affiliation::Admin {
            return Err(err(Condition::Forbidden, "Only moderators can remove messages."));
        }
        let by = self.occ_jid(&o.nick).to_string();
        let oid = o.id.clone();
        if let Some(i) = self.history.iter().position(|h| h.sid == sid) {
            if let Some(h) = self.history.remove(i) {
                self.history_bytes -= h.bytes;
            }
            if self.config.persistent {
                out.db.push(Op::Unhistory { sid: sid.to_string() });
            }
        }
        let reason_el = |n: &str| reason.map(|r| Element::new("reason", n).text(r));
        // Both versions of the XEP, so older and newer clients each find theirs.
        let mut v1 = Element::new("retract", ns::RETRACT).attr_set("id", sid).child(
            Element::new("moderated", MSG_MODERATE_1)
                .attr_set("by", by.as_str())
                .child(Element::new("occupant-id", ns::OCCUPANT_ID).attr_set("id", oid.as_str())),
        );
        if let Some(r) = reason_el(ns::RETRACT) {
            v1.append(r);
        }
        let mut moderated0 =
            Element::new("moderated", MSG_MODERATE_0).attr_set("by", by.as_str()).child(Element::new("retract", RETRACT_0));
        if let Some(r) = reason_el(MSG_MODERATE_0) {
            moderated0.append(r);
        }
        let msg = Element::new("message", ns::CLIENT)
            .attr_set("from", self.jid.to_string())
            .attr_set("type", "groupchat")
            .attr_set("id", quark_core::new_id())
            .child(v1)
            .child(Element::new("apply-to", FASTEN).attr_set("id", sid).child(moderated0));
        // What the archive keeps instead (XEP-0425 §5), in both versions too.
        let stamp = quark_core::time::xep82(quark_core::time::now_ms());
        let mut retracted = Element::new("retracted", ns::RETRACT).attr_set("stamp", stamp.as_str()).child(
            Element::new("moderated", MSG_MODERATE_1)
                .attr_set("by", by.as_str())
                .child(Element::new("occupant-id", ns::OCCUPANT_ID).attr_set("id", oid.as_str())),
        );
        if let Some(r) = reason_el(ns::RETRACT) {
            retracted.append(r);
        }
        let mut retracted0 = Element::new("moderated", MSG_MODERATE_0)
            .attr_set("by", by.as_str())
            .child(Element::new("retracted", RETRACT_0).attr_set("stamp", stamp.as_str()));
        if let Some(r) = reason_el(MSG_MODERATE_0) {
            retracted0.append(r);
        }
        let tombstone = Tombstone { sid: sid.to_string(), marks: vec![retracted, retracted0], sender_id: None };
        Ok(Prepared {
            msg,
            sender: self.jid.clone(),
            archive: true,
            history: false,
            subject: None,
            nick: None,
            retracts: None,
            tombstone: Some(tombstone),
        })
    }

    // ---------------------------------------------------------------- admin (XEP-0045 §8–9)

    /// `muc#admin` get: an affiliation or role list.
    pub fn admin_get(&self, from: &Jid, admin: bool, query: &Element) -> Result<Element, StanzaError> {
        let aff = self.aff(&from.to_bare(), admin);
        let role = self.role_of(from);
        let item = query.get_child("item", ns::MUC_ADMIN).ok_or_else(|| err(Condition::BadRequest, "Say which list you want."))?;
        let mut q = Element::new("query", ns::MUC_ADMIN);
        if let Some(a) = item.attr("affiliation") {
            let want = Affiliation::parse(a)
                .filter(|a| *a != Affiliation::None)
                .ok_or_else(|| err(Condition::BadRequest, "That isn't an affiliation."))?;
            // Members may see who's in a non-anonymous room (OMEMO clients need the list).
            let ok =
                aff >= Affiliation::Admin || (want != Affiliation::Outcast && aff >= Affiliation::Member && self.config.non_anonymous());
            if !ok {
                return Err(err(Condition::Forbidden, "Only admins and owners can see that list."));
            }
            let mut entries: Vec<(&Jid, &AffEntry)> = self.affiliations.iter().filter(|(_, e)| e.affiliation == want).collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            for (j, e) in entries {
                let mut it = Element::new("item", ns::MUC_ADMIN)
                    .attr_set("affiliation", want.as_str())
                    .attr_set("jid", j.to_string())
                    .attr_opt("nick", e.nick.clone());
                if let Some(r) = &e.reason {
                    it.append(Element::new("reason", ns::MUC_ADMIN).text(r.as_str()));
                }
                q.append(it);
            }
            return Ok(q);
        }
        if let Some(r) = item.attr("role") {
            let want = Role::parse(r).filter(|r| *r != Role::None).ok_or_else(|| err(Condition::BadRequest, "That isn't a role."))?;
            if role != Role::Moderator && aff < Affiliation::Admin {
                return Err(err(Condition::Forbidden, "Only moderators can see that list."));
            }
            let mut v: Vec<&Occupant> = self.occupants.values().filter(|o| o.role == want).collect();
            v.sort_by(|a, b| a.nick.cmp(&b.nick));
            for o in v {
                q.append(
                    Element::new("item", ns::MUC_ADMIN)
                        .attr_set("affiliation", self.occ_aff(o).as_str())
                        .attr_set("role", want.as_str())
                        .attr_set("nick", o.nick.as_str())
                        .attr_opt("jid", o.primary().map(|s| s.jid.to_string())),
                );
            }
            return Ok(q);
        }
        Err(err(Condition::BadRequest, "Say which list you want."))
    }

    /// `muc#admin` set: kicks, voice, moderators, bans and memberships, all or nothing.
    pub fn admin_set(&mut self, from: &Jid, admin: bool, query: &Element, out: &mut Out) -> Result<(), StanzaError> {
        enum Change {
            Role { nick: String, role: Role, reason: Option<String> },
            Aff { jid: Jid, aff: Affiliation, reason: Option<String> },
        }
        let actor_bare = from.to_bare();
        let actor_aff = self.aff(&actor_bare, admin);
        let actor_role = if actor_aff >= Affiliation::Admin { Role::Moderator } else { self.role_of(from) };
        let actor_nick = self.nick_of(from).map(str::to_string);
        let items: Vec<&Element> = query.children().filter(|c| c.is("item", ns::MUC_ADMIN)).collect();
        if items.is_empty() || items.len() > MAX_ITEMS_PER_REQUEST {
            return Err(err(Condition::BadRequest, "Send between one and a hundred items."));
        }
        let mut plan = Vec::with_capacity(items.len());
        let mut owners: Vec<Jid> =
            self.affiliations.iter().filter(|(_, a)| a.affiliation == Affiliation::Owner).map(|(j, _)| j.clone()).collect();
        for it in items {
            let reason = it.child_text("reason", ns::MUC_ADMIN);
            if let Some(a) = it.attr("affiliation") {
                let aff = Affiliation::parse(a).ok_or_else(|| err(Condition::BadRequest, "That isn't an affiliation."))?;
                let jid = match (it.attr("jid"), it.attr("nick")) {
                    (Some(j), _) => Jid::parse(j).map_err(|_| err(Condition::JidMalformed, "That address isn't valid."))?.to_bare(),
                    (None, Some(n)) => self
                        .occupants
                        .get(n)
                        .map(|o| o.bare.clone())
                        .ok_or_else(|| err(Condition::ItemNotFound, "There's nobody with that nickname here."))?,
                    (None, None) => return Err(err(Condition::BadRequest, "Say whose affiliation to change.")),
                };
                let old = self.aff(&jid, false);
                check_affiliation_change(actor_aff, old, aff)?;
                owners.retain(|o| *o != jid);
                if aff == Affiliation::Owner {
                    owners.push(jid.clone());
                }
                plan.push(Change::Aff { jid, aff, reason });
            } else if let Some(r) = it.attr("role") {
                let role = Role::parse(r).ok_or_else(|| err(Condition::BadRequest, "That isn't a role."))?;
                let nick = it.attr("nick").ok_or_else(|| err(Condition::BadRequest, "Say whose role to change."))?;
                let t = self.occupants.get(nick).ok_or_else(|| err(Condition::ItemNotFound, "There's nobody with that nickname here."))?;
                check_role_change(actor_aff, actor_role, self.occ_aff(t), t.role, role)?;
                plan.push(Change::Role { nick: nick.to_string(), role, reason });
            } else {
                return Err(err(Condition::BadRequest, "Each item needs a role or an affiliation."));
            }
        }
        let had_owner = self.affiliations.values().any(|a| a.affiliation == Affiliation::Owner);
        if had_owner && owners.is_empty() {
            return Err(err(Condition::Conflict, "A group chat needs at least one owner."));
        }
        // Bans and everything else have limits of their own, so a full member list (people can
        // register themselves) never stops a ban. A change that shrinks a list is always fine.
        let (standing, bans) = self.affiliation_counts();
        let (mut standing_after, mut bans_after) = (standing, bans);
        let mut planned: HashMap<&Jid, Affiliation> = HashMap::new();
        for c in &plan {
            if let Change::Aff { jid, aff, .. } = c {
                let before =
                    planned.get(jid).copied().unwrap_or_else(|| self.affiliations.get(jid).map_or(Affiliation::None, |a| a.affiliation));
                for (a, delta) in [(before, -1isize), (*aff, 1)] {
                    let slot = match a {
                        Affiliation::None => continue,
                        Affiliation::Outcast => &mut bans_after,
                        _ => &mut standing_after,
                    };
                    *slot = slot.saturating_add_signed(delta);
                }
                planned.insert(jid, *aff);
            }
        }
        if standing_after > standing && standing_after > MAX_AFFILIATIONS {
            return Err(err(Condition::ResourceConstraint, "This group chat has too many members."));
        }
        if bans_after > bans && bans_after > MAX_BANS {
            return Err(err(Condition::ResourceConstraint, "This group chat has banned as many people as it can; lift some bans first."));
        }
        let actor = actor_nick.as_deref();
        for c in plan {
            match c {
                Change::Role { nick, role, reason } => {
                    if role == Role::None {
                        self.remove_occupant(&nick, &[307], actor, reason.as_deref(), out);
                    } else if let Some(o) = self.occupants.get_mut(&nick) {
                        if o.role != role {
                            let was = std::mem::replace(&mut o.role, role);
                            self.announce(&nick, actor, reason.as_deref(), was, out);
                        }
                    }
                }
                Change::Aff { jid, aff, reason } => self.set_affiliation(&jid, aff, reason, actor, out),
            }
        }
        Ok(())
    }

    /// Sets an affiliation and applies it to anyone in the room under that address.
    pub fn set_affiliation(&mut self, jid: &Jid, aff: Affiliation, reason: Option<String>, actor: Option<&str>, out: &mut Out) {
        let prev = self.affiliations.remove(jid);
        if aff != Affiliation::None || prev.as_ref().is_some_and(|p| p.nick.is_some() && aff >= Affiliation::Member) {
            let (nick, last_nick) = prev.map_or((None, None), |p| (p.nick, p.last_nick));
            let nick = if aff >= Affiliation::Member { nick } else { None };
            self.affiliations.insert(jid.clone(), AffEntry { affiliation: aff, reason: reason.clone(), nick, last_nick });
        }
        self.save_affiliation(jid, out);
        let nicks: Vec<String> = self.occupants.values().filter(|o| o.bare == *jid).map(|o| o.nick.clone()).collect();
        for n in nicks {
            if aff == Affiliation::Outcast {
                self.remove_occupant(&n, &[301], actor, reason.as_deref(), out);
            } else if self.config.members_only && aff < Affiliation::Member && self.occupants.get(&n).is_some_and(|o| !o.admin) {
                self.remove_occupant(&n, &[321], actor, reason.as_deref(), out);
            } else if let Some(o) = self.occupants.get_mut(&n) {
                let was =
                    std::mem::replace(&mut o.role, default_role(if o.admin { Affiliation::Owner } else { aff }, self.config.moderated));
                self.announce(&n, actor, reason.as_deref(), was, out);
            }
        }
    }

    // ---------------------------------------------------------------- owner (XEP-0045 §10)

    /// Applies a submitted configuration form.
    pub fn configure(&mut self, v: &crate::modules::forms::Values, out: &mut Out) -> Result<(), StanzaError> {
        let was_persistent = self.config.persistent;
        // A form that's refused leaves everything as it was, a new room still locked included.
        let changes = self.config.apply(v).map_err(|t| err(Condition::NotAcceptable, &t))?;
        let was_locked = self.locked_since.take().is_some();
        if self.config.persistent && !was_persistent {
            out.db.push(Op::Snapshot(Box::new(self.snapshot())));
        } else if changes.became_temporary {
            out.db.push(Op::Delete);
        } else {
            self.save(out);
        }
        if !was_locked {
            let mut x = Element::new("x", ns::MUC_USER);
            for c in &changes.codes {
                x.append(Element::new("status", ns::MUC_USER).attr_set("code", c.to_string()));
            }
            let note = Element::new("message", ns::CLIENT).attr_set("from", self.jid.to_string()).attr_set("type", "groupchat").child(x);
            for o in self.occupants.values() {
                for s in &o.sessions {
                    let mut m = note.clone();
                    m.set_attr("id", quark_core::new_id());
                    m.set_attr("to", s.jid.to_string());
                    out.send.push(m);
                }
            }
        }
        if changes.became_members_only {
            let out_now: Vec<String> = self
                .occupants
                .values()
                .filter(|o| !o.admin && self.aff(&o.bare, false) < Affiliation::Member)
                .map(|o| o.nick.clone())
                .collect();
            for n in out_now {
                self.remove_occupant(&n, &[322], None, None, out);
            }
        }
        if self.occupants.is_empty() && !self.config.persistent {
            self.close(out);
        }
        Ok(())
    }

    /// The owner accepts the defaults for a new room (an instant room, §10.1.2).
    pub fn unlock(&mut self, out: &mut Out) {
        if self.locked_since.take().is_some() && self.config.persistent {
            out.db.push(Op::Snapshot(Box::new(self.snapshot())));
        }
    }

    // ---------------------------------------------------------------- registration (§7.10)

    pub fn register_get(&self, from: &Jid, admin: bool) -> Result<Element, StanzaError> {
        let bare = from.to_bare();
        if self.aff(&bare, admin) == Affiliation::Outcast {
            return Err(err(Condition::Forbidden, "You've been banned from this group chat."));
        }
        let q = Element::new("query", ns::REGISTER);
        if let Some(n) = self.affiliations.get(&bare).and_then(|a| a.nick.clone()) {
            return Ok(q.child(Element::new("registered", ns::REGISTER)).text_child("username", ns::REGISTER, n));
        }
        Ok(q.text_child("instructions", ns::REGISTER, "Choose the nickname to keep for yourself in this group chat.").child(
            crate::modules::forms::Form::new("form", "http://jabber.org/protocol/muc#register")
                .title("Register with the group chat")
                .field("muc#register_roomnick", "text-single", "Nickname", None)
                .required()
                .build(),
        ))
    }

    pub fn register_set(&mut self, from: &Jid, admin: bool, q: &Element, out: &mut Out) -> Result<(), StanzaError> {
        let bare = from.to_bare();
        let aff = self.aff(&bare, admin);
        if aff == Affiliation::Outcast {
            return Err(err(Condition::Forbidden, "You've been banned from this group chat."));
        }
        if q.has_child("remove", ns::REGISTER) {
            let Some(e) = self.affiliations.get_mut(&bare) else { return Ok(()) };
            e.nick = None;
            if e.affiliation == Affiliation::Member {
                self.set_affiliation(&bare, Affiliation::None, None, None, out);
            } else {
                self.save_affiliation(&bare, out);
            }
            return Ok(());
        }
        let Some(x) = crate::modules::forms::find(q) else {
            return Err(err(Condition::BadRequest, "Send the registration form."));
        };
        if x.attr("type") == Some("cancel") {
            return Ok(());
        }
        let v = crate::modules::forms::Values::parse(x);
        let nick = v
            .get("muc#register_roomnick")
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .ok_or_else(|| err(Condition::NotAcceptable, "Choose a nickname."))?;
        let nick = self
            .jid
            .with_resource(nick)
            .map_err(|_| err(Condition::JidMalformed, "That nickname can't be used."))?
            .resource()
            .unwrap_or_default()
            .to_string();
        if nick.chars().count() > MAX_NICK_CHARS {
            return Err(err(Condition::NotAcceptable, "That nickname is too long."));
        }
        if self.config.members_only && aff < Affiliation::Member {
            return Err(err(Condition::NotAllowed, "Only members can register with this group chat."));
        }
        if self.reserved_by_other(&nick, &bare) || self.occupants.get(&nick).is_some_and(|o| o.bare != bare) {
            return Err(err(Condition::Conflict, "That nickname is taken."));
        }
        let became_member = aff < Affiliation::Member;
        if became_member {
            // Registering makes someone a member, and members talk without being given a voice.
            // So only someone in the room who may talk already can make themselves one (anyone
            // else would be a stranger, or a remote server, filling the member list).
            let Some(o) = self.occupant_of(from) else {
                return Err(err(Condition::NotAcceptable, "Join the group chat before registering with it."));
            };
            if o.role < Role::Participant {
                return Err(err(Condition::NotAllowed, "You need a voice in this group chat before you can register with it."));
            }
            if self.affiliation_counts().0 >= MAX_SELF_SERVICE {
                return Err(err(Condition::ResourceConstraint, "This group chat has too many members; ask an admin to add you."));
            }
        }
        let e = self.affiliations.entry(bare.clone()).or_insert(AffEntry {
            affiliation: Affiliation::Member,
            reason: None,
            nick: None,
            last_nick: None,
        });
        if e.affiliation < Affiliation::Member {
            e.affiliation = Affiliation::Member;
        }
        e.nick = Some(nick);
        self.save_affiliation(&bare, out);
        if became_member {
            // Their role stays: they could talk already, and nothing else changes with it.
            let nicks: Vec<(String, Role)> = self.occupants.values().filter(|o| o.bare == bare).map(|o| (o.nick.clone(), o.role)).collect();
            for (n, role) in nicks {
                self.announce(&n, None, None, role, out);
            }
        }
        Ok(())
    }

    /// disco#info node `x-roomuser-item` (§7.12): the nickname someone registered.
    pub fn reserved_nick(&self, bare: &Jid) -> Option<&str> {
        self.affiliations.get(bare).and_then(|a| a.nick.as_deref())
    }

    // ---------------------------------------------------------------- avatar (vCard on the room)

    fn set_vcard_inner(&mut self, xml: Option<String>) {
        use base64::Engine;
        self.avatar_hash = xml.as_deref().and_then(|x| Element::parse(x).ok()).and_then(|v| {
            let b = v.get_child("PHOTO", ns::VCARD)?.child_text("BINVAL", ns::VCARD)?;
            let clean: String = b.chars().filter(|c| !c.is_whitespace()).collect();
            let bytes = base64::engine::general_purpose::STANDARD.decode(clean).ok()?;
            Some(hex::encode(<sha1::Sha1 as Digest>::digest(&bytes)))
        });
        self.vcard = xml;
    }

    /// An owner changes the room's vCard; everyone learns the new avatar.
    pub fn set_vcard(&mut self, xml: Option<String>, out: &mut Out) {
        self.set_vcard_inner(xml);
        self.save(out);
        let photo = Element::new("x", ns::VCARD_UPDATE).text_child("photo", ns::VCARD_UPDATE, self.avatar_hash.clone().unwrap_or_default());
        let p = Element::new("presence", ns::CLIENT).attr_set("from", self.jid.to_string()).child(photo);
        let note = Element::new("message", ns::CLIENT)
            .attr_set("from", self.jid.to_string())
            .attr_set("type", "groupchat")
            .child(Element::new("x", ns::MUC_USER).child(Element::new("status", ns::MUC_USER).attr_set("code", "104")));
        for o in self.occupants.values() {
            for s in &o.sessions {
                let mut x = p.clone();
                x.set_attr("to", s.jid.to_string());
                out.send.push(x);
                let mut m = note.clone();
                m.set_attr("to", s.jid.to_string());
                m.set_attr("id", quark_core::new_id());
                out.send.push(m);
            }
        }
    }

    // ---------------------------------------------------------------- IQs between occupants

    /// Relays an IQ from one occupant to another (vCards go to the account, the rest to the
    /// newest device), remembering who asked so the answer finds its way back.
    pub fn relay_iq(&mut self, from: &Jid, nick: &str, iq: &Element) -> Result<Element, StanzaError> {
        let Some(from_nick) = self.by_session.get(from).cloned() else {
            return Err(err(Condition::NotAcceptable, "You're not in this group chat."));
        };
        let Some(t) = self.occupants.get(nick) else {
            return Err(err(Condition::ItemNotFound, "There's nobody with that nickname here."));
        };
        let vcard = iq.first_child().is_some_and(|p| p.ns() == ns::VCARD);
        let to = if vcard { t.bare.clone() } else { t.primary().map(|s| s.jid.clone()).ok_or_else(StanzaError::item_not_found)? };
        if self.pending.len() >= MAX_PENDING_IQS {
            let now = Instant::now();
            self.pending.retain(|_, p| now.duration_since(p.at) < PENDING_IQ_TTL);
            if self.pending.len() >= MAX_PENDING_IQS {
                return Err(err(Condition::ResourceConstraint, "Too many requests are waiting; try again soon.").with_type(ErrorType::Wait));
            }
        }
        let id = quark_core::new_id();
        self.pending.insert(
            id.clone(),
            Proxied {
                requester: from.clone(),
                id: iq.attr("id").unwrap_or_default().to_string(),
                target: to.to_bare(),
                from_nick: from_nick.clone(),
                at: Instant::now(),
            },
        );
        let mut fwd = iq.clone();
        fwd.set_attr("id", id);
        fwd.set_attr("from", self.occ_jid(&from_nick).to_string());
        fwd.set_attr("to", to.to_string());
        Ok(fwd)
    }

    /// An answer to a relayed IQ, on its way back to whoever asked.
    pub fn relay_answer(&mut self, from: &Jid, nick: &str, iq: &Element) -> Option<Element> {
        let id = iq.attr("id")?;
        let p = self.pending.get(id)?;
        if p.target != from.to_bare() || p.from_nick != nick {
            return None;
        }
        let p = self.pending.remove(id)?;
        let target_nick =
            self.by_session.get(from).cloned().or_else(|| self.occupants.values().find(|o| o.bare == p.target).map(|o| o.nick.clone()))?;
        let mut back = iq.clone();
        back.set_attr("id", p.id);
        back.set_attr("from", self.occ_jid(&target_nick).to_string());
        back.set_attr("to", p.requester.to_string());
        Some(back)
    }

    /// Drops relayed IQs nobody answered.
    pub fn expire(&mut self) {
        let now = Instant::now();
        self.pending.retain(|_, p| now.duration_since(p.at) < PENDING_IQ_TTL);
    }

    /// Who may read the archive (XEP-0313 §5.1.2 on a room): whoever could join it. A password
    /// can't be checked on a query, so in a room that has one only the people in it now (who
    /// gave it) and those who never need it (admins and owners) may read back.
    pub fn may_read_archive(&self, from: &Jid, admin: bool) -> Result<(), StanzaError> {
        let aff = self.aff(&from.to_bare(), admin);
        if aff == Affiliation::Outcast {
            return Err(err(Condition::Forbidden, "You've been banned from this group chat."));
        }
        if self.config.members_only && aff < Affiliation::Member {
            return Err(err(Condition::Forbidden, "Only members can read this group chat's history."));
        }
        if self.config.password.is_some() && aff < Affiliation::Admin && self.occupant_of(from).is_none() {
            return Err(err(Condition::Forbidden, "Join the group chat to read its history."));
        }
        Ok(())
    }
}

/// How an occupant's presence is sent.
#[derive(Default)]
struct Spec<'a> {
    unavailable: bool,
    /// Presence content; the occupant's newest device's by default.
    base: Option<&'a Element>,
    /// Status codes for everyone.
    codes: &'a [u16],
    /// More codes for the occupant's own devices (110 is always added for them).
    own_codes: &'a [u16],
    new_nick: Option<&'a str>,
    actor: Option<&'a str>,
    reason: Option<&'a str>,
    destroy: Option<&'a Element>,
    /// The affiliation and role shown, when not the current ones (leaving: role none).
    item: Option<(Affiliation, Role)>,
}

fn aff_row(j: &Jid, a: &AffEntry) -> AffRow {
    AffRow {
        jid: j.to_string(),
        affiliation: a.affiliation,
        reason: a.reason.clone(),
        nick: a.nick.clone(),
        last_nick: a.last_nick.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn room() -> Room {
        Room::new(Jid::parse("tea@rooms.x").unwrap(), Config::default(), None, 0)
    }

    fn j(s: &str) -> Jid {
        Jid::parse(s).unwrap()
    }

    fn join(r: &mut Room, from: &str, nick: &str) -> Result<Out, StanzaError> {
        let p = Element::new("presence", ns::CLIENT).child(Element::new("x", ns::MUC));
        let mut out = Out::default();
        let from = j(from);
        r.join(Join { from: &from, nick, presence: &p, admin: false, created: false, now: 1000 }, &mut out)?;
        Ok(out)
    }

    fn codes(p: &Element) -> Vec<String> {
        p.get_child("x", ns::MUC_USER)
            .map(|x| x.children().filter(|c| c.name() == "status").filter_map(|c| c.attr("code").map(String::from)).collect())
            .unwrap_or_default()
    }

    #[test]
    fn joining_sends_others_then_self_then_subject() {
        let mut r = room();
        join(&mut r, "a@x/1", "alice").unwrap();
        let out = join(&mut r, "b@x/1", "bob").unwrap();
        let to_bob: Vec<&Element> = out.send.iter().filter(|e| e.attr("to") == Some("b@x/1")).collect();
        assert_eq!(to_bob[0].attr("from"), Some("tea@rooms.x/alice"));
        assert_eq!(to_bob[1].attr("from"), Some("tea@rooms.x/bob"));
        assert!(codes(to_bob[1]).contains(&"110".to_string()));
        assert!(to_bob.last().unwrap().has_child("subject", ns::CLIENT));
        // Alice hears about bob, without his address (semi-anonymous) or 110.
        let to_alice: Vec<&Element> = out.send.iter().filter(|e| e.attr("to") == Some("a@x/1")).collect();
        assert_eq!(to_alice.len(), 1);
        let item = to_alice[0].get_child("x", ns::MUC_USER).unwrap().get_child("item", ns::MUC_USER).unwrap();
        assert_eq!(item.attr("jid"), None);
        assert!(codes(to_alice[0]).is_empty());
    }

    #[test]
    fn nick_conflicts_but_same_person_shares_it() {
        let mut r = room();
        join(&mut r, "a@x/phone", "alice").unwrap();
        assert_eq!(join(&mut r, "b@x/1", "alice").unwrap_err().condition, Condition::Conflict);
        let out = join(&mut r, "a@x/laptop", "alice").unwrap();
        assert_eq!(r.occupant_count(), 1);
        assert_eq!(r.occupant("alice").unwrap().sessions.len(), 2);
        // The phone hears the updated self-presence.
        assert!(out.send.iter().any(|e| e.attr("to") == Some("a@x/phone") && codes(e).contains(&"110".to_string())));
        // One device leaving keeps the occupant.
        let mut out = Out::default();
        r.leave(&j("a@x/laptop"), None, &[], &mut out);
        assert_eq!(r.occupant_count(), 1);
        let gone = out.send.iter().find(|e| e.attr("to") == Some("a@x/laptop")).unwrap();
        assert_eq!(gone.attr("type"), Some("unavailable"));
    }

    #[test]
    fn temporary_room_closes_when_empty() {
        let mut r = room();
        join(&mut r, "a@x/1", "alice").unwrap();
        let mut out = Out::default();
        r.leave(&j("a@x/1"), None, &[], &mut out);
        assert!(out.closed);
    }

    #[test]
    fn members_only_password_and_bans() {
        let mut r = room();
        r.config.members_only = true;
        assert_eq!(join(&mut r, "a@x/1", "alice").unwrap_err().condition, Condition::RegistrationRequired);
        r.affiliations.insert(j("a@x"), AffEntry { affiliation: Affiliation::Member, reason: None, nick: None, last_nick: None });
        r.config.password = Some("pw".into());
        assert_eq!(join(&mut r, "a@x/1", "alice").unwrap_err().condition, Condition::NotAuthorized);
        r.config.password = None;
        join(&mut r, "a@x/1", "alice").unwrap();
        let mut out = Out::default();
        r.set_affiliation(&j("a@x"), Affiliation::Outcast, Some("spam".into()), None, &mut out);
        assert_eq!(r.occupant_count(), 0);
        assert!(out.send.iter().any(|e| codes(e).contains(&"301".to_string())));
        r.config.members_only = false;
        assert_eq!(join(&mut r, "a@x/2", "alice").unwrap_err().condition, Condition::Forbidden);
    }

    #[test]
    fn permissions() {
        use Affiliation as A;
        assert!(check_role_change(A::None, Role::Moderator, A::None, Role::Participant, Role::None).is_ok());
        assert!(check_role_change(A::None, Role::Participant, A::None, Role::Participant, Role::None).is_err());
        assert_eq!(
            check_role_change(A::Owner, Role::Moderator, A::Admin, Role::Moderator, Role::None).unwrap_err().condition,
            Condition::NotAllowed
        );
        assert!(check_role_change(A::None, Role::Moderator, A::None, Role::Participant, Role::Moderator).is_err());
        assert!(check_affiliation_change(A::Admin, A::None, A::Outcast).is_ok());
        assert!(check_affiliation_change(A::Admin, A::Admin, A::Outcast).is_err());
        assert!(check_affiliation_change(A::Admin, A::None, A::Admin).is_err());
        assert!(check_affiliation_change(A::Owner, A::None, A::Owner).is_ok());
        assert!(check_affiliation_change(A::Member, A::None, A::Member).is_err());
    }

    #[test]
    fn history_limits() {
        let mut r = room();
        for i in 0..30 {
            let msg = Element::new("message", ns::CLIENT).text_child("body", ns::CLIENT, format!("m{i}"));
            r.push_history(HistoryItem { bytes: 10, msg, stamp: i * 1000, sid: i.to_string(), sender: j("a@x") });
        }
        assert_eq!(r.select_history(HistoryLimits::default()).len(), 20, "the room's history length");
        assert_eq!(r.select_history(HistoryLimits { max_stanzas: Some(3), ..Default::default() }).first().unwrap().sid, "27");
        assert_eq!(r.select_history(HistoryLimits { max_chars: Some(0), ..Default::default() }).len(), 0);
        assert_eq!(r.select_history(HistoryLimits { max_chars: Some(25), ..Default::default() }).len(), 2);
        assert_eq!(r.select_history(HistoryLimits { since: Some(28_000), ..Default::default() }).len(), 2);
        let h = Element::new("history", ns::MUC).attr_set("seconds", "2");
        assert_eq!(HistoryLimits::parse(Some(&h), 30_000).since, Some(28_000));
    }

    #[test]
    fn messages_need_voice_and_get_occupant_ids() {
        let mut r = room();
        r.config.moderated = true;
        join(&mut r, "a@x/1", "alice").unwrap();
        let msg = Element::new("message", ns::CLIENT).attr_set("type", "groupchat").text_child("body", ns::CLIENT, "hi");
        assert_eq!(r.prepare_message(&j("a@x/1"), &msg).unwrap_err().condition, Condition::Forbidden);
        r.config.moderated = false;
        join(&mut r, "b@x/1", "bob").unwrap();
        let p = r.prepare_message(&j("b@x/1"), &msg).unwrap().unwrap();
        assert!(p.msg.has_child("occupant-id", ns::OCCUPANT_ID));
        assert!(p.history && p.archive);
        let mut out = Out::default();
        r.commit_message(p, Some("sid1".into()), 5, &mut out);
        assert_eq!(out.send.len(), 2, "both occupants, the sender included");
        assert!(out.send.iter().all(|m| m.get_child("stanza-id", ns::SID).and_then(|s| s.attr("id")) == Some("sid1")));
        assert_eq!(r.prepare_message(&j("c@x/1"), &msg).unwrap_err().condition, Condition::NotAcceptable);
    }

    fn aff(a: Affiliation) -> AffEntry {
        AffEntry { affiliation: a, reason: None, nick: None, last_nick: None }
    }

    fn register(nick: &str) -> Element {
        let form = crate::modules::forms::Form::new("submit", "http://jabber.org/protocol/muc#register")
            .field("muc#register_roomnick", "text-single", "", Some(nick))
            .build();
        Element::new("query", ns::REGISTER).child(form)
    }

    #[test]
    fn registering_needs_to_be_in_the_room_with_a_voice() {
        let mut r = room();
        r.config.moderated = true;
        let mut out = Out::default();
        // From outside (a remote server filling the list, say): refused.
        assert_eq!(
            r.register_set(&j("far@away.example/x"), false, &register("far"), &mut out).unwrap_err().condition,
            Condition::NotAcceptable
        );
        assert!(r.affiliations.is_empty());
        // A visitor in a moderated room can't give themselves a voice by registering.
        join(&mut r, "v@x/1", "vis").unwrap();
        assert_eq!(r.occupant("vis").unwrap().role, Role::Visitor);
        assert_eq!(r.register_set(&j("v@x/1"), false, &register("vis"), &mut out).unwrap_err().condition, Condition::NotAllowed);
        assert_eq!(r.occupant("vis").unwrap().role, Role::Visitor);
        // Someone who may talk registers and keeps their role.
        r.occupants.get_mut("vis").unwrap().role = Role::Participant;
        r.register_set(&j("v@x/1"), false, &register("vis"), &mut out).unwrap();
        assert_eq!(r.aff(&j("v@x"), false), Affiliation::Member);
        assert_eq!(r.reserved_nick(&j("v@x")), Some("vis"));
    }

    #[test]
    fn self_service_stops_short_so_bans_always_fit() {
        let mut r = room();
        r.affiliations.insert(j("o@x"), aff(Affiliation::Owner));
        for i in 0..MAX_SELF_SERVICE {
            r.affiliations.insert(j(&format!("m{i}@x")), aff(Affiliation::Member));
        }
        join(&mut r, "p@x/1", "p").unwrap();
        let mut out = Out::default();
        assert_eq!(r.register_set(&j("p@x/1"), false, &register("p"), &mut out).unwrap_err().condition, Condition::ResourceConstraint);
        // The list of members can still grow through admins, up to its own limit…
        for i in MAX_SELF_SERVICE..MAX_AFFILIATIONS - 1 {
            r.affiliations.insert(j(&format!("m{i}@x")), aff(Affiliation::Member));
        }
        let add = |who: &str, a: &str| {
            Element::new("query", ns::MUC_ADMIN).child(Element::new("item", ns::MUC_ADMIN).attr_set("jid", who).attr_set("affiliation", a))
        };
        assert_eq!(
            r.admin_set(&j("o@x/1"), false, &add("new@x", "member"), &mut out).unwrap_err().condition,
            Condition::ResourceConstraint
        );
        // …and a ban still goes through, of a stranger or of a member.
        r.admin_set(&j("o@x/1"), false, &add("spam@x", "outcast"), &mut out).unwrap();
        r.admin_set(&j("o@x/1"), false, &add("m1@x", "outcast"), &mut out).unwrap();
        assert_eq!(r.aff(&j("spam@x"), false), Affiliation::Outcast);
        assert_eq!(r.aff(&j("m1@x"), false), Affiliation::Outcast);
    }

    #[test]
    fn a_password_keeps_the_archive_to_the_people_in_the_room() {
        let mut r = room();
        r.config.password = Some("pw".into());
        r.affiliations.insert(j("m@x"), aff(Affiliation::Member));
        r.affiliations.insert(j("a@x"), aff(Affiliation::Admin));
        assert_eq!(r.may_read_archive(&j("s@x/1"), false).unwrap_err().condition, Condition::Forbidden);
        assert_eq!(r.may_read_archive(&j("m@x/1"), false).unwrap_err().condition, Condition::Forbidden);
        assert!(r.may_read_archive(&j("a@x/1"), false).is_ok(), "admins don't need the password to join either");
        let p = Element::new("presence", ns::CLIENT).child(Element::new("x", ns::MUC).child(Element::new("password", ns::MUC).text("pw")));
        let mut out = Out::default();
        r.join(Join { from: &j("s@x/1"), nick: "s", presence: &p, admin: false, created: false, now: 0 }, &mut out).unwrap();
        assert!(r.may_read_archive(&j("s@x/1"), false).is_ok());
        r.config.password = None;
        assert!(r.may_read_archive(&j("m@x/1"), false).is_ok());
    }

    #[test]
    fn a_refused_configuration_leaves_a_new_room_locked() {
        let mut r = room();
        r.locked_since = Some(Instant::now());
        let bad = crate::modules::forms::Values::parse(
            &crate::modules::forms::Form::new("submit", super::super::config::ROOMCONFIG)
                .field("muc#roomconfig_roomname", "text-single", "", Some(&"n".repeat(10_000)))
                .build(),
        );
        let mut out = Out::default();
        assert!(r.configure(&bad, &mut out).is_err());
        assert!(r.locked_since.is_some());
        let good = crate::modules::forms::Values::parse(
            &crate::modules::forms::Form::new("submit", super::super::config::ROOMCONFIG)
                .field("muc#roomconfig_roomname", "text-single", "", Some("Tea"))
                .build(),
        );
        r.configure(&good, &mut out).unwrap();
        assert!(r.locked_since.is_none());
    }

    #[test]
    fn retractions_are_saved_and_leave_a_tombstone_for_the_sender_only() {
        let mut r = room();
        r.config.persistent = true;
        join(&mut r, "a@x/1", "alice").unwrap();
        join(&mut r, "b@x/1", "bob").unwrap();
        let msg = Element::new("message", ns::CLIENT).attr_set("type", "groupchat").text_child("body", ns::CLIENT, "oops");
        let p = r.prepare_message(&j("a@x/1"), &msg).unwrap().unwrap();
        let mut out = Out::default();
        r.commit_message(p, Some("sid1".into()), 5, &mut out);
        let archived = r.history.back().unwrap().msg.clone();
        let retract = Element::new("message", ns::CLIENT)
            .attr_set("type", "groupchat")
            .child(Element::new("retract", ns::RETRACT).attr_set("id", "sid1"));
        // Bob can't take back Alice's message.
        let p = r.prepare_message(&j("b@x/1"), &retract).unwrap().unwrap();
        assert!(p.tombstone.as_ref().unwrap().apply(&archived).is_none());
        let mut out = Out::default();
        r.commit_message(p, Some("sid2".into()), 6, &mut out);
        assert_eq!(r.history.len(), 1);
        assert!(!out.db.iter().any(|o| matches!(o, Op::Unhistory { .. })));
        // Alice can, and it's saved.
        let p = r.prepare_message(&j("a@x/1"), &retract).unwrap().unwrap();
        let t = p.tombstone.clone().unwrap().apply(&archived).unwrap();
        assert!(t.has_child("retracted", ns::RETRACT) && !t.has_child("body", ns::CLIENT));
        assert_eq!(t.attr("from"), Some("tea@rooms.x/alice"));
        assert!(t.has_child("occupant-id", ns::OCCUPANT_ID));
        let mut out = Out::default();
        r.commit_message(p, Some("sid3".into()), 7, &mut out);
        assert!(r.history.is_empty());
        assert!(out.db.iter().any(|o| matches!(o, Op::Unhistory { sid } if sid == "sid1")));
    }

    fn invite(to: &str, reason: &str) -> Element {
        Element::new("invite", ns::MUC_USER).attr_set("to", to).text_child("reason", ns::MUC_USER, reason)
    }

    #[test]
    fn invitations_are_rate_limited_and_only_invitees_decline() {
        let mut r = room();
        join(&mut r, "a@x/1", "alice").unwrap();
        let mut out = Out::default();
        // Nobody invited Eve: she can't use the room to message Alice.
        let decline = |to: &str| Element::new("x", ns::MUC_USER).child(Element::new("decline", ns::MUC_USER).attr_set("to", to));
        assert_eq!(r.invitations(&j("e@evil/1"), false, &decline("a@x"), &mut out).unwrap_err().condition, Condition::NotAcceptable);
        assert!(out.route.is_empty());
        // Reasons are bounded.
        let x = Element::new("x", ns::MUC_USER).child(invite("b@x", &"r".repeat(MAX_REASON_BYTES + 1)));
        assert_eq!(r.invitations(&j("a@x/1"), false, &x, &mut out).unwrap_err().condition, Condition::NotAcceptable);
        r.invitations(&j("a@x/1"), false, &Element::new("x", ns::MUC_USER).child(invite("b@x", "tea?")), &mut out).unwrap();
        assert_eq!(out.route.len(), 1);
        // Bob declines once; to Alice, whoever he names.
        r.invitations(&j("b@x/phone"), false, &decline("a@x"), &mut out).unwrap();
        assert_eq!(out.route.last().unwrap().attr("to"), Some("a@x"));
        assert!(r.invitations(&j("b@x/phone"), false, &decline("a@x"), &mut out).is_err());
        // Invitations draw on the same allowance as messages.
        let mut refused = false;
        for i in 0..10 {
            let x =
                Element::new("x", ns::MUC_USER).children_from((0..MAX_INVITES_PER_MESSAGE).map(|k| invite(&format!("p{i}{k}@x"), "hi")));
            if let Err(e) = r.invitations(&j("a@x/1"), false, &x, &mut out) {
                assert_eq!(e.condition, Condition::ResourceConstraint);
                refused = true;
                break;
            }
        }
        assert!(refused);
    }

    #[test]
    fn moderators_spare_people_at_or_above_their_affiliation() {
        use Affiliation as A;
        // A member who's a moderator can't kick or silence another member…
        assert_eq!(
            check_role_change(A::Member, Role::Moderator, A::Member, Role::Participant, Role::None).unwrap_err().condition,
            Condition::NotAllowed
        );
        assert!(check_role_change(A::Member, Role::Moderator, A::Member, Role::Participant, Role::Visitor).is_err());
        // …but can deal with strangers, and an admin can deal with members.
        assert!(check_role_change(A::Member, Role::Moderator, A::None, Role::Participant, Role::None).is_ok());
        assert!(check_role_change(A::None, Role::Moderator, A::None, Role::Participant, Role::Visitor).is_ok());
        assert!(check_role_change(A::Admin, Role::Moderator, A::Member, Role::Participant, Role::None).is_ok());
        // Giving a voice isn't taking anything away.
        assert!(check_role_change(A::Member, Role::Moderator, A::Member, Role::Visitor, Role::Participant).is_ok());
    }

    #[test]
    fn clients_cant_hand_themselves_hats() {
        let mut r = room();
        let p = Element::new("presence", ns::CLIENT)
            .child(Element::new("x", ns::MUC))
            .child(Element::new("hats", HATS).child(Element::new("hat", HATS).attr_set("title", "Owner").attr_set("uri", "urn:x")));
        let mut out = Out::default();
        let from = j("a@x/1");
        r.join(Join { from: &from, nick: "alice", presence: &p, admin: false, created: false, now: 0 }, &mut out).unwrap();
        join(&mut r, "b@x/1", "bob").unwrap();
        assert!(out.send.iter().all(|e| !e.has_child("hats", HATS)));
        let mut out = Out::default();
        r.send_roster(&j("b@x/1"), "bob", &mut out);
        assert!(!out.send.is_empty() && out.send.iter().all(|e| !e.has_child("hats", HATS)));
    }

    #[test]
    fn kicking_needs_a_moderator_and_spares_admins() {
        let mut r = room();
        r.affiliations.insert(j("o@x"), AffEntry { affiliation: Affiliation::Owner, reason: None, nick: None, last_nick: None });
        join(&mut r, "o@x/1", "owner").unwrap();
        join(&mut r, "b@x/1", "bob").unwrap();
        let kick = |nick: &str| {
            Element::new("query", ns::MUC_ADMIN).child(Element::new("item", ns::MUC_ADMIN).attr_set("nick", nick).attr_set("role", "none"))
        };
        let mut out = Out::default();
        assert_eq!(r.admin_set(&j("b@x/1"), false, &kick("owner"), &mut out).unwrap_err().condition, Condition::Forbidden);
        r.admin_set(&j("o@x/1"), false, &kick("bob"), &mut out).unwrap();
        assert!(r.occupant("bob").is_none());
        let to_bob = out.send.iter().find(|e| e.attr("to") == Some("b@x/1")).unwrap();
        assert!(codes(to_bob).contains(&"307".to_string()));
        // The last owner can't step down.
        let q = Element::new("query", ns::MUC_ADMIN)
            .child(Element::new("item", ns::MUC_ADMIN).attr_set("jid", "o@x").attr_set("affiliation", "member"));
        assert_eq!(r.admin_set(&j("o@x/1"), false, &q, &mut out).unwrap_err().condition, Condition::Conflict);
    }
}
