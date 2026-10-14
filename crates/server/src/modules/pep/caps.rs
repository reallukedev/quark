//! Entity capabilities (XEP-0115) for PEP's `+notify` filtering (XEP-0163 §4.3): verification
//! strings, and bounded caches of what each `ver` says a client wants notifications for.

use std::borrow::Borrow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use parking_lot::Mutex;
use quark_core::{ns, Element, Jid};
use sha2::Digest;

/// The nodes a client asked notifications for.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Caps {
    notify: HashSet<String>,
}

/// Most `+notify` features kept per client; real ones list a few dozen.
const MAX_NOTIFY: usize = 256;

impl Caps {
    /// Reads `<feature var='node+notify'/>` out of a disco#info answer.
    pub fn from_disco(query: &Element) -> Caps {
        let notify = query
            .children()
            .filter(|c| c.is("feature", ns::DISCO_INFO))
            .filter_map(|f| f.attr("var")?.strip_suffix("+notify"))
            .filter(|n| !n.is_empty() && n.len() <= 1024)
            .take(MAX_NOTIFY)
            .map(str::to_string)
            .collect();
        Caps { notify }
    }

    pub fn wants(&self, node: &str) -> bool {
        self.notify.contains(node)
    }

    /// Nodes this wants that `before` didn't.
    pub fn added_since<'a>(&'a self, before: Option<&Caps>) -> Vec<&'a str> {
        self.notify.iter().filter(|n| before.is_none_or(|b| !b.wants(n))).map(String::as_str).collect()
    }

    pub fn nodes(&self) -> impl Iterator<Item = &str> {
        self.notify.iter().map(String::as_str)
    }
}

/// A form in a verification string: its FORM_TYPE, then (var, sorted values) by var.
type Form = (String, Vec<(String, Vec<String>)>);

/// The XEP-0115 §5.1 verification string of a disco#info answer, or None when §5.4 says the
/// answer is invalid (duplicate identities, features or form types).
pub fn ver_string(query: &Element) -> Option<String> {
    let mut identities: Vec<(String, String, String, String)> = query
        .children()
        .filter(|c| c.is("identity", ns::DISCO_INFO))
        .map(|i| {
            let a = |k| i.attr(k).unwrap_or("").to_string();
            (a("category"), a("type"), a("xml:lang"), a("name"))
        })
        .collect();
    identities.sort();
    if identities.windows(2).any(|w| w[0] == w[1]) {
        return None;
    }
    let mut features: Vec<&str> = query.children().filter(|c| c.is("feature", ns::DISCO_INFO)).filter_map(|f| f.attr("var")).collect();
    features.sort_unstable();
    if features.windows(2).any(|w| w[0] == w[1]) {
        return None;
    }
    let mut forms: Vec<Form> = Vec::new();
    for x in query.children().filter(|c| c.is("x", ns::DATA_FORMS)) {
        let fields: Vec<&Element> = x.children().filter(|c| c.is("field", ns::DATA_FORMS)).collect();
        let Some(ft) = fields.iter().find(|f| f.attr("var") == Some("FORM_TYPE")) else { continue };
        // A FORM_TYPE that isn't hidden makes the form not count (§5.4 step 3.6).
        if ft.attr("type") != Some("hidden") {
            continue;
        }
        let form_type = ft.child_text("value", ns::DATA_FORMS).unwrap_or_default();
        let mut rest: Vec<(String, Vec<String>)> = fields
            .iter()
            .filter(|f| f.attr("var") != Some("FORM_TYPE"))
            .map(|f| {
                let mut vals: Vec<String> = f.children().filter(|v| v.is("value", ns::DATA_FORMS)).map(|v| v.text_content()).collect();
                vals.sort_unstable();
                (f.attr("var").unwrap_or("").to_string(), vals)
            })
            .collect();
        rest.sort();
        forms.push((form_type, rest));
    }
    forms.sort();
    if forms.windows(2).any(|w| w[0].0 == w[1].0) {
        return None;
    }
    let mut s = String::with_capacity(512);
    for (c, t, l, n) in &identities {
        s.push_str(&format!("{c}/{t}/{l}/{n}<"));
    }
    for f in features {
        s.push_str(f);
        s.push('<');
    }
    for (ft, fields) in forms {
        s.push_str(&ft);
        s.push('<');
        for (var, vals) in fields {
            s.push_str(&var);
            s.push('<');
            for v in vals {
                s.push_str(&v);
                s.push('<');
            }
        }
    }
    Some(s)
}

/// Whether we can check a `hash` algorithm (IANA names, XEP-0115 §5.1).
pub fn verifiable(algo: &str) -> bool {
    matches!(algo, "sha-1" | "sha-256" | "sha-512")
}

/// Does `ver` really hash this disco#info answer?
pub fn verify(query: &Element, algo: &str, ver: &str) -> bool {
    let Some(s) = ver_string(query) else { return false };
    let digest = match algo {
        "sha-1" => sha1::Sha1::digest(s.as_bytes()).to_vec(),
        "sha-256" => sha2::Sha256::digest(s.as_bytes()).to_vec(),
        "sha-512" => sha2::Sha512::digest(s.as_bytes()).to_vec(),
        _ => return false,
    };
    B64.encode(digest) == ver
}

/// A map that forgets its oldest entries past `cap`, for caches remote parties can grow.
pub struct Bounded<K, V> {
    map: HashMap<K, V>,
    order: VecDeque<K>,
    cap: usize,
}

impl<K: Hash + Eq + Clone, V> Bounded<K, V> {
    pub fn new(cap: usize) -> Self {
        Bounded { map: HashMap::new(), order: VecDeque::new(), cap: cap.max(1) }
    }

    pub fn get<Q: Hash + Eq + ?Sized>(&self, k: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
    {
        self.map.get(k)
    }

    pub fn insert(&mut self, k: K, v: V) {
        if let Some(slot) = self.map.get_mut(&k) {
            *slot = v;
            return;
        }
        while self.map.len() >= self.cap {
            let Some(old) = self.order.pop_front() else { break };
            self.map.remove(&old);
        }
        self.order.push_back(k.clone());
        self.map.insert(k, v);
        // Keys removed by `remove` linger in `order`; drop them once they pile up.
        if self.order.len() > self.cap * 2 {
            let map = &self.map;
            self.order.retain(|k| map.contains_key(k));
        }
    }

    pub fn remove(&mut self, k: &K) -> Option<V> {
        self.map.remove(k)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.map.len()
    }
}

/// Who is waiting for a `ver` to be resolved.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Waiter {
    /// A local session (its full JID).
    Local(Jid),
    /// A remote contact's resource, online for a local account.
    Remote { owner: Jid, entity: Jid },
}

impl Waiter {
    /// The entity that presented the caps, and that gets asked about them.
    pub fn entity(&self) -> &Jid {
        match self {
            Waiter::Local(j) => j,
            Waiter::Remote { entity, .. } => entity,
        }
    }

    /// Whose share of the queries in flight this takes: the account (or remote contact) behind
    /// it, so one party making up `ver`s only ever holds up itself.
    fn party(&self) -> Jid {
        self.entity().to_bare()
    }
}

/// Queries in flight, by key: who's waiting (with the caps node each presented), the first
/// being the one asked. Plus how many queries each party has in flight.
#[derive(Default)]
struct Pending {
    queries: HashMap<String, Vec<(Waiter, String)>>,
    per_party: HashMap<Jid, usize>,
}

impl Pending {
    fn has_room(&self, party: &Jid) -> bool {
        self.queries.len() < MAX_PENDING && self.per_party.get(party).copied().unwrap_or(0) < MAX_PENDING_PER_PARTY
    }
    fn start(&mut self, party: Jid) {
        *self.per_party.entry(party).or_default() += 1;
    }
    fn finish(&mut self, party: &Jid) {
        if let Some(n) = self.per_party.get_mut(party) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.per_party.remove(party);
            }
        }
    }
}

/// How often a waiter whose lookup failed was tried again.
#[derive(Debug, Clone, Copy)]
struct Retry {
    tries: u32,
    /// A retry is already scheduled, so another failure doesn't schedule a second.
    scheduled: bool,
}

/// What's known about caps, shared by every account on the server.
pub struct CapsCache {
    /// Answers whose hash checked out, by `ver`: true for whoever presents that `ver`.
    verified: Mutex<Bounded<String, Arc<Caps>>>,
    /// Answers we couldn't verify, only trusted for the entity that gave them.
    per_entity: Mutex<Bounded<Jid, (String, Arc<Caps>)>>,
    pending: Mutex<Pending>,
    retries: Mutex<Bounded<Waiter, Retry>>,
}

const VERIFIED_CAP: usize = 4096;
const PER_ENTITY_CAP: usize = 8192;
const MAX_PENDING: usize = 512;
/// Queries one account (or remote contact) may have in flight; real clients need one or two.
const MAX_PENDING_PER_PARTY: usize = 4;
const MAX_WAITERS: usize = 1024;
/// Longest caps `node` or `ver` looked up; real ones are well under 100 bytes.
pub const MAX_CAPS_FIELD: usize = 1024;
/// Retries after a failed lookup: after RETRY_BASE, then twice as long each time (1 s to 16 s).
const MAX_RETRIES: u32 = 5;
const RETRY_BASE: Duration = Duration::from_secs(1);
const RETRIES_CAP: usize = 8192;

impl Default for CapsCache {
    fn default() -> Self {
        CapsCache {
            verified: Mutex::new(Bounded::new(VERIFIED_CAP)),
            per_entity: Mutex::new(Bounded::new(PER_ENTITY_CAP)),
            pending: Mutex::new(Pending::default()),
            retries: Mutex::new(Bounded::new(RETRIES_CAP)),
        }
    }
}

/// What to do after a presence's caps were looked up.
#[derive(Debug)]
pub enum Lookup {
    Known(Arc<Caps>),
    /// Unknown: the caller should send the query (it's the first to ask).
    Ask(String),
    /// Unknown, and someone already asked; the waiter is queued.
    Queued,
    /// Unknown, and the waiter's party (or the whole server) has too many queries in flight to
    /// ask now: try again later.
    Busy,
}

/// The outcome of one query.
#[derive(Debug, Default)]
pub struct Resolved {
    /// What the asked entity answered, if it did.
    pub caps: Option<Arc<Caps>>,
    /// Waiters `caps` is good for.
    pub done: Vec<Waiter>,
    /// Waiters still without caps, to try again later.
    pub retry: Vec<Waiter>,
    /// Ask this waiter next (with the caps node it presented), for the others still queued.
    pub next: Option<(Waiter, String)>,
}

impl CapsCache {
    pub fn get(&self, entity: &Jid, ver: &str) -> Option<Arc<Caps>> {
        if let Some(c) = self.verified.lock().get(ver) {
            return Some(c.clone());
        }
        self.per_entity.lock().get(entity).filter(|(v, _)| v == ver).map(|(_, c)| c.clone())
    }

    /// Looks `ver` up for `waiter`; when unknown, queues the waiter under the query key.
    pub fn lookup(&self, node: &str, ver: &str, hash: Option<&str>, waiter: Waiter) -> Lookup {
        if let Some(c) = self.get(waiter.entity(), ver) {
            return Lookup::Known(c);
        }
        // Verifiable answers are shared, so one query serves everyone with the same `ver`.
        let key = match hash {
            Some(h) if verifiable(h) => format!("{h}\0{ver}"),
            _ => format!("{}\0{ver}", waiter.entity()),
        };
        let mut p = self.pending.lock();
        if let Some(w) = p.queries.get_mut(&key) {
            if w.iter().any(|(q, _)| *q == waiter) {
                return Lookup::Queued;
            }
            if w.len() >= MAX_WAITERS {
                return Lookup::Busy;
            }
            w.push((waiter, node.to_string()));
            return Lookup::Queued;
        }
        let party = waiter.party();
        if !p.has_room(&party) {
            return Lookup::Busy;
        }
        p.start(party);
        p.queries.insert(key.clone(), vec![(waiter, node.to_string())]);
        Lookup::Ask(key)
    }

    /// Takes the asked entity's answer (None after a timeout or an error). A verified answer is
    /// cached for everyone and serves every waiter. Otherwise it's only good for the entity that
    /// gave it, and the next waiter whose party has room is asked in turn, so one slow or lying
    /// client doesn't leave the others without caps. Those that can't be asked now, and the
    /// entity itself when it didn't answer, are handed back to try again later.
    pub fn resolve(&self, key: &str, entity: &Jid, ver: &str, hash: Option<&str>, answer: Option<&Element>) -> Resolved {
        let waiters = {
            let mut p = self.pending.lock();
            p.finish(&entity.to_bare());
            p.queries.remove(key).unwrap_or_default()
        };
        let caps = answer.map(|q| Arc::new(Caps::from_disco(q)));
        let mut out = Resolved { caps: caps.clone(), ..Resolved::default() };
        if let (Some(q), Some(c)) = (answer, &caps) {
            if hash.is_some_and(|h| verifiable(h) && verify(q, h, ver)) {
                self.verified.lock().insert(ver.to_string(), c.clone());
                out.done = waiters.into_iter().map(|(w, _)| w).collect();
                return out;
            }
            self.per_entity.lock().insert(entity.clone(), (ver.to_string(), c.clone()));
        }
        let (mine, mut rest): (Vec<_>, Vec<_>) = waiters.into_iter().partition(|(w, _)| w.entity() == entity);
        let mine = mine.into_iter().map(|(w, _)| w);
        if caps.is_some() {
            out.done.extend(mine);
        } else {
            out.retry.extend(mine);
        }
        let mut p = self.pending.lock();
        while !rest.is_empty() {
            let party = rest[0].0.party();
            if p.has_room(&party) {
                p.start(party);
                out.next = Some(rest[0].clone());
                p.queries.insert(key.to_string(), rest);
                break;
            }
            out.retry.push(rest.remove(0).0);
        }
        out
    }

    /// When to look `w` up again after a failure, or None when it had its tries (or one is
    /// already scheduled); its next presence then asks again anyway.
    pub fn schedule_retry(&self, w: &Waiter) -> Option<Duration> {
        let mut r = self.retries.lock();
        let cur = r.get(w).copied().unwrap_or(Retry { tries: 0, scheduled: false });
        if cur.scheduled || cur.tries >= MAX_RETRIES {
            return None;
        }
        r.insert(w.clone(), Retry { tries: cur.tries + 1, scheduled: true });
        Some(RETRY_BASE * 2u32.pow(cur.tries))
    }

    /// A scheduled retry is starting.
    pub fn retry_due(&self, w: &Waiter) {
        let mut r = self.retries.lock();
        if let Some(cur) = r.get(w).copied() {
            r.insert(w.clone(), Retry { scheduled: false, ..cur });
        }
    }

    /// `w` got its caps: a later failure starts with a full set of tries.
    pub fn succeeded(&self, w: &Waiter) {
        self.retries.lock().remove(w);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// XEP-0115 §5.2, the simple example.
    #[test]
    fn simple_example_verifies() {
        let q = Element::parse(
            "<query xmlns='http://jabber.org/protocol/disco#info' node='http://code.google.com/p/exodus#QgayPKawpkPSDYmwT/WM94uAlu0='>\
             <identity category='client' name='Exodus 0.9.1' type='pc'/>\
             <feature var='http://jabber.org/protocol/caps'/>\
             <feature var='http://jabber.org/protocol/disco#info'/>\
             <feature var='http://jabber.org/protocol/disco#items'/>\
             <feature var='http://jabber.org/protocol/muc'/></query>",
        )
        .unwrap();
        assert!(verify(&q, "sha-1", "QgayPKawpkPSDYmwT/WM94uAlu0="));
        assert!(!verify(&q, "sha-1", "QgayPKawpkPSDYmwT/WM94uAlu1="));
        assert!(!verify(&q, "md5", "QgayPKawpkPSDYmwT/WM94uAlu0="));
    }

    /// XEP-0115 §5.3, the complex example with a form and languages.
    #[test]
    fn complex_example_verifies() {
        let q = Element::parse(
            "<query xmlns='http://jabber.org/protocol/disco#info' node='http://psi-im.org#q07IKJEyjvHSyhy//CH0CxmKi8w='>\
             <identity xml:lang='en' category='client' name='Psi 0.11' type='pc'/>\
             <identity xml:lang='el' category='client' name='Ψ 0.11' type='pc'/>\
             <feature var='http://jabber.org/protocol/caps'/>\
             <feature var='http://jabber.org/protocol/disco#info'/>\
             <feature var='http://jabber.org/protocol/disco#items'/>\
             <feature var='http://jabber.org/protocol/muc'/>\
             <x xmlns='jabber:x:data' type='result'>\
               <field var='FORM_TYPE' type='hidden'><value>urn:xmpp:dataforms:softwareinfo</value></field>\
               <field var='ip_version' type='text-multi'><value>ipv4</value><value>ipv6</value></field>\
               <field var='os'><value>Mac</value></field>\
               <field var='os_version'><value>10.5.1</value></field>\
               <field var='software'><value>Psi</value></field>\
               <field var='software_version'><value>0.11</value></field>\
             </x></query>",
        )
        .unwrap();
        assert!(verify(&q, "sha-1", "q07IKJEyjvHSyhy//CH0CxmKi8w="));
    }

    #[test]
    fn duplicate_features_are_invalid() {
        let q =
            Element::parse("<query xmlns='http://jabber.org/protocol/disco#info'><feature var='a'/><feature var='a'/></query>").unwrap();
        assert!(ver_string(&q).is_none());
    }

    #[test]
    fn notify_features_are_collected() {
        let q = Element::parse(
            "<query xmlns='http://jabber.org/protocol/disco#info'><feature var='urn:xmpp:avatar:metadata+notify'/>\
             <feature var='urn:xmpp:avatar:metadata'/><feature var='+notify'/></query>",
        )
        .unwrap();
        let c = Caps::from_disco(&q);
        assert!(c.wants("urn:xmpp:avatar:metadata"));
        assert_eq!(c.nodes().count(), 1);
        assert_eq!(c.added_since(Some(&c)), Vec::<&str>::new());
        assert_eq!(c.added_since(None), vec!["urn:xmpp:avatar:metadata"]);
    }

    #[test]
    fn bounded_map_forgets_the_oldest() {
        let mut m = Bounded::new(2);
        m.insert(1, "a");
        m.insert(2, "b");
        m.insert(3, "c");
        assert!(m.get(&1).is_none());
        assert_eq!(m.get(&3), Some(&"c"));
        m.remove(&2);
        for i in 10..20 {
            m.insert(i, "x");
        }
        assert_eq!(m.len(), 2);
        assert!(m.order.len() <= 4);
    }

    fn local(j: &str) -> Waiter {
        Waiter::Local(Jid::parse(j).unwrap())
    }

    #[test]
    fn one_query_per_verifiable_ver() {
        let c = CapsCache::default();
        let (a, b) = (local("a@x/1"), local("b@x/1"));
        let Lookup::Ask(key) = c.lookup("n", "v", Some("sha-1"), a.clone()) else { panic!() };
        assert!(matches!(c.lookup("n", "v", Some("sha-1"), b.clone()), Lookup::Queued));
        // A wrong hash: only the entity that answered gets the (unverified) result, and the next
        // waiter is asked for itself.
        let q = Element::parse("<query xmlns='http://jabber.org/protocol/disco#info'><feature var='n+notify'/></query>").unwrap();
        let r = c.resolve(&key, a.entity(), "v", Some("sha-1"), Some(&q));
        assert!(r.caps.is_some_and(|c| c.wants("n")));
        assert_eq!(r.done, vec![a.clone()]);
        assert_eq!(r.next, Some((b.clone(), "n".to_string())));
        assert!(c.get(a.entity(), "v").is_some());
        assert!(c.get(b.entity(), "v").is_none());
        // B doesn't answer either: it's handed back for a retry, and nothing is cached.
        let r = c.resolve(&key, b.entity(), "v", Some("sha-1"), None);
        assert_eq!((r.done, r.retry, r.next), (vec![], vec![b.clone()], None));
        assert!(matches!(c.lookup("n", "v", Some("sha-1"), b.clone()), Lookup::Ask(_)));
    }

    #[test]
    fn a_slow_client_hands_the_query_to_the_next_waiter() {
        let c = CapsCache::default();
        let (a, b, d) = (local("a@x/1"), local("b@x/1"), local("d@x/1"));
        let Lookup::Ask(key) = c.lookup("n", "v", Some("sha-1"), a.clone()) else { panic!() };
        c.lookup("n2", "v", Some("sha-1"), b.clone());
        c.lookup("n", "v", Some("sha-1"), d.clone());
        let r = c.resolve(&key, a.entity(), "v", Some("sha-1"), None);
        assert_eq!(r.retry, vec![a]);
        assert_eq!(r.next, Some((b.clone(), "n2".to_string())));
        // A verified answer from B serves D too.
        let q = Element::parse("<query xmlns='http://jabber.org/protocol/disco#info'><feature var='f'/></query>").unwrap();
        let ver = B64.encode(sha1::Sha1::digest(ver_string(&q).unwrap().as_bytes()));
        let r = c.resolve(&key, b.entity(), "v", Some("sha-1"), Some(&q));
        assert_eq!(r.done, vec![b.clone()], "the answer doesn't match `v`, so it's only B's");
        assert_eq!(r.next.map(|n| n.0), Some(d.clone()));
        let Lookup::Ask(key) = c.lookup("n", &ver, Some("sha-1"), b.clone()) else { panic!() };
        c.lookup("n", &ver, Some("sha-1"), d.clone());
        let r = c.resolve(&key, b.entity(), &ver, Some("sha-1"), Some(&q));
        assert_eq!(r.done, vec![b, d]);
    }

    #[test]
    fn made_up_vers_only_hold_up_their_own_account() {
        let c = CapsCache::default();
        for i in 0..MAX_PENDING_PER_PARTY {
            assert!(matches!(c.lookup("n", &format!("fake{i}"), Some("sha-1"), local("eve@x/1")), Lookup::Ask(_)));
        }
        assert!(matches!(c.lookup("n", "fake-more", Some("sha-1"), local("eve@x/2")), Lookup::Busy));
        assert!(matches!(c.lookup("n", "real", Some("sha-1"), local("bob@x/1")), Lookup::Ask(_)));
    }

    #[test]
    fn retries_back_off_and_stop() {
        let c = CapsCache::default();
        let a = local("a@x/1");
        assert_eq!(c.schedule_retry(&a), Some(RETRY_BASE));
        assert_eq!(c.schedule_retry(&a), None, "one retry at a time");
        let mut waits = Vec::new();
        for _ in 1..MAX_RETRIES {
            c.retry_due(&a);
            waits.push(c.schedule_retry(&a).unwrap());
        }
        assert_eq!(waits.last(), Some(&(RETRY_BASE * 16)));
        c.retry_due(&a);
        assert_eq!(c.schedule_retry(&a), None);
        c.succeeded(&a);
        assert_eq!(c.schedule_retry(&a), Some(RETRY_BASE));
    }
}
