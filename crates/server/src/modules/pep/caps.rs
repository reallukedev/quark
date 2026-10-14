//! Entity capabilities (XEP-0115) for PEP's `+notify` filtering (XEP-0163 §4.3): verification
//! strings, and bounded caches of what each `ver` says a client wants notifications for.

use std::borrow::Borrow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::sync::Arc;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Waiter {
    /// A local session (its full JID).
    Local(Jid),
    /// A remote contact's resource, online for a local account.
    Remote { owner: Jid, entity: Jid },
}

/// What's known about caps, shared by every account on the server.
pub struct CapsCache {
    /// Answers whose hash checked out, by `ver`: true for whoever presents that `ver`.
    verified: Mutex<Bounded<String, Arc<Caps>>>,
    /// Answers we couldn't verify, only trusted for the entity that gave them.
    per_entity: Mutex<Bounded<Jid, (String, Arc<Caps>)>>,
    /// Queries in flight, by key, with who's waiting.
    pending: Mutex<HashMap<String, Vec<Waiter>>>,
}

const VERIFIED_CAP: usize = 4096;
const PER_ENTITY_CAP: usize = 8192;
const MAX_PENDING: usize = 512;
const MAX_WAITERS: usize = 1024;

impl Default for CapsCache {
    fn default() -> Self {
        CapsCache {
            verified: Mutex::new(Bounded::new(VERIFIED_CAP)),
            per_entity: Mutex::new(Bounded::new(PER_ENTITY_CAP)),
            pending: Mutex::new(HashMap::new()),
        }
    }
}

/// What to do after a presence's caps were looked up.
pub enum Lookup {
    Known(Arc<Caps>),
    /// Unknown: the caller should send the query (it's the first to ask).
    Ask(String),
    /// Unknown, and someone already asked; the waiter is queued.
    Queued,
    /// Unknown, and too many queries are in flight to ask now.
    Busy,
}

impl CapsCache {
    pub fn get(&self, entity: &Jid, ver: &str) -> Option<Arc<Caps>> {
        if let Some(c) = self.verified.lock().get(ver) {
            return Some(c.clone());
        }
        self.per_entity.lock().get(entity).filter(|(v, _)| v == ver).map(|(_, c)| c.clone())
    }

    /// Looks `ver` up for `waiter`; when unknown, queues the waiter under the query key.
    pub fn lookup(&self, entity: &Jid, ver: &str, hash: Option<&str>, waiter: Waiter) -> Lookup {
        if let Some(c) = self.get(entity, ver) {
            return Lookup::Known(c);
        }
        // Verifiable answers are shared, so one query serves everyone with the same `ver`.
        let key = match hash {
            Some(h) if verifiable(h) => format!("{h}\0{ver}"),
            _ => format!("{entity}\0{ver}"),
        };
        let mut p = self.pending.lock();
        if let Some(w) = p.get_mut(&key) {
            if w.len() < MAX_WAITERS && !w.contains(&waiter) {
                w.push(waiter);
            }
            return Lookup::Queued;
        }
        if p.len() >= MAX_PENDING {
            return Lookup::Busy;
        }
        p.insert(key.clone(), vec![waiter]);
        Lookup::Ask(key)
    }

    /// Stores the answer and hands back who was waiting. Without an answer (a timeout, an
    /// error) nothing is cached, so the entity is asked again with its next presence: a slow
    /// phone must not lose its notifications for good.
    pub fn resolve(&self, key: &str, entity: &Jid, ver: &str, hash: Option<&str>, answer: Option<&Element>) -> (Arc<Caps>, Vec<Waiter>) {
        let waiters = self.pending.lock().remove(key).unwrap_or_default();
        let Some(q) = answer else { return (Arc::new(Caps::default()), Vec::new()) };
        let caps = Arc::new(Caps::from_disco(q));
        if hash.is_some_and(|h| verifiable(h) && verify(q, h, ver)) {
            self.verified.lock().insert(ver.to_string(), caps.clone());
            return (caps, waiters);
        }
        // Unverified: good for this entity only. Others who waited on the same key ask again
        // with their next presence.
        self.per_entity.lock().insert(entity.clone(), (ver.to_string(), caps.clone()));
        let mine = |w: &Waiter| match w {
            Waiter::Local(j) => j == entity,
            Waiter::Remote { entity: e, .. } => e == entity,
        };
        (caps, waiters.into_iter().filter(mine).collect())
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

    #[test]
    fn one_query_per_verifiable_ver() {
        let c = CapsCache::default();
        let a = Jid::parse("a@x/1").unwrap();
        let b = Jid::parse("b@x/1").unwrap();
        let Lookup::Ask(key) = c.lookup(&a, "v", Some("sha-1"), Waiter::Local(a.clone())) else { panic!() };
        assert!(matches!(c.lookup(&b, "v", Some("sha-1"), Waiter::Local(b.clone())), Lookup::Queued));
        // A wrong hash: only the entity that answered gets the (unverified) result.
        let q = Element::parse("<query xmlns='http://jabber.org/protocol/disco#info'><feature var='n+notify'/></query>").unwrap();
        let (caps, waiters) = c.resolve(&key, &a, "v", Some("sha-1"), Some(&q));
        assert!(caps.wants("n"));
        assert_eq!(waiters, vec![Waiter::Local(a.clone())]);
        assert!(c.get(&a, "v").is_some());
        assert!(c.get(&b, "v").is_none());
        // No answer: nothing cached, the next presence asks again.
        let Lookup::Ask(key) = c.lookup(&b, "w", None, Waiter::Local(b.clone())) else { panic!() };
        let (_, waiters) = c.resolve(&key, &b, "w", None, None);
        assert!(waiters.is_empty());
        assert!(matches!(c.lookup(&b, "w", None, Waiter::Local(b.clone())), Lookup::Ask(_)));
    }
}
