//! Signed-in client sessions, by account. Each session is an actor (see `c2s::session`); this
//! registry holds a handle to send it stanzas and the state other parts of the server read.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use quark_core::{Element, Jid};
use tokio::sync::mpsc;

use crate::c2s::session::SessionMsg;

/// Facts about a connection, fixed at sign-in.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub ip: Option<IpAddr>,
    pub secure: bool,
    /// When the session started, ms since the epoch.
    pub since: i64,
    /// "tcp" or "websocket".
    pub transport: &'static str,
    /// The client's software, from SASL2 `<user-agent>` or the resource.
    pub client: Option<String>,
}

/// What other parts of the server need to know about a session right now.
#[derive(Debug, Default, Clone)]
pub struct Presence {
    /// Sent initial presence and not gone unavailable since.
    pub available: bool,
    pub priority: i8,
    /// The last available presence broadcast, with `from` set.
    pub last: Option<Element>,
    /// Asked for the roster (RFC 6121 §2.1.6 "interested resource").
    pub interested: bool,
    /// JIDs sent directed presence, owed an unavailable when the session ends.
    pub directed: HashSet<Jid>,
    /// XEP-0115 caps `ver` and `node`, for PEP notifications.
    pub caps: Option<(String, String)>,
}

#[derive(Debug, Default)]
pub struct Flags {
    pub carbons: bool,
    /// Client State Indication: the app is in the background.
    pub inactive: bool,
    /// Stream management enabled with resumption.
    pub resumable: bool,
    /// The connection dropped and the session waits to be resumed.
    pub hibernating: bool,
    /// XEP-0198 resumption id.
    pub smid: Option<String>,
}

pub struct SessionHandle {
    pub id: u64,
    pub jid: Jid,
    pub info: SessionInfo,
    tx: mpsc::UnboundedSender<SessionMsg>,
    queued: Arc<AtomicUsize>,
    max_queue: usize,
    pub presence: Mutex<Presence>,
    pub flags: Mutex<Flags>,
}

impl std::fmt::Debug for SessionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionHandle").field("jid", &self.jid).finish_non_exhaustive()
    }
}

impl SessionHandle {
    pub fn new(jid: Jid, info: SessionInfo, tx: mpsc::UnboundedSender<SessionMsg>, queued: Arc<AtomicUsize>, max_queue: usize) -> Self {
        static IDS: AtomicU64 = AtomicU64::new(1);
        SessionHandle {
            id: IDS.fetch_add(1, Ordering::Relaxed),
            jid,
            info,
            tx,
            queued,
            max_queue,
            presence: Mutex::new(Presence::default()),
            flags: Mutex::new(Flags::default()),
        }
    }

    /// Queues a stanza for the client. A client that stops reading is cut off once its queue
    /// passes the limit, instead of letting memory grow.
    pub fn send(&self, el: Element) -> bool {
        let n = self.queued.fetch_add(1, Ordering::Relaxed);
        if n >= self.max_queue {
            self.queued.fetch_sub(1, Ordering::Relaxed);
            let _ = self.tx.send(SessionMsg::Close {
                condition: "policy-violation",
                text: Some("Too many stanzas waiting; the connection is too slow.".into()),
            });
            return false;
        }
        if self.tx.send(SessionMsg::Deliver(el)).is_err() {
            self.queued.fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    pub fn close(&self, condition: &'static str, text: Option<String>) {
        let _ = self.tx.send(SessionMsg::Close { condition, text });
    }

    pub(crate) fn post(&self, m: SessionMsg) -> bool {
        self.tx.send(m).is_ok()
    }

    /// The last available presence it broadcast (the lock is released before returning, so this
    /// is safe to use across awaits).
    pub fn last_presence(&self) -> Option<Element> {
        self.presence.lock().last.clone()
    }

    pub fn available(&self) -> bool {
        self.presence.lock().available
    }

    pub fn priority(&self) -> i8 {
        self.presence.lock().priority
    }

    pub fn carbons(&self) -> bool {
        self.flags.lock().carbons
    }
}

/// All sessions, by bare JID.
#[derive(Default)]
pub struct Sessions {
    by_bare: RwLock<HashMap<Jid, Vec<Arc<SessionHandle>>>>,
    by_smid: RwLock<HashMap<String, Arc<SessionHandle>>>,
}

impl Sessions {
    /// Adds a session. If the resource is taken, the old session is returned so the caller can
    /// close it (RFC 6120 §7.7.2.2: the newer one wins).
    pub fn add(&self, s: Arc<SessionHandle>) -> Option<Arc<SessionHandle>> {
        let mut map = self.by_bare.write();
        let list = map.entry(s.jid.to_bare()).or_default();
        let old = list.iter().position(|x| x.jid == s.jid).map(|i| list.swap_remove(i));
        list.push(s);
        old
    }

    /// Removes this exact session (not a newer one with the same resource).
    pub fn remove(&self, s: &SessionHandle) {
        let mut map = self.by_bare.write();
        let bare = s.jid.to_bare();
        if let Some(list) = map.get_mut(&bare) {
            list.retain(|x| x.id != s.id);
            if list.is_empty() {
                map.remove(&bare);
            }
        }
        drop(map);
        if let Some(id) = s.flags.lock().smid.clone() {
            let mut m = self.by_smid.write();
            if m.get(&id).is_some_and(|x| x.id == s.id) {
                m.remove(&id);
            }
        }
    }

    pub fn register_smid(&self, id: &str, s: Arc<SessionHandle>) {
        self.by_smid.write().insert(id.to_string(), s);
    }

    pub fn by_smid(&self, id: &str) -> Option<Arc<SessionHandle>> {
        self.by_smid.read().get(id).cloned()
    }

    pub fn get(&self, full: &Jid) -> Option<Arc<SessionHandle>> {
        self.by_bare.read().get(&full.to_bare())?.iter().find(|s| s.jid == *full).cloned()
    }

    /// All sessions of an account.
    pub fn of(&self, bare: &Jid) -> Vec<Arc<SessionHandle>> {
        self.by_bare.read().get(bare).cloned().unwrap_or_default()
    }

    pub fn count_of(&self, bare: &Jid) -> usize {
        self.by_bare.read().get(bare).map_or(0, Vec::len)
    }

    /// Sessions that sent available presence.
    pub fn available_of(&self, bare: &Jid) -> Vec<Arc<SessionHandle>> {
        self.of(bare).into_iter().filter(|s| s.available()).collect()
    }

    pub fn is_online(&self, bare: &Jid) -> bool {
        self.by_bare.read().contains_key(bare)
    }

    /// Every session on a domain.
    pub fn on_host(&self, domain: &str) -> Vec<Arc<SessionHandle>> {
        self.by_bare.read().iter().filter(|(j, _)| j.domain() == domain).flat_map(|(_, v)| v.iter().cloned()).collect()
    }

    pub fn total(&self) -> usize {
        self.by_bare.read().values().map(Vec::len).sum()
    }
}
