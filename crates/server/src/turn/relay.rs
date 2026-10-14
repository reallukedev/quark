//! The relay itself: authentication, allocations, permissions, channels and forwarding.
//!
//! Requests are rare and handled inline; data is the hot path. Client→peer packets arrive on the
//! shared listener (UDP) or the client's connection (TCP) and go straight out of the allocation's
//! socket. Peer→client packets are read by one task per allocation into a buffer with headroom, so
//! the ChannelData or Data indication header is written in front of the payload without copying.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use parking_lot::{Mutex, RwLock};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};

use super::policy::PeerPolicy;
use super::stun::{self, attr, method, Class, Message, Writer, HEADER, MAX_DATA_HEADER};
use crate::config::{TurnQuota, TurnSection};

/// Default and minimum allocation lifetime (RFC 8656 §2.2).
const DEFAULT_LIFETIME: u32 = 600;
const PERMISSION_LIFETIME: Duration = Duration::from_secs(300);
const CHANNEL_LIFETIME: Duration = Duration::from_secs(600);
/// How long a nonce stays fresh. Clients refresh allocations every ~10 minutes, so an hour keeps
/// most refreshes from needing a 438 round trip.
const NONCE_SECS: u64 = 3600;
const MAX_PERMISSIONS: usize = 64;
const MAX_CHANNELS: usize = 64;
/// UDP in, plus headroom for the largest header we put in front.
pub const HEADROOM: usize = MAX_DATA_HEADER;
pub const PACKET_BUF: usize = HEADROOM + 65_535 + 4;
const UDP_TRANSPORT: u8 = 17;

/// Bytes per second unauthenticated UDP answers may exceed their requests by, per source address
/// and in total. STUN answers are a little bigger than requests (a 401 carries a realm and a
/// nonce), so a spoofed source could otherwise be used to amplify traffic towards a victim.
const AMP_PER_IP: (u64, u64) = (1024, 4096);
const AMP_TOTAL: (u64, u64) = (128 * 1024, 256 * 1024);
const AMP_TRACKED: usize = 16_384;

/// Who a client is: its transport and address (the 5-tuple, as our side is fixed per listener).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientKey {
    pub tcp: bool,
    pub addr: SocketAddr,
}

/// How to reach a client.
#[derive(Debug, Clone)]
pub enum ClientTx {
    /// Through the shared UDP listener.
    Udp(Arc<UdpSocket>),
    /// Through the client's TCP connection's writer; full means slow, and packets are dropped.
    Tcp(mpsc::Sender<Bytes>),
}

/// A token bucket in bytes; `rate == 0` means no limit.
#[derive(Debug, Clone, Copy)]
pub struct Bucket {
    rate: u64,
    burst: u64,
    tokens: u64,
    last: Instant,
}

impl Bucket {
    pub fn new(rate: u64, burst: u64, now: Instant) -> Bucket {
        Bucket { rate, burst, tokens: burst, last: now }
    }

    pub fn take(&mut self, n: u64, now: Instant) -> bool {
        if self.rate == 0 {
            return true;
        }
        let add = (now.saturating_duration_since(self.last).as_micros() * u128::from(self.rate) / 1_000_000) as u64;
        if add > 0 {
            self.tokens = self.tokens.saturating_add(add).min(self.burst);
            self.last = now;
        }
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }

    fn is_full(&mut self, now: Instant) -> bool {
        self.take(0, now) && self.tokens >= self.burst
    }
}

fn bandwidth_bucket(q: &TurnQuota, now: Instant) -> Bucket {
    let rate = u64::from(q.kbps) * 125;
    Bucket::new(rate, rate.max(70_000), now)
}

#[derive(Debug)]
struct Channel {
    number: u16,
    peer: SocketAddr,
    expires: Instant,
}

#[derive(Debug)]
struct AllocState {
    expires: Instant,
    permissions: Vec<(IpAddr, Instant)>,
    channels: Vec<Channel>,
    bucket: Bucket,
}

impl AllocState {
    fn permitted(&self, ip: IpAddr, now: Instant) -> bool {
        self.permissions.iter().any(|(p, exp)| *p == ip && *exp > now)
    }

    fn prune(&mut self, now: Instant) {
        self.permissions.retain(|(_, e)| *e > now);
        self.channels.retain(|c| c.expires > now);
    }
}

/// One relayed address.
#[derive(Debug)]
pub struct Allocation {
    client: ClientKey,
    tx: ClientTx,
    pub(super) socket: Arc<UdpSocket>,
    /// The address peers send to (with the external IP when behind NAT).
    relayed: SocketAddr,
    username: Box<str>,
    /// The account part of the username, for the per-account quota.
    user: Box<str>,
    /// The Allocate transaction, so a retransmitted Allocate gets the same answer.
    tid: [u8; 12],
    state: Mutex<AllocState>,
    pub(super) stop: Notify,
}

impl Allocation {
    /// Frames `buf[HEADROOM..HEADROOM + len]`, which came from `peer`, for the client and sends it:
    /// as ChannelData when a channel is bound to the peer, as a Data indication otherwise.
    /// Dropped without a permission or over the bandwidth limit.
    pub(super) fn forward_to_client(&self, buf: &mut [u8], len: usize, peer: SocketAddr, now: Instant) {
        let channel = {
            let mut st = self.state.lock();
            if !st.permitted(peer.ip(), now) || !st.bucket.take(len as u64, now) {
                return;
            }
            st.channels.iter().find(|c| c.peer == peer && c.expires > now).map(|c| c.number)
        };
        let end = HEADROOM + len;
        let (start, total) = match channel {
            Some(ch) => {
                let s = HEADROOM - 4;
                buf[s..s + 2].copy_from_slice(&ch.to_be_bytes());
                buf[s + 2..s + 4].copy_from_slice(&(len as u16).to_be_bytes());
                // ChannelData over TCP is padded to 4 bytes; over UDP padding is optional.
                let pad = if self.client.tcp { (4 - len % 4) % 4 } else { 0 };
                (s, 4 + len + pad)
            }
            // A Data indication's length must fit STUN's 16 bits.
            None if len > 65_000 => return,
            None => {
                let tid: [u8; 12] = rand::random();
                let s = stun::data_indication_header(buf, HEADROOM, &tid, peer, len);
                (s, HEADROOM - s + ((len + 3) & !3))
            }
        };
        buf[end..start + total].fill(0);
        self.send_to_client(&buf[start..start + total]);
    }

    fn send_to_client(&self, pkt: &[u8]) {
        match &self.tx {
            // UDP: a full send buffer drops the packet, as the network would.
            ClientTx::Udp(sock) => {
                let _ = sock.try_send_to(pkt, self.client.addr);
            }
            // TCP: one copy into a shared buffer for the writer task.
            ClientTx::Tcp(tx) => {
                let _ = tx.try_send(Bytes::copy_from_slice(pkt));
            }
        }
    }
}

#[derive(Default)]
struct Tables {
    by_client: HashMap<ClientKey, Arc<Allocation>>,
    by_relay: HashMap<SocketAddr, Arc<Allocation>>,
    per_user: HashMap<Box<str>, usize>,
}

impl Tables {
    fn remove(&mut self, key: &ClientKey) -> Option<Arc<Allocation>> {
        let a = self.by_client.remove(key)?;
        self.by_relay.remove(&a.relayed);
        if let Some(n) = self.per_user.get_mut(&a.user) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.per_user.remove(&a.user);
            }
        }
        a.stop.notify_one();
        Some(a)
    }
}

struct AmpGuard {
    per_ip: Mutex<HashMap<IpAddr, Bucket>>,
    total: Mutex<Bucket>,
}

impl AmpGuard {
    fn allow(&self, ip: IpAddr, excess: usize, now: Instant) -> bool {
        let n = excess as u64;
        {
            let mut m = self.per_ip.lock();
            if m.len() >= AMP_TRACKED && !m.contains_key(&ip) {
                m.retain(|_, b| !b.is_full(now));
                if m.len() >= AMP_TRACKED {
                    return false;
                }
            }
            if !m.entry(ip).or_insert_with(|| Bucket::new(AMP_PER_IP.0, AMP_PER_IP.1, now)).take(n, now) {
                return false;
            }
        }
        self.total.lock().take(n, now)
    }

    fn prune(&self, now: Instant) {
        self.per_ip.lock().retain(|_, b| !b.is_full(now));
    }
}

/// The parts of the config the relay reads per request; swapped on reload.
#[derive(Debug, Clone)]
pub struct Limits {
    pub policy: PeerPolicy,
    pub quota: TurnQuota,
    pub external_ip: Option<IpAddr>,
}

impl Limits {
    pub fn new(t: &TurnSection) -> Limits {
        Limits { policy: PeerPolicy::new(&t.peers), quota: t.quota.clone(), external_ip: t.external_ip }
    }
}

/// What handling a packet produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing to send back.
    Nothing,
    /// `out` holds an answer.
    Reply,
}

/// Why a request failed after authentication (the answer carries MESSAGE-INTEGRITY).
struct Refuse(u16, &'static str);

pub struct Relay {
    secret: Box<str>,
    realm: Box<str>,
    nonce_key: [u8; 32],
    /// The address relay sockets bind to (the listener's, or unspecified).
    bind_ip: IpAddr,
    ports: (u16, u16),
    /// The shared UDP listener, for answering and forwarding to UDP clients.
    pub(super) udp: Arc<UdpSocket>,
    limits: RwLock<Arc<Limits>>,
    tables: Mutex<Tables>,
    /// The server's own addresses that relayed addresses use. Packets to them go to our own
    /// allocations or nowhere, never to other services on the box.
    own_ips: RwLock<Vec<IpAddr>>,
    amp: AmpGuard,
    pub(super) shutdown: tokio::sync::watch::Receiver<bool>,
}

impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relay").field("realm", &self.realm).field("bind_ip", &self.bind_ip).finish_non_exhaustive()
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The long-term key (RFC 8489 §9.2.2): MD5(username ":" realm ":" password).
pub fn long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(username.as_bytes());
    h.update(b":");
    h.update(realm.as_bytes());
    h.update(b":");
    h.update(password.as_bytes());
    h.finalize().into()
}

/// The TURN REST password for a username: base64(HMAC-SHA1(secret, username)).
pub fn rest_password(secret: &str, username: &str) -> String {
    use base64::Engine;
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret.as_bytes()).unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
    mac.update(username.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

impl Relay {
    pub fn new(
        secret: &str,
        realm: &str,
        bind_ip: IpAddr,
        ports: (u16, u16),
        udp: Arc<UdpSocket>,
        limits: Limits,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Relay {
        let mut own = Vec::new();
        if !bind_ip.is_unspecified() {
            own.push(bind_ip);
        }
        if let Some(ip) = limits.external_ip {
            own.push(ip);
        }
        let now = Instant::now();
        Relay {
            secret: secret.into(),
            realm: realm.into(),
            nonce_key: rand::random(),
            bind_ip,
            ports,
            udp,
            limits: RwLock::new(Arc::new(limits)),
            tables: Mutex::new(Tables::default()),
            own_ips: RwLock::new(own),
            amp: AmpGuard { per_ip: Mutex::new(HashMap::new()), total: Mutex::new(Bucket::new(AMP_TOTAL.0, AMP_TOTAL.1, now)) },
            shutdown,
        }
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }

    pub fn realm(&self) -> &str {
        &self.realm
    }

    pub fn set_limits(&self, l: Limits) {
        *self.limits.write() = Arc::new(l);
    }

    /// The longest lifetime a client can be granted, in seconds.
    pub fn max_lifetime(&self) -> u32 {
        self.limits.read().quota.max_lifetime_secs.max(DEFAULT_LIFETIME)
    }

    fn limits(&self) -> Arc<Limits> {
        self.limits.read().clone()
    }

    pub fn allocation_count(&self) -> usize {
        self.tables.lock().by_client.len()
    }

    /// Drops a client's allocation (its TCP connection closed).
    pub fn remove_client(&self, key: &ClientKey) {
        self.tables.lock().remove(key);
    }

    pub fn has_allocation(&self, key: &ClientKey) -> bool {
        self.tables.lock().by_client.contains_key(key)
    }

    /// Removes expired allocations, permissions and channels.
    pub fn sweep(&self, now: Instant) {
        let mut t = self.tables.lock();
        let expired: Vec<ClientKey> = t
            .by_client
            .iter()
            .filter_map(|(k, a)| {
                let mut st = a.state.lock();
                st.prune(now);
                (st.expires <= now).then_some(*k)
            })
            .collect();
        for k in &expired {
            t.remove(k);
        }
        drop(t);
        if !expired.is_empty() {
            tracing::debug!(count = expired.len(), "relay allocations expired");
        }
        self.amp.prune(now);
    }

    /// Removes every allocation (shutdown).
    pub fn clear(&self) {
        let mut t = self.tables.lock();
        let keys: Vec<ClientKey> = t.by_client.keys().copied().collect();
        for k in &keys {
            t.remove(k);
        }
    }

    // ------------------------------------------------------------------ nonces

    fn nonce(&self, ip: IpAddr, now: u64) -> [u8; 24] {
        let exp = (now + NONCE_SECS) as u32;
        let mut out = [0u8; 24];
        let _ = hex::encode_to_slice(exp.to_be_bytes(), &mut out[..8]);
        let _ = hex::encode_to_slice(&self.nonce_mac(exp, ip)[..8], &mut out[8..]);
        out
    }

    fn nonce_mac(&self, exp: u32, ip: IpAddr) -> [u8; 20] {
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&self.nonce_key).unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
        mac.update(&exp.to_be_bytes());
        match ip {
            IpAddr::V4(v) => mac.update(&v.octets()),
            IpAddr::V6(v) => mac.update(&v.octets()),
        }
        mac.finalize().into_bytes().into()
    }

    fn nonce_fresh(&self, nonce: &[u8], ip: IpAddr, now: u64) -> bool {
        if nonce.len() != 24 {
            return false;
        }
        let mut e = [0u8; 4];
        let mut tag = [0u8; 8];
        if hex::decode_to_slice(&nonce[..8], &mut e).is_err() || hex::decode_to_slice(&nonce[8..], &mut tag).is_err() {
            return false;
        }
        let exp = u32::from_be_bytes(e);
        if u64::from(exp) <= now || u64::from(exp) > now + NONCE_SECS + 60 {
            return false;
        }
        self.nonce_mac(exp, ip)[..8].ct_eq(&tag).into()
    }

    // ------------------------------------------------------------------ packets

    /// Handles one packet from a client. Any answer is left in `out`. `tcp_tx` is the client's
    /// connection writer when it came over TCP. `scratch` is a [`PACKET_BUF`]-sized buffer for
    /// relaying to our own allocations.
    pub fn handle(
        &self,
        pkt: &[u8],
        client: ClientKey,
        tcp_tx: Option<&mpsc::Sender<Bytes>>,
        out: &mut Vec<u8>,
        scratch: &mut [u8],
    ) -> Outcome {
        let now = Instant::now();
        if stun::is_channel_data(pkt) {
            if let Some((ch, data)) = stun::parse_channel_data(pkt) {
                self.channel_data(client, ch, data, scratch, now);
            }
            return Outcome::Nothing;
        }
        let Ok(m) = Message::parse(pkt) else { return Outcome::Nothing };
        let authed = match (m.class, m.method) {
            (Class::Request, method::BINDING) => {
                self.binding(&m, client, out);
                false
            }
            (Class::Request, method::ALLOCATE | method::REFRESH | method::CREATE_PERMISSION | method::CHANNEL_BIND) => {
                let Some(key) = self.authenticate(&m, client.addr.ip(), out) else {
                    return self.unauthenticated(pkt.len(), client, out, now);
                };
                let username = m.str_attr(attr::USERNAME).unwrap_or_default();
                let r = match m.method {
                    method::ALLOCATE => self.allocate(&m, client, tcp_tx, username, &key, out, now),
                    method::REFRESH => self.refresh(&m, client, username, &key, out, now),
                    method::CREATE_PERMISSION => self.create_permission(&m, client, username, &key, out, now),
                    _ => self.channel_bind(&m, client, username, &key, out, now),
                };
                if let Err(Refuse(code, reason)) = r {
                    let mut w = Writer::new(out, m.method, Class::Error, m.tid);
                    w.error(code, reason);
                    finish(&mut w, &m, Some(&key));
                }
                true
            }
            (Class::Indication, method::SEND) => {
                self.send_indication(&m, client, scratch, now);
                return Outcome::Nothing;
            }
            (Class::Request, _) => {
                let mut w = Writer::new(out, m.method, Class::Error, m.tid);
                w.error(400, "Bad Request");
                finish(&mut w, &m, None);
                false
            }
            _ => return Outcome::Nothing,
        };
        if authed {
            Outcome::Reply
        } else {
            self.unauthenticated(pkt.len(), client, out, now)
        }
    }

    /// An answer to an unauthenticated request: over UDP, only within the amplification budget.
    fn unauthenticated(&self, req_len: usize, client: ClientKey, out: &[u8], now: Instant) -> Outcome {
        if out.is_empty() {
            return Outcome::Nothing;
        }
        if client.tcp || out.len() <= req_len || self.amp.allow(client.addr.ip(), out.len() - req_len, now) {
            Outcome::Reply
        } else {
            Outcome::Nothing
        }
    }

    fn binding(&self, m: &Message, client: ClientKey, out: &mut Vec<u8>) {
        let (unknown, n) = m.unknown_required(KNOWN_BINDING);
        let mut w = if n > 0 {
            let mut w = Writer::new(out, method::BINDING, Class::Error, m.tid);
            w.error(420, "Unknown Attribute").unknown(&unknown[..n]);
            w
        } else {
            let mut w = Writer::new(out, method::BINDING, Class::Success, m.tid);
            w.xor_addr(attr::XOR_MAPPED_ADDRESS, client.addr);
            w
        };
        // Nothing else: an unauthenticated answer stays as small as it can be.
        finish(&mut w, m, None);
    }

    /// Checks the long-term credentials (RFC 8489 §9.2.4). On failure `out` holds the challenge
    /// or error, without MESSAGE-INTEGRITY.
    fn authenticate(&self, m: &Message, ip: IpAddr, out: &mut Vec<u8>) -> Option<[u8; 16]> {
        let now = now_secs();
        let challenge = |out: &mut Vec<u8>, code: u16, reason: &str| {
            let nonce = self.nonce(ip, now);
            let mut w = Writer::new(out, m.method, Class::Error, m.tid);
            w.error(code, reason).attr(attr::REALM, self.realm.as_bytes()).attr(attr::NONCE, &nonce);
            finish(&mut w, m, None);
        };
        if !m.has_integrity() {
            challenge(out, 401, "Unauthorized");
            return None;
        }
        let (Some(username), Some(realm), Some(nonce)) = (m.str_attr(attr::USERNAME), m.str_attr(attr::REALM), m.get(attr::NONCE)) else {
            let mut w = Writer::new(out, m.method, Class::Error, m.tid);
            w.error(400, "Bad Request");
            finish(&mut w, m, None);
            return None;
        };
        if !self.nonce_fresh(nonce, ip, now) {
            challenge(out, 438, "Stale Nonce");
            return None;
        }
        let expiry = username.split_once(':').map_or(username, |(e, _)| e).parse::<u64>().ok();
        if realm != &*self.realm || expiry.is_none_or(|e| e <= now) {
            challenge(out, 401, "Unauthorized");
            return None;
        }
        let key = long_term_key(username, &self.realm, &rest_password(&self.secret, username));
        if !m.check_integrity(&key) {
            challenge(out, 401, "Unauthorized");
            return None;
        }
        Some(key)
    }

    fn own_allocation(&self, client: ClientKey, username: &str) -> Result<Arc<Allocation>, Refuse> {
        let a = self.tables.lock().by_client.get(&client).cloned().ok_or(Refuse(437, "Allocation Mismatch"))?;
        if &*a.username != username {
            return Err(Refuse(441, "Wrong Credentials"));
        }
        Ok(a)
    }

    #[allow(clippy::too_many_arguments)]
    fn allocate(
        &self,
        m: &Message,
        client: ClientKey,
        tcp_tx: Option<&mpsc::Sender<Bytes>>,
        username: &str,
        key: &[u8; 16],
        out: &mut Vec<u8>,
        now: Instant,
    ) -> Result<(), Refuse> {
        let existing = self.tables.lock().by_client.get(&client).cloned();
        if let Some(a) = existing {
            // A retransmitted Allocate gets the same answer; anything else is a mismatch.
            if a.tid != m.tid || &*a.username != username {
                return Err(Refuse(437, "Allocation Mismatch"));
            }
            let left = a.state.lock().expires.saturating_duration_since(now).as_secs() as u32;
            allocate_success(out, m, key, a.relayed, client.addr, left);
            return Ok(());
        }
        let (unknown, n) = m.unknown_required(KNOWN_TURN);
        if n > 0 {
            let mut w = Writer::new(out, m.method, Class::Error, m.tid);
            w.error(420, "Unknown Attribute").unknown(&unknown[..n]);
            finish(&mut w, m, Some(key));
            return Ok(());
        }
        match m.get(attr::REQUESTED_TRANSPORT) {
            Some(v) if v.first() == Some(&UDP_TRANSPORT) => {}
            Some(_) => return Err(Refuse(442, "Unsupported Transport Protocol")),
            None => return Err(Refuse(400, "Bad Request")),
        }
        let v6 = match m.get(attr::REQUESTED_ADDRESS_FAMILY).map(|v| v.first().copied()) {
            None | Some(Some(0x01)) => false,
            Some(Some(0x02)) => true,
            Some(_) => return Err(Refuse(440, "Address Family not Supported")),
        };
        let limits = self.limits();
        let user: Box<str> = username.split_once(':').map_or("", |(_, u)| u).into();
        {
            let t = self.tables.lock();
            if t.by_client.len() >= limits.quota.allocations
                || t.per_user.get(&user).copied().unwrap_or(0) >= limits.quota.allocations_per_user
            {
                return Err(Refuse(486, "Allocation Quota Reached"));
            }
        }
        let lifetime = lifetime(m, &limits.quota);
        let even = m.has(attr::EVEN_PORT);
        let (socket, local) = self.bind_relay(v6, even)?;
        let relayed = SocketAddr::new(self.advertised_ip(v6, client.addr, &limits)?, local.port());
        let tx = match tcp_tx {
            Some(tx) => ClientTx::Tcp(tx.clone()),
            None => ClientTx::Udp(self.udp.clone()),
        };
        let a = Arc::new(Allocation {
            client,
            tx,
            socket: Arc::new(socket),
            relayed,
            username: username.into(),
            user: user.clone(),
            tid: m.tid,
            state: Mutex::new(AllocState {
                expires: now + Duration::from_secs(u64::from(lifetime)),
                permissions: Vec::new(),
                channels: Vec::new(),
                bucket: bandwidth_bucket(&limits.quota, now),
            }),
            stop: Notify::new(),
        });
        {
            let mut t = self.tables.lock();
            // Checked again: another request may have raced us between the locks.
            if t.by_client.contains_key(&client) {
                return Err(Refuse(437, "Allocation Mismatch"));
            }
            t.by_client.insert(client, a.clone());
            t.by_relay.insert(relayed, a.clone());
            *t.per_user.entry(user).or_insert(0) += 1;
        }
        {
            let mut own = self.own_ips.write();
            if !own.contains(&relayed.ip()) {
                own.push(relayed.ip());
            }
        }
        tracing::debug!(client = %client.addr, tcp = client.tcp, relayed = %relayed, "relay allocation created");
        super::io::spawn_allocation(self.shutdown.clone(), a);
        allocate_success(out, m, key, relayed, client.addr, lifetime);
        Ok(())
    }

    /// Binds a relay socket on a free port in the configured range, starting at a random one.
    fn bind_relay(&self, v6: bool, even: bool) -> Result<(UdpSocket, SocketAddr), Refuse> {
        let ip = match (self.bind_ip, v6) {
            (IpAddr::V4(ip), false) => IpAddr::V4(ip),
            (IpAddr::V6(ip), true) => IpAddr::V6(ip),
            (IpAddr::V4(ip), true) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            (IpAddr::V6(ip), false) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            _ => return Err(Refuse(440, "Address Family not Supported")),
        };
        let (lo, hi) = self.ports;
        let span = u32::from(hi - lo) + 1;
        let start = rand::random::<u32>() % span;
        for i in 0..span {
            let port = lo + ((start + i) % span) as u16;
            if even && port % 2 == 1 {
                continue;
            }
            if let Ok(s) = bind_udp(SocketAddr::new(ip, port)) {
                let local = s.local_addr().map_err(|_| Refuse(500, "Server Error"))?;
                return Ok((s, local));
            }
        }
        tracing::warn!(min = lo, max = hi, "no free relay ports; widen turn.relay_min..turn.relay_max");
        Err(Refuse(508, "Insufficient Capacity"))
    }

    /// The IP peers reach a new relayed address at: the configured external IP, the address we
    /// bind to, or the one the system would use to reach the client.
    fn advertised_ip(&self, v6: bool, client: SocketAddr, limits: &Limits) -> Result<IpAddr, Refuse> {
        if let Some(ip) = limits.external_ip.filter(|ip| ip.is_ipv6() == v6) {
            return Ok(ip);
        }
        if !self.bind_ip.is_unspecified() && self.bind_ip.is_ipv6() == v6 {
            return Ok(self.bind_ip);
        }
        let target = if client.is_ipv6() == v6 {
            client
        } else if v6 {
            SocketAddr::from(([0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888], 53))
        } else {
            SocketAddr::from(([8, 8, 8, 8], 53))
        };
        let probe = std::net::UdpSocket::bind(if v6 {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        })
        .and_then(|s| s.connect(target).and_then(|_| s.local_addr()));
        match probe {
            Ok(a) if !a.ip().is_unspecified() => Ok(a.ip()),
            _ => Err(Refuse(440, "Address Family not Supported")),
        }
    }

    fn refresh(
        &self,
        m: &Message,
        client: ClientKey,
        username: &str,
        key: &[u8; 16],
        out: &mut Vec<u8>,
        now: Instant,
    ) -> Result<(), Refuse> {
        let a = self.own_allocation(client, username)?;
        if let Some(f) = m.get(attr::REQUESTED_ADDRESS_FAMILY).and_then(|v| v.first().copied()) {
            if (f == 0x02) != a.relayed.is_ipv6() {
                return Err(Refuse(443, "Peer Address Family Mismatch"));
            }
        }
        let limits = self.limits();
        let granted = if m.u32_attr(attr::LIFETIME) == Some(0) {
            self.tables.lock().remove(&client);
            tracing::debug!(client = %client.addr, "relay allocation released");
            0
        } else {
            let l = lifetime(m, &limits.quota);
            a.state.lock().expires = now + Duration::from_secs(u64::from(l));
            l
        };
        let mut w = Writer::new(out, method::REFRESH, Class::Success, m.tid);
        w.u32(attr::LIFETIME, granted);
        finish(&mut w, m, Some(key));
        Ok(())
    }

    /// Whether a client may talk to `ip`: the policy allows it, or it's one of our own relayed
    /// addresses (two callers on the same relay).
    fn peer_allowed(&self, ip: IpAddr, limits: &Limits) -> bool {
        limits.policy.allows(ip) || self.own_ips.read().contains(&ip)
    }

    fn create_permission(
        &self,
        m: &Message,
        client: ClientKey,
        username: &str,
        key: &[u8; 16],
        out: &mut Vec<u8>,
        now: Instant,
    ) -> Result<(), Refuse> {
        let a = self.own_allocation(client, username)?;
        let limits = self.limits();
        let mut peers = [IpAddr::V4(Ipv4Addr::UNSPECIFIED); 8];
        let mut n = 0;
        for p in m.xor_addrs(attr::XOR_PEER_ADDRESS) {
            let p = p.ok_or(Refuse(400, "Bad Request"))?;
            if p.is_ipv6() != a.relayed.is_ipv6() {
                return Err(Refuse(443, "Peer Address Family Mismatch"));
            }
            if !self.peer_allowed(p.ip(), &limits) {
                return Err(Refuse(403, "Forbidden"));
            }
            if n == peers.len() {
                return Err(Refuse(508, "Insufficient Capacity"));
            }
            peers[n] = p.ip();
            n += 1;
        }
        if n == 0 {
            return Err(Refuse(400, "Bad Request"));
        }
        {
            let mut st = a.state.lock();
            st.prune(now);
            for ip in &peers[..n] {
                permit(&mut st, *ip, now)?;
            }
        }
        let mut w = Writer::new(out, method::CREATE_PERMISSION, Class::Success, m.tid);
        finish(&mut w, m, Some(key));
        Ok(())
    }

    fn channel_bind(
        &self,
        m: &Message,
        client: ClientKey,
        username: &str,
        key: &[u8; 16],
        out: &mut Vec<u8>,
        now: Instant,
    ) -> Result<(), Refuse> {
        let a = self.own_allocation(client, username)?;
        let number = m.u32_attr(attr::CHANNEL_NUMBER).map(|v| (v >> 16) as u16).filter(|n| (0x4000..=0x4FFF).contains(n));
        let (Some(number), Some(peer)) = (number, m.xor_addr(attr::XOR_PEER_ADDRESS)) else {
            return Err(Refuse(400, "Bad Request"));
        };
        if peer.is_ipv6() != a.relayed.is_ipv6() {
            return Err(Refuse(443, "Peer Address Family Mismatch"));
        }
        if !self.peer_allowed(peer.ip(), &self.limits()) {
            return Err(Refuse(403, "Forbidden"));
        }
        {
            let mut st = a.state.lock();
            st.prune(now);
            let expires = now + CHANNEL_LIFETIME;
            let at = st.channels.iter().position(|c| c.number == number || c.peer == peer);
            match at {
                Some(i) if st.channels[i].number == number && st.channels[i].peer == peer => {}
                // The number is taken by another peer, or the peer has another number.
                Some(_) => return Err(Refuse(400, "Bad Request")),
                None if st.channels.len() >= MAX_CHANNELS => return Err(Refuse(508, "Insufficient Capacity")),
                None => {}
            }
            // The binding also installs or refreshes the peer's permission.
            permit(&mut st, peer.ip(), now)?;
            match at {
                Some(i) => st.channels[i].expires = expires,
                None => st.channels.push(Channel { number, peer, expires }),
            }
        }
        let mut w = Writer::new(out, method::CHANNEL_BIND, Class::Success, m.tid);
        finish(&mut w, m, Some(key));
        Ok(())
    }

    fn send_indication(&self, m: &Message, client: ClientKey, scratch: &mut [u8], now: Instant) {
        let (Some(peer), Some(data)) = (m.xor_addr(attr::XOR_PEER_ADDRESS), m.get(attr::DATA)) else { return };
        let Some(a) = self.tables.lock().by_client.get(&client).cloned() else { return };
        {
            let mut st = a.state.lock();
            if !st.permitted(peer.ip(), now) || !st.bucket.take(data.len() as u64, now) {
                return;
            }
        }
        self.to_peer(&a, peer, data, scratch, now);
    }

    fn channel_data(&self, client: ClientKey, ch: u16, data: &[u8], scratch: &mut [u8], now: Instant) {
        let Some(a) = self.tables.lock().by_client.get(&client).cloned() else { return };
        let peer = {
            let mut st = a.state.lock();
            let Some(peer) = st.channels.iter().find(|c| c.number == ch && c.expires > now).map(|c| c.peer) else { return };
            if !st.bucket.take(data.len() as u64, now) {
                return;
            }
            peer
        };
        self.to_peer(&a, peer, data, scratch, now);
    }

    /// Sends client data to a peer. A peer that is another of our relayed addresses gets it
    /// directly (no hairpin through the NAT); other addresses of this server get nothing.
    fn to_peer(&self, from: &Allocation, peer: SocketAddr, data: &[u8], scratch: &mut [u8], now: Instant) {
        if self.own_ips.read().contains(&peer.ip()) {
            let target = self.tables.lock().by_relay.get(&peer).cloned();
            match target {
                Some(t) if data.len() + HEADROOM + 4 <= scratch.len() => {
                    scratch[HEADROOM..HEADROOM + data.len()].copy_from_slice(data);
                    t.forward_to_client(scratch, data.len(), from.relayed, now);
                    return;
                }
                Some(_) => return,
                None if !self.limits().policy.explicitly_allows(peer.ip()) => return,
                None => {}
            }
        }
        let _ = from.socket.try_send_to(data, peer);
    }
}

/// Attributes we understand in TURN requests.
const KNOWN_TURN: &[u16] = &[
    attr::USERNAME,
    attr::MESSAGE_INTEGRITY,
    attr::MESSAGE_INTEGRITY_SHA256,
    attr::REALM,
    attr::NONCE,
    attr::LIFETIME,
    attr::REQUESTED_TRANSPORT,
    attr::REQUESTED_ADDRESS_FAMILY,
    // Honoured as far as we can: we can't set DF on every platform, and peers rarely care.
    attr::DONT_FRAGMENT,
    attr::EVEN_PORT,
    attr::XOR_PEER_ADDRESS,
    attr::CHANNEL_NUMBER,
    attr::DATA,
];

/// Attributes we understand in Binding requests (ICE checks carry these).
const KNOWN_BINDING: &[u16] =
    &[attr::USERNAME, attr::MESSAGE_INTEGRITY, attr::MESSAGE_INTEGRITY_SHA256, attr::PRIORITY, attr::USE_CANDIDATE, attr::MAPPED_ADDRESS];

fn permit(st: &mut AllocState, ip: IpAddr, now: Instant) -> Result<(), Refuse> {
    let exp = now + PERMISSION_LIFETIME;
    match st.permissions.iter().position(|(p, _)| *p == ip) {
        Some(i) => st.permissions[i].1 = exp,
        None if st.permissions.len() >= MAX_PERMISSIONS => return Err(Refuse(508, "Insufficient Capacity")),
        None => st.permissions.push((ip, exp)),
    }
    Ok(())
}

/// The lifetime to grant (RFC 8656 §7.2): what was asked, within the default and the maximum.
fn lifetime(m: &Message, q: &TurnQuota) -> u32 {
    let max = q.max_lifetime_secs.max(DEFAULT_LIFETIME);
    m.u32_attr(attr::LIFETIME).map_or(DEFAULT_LIFETIME, |l| l.clamp(DEFAULT_LIFETIME, max))
}

fn allocate_success(out: &mut Vec<u8>, m: &Message, key: &[u8; 16], relayed: SocketAddr, mapped: SocketAddr, lifetime: u32) {
    let mut w = Writer::new(out, method::ALLOCATE, Class::Success, m.tid);
    w.xor_addr(attr::XOR_RELAYED_ADDRESS, relayed).u32(attr::LIFETIME, lifetime).xor_addr(attr::XOR_MAPPED_ADDRESS, mapped);
    finish(&mut w, m, Some(key));
}

/// Adds MESSAGE-INTEGRITY for authenticated answers, and FINGERPRINT when the request had one.
fn finish(w: &mut Writer, m: &Message, key: Option<&[u8; 16]>) {
    if let Some(k) = key {
        w.integrity(k);
    }
    if m.has_fingerprint {
        w.fingerprint();
    }
}

/// A non-blocking UDP socket for tokio. IPv6 sockets are IPv6 only, so the policy sees the
/// families it expects.
pub fn bind_udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let s = socket2::Socket::new(socket2::Domain::for_address(addr), socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if addr.is_ipv6() {
        s.set_only_v6(true)?;
    }
    s.set_nonblocking(true)?;
    s.bind(&addr.into())?;
    UdpSocket::from_std(s.into())
}

#[allow(dead_code)]
const _: () = assert!(HEADROOM >= HEADER + 4);

#[cfg(test)]
mod tests {
    use super::*;

    async fn relay() -> Relay {
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut t = TurnSection::default();
        t.peers.allow_loopback = true;
        let (_tx, rx) = tokio::sync::watch::channel(false);
        Relay::new("s3cret", "quark.test", "127.0.0.1".parse().unwrap(), (49152, 65535), udp, Limits::new(&t), rx)
    }

    #[test]
    fn rest_password_matches_coturn() {
        // coturn's use-auth-secret: base64(hmac-sha1(static-auth-secret, "expiry:user")); the
        // expected value is from Python's hmac module.
        assert_eq!(rest_password("north", "1433895918:alice"), "RqMvcGPYTJMGThVLSi4amT4zFtI=");
    }

    #[test]
    fn long_term_key_is_md5_of_user_realm_password() {
        // The RFC 5769 §2.4 credentials; the expected digest is from Python's hashlib.
        let k = long_term_key("\u{30DE}\u{30C8}\u{30EA}\u{30C3}\u{30AF}\u{30B9}", "example.org", "TheMatrIX");
        assert_eq!(hex::encode(k), "e8ca7ad59d5eb0518e312911d2dab2a9");
    }

    #[tokio::test]
    async fn nonces_are_bound_to_the_address_and_expire() {
        let r = relay().await;
        let ip: IpAddr = "192.0.2.5".parse().unwrap();
        let now = 1_000_000;
        let n = r.nonce(ip, now);
        assert!(r.nonce_fresh(&n, ip, now));
        assert!(!r.nonce_fresh(&n, "192.0.2.6".parse().unwrap(), now));
        assert!(!r.nonce_fresh(&n, ip, now + NONCE_SECS + 1));
        let mut forged = n;
        forged[23] = if forged[23] == b'0' { b'1' } else { b'0' };
        assert!(!r.nonce_fresh(&forged, ip, now));
        assert!(!r.nonce_fresh(b"short", ip, now));
    }

    #[test]
    fn buckets_refill_over_time_and_cap_at_burst() {
        let t0 = Instant::now();
        let mut b = Bucket::new(1000, 2000, t0);
        assert!(b.take(2000, t0));
        assert!(!b.take(1, t0));
        assert!(b.take(500, t0 + Duration::from_millis(500)));
        assert!(!b.take(2001, t0 + Duration::from_secs(100)));
        assert!(Bucket::new(0, 0, t0).take(u64::MAX, t0));
    }

    #[tokio::test]
    async fn amplification_budget_runs_out_per_source() {
        let r = relay().await;
        let now = Instant::now();
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let mut sent = 0;
        while r.amp.allow(ip, 80, now) {
            sent += 80;
            assert!(sent <= AMP_PER_IP.1 as usize);
        }
        assert!(r.amp.allow("198.51.100.2".parse().unwrap(), 80, now));
    }

    #[tokio::test]
    async fn unauthenticated_allocate_gets_a_challenge_no_bigger_than_needed() {
        let r = relay().await;
        let mut req = Vec::new();
        Writer::new(&mut req, method::ALLOCATE, Class::Request, [7; 12]).attr(attr::REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
        let (mut out, mut scratch) = (Vec::new(), vec![0u8; PACKET_BUF]);
        let client = ClientKey { tcp: false, addr: "203.0.113.9:5000".parse().unwrap() };
        assert_eq!(r.handle(&req, client, None, &mut out, &mut scratch), Outcome::Reply);
        let m = Message::parse(&out).unwrap();
        assert_eq!(m.class, Class::Error);
        assert_eq!(m.get(attr::ERROR_CODE).unwrap()[2..4], [4, 1]);
        assert_eq!(m.str_attr(attr::REALM), Some("quark.test"));
        assert!(!m.has_integrity());
    }

    #[tokio::test]
    async fn garbage_and_responses_are_ignored() {
        let r = relay().await;
        let (mut out, mut scratch) = (Vec::new(), vec![0u8; PACKET_BUF]);
        let client = ClientKey { tcp: false, addr: "203.0.113.9:5000".parse().unwrap() };
        for pkt in [&b"hello"[..], &[0x40, 0, 0, 1, 9][..], &[0xFF; 40][..]] {
            assert_eq!(r.handle(pkt, client, None, &mut out, &mut scratch), Outcome::Nothing);
        }
        let mut resp = Vec::new();
        Writer::new(&mut resp, method::BINDING, Class::Success, [1; 12]);
        assert_eq!(r.handle(&resp, client, None, &mut out, &mut scratch), Outcome::Nothing);
    }
}
