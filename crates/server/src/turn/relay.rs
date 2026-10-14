//! The relay itself: authentication, allocations, permissions, channels and forwarding.
//!
//! Requests are rare and handled inline; data is the hot path. Client→peer packets arrive on the
//! shared listener (UDP) or the client's connection (TCP) and go straight out of the allocation's
//! socket. Peer→client packets are read by one task per allocation into a buffer with headroom, so
//! the ChannelData or Data indication header is written in front of the payload without copying.
//!
//! The hot path takes no relay-wide lock: allocations are found in sharded maps (by the client's
//! 5-tuple, or by relayed port for traffic between two of our own allocations), each allocation
//! guards its own state, and the config and the server's own addresses are lock-free snapshots.
//! Only making and ending allocations touches the shared quota book.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use bytes::Bytes;
use dashmap::DashMap;
use hmac::Mac;
use md5::{Digest, Md5};
use parking_lot::Mutex;
use subtle::ConstantTimeEq;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};

use super::policy::{canonical, PeerPolicy};
use super::stun::{self, attr, hmac_sha1, method, Class, Message, Writer, HEADER, MAX_DATA_HEADER};
use crate::config::{TurnQuota, TurnSection};

/// Default and minimum allocation lifetime (RFC 8656 §2.2).
const DEFAULT_LIFETIME: u32 = 600;
/// How long an allocation lives without ever getting a permission. Clients allocate on every
/// call while gathering candidates and most of those are never used; this hands their ports
/// back well before the granted lifetime, while leaving time for the other side to answer.
const UNUSED_LIFETIME: Duration = Duration::from_secs(180);
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

/// Bytes per second unauthenticated UDP answers may exceed their requests by. STUN answers are a
/// little bigger than requests (a 401 carries a realm and a nonce), so a spoofed source could
/// otherwise be used to amplify traffic towards a victim. Each source (see [`source_prefix`]) has
/// its own budget, all of them share one, and a reserve on top of that is kept for sources that
/// recently proved they're real (an authenticated request), so a flood from many sources can't
/// stop returning users from getting their challenges.
const AMP_PER_SOURCE: (u64, u64) = (1024, 4096);
const AMP_SHARED: (u64, u64) = (96 * 1024, 192 * 1024);
const AMP_RESERVE: (u64, u64) = (32 * 1024, 64 * 1024);
const AMP_TRACKED: usize = 16_384;

/// Who a client is: its transport and address (the 5-tuple, as our side is fixed per listener).
/// The address is as the socket reports it (IPv4-mapped on a dual-stack listener), so answers go
/// back the way the request came; [`ClientKey::ip`] is the address it really has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientKey {
    pub tcp: bool,
    pub addr: SocketAddr,
}

impl ClientKey {
    /// The client's address with any IPv4-mapped spelling undone, for answers and policy.
    pub fn unmapped(&self) -> SocketAddr {
        SocketAddr::new(canonical_mapped(self.addr.ip()), self.addr.port())
    }

    fn ip(&self) -> IpAddr {
        canonical_mapped(self.addr.ip())
    }
}

/// `::ffff:a.b.c.d` as `a.b.c.d`. Only the mapped form: on a dual-stack socket that's how IPv4
/// clients show up, while NAT64 addresses are real IPv6 clients.
fn canonical_mapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

/// The unit one sender controls: an IPv4 address, or an IPv6 /64 (one subscriber's network, in
/// which addresses are free to rotate).
pub(super) fn source_prefix(ip: IpAddr) -> IpAddr {
    match canonical_mapped(ip) {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !u128::from(u64::MAX))),
        v4 => v4,
    }
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
    /// Whether a permission was ever installed; until then [`UNUSED_LIFETIME`] applies.
    used: bool,
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

/// Where a relayed address is bound: its family and port. Relay sockets listen on every address
/// of the family, so this is what a packet to any of the server's own addresses reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RelayPort {
    v6: bool,
    port: u16,
}

impl RelayPort {
    fn of(a: SocketAddr) -> RelayPort {
        RelayPort { v6: canonical(a.ip()).is_ipv6(), port: a.port() }
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
    created: Instant,
    state: Mutex<AllocState>,
    /// Set when its socket stopped working; the sweeper then ends it.
    dead: AtomicBool,
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

    /// Marks the allocation broken (its socket keeps failing), for the sweeper to end.
    pub(super) fn fail(&self) {
        self.dead.store(true, Ordering::Relaxed);
    }

    fn relay_port(&self) -> RelayPort {
        RelayPort::of(self.relayed)
    }
}

/// The quota book: who holds an allocation (or is getting one) and how many each account has.
/// Checking and reserving happen under one lock, so racing requests can't both squeeze in.
#[derive(Debug, Default)]
struct Registry {
    clients: HashSet<ClientKey>,
    per_user: HashMap<Box<str>, usize>,
}

impl Registry {
    fn reserve(&mut self, client: ClientKey, user: &str, total: usize, per_user: usize) -> Result<(), Refuse> {
        if self.clients.contains(&client) {
            return Err(Refuse(437, "Allocation Mismatch"));
        }
        if self.clients.len() >= total || self.per_user.get(user).copied().unwrap_or(0) >= per_user {
            return Err(Refuse(486, "Allocation Quota Reached"));
        }
        self.clients.insert(client);
        *self.per_user.entry(user.into()).or_insert(0) += 1;
        Ok(())
    }

    fn release(&mut self, client: &ClientKey, user: &str) {
        if !self.clients.remove(client) {
            return;
        }
        if let Some(n) = self.per_user.get_mut(user) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.per_user.remove(user);
            }
        }
    }
}

struct AmpState {
    per_source: HashMap<IpAddr, Bucket>,
    shared: Bucket,
    reserve: Bucket,
    /// Sources that sent an authenticated request lately, until when, with their own budget.
    verified: HashMap<IpAddr, (Instant, Bucket)>,
}

struct AmpGuard(Mutex<AmpState>);

impl AmpGuard {
    fn new(now: Instant) -> AmpGuard {
        AmpGuard(Mutex::new(AmpState {
            per_source: HashMap::new(),
            shared: Bucket::new(AMP_SHARED.0, AMP_SHARED.1, now),
            reserve: Bucket::new(AMP_RESERVE.0, AMP_RESERVE.1, now),
            verified: HashMap::new(),
        }))
    }

    /// Whether an answer `excess` bytes bigger than its request may go to `ip`.
    fn allow(&self, ip: IpAddr, excess: usize, now: Instant) -> bool {
        let (n, src) = (excess as u64, source_prefix(ip));
        let mut st = self.0.lock();
        let st = &mut *st;
        if let Some((until, b)) = st.verified.get_mut(&src) {
            if *until > now {
                return b.take(n, now) && (st.shared.take(n, now) || st.reserve.take(n, now));
            }
        }
        if st.per_source.len() >= AMP_TRACKED && !st.per_source.contains_key(&src) {
            st.per_source.retain(|_, b| !b.is_full(now));
            if st.per_source.len() >= AMP_TRACKED {
                return false;
            }
        }
        st.per_source.entry(src).or_insert_with(|| Bucket::new(AMP_PER_SOURCE.0, AMP_PER_SOURCE.1, now)).take(n, now)
            && st.shared.take(n, now)
    }

    /// Notes that `ip` answered a challenge (it's reachable there, so not spoofed).
    fn verify(&self, ip: IpAddr, now: Instant) {
        let src = source_prefix(ip);
        let until = now + Duration::from_secs(NONCE_SECS);
        let mut st = self.0.lock();
        if let Some(v) = st.verified.get_mut(&src) {
            v.0 = until;
            return;
        }
        if st.verified.len() >= AMP_TRACKED {
            st.verified.retain(|_, (u, _)| *u > now);
            if st.verified.len() >= AMP_TRACKED {
                return;
            }
        }
        st.verified.insert(src, (until, Bucket::new(AMP_PER_SOURCE.0, AMP_PER_SOURCE.1, now)));
    }

    fn prune(&self, now: Instant) {
        let mut st = self.0.lock();
        st.per_source.retain(|_, b| !b.is_full(now));
        st.verified.retain(|_, (u, _)| *u > now);
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

/// The server's own addresses: every interface's (and its broadcast address), the configured
/// external IP, and the addresses relayed addresses are advertised at. A peer there is one of our
/// own allocations or nobody, never another service on the box or a neighbour on its networks.
#[derive(Debug, Default)]
struct OwnAddrs(Vec<IpAddr>);

impl OwnAddrs {
    fn contains(&self, ip: IpAddr) -> bool {
        self.0.contains(&canonical(ip))
    }
}

/// Every address of every interface, or None when the system won't say.
fn interface_addrs() -> Option<Vec<IpAddr>> {
    match if_addrs::get_if_addrs() {
        Ok(list) => Some(
            list.into_iter()
                .flat_map(|i| match i.addr {
                    if_addrs::IfAddr::V4(a) => [Some(IpAddr::V4(a.ip)), a.broadcast.map(IpAddr::V4)],
                    if_addrs::IfAddr::V6(a) => [Some(IpAddr::V6(a.ip)), a.broadcast.map(IpAddr::V6)],
                })
                .flatten()
                .collect(),
        ),
        Err(e) => {
            tracing::warn!(error = %e, "couldn't list this machine's addresses for the call relay");
            None
        }
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
#[derive(Debug, PartialEq, Eq)]
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
    limits: ArcSwap<Limits>,
    /// Sharded maps, so packets for different allocations rarely meet on a lock.
    by_client: DashMap<ClientKey, Arc<Allocation>>,
    by_port: DashMap<RelayPort, Arc<Allocation>>,
    registry: Mutex<Registry>,
    own: ArcSwap<OwnAddrs>,
    amp: AmpGuard,
    /// Said once that the address relayed addresses are advertised at can't work (see
    /// [`unreachable_for`]).
    warned_private: AtomicBool,
    pub(super) shutdown: tokio::sync::watch::Receiver<bool>,
}

/// Whether relayed addresses at `advertised` can't work for `client`: a private address (a
/// container's bridge network, a LAN behind NAT) handed to a client on the internet, which has
/// no route to it. Under Docker that is what the system picks unless `turn.external_ip` is set.
fn unreachable_for(advertised: IpAddr, client: IpAddr) -> bool {
    let public = PeerPolicy::public_only(Vec::new());
    !public.allows(advertised) && public.allows(client)
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
    let mut mac = hmac_sha1(secret.as_bytes());
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
        let r = Relay {
            secret: secret.into(),
            realm: realm.into(),
            nonce_key: rand::random(),
            bind_ip,
            ports,
            udp,
            limits: ArcSwap::from_pointee(limits),
            by_client: DashMap::new(),
            by_port: DashMap::new(),
            registry: Mutex::new(Registry::default()),
            own: ArcSwap::from_pointee(OwnAddrs::default()),
            amp: AmpGuard::new(Instant::now()),
            warned_private: AtomicBool::new(false),
            shutdown,
        };
        r.refresh_own_addrs();
        r
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }

    pub fn realm(&self) -> &str {
        &self.realm
    }

    pub fn set_limits(&self, l: Limits) {
        let moved = l.external_ip != self.limits.load().external_ip;
        self.limits.store(Arc::new(l));
        // A new external IP is one of our own addresses at once, not at the next listing.
        if moved {
            self.refresh_own_addrs();
        }
    }

    /// The longest lifetime a client can be granted, in seconds.
    pub fn max_lifetime(&self) -> u32 {
        self.limits.load().quota.max_lifetime_secs.max(DEFAULT_LIFETIME)
    }

    fn limits(&self) -> Arc<Limits> {
        self.limits.load_full()
    }

    /// Relayed addresses one account may hold: the configured quota, but never so many that a
    /// few accounts could take every relay port (an eighth of the range, and at least two).
    fn per_user_quota(&self, q: &TurnQuota) -> usize {
        let span = usize::from(self.ports.1.saturating_sub(self.ports.0)) + 1;
        q.allocations_per_user.min((span / 8).max(2))
    }

    pub fn allocation_count(&self) -> usize {
        self.by_client.len()
    }

    /// Drops a client's allocation (its TCP connection closed).
    pub fn remove_client(&self, key: &ClientKey) {
        self.remove(key);
    }

    pub fn has_allocation(&self, key: &ClientKey) -> bool {
        self.by_client.contains_key(key)
    }

    fn remove(&self, key: &ClientKey) -> Option<Arc<Allocation>> {
        self.remove_where(key, |_| true)
    }

    /// Ends the client's allocation when `pred` holds for it (a sweep only ends the one it saw,
    /// not a new one the client made since).
    fn remove_where(&self, key: &ClientKey, pred: impl FnOnce(&Arc<Allocation>) -> bool) -> Option<Arc<Allocation>> {
        let (_, a) = self.by_client.remove_if(key, |_, a| pred(a))?;
        self.by_port.remove_if(&a.relay_port(), |_, b| Arc::ptr_eq(b, &a));
        self.registry.lock().release(key, &a.user);
        a.stop.notify_one();
        Some(a)
    }

    /// Lists the machine's addresses again (interfaces come and go: DHCP, VPNs, containers).
    pub fn refresh_own_addrs(&self) {
        let Some(mut ips) = interface_addrs() else { return };
        if !self.bind_ip.is_unspecified() {
            ips.push(self.bind_ip);
        }
        ips.extend(self.limits.load().external_ip);
        ips.extend(self.by_port.iter().map(|a| a.relayed.ip()));
        let mut ips: Vec<IpAddr> = ips.into_iter().map(canonical).collect();
        ips.sort_unstable();
        ips.dedup();
        self.own.store(Arc::new(OwnAddrs(ips)));
    }

    /// Removes expired, broken and long-unused allocations, and expired permissions and channels.
    pub fn sweep(&self, now: Instant) {
        // Copied out first, so no shard stays locked while allocations are ended.
        let all: Vec<Arc<Allocation>> = self.by_client.iter().map(|e| e.value().clone()).collect();
        let expired: Vec<Arc<Allocation>> = all
            .into_iter()
            .filter(|a| {
                let mut st = a.state.lock();
                st.prune(now);
                st.expires <= now || (!st.used && a.created + UNUSED_LIFETIME <= now) || a.dead.load(Ordering::Relaxed)
            })
            .collect();
        for a in &expired {
            self.remove_where(&a.client, |b| Arc::ptr_eq(a, b));
        }
        if !expired.is_empty() {
            tracing::debug!(count = expired.len(), "relay allocations ended");
        }
        self.amp.prune(now);
    }

    /// Removes every allocation (shutdown).
    pub fn clear(&self) {
        let keys: Vec<ClientKey> = self.by_client.iter().map(|e| *e.key()).collect();
        for k in &keys {
            self.remove(k);
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
        let mut mac = hmac_sha1(&self.nonce_key);
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
                let Some(key) = self.authenticate(&m, client.ip(), out) else {
                    return self.unauthenticated(pkt.len(), client, out, now);
                };
                if !client.tcp {
                    self.amp.verify(client.ip(), now);
                }
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
        if client.tcp || out.len() <= req_len || self.amp.allow(client.ip(), out.len() - req_len, now) {
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
            w.xor_addr(attr::XOR_MAPPED_ADDRESS, client.unmapped());
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
        let a = self.by_client.get(&client).map(|e| e.value().clone()).ok_or(Refuse(437, "Allocation Mismatch"))?;
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
        if let Some(a) = self.by_client.get(&client).map(|e| e.value().clone()) {
            // A retransmitted Allocate gets the same answer; anything else is a mismatch.
            if a.tid != m.tid || &*a.username != username {
                return Err(Refuse(437, "Allocation Mismatch"));
            }
            let left = a.state.lock().expires.saturating_duration_since(now).as_secs() as u32;
            allocate_success(out, m, key, a.relayed, client.unmapped(), left);
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
        // Checked and counted in one go; handed back below if the allocation can't be made.
        self.registry.lock().reserve(client, &user, limits.quota.allocations, self.per_user_quota(&limits.quota))?;
        let made = self.bind_relay(v6, m.has(attr::EVEN_PORT)).and_then(|(socket, local)| {
            let ip = self.advertised_ip(v6, client.unmapped(), &limits)?;
            Ok((socket, SocketAddr::new(ip, local.port())))
        });
        let (socket, relayed) = match made {
            Ok(v) => v,
            Err(e) => {
                self.registry.lock().release(&client, &user);
                return Err(e);
            }
        };
        let lifetime = lifetime(m, &limits.quota);
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
            user,
            tid: m.tid,
            created: now,
            state: Mutex::new(AllocState {
                expires: now + Duration::from_secs(u64::from(lifetime)),
                permissions: Vec::new(),
                channels: Vec::new(),
                bucket: bandwidth_bucket(&limits.quota, now),
                used: false,
            }),
            dead: AtomicBool::new(false),
            stop: Notify::new(),
        });
        self.by_port.insert(a.relay_port(), a.clone());
        self.by_client.insert(client, a.clone());
        if !self.own.load().contains(relayed.ip()) {
            self.own.rcu(|o| {
                let mut ips = o.0.clone();
                ips.push(canonical(relayed.ip()));
                OwnAddrs(ips)
            });
        }
        tracing::debug!(client = %client.addr, tcp = client.tcp, relayed = %relayed, "relay allocation created");
        super::io::spawn_allocation(self.shutdown.clone(), a);
        allocate_success(out, m, key, relayed, client.unmapped(), lifetime);
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
            if let Ok(s) = bind_udp(SocketAddr::new(ip, port), false) {
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
            Ok(a) if !a.ip().is_unspecified() => {
                if unreachable_for(a.ip(), client.ip()) && !self.warned_private.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        advertised = %a.ip(),
                        client = %client.ip(),
                        "the call relay hands out a private address to clients on the internet, so calls through it will fail; \
                         set turn.external_ip (or QUARK_TURN_EXTERNAL_IP) to the server's public address"
                    );
                }
                Ok(a.ip())
            }
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
            self.remove(&client);
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

    /// Whether a client may talk to `ip`: the policy allows it, or it's one of the server's own
    /// addresses, where [`Relay::to_peer`] only delivers to our own relayed ports (two callers on
    /// the same relay).
    fn peer_allowed(&self, ip: IpAddr, limits: &Limits) -> bool {
        limits.policy.allows(ip) || self.own.load().contains(ip)
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
            if !peers[..n].contains(&p.ip()) {
                peers[n] = p.ip();
                n += 1;
            }
        }
        if n == 0 {
            return Err(Refuse(400, "Bad Request"));
        }
        {
            // All or nothing (RFC 8656 §9.2): room for every new one is checked before any is
            // installed.
            let mut st = a.state.lock();
            st.prune(now);
            let new = peers[..n].iter().filter(|ip| !st.permissions.iter().any(|(p, _)| p == *ip)).count();
            if st.permissions.len() + new > MAX_PERMISSIONS {
                return Err(Refuse(508, "Insufficient Capacity"));
            }
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
        let Some(a) = self.by_client.get(&client).map(|e| e.value().clone()) else { return };
        {
            let mut st = a.state.lock();
            if !st.permitted(peer.ip(), now) || !st.bucket.take(data.len() as u64, now) {
                return;
            }
        }
        self.to_peer(&a, peer, data, scratch, now);
    }

    fn channel_data(&self, client: ClientKey, ch: u16, data: &[u8], scratch: &mut [u8], now: Instant) {
        let Some(a) = self.by_client.get(&client).map(|e| e.value().clone()) else { return };
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

    /// Sends client data to a peer. A peer at one of the server's own addresses gets it only when
    /// the port is one of our relayed ports, directly (no hairpin through the NAT); every other
    /// port there gets nothing, unless the config allows that address explicitly.
    fn to_peer(&self, from: &Allocation, peer: SocketAddr, data: &[u8], scratch: &mut [u8], now: Instant) {
        if self.own.load().contains(peer.ip()) {
            match self.by_port.get(&RelayPort::of(peer)).map(|e| e.value().clone()) {
                Some(t) if data.len() + HEADROOM + 4 <= scratch.len() => {
                    scratch[HEADROOM..HEADROOM + data.len()].copy_from_slice(data);
                    t.forward_to_client(scratch, data.len(), from.relayed, now);
                    return;
                }
                Some(_) => return,
                None if !self.limits.load().policy.explicitly_allows(peer.ip()) => return,
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
    st.used = true;
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

/// A non-blocking UDP socket for tokio. With `dual_stack`, an IPv6 socket takes IPv4 too (the
/// listener on `[::]`); otherwise it's IPv6 only (relay sockets, so the policy sees the family an
/// allocation was made for).
pub fn bind_udp(addr: SocketAddr, dual_stack: bool) -> std::io::Result<UdpSocket> {
    let s = socket2::Socket::new(socket2::Domain::for_address(addr), socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if addr.is_ipv6() {
        s.set_only_v6(!dual_stack)?;
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
        relay_with((49152, 65535), |_| {}).await
    }

    async fn relay_with(ports: (u16, u16), f: impl FnOnce(&mut TurnSection)) -> Relay {
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut t = TurnSection::default();
        t.peers.allow_loopback = true;
        f(&mut t);
        let (_tx, rx) = tokio::sync::watch::channel(false);
        Relay::new("s3cret", "quark.test", "127.0.0.1".parse().unwrap(), ports, udp, Limits::new(&t), rx)
    }

    fn client(n: u16) -> ClientKey {
        ClientKey { tcp: false, addr: SocketAddr::from(([203, 0, 113, 9], 5000 + n)) }
    }

    /// A request signed with valid credentials for `user`, as a client at `client` would send.
    fn signed(r: &Relay, client: ClientKey, user: &str, method: u16, build: impl Fn(&mut Writer)) -> Vec<u8> {
        let username = format!("{}:{user}", now_secs() + 3600);
        let key = long_term_key(&username, "quark.test", &rest_password("s3cret", &username));
        let nonce = r.nonce(client.ip(), now_secs());
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf, method, Class::Request, rand::random());
        build(&mut w);
        w.attr(attr::USERNAME, username.as_bytes()).attr(attr::REALM, b"quark.test").attr(attr::NONCE, &nonce).integrity(&key);
        buf
    }

    /// Sends `pkt` from `client`; the answer's error code, or None for a success.
    fn ask(r: &Relay, client: ClientKey, pkt: &[u8]) -> Option<u16> {
        let (mut out, mut scratch) = (Vec::new(), vec![0u8; PACKET_BUF]);
        assert_eq!(r.handle(pkt, client, None, &mut out, &mut scratch), Outcome::Reply);
        let m = Message::parse(&out).unwrap();
        m.get(attr::ERROR_CODE).map(|e| u16::from(e[2]) * 100 + u16::from(e[3]))
    }

    fn allocate(r: &Relay, client: ClientKey, user: &str) -> Option<u16> {
        let req = signed(r, client, user, method::ALLOCATE, |w| {
            w.attr(attr::REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
        });
        ask(r, client, &req)
    }

    fn permit_peers(r: &Relay, client: ClientKey, peers: &[SocketAddr]) -> Option<u16> {
        let req = signed(r, client, "alice@quark.test", method::CREATE_PERMISSION, |w| {
            for p in peers {
                w.xor_addr(attr::XOR_PEER_ADDRESS, *p);
            }
        });
        ask(r, client, &req)
    }

    fn permissions(r: &Relay, client: ClientKey) -> usize {
        r.by_client.get(&client).map_or(0, |a| a.state.lock().permissions.len())
    }

    #[tokio::test]
    async fn ipv4_clients_on_a_dual_stack_listener_learn_their_ipv4_address() {
        let r = relay().await;
        let mapped = ClientKey { tcp: false, addr: "[::ffff:203.0.113.9]:5000".parse().unwrap() };
        let mut req = Vec::new();
        Writer::new(&mut req, method::BINDING, Class::Request, [5; 12]);
        let (mut out, mut scratch) = (Vec::new(), vec![0u8; PACKET_BUF]);
        assert_eq!(r.handle(&req, mapped, None, &mut out, &mut scratch), Outcome::Reply);
        let m = Message::parse(&out).unwrap();
        assert_eq!(m.xor_addr(attr::XOR_MAPPED_ADDRESS), Some("203.0.113.9:5000".parse().unwrap()));
    }

    #[tokio::test]
    async fn the_per_account_quota_is_held_to_a_share_of_the_port_range() {
        // 16 ports: an account gets two of them, whatever the configured quota says.
        let r = relay_with((61_200, 61_215), |_| {}).await;
        assert_eq!(allocate(&r, client(1), "alice@quark.test"), None);
        assert_eq!(allocate(&r, client(2), "alice@quark.test"), None);
        assert_eq!(allocate(&r, client(3), "alice@quark.test"), Some(486));
        assert_eq!(allocate(&r, client(4), "bob@quark.test"), None);
        assert_eq!(r.per_user_quota(&TurnQuota::default()), 2);
        assert_eq!(relay().await.per_user_quota(&TurnQuota::default()), 16);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn racing_allocations_never_exceed_the_quota() {
        let r = relay_with((49152, 65535), |t| t.quota.allocations_per_user = 1).await;
        let rt = tokio::runtime::Handle::current();
        let ok = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|sc| {
            for i in 0..16 {
                let (r, rt, ok) = (&r, &rt, &ok);
                sc.spawn(move || {
                    let _rt = rt.enter();
                    if allocate(r, client(i), "alice@quark.test").is_none() {
                        ok.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });
        assert_eq!(ok.load(Ordering::Relaxed), 1);
        assert_eq!(r.allocation_count(), 1);
        assert_eq!(r.registry.lock().clients.len(), 1);
    }

    #[tokio::test]
    async fn create_permission_installs_all_or_nothing() {
        let r = relay().await;
        let c = client(1);
        assert_eq!(allocate(&r, c, "alice@quark.test"), None);
        let peer = |i: usize| SocketAddr::from(([1, 1, (i / 200) as u8, (i % 200) as u8 + 1], 9));
        for chunk in (0..MAX_PERMISSIONS - 1).collect::<Vec<_>>().chunks(8) {
            let peers: Vec<SocketAddr> = chunk.iter().map(|i| peer(*i)).collect();
            assert_eq!(permit_peers(&r, c, &peers), None);
        }
        assert_eq!(permissions(&r, c), MAX_PERMISSIONS - 1);
        // One slot left, two new peers: neither is installed.
        assert_eq!(permit_peers(&r, c, &[peer(500), peer(501)]), Some(508));
        assert_eq!(permissions(&r, c), MAX_PERMISSIONS - 1);
        // Refreshing existing ones alongside one new one fits.
        assert_eq!(permit_peers(&r, c, &[peer(0), peer(500)]), None);
        assert_eq!(permissions(&r, c), MAX_PERMISSIONS);
    }

    #[tokio::test]
    async fn unused_allocations_end_early_and_used_ones_live_on() {
        let r = relay().await;
        assert_eq!(allocate(&r, client(1), "alice@quark.test"), None);
        assert_eq!(allocate(&r, client(2), "bob@quark.test"), None);
        assert_eq!(permit_peers(&r, client(1), &["8.8.8.8:9".parse().unwrap()]), None);
        let later = Instant::now() + UNUSED_LIFETIME + Duration::from_secs(1);
        r.sweep(later);
        assert!(r.has_allocation(&client(1)));
        assert!(!r.has_allocation(&client(2)));
        assert!(!r.registry.lock().per_user.contains_key("bob@quark.test"));
    }

    #[tokio::test]
    async fn broken_allocations_are_swept_and_their_quota_freed() {
        let r = relay_with((49152, 65535), |t| t.quota.allocations_per_user = 1).await;
        assert_eq!(allocate(&r, client(1), "alice@quark.test"), None);
        if let Some(a) = r.by_client.get(&client(1)) {
            a.fail();
        }
        r.sweep(Instant::now());
        assert!(!r.has_allocation(&client(1)));
        assert_eq!(allocate(&r, client(2), "alice@quark.test"), None);
    }

    #[tokio::test]
    async fn own_addresses_include_every_interface() {
        let r = relay().await;
        let own = r.own.load();
        assert!(own.contains("127.0.0.1".parse().unwrap()));
        for ip in interface_addrs().unwrap_or_default() {
            assert!(own.contains(ip), "{ip}");
        }
    }

    #[tokio::test]
    async fn a_new_external_ip_is_guarded_at_once() {
        let r = relay().await;
        let ext: IpAddr = "198.51.100.77".parse().unwrap();
        assert!(!r.own.load().contains(ext));
        r.set_limits(Limits::new(&TurnSection { external_ip: Some(ext), ..TurnSection::default() }));
        assert!(r.own.load().contains(ext), "peers at the external IP are only our own allocations");
    }

    #[test]
    fn private_relayed_addresses_are_flagged_for_internet_clients() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        // Docker's bridge address handed to a phone on mobile data.
        assert!(unreachable_for(ip("172.17.0.2"), ip("93.184.216.34")));
        assert!(!unreachable_for(ip("172.17.0.2"), ip("192.168.1.20")), "a client on the LAN can reach it");
        assert!(!unreachable_for(ip("1.1.1.1"), ip("93.184.216.34")));
    }

    #[test]
    fn ipv6_sources_are_grouped_by_their_64() {
        let a = source_prefix("2001:db8:1:2:aaaa::1".parse().unwrap());
        assert_eq!(a, source_prefix("2001:db8:1:2:bbbb::9".parse().unwrap()));
        assert_ne!(a, source_prefix("2001:db8:1:3::1".parse().unwrap()));
        assert_eq!(source_prefix("::ffff:198.51.100.1".parse().unwrap()), source_prefix("198.51.100.1".parse().unwrap()));
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
            assert!(sent <= AMP_PER_SOURCE.1 as usize);
        }
        assert!(r.amp.allow("198.51.100.2".parse().unwrap(), 80, now));
        // Rotating addresses within one IPv6 /64 doesn't buy more.
        let mut sent = 0;
        for i in 0u16.. {
            if !r.amp.allow(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, i)), 80, now) {
                break;
            }
            sent += 80;
            assert!(sent <= AMP_PER_SOURCE.1 as usize);
        }
    }

    #[tokio::test]
    async fn a_flood_from_many_sources_leaves_returning_users_their_challenges() {
        let r = relay().await;
        let now = Instant::now();
        let known: IpAddr = "192.0.2.77".parse().unwrap();
        r.amp.verify(known, now);
        // Enough sources to drain the shared budget.
        for i in 0..(AMP_SHARED.1 / AMP_PER_SOURCE.1 + 8) as u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + i));
            while r.amp.allow(ip, 512, now) {}
        }
        assert!(!r.amp.allow("192.0.2.78".parse().unwrap(), 80, now));
        assert!(r.amp.allow(known, 80, now));
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
