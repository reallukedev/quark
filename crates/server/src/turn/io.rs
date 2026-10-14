//! The relay's sockets: the shared UDP listener, TCP connections (RFC 8656 §3.1 framing), one
//! task per allocation for peer traffic, and the expiry sweep.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};

use super::relay::{bind_udp, source_prefix, Allocation, ClientKey, Limits, Outcome, Relay, HEADROOM, PACKET_BUF};
use super::stun;
use crate::server::Server;

/// TCP connections at once, so a flood of idle connections can't exhaust the process.
const MAX_TCP: usize = 1024;
/// TCP connections at once from one source (an IPv4 address or an IPv6 /64), so one host can't
/// take every slot. A household behind one address has a few phones with one or two each.
const MAX_TCP_PER_SOURCE: usize = 16;
/// A TCP connection must hold an allocation (which takes authenticating) within this long of
/// connecting, or of losing its last one. Binding requests don't extend it, so unauthenticated
/// connections can't sit on slots. With an allocation it may idle this long between packets
/// plus the longest allocation lifetime.
const TCP_IDLE: Duration = Duration::from_secs(30);
const TCP_WRITE: Duration = Duration::from_secs(10);
/// Packets queued for a slow TCP client before new ones are dropped.
const TCP_QUEUE: usize = 256;
const SWEEP: Duration = Duration::from_secs(5);
/// Sweeps between listings of the machine's addresses (every 30 seconds).
const OWN_ADDRS_EVERY: u32 = 6;

/// Binds UDP and TCP on the same port. With port 0 the UDP port is picked first and TCP follows
/// it, retrying a few times if TCP's twin happens to be taken.
pub fn bind(addr: SocketAddr) -> anyhow::Result<(UdpSocket, TcpListener)> {
    let mut last = None;
    for _ in 0..if addr.port() == 0 { 16 } else { 1 } {
        // Dual-stack, like TCP: `[::]` takes IPv4 clients too.
        let udp = bind_udp(addr, true)?;
        let port = udp.local_addr()?.port();
        match bind_tcp(SocketAddr::new(addr.ip(), port)) {
            Ok(tcp) => return Ok((udp, tcp)),
            Err(e) => last = Some(e),
        }
    }
    Err(last.map_or_else(|| anyhow::anyhow!("couldn't bind the relay"), anyhow::Error::from))
}

fn bind_tcp(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let s = socket2::Socket::new(socket2::Domain::for_address(addr), socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    if addr.is_ipv6() {
        s.set_only_v6(false).ok();
    }
    s.set_reuse_address(true)?;
    s.set_nonblocking(true)?;
    s.bind(&addr.into())?;
    s.listen(1024)?;
    TcpListener::from_std(s.into())
}

/// Starts the listener tasks and the sweeper.
pub fn spawn(srv: &Arc<Server>, relay: Arc<Relay>, tcp: TcpListener) {
    let state_srv = Arc::downgrade(srv);
    let r = relay.clone();
    tokio::spawn(async move {
        udp_loop(&r).await;
        r.clear();
        if let Some(s) = state_srv.upgrade() {
            s.turn.set_running(false);
        }
    });
    tokio::spawn(tcp_accept(relay.clone(), tcp));
    tokio::spawn(sweeper(relay, Arc::downgrade(srv)));
}

async fn udp_loop(relay: &Relay) {
    let mut shutdown = relay.shutdown.clone();
    let mut buf = vec![0u8; 65_536];
    let mut out = Vec::with_capacity(1500);
    let mut scratch = vec![0u8; PACKET_BUF];
    loop {
        tokio::select! {
            r = relay.udp.recv_from(&mut buf) => match r {
                Ok((n, from)) => {
                    let client = ClientKey { tcp: false, addr: from };
                    if relay.handle(&buf[..n], client, None, &mut out, &mut scratch) == Outcome::Reply {
                        let _ = relay.udp.try_send_to(&out, from);
                    }
                }
                // ICMP errors from earlier sends show up here on some systems; they're harmless.
                Err(e) => tracing::trace!(error = %e, "relay receive error"),
            },
            r = shutdown.changed() => if r.is_err() || *shutdown.borrow() { break },
        }
    }
}

/// Open TCP connections, in total and per source.
#[derive(Debug, Default)]
struct TcpSlots {
    total: usize,
    per_source: HashMap<IpAddr, usize>,
}

/// One connection's place in [`TcpSlots`], given back on drop.
struct TcpSlot {
    slots: Arc<Mutex<TcpSlots>>,
    source: IpAddr,
}

impl TcpSlots {
    fn acquire(slots: &Arc<Mutex<TcpSlots>>, ip: IpAddr, total: usize, per_source: usize) -> Option<TcpSlot> {
        let source = source_prefix(ip);
        let mut s = slots.lock();
        let n = s.per_source.get(&source).copied().unwrap_or(0);
        if s.total >= total || n >= per_source {
            return None;
        }
        s.total += 1;
        s.per_source.insert(source, n + 1);
        Some(TcpSlot { slots: slots.clone(), source })
    }
}

impl Drop for TcpSlot {
    fn drop(&mut self) {
        let mut s = self.slots.lock();
        s.total = s.total.saturating_sub(1);
        if let Some(n) = s.per_source.get_mut(&self.source) {
            *n -= 1;
            if *n == 0 {
                s.per_source.remove(&self.source);
            }
        }
    }
}

async fn tcp_accept(relay: Arc<Relay>, listener: TcpListener) {
    let mut shutdown = relay.shutdown.clone();
    let slots = Arc::new(Mutex::new(TcpSlots::default()));
    loop {
        tokio::select! {
            r = listener.accept() => match r {
                Ok((stream, peer)) => {
                    let Some(slot) = TcpSlots::acquire(&slots, peer.ip(), MAX_TCP, MAX_TCP_PER_SOURCE) else { continue };
                    let _ = stream.set_nodelay(true);
                    let r = relay.clone();
                    tokio::spawn(async move {
                        tcp_conn(&r, stream, peer, TCP_IDLE).await;
                        r.remove_client(&ClientKey { tcp: true, addr: peer });
                        drop(slot);
                    });
                }
                Err(e) => {
                    tracing::debug!(error = %e, "relay accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            },
            r = shutdown.changed() => if r.is_err() || *shutdown.borrow() { break },
        }
    }
}

/// One TCP client: STUN messages and ChannelData back to back on the stream. Without an
/// allocation it's closed `auth_within` after connecting (or after its last allocation ended).
async fn tcp_conn(relay: &Relay, stream: TcpStream, peer: SocketAddr, auth_within: Duration) {
    let key = ClientKey { tcp: true, addr: peer };
    let (mut rd, mut wr) = stream.into_split();
    let (tx, mut rx) = mpsc::channel::<Bytes>(TCP_QUEUE);
    let writer = tokio::spawn(async move {
        while let Some(b) = rx.recv().await {
            match tokio::time::timeout(TCP_WRITE, wr.write_all(&b)).await {
                Ok(Ok(())) => {}
                _ => break,
            }
        }
        let _ = wr.shutdown().await;
    });
    let mut shutdown = relay.shutdown.clone();
    let mut buf = vec![0u8; 2 * (65_536 + 8)];
    let mut filled = 0usize;
    let mut out = Vec::with_capacity(1500);
    let mut scratch = vec![0u8; PACKET_BUF];
    let max_idle = auth_within + Duration::from_secs(u64::from(relay.max_lifetime()));
    let mut auth_deadline = tokio::time::Instant::now() + auth_within;
    'conn: loop {
        // Frame and handle everything complete in the buffer.
        let mut at = 0;
        while filled - at >= 4 {
            let head = &buf[at..filled];
            let len = if head[0] & 0xC0 == 0 {
                stun::framed_len(head).unwrap_or(usize::MAX)
            } else if stun::is_channel_data(head) {
                let l = 4 + usize::from(u16::from_be_bytes([head[2], head[3]]));
                (l + 3) & !3
            } else {
                break 'conn;
            };
            if len > 65_536 + 8 {
                break 'conn;
            }
            if filled - at < len {
                break;
            }
            if relay.handle(&buf[at..at + len], key, Some(&tx), &mut out, &mut scratch) == Outcome::Reply
                && tx.send(Bytes::copy_from_slice(&out)).await.is_err()
            {
                break 'conn;
            }
            at += len;
        }
        buf.copy_within(at..filled, 0);
        filled -= at;
        let now = tokio::time::Instant::now();
        let until = if relay.has_allocation(&key) {
            auth_deadline = now + auth_within;
            now + max_idle
        } else {
            auth_deadline
        };
        tokio::select! {
            r = tokio::time::timeout_at(until, rd.read(&mut buf[filled..])) => match r {
                Ok(Ok(n)) if n > 0 => filled += n,
                _ => break,
            },
            r = shutdown.changed() => if r.is_err() || *shutdown.borrow() { break },
        }
    }
    drop(tx);
    writer.abort();
}

/// Reads what peers send to an allocation's relayed address and passes it to the client. A socket
/// that keeps failing is backed off from, then given up on: the allocation is marked broken so the
/// sweeper ends it (the client sees 437 and allocates again) instead of it living on deaf.
pub fn spawn_allocation(mut shutdown: watch::Receiver<bool>, a: Arc<Allocation>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; PACKET_BUF];
        let mut errors = 0u32;
        loop {
            tokio::select! {
                r = a.socket.recv_from(&mut buf[HEADROOM..HEADROOM + 65_535]) => match r {
                    Ok((n, peer)) => {
                        errors = 0;
                        a.forward_to_client(&mut buf, n, peer, Instant::now());
                    }
                    Err(e) => {
                        errors += 1;
                        if errors > 100 {
                            tracing::warn!(error = %e, "relay socket keeps failing; ending its allocation");
                            a.fail();
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(u64::from(errors.min(50)))).await;
                    }
                },
                _ = a.stop.notified() => break,
                r = shutdown.changed() => if r.is_err() || *shutdown.borrow() { break },
            }
        }
    });
}

/// Expires allocations, permissions and channels, picks up config changes after a reload, and
/// now and then lists the machine's addresses again.
async fn sweeper(relay: Arc<Relay>, srv: Weak<Server>) {
    let mut shutdown = relay.shutdown.clone();
    let mut tick = tokio::time::interval(SWEEP);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut n = 0u32;
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let Some(s) = srv.upgrade() else { break };
                relay.set_limits(Limits::new(&s.config().turn));
                drop(s);
                relay.sweep(Instant::now());
                n = n.wrapping_add(1);
                if n.is_multiple_of(OWN_ADDRS_EVERY) {
                    relay.refresh_own_addrs();
                }
            }
            r = shutdown.changed() => if r.is_err() || *shutdown.borrow() { break },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TurnSection;
    use crate::turn::stun::{attr, method, Class, Message, Writer};

    fn relay(udp: UdpSocket) -> Arc<Relay> {
        let (tx, rx) = watch::channel(false);
        std::mem::forget(tx);
        let ip = udp.local_addr().map(|a| a.ip()).unwrap_or(IpAddr::from([127, 0, 0, 1]));
        Arc::new(Relay::new("s3cret", "quark.test", ip, (49152, 65535), Arc::new(udp), Limits::new(&TurnSection::default()), rx))
    }

    fn binding() -> Vec<u8> {
        let mut req = Vec::new();
        Writer::new(&mut req, method::BINDING, Class::Request, [4; 12]);
        req
    }

    #[tokio::test]
    async fn a_listener_on_the_ipv6_wildcard_answers_ipv4_clients_too() -> anyhow::Result<()> {
        let Ok((udp, tcp)) = bind("[::]:0".parse()?) else { return Ok(()) }; // no IPv6 here
        let port = udp.local_addr()?.port();
        let r = relay(udp);
        let lr = r.clone();
        tokio::spawn(async move { udp_loop(&lr).await });
        let c = UdpSocket::bind("127.0.0.1:0").await?;
        c.send_to(&binding(), ("127.0.0.1", port)).await?;
        let mut buf = [0u8; 256];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), c.recv_from(&mut buf)).await??;
        let m = Message::parse(&buf[..n]).map_err(|_| anyhow::anyhow!("not STUN"))?;
        assert_eq!(m.xor_addr(attr::XOR_MAPPED_ADDRESS), Some(c.local_addr()?));
        // TCP on the same port takes IPv4 as well.
        drop(TcpStream::connect(("127.0.0.1", tcp.local_addr()?.port())).await?);
        Ok(())
    }

    #[tokio::test]
    async fn tcp_connections_that_never_authenticate_are_closed_despite_binding_traffic() -> anyhow::Result<()> {
        let r = relay(UdpSocket::bind("127.0.0.1:0").await?);
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let lr = r.clone();
        tokio::spawn(async move {
            if let Ok((s, peer)) = listener.accept().await {
                tcp_conn(&lr, s, peer, Duration::from_millis(400)).await;
            }
        });
        let mut c = TcpStream::connect(addr).await?;
        let started = Instant::now();
        let mut buf = [0u8; 256];
        loop {
            // A Binding request every 100 ms used to keep the connection open forever.
            if c.write_all(&binding()).await.is_err() {
                break;
            }
            match tokio::time::timeout(Duration::from_millis(100), c.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => break,
                _ => {}
            }
            assert!(started.elapsed() < Duration::from_secs(5), "the connection stayed open");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(started.elapsed() >= Duration::from_millis(350));
        Ok(())
    }

    #[test]
    fn tcp_slots_are_capped_per_source_and_given_back() {
        let slots = Arc::new(Mutex::new(TcpSlots::default()));
        let v6 = |i: u16| IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i));
        let v4 = |i: u8| IpAddr::from([198, 51, 100, i]);
        // Addresses in one /64 count as one source.
        let held: Vec<TcpSlot> = (1..=3).filter_map(|i| TcpSlots::acquire(&slots, v6(i), 10, 3)).collect();
        assert_eq!(held.len(), 3);
        assert!(TcpSlots::acquire(&slots, v6(9), 10, 3).is_none());
        let other = TcpSlots::acquire(&slots, v4(1), 4, 3);
        assert!(other.is_some());
        assert!(TcpSlots::acquire(&slots, v4(2), 4, 3).is_none(), "the total cap");
        drop(held);
        assert!(TcpSlots::acquire(&slots, v6(9), 10, 3).is_some());
        drop(other);
        assert_eq!(slots.lock().total, 0);
    }
}
